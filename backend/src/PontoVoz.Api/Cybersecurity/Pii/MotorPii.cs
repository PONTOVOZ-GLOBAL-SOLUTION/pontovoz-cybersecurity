using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Options;

namespace PontoVoz.Api.Cybersecurity.Pii;

/// <summary>
/// Motor de parsing PII. Percorre um JSON (objetos aninhados e listas), um conjunto de campos
/// (query string, formulário) ou um texto livre e devolve: as detecções classificadas, uma cópia
/// sanitizada da entrada e, só para uso interno do Taint Analysis, os valores originais.
/// <para>
/// Um valor é classificado pelo nome do campo (<c>cpf</c>, <c>senha</c>, <c>laudo</c>...) ou pelo
/// conteúdo (CPF com dígitos verificadores, e-mail, telefone, código CID...). Campos sem nome
/// sensível também são varridos, de modo que um CPF digitado em <c>observacao</c> é reconhecido.
/// Uma estrutura sob um campo sensível (por exemplo, <c>"saude": { ... }</c>) é protegida por inteiro.
/// </para>
/// </summary>
public sealed partial class MotorPii(IOptions<OpcoesCybersecurity> opcoes)
{
    // A cópia sanitizada vai para logs e telas: acentos legíveis, sem sequências de escape.
    private static readonly JsonSerializerOptions TextoLegivel = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly OpcoesCybersecurity _opcoes = opcoes.Value;

    public ResultadoAnalisePii AnalisarJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return ResultadoAnalisePii.Vazio(SituacaoAnalise.CorpoVazio);
        }

        if (ProfundidadeMaxima(json) > _opcoes.ProfundidadeMaximaJson)
        {
            return AnalisarTextoComSituacao(json, SituacaoAnalise.EstruturaExcessiva);
        }

        JsonNode? raiz;
        try
        {
            raiz = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { MaxDepth = _opcoes.ProfundidadeMaximaJson + 1 });
        }
        catch (JsonException)
        {
            return AnalisarTextoComSituacao(json, SituacaoAnalise.JsonMalformado);
        }

        if (ContarNos(raiz, _opcoes.LimiteNosJson + 1) > _opcoes.LimiteNosJson)
        {
            return AnalisarTextoComSituacao(json, SituacaoAnalise.EstruturaExcessiva);
        }

        return AnalisarNo(raiz);
    }

    /// <summary>Campos de query string ou de formulário, analisados como um objeto JSON de textos.</summary>
    public ResultadoAnalisePii AnalisarCampos(IEnumerable<KeyValuePair<string, string?>> campos)
    {
        var objeto = new JsonObject();
        foreach (var (nome, valor) in campos)
        {
            string chave = nome;
            for (int repeticao = 2; objeto.ContainsKey(chave); repeticao++)
            {
                chave = $"{nome}#{repeticao}";
            }

            objeto[chave] = valor;
        }

        return objeto.Count == 0 ? ResultadoAnalisePii.Vazio(SituacaoAnalise.CorpoVazio) : AnalisarNo(objeto);
    }

    /// <summary>Texto livre: mensagens de log, corpos que não são JSON e conteúdos de saída.</summary>
    public ResultadoAnalisePii AnalisarTexto(string? texto) =>
        string.IsNullOrEmpty(texto)
            ? ResultadoAnalisePii.Vazio(SituacaoAnalise.CorpoVazio)
            : AnalisarTextoComSituacao(texto, SituacaoAnalise.Analisado);

    /// <summary>
    /// Substitui cada ocorrência de PII num texto pelo valor que <paramref name="substituto"/>
    /// devolver para a categoria. Usado pelas saídas, que aplicam a decisão da política (máscara ou bloqueio).
    /// </summary>
    internal static string Substituir(string texto, Func<CategoriaPii, string, string> substituto, ICollection<CategoriaPii> categorias)
    {
        List<RegrasPii.Ocorrencia> ocorrencias = RegrasPii.LocalizarEmTextoBruto(texto);
        if (ocorrencias.Count == 0)
        {
            return texto;
        }

        var resultado = new StringBuilder(texto);
        for (int i = ocorrencias.Count - 1; i >= 0; i--)
        {
            RegrasPii.Ocorrencia o = ocorrencias[i];
            categorias.Add(o.Categoria);
            resultado.Remove(o.Inicio, o.Tamanho).Insert(o.Inicio, substituto(o.Categoria, texto.Substring(o.Inicio, o.Tamanho)));
        }

        return resultado.ToString();
    }

    private static ResultadoAnalisePii AnalisarNo(JsonNode? raiz)
    {
        var estado = new Estado();
        JsonNode? sanitizado = Visitar(raiz, "$", chave: null, herdada: null, estado);
        return new ResultadoAnalisePii(SituacaoAnalise.Analisado, estado.Deteccoes, sanitizado, sanitizado?.ToJsonString(TextoLegivel) ?? "null", estado.Valores);
    }

    private static ResultadoAnalisePii AnalisarTextoComSituacao(string texto, SituacaoAnalise situacao)
    {
        var estado = new Estado();
        List<RegrasPii.Ocorrencia> ocorrencias = RegrasPii.LocalizarEmTextoBruto(texto);
        var sanitizado = new StringBuilder(texto);
        for (int i = ocorrencias.Count - 1; i >= 0; i--)
        {
            RegrasPii.Ocorrencia o = ocorrencias[i];
            string original = texto.Substring(o.Inicio, o.Tamanho);
            string caminho = $"texto[{o.Inicio}]";
            estado.Detectar(o.Categoria, caminho, o.Regra, o.Confianca);
            estado.Registrar(o.Categoria, caminho, original);
            sanitizado.Remove(o.Inicio, o.Tamanho).Insert(o.Inicio, MascaradorPii.Mascarar(o.Categoria, original));
        }

        estado.Deteccoes.Reverse();
        return new ResultadoAnalisePii(situacao, estado.Deteccoes, sanitizado: null, sanitizado.ToString(), estado.Valores);
    }

    private static JsonNode? Visitar(JsonNode? no, string caminho, string? chave, CategoriaPii? herdada, Estado estado)
    {
        switch (no)
        {
            case null:
                return null;

            case JsonObject objeto:
                var copia = new JsonObject();
                foreach (var (nome, valor) in objeto)
                {
                    string nomeSeguro = ChaveSegura(nome, caminho, estado);
                    string caminhoFilho = CaminhoPropriedade(caminho, nomeSeguro);
                    CategoriaPii? categoria = herdada;
                    if (categoria is null && valor is JsonObject or JsonArray && RegrasPii.CategoriaPorChave(nome) is { } daChave)
                    {
                        // Estrutura inteira sob um campo sensível: todos os valores internos ficam protegidos.
                        estado.Detectar(daChave, caminhoFilho, $"campo-{Regra(daChave)}-estrutura", Confianca.Alta);
                        categoria = daChave;
                    }

                    copia[nomeSeguro] = Visitar(valor, caminhoFilho, nome, categoria, estado);
                }

                return copia;

            case JsonArray lista:
                var copiaLista = new JsonArray();
                for (int i = 0; i < lista.Count; i++)
                {
                    copiaLista.Add(Visitar(lista[i], $"{caminho}[{i}]", chave, herdada, estado));
                }

                return copiaLista;

            default:
                return VisitarValor((JsonValue)no, caminho, chave, herdada, estado);
        }
    }

    private static JsonNode? VisitarValor(JsonValue valor, string caminho, string? chave, CategoriaPii? herdada, Estado estado)
    {
        JsonValueKind tipo = valor.GetValueKind();
        string? texto = tipo switch
        {
            JsonValueKind.String => valor.GetValue<string>(),
            JsonValueKind.Number => valor.ToJsonString(),
            _ => null,
        };

        if (herdada is { } dentroDeEstrutura)
        {
            if (tipo == JsonValueKind.Null)
            {
                return null;
            }

            if (texto is not null)
            {
                estado.Registrar(dentroDeEstrutura, caminho, texto);
            }

            return MascaradorPii.Mascarar(dentroDeEstrutura, texto ?? valor.ToJsonString());
        }

        if (chave is not null && RegrasPii.CategoriaPorChave(chave) is { } categoria)
        {
            return ClassificarPorCampo(categoria, valor, tipo, texto, caminho, estado);
        }

        // Campo sem nome sensível: o conteúdo é varrido (texto, ou número que pode ser um CPF sem pontuação).
        if (texto is null || (tipo == JsonValueKind.Number && texto.Length < 11))
        {
            return valor.DeepClone();
        }

        return VarrerTexto(texto, caminho, estado, valor);
    }

    private static JsonNode? ClassificarPorCampo(CategoriaPii categoria, JsonValue valor, JsonValueKind tipo, string? texto, string caminho, Estado estado)
    {
        if (tipo == JsonValueKind.Null || (texto is not null && string.IsNullOrWhiteSpace(texto)))
        {
            return valor.DeepClone();
        }

        if (texto is null)
        {
            // Booleano em campo sensível (por exemplo, "possuiDoencaCronica": true) também é informação de saúde.
            estado.Detectar(categoria, caminho, $"campo-{Regra(categoria)}", Confianca.Alta);
            return MascaradorPii.Mascarar(categoria, valor.ToJsonString());
        }

        string regra = $"campo-{Regra(categoria)}";
        Confianca confianca = Confianca.Alta;
        bool formatoCpf = RegrasPii.SomenteDigitos(texto).Length == 11 && CpfOuDigitos().IsMatch(texto.Trim());

        if (categoria == CategoriaPii.Cpf)
        {
            regra += ValidadorCpf.Valido(texto) ? "+dv-valido" : "+dv-invalido";
        }
        else if (categoria == CategoriaPii.DocumentoIdentificador && formatoCpf)
        {
            // "documento": "123.456.789-00" — o campo indica documento e o formato é de CPF.
            categoria = CategoriaPii.Cpf;
            regra = ValidadorCpf.Valido(texto) ? "campo-documento+cpf-dv-valido" : "campo-documento+formato-cpf";
            confianca = ValidadorCpf.Valido(texto) ? Confianca.Alta : Confianca.Media;
        }

        estado.Detectar(categoria, caminho, regra, confianca);
        estado.Registrar(categoria, caminho, texto);
        return MascaradorPii.Mascarar(categoria, texto);
    }

    private static JsonNode? VarrerTexto(string texto, string caminho, Estado estado, JsonValue original)
    {
        List<RegrasPii.Ocorrencia> ocorrencias = RegrasPii.Localizar(texto);
        if (ocorrencias.Count == 0)
        {
            return original.DeepClone();
        }

        foreach (RegrasPii.Ocorrencia o in ocorrencias)
        {
            estado.Detectar(o.Categoria, caminho, o.Regra, o.Confianca);
            estado.Registrar(o.Categoria, caminho, texto.Substring(o.Inicio, o.Tamanho));
        }

        if (ocorrencias.Exists(o => o.Categoria == CategoriaPii.Saude))
        {
            // Relato clínico em texto livre: o campo inteiro é suprimido, não só a expressão encontrada.
            estado.Registrar(CategoriaPii.Saude, caminho, texto);
            return MascaradorPii.MarcadorSaude;
        }

        var sanitizado = new StringBuilder(texto);
        for (int i = ocorrencias.Count - 1; i >= 0; i--)
        {
            RegrasPii.Ocorrencia o = ocorrencias[i];
            sanitizado.Remove(o.Inicio, o.Tamanho).Insert(o.Inicio, MascaradorPii.Mascarar(o.Categoria, texto.Substring(o.Inicio, o.Tamanho)));
        }

        return sanitizado.ToString();
    }

    /// <summary>O próprio nome de um campo pode conter PII (por exemplo, um CPF usado como chave).</summary>
    private static string ChaveSegura(string nome, string caminho, Estado estado)
    {
        List<RegrasPii.Ocorrencia> ocorrencias = RegrasPii.Localizar(nome);
        if (ocorrencias.Count == 0)
        {
            return nome;
        }

        foreach (RegrasPii.Ocorrencia o in ocorrencias)
        {
            estado.Detectar(o.Categoria, $"{caminho}.[nome-do-campo]", o.Regra, o.Confianca);
            estado.Registrar(o.Categoria, caminho, nome.Substring(o.Inicio, o.Tamanho));
        }

        return $"[campo-protegido-{estado.Deteccoes.Count}]";
    }

    private static string CaminhoPropriedade(string caminho, string nome) =>
        IdentificadorSimples().IsMatch(nome) ? $"{caminho}.{nome}" : $"{caminho}['{nome.Replace("'", "\\'", StringComparison.Ordinal)}']";

    private static string Regra(CategoriaPii categoria) => categoria switch
    {
        CategoriaPii.DocumentoIdentificador => "documento",
        _ => categoria.ToString().ToLowerInvariant(),
    };

    /// <summary>Maior nível de aninhamento de objetos e listas, ignorando o conteúdo de strings.</summary>
    internal static int ProfundidadeMaxima(string json)
    {
        int atual = 0;
        int maxima = 0;
        bool emTexto = false;
        bool escape = false;
        foreach (char c in json)
        {
            if (emTexto)
            {
                if (escape)
                {
                    escape = false;
                }
                else if (c == '\\')
                {
                    escape = true;
                }
                else if (c == '"')
                {
                    emTexto = false;
                }

                continue;
            }

            switch (c)
            {
                case '"':
                    emTexto = true;
                    break;
                case '{' or '[':
                    maxima = Math.Max(maxima, ++atual);
                    break;
                case '}' or ']':
                    atual--;
                    break;
            }
        }

        return maxima;
    }

    private static int ContarNos(JsonNode? no, int parada)
    {
        int total = 0;
        var pendentes = new Stack<JsonNode?>();
        pendentes.Push(no);
        while (pendentes.Count > 0 && total < parada)
        {
            JsonNode? atual = pendentes.Pop();
            total++;
            switch (atual)
            {
                case JsonObject objeto:
                    foreach (var (_, filho) in objeto)
                    {
                        pendentes.Push(filho);
                    }

                    break;
                case JsonArray lista:
                    foreach (JsonNode? filho in lista)
                    {
                        pendentes.Push(filho);
                    }

                    break;
            }
        }

        return total;
    }

    [GeneratedRegex(@"\A[A-Za-z_][A-Za-z0-9_]*\z")]
    private static partial Regex IdentificadorSimples();

    [GeneratedRegex(@"\A(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})\z")]
    private static partial Regex CpfOuDigitos();

    private sealed class Estado
    {
        public List<DeteccaoPii> Deteccoes { get; } = [];

        public List<ValorContaminado> Valores { get; } = [];

        public void Detectar(CategoriaPii categoria, string caminho, string regra, Confianca confianca) =>
            Deteccoes.Add(new DeteccaoPii(categoria, CatalogoPii.Sensibilidade(categoria), caminho, regra, confianca, CatalogoPii.Acao(categoria)));

        /// <summary>
        /// Guarda o valor original (e a versão só com dígitos, para documentos e telefones) para o
        /// Taint Analysis. Valores muito curtos não são procurados nas saídas, para não confundir
        /// trechos comuns com o dado protegido; eles continuam mascarados na cópia sanitizada.
        /// </summary>
        public void Registrar(CategoriaPii categoria, string caminho, string valor)
        {
            string limpo = valor.Trim();
            if (limpo.Length >= ContextoTaintLimites.TamanhoMinimoValor)
            {
                Valores.Add(new ValorContaminado(categoria, caminho, limpo));
            }

            if (categoria is CategoriaPii.Cpf or CategoriaPii.Rg or CategoriaPii.Telefone or CategoriaPii.DocumentoIdentificador)
            {
                string digitos = RegrasPii.SomenteDigitos(limpo);
                if (digitos.Length >= 6 && digitos != limpo)
                {
                    Valores.Add(new ValorContaminado(categoria, caminho, digitos));
                }
            }
        }
    }
}

/// <summary>Limites compartilhados entre o motor e o contexto de Taint.</summary>
internal static class ContextoTaintLimites
{
    /// <summary>Valores com menos caracteres não são procurados nas saídas (ver <c>Estado.Registrar</c>).</summary>
    public const int TamanhoMinimoValor = 4;
}
