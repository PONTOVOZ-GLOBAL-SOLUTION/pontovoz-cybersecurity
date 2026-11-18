using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PontoVoz.Api.Cybersecurity.Pii;

/// <summary>
/// Metadados de uma ocorrência de informação pessoal. Não contém o valor detectado: pode ser
/// registrado em auditoria, exibido no painel e enviado ao LLM.
/// </summary>
/// <param name="Categoria">Tipo de dado.</param>
/// <param name="Sensibilidade">Grau de proteção exigido.</param>
/// <param name="Caminho">Caminho JSON da ocorrência (por exemplo, <c>$.passageiro.documentos[0].numero</c>).</param>
/// <param name="Regra">Regra que confirmou a detecção (por exemplo, <c>texto-cpf-formatado+dv</c>).</param>
/// <param name="Confianca">Força da evidência.</param>
/// <param name="Acao">Proteção aplicada ao valor.</param>
public sealed record DeteccaoPii(
    CategoriaPii Categoria,
    Sensibilidade Sensibilidade,
    string Caminho,
    string Regra,
    Confianca Confianca,
    AcaoProtecao Acao);

public enum SituacaoAnalise
{
    Analisado,
    CorpoVazio,
    JsonMalformado,
    EstruturaExcessiva,
}

/// <summary>
/// Valor original de uma ocorrência, mantido apenas na memória da requisição para que o Taint
/// Analysis reconheça o dado nas saídas. Não é serializável e o <see cref="ToString"/> não o revela.
/// </summary>
internal sealed class ValorContaminado
{
    public ValorContaminado(CategoriaPii categoria, string caminho, string valor)
    {
        Categoria = categoria;
        Caminho = caminho;
        Valor = valor;
    }

    public CategoriaPii Categoria { get; }

    public string Caminho { get; }

    public string Valor { get; }

    /// <summary>
    /// Formas em que o valor pode aparecer numa saída: o texto original e as versões escapadas
    /// por serializadores JSON, que trocam letras acentuadas por sequências <c>\uXXXX</c>.
    /// </summary>
    public IReadOnlyList<string> Variantes => field ??= CalcularVariantes(Valor);

    private static string[] CalcularVariantes(string valor)
    {
        string padrao = JsonEncodedText.Encode(valor).ToString();
        string relaxado = JsonEncodedText.Encode(valor, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();
        return [.. new[] { valor, padrao, relaxado }.Distinct(StringComparer.Ordinal).OrderByDescending(v => v.Length)];
    }

    public override string ToString() => $"[{CatalogoPii.Rotulo(Categoria)} protegido em {Caminho}]";
}

/// <summary>Resultado de uma análise: as detecções, a cópia sanitizada da entrada e a situação.</summary>
public sealed class ResultadoAnalisePii
{
    internal ResultadoAnalisePii(SituacaoAnalise situacao, IReadOnlyList<DeteccaoPii> deteccoes, JsonNode? sanitizado, string? textoSanitizado, IReadOnlyList<ValorContaminado> valores)
    {
        Situacao = situacao;
        Deteccoes = deteccoes;
        Sanitizado = sanitizado;
        TextoSanitizado = textoSanitizado;
        Valores = valores;
    }

    public SituacaoAnalise Situacao { get; }

    public IReadOnlyList<DeteccaoPii> Deteccoes { get; }

    /// <summary>Cópia do JSON com os valores sensíveis mascarados ou suprimidos (nula se a entrada não era JSON válido).</summary>
    public JsonNode? Sanitizado { get; }

    /// <summary>Texto da entrada com as ocorrências substituídas, seguro para log e exibição.</summary>
    public string? TextoSanitizado { get; }

    public bool PossuiPii => Deteccoes.Count > 0;

    internal IReadOnlyList<ValorContaminado> Valores { get; }

    internal static ResultadoAnalisePii Vazio(SituacaoAnalise situacao) => new(situacao, [], null, null, []);
}
