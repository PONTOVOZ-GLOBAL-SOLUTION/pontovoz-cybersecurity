using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Pii;

namespace PontoVoz.Api.Cybersecurity.Taint;

/// <summary>Resultado da verificação de uma saída.</summary>
/// <param name="Interceptado">Verdadeiro se havia conteúdo protegido a caminho da saída.</param>
/// <param name="Conteudo">O que a saída pode receber (o original, se nada foi interceptado).</param>
/// <param name="Decisao">Decisão mais restritiva aplicada.</param>
/// <param name="EventoId">Evento de auditoria registrado, quando houve interceptação.</param>
public sealed record ResultadoProtecaoSink(bool Interceptado, string Conteudo, DecisaoPolitica Decisao, string? EventoId);

/// <summary>Operação recusada porque levaria um valor protegido a uma saída não autorizada.</summary>
public sealed class SaidaBloqueadaException(TipoSink sink, string? eventoId)
    : Exception($"Saída {sink} bloqueada pela política de proteção de dados pessoais (evento {eventoId}).")
{
    public TipoSink Sink { get; } = sink;

    public string? EventoId { get; } = eventoId;
}

/// <summary>
/// Camada de validação antes das saídas. Combina duas verificações:
/// <list type="number">
/// <item><b>Taint:</b> procura no conteúdo os valores marcados na entrada da requisição atual,
/// inclusive quando aparecem dentro de outro texto (concatenação, mensagem de exceção).</item>
/// <item><b>Padrões:</b> aplica as regras do motor PII ao conteúdo, para dados que não passaram
/// por uma fonte rastreada.</item>
/// </list>
/// Cada interceptação aplica <see cref="PoliticaSinks"/> e gera um evento <c>PII_TAINT_SINK_BLOCKED</c>.
/// </summary>
public sealed class GuardaSinks(IHttpContextAccessor acessorHttp, RegistroEventosSeguranca registro)
{
    public ContextoTaint? ContextoAtual => acessorHttp.HttpContext?.Features.Get<ContextoTaint>();

    /// <summary>
    /// Saídas de fluxo (log, resposta): devolve o conteúdo que pode seguir. Com
    /// <paramref name="verificarPadroes"/> falso, só os valores marcados na entrada são procurados.
    /// </summary>
    public ResultadoProtecaoSink Proteger(TipoSink sink, string conteudo, string destino, bool verificarPadroes = true)
    {
        ArgumentNullException.ThrowIfNull(conteudo);
        ContextoTaint? contexto = ContextoAtual;
        var categorias = new HashSet<CategoriaPii>();
        var caminhos = new HashSet<string>(StringComparer.Ordinal);
        DecisaoPolitica decisao = DecisaoPolitica.Permitir;
        string resultado = conteudo;

        if (contexto is { Estado: EstadoTaint.Contaminado })
        {
            foreach (ValorContaminado valor in contexto.Valores)
            {
                foreach (string variante in valor.Variantes)
                {
                    if (!resultado.Contains(variante, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    DecisaoPolitica decisaoValor = PoliticaSinks.Decidir(sink, CatalogoPii.Sensibilidade(valor.Categoria));
                    resultado = resultado.Replace(variante, PoliticaSinks.Substituto(decisaoValor, valor.Categoria, valor.Valor), StringComparison.Ordinal);
                    categorias.Add(valor.Categoria);
                    caminhos.Add(valor.Caminho);
                    decisao = Mais(decisao, decisaoValor);
                }
            }
        }

        var categoriasPadrao = new List<CategoriaPii>();
        if (verificarPadroes)
        {
            resultado = MotorPii.Substituir(resultado, (categoria, valor) =>
            {
                DecisaoPolitica decisaoValor = PoliticaSinks.Decidir(sink, CatalogoPii.Sensibilidade(categoria));
                decisao = Mais(decisao, decisaoValor);
                return PoliticaSinks.Substituto(decisaoValor, categoria, valor);
            }, categoriasPadrao);
        }

        if (categoriasPadrao.Count > 0)
        {
            categorias.UnionWith(categoriasPadrao);
            caminhos.Add("conteudo-da-saida");
        }

        if (categorias.Count == 0)
        {
            return new ResultadoProtecaoSink(false, conteudo, DecisaoPolitica.Permitir, null);
        }

        EventoSeguranca evento = registro.Registrar(new NovoEventoSeguranca(
            Codigo: CodigosEvento.SinkBloqueado,
            CorrelacaoId: contexto?.CorrelacaoId ?? "processo-interno",
            Fonte: contexto?.Fonte ?? "processo interno (sem requisição)",
            Categorias: [.. categorias.Order()],
            Caminhos: [.. caminhos.Order(StringComparer.Ordinal)],
            TipoDestino: sink,
            Destino: destino,
            Decisao: decisao,
            Resultado: decisao == DecisaoPolitica.Bloquear
                ? "O valor original foi substituído por um marcador de bloqueio; nenhum trecho do conteúdo protegido chegou ao destino."
                : "O valor original foi substituído pela versão mascarada antes de chegar ao destino.",
            MensagemTecnica: $"{CodigosEvento.SinkBloqueado}: {string.Join(", ", categorias.Order())} a caminho de {sink} ({destino}); política aplicada: {decisao}.",
            QuantidadeDeteccoes: categorias.Count));

        return new ResultadoProtecaoSink(true, resultado, decisao, evento.Id);
    }

    /// <summary>
    /// Saídas transacionais (persistência, serviço externo): lança <see cref="SaidaBloqueadaException"/>
    /// se o conteúdo levaria um valor protegido ao destino. Nada é enviado ou gravado nesse caso.
    /// </summary>
    public void ExigirSemDadosProtegidos(TipoSink sink, string conteudo, string destino, bool verificarPadroes = true)
    {
        ResultadoProtecaoSink resultado = Proteger(sink, conteudo, destino, verificarPadroes);
        if (resultado.Interceptado)
        {
            throw new SaidaBloqueadaException(sink, resultado.EventoId);
        }
    }

    private static DecisaoPolitica Mais(DecisaoPolitica a, DecisaoPolitica b) => (DecisaoPolitica)Math.Max((int)a, (int)b);
}
