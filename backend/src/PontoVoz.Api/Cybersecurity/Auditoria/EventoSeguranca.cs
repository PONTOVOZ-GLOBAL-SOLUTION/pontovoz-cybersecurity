using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Api.Cybersecurity.Auditoria;

public static class CodigosEvento
{
    /// <summary>Entrada analisada sem nenhuma informação pessoal.</summary>
    public const string AnaliseSemDeteccao = "PII_ANALISE_SEM_DETECCAO";

    /// <summary>Informação pessoal reconhecida na entrada, classificada e marcada para proteção.</summary>
    public const string PiiDetectado = "PII_DETECTADO_PROTEGIDO";

    /// <summary>Um valor marcado tentou alcançar uma saída e a política o bloqueou ou mascarou.</summary>
    public const string SinkBloqueado = "PII_TAINT_SINK_BLOCKED";

    /// <summary>Entrada recusada sem análise completa (corpo acima do limite ou estrutura excessiva).</summary>
    public const string EntradaRejeitada = "PII_ENTRADA_REJEITADA";
}

public enum NivelRisco
{
    Verde,
    Amarelo,
    Vermelho,
}

public enum OrigemMensagem
{
    /// <summary>Aguardando a tradução pela IA.</summary>
    Pendente,

    /// <summary>Gerada pelo LLM e aprovada pela validação local.</summary>
    Llm,

    /// <summary>Mensagem local usada porque o LLM não estava disponível ou respondeu de forma inadequada.</summary>
    Fallback,

    /// <summary>Evento sem risco: mensagem local fixa, sem chamada à IA.</summary>
    Padrao,
}

/// <summary>
/// Evento de auditoria. Contém apenas metadados (categoria, caminho, fonte, destino, decisão):
/// nenhum valor detectado é guardado. Os textos passam por uma sanitização adicional ao serem registrados.
/// </summary>
public sealed record EventoSeguranca
{
    public required string Id { get; init; }

    public required DateTimeOffset OcorridoEm { get; init; }

    public required string Codigo { get; init; }

    /// <summary>Identificador da requisição: liga a detecção na entrada às interceptações nas saídas.</summary>
    public required string CorrelacaoId { get; init; }

    public required string Fonte { get; init; }

    public required IReadOnlyList<CategoriaPii> Categorias { get; init; }

    public required IReadOnlyList<string> Caminhos { get; init; }

    public TipoSink? TipoDestino { get; init; }

    public string? Destino { get; init; }

    public required DecisaoPolitica Decisao { get; init; }

    public required string Resultado { get; init; }

    public required NivelRisco NivelRisco { get; init; }

    public required string MensagemTecnica { get; init; }

    public int QuantidadeDeteccoes { get; init; }

    public string? MensagemCidadao { get; init; }

    public OrigemMensagem OrigemMensagem { get; init; }

    /// <summary>Por que a mensagem local foi usada (somente para a auditoria técnica).</summary>
    public string? MotivoFallback { get; init; }

    public string? ModeloLlm { get; init; }

    public DateTimeOffset? ExplicadoEm { get; init; }
}

/// <summary>Dados de um novo evento, antes de receber identificador, horário e nível de risco.</summary>
public sealed record NovoEventoSeguranca(
    string Codigo,
    string CorrelacaoId,
    string Fonte,
    IReadOnlyList<CategoriaPii> Categorias,
    IReadOnlyList<string> Caminhos,
    TipoSink? TipoDestino,
    string? Destino,
    DecisaoPolitica Decisao,
    string Resultado,
    string MensagemTecnica,
    int QuantidadeDeteccoes);
