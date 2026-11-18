using System.Text.Json.Nodes;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.IA;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Taint;
using PontoVoz.Api.Security;

namespace PontoVoz.Api.Cybersecurity.Api;

/// <summary>
/// Dados do painel Risco Cidadão e da auditoria técnica. Protegido pela mesma chave das rotas
/// administrativas (<c>X-PontoVoz-Admin-Key</c>): fora de Development, sem chave configurada, responde 403.
/// </summary>
[ApiController]
[Route("api/v1/seguranca")]
[ServiceFilter(typeof(ChaveAdministrativaFilter))]
[ApiExplorerSettings(GroupName = CybersecurityExtensions.DocumentoOpenApi)]
[Tags("Cybersecurity")]
public sealed class SegurancaController(
    RegistroEventosSeguranca registro,
    TradutorRiscoCidadao tradutor,
    IClienteLlm cliente,
    IOptions<OpcoesCybersecurity> opcoes,
    IHostEnvironment ambiente,
    TimeProvider relogio) : ControllerBase
{
    /// <summary>Estado do painel: indicador de Risco Cidadão, totais, eventos recentes e situação da IA.</summary>
    [HttpGet("painel")]
    [ProducesResponseType<PainelSegurancaDto>(StatusCodes.Status200OK)]
    public ActionResult<PainelSegurancaDto> Painel([FromQuery] int limite = 30)
    {
        AvaliacaoRisco risco = registro.AvaliarRisco();
        EventoSeguranca? referencia = risco.EventoReferenciaId is null ? null : registro.Obter(risco.EventoReferenciaId);
        string mensagem = referencia?.MensagemCidadao
            ?? (referencia is null ? MensagensLocais.Para(CodigosEvento.AnaliseSemDeteccao, []) : "Preparando a explicação deste evento...");

        return new PainelSegurancaDto(
            Modulo: "PontoVoz · Cybersecurity",
            Risco: new RiscoCidadaoDto(risco.Nivel, risco.Titulo, risco.Descricao, mensagem, referencia?.OrigemMensagem ?? OrigemMensagem.Padrao, risco.EventoReferenciaId, risco.JanelaMinutos),
            Indicadores: registro.Indicadores(),
            Eventos: registro.Listar(limite),
            Ia: new SituacaoIaDto(cliente.Provedor, cliente.Modelo, cliente.Configurado),
            DemonstracaoHabilitada: DemonstracaoLocalFilter.Habilitada(opcoes.Value, ambiente),
            GeradoEm: relogio.GetUtcNow());
    }

    /// <summary>Eventos de auditoria mais recentes, do mais novo para o mais antigo.</summary>
    [HttpGet("eventos")]
    [ProducesResponseType<IReadOnlyList<EventoSeguranca>>(StatusCodes.Status200OK)]
    public ActionResult<IReadOnlyList<EventoSeguranca>> Eventos([FromQuery] int limite = 50) => Ok(registro.Listar(limite));

    /// <summary>Um evento e a trilha completa da mesma requisição (entrada, classificação e saídas).</summary>
    [HttpGet("eventos/{id}")]
    [ProducesResponseType<TrilhaEventoDto>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status404NotFound, "application/problem+json")]
    public ActionResult<TrilhaEventoDto> Evento(string id)
    {
        EventoSeguranca? evento = registro.Obter(id);
        return evento is null
            ? Problem(statusCode: StatusCodes.Status404NotFound, title: "Evento não encontrado", detail: "Nenhum evento de segurança com o identificador informado.")
            : new TrilhaEventoDto(evento, registro.DaCorrelacao(evento.CorrelacaoId));
    }

    /// <summary>
    /// Analisa um JSON com o motor PII e devolve a classificação e a cópia mascarada. A análise é
    /// a mesma feita pelo interceptador na entrada da requisição; nenhum valor original é devolvido.
    /// </summary>
    [HttpPost("analises")]
    [Consumes("application/json")]
    [ProducesResponseType<AnalisePiiDto>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, "application/problem+json")]
    public ActionResult<AnalisePiiDto> Analisar()
    {
        ContextoTaint? taint = HttpContext.Features.Get<ContextoTaint>();
        ResultadoAnalisePii? analise = taint?.AnaliseCorpo;
        if (taint is null || analise is null || analise.Situacao == SituacaoAnalise.CorpoVazio)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "Corpo ausente", detail: "Envie um corpo JSON para análise.");
        }

        return new AnalisePiiDto(analise.Situacao, analise.Deteccoes.Count, analise.Deteccoes, analise.Sanitizado, analise.Sanitizado is null ? analise.TextoSanitizado : null,
            taint.Estado, taint.Marcas, taint.CorrelacaoId, [.. registro.DaCorrelacao(taint.CorrelacaoId).Select(e => e.Id)]);
    }

    /// <summary>
    /// Gera agora a explicação do evento pela IA (sem reaproveitar mensagens anteriores) e devolve
    /// a estrutura sanitizada enviada ao provedor. Sem chave configurada, devolve o fallback identificado.
    /// </summary>
    [HttpPost("eventos/{id}/explicacao")]
    [ProducesResponseType<ExplicacaoEventoDto>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status404NotFound, "application/problem+json")]
    public async Task<ActionResult<ExplicacaoEventoDto>> Explicar(string id, CancellationToken cancellationToken)
    {
        EventoSeguranca? evento = registro.Obter(id);
        if (evento is null)
        {
            return Problem(statusCode: StatusCodes.Status404NotFound, title: "Evento não encontrado", detail: "Nenhum evento de segurança com o identificador informado.");
        }

        ResultadoTraducao resultado = await tradutor.ExplicarAsync(evento, reutilizar: false, cancellationToken);
        EventoSeguranca atualizado = registro.AtualizarExplicacao(id, resultado.Explicacao) ?? evento;
        PromptRisco prompt = ConstrutorPromptRisco.Montar(resultado.DadosEnviados);
        return new ExplicacaoEventoDto(atualizado, resultado.DadosEnviados, prompt.Mensagem, resultado.ChamadaExternaRealizada, cliente.Provedor, cliente.Configurado);
    }

    /// <summary>Exportação da trilha de auditoria em memória, para anexar como evidência.</summary>
    [HttpGet("auditoria")]
    [ProducesResponseType<AuditoriaDto>(StatusCodes.Status200OK)]
    public ActionResult<AuditoriaDto> Auditoria() =>
        new AuditoriaDto(relogio.GetUtcNow(), registro.Indicadores(), registro.AvaliarRisco(), registro.Listar(opcoes.Value.CapacidadeEventos));
}

public sealed record RiscoCidadaoDto(NivelRisco Nivel, string Titulo, string Descricao, string MensagemCidadao, OrigemMensagem OrigemMensagem, string? EventoReferenciaId, int JanelaMinutos);

public sealed record SituacaoIaDto(string Provedor, string Modelo, bool ChaveConfigurada);

public sealed record PainelSegurancaDto(
    string Modulo,
    RiscoCidadaoDto Risco,
    IndicadoresSeguranca Indicadores,
    IReadOnlyList<EventoSeguranca> Eventos,
    SituacaoIaDto Ia,
    bool DemonstracaoHabilitada,
    DateTimeOffset GeradoEm);

public sealed record TrilhaEventoDto(EventoSeguranca Evento, IReadOnlyList<EventoSeguranca> MesmaRequisicao);

public sealed record AnalisePiiDto(
    SituacaoAnalise Situacao,
    int QuantidadeDeteccoes,
    IReadOnlyList<DeteccaoPii> Deteccoes,
    JsonNode? CorpoSanitizado,
    string? TextoSanitizado,
    EstadoTaint EstadoTaint,
    IReadOnlyList<MarcaTaint> Marcas,
    string CorrelacaoId,
    IReadOnlyList<string> Eventos);

public sealed record ExplicacaoEventoDto(
    EventoSeguranca Evento,
    DadosPromptRisco DadosEnviadosAoLlm,
    string PromptUsuario,
    bool ChamadaExternaRealizada,
    string Provedor,
    bool ChaveConfigurada);

public sealed record AuditoriaDto(DateTimeOffset ExportadoEm, IndicadoresSeguranca Indicadores, AvaliacaoRisco Risco, IReadOnlyList<EventoSeguranca> Eventos);
