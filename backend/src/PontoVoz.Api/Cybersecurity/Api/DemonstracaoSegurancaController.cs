using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Taint;
using PontoVoz.Api.Security;

namespace PontoVoz.Api.Cybersecurity.Api;

/// <summary>
/// Cenários controlados para o painel. A rota <c>vazamento-controlado</c> contém, de propósito,
/// código inseguro: registra o corpo recebido em log, tenta enviá-lo a um serviço externo e o
/// devolve na resposta (ou numa mensagem de exceção). Serve para provar que as saídas interceptam
/// os valores marcados. Só existe em Development, com <c>Cybersecurity:Demonstracao:Habilitada</c>
/// e para chamadas da própria máquina; nos demais casos responde 404.
/// </summary>
[ApiController]
[Route("api/v1/seguranca/demonstracao")]
[ServiceFilter(typeof(ChaveAdministrativaFilter))]
[ServiceFilter(typeof(DemonstracaoLocalFilter))]
[ApiExplorerSettings(GroupName = CybersecurityExtensions.DocumentoOpenApi)]
[Tags("Cybersecurity · Demonstração")]
public sealed class DemonstracaoSegurancaController(
    GuardaSinks guarda,
    RegistroEventosSeguranca registro,
    ILogger<DemonstracaoSegurancaController> logger) : ControllerBase
{
    /// <summary>Tentativa controlada de levar o cadastro recebido a saídas inseguras.</summary>
    /// <param name="corpo">JSON fictício com dados pessoais.</param>
    /// <param name="modo"><c>resposta</c>: log, serviço externo e eco na resposta. <c>erro</c>: exceção com o cadastro na mensagem.</param>
    [HttpPost("vazamento-controlado")]
    [Consumes("application/json")]
    [ProducesResponseType<JsonObject>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status500InternalServerError, "application/problem+json")]
    public IActionResult VazamentoControlado([FromBody] JsonElement corpo, [FromQuery] string modo = "resposta")
    {
        string cadastro = corpo.GetRawText();

        if (string.Equals(modo, "erro", StringComparison.OrdinalIgnoreCase))
        {
            // Inseguro de propósito: a mensagem da exceção carrega o cadastro inteiro.
            throw new InvalidOperationException($"Falha simulada ao processar o cadastro {cadastro}");
        }

        // Inseguro de propósito: equivalente a logger.info(dados_do_cidadao).
        logger.LogWarning("Demonstração: cadastro recebido registrado em log sem tratamento: {Cadastro}", cadastro);

        string servicoExterno;
        try
        {
            guarda.ExigirSemDadosProtegidos(TipoSink.ServicoExterno, cadastro, "servico-externo:parceiro-ficticio");
            servicoExterno = "enviado";
        }
        catch (SaidaBloqueadaException bloqueio)
        {
            servicoExterno = $"bloqueado (evento {bloqueio.EventoId})";
        }

        // Inseguro de propósito: devolve o cadastro recebido na resposta HTTP.
        return Ok(new JsonObject
        {
            ["aviso"] = "Resposta de demonstração: o código tentou devolver o cadastro recebido sem tratamento.",
            ["servicoExterno"] = servicoExterno,
            ["cadastroDevolvido"] = JsonNode.Parse(cadastro),
        });
    }

    /// <summary>Limpa os eventos e os totais para recomeçar a demonstração no estado verde.</summary>
    [HttpPost("reiniciar")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public IActionResult Reiniciar()
    {
        registro.Reiniciar();
        logger.LogInformation("Painel de segurança reiniciado para nova demonstração.");
        return NoContent();
    }
}

/// <summary>Libera as rotas de demonstração apenas em Development, com a opção ligada e acesso local.</summary>
public sealed class DemonstracaoLocalFilter(IOptions<OpcoesCybersecurity> opcoes, IHostEnvironment ambiente) : IAsyncActionFilter
{
    public static bool Habilitada(OpcoesCybersecurity opcoes, IHostEnvironment ambiente) =>
        ambiente.IsDevelopment() && opcoes.Demonstracao.Habilitada;

    public Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        // Sem endereço remoto conhecido a origem não pode ser confirmada, e a rota não é liberada.
        IPAddress? remoto = context.HttpContext.Connection.RemoteIpAddress;
        bool local = remoto is not null && IPAddress.IsLoopback(remoto);

        if (!Habilitada(opcoes.Value, ambiente) || !local)
        {
            context.Result = new NotFoundResult();
            return Task.CompletedTask;
        }

        return next();
    }
}
