using System.Net;
using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

using PontoVoz.Api.Cybersecurity;
using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.IA;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>
/// Dados fictícios usados em todos os testes do módulo. Os CPFs têm dígitos verificadores
/// válidos, mas são sequências de exemplo (123.456.789-09 e 111.444.777-35).
/// </summary>
internal static class DadosFicticios
{
    public const string Cpf = "111.444.777-35";
    public const string CpfSemPontuacao = "11144477735";
    public const string CpfSequencia = "123.456.789-09";
    public const string CpfInvalido = "123.456.789-00";
    public const string Rg = "12.345.678-X";
    public const string Email = "passageiro.ficticio@exemplo.com.br";
    public const string Telefone = "(11) 91234-5678";
    public const string Senha = "Senha@Teste123";
    public const string Laudo = "CID-10 E11 diabetes tipo 2 (dado fictício)";

    /// <summary>Valores que nunca podem aparecer em saídas, logs ou auditoria.</summary>
    public static readonly string[] Originais = [Cpf, CpfSemPontuacao, CpfSequencia, Rg, Email, Telefone, Senha, Laudo, "diabetes tipo 2"];

    public static string CadastroCompleto => $$"""
        {
          "cpf": "{{Cpf}}",
          "rg": "{{Rg}}",
          "senha": "{{Senha}}",
          "saude": { "condicao": "{{Laudo}}" },
          "email": "{{Email}}",
          "telefone": "{{Telefone}}"
        }
        """;

    public static void AssertSemOriginais(string texto)
    {
        foreach (string original in Originais)
        {
            Assert.DoesNotContain(original, texto, StringComparison.Ordinal);
        }
    }
}

/// <summary>Monta as peças do módulo sem a API: motor, registro, guarda e um HttpContext controlado.</summary>
internal sealed class ModuloSegurancaTeste
{
    public ModuloSegurancaTeste(OpcoesCybersecurity? opcoes = null, DateTimeOffset? agora = null)
    {
        Opcoes = Options.Create(opcoes ?? new OpcoesCybersecurity());
        Relogio = new FakeTimeProvider(agora ?? new DateTimeOffset(2026, 11, 18, 20, 0, 0, TimeSpan.FromHours(-3)));
        Motor = new MotorPii(Opcoes);
        Fila = new FilaExplicacoes();
        Registro = new RegistroEventosSeguranca(Opcoes, Relogio, Fila, NullLogger<RegistroEventosSeguranca>.Instance);
        Acessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        Guarda = new GuardaSinks(Acessor, Registro);
    }

    public IOptions<OpcoesCybersecurity> Opcoes { get; }

    public FakeTimeProvider Relogio { get; }

    public MotorPii Motor { get; }

    public FilaExplicacoes Fila { get; }

    public RegistroEventosSeguranca Registro { get; }

    public HttpContextAccessor Acessor { get; }

    public GuardaSinks Guarda { get; }

    /// <summary>Simula a entrada de uma requisição: analisa o JSON e contamina o contexto, como o interceptador.</summary>
    public ContextoTaint Contaminar(string json, string fonte = "POST /api/teste")
    {
        var contexto = new ContextoTaint("req-teste", fonte);
        contexto.Contaminar(Motor.AnalisarJson(json), InterceptadorDadosPessoais.FonteCorpoJson);
        Acessor.HttpContext!.Features.Set(contexto);
        return contexto;
    }

    public void SemRequisicao() => Acessor.HttpContext = null;
}

/// <summary>Cliente de LLM programável para os testes da tradução.</summary>
internal sealed class ClienteLlmFalso(Func<PromptRisco, string> responder, bool configurado = true) : IClienteLlm
{
    // Também é chamado pela tradução automática, em segundo plano.
    public System.Collections.Concurrent.ConcurrentQueue<PromptRisco> Prompts { get; } = new();

    public string Provedor => "Falso";

    public string Modelo => "modelo-teste";

    public bool Configurado => configurado;

    public Task<string> GerarAsync(PromptRisco prompt, CancellationToken cancellationToken)
    {
        Prompts.Enqueue(prompt);
        return Task.FromResult(responder(prompt));
    }
}

/// <summary>Manipulador HTTP que registra as requisições e devolve a resposta programada.</summary>
internal sealed class ManipuladorHttpFalso(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder) : HttpMessageHandler
{
    public List<(HttpRequestMessage Requisicao, string Corpo)> Recebidas { get; } = [];

    public static ManipuladorHttpFalso Json(HttpStatusCode status, string corpo) =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(corpo, Encoding.UTF8, "application/json") }));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string corpo = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Recebidas.Add((request, corpo));
        return await responder(request, cancellationToken);
    }
}
