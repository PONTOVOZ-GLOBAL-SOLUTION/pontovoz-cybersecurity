using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Sinks;
using PontoVoz.Api.Cybersecurity.Taint;
using PontoVoz.Tests.Api;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>
/// Provedor de log que, como o console com escopos habilitados ou o formatador JSON, escreve os
/// escopos ativos junto de cada mensagem. Serve para verificar o que chega ao destino final.
/// </summary>
internal sealed class LogsComEscopo : ILoggerProvider, ISupportExternalScope
{
    private IExternalScopeProvider? _escopos;

    public ConcurrentQueue<string> Linhas { get; } = new();

    public string TextoCompleto => string.Join(Environment.NewLine, Linhas);

    public ILogger CreateLogger(string categoryName) => new Registrador(this);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _escopos = scopeProvider;

    public void Dispose()
    {
    }

    private sealed class Registrador(LogsComEscopo dono) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => dono._escopos?.Push(state);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var linha = new StringBuilder(formatter(state, exception));
            dono._escopos?.ForEachScope((escopo, destino) =>
            {
                destino.Append(" => ").Append(escopo);
                if (escopo is IEnumerable<KeyValuePair<string, object?>> pares)
                {
                    foreach (var (chave, valor) in pares)
                    {
                        destino.Append(' ').Append(chave).Append('=').Append(valor);
                    }
                }
            }, linha);
            dono.Linhas.Enqueue(linha.ToString());
        }
    }
}

/// <summary>Pontos verificados na auditoria final: escopos de log, formulário multipart e acesso às rotas de demonstração.</summary>
public sealed class AuditoriaFinalTests
{
    private static CancellationToken Ct => ApiTeste.Ct;

    [Fact]
    public void EscopoDeLogComDadoContaminado_ChegaSanitizadoAoProvedor()
    {
        var modulo = new ModuloSegurancaTeste();
        var logs = new LogsComEscopo();
        var servicos = new ServiceCollection();
        servicos.AddSingleton(modulo.Guarda);
        servicos.AddLogging(logging => logging.AddProvider(logs));
        servicos.ProtegerSinksDeLog();
        using ServiceProvider provedor = servicos.BuildServiceProvider();
        modulo.Contaminar(DadosFicticios.CadastroCompleto);
        ILogger logger = provedor.GetRequiredService<ILoggerFactory>().CreateLogger("Teste");

        using (logger.BeginScope("Passageiro {Cpf} senha {Senha}", DadosFicticios.Cpf, DadosFicticios.Senha))
        using (logger.BeginScope(new Dictionary<string, object?> { ["email"] = DadosFicticios.Email }))
        {
            logger.LogInformation("Consulta registrada.");
        }

        string texto = logs.TextoCompleto;
        Assert.Contains("Consulta registrada.", texto, StringComparison.Ordinal);
        Assert.Contains("***.444.***-35", texto, StringComparison.Ordinal);
        DadosFicticios.AssertSemOriginais(texto);
        Assert.Contains(modulo.Registro.Listar(), e => e.Destino!.StartsWith("log-escopo:", StringComparison.Ordinal));
    }

    [Fact]
    public void EscopoSemDadoProtegido_PermaneceEstruturado()
    {
        var modulo = new ModuloSegurancaTeste();
        var logs = new LogsComEscopo();
        var servicos = new ServiceCollection();
        servicos.AddSingleton(modulo.Guarda);
        servicos.AddLogging(logging => logging.AddProvider(logs));
        servicos.ProtegerSinksDeLog();
        using ServiceProvider provedor = servicos.BuildServiceProvider();
        ILogger logger = provedor.GetRequiredService<ILoggerFactory>().CreateLogger("Teste");

        using (logger.BeginScope(new Dictionary<string, object?> { ["parada"] = "SIM-P001" }))
        {
            logger.LogInformation("ok");
        }

        Assert.Contains("parada=SIM-P001", logs.TextoCompleto, StringComparison.Ordinal);
        Assert.Empty(modulo.Registro.Listar());
    }

    [Fact]
    public async Task FormularioMultipart_TemOsCamposDeTextoAnalisadosPeloNome()
    {
        await using ApiTeste api = await CriarAsync();
        using var formulario = new MultipartFormDataContent
        {
            { new StringContent(DadosFicticios.Senha), "senha" },
            { new StringContent("Passageiro Fictício"), "nome" },
            { new StringContent($"contato {DadosFicticios.Email}"), "observacao" },
        };
        using HttpClient cliente = api.Cliente();

        using HttpResponseMessage resposta = await cliente.PostAsync(new Uri("/api/v1/admin/linhas", UriKind.Relative), formulario, Ct);

        EventoSeguranca deteccao = Assert.Single(Registro(api).Listar(), e => e.Codigo == CodigosEvento.PiiDetectado);
        Assert.Contains("campo-senha", deteccao.MensagemTecnica, StringComparison.Ordinal);
        Assert.Contains("$.senha", deteccao.Caminhos);
        Assert.Contains("$.observacao", deteccao.Caminhos);
        Assert.Contains(InterceptadorDadosPessoais.FonteMultipart, deteccao.MensagemTecnica, StringComparison.Ordinal);
        DadosFicticios.AssertSemOriginais(await resposta.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task FormularioMultipart_ArquivoAnexadoNaoEhLidoComoCampo()
    {
        await using ApiTeste api = await CriarAsync();
        var arquivo = new ByteArrayContent(Encoding.UTF8.GetBytes("conteudo qualquer"));
        arquivo.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var formulario = new MultipartFormDataContent { { arquivo, "anexo", "documento.bin" }, { new StringContent("SIM-P001"), "parada" } };
        using HttpClient cliente = api.Cliente();

        await cliente.PostAsync(new Uri("/api/v1/admin/linhas", UriKind.Relative), formulario, Ct);

        EventoSeguranca evento = Assert.Single(Registro(api).Listar());
        Assert.Equal(CodigosEvento.AnaliseSemDeteccao, evento.Codigo);
    }

    [Theory]
    [InlineData(null, HttpStatusCode.NotFound)]
    [InlineData("10.0.0.25", HttpStatusCode.NotFound)]
    [InlineData("127.0.0.1", HttpStatusCode.NoContent)]
    [InlineData("::1", HttpStatusCode.NoContent)]
    public async Task RotasDeDemonstracao_SoAtendemChamadasDaPropriaMaquina(string? enderecoRemoto, HttpStatusCode esperado)
    {
        await using ApiTeste api = await CriarAsync(enderecoRemoto, simularEndereco: true);

        ApiTeste.Resposta resposta = await api.EnviarAsync(HttpMethod.Post, "/api/v1/seguranca/demonstracao/reiniciar");

        Assert.Equal(esperado, resposta.Status);
    }

    [Fact]
    public async Task RespostaSemContentType_TambemPassaPelaProtecao()
    {
        await using ApiTeste api = await CriarAsync(configurarApp: app => app.Map("/api/teste-sem-tipo", ramo => ramo.Run(async contexto =>
        {
            // Escreve o corpo recebido de volta, sem declarar Content-Type.
            contexto.Request.EnableBuffering();
            using var leitor = new StreamReader(contexto.Request.Body);
            await contexto.Response.WriteAsync(await leitor.ReadToEndAsync(), contexto.RequestAborted);
        })));

        ApiTeste.Resposta resposta = await api.EnviarAsync(HttpMethod.Post, "/api/teste-sem-tipo", DadosFicticios.CadastroCompleto);

        Assert.Null(resposta.ContentType);
        DadosFicticios.AssertSemOriginais(resposta.Corpo);
    }

    private static RegistroEventosSeguranca Registro(ApiTeste api) => api.Fabrica.Services.GetRequiredService<RegistroEventosSeguranca>();

    private static Task<ApiTeste> CriarAsync(string? enderecoRemoto = "127.0.0.1", bool simularEndereco = true, Action<IApplicationBuilder>? configurarApp = null) =>
        ApiTeste.CriarAsync(builder =>
        {
            builder.UseSetting("Cybersecurity:Llm:Provedor", "Nenhum");
            builder.ConfigureTestServices(services =>
            {
                if (simularEndereco)
                {
                    services.AddSingleton<IStartupFilter>(new EnderecoRemotoSimulado(enderecoRemoto, configurarApp));
                }
            });
        });
}

/// <summary>
/// O servidor de testes não informa o endereço remoto; este filtro define um, como o Kestrel faria,
/// e permite acrescentar rotas de teste dentro do pipeline real (depois do interceptador).
/// </summary>
internal sealed class EnderecoRemotoSimulado(string? endereco, Action<IApplicationBuilder>? configurarApp) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use((contexto, proximo) =>
        {
            contexto.Connection.RemoteIpAddress = endereco is null ? null : IPAddress.Parse(endereco);
            return proximo(contexto);
        });
        next(app);
        configurarApp?.Invoke(app);
    };
}
