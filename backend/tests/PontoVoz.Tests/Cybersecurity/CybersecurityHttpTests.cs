using System.Net;
using System.Text;
using System.Text.Json.Nodes;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.IA;
using PontoVoz.Api.Cybersecurity.Sinks;
using PontoVoz.Api.Cybersecurity.Taint;
using PontoVoz.Api.Infrastructure.Persistence;
using PontoVoz.Tests.Api;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>
/// O módulo na API real, em memória: interceptador, sinks de log, resposta e persistência,
/// rotas do painel e cenários de demonstração. Nenhum teste chama um provedor de LLM real.
/// </summary>
public sealed class CybersecurityHttpTests
{
    private const string Analises = "/api/v1/seguranca/analises";
    private const string Vazamento = "/api/v1/seguranca/demonstracao/vazamento-controlado";

    private static CancellationToken Ct => ApiTeste.Ct;

    private sealed record Ambiente(ApiTeste Api, LogsEmMemoria Logs) : IAsyncDisposable
    {
        public RegistroEventosSeguranca Registro => Api.Fabrica.Services.GetRequiredService<RegistroEventosSeguranca>();

        public ValueTask DisposeAsync() => Api.DisposeAsync();
    }

    private static async Task<Ambiente> CriarAsync(IClienteLlm? cliente = null, string ambiente = "Development", string? chave = null, bool demonstracao = true)
    {
        var logs = new LogsEmMemoria();
        ApiTeste api = await ApiTeste.CriarAsync(builder =>
        {
            builder.UseSetting("Cybersecurity:Llm:Provedor", "Nenhum");
            builder.UseSetting("Cybersecurity:Demonstracao:Habilitada", demonstracao ? "true" : "false");
            builder.ConfigureLogging(logging => logging.AddProvider(logs));
            builder.ConfigureTestServices(services =>
            {
                if (cliente is not null)
                {
                    services.AddTransient(_ => cliente);
                }

                // O provedor de teste entra depois do Program.cs; recebe a mesma proteção dos demais.
                services.ProtegerSinksDeLog();

                // Como o Kestrel local, o servidor em memória passa a informar o endereço de loopback.
                services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new EnderecoRemotoSimulado("127.0.0.1", null));
            });
        }, chaveAdministrativa: chave, ambiente: ambiente);
        return new Ambiente(api, logs);
    }

    private static async Task<T> AguardarAsync<T>(Func<T?> obter, Func<T, bool> condicao)
        where T : class
    {
        for (int tentativa = 0; tentativa < 100; tentativa++)
        {
            if (obter() is { } valor && condicao(valor))
            {
                return valor;
            }

            await Task.Delay(50, Ct);
        }

        throw new TimeoutException("A condição esperada não ocorreu.");
    }

    [Fact]
    public async Task ConsultaPublica_ContinuaIgual_ERegistraAnaliseSemRisco()
    {
        await using Ambiente amb = await CriarAsync();

        ApiTeste.Resposta resposta = await amb.Api.GetAsync("/api/v1/paradas?codigoExterno=SIM-P001");

        Assert.Equal(HttpStatusCode.OK, resposta.Status);
        Assert.Equal("SIM-P001", resposta.Json["itens"]![0]!["codigoExterno"]!.GetValue<string>());
        Assert.False(resposta.Cabecalhos.Contains("X-PontoVoz-Protecao"));
        EventoSeguranca evento = Assert.Single(amb.Registro.Listar());
        Assert.Equal(CodigosEvento.AnaliseSemDeteccao, evento.Codigo);
        Assert.Equal(NivelRisco.Verde, amb.Registro.AvaliarRisco().Nivel);
    }

    [Fact]
    public async Task PainelInicial_EstaVerde_ComMensagemPadrao()
    {
        await using Ambiente amb = await CriarAsync();

        JsonNode painel = (await amb.Api.GetAsync("/api/v1/seguranca/painel")).Json;

        Assert.Equal("Verde", painel["risco"]!["nivel"]!.GetValue<string>());
        Assert.Equal(0, painel["indicadores"]!["eventosAnalisados"]!.GetValue<int>());
        Assert.Equal("Nenhum", painel["ia"]!["provedor"]!.GetValue<string>());
        Assert.True(painel["demonstracaoHabilitada"]!.GetValue<bool>());
        // A leitura do próprio painel não conta como evento.
        Assert.Empty(amb.Registro.Listar());
    }

    [Fact]
    public async Task AnaliseDeJson_ClassificaEMascara_SemDevolverValorOriginal()
    {
        await using Ambiente amb = await CriarAsync();

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, Analises, DadosFicticios.CadastroCompleto);

        Assert.Equal(HttpStatusCode.OK, resposta.Status);
        Assert.Equal(6, resposta.Json["quantidadeDeteccoes"]!.GetValue<int>());
        Assert.Equal("Contaminado", resposta.Json["estadoTaint"]!.GetValue<string>());
        Assert.Equal("***.444.***-35", resposta.Json["corpoSanitizado"]!["cpf"]!.GetValue<string>());
        DadosFicticios.AssertSemOriginais(resposta.Corpo);
        DadosFicticios.AssertSemOriginais(amb.Logs.TextoCompleto);
        Assert.Contains("Corpo protegido:", amb.Logs.TextoCompleto, StringComparison.Ordinal);
        Assert.Equal(NivelRisco.Amarelo, amb.Registro.AvaliarRisco().Nivel);
    }

    [Fact]
    public async Task VazamentoControlado_BloqueiaLogServicoExternoEResposta()
    {
        await using Ambiente amb = await CriarAsync();

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, Vazamento, DadosFicticios.CadastroCompleto);

        Assert.Equal(HttpStatusCode.OK, resposta.Status);
        DadosFicticios.AssertSemOriginais(resposta.Corpo);
        JsonNode devolvido = resposta.Json["cadastroDevolvido"]!;
        Assert.Equal("***.444.***-35", devolvido["cpf"]!.GetValue<string>());
        Assert.Equal("[BLOQUEADO: SENHA]", devolvido["senha"]!.GetValue<string>());
        Assert.Equal("[BLOQUEADO: INFORMAÇÃO DE SAÚDE]", devolvido["saude"]!["condicao"]!.GetValue<string>());
        Assert.StartsWith("bloqueado", resposta.Json["servicoExterno"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.StartsWith("resposta-sanitizada", resposta.Cabecalhos.GetValues("X-PontoVoz-Protecao").Single(), StringComparison.Ordinal);

        DadosFicticios.AssertSemOriginais(amb.Logs.TextoCompleto);
        Assert.Contains("registrado em log sem tratamento", amb.Logs.TextoCompleto, StringComparison.Ordinal);

        IReadOnlyList<EventoSeguranca> eventos = amb.Registro.Listar();
        Assert.Equal(
            [TipoSink.Log, TipoSink.ServicoExterno, TipoSink.RespostaHttp],
            eventos.Where(e => e.Codigo == CodigosEvento.SinkBloqueado).Reverse().Select(e => e.TipoDestino!.Value));
        Assert.Single(eventos, e => e.Codigo == CodigosEvento.PiiDetectado);
        Assert.All(eventos, e => Assert.Equal(eventos[0].CorrelacaoId, e.CorrelacaoId));
        Assert.Equal(NivelRisco.Vermelho, amb.Registro.AvaliarRisco().Nivel);
        DadosFicticios.AssertSemOriginais((await amb.Api.GetAsync("/api/v1/seguranca/auditoria")).Corpo);
    }

    [Fact]
    public async Task ExcecaoComPayload_ViraErroGenerico_ELogSanitizado()
    {
        await using Ambiente amb = await CriarAsync();

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, $"{Vazamento}?modo=erro", DadosFicticios.CadastroCompleto);

        Assert.Equal(HttpStatusCode.InternalServerError, resposta.Status);
        Assert.Equal("ErroInterno", resposta.Json["codigo"]!.GetValue<string>());
        DadosFicticios.AssertSemOriginais(resposta.Corpo);
        Assert.Contains("Falha simulada ao processar o cadastro", amb.Logs.TextoCompleto, StringComparison.Ordinal);
        DadosFicticios.AssertSemOriginais(amb.Logs.TextoCompleto);
        Assert.Contains(amb.Registro.Listar(), e => e.Codigo == CodigosEvento.SinkBloqueado && e.TipoDestino == TipoSink.Log);
    }

    [Fact]
    public async Task RotaRealComCpfNoCampoDeOrigem_TemAGravacaoRecusada()
    {
        await using Ambiente amb = await CriarAsync();
        int paradaId = await amb.Api.IdDaParadaAsync("SIM-P001");
        int linhaId = await amb.Api.IdDaLinhaAsync("SIM-L001");
        string corpo = $$"""{"paradaId":{{paradaId}},"linhaId":{{linhaId}},"observadaEm":"2026-11-10T14:30:00-03:00","origemRegistro":"{{DadosFicticios.CpfSemPontuacao}}"}""";

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, "/api/v1/admin/observacoes-passagem", corpo);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resposta.Status);
        Assert.Equal("DadoPessoalBloqueado", resposta.Json["codigo"]!.GetValue<string>());
        DadosFicticios.AssertSemOriginais(resposta.Corpo);
        await using PontoVozDbContext contexto = amb.Api.NovoContexto();
        var registros = await contexto.RegistrosPassagem.ToListAsync(Ct);
        Assert.DoesNotContain(registros, r => r.OrigemRegistro == DadosFicticios.CpfSemPontuacao);
        Assert.Contains(amb.Registro.Listar(), e => e.TipoDestino == TipoSink.Persistencia && e.Decisao == DecisaoPolitica.Bloquear);
    }

    [Fact]
    public async Task RotaRealSemDadoPessoal_ContinuaGravando()
    {
        await using Ambiente amb = await CriarAsync();
        int paradaId = await amb.Api.IdDaParadaAsync("SIM-P001");
        int linhaId = await amb.Api.IdDaLinhaAsync("SIM-L001");
        string corpo = $$"""{"paradaId":{{paradaId}},"linhaId":{{linhaId}},"observadaEm":"2026-11-10T14:30:00-03:00","origemRegistro":"operador-local"}""";

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, "/api/v1/admin/observacoes-passagem", corpo);

        Assert.Equal(HttpStatusCode.Created, resposta.Status);
        EventoSeguranca evento = Assert.Single(amb.Registro.Listar(), e => e.Fonte == "POST /api/v1/admin/observacoes-passagem");
        Assert.Equal(CodigosEvento.AnaliseSemDeteccao, evento.Codigo);
        Assert.DoesNotContain(amb.Registro.Listar(), e => e.NivelRisco != NivelRisco.Verde);
    }

    [Fact]
    public async Task DadoPessoalNaQueryString_EhMarcado_ENaoApareceNaResposta()
    {
        await using Ambiente amb = await CriarAsync();

        ApiTeste.Resposta resposta = await amb.Api.GetAsync($"/api/v1/paradas?texto={Uri.EscapeDataString(DadosFicticios.Cpf)}");

        DadosFicticios.AssertSemOriginais(resposta.Corpo);
        EventoSeguranca deteccao = Assert.Single(amb.Registro.Listar(), e => e.Codigo == CodigosEvento.PiiDetectado);
        Assert.Contains(InterceptadorDadosPessoais.FonteQuery, deteccao.MensagemTecnica, StringComparison.Ordinal);
        Assert.Equal("GET /api/v1/paradas", deteccao.Fonte);
    }

    [Fact]
    public async Task FormularioComDadoPessoal_EhAnalisado()
    {
        await using Ambiente amb = await CriarAsync();

        await amb.Api.EnviarAsync(HttpMethod.Post, Analises, $"cpf={Uri.EscapeDataString(DadosFicticios.Cpf)}&nome=Teste", tipoConteudo: "application/x-www-form-urlencoded");

        EventoSeguranca deteccao = Assert.Single(amb.Registro.Listar(), e => e.Codigo == CodigosEvento.PiiDetectado);
        Assert.Contains(InterceptadorDadosPessoais.FonteFormulario, deteccao.MensagemTecnica, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CorpoAcimaDoLimite_EhRecusadoAntesDosControllers()
    {
        await using Ambiente amb = await CriarAsync();
        string grande = $$"""{"observacao":"{{new string('a', 70 * 1024)}}"}""";

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, "/api/v1/admin/paradas", grande);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resposta.Status);
        Assert.Equal("CorpoExcedeLimiteSeguranca", resposta.Json["codigo"]!.GetValue<string>());
        Assert.Equal(CodigosEvento.EntradaRejeitada, Assert.Single(amb.Registro.Listar()).Codigo);
    }

    [Fact]
    public async Task JsonProfundoDemais_EhRecusado()
    {
        await using Ambiente amb = await CriarAsync();
        string profundo = string.Concat(Enumerable.Repeat("{\"a\":", 50)) + "1" + new string('}', 50);

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, Analises, profundo);

        Assert.Equal(HttpStatusCode.BadRequest, resposta.Status);
        Assert.Equal("EstruturaJsonExcessiva", resposta.Json["codigo"]!.GetValue<string>());
    }

    [Fact]
    public async Task JsonMalformadoComDadoPessoal_MantemOErroDoContrato_ESemVazarNoLog()
    {
        await using Ambiente amb = await CriarAsync();
        string malformado = $$"""{"codigoExterno":"SIM-P009","cpf":"{{DadosFicticios.Cpf}}","nome": """;

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, "/api/v1/admin/paradas", malformado);

        Assert.Equal(HttpStatusCode.BadRequest, resposta.Status);
        Assert.Equal("RequisicaoInvalida", resposta.Json["codigo"]!.GetValue<string>());
        DadosFicticios.AssertSemOriginais(resposta.Corpo);
        DadosFicticios.AssertSemOriginais(amb.Logs.TextoCompleto);
        Assert.Contains("(malformado)", Assert.Single(amb.Registro.Listar(), e => e.Codigo == CodigosEvento.PiiDetectado).MensagemTecnica, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Demonstracao_NaoExisteForaDeDevelopment()
    {
        await using Ambiente amb = await CriarAsync(ambiente: "Production", chave: "chave-teste-cyber");
        var cabecalho = new Dictionary<string, string> { ["X-PontoVoz-Admin-Key"] = "chave-teste-cyber" };

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, Vazamento, DadosFicticios.CadastroCompleto, cabecalho);

        Assert.Equal(HttpStatusCode.NotFound, resposta.Status);
        DadosFicticios.AssertSemOriginais(amb.Logs.TextoCompleto);
    }

    [Fact]
    public async Task Demonstracao_DesligadaNaConfiguracao_Responde404()
    {
        await using Ambiente amb = await CriarAsync(demonstracao: false);

        Assert.Equal(HttpStatusCode.NotFound, (await amb.Api.EnviarAsync(HttpMethod.Post, "/api/v1/seguranca/demonstracao/reiniciar")).Status);
    }

    [Fact]
    public async Task RotasDoPainel_ExigemAChaveQuandoConfigurada()
    {
        await using Ambiente amb = await CriarAsync(chave: "chave-teste-cyber");

        ApiTeste.Resposta semChave = await amb.Api.GetAsync("/api/v1/seguranca/painel");
        ApiTeste.Resposta comChave = await amb.Api.EnviarAsync(HttpMethod.Get, "/api/v1/seguranca/painel", cabecalhos: new Dictionary<string, string> { ["X-PontoVoz-Admin-Key"] = "chave-teste-cyber" });

        Assert.Equal(HttpStatusCode.Unauthorized, semChave.Status);
        Assert.Equal(HttpStatusCode.OK, comChave.Status);
    }

    [Fact]
    public async Task RotasDoPainel_ForaDeDevelopmentSemChave_Respondem403()
    {
        await using Ambiente amb = await CriarAsync(ambiente: "Production");

        Assert.Equal(HttpStatusCode.Forbidden, (await amb.Api.GetAsync("/api/v1/seguranca/eventos")).Status);
    }

    [Fact]
    public async Task ExplicacaoComLlm_UsaSoDadosSanitizados_EAtualizaOEvento()
    {
        var cliente = new ClienteLlmFalso(_ => "Identificamos uma tentativa de envio de informação pessoal. O sistema bloqueou essa operação para proteger seus dados.");
        await using Ambiente amb = await CriarAsync(cliente);
        await amb.Api.EnviarAsync(HttpMethod.Post, Vazamento, DadosFicticios.CadastroCompleto);
        EventoSeguranca bloqueio = amb.Registro.Listar().First(e => e.Codigo == CodigosEvento.SinkBloqueado);

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, $"/api/v1/seguranca/eventos/{bloqueio.Id}/explicacao");

        Assert.Equal(HttpStatusCode.OK, resposta.Status);
        Assert.Equal("Llm", resposta.Json["evento"]!["origemMensagem"]!.GetValue<string>());
        Assert.True(resposta.Json["chamadaExternaRealizada"]!.GetValue<bool>());
        Assert.Equal(CodigosEvento.SinkBloqueado, resposta.Json["dadosEnviadosAoLlm"]!["codigoEvento"]!.GetValue<string>());
        Assert.NotEmpty(cliente.Prompts);
        Assert.All(cliente.Prompts, p => DadosFicticios.AssertSemOriginais(p.Instrucoes + p.Mensagem));
    }

    [Fact]
    public async Task ExplicacaoSemProvedor_UsaFallbackIdentificado_SemChamadaExterna()
    {
        await using Ambiente amb = await CriarAsync();
        await amb.Api.EnviarAsync(HttpMethod.Post, Analises, DadosFicticios.CadastroCompleto);
        EventoSeguranca deteccao = Assert.Single(amb.Registro.Listar());

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, $"/api/v1/seguranca/eventos/{deteccao.Id}/explicacao");

        Assert.Equal("Fallback", resposta.Json["evento"]!["origemMensagem"]!.GetValue<string>());
        Assert.Equal("ProvedorDesabilitado", resposta.Json["evento"]!["motivoFallback"]!.GetValue<string>());
        Assert.False(resposta.Json["chamadaExternaRealizada"]!.GetValue<bool>());
    }

    [Fact]
    public async Task TraducaoAutomatica_PreencheAMensagemDosEventosComRisco()
    {
        await using Ambiente amb = await CriarAsync();

        await amb.Api.EnviarAsync(HttpMethod.Post, Vazamento, DadosFicticios.CadastroCompleto);

        IReadOnlyList<EventoSeguranca> eventos = await AguardarAsync(
            () => amb.Registro.Listar(),
            lista => lista.All(e => e.OrigemMensagem != OrigemMensagem.Pendente));
        Assert.All(eventos, e => Assert.False(string.IsNullOrWhiteSpace(e.MensagemCidadao)));
        Assert.All(eventos, e => Assert.Equal(OrigemMensagem.Fallback, e.OrigemMensagem));
    }

    [Fact]
    public async Task ReiniciarDemonstracao_VoltaAoVerde()
    {
        await using Ambiente amb = await CriarAsync();
        await amb.Api.EnviarAsync(HttpMethod.Post, Vazamento, DadosFicticios.CadastroCompleto);

        ApiTeste.Resposta resposta = await amb.Api.EnviarAsync(HttpMethod.Post, "/api/v1/seguranca/demonstracao/reiniciar");

        Assert.Equal(HttpStatusCode.NoContent, resposta.Status);
        Assert.Equal("Verde", (await amb.Api.GetAsync("/api/v1/seguranca/painel")).Json["risco"]!["nivel"]!.GetValue<string>());
    }

    [Fact]
    public async Task TrilhaDoEvento_LigaEntradaESaidasDaMesmaRequisicao()
    {
        await using Ambiente amb = await CriarAsync();
        await amb.Api.EnviarAsync(HttpMethod.Post, Vazamento, DadosFicticios.CadastroCompleto);
        EventoSeguranca resposta = amb.Registro.Listar().First(e => e.TipoDestino == TipoSink.RespostaHttp);

        JsonNode trilha = (await amb.Api.GetAsync($"/api/v1/seguranca/eventos/{resposta.Id}")).Json;

        Assert.Equal(
            [CodigosEvento.PiiDetectado, CodigosEvento.SinkBloqueado, CodigosEvento.SinkBloqueado, CodigosEvento.SinkBloqueado],
            trilha["mesmaRequisicao"]!.AsArray().Select(e => e!["codigo"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Painel_EhServidoComoPaginaEstatica()
    {
        await using Ambiente amb = await CriarAsync();

        ApiTeste.Resposta pagina = await amb.Api.GetAsync("/seguranca/index.html");
        ApiTeste.Resposta script = await amb.Api.GetAsync("/seguranca/painel.js");

        Assert.Equal(HttpStatusCode.OK, pagina.Status);
        Assert.Equal("text/html", pagina.TipoMidia);
        Assert.Contains("Risco Cidadão", pagina.Corpo, StringComparison.Ordinal);
        Assert.Contains("/api/v1/seguranca", script.Corpo, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DocumentoOpenApiDoModulo_ListaAsRotasDeSeguranca()
    {
        await using Ambiente amb = await CriarAsync();

        JsonObject caminhos = (await amb.Api.GetAsync("/openapi/seguranca.json")).Json["paths"]!.AsObject();

        Assert.Contains("/api/v1/seguranca/painel", caminhos.Select(par => par.Key));
        Assert.Contains("/api/v1/seguranca/demonstracao/vazamento-controlado", caminhos.Select(par => par.Key));
    }

    [Fact]
    public async Task ProvedoresDeLogDaAplicacao_SaoTodosProtegidos()
    {
        await using ApiTeste api = await ApiTeste.CriarAsync();

        IEnumerable<ILoggerProvider> provedores = api.Fabrica.Services.GetServices<ILoggerProvider>();

        Assert.NotEmpty(provedores);
        Assert.All(provedores, provedor => Assert.IsType<ProvedorLogProtegido>(provedor));
    }

    [Fact]
    public async Task CorpoEmTextoComDadoPessoal_TambemEhVarrido()
    {
        await using Ambiente amb = await CriarAsync();
        using var conteudo = new StringContent($"senha: {DadosFicticios.Senha}", Encoding.UTF8, "text/plain");
        using HttpClient cliente = amb.Api.Cliente();

        using HttpResponseMessage resposta = await cliente.PostAsync(new Uri("/api/v1/admin/linhas", UriKind.Relative), conteudo, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, resposta.StatusCode);
        Assert.Contains(amb.Registro.Listar(), e => e.Codigo == CodigosEvento.PiiDetectado);
        DadosFicticios.AssertSemOriginais(amb.Logs.TextoCompleto);
    }
}
