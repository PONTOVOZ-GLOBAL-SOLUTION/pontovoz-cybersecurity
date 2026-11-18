using System.Net;
using System.Text.Json.Nodes;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity;
using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.IA;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>Tradução de eventos por IA: sanitização, prompt, validação da resposta e fallback.</summary>
public sealed class TradutorRiscoCidadaoTests
{
    private const string MensagemBoa = "Identificamos uma tentativa de envio do seu CPF para uma área não autorizada. O sistema bloqueou a operação para proteger seus dados.";

    private readonly ModuloSegurancaTeste _modulo = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private TradutorRiscoCidadao Tradutor(IClienteLlm cliente) =>
        new(cliente, _modulo.Guarda, new CacheExplicacoes(), _modulo.Opcoes, NullLogger<TradutorRiscoCidadao>.Instance);

    private EventoSeguranca Bloqueio(params CategoriaPii[] categorias) =>
        _modulo.Registro.Registrar(new NovoEventoSeguranca(CodigosEvento.SinkBloqueado, "req", "POST /api/v1/seguranca/demonstracao/vazamento-controlado",
            categorias.Length == 0 ? [CategoriaPii.Cpf] : categorias, ["$.cpf"], TipoSink.Log, "log:Demonstracao", DecisaoPolitica.Mascarar, "mascarado",
            $"PII_TAINT_SINK_BLOCKED em $.cpf", 1));

    [Fact]
    public void DadosDoPrompt_SaoSoEnumeracoes_SemCaminhoNemMensagemTecnica()
    {
        DadosPromptRisco dados = ConstrutorPromptRisco.Dados(Bloqueio(CategoriaPii.Saude, CategoriaPii.Senha));
        PromptRisco prompt = ConstrutorPromptRisco.Montar(dados);

        Assert.Equal(CodigosEvento.SinkBloqueado, dados.CodigoEvento);
        Assert.Equal(["informação de saúde", "senha"], dados.CategoriasGenericas);
        Assert.Equal("o registro interno de funcionamento do sistema", dados.DestinoDaTentativa);
        Assert.DoesNotContain("$.cpf", prompt.Mensagem, StringComparison.Ordinal);
        Assert.DoesNotContain("vazamento-controlado", prompt.Mensagem, StringComparison.Ordinal);
        Assert.Contains("cidadão leigo de 60 anos", prompt.Mensagem, StringComparison.Ordinal);
        Assert.Contains("em até 2 frases", prompt.Mensagem, StringComparison.Ordinal);
        Assert.Contains("português do Brasil", prompt.Instrucoes, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RespostaValida_EhUsada_ComOrigemLlm()
    {
        var cliente = new ClienteLlmFalso(_ => $"  \"{MensagemBoa}\"  ");

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Equal(OrigemMensagem.Llm, resultado.Explicacao.Origem);
        Assert.Equal(MensagemBoa, resultado.Explicacao.Mensagem);
        Assert.Equal("Falso/modelo-teste", resultado.Explicacao.Modelo);
        Assert.True(resultado.ChamadaExternaRealizada);
        Assert.Single(cliente.Prompts);
    }

    [Fact]
    public async Task ConteudoEnviado_NaoTemDadoPessoalDaRequisicao()
    {
        _modulo.Contaminar(DadosFicticios.CadastroCompleto);
        var cliente = new ClienteLlmFalso(_ => MensagemBoa);

        await Tradutor(cliente).ExplicarAsync(Bloqueio(CategoriaPii.Cpf, CategoriaPii.Senha, CategoriaPii.Saude), reutilizar: false, Ct);

        PromptRisco enviado = Assert.Single(cliente.Prompts);
        DadosFicticios.AssertSemOriginais(enviado.Instrucoes + enviado.Mensagem);
    }

    [Fact]
    public async Task PromptQueLevariaValorMarcado_EhBloqueadoAntesDoEnvio()
    {
        // Valor marcado que coincide com um trecho do prompt: a saída para o LLM é recusada.
        _modulo.Contaminar("""{"laudo":"proteção de dados"}""");
        var cliente = new ClienteLlmFalso(_ => MensagemBoa);

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Empty(cliente.Prompts);
        Assert.Equal(OrigemMensagem.Fallback, resultado.Explicacao.Origem);
        Assert.Equal("ConteudoBloqueadoAntesDoEnvio", resultado.Explicacao.MotivoFallback);
        Assert.Contains(_modulo.Registro.Listar(), e => e.TipoDestino == TipoSink.ServicoExterno);
    }

    [Theory]
    [InlineData("RespostaLonga", "O sistema bloqueou a operação. Seus dados continuam protegidos. A tentativa foi registrada. Nenhuma ação é necessária. Obrigado pela compreensão.")]
    [InlineData("TermoTecnico", "O middleware bloqueou o sink de log com o seu CPF mascarado.")]
    [InlineData("AfirmaVazamento", "Seus dados vazaram, mas o sistema já está cuidando disso.")]
    [InlineData("PromessaAbsoluta", "Seus dados estão 100% seguros e nunca serão acessados por ninguém.")]
    [InlineData("Alarmismo", "Perigo! Houve um ataque ao sistema e você deve agir imediatamente.")]
    [InlineData("ContemDadoPessoal", "O CPF 111.444.777-35 foi protegido pelo sistema de forma adequada.")]
    [InlineData("IdiomaInesperado", "Personal data transfer blocked by policy.")]
    [InlineData("RespostaVazia", "   ")]
    public async Task RespostaInadequada_EhDescartada_EUsaOFallback(string motivo, string resposta)
    {
        var cliente = new ClienteLlmFalso(_ => resposta);

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Equal(OrigemMensagem.Fallback, resultado.Explicacao.Origem);
        Assert.Equal($"RespostaInadequada:{motivo}", resultado.Explicacao.MotivoFallback);
        Assert.Equal(MensagensLocais.Para(CodigosEvento.SinkBloqueado, [CategoriaPii.Cpf]), resultado.Explicacao.Mensagem);
    }

    [Fact]
    public async Task RespostaExcessivamenteLonga_EhDescartada()
    {
        var cliente = new ClienteLlmFalso(_ => new string('a', 200) + " o sistema de " + new string('b', 200));

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Equal("RespostaInadequada:RespostaLonga", resultado.Explicacao.MotivoFallback);
    }

    [Fact]
    public async Task SemChave_UsaFallbackSemChamarOProvedor()
    {
        var cliente = new ClienteLlmFalso(_ => MensagemBoa, configurado: false);

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Empty(cliente.Prompts);
        Assert.False(resultado.ChamadaExternaRealizada);
        Assert.Equal("ChaveNaoConfigurada", resultado.Explicacao.MotivoFallback);
    }

    [Fact]
    public async Task ProvedorDesabilitado_UsaFallbackIdentificado()
    {
        ResultadoTraducao resultado = await Tradutor(new ClienteLlmDesabilitado()).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Equal("ProvedorDesabilitado", resultado.Explicacao.MotivoFallback);
    }

    [Fact]
    public async Task FalhaDoProvedor_UsaFallbackComOMotivo()
    {
        var cliente = new ClienteLlmFalso(_ => throw new FalhaLlmException(MotivoFalhaLlm.ServicoIndisponivel, "503"));

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.Equal(OrigemMensagem.Fallback, resultado.Explicacao.Origem);
        Assert.Equal("ServicoIndisponivel", resultado.Explicacao.MotivoFallback);
        Assert.True(resultado.ChamadaExternaRealizada);
    }

    [Fact]
    public async Task EventoVerde_NaoChamaAIa()
    {
        var cliente = new ClienteLlmFalso(_ => MensagemBoa);
        EventoSeguranca verde = _modulo.Registro.Registrar(new NovoEventoSeguranca(CodigosEvento.AnaliseSemDeteccao, "req", "GET /api", [], [], null, null, DecisaoPolitica.Permitir, "ok", "ok", 0));

        ResultadoTraducao resultado = await Tradutor(cliente).ExplicarAsync(verde, reutilizar: false, Ct);

        Assert.Equal(OrigemMensagem.Padrao, resultado.Explicacao.Origem);
        Assert.Empty(cliente.Prompts);
    }

    [Fact]
    public async Task EventoIdentico_ReaproveitaAMensagemDoLlm_QuandoPermitido()
    {
        var cliente = new ClienteLlmFalso(_ => MensagemBoa);
        TradutorRiscoCidadao tradutor = Tradutor(cliente);

        await tradutor.ExplicarAsync(Bloqueio(), reutilizar: true, Ct);
        ResultadoTraducao segunda = await tradutor.ExplicarAsync(Bloqueio(), reutilizar: true, Ct);
        await tradutor.ExplicarAsync(Bloqueio(), reutilizar: false, Ct);

        Assert.True(segunda.Reutilizada);
        Assert.Equal(2, cliente.Prompts.Count);
    }

    [Theory]
    [InlineData(CodigosEvento.SinkBloqueado, CategoriaPii.Cpf)]
    [InlineData(CodigosEvento.SinkBloqueado, CategoriaPii.Senha)]
    [InlineData(CodigosEvento.SinkBloqueado, CategoriaPii.Saude)]
    [InlineData(CodigosEvento.PiiDetectado, CategoriaPii.Email)]
    [InlineData(CodigosEvento.EntradaRejeitada, CategoriaPii.Cpf)]
    [InlineData(CodigosEvento.AnaliseSemDeteccao, CategoriaPii.Cpf)]
    public void MensagensLocais_PassamNaMesmaValidacaoDoLlm(string codigo, CategoriaPii categoria)
    {
        string mensagem = MensagensLocais.Para(codigo, [categoria]);

        ValidacaoMensagem validacao = ValidadorMensagemCidadao.Validar(mensagem, 320, houveBloqueio: codigo == CodigosEvento.SinkBloqueado);

        Assert.True(validacao.Valida, validacao.Motivo);
    }
}

/// <summary>Clientes HTTP dos provedores: formato da requisição e tradução das falhas.</summary>
public sealed class ClientesLlmTests
{
    private static readonly PromptRisco Prompt = new("instruções do sistema", "evento sanitizado");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static IOptions<OpcoesCybersecurity> Opcoes(string? chave = "chave-de-teste", int tempoLimite = 5) =>
        Options.Create(new OpcoesCybersecurity { Llm = new OpcoesLlm { ChaveApi = chave, TempoLimiteSegundos = tempoLimite, VariavelAmbienteChave = "PONTOVOZ_TESTE_SEM_VARIAVEL" } });

    private static IConfiguration ConfiguracaoVazia => new ConfigurationBuilder().Build();

    private static ClienteGemini Gemini(ManipuladorHttpFalso manipulador, IOptions<OpcoesCybersecurity>? opcoes = null) =>
        new(new HttpClient(manipulador) { BaseAddress = new Uri(ClienteGemini.UrlPadrao) }, opcoes ?? Opcoes(), ConfiguracaoVazia);

    [Fact]
    public async Task Gemini_EnviaPromptNoFormatoDaApi_ELeOTexto()
    {
        var manipulador = ManipuladorHttpFalso.Json(HttpStatusCode.OK, """{"candidates":[{"content":{"parts":[{"text":"Mensagem gerada. "}]}}]}""");

        string texto = await Gemini(manipulador).GerarAsync(Prompt, Ct);

        Assert.Equal("Mensagem gerada.", texto);
        var (requisicao, corpo) = Assert.Single(manipulador.Recebidas);
        Assert.Equal("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", requisicao.RequestUri!.ToString());
        Assert.Equal("chave-de-teste", requisicao.Headers.GetValues("x-goog-api-key").Single());
        JsonNode json = JsonNode.Parse(corpo)!;
        Assert.Equal("instruções do sistema", json["systemInstruction"]!["parts"]![0]!["text"]!.GetValue<string>());
        Assert.Equal("evento sanitizado", json["contents"]![0]!["parts"]![0]!["text"]!.GetValue<string>());
    }

    [Fact]
    public async Task OpenAi_EnviaMensagensComChaveBearer_ELeOTexto()
    {
        var manipulador = ManipuladorHttpFalso.Json(HttpStatusCode.OK, """{"choices":[{"message":{"content":"Mensagem gerada."}}]}""");
        var cliente = new ClienteOpenAi(new HttpClient(manipulador) { BaseAddress = new Uri(ClienteOpenAi.UrlPadrao) }, Opcoes(), ConfiguracaoVazia);

        Assert.Equal("Mensagem gerada.", await cliente.GerarAsync(Prompt, Ct));
        var (requisicao, corpo) = Assert.Single(manipulador.Recebidas);
        Assert.Equal("https://api.openai.com/v1/chat/completions", requisicao.RequestUri!.ToString());
        Assert.Equal("Bearer", requisicao.Headers.Authorization!.Scheme);
        Assert.Equal("system", JsonNode.Parse(corpo)!["messages"]![0]!["role"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError, MotivoFalhaLlm.ServicoIndisponivel)]
    [InlineData(HttpStatusCode.ServiceUnavailable, MotivoFalhaLlm.ServicoIndisponivel)]
    [InlineData(HttpStatusCode.TooManyRequests, MotivoFalhaLlm.ServicoIndisponivel)]
    [InlineData(HttpStatusCode.BadRequest, MotivoFalhaLlm.ErroHttp)]
    [InlineData(HttpStatusCode.Unauthorized, MotivoFalhaLlm.ErroHttp)]
    public async Task ErroHttp_ViraFalhaComMotivo(HttpStatusCode status, MotivoFalhaLlm motivo)
    {
        FalhaLlmException falha = await Assert.ThrowsAsync<FalhaLlmException>(() => Gemini(ManipuladorHttpFalso.Json(status, "{}")).GerarAsync(Prompt, Ct));

        Assert.Equal(motivo, falha.Motivo);
    }

    [Theory]
    [InlineData("nao e json")]
    [InlineData("""{"candidates":[]}""")]
    [InlineData("""{"candidates":[{"content":{"parts":[{"text":""}]}}]}""")]
    public async Task RespostaSemTexto_ViraRespostaInvalida(string corpo)
    {
        FalhaLlmException falha = await Assert.ThrowsAsync<FalhaLlmException>(() => Gemini(ManipuladorHttpFalso.Json(HttpStatusCode.OK, corpo)).GerarAsync(Prompt, Ct));

        Assert.Equal(MotivoFalhaLlm.RespostaInvalida, falha.Motivo);
    }

    [Fact]
    public async Task ProvedorLento_ViraTempoEsgotado()
    {
        var lento = new ManipuladorHttpFalso(async (_, cancelamento) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancelamento);
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        FalhaLlmException falha = await Assert.ThrowsAsync<FalhaLlmException>(() => Gemini(lento, Opcoes(tempoLimite: 1)).GerarAsync(Prompt, Ct));

        Assert.Equal(MotivoFalhaLlm.TempoEsgotado, falha.Motivo);
    }

    [Fact]
    public async Task FalhaDeConexao_ViraFalhaConexao()
    {
        var semRede = new ManipuladorHttpFalso((_, _) => throw new HttpRequestException(HttpRequestError.NameResolutionError));

        FalhaLlmException falha = await Assert.ThrowsAsync<FalhaLlmException>(() => Gemini(semRede).GerarAsync(Prompt, Ct));

        Assert.Equal(MotivoFalhaLlm.FalhaConexao, falha.Motivo);
    }

    [Fact]
    public async Task SemChave_NaoFazRequisicao()
    {
        var manipulador = ManipuladorHttpFalso.Json(HttpStatusCode.OK, "{}");
        ClienteGemini cliente = Gemini(manipulador, Opcoes(chave: null));

        Assert.False(cliente.Configurado);
        FalhaLlmException falha = await Assert.ThrowsAsync<FalhaLlmException>(() => cliente.GerarAsync(Prompt, Ct));
        Assert.Equal(MotivoFalhaLlm.ChaveNaoConfigurada, falha.Motivo);
        Assert.Empty(manipulador.Recebidas);
    }

    [Fact]
    public void Chave_PodeVirDaVariavelDeAmbienteConfigurada()
    {
        IConfiguration configuracao = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["MINHA_VARIAVEL"] = "valor" }).Build();
        var opcoes = Options.Create(new OpcoesCybersecurity { Llm = new OpcoesLlm { ChaveApi = "", VariavelAmbienteChave = "MINHA_VARIAVEL" } });

        Assert.True(new ClienteGemini(new HttpClient(), opcoes, configuracao).Configurado);
    }
}

public sealed class ValidadorMensagemCidadaoTests
{
    [Theory]
    [InlineData("Identificamos uma tentativa de envio de informação pessoal para uma área não autorizada. O sistema bloqueou essa operação.")]
    [InlineData("Tentaram acessar seu documento de saúde, mas nosso sistema bloqueou a ação para proteger sua privacidade.")]
    public void MensagemClaraEmPortugues_EhAprovada(string mensagem)
    {
        Assert.True(ValidadorMensagemCidadao.Validar(mensagem, 320, houveBloqueio: true).Valida);
    }

    [Fact]
    public void Normalizacao_RemoveAspasMarcacaoEQuebrasDeLinha()
    {
        ValidacaoMensagem validacao = ValidadorMensagemCidadao.Validar("\"**O sistema** bloqueou\na operação para proteger seus dados.\"", 320, true);

        Assert.Equal("O sistema bloqueou a operação para proteger seus dados.", validacao.Mensagem);
    }

    [Fact]
    public void AfirmarVazamento_SoEhProibidoQuandoHouveBloqueio()
    {
        const string mensagem = "Seus dados vazaram de um sistema que não é o PontoVoz.";

        Assert.False(ValidadorMensagemCidadao.Validar(mensagem, 320, houveBloqueio: true).Valida);
        Assert.True(ValidadorMensagemCidadao.Validar(mensagem, 320, houveBloqueio: false).Valida);
    }
}
