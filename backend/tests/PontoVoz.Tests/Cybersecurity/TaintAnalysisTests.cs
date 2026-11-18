using System.Text.Json;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using PontoVoz.Api.Cybersecurity;
using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Sinks;
using PontoVoz.Api.Cybersecurity.Taint;
using PontoVoz.Tests.Api;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>Source → marcação → sink → política: comportamento da guarda das saídas.</summary>
public sealed class TaintAnalysisTests
{
    private readonly ModuloSegurancaTeste _modulo = new();

    [Fact]
    public void Contexto_ComecaLimpo_EFicaContaminadoComAsMarcasDaEntrada()
    {
        var contexto = new ContextoTaint("req", "POST /api/teste");
        Assert.Equal(EstadoTaint.Limpo, contexto.Estado);

        contexto.Contaminar(_modulo.Motor.AnalisarJson(DadosFicticios.CadastroCompleto), InterceptadorDadosPessoais.FonteCorpoJson);

        Assert.Equal(EstadoTaint.Contaminado, contexto.Estado);
        Assert.Equal(["T1", "T2", "T3", "T4", "T5", "T6"], contexto.Marcas.Select(m => m.Id));
        Assert.All(contexto.Marcas, marca => Assert.Equal(InterceptadorDadosPessoais.FonteCorpoJson, marca.TipoFonte));
        DadosFicticios.AssertSemOriginais(JsonSerializer.Serialize(contexto.Marcas));
    }

    [Fact]
    public void DadoPessoalEmLog_EhMascarado_EGeraEventoDeBloqueio()
    {
        _modulo.Contaminar($$"""{"cpf":"{{DadosFicticios.Cpf}}"}""");

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.Log, $"Cadastro recebido: {DadosFicticios.Cpf}", "log:teste");

        Assert.True(resultado.Interceptado);
        Assert.Equal("Cadastro recebido: ***.444.***-35", resultado.Conteudo);
        Assert.Equal(DecisaoPolitica.Mascarar, resultado.Decisao);
        EventoSeguranca evento = Assert.Single(_modulo.Registro.Listar());
        Assert.Equal(CodigosEvento.SinkBloqueado, evento.Codigo);
        Assert.Equal(TipoSink.Log, evento.TipoDestino);
        Assert.Equal(NivelRisco.Vermelho, evento.NivelRisco);
        Assert.Equal(["$.cpf"], evento.Caminhos);
        Assert.Equal("req-teste", evento.CorrelacaoId);
    }

    [Fact]
    public void SenhaEmLog_EhBloqueada_SemNenhumTrecho()
    {
        _modulo.Contaminar($$"""{"senha":"{{DadosFicticios.Senha}}"}""");

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.Log, $"login com {DadosFicticios.Senha}", "log:teste");

        Assert.Equal("login com [BLOQUEADO: SENHA]", resultado.Conteudo);
        Assert.Equal(DecisaoPolitica.Bloquear, resultado.Decisao);
    }

    [Fact]
    public void RespostaHttpComDadoDeSaudeEscapadoPeloSerializador_TambemEhBloqueada()
    {
        _modulo.Contaminar($$"""{"laudo":"{{DadosFicticios.Laudo}}"}""");
        string respostaSerializada = JsonSerializer.Serialize(new { eco = DadosFicticios.Laudo });
        Assert.Contains("\\u00ED", respostaSerializada, StringComparison.Ordinal);

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.RespostaHttp, respostaSerializada, "resposta:200");

        Assert.True(resultado.Interceptado);
        Assert.Equal("""{"eco":"[BLOQUEADO: INFORMAÇÃO DE SAÚDE]"}""", resultado.Conteudo);
        Assert.DoesNotContain("diabetes", resultado.Conteudo, StringComparison.Ordinal);
    }

    [Fact]
    public void ValorDerivadoSoComDigitos_TambemEhReconhecidoNaSaida()
    {
        _modulo.Contaminar($$"""{"cpf":"{{DadosFicticios.Cpf}}"}""");

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.Log, $"chave={DadosFicticios.CpfSemPontuacao}", "log:teste");

        Assert.Equal("chave=***.444.***-35", resultado.Conteudo);
    }

    [Fact]
    public void VariosCamposContaminados_SaoTodosSubstituidos()
    {
        _modulo.Contaminar(DadosFicticios.CadastroCompleto);

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.RespostaHttp, DadosFicticios.CadastroCompleto, "resposta:200");

        DadosFicticios.AssertSemOriginais(resultado.Conteudo);
        Assert.Equal(DecisaoPolitica.Bloquear, resultado.Decisao);
        EventoSeguranca evento = Assert.Single(_modulo.Registro.Listar());
        Assert.Equal(6, evento.Categorias.Count);
        using JsonDocument _ = JsonDocument.Parse(resultado.Conteudo);
    }

    [Fact]
    public void ConteudoSemDadoProtegido_SaiIntacto_ESemEvento()
    {
        _modulo.Contaminar($$"""{"cpf":"{{DadosFicticios.Cpf}}","linhaId":4}""");
        const string conteudo = """{"paradaId":1,"codigoLinha":"SIM-L004","letreiro":"SIM-104"}""";

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.RespostaHttp, conteudo, "resposta:200");

        Assert.False(resultado.Interceptado);
        Assert.Same(conteudo, resultado.Conteudo);
        Assert.Empty(_modulo.Registro.Listar());
    }

    [Fact]
    public void ConteudoJaMascarado_NaoEhInterceptadoDeNovo()
    {
        _modulo.Contaminar($$"""{"cpf":"{{DadosFicticios.Cpf}}","senha":"{{DadosFicticios.Senha}}"}""");

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.Log, """Corpo protegido: {"cpf":"***.444.***-35","senha":"[SENHA REMOVIDA]"}""", "log:teste");

        Assert.False(resultado.Interceptado);
    }

    [Fact]
    public void SaidaParaServicoExterno_EhRecusada()
    {
        _modulo.Contaminar($$"""{"email":"{{DadosFicticios.Email}}"}""");

        SaidaBloqueadaException bloqueio = Assert.Throws<SaidaBloqueadaException>(() =>
            _modulo.Guarda.ExigirSemDadosProtegidos(TipoSink.ServicoExterno, $"enviar {DadosFicticios.Email}", "servico-externo:teste"));

        Assert.Equal(TipoSink.ServicoExterno, bloqueio.Sink);
        EventoSeguranca evento = Assert.Single(_modulo.Registro.Listar());
        Assert.Equal(bloqueio.EventoId, evento.Id);
        Assert.Equal(DecisaoPolitica.Bloquear, evento.Decisao);
        Assert.DoesNotContain(DadosFicticios.Email, bloqueio.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SemRequisicao_OsPadroesAindaProtegemAsSaidas()
    {
        _modulo.SemRequisicao();

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.Log, $"falha ao notificar {DadosFicticios.Email}", "log:teste");

        Assert.Equal("falha ao notificar p***@e***.br", resultado.Conteudo);
        Assert.Equal("processo-interno", Assert.Single(_modulo.Registro.Listar()).CorrelacaoId);
    }

    [Fact]
    public void SomenteTaint_IgnoraPadroesQueNaoVieramDaEntrada()
    {
        _modulo.Contaminar("""{"linhaId":4}""");

        ResultadoProtecaoSink resultado = _modulo.Guarda.Proteger(TipoSink.Persistencia, DadosFicticios.Email, "persistencia:teste", verificarPadroes: false);

        Assert.False(resultado.Interceptado);
    }

    [Theory]
    [InlineData(TipoSink.Log, Sensibilidade.DadoPessoal, DecisaoPolitica.Mascarar)]
    [InlineData(TipoSink.Log, Sensibilidade.DadoPessoalSensivel, DecisaoPolitica.Bloquear)]
    [InlineData(TipoSink.Log, Sensibilidade.SegredoAutenticacao, DecisaoPolitica.Bloquear)]
    [InlineData(TipoSink.RespostaHttp, Sensibilidade.DadoPessoal, DecisaoPolitica.Mascarar)]
    [InlineData(TipoSink.RespostaHttp, Sensibilidade.DadoPessoalSensivel, DecisaoPolitica.Bloquear)]
    [InlineData(TipoSink.RespostaHttp, Sensibilidade.SegredoAutenticacao, DecisaoPolitica.Bloquear)]
    [InlineData(TipoSink.Persistencia, Sensibilidade.DadoPessoal, DecisaoPolitica.Bloquear)]
    [InlineData(TipoSink.ServicoExterno, Sensibilidade.DadoPessoal, DecisaoPolitica.Bloquear)]
    public void Politica_DecideConformeSaidaESensibilidade(TipoSink sink, Sensibilidade sensibilidade, DecisaoPolitica esperada)
    {
        Assert.Equal(esperada, PoliticaSinks.Decidir(sink, sensibilidade));
    }
}

/// <summary>Sink de log: o decorador dos provedores impede que o valor original seja escrito.</summary>
public sealed class ProvedorLogProtegidoTests
{
    private static (ModuloSegurancaTeste Modulo, ILogger Logger, LogsEmMemoria Logs) Criar()
    {
        var modulo = new ModuloSegurancaTeste();
        var servicos = new ServiceCollection().AddSingleton(modulo.Guarda).BuildServiceProvider();
        var logs = new LogsEmMemoria();
        var provedor = new ProvedorLogProtegido(logs, servicos);
        return (modulo, provedor.CreateLogger("Teste.Categoria"), logs);
    }

    [Fact]
    public void MensagemComDadoContaminado_EhEscritaSanitizada()
    {
        var (modulo, logger, logs) = Criar();
        modulo.Contaminar(DadosFicticios.CadastroCompleto);

        logger.LogInformation("Cadastro recebido: {Cadastro}", DadosFicticios.CadastroCompleto);

        DadosFicticios.AssertSemOriginais(logs.TextoCompleto);
        Assert.Contains("***.444.***-35", logs.TextoCompleto, StringComparison.Ordinal);
        Assert.Contains("[BLOQUEADO: SENHA]", logs.TextoCompleto, StringComparison.Ordinal);
    }

    [Fact]
    public void ExcecaoComPayload_TemOTextoSanitizado()
    {
        var (modulo, logger, logs) = Criar();
        modulo.Contaminar(DadosFicticios.CadastroCompleto);

        logger.LogError(new InvalidOperationException($"Falha ao processar {DadosFicticios.CadastroCompleto}"), "Erro inesperado.");

        DadosFicticios.AssertSemOriginais(logs.TextoCompleto);
        Assert.Contains("InvalidOperationException", logs.TextoCompleto, StringComparison.Ordinal);
    }

    [Fact]
    public void MensagemLimpa_SegueSemAlteracao()
    {
        var (modulo, logger, logs) = Criar();

        logger.LogInformation("Consulta da parada {Codigo} concluída.", "SIM-P001");

        Assert.Equal("Consulta da parada SIM-P001 concluída.", Assert.Single(logs.Entradas).Mensagem);
        Assert.Empty(modulo.Registro.Listar());
    }

    [Fact]
    public void ProtegerSinksDeLog_EnvolveTodosOsProvedores_UmaUnicaVez()
    {
        var logs = new LogsEmMemoria();
        var servicos = new ServiceCollection();
        servicos.AddSingleton(new ModuloSegurancaTeste().Guarda);
        servicos.AddLogging(logging => logging.AddProvider(logs).AddProvider(NullLoggerProvider.Instance));

        servicos.ProtegerSinksDeLog().ProtegerSinksDeLog();

        using ServiceProvider provedor = servicos.BuildServiceProvider();
        ILoggerProvider[] provedores = [.. provedor.GetServices<ILoggerProvider>()];
        Assert.Equal(2, provedores.Length);
        Assert.All(provedores, p => Assert.IsNotType<ProvedorLogProtegido>(Assert.IsType<ProvedorLogProtegido>(p).Interno));
    }

    [Fact]
    public void MesmaMensagemEmVariosProvedores_GeraUmEventoSo()
    {
        var modulo = new ModuloSegurancaTeste();
        var servicos = new ServiceCollection();
        servicos.AddSingleton(modulo.Guarda);
        servicos.AddLogging(logging => logging.AddProvider(new LogsEmMemoria()).AddProvider(new LogsEmMemoria()));
        servicos.ProtegerSinksDeLog();
        using ServiceProvider provedor = servicos.BuildServiceProvider();
        modulo.Contaminar($$"""{"cpf":"{{DadosFicticios.Cpf}}"}""");

        provedor.GetRequiredService<ILoggerFactory>().CreateLogger("Teste").LogWarning("cpf {Cpf}", DadosFicticios.Cpf);

        Assert.Single(modulo.Registro.Listar());
    }
}

/// <summary>Trilha de auditoria e indicador de Risco Cidadão.</summary>
public sealed class AuditoriaRiscoTests
{
    private readonly ModuloSegurancaTeste _modulo = new();

    private EventoSeguranca Registrar(string codigo, int deteccoes = 1, string mensagem = "teste") =>
        _modulo.Registro.Registrar(new NovoEventoSeguranca(codigo, "req", "POST /api/teste", [CategoriaPii.Cpf], ["$.cpf"], null, null,
            DecisaoPolitica.Mascarar, "resultado", mensagem, deteccoes));

    [Fact]
    public void Registro_NaoGuardaValorOriginal_MesmoSeOChamadorTentar()
    {
        EventoSeguranca evento = Registrar(CodigosEvento.PiiDetectado, mensagem: $"CPF {DadosFicticios.Cpf} e e-mail {DadosFicticios.Email}");

        Assert.Equal("CPF [BLOQUEADO: CPF] e e-mail [BLOQUEADO: E-MAIL]", evento.MensagemTecnica);
        DadosFicticios.AssertSemOriginais(JsonSerializer.Serialize(_modulo.Registro.Listar()));
    }

    [Fact]
    public void SemEventos_RiscoVerde()
    {
        AvaliacaoRisco risco = _modulo.Registro.AvaliarRisco();

        Assert.Equal(NivelRisco.Verde, risco.Nivel);
        Assert.Null(risco.EventoReferenciaId);
    }

    [Fact]
    public void AnaliseSemDeteccao_ContinuaVerde_ComMensagemPadrao()
    {
        EventoSeguranca evento = Registrar(CodigosEvento.AnaliseSemDeteccao, 0);

        Assert.Equal(NivelRisco.Verde, _modulo.Registro.AvaliarRisco().Nivel);
        Assert.Equal(OrigemMensagem.Padrao, evento.OrigemMensagem);
        Assert.False(_modulo.Fila.Leitor.TryRead(out _));
    }

    [Fact]
    public void DadoPessoalDetectado_RiscoAmarelo_EEventoVaiParaAFilaDaIa()
    {
        EventoSeguranca evento = Registrar(CodigosEvento.PiiDetectado, 2);

        AvaliacaoRisco risco = _modulo.Registro.AvaliarRisco();
        Assert.Equal(NivelRisco.Amarelo, risco.Nivel);
        Assert.Equal(evento.Id, risco.EventoReferenciaId);
        Assert.True(_modulo.Fila.Leitor.TryRead(out string? enfileirado));
        Assert.Equal(evento.Id, enfileirado);
        Assert.Equal(OrigemMensagem.Pendente, evento.OrigemMensagem);
    }

    [Fact]
    public void SinkBloqueado_RiscoVermelho_PrevaleceSobreEventosPosterioresMaisLeves()
    {
        EventoSeguranca bloqueio = Registrar(CodigosEvento.SinkBloqueado);
        Registrar(CodigosEvento.PiiDetectado);
        Registrar(CodigosEvento.AnaliseSemDeteccao, 0);

        AvaliacaoRisco risco = _modulo.Registro.AvaliarRisco();
        Assert.Equal(NivelRisco.Vermelho, risco.Nivel);
        Assert.Equal(bloqueio.Id, risco.EventoReferenciaId);
        Assert.Contains("não chegou ao destino", risco.Descricao, StringComparison.Ordinal);
    }

    [Fact]
    public void EventosForaDaJanela_NaoContamParaORisco()
    {
        Registrar(CodigosEvento.SinkBloqueado);

        _modulo.Relogio.Advance(TimeSpan.FromMinutes(_modulo.Opcoes.Value.JanelaRiscoMinutos + 1));

        Assert.Equal(NivelRisco.Verde, _modulo.Registro.AvaliarRisco().Nivel);
    }

    [Fact]
    public void Indicadores_ContamCadaTipoDeEvento_EReiniciarZeraTudo()
    {
        Registrar(CodigosEvento.AnaliseSemDeteccao, 0);
        Registrar(CodigosEvento.PiiDetectado, 3);
        Registrar(CodigosEvento.SinkBloqueado);
        Registrar(CodigosEvento.SinkBloqueado);
        Registrar(CodigosEvento.EntradaRejeitada, 0);

        Assert.Equal(new IndicadoresSeguranca(3, 3, 2, 1, 1), _modulo.Registro.Indicadores());

        _modulo.Registro.Reiniciar();
        Assert.Equal(new IndicadoresSeguranca(0, 0, 0, 0, 0), _modulo.Registro.Indicadores());
        Assert.Empty(_modulo.Registro.Listar());
    }

    [Fact]
    public void Capacidade_DescartaOsEventosMaisAntigos()
    {
        var modulo = new ModuloSegurancaTeste(new OpcoesCybersecurity { CapacidadeEventos = 3 });
        for (int i = 0; i < 5; i++)
        {
            modulo.Registro.Registrar(new NovoEventoSeguranca(CodigosEvento.AnaliseSemDeteccao, $"req-{i}", "GET /api", [], [], null, null, DecisaoPolitica.Permitir, "ok", "ok", 0));
        }

        Assert.Equal(["req-4", "req-3", "req-2"], modulo.Registro.Listar().Select(e => e.CorrelacaoId));
        Assert.Equal(5, modulo.Registro.Indicadores().EventosAnalisados);
    }

    [Theory]
    [InlineData(CodigosEvento.AnaliseSemDeteccao, NivelRisco.Verde)]
    [InlineData(CodigosEvento.PiiDetectado, NivelRisco.Amarelo)]
    [InlineData(CodigosEvento.EntradaRejeitada, NivelRisco.Amarelo)]
    [InlineData(CodigosEvento.SinkBloqueado, NivelRisco.Vermelho)]
    public void ClassificarEvento_SegueAPoliticaDocumentada(string codigo, NivelRisco esperado)
    {
        Assert.Equal(esperado, CalculadoraRiscoCidadao.ClassificarEvento(codigo));
    }
}
