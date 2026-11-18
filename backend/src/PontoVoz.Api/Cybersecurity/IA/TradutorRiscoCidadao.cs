using System.Collections.Concurrent;
using System.Threading.Channels;

using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Api.Cybersecurity.IA;

/// <summary>Explicação de um evento para o cidadão.</summary>
/// <param name="Mensagem">Texto exibido no painel.</param>
/// <param name="Origem">LLM, fallback local ou mensagem padrão.</param>
/// <param name="MotivoFallback">Por que o LLM não foi usado (auditoria técnica).</param>
/// <param name="Modelo">Provedor e modelo, quando a mensagem veio do LLM.</param>
public sealed record ExplicacaoRisco(string Mensagem, OrigemMensagem Origem, string? MotivoFallback, string? Modelo);

/// <summary>Resultado da tradução, com os dados exatamente como foram (ou seriam) enviados ao provedor.</summary>
/// <param name="Explicacao">Mensagem e origem.</param>
/// <param name="DadosEnviados">Estrutura sanitizada usada no prompt.</param>
/// <param name="ChamadaExternaRealizada">Verdadeiro somente se houve requisição ao provedor nesta tradução.</param>
/// <param name="Reutilizada">A mensagem foi reaproveitada de um evento idêntico já traduzido pelo LLM.</param>
public sealed record ResultadoTraducao(ExplicacaoRisco Explicacao, DadosPromptRisco DadosEnviados, bool ChamadaExternaRealizada, bool Reutilizada);

/// <summary>
/// Traduz eventos técnicos em mensagens para o cidadão. O nível de risco já foi decidido pelo
/// backend; o LLM só redige o texto. Fluxo: dados sanitizados → verificação da saída externa
/// pelo Taint Analysis → chamada ao provedor → validação da resposta → fallback local se preciso.
/// </summary>
public sealed class TradutorRiscoCidadao(
    IClienteLlm cliente,
    GuardaSinks guarda,
    CacheExplicacoes cache,
    IOptions<OpcoesCybersecurity> opcoes,
    ILogger<TradutorRiscoCidadao> logger)
{
    public async Task<ResultadoTraducao> ExplicarAsync(EventoSeguranca evento, bool reutilizar, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evento);
        DadosPromptRisco dados = ConstrutorPromptRisco.Dados(evento);
        string local = MensagensLocais.Para(evento.Codigo, evento.Categorias);

        if (evento.NivelRisco == NivelRisco.Verde)
        {
            return new ResultadoTraducao(new ExplicacaoRisco(local, OrigemMensagem.Padrao, null, null), dados, false, false);
        }

        string assinatura = string.Join('|', dados.CodigoEvento, string.Join(',', dados.CategoriasGenericas), dados.DestinoDaTentativa, dados.AcaoExecutada);
        if (reutilizar && cache.TryGetValue(assinatura, out ExplicacaoRisco? anterior))
        {
            return new ResultadoTraducao(anterior, dados, false, true);
        }

        if (!cliente.Configurado)
        {
            return Fallback(local, dados, cliente.Provedor == "Nenhum" ? nameof(MotivoFalhaLlm.ProvedorDesabilitado) : nameof(MotivoFalhaLlm.ChaveNaoConfigurada), chamou: false);
        }

        PromptRisco prompt = ConstrutorPromptRisco.Montar(dados);
        try
        {
            // O prompt é uma saída para serviço externo: passa pela mesma política das demais saídas.
            guarda.ExigirSemDadosProtegidos(TipoSink.ServicoExterno, $"{prompt.Instrucoes}\n{prompt.Mensagem}", $"llm:{cliente.Provedor}");
        }
        catch (SaidaBloqueadaException)
        {
            return Fallback(local, dados, "ConteudoBloqueadoAntesDoEnvio", chamou: false);
        }

        string resposta;
        try
        {
            resposta = await cliente.GerarAsync(prompt, cancellationToken);
        }
        catch (FalhaLlmException falha)
        {
            logger.LogWarning("Tradução do evento {Id} pelo provedor {Provedor} falhou: {Motivo}. Usando a mensagem local.", evento.Id, cliente.Provedor, falha.Motivo);
            return Fallback(local, dados, falha.Motivo.ToString(), chamou: true);
        }

        ValidacaoMensagem validacao = ValidadorMensagemCidadao.Validar(resposta, opcoes.Value.Llm.TamanhoMaximoMensagem, evento.Codigo == CodigosEvento.SinkBloqueado);
        if (!validacao.Valida)
        {
            logger.LogWarning("Resposta do provedor {Provedor} para o evento {Id} reprovada na validação ({Motivo}). Usando a mensagem local.", cliente.Provedor, evento.Id, validacao.Motivo);
            return Fallback(local, dados, $"RespostaInadequada:{validacao.Motivo}", chamou: true);
        }

        var explicacao = new ExplicacaoRisco(validacao.Mensagem, OrigemMensagem.Llm, null, $"{cliente.Provedor}/{cliente.Modelo}");
        cache[assinatura] = explicacao;
        logger.LogInformation("Evento {Id} traduzido pelo provedor {Provedor} ({Modelo}).", evento.Id, cliente.Provedor, cliente.Modelo);
        return new ResultadoTraducao(explicacao, dados, true, false);
    }

    private static ResultadoTraducao Fallback(string mensagem, DadosPromptRisco dados, string motivo, bool chamou) =>
        new(new ExplicacaoRisco(mensagem, OrigemMensagem.Fallback, motivo, null), dados, chamou, false);
}

/// <summary>Explicações já aprovadas, por tipo de evento: eventos idênticos não geram nova chamada paga.</summary>
public sealed class CacheExplicacoes : ConcurrentDictionary<string, ExplicacaoRisco>;

/// <summary>Fila dos eventos que aguardam explicação.</summary>
public sealed class FilaExplicacoes
{
    private readonly Channel<string> _canal = Channel.CreateBounded<string>(new BoundedChannelOptions(200)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
    });

    public void Enfileirar(string eventoId) => _canal.Writer.TryWrite(eventoId);

    public ChannelReader<string> Leitor => _canal.Reader;
}

/// <summary>Processa a fila em segundo plano, para que a chamada ao LLM não atrase a requisição do usuário.</summary>
public sealed class ServicoExplicacoes(
    FilaExplicacoes fila,
    RegistroEventosSeguranca registro,
    IServiceScopeFactory escopos,
    IOptions<OpcoesCybersecurity> opcoes,
    ILogger<ServicoExplicacoes> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (string id in fila.Leitor.ReadAllAsync(stoppingToken))
        {
            EventoSeguranca? evento = registro.Obter(id);
            if (evento is null)
            {
                continue;
            }

            if (!opcoes.Value.Llm.TraducaoAutomatica)
            {
                registro.AtualizarExplicacao(id, new ExplicacaoRisco(MensagensLocais.Para(evento.Codigo, evento.Categorias), OrigemMensagem.Fallback, "TraducaoAutomaticaDesativada", null));
                continue;
            }

            try
            {
                await using AsyncServiceScope escopo = escopos.CreateAsyncScope();
                TradutorRiscoCidadao tradutor = escopo.ServiceProvider.GetRequiredService<TradutorRiscoCidadao>();
                ResultadoTraducao resultado = await tradutor.ExplicarAsync(evento, reutilizar: true, stoppingToken);
                registro.AtualizarExplicacao(id, resultado.Explicacao);
            }
            catch (Exception excecao) when (excecao is not OperationCanceledException)
            {
                logger.LogError(excecao, "Falha inesperada ao explicar o evento {Id}.", id);
                registro.AtualizarExplicacao(id, new ExplicacaoRisco(MensagensLocais.Para(evento.Codigo, evento.Categorias), OrigemMensagem.Fallback, "FalhaInterna", null));
            }
        }
    }
}
