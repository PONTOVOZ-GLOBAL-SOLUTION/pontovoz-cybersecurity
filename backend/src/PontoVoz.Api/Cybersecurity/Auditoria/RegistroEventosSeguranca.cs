using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity.IA;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Api.Cybersecurity.Auditoria;

/// <summary>Totais desde o início da execução (ou desde o último reinício da demonstração).</summary>
/// <param name="EventosAnalisados">Requisições cuja entrada foi analisada pelo motor PII.</param>
/// <param name="DadosPessoaisIdentificados">Ocorrências de PII reconhecidas nas entradas.</param>
/// <param name="TentativasBloqueadas">Interceptações nas saídas (log, resposta, persistência, serviço externo).</param>
/// <param name="EventosSemRisco">Análises concluídas sem informação pessoal.</param>
/// <param name="EntradasRejeitadas">Entradas recusadas por tamanho ou estrutura.</param>
public sealed record IndicadoresSeguranca(int EventosAnalisados, int DadosPessoaisIdentificados, int TentativasBloqueadas, int EventosSemRisco, int EntradasRejeitadas);

/// <summary>
/// Trilha de auditoria em memória (os eventos mais recentes, até a capacidade configurada).
/// Antes de guardar um evento, os textos passam pelo motor PII: mesmo que um chamador incluísse
/// um valor pessoal na mensagem técnica, ele seria substituído antes do registro.
/// </summary>
public sealed class RegistroEventosSeguranca(
    IOptions<OpcoesCybersecurity> opcoes,
    TimeProvider relogio,
    FilaExplicacoes fila,
    ILogger<RegistroEventosSeguranca> logger)
{
    private readonly Lock _trava = new();
    private readonly LinkedList<EventoSeguranca> _eventos = new();
    private readonly OpcoesCybersecurity _opcoes = opcoes.Value;
    private int _analisados;
    private int _identificados;
    private int _bloqueados;
    private int _semRisco;
    private int _rejeitados;

    public EventoSeguranca Registrar(NovoEventoSeguranca novo)
    {
        ArgumentNullException.ThrowIfNull(novo);
        NivelRisco nivel = CalculadoraRiscoCidadao.ClassificarEvento(novo.Codigo);
        var evento = new EventoSeguranca
        {
            Id = $"EVT-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            OcorridoEm = relogio.GetUtcNow(),
            Codigo = novo.Codigo,
            CorrelacaoId = Sanitizar(novo.CorrelacaoId),
            Fonte = Sanitizar(novo.Fonte),
            Categorias = novo.Categorias,
            Caminhos = [.. novo.Caminhos.Select(Sanitizar)],
            TipoDestino = novo.TipoDestino,
            Destino = novo.Destino is null ? null : Sanitizar(novo.Destino),
            Decisao = novo.Decisao,
            Resultado = Sanitizar(novo.Resultado),
            NivelRisco = nivel,
            MensagemTecnica = Sanitizar(novo.MensagemTecnica),
            QuantidadeDeteccoes = novo.QuantidadeDeteccoes,
            OrigemMensagem = nivel == NivelRisco.Verde ? OrigemMensagem.Padrao : OrigemMensagem.Pendente,
            MensagemCidadao = nivel == NivelRisco.Verde ? MensagensLocais.Para(novo.Codigo, novo.Categorias) : null,
        };

        lock (_trava)
        {
            _eventos.AddFirst(evento);
            while (_eventos.Count > Math.Max(1, _opcoes.CapacidadeEventos))
            {
                _eventos.RemoveLast();
            }

            switch (evento.Codigo)
            {
                case CodigosEvento.AnaliseSemDeteccao:
                    _analisados++;
                    _semRisco++;
                    break;
                case CodigosEvento.PiiDetectado:
                    _analisados++;
                    _identificados += evento.QuantidadeDeteccoes;
                    break;
                case CodigosEvento.SinkBloqueado:
                    _bloqueados++;
                    break;
                case CodigosEvento.EntradaRejeitada:
                    _analisados++;
                    _rejeitados++;
                    break;
            }
        }

        logger.LogInformation("Evento de segurança {Id} {Codigo} · risco {Nivel} · fonte {Fonte} · destino {Destino} · decisão {Decisao} · categorias {Categorias} · correlação {Correlacao}",
            evento.Id, evento.Codigo, evento.NivelRisco, evento.Fonte, evento.Destino ?? "-", evento.Decisao, string.Join(",", evento.Categorias), evento.CorrelacaoId);

        if (nivel != NivelRisco.Verde)
        {
            fila.Enfileirar(evento.Id);
        }

        return evento;
    }

    public IReadOnlyList<EventoSeguranca> Listar(int limite = 50)
    {
        lock (_trava)
        {
            return [.. _eventos.Take(Math.Clamp(limite, 1, _opcoes.CapacidadeEventos))];
        }
    }

    public EventoSeguranca? Obter(string id)
    {
        lock (_trava)
        {
            return _eventos.FirstOrDefault(e => e.Id == id);
        }
    }

    public IReadOnlyList<EventoSeguranca> DaCorrelacao(string correlacaoId)
    {
        lock (_trava)
        {
            return [.. _eventos.Where(e => e.CorrelacaoId == correlacaoId).Reverse()];
        }
    }

    public IndicadoresSeguranca Indicadores()
    {
        lock (_trava)
        {
            return new IndicadoresSeguranca(_analisados, _identificados, _bloqueados, _semRisco, _rejeitados);
        }
    }

    public AvaliacaoRisco AvaliarRisco()
    {
        lock (_trava)
        {
            return CalculadoraRiscoCidadao.Avaliar(_eventos, relogio.GetUtcNow(), _opcoes.JanelaRiscoMinutos);
        }
    }

    /// <summary>Grava a explicação ao cidadão produzida pela IA ou pela mensagem local.</summary>
    public EventoSeguranca? AtualizarExplicacao(string id, ExplicacaoRisco explicacao)
    {
        ArgumentNullException.ThrowIfNull(explicacao);
        lock (_trava)
        {
            for (LinkedListNode<EventoSeguranca>? no = _eventos.First; no is not null; no = no.Next)
            {
                if (no.Value.Id == id)
                {
                    no.Value = no.Value with
                    {
                        MensagemCidadao = explicacao.Mensagem,
                        OrigemMensagem = explicacao.Origem,
                        MotivoFallback = explicacao.MotivoFallback,
                        ModeloLlm = explicacao.Modelo,
                        ExplicadoEm = relogio.GetUtcNow(),
                    };
                    return no.Value;
                }
            }
        }

        return null;
    }

    /// <summary>Limpa a trilha e os totais (usado pela demonstração, para começar do estado verde).</summary>
    public void Reiniciar()
    {
        lock (_trava)
        {
            _eventos.Clear();
            _analisados = _identificados = _bloqueados = _semRisco = _rejeitados = 0;
        }
    }

    private static string Sanitizar(string texto) =>
        MotorPii.Substituir(texto, (categoria, _) => MascaradorPii.MarcadorBloqueio(categoria), new List<CategoriaPii>());
}
