using PontoVoz.Api.Cybersecurity.Pii;

namespace PontoVoz.Api.Cybersecurity.Taint;

/// <summary>Marca de contaminação de um campo: o que foi detectado, onde e por qual fonte entrou.</summary>
/// <param name="Id">Identificador da marca dentro da requisição (<c>T1</c>, <c>T2</c>...).</param>
/// <param name="Categoria">Tipo de dado.</param>
/// <param name="Sensibilidade">Grau de proteção, usado pela política de cada saída.</param>
/// <param name="Caminho">Caminho JSON ou nome do campo.</param>
/// <param name="TipoFonte">Fonte da entrada: corpo JSON, query string, formulário ou texto.</param>
/// <param name="Regra">Regra do motor PII que originou a marca.</param>
public sealed record MarcaTaint(string Id, CategoriaPii Categoria, Sensibilidade Sensibilidade, string Caminho, string TipoFonte, string Regra);

public enum EstadoTaint
{
    /// <summary>Nenhum dado pessoal entrou pela requisição.</summary>
    Limpo,

    /// <summary>Há valores marcados: toda saída desta requisição passa pela verificação da política.</summary>
    Contaminado,
}

/// <summary>
/// Estado de contaminação de uma requisição (source). Criado pelo interceptador de entrada,
/// guardado em <c>HttpContext.Features</c> e consultado por todas as saídas (sinks) até o fim da
/// requisição. Os valores originais ficam somente nesta memória, que é descartada com a requisição.
/// </summary>
public sealed class ContextoTaint(string correlacaoId, string fonte)
{
    private readonly Lock _trava = new();
    private readonly List<MarcaTaint> _marcas = [];
    private readonly List<ValorContaminado> _valores = [];

    public string CorrelacaoId { get; } = correlacaoId;

    /// <summary>Método e rota da requisição, sem query string (que pode conter o próprio dado).</summary>
    public string Fonte { get; } = fonte;

    public EstadoTaint Estado
    {
        get
        {
            lock (_trava)
            {
                return _marcas.Count == 0 ? EstadoTaint.Limpo : EstadoTaint.Contaminado;
            }
        }
    }

    public IReadOnlyList<MarcaTaint> Marcas
    {
        get
        {
            lock (_trava)
            {
                return [.. _marcas];
            }
        }
    }

    /// <summary>Análise do corpo da requisição, para a rota de análise devolver o resultado sem repetir o trabalho.</summary>
    public ResultadoAnalisePii? AnaliseCorpo { get; internal set; }

    internal IReadOnlyList<ValorContaminado> Valores
    {
        get
        {
            lock (_trava)
            {
                // Valores maiores primeiro: assim "529.982.247-25" é substituído antes de "52998224725".
                return [.. _valores.OrderByDescending(v => v.Valor.Length)];
            }
        }
    }

    /// <summary>Propaga para a requisição as detecções de uma fonte.</summary>
    internal void Contaminar(ResultadoAnalisePii analise, string tipoFonte)
    {
        lock (_trava)
        {
            foreach (DeteccaoPii deteccao in analise.Deteccoes)
            {
                _marcas.Add(new MarcaTaint($"T{_marcas.Count + 1}", deteccao.Categoria, deteccao.Sensibilidade, deteccao.Caminho, tipoFonte, deteccao.Regra));
            }

            foreach (ValorContaminado valor in analise.Valores)
            {
                if (!_valores.Exists(v => v.Valor == valor.Valor))
                {
                    _valores.Add(valor);
                }
            }
        }
    }
}
