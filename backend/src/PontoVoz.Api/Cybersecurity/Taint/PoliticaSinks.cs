using PontoVoz.Api.Cybersecurity.Pii;

namespace PontoVoz.Api.Cybersecurity.Taint;

/// <summary>Saídas (sinks) monitoradas pelo Taint Analysis.</summary>
public enum TipoSink
{
    Log,
    RespostaHttp,
    Persistencia,
    ServicoExterno,
}

public enum DecisaoPolitica
{
    Permitir,
    Mascarar,
    Bloquear,
}

/// <summary>
/// Política explícita de saída. Em saídas de fluxo (log e resposta HTTP), "bloquear" significa
/// trocar o valor por um marcador sem nenhum trecho do original; em saídas transacionais
/// (persistência e serviço externo), a operação inteira é recusada.
/// <list type="table">
/// <listheader><term>Saída</term><description>Dado pessoal · Dado sensível (saúde) · Segredo (senha)</description></listheader>
/// <item><term>Log</term><description>Mascarar · Bloquear · Bloquear</description></item>
/// <item><term>Resposta HTTP</term><description>Mascarar · Bloquear · Bloquear</description></item>
/// <item><term>Persistência</term><description>Bloquear · Bloquear · Bloquear (o PontoVoz não precisa guardar dados pessoais)</description></item>
/// <item><term>Serviço externo</term><description>Bloquear · Bloquear · Bloquear (inclui o LLM)</description></item>
/// </list>
/// </summary>
public static class PoliticaSinks
{
    public static DecisaoPolitica Decidir(TipoSink sink, Sensibilidade sensibilidade) => (sink, sensibilidade) switch
    {
        (TipoSink.Persistencia or TipoSink.ServicoExterno, _) => DecisaoPolitica.Bloquear,
        (_, Sensibilidade.DadoPessoalSensivel or Sensibilidade.SegredoAutenticacao) => DecisaoPolitica.Bloquear,
        _ => DecisaoPolitica.Mascarar,
    };

    /// <summary>Texto que substitui o valor na saída, conforme a decisão.</summary>
    public static string Substituto(DecisaoPolitica decisao, CategoriaPii categoria, string valor) =>
        decisao == DecisaoPolitica.Bloquear ? MascaradorPii.MarcadorBloqueio(categoria) : MascaradorPii.Mascarar(categoria, valor);
}
