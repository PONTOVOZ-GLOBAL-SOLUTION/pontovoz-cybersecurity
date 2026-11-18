namespace PontoVoz.Api.Cybersecurity.Auditoria;

/// <summary>Estado do indicador de Risco Cidadão.</summary>
/// <param name="Nivel">Verde, amarelo ou vermelho.</param>
/// <param name="Titulo">Frase curta exibida junto ao farol.</param>
/// <param name="Descricao">O que o nível significa no período considerado.</param>
/// <param name="EventoReferenciaId">Evento mais recente que determinou o nível (nulo no verde sem eventos).</param>
/// <param name="JanelaMinutos">Período considerado.</param>
public sealed record AvaliacaoRisco(NivelRisco Nivel, string Titulo, string Descricao, string? EventoReferenciaId, int JanelaMinutos);

/// <summary>
/// Regras do indicador. A decisão é técnica e determinística, derivada dos eventos registrados
/// pelo backend; a IA só redige a explicação.
/// <list type="bullet">
/// <item><b>Verde:</b> nenhuma informação pessoal e nenhuma tentativa insegura na janela.</item>
/// <item><b>Amarelo:</b> informação pessoal detectada e protegida (ou entrada recusada), sem tentativa de saída insegura.</item>
/// <item><b>Vermelho:</b> ao menos uma tentativa de levar dado protegido a uma saída não autorizada foi interceptada.
/// Indica a gravidade da tentativa, não a confirmação de vazamento.</item>
/// </list>
/// </summary>
public static class CalculadoraRiscoCidadao
{
    public static NivelRisco ClassificarEvento(string codigo) => codigo switch
    {
        CodigosEvento.SinkBloqueado => NivelRisco.Vermelho,
        CodigosEvento.PiiDetectado or CodigosEvento.EntradaRejeitada => NivelRisco.Amarelo,
        _ => NivelRisco.Verde,
    };

    public static AvaliacaoRisco Avaliar(IEnumerable<EventoSeguranca> eventos, DateTimeOffset agora, int janelaMinutos)
    {
        DateTimeOffset inicio = agora.AddMinutes(-janelaMinutos);
        List<EventoSeguranca> recentes = [.. eventos.Where(e => e.OcorridoEm >= inicio)];

        EventoSeguranca? referencia = recentes
            .OrderByDescending(e => e.NivelRisco)
            .ThenByDescending(e => e.OcorridoEm)
            .FirstOrDefault();
        NivelRisco nivel = referencia?.NivelRisco ?? NivelRisco.Verde;

        int bloqueios = recentes.Count(e => e.NivelRisco == NivelRisco.Vermelho);
        int protegidos = recentes.Where(e => e.Codigo == CodigosEvento.PiiDetectado).Sum(e => e.QuantidadeDeteccoes);

        return nivel switch
        {
            NivelRisco.Vermelho => new AvaliacaoRisco(nivel, "Tentativa de saída insegura bloqueada",
                $"{Plural(bloqueios, "tentativa", "tentativas")} de enviar dado pessoal para destino não autorizado nos últimos {janelaMinutos} minutos. " +
                "A política de proteção interceptou o envio: o valor original não chegou ao destino.",
                referencia!.Id, janelaMinutos),
            NivelRisco.Amarelo => new AvaliacaoRisco(nivel, "Dado pessoal identificado e protegido",
                protegidos > 0
                    ? $"{Plural(protegidos, "ocorrência de dado pessoal reconhecida e mascarada", "ocorrências de dados pessoais reconhecidas e mascaradas")} nos últimos {janelaMinutos} minutos, sem tentativa de saída insegura."
                    : $"Entrada recusada por não poder ser verificada com segurança nos últimos {janelaMinutos} minutos.",
                referencia!.Id, janelaMinutos),
            _ => new AvaliacaoRisco(nivel, "Nenhuma tentativa insegura observada",
                recentes.Count == 0
                    ? $"Nenhuma requisição analisada nos últimos {janelaMinutos} minutos."
                    : $"As requisições analisadas nos últimos {janelaMinutos} minutos não continham dados pessoais.",
                referencia?.Id, janelaMinutos),
        };
    }

    private static string Plural(int quantidade, string singular, string plural) => $"{quantidade} {(quantidade == 1 ? singular : plural)}";
}
