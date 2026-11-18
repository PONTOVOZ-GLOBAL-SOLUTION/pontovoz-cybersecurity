using System.Text.RegularExpressions;

using PontoVoz.Api.Cybersecurity.Pii;

namespace PontoVoz.Api.Cybersecurity.IA;

public sealed record ValidacaoMensagem(bool Valida, string Mensagem, string? Motivo);

/// <summary>
/// Confere a resposta do LLM antes de ela chegar ao cidadão. Uma resposta reprovada é descartada
/// e substituída pela mensagem local; o motivo fica registrado na auditoria técnica.
/// </summary>
public static partial class ValidadorMensagemCidadao
{
    private static readonly string[] PalavrasPortugues = [" o ", " a ", " de ", " que ", " para ", " seu ", " sua ", " foi ", " não ", " os ", " as ", " uma ", " um ", " e ", " do ", " da ", " seus ", " suas "];

    public static ValidacaoMensagem Validar(string? resposta, int tamanhoMaximo, bool houveBloqueio)
    {
        if (string.IsNullOrWhiteSpace(resposta))
        {
            return Reprovada(string.Empty, "RespostaVazia");
        }

        string mensagem = Normalizar(resposta);

        if (mensagem.Length > tamanhoMaximo || Frases(mensagem) > 3)
        {
            return Reprovada(mensagem, "RespostaLonga");
        }

        if (TermoTecnico().IsMatch(mensagem))
        {
            return Reprovada(mensagem, "TermoTecnico");
        }

        if (houveBloqueio && AfirmaVazamento().IsMatch(mensagem))
        {
            return Reprovada(mensagem, "AfirmaVazamento");
        }

        if (PromessaAbsoluta().IsMatch(mensagem))
        {
            return Reprovada(mensagem, "PromessaAbsoluta");
        }

        if (Alarmismo().IsMatch(mensagem))
        {
            return Reprovada(mensagem, "Alarmismo");
        }

        if (RegrasPii.LocalizarEmTextoBruto(mensagem).Count > 0)
        {
            return Reprovada(mensagem, "ContemDadoPessoal");
        }

        string comEspacos = $" {mensagem.ToLowerInvariant()} ";
        if (PalavrasPortugues.Count(p => comEspacos.Contains(p, StringComparison.Ordinal)) < 2)
        {
            return Reprovada(mensagem, "IdiomaInesperado");
        }

        return new ValidacaoMensagem(true, mensagem, null);
    }

    /// <summary>Remove aspas, marcação e quebras de linha que os modelos costumam acrescentar.</summary>
    internal static string Normalizar(string resposta)
    {
        string texto = resposta.Replace("**", string.Empty, StringComparison.Ordinal).Replace("`", string.Empty, StringComparison.Ordinal);
        texto = EspacosRepetidos().Replace(texto, " ").Trim();
        texto = texto.Trim('"', '\'', '“', '”', ' ');
        return texto;
    }

    private static int Frases(string mensagem) =>
        FimDeFrase().Split(mensagem).Count(parte => !string.IsNullOrWhiteSpace(parte));

    private static ValidacaoMensagem Reprovada(string mensagem, string motivo) => new(false, mensagem, motivo);

    [GeneratedRegex(@"\s+")]
    private static partial Regex EspacosRepetidos();

    [GeneratedRegex(@"[.!?]+(?:\s|$)")]
    private static partial Regex FimDeFrase();

    [GeneratedRegex(@"\b(?:middleware|sinks?|taint|stack\s*trace|payload|json|https?|endpoints?|logs?|exceptions?|exce[çc][aã]o|erro\s*\d{3}|api|backend|regex|pii|status\s*code)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TermoTecnico();

    [GeneratedRegex(@"\b(?:houve|ocorreu|aconteceu)\s+(?:um\s+)?vazamento|\bvaza(?:ram|ou|dos?|das?)\b|\bforam\s+(?:expost[oa]s|vazad[oa]s|roubad[oa]s|divulgad[oa]s)\b|\bfoi\s+(?:expost[oa]|vazad[oa]|roubad[oa]|divulgad[oa])\b|\binvadid[oa]s?\b|\bhacke", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AfirmaVazamento();

    [GeneratedRegex(@"100\s*%|\btotalmente\s+(?:segur|protegid)|\bcompletamente\s+(?:segur|protegid)|\bgarant(?:imos|ia\s+total|e\s+que)|\bjamais\b|\bnunca\s+(?:ser[aá]|ir[aá]|poder[aá])|\brisco\s+zero\b|\bimposs[ií]vel\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PromessaAbsoluta();

    [GeneratedRegex(@"\burgente\b|\bperigo\b|\bgrav[ei]ssim|\bimediatamente\b|\bataque\b|\bcriminos|\bfraude\b|!{2,}|\balerta\s+m[aá]ximo\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Alarmismo();
}
