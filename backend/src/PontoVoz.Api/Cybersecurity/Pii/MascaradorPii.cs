using System.Text;

namespace PontoVoz.Api.Cybersecurity.Pii;

/// <summary>
/// Versões exibíveis dos valores detectados. CPF segue o formato indicado pelo professor
/// (<c>***.456.***-00</c>); documentos e telefones mantêm só os últimos caracteres; senha e dado
/// de saúde são substituídos por um marcador, sem nenhum trecho do original.
/// </summary>
public static class MascaradorPii
{
    public const string MarcadorSenha = "[SENHA REMOVIDA]";
    public const string MarcadorSaude = "[DADO DE SAÚDE PROTEGIDO]";

    public static string Mascarar(CategoriaPii categoria, string valor) => categoria switch
    {
        CategoriaPii.Cpf => MascararCpf(valor),
        CategoriaPii.Rg or CategoriaPii.DocumentoIdentificador => ManterFinais(valor, 2),
        CategoriaPii.Telefone => ManterFinais(valor, 4),
        CategoriaPii.Email => MascararEmail(valor),
        CategoriaPii.Saude => MarcadorSaude,
        CategoriaPii.Senha => MarcadorSenha,
        _ => ManterFinais(valor, 0),
    };

    /// <summary>Marcador usado quando a política bloqueia o valor numa saída (nenhum trecho é mantido).</summary>
    public static string MarcadorBloqueio(CategoriaPii categoria) => $"[BLOQUEADO: {CatalogoPii.Rotulo(categoria).ToUpperInvariant()}]";

    private static string MascararCpf(string valor)
    {
        string digitos = RegrasPii.SomenteDigitos(valor);
        return digitos.Length == 11
            ? $"***.{digitos.Substring(3, 3)}.***-{digitos.Substring(9, 2)}"
            : ManterFinais(valor, 2);
    }

    private static string MascararEmail(string valor)
    {
        int arroba = valor.LastIndexOf('@');
        if (arroba < 1 || arroba == valor.Length - 1)
        {
            return ManterFinais(valor, 0);
        }

        string dominio = valor[(arroba + 1)..];
        int ponto = dominio.LastIndexOf('.');
        string sufixo = ponto > 0 ? dominio[ponto..] : string.Empty;
        return $"{valor[0]}***@{dominio[0]}***{sufixo}";
    }

    /// <summary>Troca letras e dígitos por <c>*</c>, mantendo a pontuação e os <paramref name="finais"/> últimos caracteres.</summary>
    private static string ManterFinais(string valor, int finais)
    {
        int total = valor.Count(char.IsLetterOrDigit);
        int manterApartirDe = total <= finais ? int.MaxValue : total - finais;
        var resultado = new StringBuilder(valor.Length);
        int posicao = 0;
        foreach (char c in valor)
        {
            if (char.IsLetterOrDigit(c))
            {
                resultado.Append(posicao >= manterApartirDe ? c : '*');
                posicao++;
            }
            else
            {
                resultado.Append(c);
            }
        }

        return resultado.ToString();
    }
}
