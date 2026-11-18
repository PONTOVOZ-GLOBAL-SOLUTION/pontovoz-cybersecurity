namespace PontoVoz.Api.Cybersecurity.Pii;

/// <summary>Validação dos dígitos verificadores do CPF (módulo 11).</summary>
public static class ValidadorCpf
{
    /// <summary>
    /// Verdadeiro se os 11 dígitos (pontuação ignorada) formam um CPF com dígitos verificadores
    /// corretos. Sequências repetidas (111.111.111-11) satisfazem o cálculo, mas não são CPFs válidos.
    /// </summary>
    public static bool Valido(string? valor)
    {
        if (valor is null)
        {
            return false;
        }

        Span<int> digitos = stackalloc int[11];
        int quantidade = 0;
        foreach (char caractere in valor)
        {
            if (char.IsAsciiDigit(caractere))
            {
                if (quantidade == 11)
                {
                    return false;
                }

                digitos[quantidade++] = caractere - '0';
            }
            else if (caractere is not ('.' or '-' or ' '))
            {
                return false;
            }
        }

        if (quantidade != 11 || TodosIguais(digitos))
        {
            return false;
        }

        return digitos[9] == DigitoVerificador(digitos[..9]) && digitos[10] == DigitoVerificador(digitos[..10]);
    }

    private static int DigitoVerificador(ReadOnlySpan<int> base_)
    {
        int soma = 0;
        int peso = base_.Length + 1;
        foreach (int digito in base_)
        {
            soma += digito * peso--;
        }

        int resto = soma % 11;
        return resto < 2 ? 0 : 11 - resto;
    }

    private static bool TodosIguais(ReadOnlySpan<int> digitos)
    {
        foreach (int digito in digitos)
        {
            if (digito != digitos[0])
            {
                return false;
            }
        }

        return true;
    }
}
