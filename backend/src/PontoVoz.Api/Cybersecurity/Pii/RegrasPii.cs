using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace PontoVoz.Api.Cybersecurity.Pii;

/// <summary>
/// Regras de reconhecimento: pelo nome do campo (contexto) e pelo conteúdo (expressões regulares
/// com validação adicional). As regras de conteúdo valem para qualquer campo de texto, inclusive
/// campos genéricos como <c>observacao</c>, e também para texto livre (logs, JSON malformado).
/// </summary>
internal static partial class RegrasPii
{
    private const int TempoLimiteRegexMs = 250;

    /// <summary>Ocorrência de PII dentro de um texto: posição, categoria e regra que a confirmou.</summary>
    internal readonly record struct Ocorrencia(CategoriaPii Categoria, int Inicio, int Tamanho, string Regra, Confianca Confianca);

    /// <summary>
    /// Categoria indicada pelo nome do campo, ou <c>null</c>. O nome é dividido em palavras
    /// (camelCase, hífen, sublinhado) e comparado sem acentos, para que <c>cpfTitular</c>,
    /// <c>numero_cpf</c> e <c>CPF</c> tenham o mesmo resultado, mas <c>cargo</c> não seja lido como RG.
    /// </summary>
    public static CategoriaPii? CategoriaPorChave(string chave)
    {
        List<string> palavras = Palavras(chave);
        if (palavras.Count == 0)
        {
            return null;
        }

        string junto = string.Concat(palavras);

        if (ContemAlgum(junto, "senha", "password", "passwd", "secret", "segredo", "apikey", "chaveapi", "chaveacesso", "accesstoken", "refreshtoken")
            || palavras.Exists(p => p is "pwd" or "pin" or "token"))
        {
            return CategoriaPii.Senha;
        }

        if (ContemAlgum(junto, "laudo", "diagnostic", "prontuario", "doenca", "enfermidade", "medicament", "alergia", "tiposanguineo",
                "condicaomedica", "condicaosaude", "condicaodesaude", "saude", "sintoma", "deficiencia", "historicomedico", "tratamentomedico", "cid10")
            || palavras.Exists(p => p is "cid" or "exame" or "exames" or "medico" or "medica"))
        {
            return CategoriaPii.Saude;
        }

        if (junto.Contains("cpf", StringComparison.Ordinal))
        {
            return CategoriaPii.Cpf;
        }

        if (palavras.Contains("rg") || ContemAlgum(junto, "registrogeral", "identidade"))
        {
            return CategoriaPii.Rg;
        }

        if (ContemAlgum(junto, "email", "correioeletronico"))
        {
            return CategoriaPii.Email;
        }

        if (ContemAlgum(junto, "telefone", "celular", "whatsapp") || palavras.Exists(p => p is "fone" or "tel"))
        {
            return CategoriaPii.Telefone;
        }

        if (ContemAlgum(junto, "documento", "passaporte", "tituloeleitor", "cartaosus")
            || palavras.Exists(p => p is "cnh" or "cns" or "pis" or "nis" or "rne" or "crnm"))
        {
            return CategoriaPii.DocumentoIdentificador;
        }

        return null;
    }

    /// <summary>
    /// Ocorrências de PII num texto, sem sobreposição, em ordem de posição. Os padrões fracos
    /// (11 dígitos sem pontuação, CPF formatado com dígito verificador inválido) só valem com
    /// confirmação adicional, para evitar falsos positivos em códigos e números comuns.
    /// </summary>
    public static List<Ocorrencia> Localizar(string texto)
    {
        var encontradas = new List<Ocorrencia>();
        if (string.IsNullOrEmpty(texto))
        {
            return encontradas;
        }

        try
        {
            foreach (Match m in SenhaEmTexto().Matches(texto))
            {
                Group valor = m.Groups["valor"];
                Adicionar(encontradas, new(CategoriaPii.Senha, valor.Index, valor.Length, "texto-rotulo-senha", Confianca.Alta));
            }

            foreach (Match m in Email().Matches(texto))
            {
                Adicionar(encontradas, new(CategoriaPii.Email, m.Index, m.Length, "texto-email", Confianca.Alta));
            }

            foreach (Match m in CpfFormatado().Matches(texto))
            {
                if (ValidadorCpf.Valido(m.Value))
                {
                    Adicionar(encontradas, new(CategoriaPii.Cpf, m.Index, m.Length, "texto-cpf-formatado+dv", Confianca.Alta));
                }
                else if (RotuloAntes(texto, m.Index, "cpf"))
                {
                    Adicionar(encontradas, new(CategoriaPii.Cpf, m.Index, m.Length, "texto-rotulo-cpf+formato", Confianca.Media));
                }
            }

            foreach (Match m in TelefoneFormatado().Matches(texto))
            {
                Adicionar(encontradas, new(CategoriaPii.Telefone, m.Index, m.Length, "texto-telefone-formatado", Confianca.Alta));
            }

            foreach (Match m in RgComRotulo().Matches(texto))
            {
                Group valor = m.Groups["valor"];
                Adicionar(encontradas, new(CategoriaPii.Rg, valor.Index, valor.Length, "texto-rotulo-rg", Confianca.Alta));
            }

            foreach (Match m in RgFormatado().Matches(texto))
            {
                Adicionar(encontradas, new(CategoriaPii.Rg, m.Index, m.Length, "texto-formato-rg", Confianca.Media));
            }

            foreach (Match m in OnzeDigitos().Matches(texto))
            {
                if (PareceCelular(m.Value))
                {
                    Adicionar(encontradas, new(CategoriaPii.Telefone, m.Index, m.Length, "texto-11-digitos-celular", Confianca.Media));
                }
                else if (ValidadorCpf.Valido(m.Value))
                {
                    Adicionar(encontradas, new(CategoriaPii.Cpf, m.Index, m.Length, "texto-11-digitos+dv", Confianca.Media));
                }
            }

            foreach (Match m in CodigoCid().Matches(texto))
            {
                Adicionar(encontradas, new(CategoriaPii.Saude, m.Index, m.Length, "texto-codigo-cid", Confianca.Alta));
            }

            foreach (Match m in ExpressaoSaude().Matches(texto))
            {
                // A expressão só indica o início do relato clínico; a ocorrência vai até o fim da frase.
                int fim = FimDaFrase(texto, m.Index + m.Length);
                Adicionar(encontradas, new(CategoriaPii.Saude, m.Index, fim - m.Index, "texto-expressao-saude", Confianca.Media));
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // Entrada patológica: o texto inteiro é tratado como sensível (falha segura).
            encontradas.Clear();
            encontradas.Add(new(CategoriaPii.DocumentoIdentificador, 0, texto.Length, "texto-tempo-limite-analise", Confianca.Media));
        }

        encontradas.Sort((a, b) => a.Inicio.CompareTo(b.Inicio));
        return encontradas;
    }

    /// <summary>
    /// Ocorrências num texto que pode conter JSON incompleto (corpo malformado, mensagem de log):
    /// primeiro os pares <c>"campo": valor</c> com nome de campo sensível, depois as regras de conteúdo.
    /// </summary>
    public static List<Ocorrencia> LocalizarEmTextoBruto(string texto)
    {
        var encontradas = new List<Ocorrencia>();
        if (string.IsNullOrEmpty(texto))
        {
            return encontradas;
        }

        try
        {
            foreach (Match m in ParChaveValor().Matches(texto))
            {
                Group valor = m.Groups["valor"];
                if (valor.Length > 0 && !JaProtegido(valor.Value) && CategoriaPorChave(m.Groups["chave"].Value) is { } categoria)
                {
                    Adicionar(encontradas, new(categoria, valor.Index, valor.Length, "texto-par-campo-sensivel", Confianca.Alta));
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return [new(CategoriaPii.DocumentoIdentificador, 0, texto.Length, "texto-tempo-limite-analise", Confianca.Media)];
        }

        foreach (Ocorrencia ocorrencia in Localizar(texto))
        {
            Adicionar(encontradas, ocorrencia);
        }

        encontradas.Sort((a, b) => a.Inicio.CompareTo(b.Inicio));
        return encontradas;
    }

    /// <summary>Palavras do nome de um campo, em minúsculas e sem acentos.</summary>
    internal static List<string> Palavras(string chave)
    {
        var palavras = new List<string>();
        var atual = new StringBuilder();
        char anterior = '\0';
        foreach (char original in SemAcentos(chave))
        {
            if (!char.IsLetterOrDigit(original))
            {
                Fechar();
            }
            else
            {
                if (char.IsUpper(original) && (char.IsLower(anterior) || char.IsDigit(anterior)))
                {
                    Fechar();
                }

                atual.Append(char.ToLowerInvariant(original));
            }

            anterior = original;
        }

        Fechar();
        return palavras;

        void Fechar()
        {
            if (atual.Length > 0)
            {
                palavras.Add(atual.ToString());
                atual.Clear();
            }
        }
    }

    internal static string SomenteDigitos(string valor) => string.Concat(valor.Where(char.IsAsciiDigit));

    /// <summary>Valor que já é uma máscara (<c>***.456.***-00</c>) ou um marcador (<c>[SENHA REMOVIDA]</c>).</summary>
    internal static bool JaProtegido(string valor) =>
        valor.Contains("***", StringComparison.Ordinal) || (valor.StartsWith('[') && valor.EndsWith(']'));

    /// <summary>11 dígitos com DDD válido e o nono dígito de celular (9) na terceira posição.</summary>
    private static bool PareceCelular(string digitos) =>
        digitos.Length == 11 && digitos[0] != '0' && digitos[1] != '0' && digitos[2] == '9';

    private static bool RotuloAntes(string texto, int posicao, string rotulo)
    {
        int inicio = Math.Max(0, posicao - 20);
        return texto.AsSpan(inicio, posicao - inicio).Contains(rotulo, StringComparison.OrdinalIgnoreCase);
    }

    private static int FimDaFrase(string texto, int posicao)
    {
        int fim = texto.IndexOfAny(['.', ';', '"', '\n', '\r', '}', ']'], posicao);
        return fim < 0 ? texto.Length : fim;
    }

    private static void Adicionar(List<Ocorrencia> encontradas, Ocorrencia nova)
    {
        if (nova.Tamanho <= 0)
        {
            return;
        }

        int fimNova = nova.Inicio + nova.Tamanho;
        bool sobrepoe = encontradas.Exists(e => nova.Inicio < e.Inicio + e.Tamanho && e.Inicio < fimNova);
        if (!sobrepoe)
        {
            encontradas.Add(nova);
        }
    }

    private static bool ContemAlgum(string texto, params string[] termos) =>
        Array.Exists(termos, termo => texto.Contains(termo, StringComparison.Ordinal));

    private static string SemAcentos(string texto)
    {
        string decomposto = texto.Normalize(NormalizationForm.FormD);
        var resultado = new StringBuilder(decomposto.Length);
        foreach (char c in decomposto)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
            {
                resultado.Append(c);
            }
        }

        return resultado.ToString();
    }

    [GeneratedRegex(@"""(?<chave>[^""\\]{1,64})""\s*:\s*(?:""(?<valor>(?:[^""\\]|\\.){1,2048})""|(?<valor>-?\d{4,20}))", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex ParChaveValor();

    [GeneratedRegex(@"(?<![\w.])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\w])", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex CpfFormatado();

    [GeneratedRegex(@"(?<![\w.\-])\d{11}(?![\w])", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex OnzeDigitos();

    [GeneratedRegex(@"\bRG\b\s*(?:n[º°o.]?\s*)?[:\-]?\s*(?<valor>\d[\dXx.\-]{4,13}[\dXx])", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TempoLimiteRegexMs)]
    private static partial Regex RgComRotulo();

    [GeneratedRegex(@"(?<![\w.])\d{1,2}\.\d{3}\.\d{3}-[\dXx](?![\w])", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex RgFormatado();

    [GeneratedRegex(@"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex Email();

    [GeneratedRegex(@"(?:\+55\s?)?\(\d{2}\)\s?9?\d{4}-?\d{4}(?!\d)|\+55\s?\d{2}\s?9?\d{4}-?\d{4}(?!\d)|(?<![\d\-:])\d{2}\s9\d{4}-\d{4}(?!\d)", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex TelefoneFormatado();

    [GeneratedRegex(@"\b(?:senha|password|passwd|pwd)\b\s*[:=]\s*(?<valor>[^\s""',;}]{1,128})", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TempoLimiteRegexMs)]
    private static partial Regex SenhaEmTexto();

    [GeneratedRegex(@"\bCID(?:[\s\-]?10)?[\s:\-]*[A-TV-Z]\d{2}(?:\.\d{1,2})?\b", RegexOptions.CultureInvariant, TempoLimiteRegexMs)]
    private static partial Regex CodigoCid();

    [GeneratedRegex(@"\b(?:laudo\s+m[eé]dico|laudo\s+de\s+\w+|diagn[oó]stic[oa]\w*\s+(?:de|com)|diagnosticad[oa]\s+com|prontu[aá]rio|portador[a]?\s+de|soropositiv[oa]|tratamento\s+(?:oncol[oó]gico|psiqui[aá]trico|psicol[oó]gico|para|de)|uso\s+cont[ií]nuo\s+de)\b",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TempoLimiteRegexMs)]
    private static partial Regex ExpressaoSaude();
}
