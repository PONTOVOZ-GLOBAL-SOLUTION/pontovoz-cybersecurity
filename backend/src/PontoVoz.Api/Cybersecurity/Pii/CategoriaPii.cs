namespace PontoVoz.Api.Cybersecurity.Pii;

/// <summary>Tipos de informação pessoal reconhecidos pelo motor de parsing.</summary>
public enum CategoriaPii
{
    Cpf,
    Rg,
    DocumentoIdentificador,
    Email,
    Telefone,
    Saude,
    Senha,
}

/// <summary>
/// Grau de proteção exigido. Segue a LGPD (art. 5º, I e II) para dados pessoais e dados pessoais
/// sensíveis; segredos de autenticação não são uma categoria da lei, mas recebem a proteção mais
/// restritiva porque permitem acesso em nome do titular.
/// </summary>
public enum Sensibilidade
{
    DadoPessoal,
    DadoPessoalSensivel,
    SegredoAutenticacao,
}

/// <summary>
/// Alta: o formato foi confirmado por regra forte (dígitos verificadores do CPF, nome do campo,
/// padrão inequívoco). Média: padrão plausível sem confirmação completa.
/// </summary>
public enum Confianca
{
    Media,
    Alta,
}

/// <summary>Como o valor é tratado antes de ser exibido: mascarado parcialmente ou suprimido por inteiro.</summary>
public enum AcaoProtecao
{
    Mascarar,
    Suprimir,
}

public static class CatalogoPii
{
    public static Sensibilidade Sensibilidade(CategoriaPii categoria) => categoria switch
    {
        CategoriaPii.Saude => Pii.Sensibilidade.DadoPessoalSensivel,
        CategoriaPii.Senha => Pii.Sensibilidade.SegredoAutenticacao,
        _ => Pii.Sensibilidade.DadoPessoal,
    };

    /// <summary>Senha e dado de saúde nunca são exibidos, nem parcialmente.</summary>
    public static AcaoProtecao Acao(CategoriaPii categoria) => Sensibilidade(categoria) == Pii.Sensibilidade.DadoPessoal
        ? AcaoProtecao.Mascarar
        : AcaoProtecao.Suprimir;

    /// <summary>Nome da categoria em linguagem comum, usado no painel e no prompt da IA.</summary>
    public static string Rotulo(CategoriaPii categoria) => categoria switch
    {
        CategoriaPii.Cpf => "CPF",
        CategoriaPii.Rg => "RG",
        CategoriaPii.DocumentoIdentificador => "documento de identificação",
        CategoriaPii.Email => "e-mail",
        CategoriaPii.Telefone => "telefone",
        CategoriaPii.Saude => "informação de saúde",
        CategoriaPii.Senha => "senha",
        _ => "informação pessoal",
    };
}
