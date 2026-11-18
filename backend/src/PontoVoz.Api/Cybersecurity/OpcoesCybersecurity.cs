namespace PontoVoz.Api.Cybersecurity;

/// <summary>Configuração do módulo (seção <c>Cybersecurity</c> do appsettings).</summary>
public sealed class OpcoesCybersecurity
{
    public const string Secao = "Cybersecurity";

    /// <summary>Corpos maiores não são analisados nem processados: a requisição recebe 413.</summary>
    public int LimiteCorpoBytes { get; set; } = 64 * 1024;

    /// <summary>Profundidade máxima de objetos e listas aninhados num corpo JSON.</summary>
    public int ProfundidadeMaximaJson { get; set; } = 32;

    /// <summary>Quantidade máxima de nós (objetos, listas e valores) num corpo JSON.</summary>
    public int LimiteNosJson { get; set; } = 5000;

    /// <summary>Eventos mantidos em memória para o painel; os mais antigos são descartados.</summary>
    public int CapacidadeEventos { get; set; } = 500;

    /// <summary>Intervalo considerado pelo indicador de Risco Cidadão.</summary>
    public int JanelaRiscoMinutos { get; set; } = 30;

    public OpcoesDemonstracao Demonstracao { get; set; } = new();

    public OpcoesLlm Llm { get; set; } = new();
}

/// <summary>
/// Rotas de demonstração (tentativa controlada de saída insegura e reinício do painel). Só
/// funcionam em Development, com <see cref="Habilitada"/> verdadeira e chamadas da própria máquina.
/// </summary>
public sealed class OpcoesDemonstracao
{
    public bool Habilitada { get; set; }
}

public sealed class OpcoesLlm
{
    /// <summary><c>Gemini</c>, <c>OpenAI</c> ou <c>Nenhum</c> (somente mensagens locais).</summary>
    public string Provedor { get; set; } = "Gemini";

    public string Modelo { get; set; } = "gemini-2.5-flash";

    /// <summary>Endereço base da API do provedor; vazio usa o endereço oficial.</summary>
    public string? UrlBase { get; set; }

    /// <summary>
    /// Chave do provedor. Nunca é gravada em arquivo do repositório: use user-secrets
    /// (<c>Cybersecurity:Llm:ChaveApi</c>) ou a variável indicada em <see cref="VariavelAmbienteChave"/>.
    /// </summary>
    public string? ChaveApi { get; set; }

    /// <summary>Variável de ambiente lida quando <see cref="ChaveApi"/> está vazia.</summary>
    public string VariavelAmbienteChave { get; set; } = "GEMINI_API_KEY";

    public int TempoLimiteSegundos { get; set; } = 10;

    /// <summary>Mensagens maiores que este limite são descartadas e substituídas pela mensagem local.</summary>
    public int TamanhoMaximoMensagem { get; set; } = 320;

    /// <summary>Gera automaticamente a explicação dos eventos com risco amarelo ou vermelho.</summary>
    public bool TraducaoAutomatica { get; set; } = true;
}
