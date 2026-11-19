using System.Runtime.CompilerServices;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>
/// Os testes sobem a API em Development, que lê os user-secrets da máquina. Se uma chave de LLM
/// estiver configurada para a demonstração, a tradução automática chamaria o provedor real durante
/// os testes. A variável de ambiente (que tem precedência sobre os user-secrets) desliga o provedor;
/// os testes que exercitam a IA usam clientes simulados.
/// </summary>
internal static class SemProvedorLlmNosTestes
{
    [ModuleInitializer]
    internal static void Configurar() => Environment.SetEnvironmentVariable("Cybersecurity__Llm__Provedor", "Nenhum");
}
