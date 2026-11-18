using System.Security.Cryptography;
using System.Text;

using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Api.Cybersecurity.Sinks;

/// <summary>
/// Sink de log. Envolve cada provedor de log registrado (console, debug, event log...) e verifica
/// toda mensagem, inclusive o texto das exceções, antes que ela seja escrita. Uma mensagem sem
/// dado protegido segue intacta, com o estado estruturado original; uma mensagem contaminada é
/// substituída pela versão sanitizada e a exceção não é repassada (seu texto já está incluído,
/// sanitizado, na mensagem).
/// </summary>
public sealed class ProvedorLogProtegido(ILoggerProvider interno, IServiceProvider servicos) : ILoggerProvider, ISupportExternalScope
{
    private GuardaSinks? _guarda;

    public ILoggerProvider Interno => interno;

    public ILogger CreateLogger(string categoryName) => new LoggerProtegido(interno.CreateLogger(categoryName), categoryName, this);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider)
    {
        if (interno is ISupportExternalScope comEscopo)
        {
            comEscopo.SetScopeProvider(scopeProvider);
        }
    }

    public void Dispose() => interno.Dispose();

    // Resolvida na primeira mensagem: os provedores de log são criados antes dos serviços do módulo.
    private GuardaSinks Guarda => _guarda ??= servicos.GetRequiredService<GuardaSinks>();

    private sealed class LoggerProtegido(ILogger interno, string categoria, ProvedorLogProtegido provedor) : ILogger
    {
        // Evita reentrada: o registro de um evento também escreve no log.
        [ThreadStatic]
        private static bool t_verificando;

        // A fábrica de logs entrega a mesma mensagem a cada provedor (console, event log...), em
        // sequência e na mesma thread. A verificação é feita uma vez e reaproveitada pelos demais,
        // para que uma tentativa gere um único evento de auditoria.
        // Só o hash da mensagem é guardado: o texto original pode conter o dado protegido.
        [ThreadStatic]
        private static byte[]? t_ultimaMensagem;

        [ThreadStatic]
        private static ResultadoProtecaoSink? t_ultimoResultado;

        [ThreadStatic]
        private static string? t_ultimoContexto;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => interno.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => interno.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!interno.IsEnabled(logLevel))
            {
                return;
            }

            if (t_verificando)
            {
                interno.Log(logLevel, eventId, state, exception, formatter);
                return;
            }

            string mensagem = formatter(state, exception);
            string completa = exception is null ? mensagem : $"{mensagem}{Environment.NewLine}{exception}";

            ResultadoProtecaoSink resultado;
            string? contexto = provedor.Guarda.ContextoAtual?.CorrelacaoId;
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(completa));
            if (t_ultimoResultado is not null && t_ultimaMensagem is not null && t_ultimoContexto == contexto && hash.AsSpan().SequenceEqual(t_ultimaMensagem))
            {
                resultado = t_ultimoResultado;
            }
            else
            {
                t_verificando = true;
                try
                {
                    resultado = provedor.Guarda.Proteger(TipoSink.Log, completa, $"log:{categoria}");
                }
                finally
                {
                    t_verificando = false;
                }

                t_ultimaMensagem = hash;
                t_ultimoResultado = resultado;
                t_ultimoContexto = contexto;
            }

            if (!resultado.Interceptado)
            {
                interno.Log(logLevel, eventId, state, exception, formatter);
                return;
            }

            interno.Log(logLevel, eventId, resultado.Conteudo, null, static (texto, _) => texto);
        }
    }
}

public static class LogProtegidoExtensions
{
    /// <summary>
    /// Substitui cada <see cref="ILoggerProvider"/> já registrado por um <see cref="ProvedorLogProtegido"/>
    /// que o envolve. Pode ser chamada de novo depois de registrar outros provedores: os já
    /// protegidos não são envolvidos duas vezes.
    /// </summary>
    public static IServiceCollection ProtegerSinksDeLog(this IServiceCollection services)
    {
        for (int i = 0; i < services.Count; i++)
        {
            ServiceDescriptor descritor = services[i];
            if (descritor.ServiceType != typeof(ILoggerProvider) || descritor.IsKeyedService || descritor.ImplementationFactory?.Target is FabricaProtegida)
            {
                continue;
            }

            var fabrica = new FabricaProtegida(descritor);
            services[i] = ServiceDescriptor.Singleton<ILoggerProvider>(fabrica.Criar);
        }

        return services;
    }

    private sealed class FabricaProtegida(ServiceDescriptor original)
    {
        public ILoggerProvider Criar(IServiceProvider servicos)
        {
            var interno = (ILoggerProvider)(original.ImplementationInstance
                ?? original.ImplementationFactory?.Invoke(servicos)
                ?? ActivatorUtilities.CreateInstance(servicos, original.ImplementationType!));
            return new ProvedorLogProtegido(interno, servicos);
        }
    }
}
