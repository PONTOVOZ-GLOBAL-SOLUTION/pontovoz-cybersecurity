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

    /// <summary>
    /// Os escopos (<c>BeginScope</c>) ficam num provedor externo mantido pela fábrica de logs e são
    /// lidos por cada provedor na hora de escrever. O acesso de leitura é envolvido para que cada
    /// escopo passe pela mesma verificação das mensagens antes de chegar ao destino.
    /// </summary>
    public void SetScopeProvider(IExternalScopeProvider scopeProvider)
    {
        if (interno is ISupportExternalScope comEscopo)
        {
            comEscopo.SetScopeProvider(scopeProvider is EscoposProtegidos ? scopeProvider : new EscoposProtegidos(scopeProvider, this));
        }
    }

    /// <summary>Versão sanitizada do escopo, ou <c>null</c> quando ele não contém dado protegido.</summary>
    internal string? EscopoSanitizado(object? estado)
    {
        if (estado is null || LoggerProtegido.Verificando)
        {
            return null;
        }

        string texto = estado.ToString() ?? string.Empty;
        if (estado is IEnumerable<KeyValuePair<string, object?>> pares)
        {
            // Escopos estruturados são verificados também pelos valores, não só pelo ToString().
            texto += " " + string.Join(" ", pares.Select(par => $"{par.Key}={par.Value}"));
        }

        LoggerProtegido.Verificando = true;
        try
        {
            ResultadoProtecaoSink resultado = Guarda.Proteger(TipoSink.Log, texto, $"log-escopo:{estado.GetType().Name}");
            return resultado.Interceptado ? resultado.Conteudo : null;
        }
        finally
        {
            LoggerProtegido.Verificando = false;
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

        internal static bool Verificando
        {
            get => t_verificando;
            set => t_verificando = value;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull =>
            provedor.EscopoSanitizado(state) is { } sanitizado ? interno.BeginScope(sanitizado) : interno.BeginScope(state);

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

/// <summary>Provedor externo de escopos que entrega aos provedores de log só escopos verificados.</summary>
internal sealed class EscoposProtegidos(IExternalScopeProvider interno, ProvedorLogProtegido provedor) : IExternalScopeProvider
{
    public void ForEachScope<TState>(Action<object?, TState> callback, TState state) =>
        interno.ForEachScope((escopo, estado) => callback(provedor.EscopoSanitizado(escopo) ?? escopo, estado), state);

    public IDisposable Push(object? state) => interno.Push(state);
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
