using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;

using PontoVoz.Api.Cybersecurity.Api;
using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.IA;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Sinks;
using PontoVoz.Api.Cybersecurity.Taint;
using PontoVoz.Api.Infrastructure.Persistence;

namespace PontoVoz.Api.Cybersecurity;

public static class CybersecurityExtensions
{
    /// <summary>Documento OpenAPI próprio do módulo (<c>/openapi/seguranca.json</c>), separado do contrato v1.</summary>
    public const string DocumentoOpenApi = "seguranca";

    /// <summary>
    /// Registra o módulo: motor PII, Taint Analysis (contexto, guarda das saídas, sinks de log e
    /// de persistência), auditoria, tradução por IA e as rotas do painel. Deve ser chamado depois
    /// dos demais registros, para que todos os provedores de log já existentes sejam protegidos.
    /// </summary>
    public static IServiceCollection AddCybersecurityPontoVoz(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<OpcoesCybersecurity>().Bind(configuration.GetSection(OpcoesCybersecurity.Secao));
        services.AddHttpContextAccessor();

        services.AddSingleton<MotorPii>();
        services.AddSingleton<FilaExplicacoes>();
        services.AddSingleton<RegistroEventosSeguranca>();
        services.AddSingleton<GuardaSinks>();
        services.AddSingleton<CacheExplicacoes>();
        services.AddSingleton<SinkPersistenciaInterceptor>();
        services.ConfigureDbContext<PontoVozDbContext>((provider, options) => options.AddInterceptors(provider.GetRequiredService<SinkPersistenciaInterceptor>()));

        services.AddHttpClient<ClienteGemini>((provider, http) =>
            http.BaseAddress = new Uri(UrlBase(provider, ClienteGemini.UrlPadrao)));
        services.AddHttpClient<ClienteOpenAi>((provider, http) =>
            http.BaseAddress = new Uri(UrlBase(provider, ClienteOpenAi.UrlPadrao)));
        services.AddTransient<IClienteLlm>(provider =>
            provider.GetRequiredService<IOptions<OpcoesCybersecurity>>().Value.Llm.Provedor.Trim().ToUpperInvariant() switch
            {
                "GEMINI" => provider.GetRequiredService<ClienteGemini>(),
                "OPENAI" => provider.GetRequiredService<ClienteOpenAi>(),
                _ => new ClienteLlmDesabilitado(),
            });
        services.AddTransient<TradutorRiscoCidadao>();
        services.AddHostedService<ServicoExplicacoes>();

        services.AddScoped<DemonstracaoLocalFilter>();
        services.AddOpenApi(DocumentoOpenApi, opcoes => opcoes.AddDocumentTransformer((documento, _, _) =>
        {
            documento.Info.Title = "PontoVoz API — Cybersecurity";
            documento.Info.Version = "seguranca";
            documento.Info.Description = "Painel Risco Cidadão, análise PII, auditoria do Taint Analysis e explicação de eventos por IA. "
                + "Rotas protegidas pela chave X-PontoVoz-Admin-Key; as de demonstração só existem em Development.";
            return Task.CompletedTask;
        }));

        services.ProtegerSinksDeLog();
        return services;
    }

    /// <summary>Coloca o interceptador de dados pessoais no início do pipeline, antes do tratamento de erros.</summary>
    public static IApplicationBuilder UseInterceptadorDadosPessoais(this IApplicationBuilder app) =>
        app.UseMiddleware<InterceptadorDadosPessoais>();

    private static string UrlBase(IServiceProvider provider, string padrao)
    {
        string? configurada = provider.GetRequiredService<IOptions<OpcoesCybersecurity>>().Value.Llm.UrlBase;
        return string.IsNullOrWhiteSpace(configurada) ? padrao : configurada;
    }
}
