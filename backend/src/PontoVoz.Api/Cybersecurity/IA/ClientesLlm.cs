using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Microsoft.Extensions.Options;

namespace PontoVoz.Api.Cybersecurity.IA;

/// <summary>Motivos de falha do provedor, registrados como motivo do fallback.</summary>
public enum MotivoFalhaLlm
{
    ChaveNaoConfigurada,
    ProvedorDesabilitado,
    TempoEsgotado,
    FalhaConexao,
    ServicoIndisponivel,
    ErroHttp,
    RespostaInvalida,
}

public sealed class FalhaLlmException(MotivoFalhaLlm motivo, string detalhe) : Exception(detalhe)
{
    public MotivoFalhaLlm Motivo { get; } = motivo;
}

/// <summary>Cliente de um provedor de LLM. Recebe somente o prompt já sanitizado.</summary>
public interface IClienteLlm
{
    string Provedor { get; }

    string Modelo { get; }

    bool Configurado { get; }

    /// <summary>Texto gerado. Lança <see cref="FalhaLlmException"/> em qualquer falha do provedor.</summary>
    Task<string> GerarAsync(PromptRisco prompt, CancellationToken cancellationToken);
}

/// <summary>Leitura da chave: <c>Cybersecurity:Llm:ChaveApi</c> ou a variável de ambiente configurada.</summary>
internal static class ChaveLlm
{
    public static string? Ler(OpcoesLlm opcoes, IConfiguration configuracao, string variavelPadrao)
    {
        string? chave = opcoes.ChaveApi;
        if (string.IsNullOrWhiteSpace(chave))
        {
            string variavel = string.IsNullOrWhiteSpace(opcoes.VariavelAmbienteChave) ? variavelPadrao : opcoes.VariavelAmbienteChave;
            chave = configuracao[variavel];
        }

        return string.IsNullOrWhiteSpace(chave) ? null : chave.Trim();
    }
}

/// <summary>Base comum: tempo limite, tradução de erros HTTP e leitura do JSON de resposta.</summary>
public abstract class ClienteLlmHttp(HttpClient http, OpcoesLlm opcoes) : IClienteLlm
{
    public abstract string Provedor { get; }

    public string Modelo => opcoes.Modelo;

    public bool Configurado => Chave is not null;

    protected abstract string? Chave { get; }

    protected OpcoesLlm Opcoes => opcoes;

    public async Task<string> GerarAsync(PromptRisco prompt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        string chave = Chave ?? throw new FalhaLlmException(MotivoFalhaLlm.ChaveNaoConfigurada, "Nenhuma chave configurada para o provedor.");

        using var tempoLimite = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        tempoLimite.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, opcoes.TempoLimiteSegundos)));

        using HttpRequestMessage requisicao = CriarRequisicao(prompt, chave);
        HttpResponseMessage resposta;
        try
        {
            resposta = await http.SendAsync(requisicao, tempoLimite.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new FalhaLlmException(MotivoFalhaLlm.TempoEsgotado, $"O provedor não respondeu em {opcoes.TempoLimiteSegundos} s.");
        }
        catch (HttpRequestException excecao)
        {
            throw new FalhaLlmException(MotivoFalhaLlm.FalhaConexao, $"Falha de conexão com o provedor ({excecao.HttpRequestError}).");
        }

        using (resposta)
        {
            if (resposta.StatusCode is HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError)
            {
                throw new FalhaLlmException(MotivoFalhaLlm.ServicoIndisponivel, $"Provedor indisponível (HTTP {(int)resposta.StatusCode}).");
            }

            if (!resposta.IsSuccessStatusCode)
            {
                throw new FalhaLlmException(MotivoFalhaLlm.ErroHttp, $"Provedor recusou a requisição (HTTP {(int)resposta.StatusCode}).");
            }

            try
            {
                string corpo = await resposta.Content.ReadAsStringAsync(tempoLimite.Token);
                return ExtrairTexto(JsonNode.Parse(corpo)) is { Length: > 0 } texto
                    ? texto
                    : throw new FalhaLlmException(MotivoFalhaLlm.RespostaInvalida, "A resposta do provedor não contém texto.");
            }
            catch (JsonException)
            {
                throw new FalhaLlmException(MotivoFalhaLlm.RespostaInvalida, "A resposta do provedor não é um JSON válido.");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new FalhaLlmException(MotivoFalhaLlm.TempoEsgotado, "O provedor não concluiu a resposta no tempo limite.");
            }
        }
    }

    protected abstract HttpRequestMessage CriarRequisicao(PromptRisco prompt, string chave);

    protected abstract string? ExtrairTexto(JsonNode? resposta);

    protected static StringContent Json(JsonNode corpo) => new(corpo.ToJsonString(), Encoding.UTF8, "application/json");
}

/// <summary>Google Gemini, rota <c>models/{modelo}:generateContent</c>.</summary>
public sealed class ClienteGemini(HttpClient http, IOptions<OpcoesCybersecurity> opcoes, IConfiguration configuracao)
    : ClienteLlmHttp(http, opcoes.Value.Llm)
{
    public const string UrlPadrao = "https://generativelanguage.googleapis.com/";

    public override string Provedor => "Gemini";

    protected override string? Chave => ChaveLlm.Ler(Opcoes, configuracao, "GEMINI_API_KEY");

    protected override HttpRequestMessage CriarRequisicao(PromptRisco prompt, string chave)
    {
        var corpo = new JsonObject
        {
            ["systemInstruction"] = new JsonObject { ["parts"] = new JsonArray(new JsonObject { ["text"] = prompt.Instrucoes }) },
            ["contents"] = new JsonArray(new JsonObject
            {
                ["role"] = "user",
                ["parts"] = new JsonArray(new JsonObject { ["text"] = prompt.Mensagem }),
            }),
            ["generationConfig"] = new JsonObject { ["temperature"] = 0.2, ["maxOutputTokens"] = 1024 },
        };

        var requisicao = new HttpRequestMessage(HttpMethod.Post, new Uri($"v1beta/models/{Uri.EscapeDataString(Modelo)}:generateContent", UriKind.Relative))
        {
            Content = Json(corpo),
        };
        requisicao.Headers.Add("x-goog-api-key", chave);
        return requisicao;
    }

    protected override string? ExtrairTexto(JsonNode? resposta)
    {
        JsonArray? partes = resposta?["candidates"] is JsonArray { Count: > 0 } candidatos ? candidatos[0]?["content"]?["parts"] as JsonArray : null;
        return partes is null
            ? null
            : string.Concat(partes.Select(parte => parte?["text"]?.GetValueKind() == JsonValueKind.String ? parte["text"]!.GetValue<string>() : string.Empty)).Trim();
    }
}

/// <summary>OpenAI, rota <c>v1/chat/completions</c>.</summary>
public sealed class ClienteOpenAi(HttpClient http, IOptions<OpcoesCybersecurity> opcoes, IConfiguration configuracao)
    : ClienteLlmHttp(http, opcoes.Value.Llm)
{
    public const string UrlPadrao = "https://api.openai.com/";

    public override string Provedor => "OpenAI";

    protected override string? Chave => ChaveLlm.Ler(Opcoes, configuracao, "OPENAI_API_KEY");

    protected override HttpRequestMessage CriarRequisicao(PromptRisco prompt, string chave)
    {
        var corpo = new JsonObject
        {
            ["model"] = Modelo,
            ["messages"] = new JsonArray(
                new JsonObject { ["role"] = "system", ["content"] = prompt.Instrucoes },
                new JsonObject { ["role"] = "user", ["content"] = prompt.Mensagem }),
            ["temperature"] = 0.2,
            ["max_completion_tokens"] = 200,
        };

        var requisicao = new HttpRequestMessage(HttpMethod.Post, new Uri("v1/chat/completions", UriKind.Relative)) { Content = Json(corpo) };
        requisicao.Headers.Authorization = new AuthenticationHeaderValue("Bearer", chave);
        return requisicao;
    }

    protected override string? ExtrairTexto(JsonNode? resposta)
    {
        JsonNode? conteudo = resposta?["choices"] is JsonArray { Count: > 0 } escolhas ? escolhas[0]?["message"]?["content"] : null;
        return conteudo?.GetValueKind() == JsonValueKind.String ? conteudo.GetValue<string>().Trim() : null;
    }
}

/// <summary>Provedor <c>Nenhum</c>: o módulo funciona só com as mensagens locais.</summary>
public sealed class ClienteLlmDesabilitado : IClienteLlm
{
    public string Provedor => "Nenhum";

    public string Modelo => "-";

    public bool Configurado => false;

    public Task<string> GerarAsync(PromptRisco prompt, CancellationToken cancellationToken) =>
        throw new FalhaLlmException(MotivoFalhaLlm.ProvedorDesabilitado, "Nenhum provedor de LLM configurado.");
}
