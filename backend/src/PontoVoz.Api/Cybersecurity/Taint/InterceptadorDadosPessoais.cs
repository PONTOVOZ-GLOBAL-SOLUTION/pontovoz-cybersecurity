using System.Text;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Pii;

namespace PontoVoz.Api.Cybersecurity.Taint;

/// <summary>
/// Middleware interceptador do módulo. É o primeiro do pipeline, antes do tratamento de erros, e
/// cumpre os dois extremos do Taint Analysis:
/// <list type="number">
/// <item><b>Source:</b> lê a query string e o corpo (JSON, formulário ou texto) das rotas
/// <c>/api</c>, aciona o motor PII e cria o <see cref="ContextoTaint"/> da requisição, com as
/// marcas e o estado de risco. O corpo continua disponível, sem alteração, para os controllers.</item>
/// <item><b>Sink de resposta:</b> numa requisição contaminada, a resposta (inclusive a de erro) fica
/// em memória até o fim e passa pela política antes de ser enviada ao cliente.</item>
/// </list>
/// Corpos acima do limite e JSON com estrutura excessiva são recusados sem chegar aos controllers.
/// </summary>
public sealed class InterceptadorDadosPessoais(
    RequestDelegate proximo,
    MotorPii motor,
    GuardaSinks guarda,
    RegistroEventosSeguranca registro,
    IOptions<OpcoesCybersecurity> opcoes,
    ILogger<InterceptadorDadosPessoais> logger)
{
    public const string FonteCorpoJson = "corpo JSON";
    public const string FonteQuery = "query string";
    public const string FonteFormulario = "formulário";
    public const string FonteTexto = "corpo em texto";
    public const string RotaModulo = "/api/v1/seguranca";

    private readonly OpcoesCybersecurity _opcoes = opcoes.Value;

    public async Task InvokeAsync(HttpContext contexto)
    {
        if (!contexto.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
        {
            await proximo(contexto);
            return;
        }

        var taint = new ContextoTaint(contexto.TraceIdentifier, $"{contexto.Request.Method} {contexto.Request.Path}");
        contexto.Features.Set(taint);

        EntradaAnalisada entrada = await AnalisarEntradaAsync(contexto, taint);
        if (entrada.Recusa is { } recusa)
        {
            await RecusarAsync(contexto, taint, recusa);
            return;
        }

        RegistrarAnalise(contexto, taint, entrada);

        if (taint.Estado == EstadoTaint.Limpo)
        {
            await proximo(contexto);
            return;
        }

        await ExecutarComRespostaProtegidaAsync(contexto, taint);
    }

    private async Task<EntradaAnalisada> AnalisarEntradaAsync(HttpContext contexto, ContextoTaint taint)
    {
        int deteccoes = 0;
        bool analisada = false;
        var fontes = new List<string>();

        if (contexto.Request.Query.Count > 0)
        {
            ResultadoAnalisePii query = motor.AnalisarCampos(contexto.Request.Query.Select(par => KeyValuePair.Create(par.Key, (string?)par.Value.ToString())));
            taint.Contaminar(query, FonteQuery);
            deteccoes += query.Deteccoes.Count;
            analisada = true;
            fontes.Add(FonteQuery);
        }

        if (!TemCorpo(contexto.Request))
        {
            return new EntradaAnalisada(analisada, deteccoes, fontes, null, null);
        }

        if (contexto.Request.ContentLength > _opcoes.LimiteCorpoBytes)
        {
            return EntradaAnalisada.Recusada(new Recusa(StatusCodes.Status413PayloadTooLarge, "CorpoExcedeLimiteSeguranca", "Corpo da requisição acima do limite",
                $"O corpo da requisição excede o limite de {_opcoes.LimiteCorpoBytes} bytes aceito pela verificação de dados pessoais."));
        }

        contexto.Request.EnableBuffering(_opcoes.LimiteCorpoBytes);
        string? corpo = await LerCorpoAsync(contexto.Request, _opcoes.LimiteCorpoBytes, contexto.RequestAborted);
        contexto.Request.Body.Position = 0;
        if (corpo is null)
        {
            return EntradaAnalisada.Recusada(new Recusa(StatusCodes.Status413PayloadTooLarge, "CorpoExcedeLimiteSeguranca", "Corpo da requisição acima do limite",
                $"O corpo da requisição excede o limite de {_opcoes.LimiteCorpoBytes} bytes aceito pela verificação de dados pessoais."));
        }

        (ResultadoAnalisePii analise, string fonte) = TipoCorpo(contexto.Request) switch
        {
            TipoConteudo.Json => (motor.AnalisarJson(corpo), FonteCorpoJson),
            TipoConteudo.Formulario => (motor.AnalisarCampos(QueryHelpers.ParseQuery(corpo).Select(par => KeyValuePair.Create(par.Key, (string?)par.Value.ToString()))), FonteFormulario),
            _ => (motor.AnalisarTexto(corpo), FonteTexto),
        };

        if (analise.Situacao == SituacaoAnalise.EstruturaExcessiva)
        {
            taint.Contaminar(analise, fonte);
            return EntradaAnalisada.Recusada(new Recusa(StatusCodes.Status400BadRequest, "EstruturaJsonExcessiva", "Estrutura JSON excessiva",
                $"O corpo JSON ultrapassa {_opcoes.ProfundidadeMaximaJson} níveis de aninhamento ou {_opcoes.LimiteNosJson} elementos."));
        }

        taint.Contaminar(analise, fonte);
        taint.AnaliseCorpo = analise;
        fontes.Add(analise.Situacao == SituacaoAnalise.JsonMalformado ? $"{fonte} (malformado)" : fonte);
        return new EntradaAnalisada(analisada || analise.Situacao != SituacaoAnalise.CorpoVazio, deteccoes + analise.Deteccoes.Count, fontes, analise, null);
    }

    private void RegistrarAnalise(HttpContext contexto, ContextoTaint taint, EntradaAnalisada entrada)
    {
        if (!entrada.Analisada)
        {
            return;
        }

        // As leituras do próprio painel (atualização periódica) não contam como eventos analisados,
        // a menos que tragam dado pessoal.
        bool leituraDoPainel = HttpMethods.IsGet(contexto.Request.Method) && contexto.Request.Path.StartsWithSegments(RotaModulo, StringComparison.OrdinalIgnoreCase);
        if (leituraDoPainel && taint.Estado == EstadoTaint.Limpo)
        {
            return;
        }

        string fontes = string.Join(" + ", entrada.Fontes);
        if (taint.Estado == EstadoTaint.Limpo)
        {
            registro.Registrar(new NovoEventoSeguranca(CodigosEvento.AnaliseSemDeteccao, taint.CorrelacaoId, taint.Fonte, [], [], null, null,
                DecisaoPolitica.Permitir, "Requisição seguiu normalmente.", $"{CodigosEvento.AnaliseSemDeteccao}: {fontes} analisado(s), nenhuma informação pessoal encontrada.", 0));
            return;
        }

        IReadOnlyList<MarcaTaint> marcas = taint.Marcas;
        List<CategoriaPii> categorias = [.. marcas.Select(m => m.Categoria).Distinct().Order()];
        registro.Registrar(new NovoEventoSeguranca(
            CodigosEvento.PiiDetectado,
            taint.CorrelacaoId,
            taint.Fonte,
            categorias,
            [.. marcas.Select(m => m.Caminho).Distinct(StringComparer.Ordinal)],
            null,
            null,
            DecisaoPolitica.Mascarar,
            "Valores classificados e marcados; todas as saídas desta requisição passam pela política de proteção.",
            $"{CodigosEvento.PiiDetectado}: {marcas.Count} marca(s) em {fontes} — " + string.Join("; ", marcas.Select(m => $"{m.Id} {m.Categoria}/{m.Sensibilidade} em {m.Caminho} ({m.Regra})")),
            marcas.Count));

        // A versão sanitizada do corpo é a única forma do conteúdo que chega ao log.
        logger.LogInformation("Entrada {Fonte} classificada: {Quantidade} ocorrência(s) de PII ({Categorias}). Corpo protegido: {Corpo}",
            taint.Fonte, marcas.Count, string.Join(", ", categorias), entrada.Analise?.TextoSanitizado ?? "(somente query string)");
    }

    private async Task ExecutarComRespostaProtegidaAsync(HttpContext contexto, ContextoTaint taint)
    {
        Stream original = contexto.Response.Body;
        await using var buffer = new MemoryStream();
        contexto.Response.Body = buffer;

        try
        {
            await proximo(contexto);
        }
        finally
        {
            contexto.Response.Body = original;
        }

        buffer.Position = 0;
        if (!Textual(contexto.Response.ContentType) || buffer.Length == 0)
        {
            await buffer.CopyToAsync(original, contexto.RequestAborted);
            return;
        }

        string texto = Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        ResultadoProtecaoSink resultado = guarda.Proteger(TipoSink.RespostaHttp, texto, $"resposta:{contexto.Response.StatusCode} {taint.Fonte}");
        byte[] saida = resultado.Interceptado ? Encoding.UTF8.GetBytes(resultado.Conteudo) : buffer.ToArray();
        if (resultado.Interceptado)
        {
            contexto.Response.Headers["X-PontoVoz-Protecao"] = $"resposta-sanitizada; evento={resultado.EventoId}";
        }

        contexto.Response.ContentLength = saida.Length;
        await original.WriteAsync(saida, contexto.RequestAborted);
    }

    private async Task RecusarAsync(HttpContext contexto, ContextoTaint taint, Recusa recusa)
    {
        List<CategoriaPii> categorias = [.. taint.Marcas.Select(m => m.Categoria).Distinct().Order()];
        EventoSeguranca evento = registro.Registrar(new NovoEventoSeguranca(CodigosEvento.EntradaRejeitada, taint.CorrelacaoId, taint.Fonte, categorias, [],
            null, null, DecisaoPolitica.Bloquear, "Requisição recusada antes de chegar aos controllers.", $"{CodigosEvento.EntradaRejeitada}: {recusa.Codigo} (HTTP {recusa.Status}).", taint.Marcas.Count));

        var problema = new ProblemDetails
        {
            Status = recusa.Status,
            Title = recusa.Titulo,
            Detail = recusa.Detalhe,
            Instance = contexto.Request.Path,
        };
        problema.Extensions["codigo"] = recusa.Codigo;
        problema.Extensions["eventoSeguranca"] = evento.Id;

        contexto.Response.StatusCode = recusa.Status;
        await contexto.RequestServices.GetRequiredService<IProblemDetailsService>().WriteAsync(new ProblemDetailsContext { HttpContext = contexto, ProblemDetails = problema });
    }

    private static bool TemCorpo(HttpRequest requisicao) =>
        requisicao.ContentLength > 0 || (requisicao.ContentLength is null && requisicao.Headers.TransferEncoding.Count > 0);

    private static async Task<string?> LerCorpoAsync(HttpRequest requisicao, int limite, CancellationToken cancellationToken)
    {
        var bytes = new byte[limite + 1];
        int lidos = 0;
        while (lidos < bytes.Length)
        {
            int n = await requisicao.Body.ReadAsync(bytes.AsMemory(lidos), cancellationToken);
            if (n == 0)
            {
                break;
            }

            lidos += n;
        }

        return lidos > limite ? null : Encoding.UTF8.GetString(bytes, 0, lidos);
    }

    private static TipoConteudo TipoCorpo(HttpRequest requisicao)
    {
        string tipo = requisicao.ContentType ?? string.Empty;
        if (tipo.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            return TipoConteudo.Json;
        }

        return tipo.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) ? TipoConteudo.Formulario : TipoConteudo.Texto;
    }

    private static bool Textual(string? tipo) =>
        tipo is not null && (tipo.Contains("json", StringComparison.OrdinalIgnoreCase) || tipo.StartsWith("text/", StringComparison.OrdinalIgnoreCase));

    private enum TipoConteudo
    {
        Json,
        Formulario,
        Texto,
    }

    private sealed record Recusa(int Status, string Codigo, string Titulo, string Detalhe);

    private sealed record EntradaAnalisada(bool Analisada, int Deteccoes, IReadOnlyList<string> Fontes, ResultadoAnalisePii? Analise, Recusa? Recusa)
    {
        public static EntradaAnalisada Recusada(Recusa recusa) => new(true, 0, [], null, recusa);
    }
}
