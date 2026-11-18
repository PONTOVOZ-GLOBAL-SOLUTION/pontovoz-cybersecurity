using PontoVoz.Api.Cybersecurity.Auditoria;
using PontoVoz.Api.Cybersecurity.Pii;
using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Api.Cybersecurity.IA;

/// <summary>
/// Tudo o que é enviado ao LLM sobre um evento. É montado só a partir de valores enumerados
/// (código, categorias, tipo de saída, decisão): não há campo capaz de carregar o valor original,
/// o caminho do campo ou a mensagem técnica.
/// </summary>
public sealed record DadosPromptRisco(
    string CodigoEvento,
    IReadOnlyList<string> CategoriasGenericas,
    string DestinoDaTentativa,
    string AcaoExecutada,
    string Resultado,
    string NivelRisco,
    string Publico);

/// <summary>Instruções de sistema e mensagem do usuário enviadas ao provedor.</summary>
public sealed record PromptRisco(string Instrucoes, string Mensagem);

public static class ConstrutorPromptRisco
{
    public const string Publico = "cidadão leigo de 60 anos, usuário de ônibus em São Paulo";

    public const string Instrucoes =
        "Você redige avisos de privacidade do PontoVoz, um totem com informações de ônibus em pontos de parada de São Paulo. " +
        "Transforme o evento técnico recebido em uma mensagem para um cidadão sem conhecimento técnico. Regras obrigatórias: " +
        "escreva em português do Brasil; use no máximo duas frases curtas; diga o que foi observado e o que o sistema fez; " +
        "não use termos técnicos como middleware, sink, taint, log, HTTP, JSON, payload, API ou stack trace; " +
        "quando a ação foi bloqueio ou mascaramento, não diga que houve vazamento nem que dados foram expostos; " +
        "não invente consequências; não prometa proteção absoluta; mantenha um tom calmo, sem alarmismo. " +
        "Responda somente com a mensagem, sem aspas e sem formatação.";

    public static DadosPromptRisco Dados(EventoSeguranca evento)
    {
        ArgumentNullException.ThrowIfNull(evento);
        return new DadosPromptRisco(
            CodigoEvento: evento.Codigo,
            CategoriasGenericas: [.. evento.Categorias.Distinct().Order().Select(CatalogoPii.Rotulo)],
            DestinoDaTentativa: Destino(evento.TipoDestino),
            AcaoExecutada: Acao(evento),
            Resultado: evento.Codigo == CodigosEvento.SinkBloqueado
                ? "a informação original não chegou ao destino"
                : "a informação continua protegida no sistema",
            NivelRisco: evento.NivelRisco.ToString().ToLowerInvariant(),
            Publico: Publico);
    }

    public static PromptRisco Montar(DadosPromptRisco dados)
    {
        ArgumentNullException.ThrowIfNull(dados);
        string categorias = dados.CategoriasGenericas.Count == 0 ? "informação pessoal" : string.Join(", ", dados.CategoriasGenericas);
        string falha = dados.CodigoEvento == CodigosEvento.SinkBloqueado
            ? $"Tentativa de envio de {categorias} para {dados.DestinoDaTentativa} bloqueada pela política de proteção de dados"
            : $"Evento {dados.CodigoEvento} envolvendo {categorias}";

        string mensagem =
            $"Código do evento: {dados.CodigoEvento}\n" +
            $"Tipo de informação: {categorias}\n" +
            $"Destino da tentativa: {dados.DestinoDaTentativa}\n" +
            $"Ação executada: {dados.AcaoExecutada}\n" +
            $"Resultado: {dados.Resultado}\n" +
            $"Nível de risco no painel: {dados.NivelRisco}\n\n" +
            $"Traduza a falha técnica '{falha}' para um {dados.Publico}, em até 2 frases.";
        return new PromptRisco(Instrucoes, mensagem);
    }

    private static string Destino(TipoSink? sink) => sink switch
    {
        TipoSink.Log => "o registro interno de funcionamento do sistema",
        TipoSink.RespostaHttp => "a resposta exibida na tela",
        TipoSink.Persistencia => "o armazenamento permanente do sistema",
        TipoSink.ServicoExterno => "um serviço externo",
        _ => "nenhum destino (apenas recebimento)",
    };

    private static string Acao(EventoSeguranca evento) => evento.Codigo switch
    {
        CodigosEvento.SinkBloqueado when evento.Decisao == DecisaoPolitica.Bloquear =>
            "o envio foi bloqueado e a informação foi substituída por um aviso de proteção",
        CodigosEvento.SinkBloqueado => "a informação foi mascarada, deixando visível só uma pequena parte, antes de chegar ao destino",
        CodigosEvento.PiiDetectado => "a informação foi identificada e passou a ser protegida",
        CodigosEvento.EntradaRejeitada => "o envio foi recusado antes de ser processado",
        _ => "nenhuma ação foi necessária",
    };
}

/// <summary>Mensagens locais: usadas sem IA nos eventos sem risco e como fallback quando o LLM falha.</summary>
public static class MensagensLocais
{
    public static string Para(string codigo, IReadOnlyCollection<CategoriaPii> categorias)
    {
        ArgumentNullException.ThrowIfNull(categorias);
        return codigo switch
        {
            CodigosEvento.SinkBloqueado when categorias.Count == 1 && categorias.Contains(CategoriaPii.Senha) =>
                "Identificamos uma tentativa de mostrar uma senha em um local não autorizado do sistema. A operação foi bloqueada e a senha não foi exibida.",
            CodigosEvento.SinkBloqueado when categorias.Contains(CategoriaPii.Saude) =>
                "Identificamos uma tentativa de enviar uma informação de saúde para uma área não autorizada. O sistema bloqueou essa operação para proteger sua privacidade.",
            CodigosEvento.SinkBloqueado =>
                "Identificamos uma tentativa de envio de informação pessoal para uma área não autorizada. O sistema bloqueou essa operação para ajudar a proteger seus dados.",
            CodigosEvento.PiiDetectado =>
                "Recebemos uma informação pessoal junto com a sua solicitação. O sistema passou a protegê-la e mostra apenas parte dela quando necessário.",
            CodigosEvento.EntradaRejeitada =>
                "O sistema recusou um envio de dados que não pôde ser verificado com segurança. Nenhuma informação desse envio foi utilizada.",
            _ => "A consulta foi verificada e não continha informações pessoais. Nenhuma ação é necessária.",
        };
    }
}
