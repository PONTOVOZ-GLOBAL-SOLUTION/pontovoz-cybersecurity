using System.Text;
using System.Text.Json.Nodes;

using Microsoft.Extensions.Options;

using PontoVoz.Api.Cybersecurity;
using PontoVoz.Api.Cybersecurity.Pii;

namespace PontoVoz.Tests.Cybersecurity;

/// <summary>Motor de parsing PII: detecção, classificação e cópia sanitizada.</summary>
public sealed class MotorPiiTests
{
    private readonly MotorPii _motor = new(Options.Create(new OpcoesCybersecurity()));

    private ResultadoAnalisePii Analisar(string json) => _motor.AnalisarJson(json);

    private static DeteccaoPii Unica(ResultadoAnalisePii resultado) => Assert.Single(resultado.Deteccoes);

    // Sem escapar acentos, para comparar com os marcadores como são exibidos.
    private static readonly System.Text.Json.JsonSerializerOptions SemEscape = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private static string Sanitizado(ResultadoAnalisePii resultado) => resultado.Sanitizado!.ToJsonString(SemEscape);

    [Fact]
    public void JsonSemDadosPessoais_NaoTemDeteccoes_ESaiIgual()
    {
        const string json = """{"codigoExterno":"SIM-P003","nome":"Parada Vila Inglesa","endereco":"Rua Augusta, 1500","coordenada":{"latitude":-23.56,"longitude":-46.65},"dadosSimulados":true}""";

        ResultadoAnalisePii resultado = Analisar(json);

        Assert.Equal(SituacaoAnalise.Analisado, resultado.Situacao);
        Assert.False(resultado.PossuiPii);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), resultado.Sanitizado));
    }

    [Fact]
    public void CpfValidoEmCampoCpf_EhClassificadoEMascarado()
    {
        ResultadoAnalisePii resultado = Analisar($$"""{"cpf":"{{DadosFicticios.CpfSequencia}}"}""");

        DeteccaoPii deteccao = Unica(resultado);
        Assert.Equal(CategoriaPii.Cpf, deteccao.Categoria);
        Assert.Equal(Sensibilidade.DadoPessoal, deteccao.Sensibilidade);
        Assert.Equal("$.cpf", deteccao.Caminho);
        Assert.Equal("campo-cpf+dv-valido", deteccao.Regra);
        Assert.Equal(Confianca.Alta, deteccao.Confianca);
        Assert.Equal(AcaoProtecao.Mascarar, deteccao.Acao);
        Assert.Equal("***.456.***-09", resultado.Sanitizado!["cpf"]!.GetValue<string>());
    }

    [Fact]
    public void ExemploDoProfessor_DocumentoComFormatoDeCpf_EhTagueadoComoCpfEMascarado()
    {
        ResultadoAnalisePii resultado = Analisar("""{"documento":"123.456.789-00"}""");

        DeteccaoPii deteccao = Unica(resultado);
        Assert.Equal(CategoriaPii.Cpf, deteccao.Categoria);
        Assert.Equal("campo-documento+formato-cpf", deteccao.Regra);
        Assert.Equal("***.456.***-00", resultado.Sanitizado!["documento"]!.GetValue<string>());
    }

    [Fact]
    public void CpfValidoEmCampoGenerico_EhReconhecidoPeloConteudo()
    {
        ResultadoAnalisePii resultado = Analisar($$"""{"observacao":"Passageiro informou o CPF {{DadosFicticios.Cpf}} no ponto"}""");

        DeteccaoPii deteccao = Unica(resultado);
        Assert.Equal(CategoriaPii.Cpf, deteccao.Categoria);
        Assert.Equal("$.observacao", deteccao.Caminho);
        Assert.Equal("texto-cpf-formatado+dv", deteccao.Regra);
        Assert.Equal("Passageiro informou o CPF ***.444.***-35 no ponto", resultado.Sanitizado!["observacao"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("""{"origemRegistro":"11144477735"}""", "texto-11-digitos+dv")]
    [InlineData("""{"identificacao":11144477735}""", "texto-11-digitos+dv")]
    [InlineData("""{"cpf":"11144477735"}""", "campo-cpf+dv-valido")]
    [InlineData("""{"cpf":"111 444 777 35"}""", "campo-cpf+dv-valido")]
    public void CpfComFormatacaoDiferente_EhReconhecido(string json, string regra)
    {
        DeteccaoPii deteccao = Unica(Analisar(json));

        Assert.Equal(CategoriaPii.Cpf, deteccao.Categoria);
        Assert.Equal(regra, deteccao.Regra);
    }

    [Fact]
    public void CpfInvalidoEmCampoGenerico_NaoEhClassificado()
    {
        Assert.False(Analisar($$"""{"observacao":"protocolo {{DadosFicticios.CpfInvalido}}"}""").PossuiPii);
        Assert.False(Analisar("""{"observacao":"111.111.111-11"}""").PossuiPii);
    }

    [Fact]
    public void CpfInvalidoEmCampoCpf_AindaEhProtegido_ComRegraDeDvInvalido()
    {
        ResultadoAnalisePii resultado = Analisar($$"""{"cpf":"{{DadosFicticios.CpfInvalido}}"}""");

        Assert.Equal("campo-cpf+dv-invalido", Unica(resultado).Regra);
        Assert.Equal("***.456.***-00", resultado.Sanitizado!["cpf"]!.GetValue<string>());
    }

    [Fact]
    public void CpfComRotuloEDvInvalido_EhReconhecidoComConfiancaMedia()
    {
        DeteccaoPii deteccao = Unica(Analisar("""{"mensagem":"CPF: 123.456.789-00"}"""));

        Assert.Equal(CategoriaPii.Cpf, deteccao.Categoria);
        Assert.Equal(Confianca.Media, deteccao.Confianca);
    }

    [Theory]
    [InlineData("""{"rg":"12.345.678-X"}""", "campo-rg")]
    [InlineData("""{"numeroRg":"123456789"}""", "campo-rg")]
    [InlineData("""{"carteiraIdentidade":"MG-12.345.678"}""", "campo-rg")]
    [InlineData("""{"observacao":"RG 12.345.678-9 apresentado"}""", "texto-rotulo-rg")]
    [InlineData("""{"observacao":"documento 12.345.678-9"}""", "texto-formato-rg")]
    public void Rg_EhReconhecidoPeloCampoOuPeloTexto(string json, string regra)
    {
        DeteccaoPii deteccao = Unica(Analisar(json));

        Assert.Equal(CategoriaPii.Rg, deteccao.Categoria);
        Assert.Equal(regra, deteccao.Regra);
    }

    [Fact]
    public void Rg_EhMascaradoMantendoSoOsUltimosCaracteres()
    {
        Assert.Equal("**.***.**8-X", Analisar($$"""{"rg":"{{DadosFicticios.Rg}}"}""").Sanitizado!["rg"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("senha")]
    [InlineData("password")]
    [InlineData("confirmacaoSenha")]
    [InlineData("pin")]
    [InlineData("api_key")]
    public void Senha_EhSegredoDeAutenticacao_ESuprimidaPorInteiro(string campo)
    {
        ResultadoAnalisePii resultado = Analisar($$"""{"{{campo}}":"{{DadosFicticios.Senha}}"}""");

        DeteccaoPii deteccao = Unica(resultado);
        Assert.Equal(CategoriaPii.Senha, deteccao.Categoria);
        Assert.Equal(Sensibilidade.SegredoAutenticacao, deteccao.Sensibilidade);
        Assert.Equal(AcaoProtecao.Suprimir, deteccao.Acao);
        Assert.Equal(MascaradorPii.MarcadorSenha, resultado.Sanitizado![campo]!.GetValue<string>());
    }

    [Fact]
    public void SenhaEmTextoLivre_EhReconhecidaPeloRotulo()
    {
        ResultadoAnalisePii resultado = Analisar("""{"observacao":"acesso do operador senha: Teste#9876"}""");

        Assert.Equal(CategoriaPii.Senha, Unica(resultado).Categoria);
        Assert.DoesNotContain("Teste#9876", Sanitizado(resultado), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"laudo":"Laudo fictício de baixa visão"}""", "$.laudo")]
    [InlineData("""{"diagnosticoMedico":"fictício"}""", "$.diagnosticoMedico")]
    [InlineData("""{"possuiDeficiencia":true}""", "$.possuiDeficiencia")]
    [InlineData("""{"observacao":"CID-10 H54 informado"}""", "$.observacao")]
    [InlineData("""{"observacao":"Passageiro diagnosticado com epilepsia"}""", "$.observacao")]
    public void DadosDeSaude_SaoSensiveis_ESuprimidos(string json, string caminho)
    {
        ResultadoAnalisePii resultado = Analisar(json);

        DeteccaoPii deteccao = Unica(resultado);
        Assert.Equal(CategoriaPii.Saude, deteccao.Categoria);
        Assert.Equal(Sensibilidade.DadoPessoalSensivel, deteccao.Sensibilidade);
        Assert.Equal(caminho, deteccao.Caminho);
        Assert.Contains(MascaradorPii.MarcadorSaude, Sanitizado(resultado), StringComparison.Ordinal);
    }

    [Fact]
    public void EstruturaDeSaude_EhProtegidaPorInteiro()
    {
        ResultadoAnalisePii resultado = Analisar("""{"saude":{"condicao":"asma (fictício)","medicamentos":["remédio A","remédio B"],"internado":false}}""");

        DeteccaoPii deteccao = Unica(resultado);
        Assert.Equal("$.saude", deteccao.Caminho);
        Assert.Equal("campo-saude-estrutura", deteccao.Regra);
        string sanitizado = Sanitizado(resultado);
        Assert.DoesNotContain("asma", sanitizado, StringComparison.Ordinal);
        Assert.DoesNotContain("remédio", sanitizado, StringComparison.Ordinal);
        Assert.DoesNotContain("false", sanitizado, StringComparison.Ordinal);
    }

    [Fact]
    public void EmailETelefone_SaoReconhecidosEmCamposGenericos()
    {
        ResultadoAnalisePii resultado = Analisar($$"""{"contato":"Falar com {{DadosFicticios.Email}} ou {{DadosFicticios.Telefone}}"}""");

        Assert.Equal([CategoriaPii.Email, CategoriaPii.Telefone], resultado.Deteccoes.Select(d => d.Categoria));
        Assert.Equal("Falar com p***@e***.br ou (**) *****-5678", resultado.Sanitizado!["contato"]!.GetValue<string>());
    }

    [Fact]
    public void CelularSemPontuacao_EhTelefone_NaoCpf()
    {
        Assert.Equal(CategoriaPii.Telefone, Unica(Analisar("""{"observacao":"ligar 11987654321"}""")).Categoria);
    }

    [Fact]
    public void CamposAninhadosEListas_TemCaminhoJsonCompleto()
    {
        string json = $$$"""
            {"viagem":{"passageiros":[
              {"nome":"Passageiro A","documentos":[{"tipo":"cpf","cpf":"{{{DadosFicticios.Cpf}}}"}]},
              {"nome":"Passageiro B","contato":{"email":"{{{DadosFicticios.Email}}}"}}
            ]}}
            """;

        ResultadoAnalisePii resultado = Analisar(json);

        Assert.Contains(resultado.Deteccoes, d => d.Caminho == "$.viagem.passageiros[0].documentos" && d.Categoria == CategoriaPii.DocumentoIdentificador);
        Assert.Contains(resultado.Deteccoes, d => d.Caminho == "$.viagem.passageiros[1].contato.email" && d.Categoria == CategoriaPii.Email);
        DadosFicticios.AssertSemOriginais(Sanitizado(resultado));
        Assert.Equal("Passageiro A", resultado.Sanitizado!["viagem"]!["passageiros"]![0]!["nome"]!.GetValue<string>());
    }

    [Fact]
    public void ListaDeObjetosComCamposGenericos_EhVarridaPeloConteudo()
    {
        string json = $$"""{"contatos":[{"tipo":"e-mail","valor":"{{DadosFicticios.Email}}"},{"tipo":"celular","valor":"{{DadosFicticios.Telefone}}"}]}""";

        ResultadoAnalisePii resultado = Analisar(json);

        Assert.Equal(["$.contatos[0].valor", "$.contatos[1].valor"], resultado.Deteccoes.Select(d => d.Caminho));
    }

    [Fact]
    public void VariosDadosPessoaisNaMesmaRequisicao_SaoTodosDetectados()
    {
        ResultadoAnalisePii resultado = Analisar(DadosFicticios.CadastroCompleto);

        Assert.Equal(
            [CategoriaPii.Cpf, CategoriaPii.Rg, CategoriaPii.Senha, CategoriaPii.Saude, CategoriaPii.Email, CategoriaPii.Telefone],
            resultado.Deteccoes.Select(d => d.Categoria));
        DadosFicticios.AssertSemOriginais(Sanitizado(resultado));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void CorpoVazio_NaoEhAnalisado(string? json)
    {
        ResultadoAnalisePii resultado = Analisar(json!);

        Assert.Equal(SituacaoAnalise.CorpoVazio, resultado.Situacao);
        Assert.False(resultado.PossuiPii);
    }

    [Fact]
    public void JsonMalformado_EhVarridoComoTexto_ESemValorOriginalNoResultado()
    {
        string json = $$"""{"cpf": "{{DadosFicticios.Cpf}}", "senha": "{{DadosFicticios.Senha}}", "obs": """;

        ResultadoAnalisePii resultado = Analisar(json);

        Assert.Equal(SituacaoAnalise.JsonMalformado, resultado.Situacao);
        Assert.Equal([CategoriaPii.Cpf, CategoriaPii.Senha], resultado.Deteccoes.Select(d => d.Categoria));
        Assert.Null(resultado.Sanitizado);
        DadosFicticios.AssertSemOriginais(resultado.TextoSanitizado!);
    }

    [Fact]
    public void JsonProfundoDemais_EhEstruturaExcessiva()
    {
        string json = string.Concat(Enumerable.Repeat("{\"a\":", 40)) + "1" + new string('}', 40);

        Assert.Equal(SituacaoAnalise.EstruturaExcessiva, Analisar(json).Situacao);
    }

    [Fact]
    public void JsonComElementosDemais_EhEstruturaExcessiva()
    {
        var json = new StringBuilder("[");
        json.AppendJoin(',', Enumerable.Range(0, 6000));
        json.Append(']');

        Assert.Equal(SituacaoAnalise.EstruturaExcessiva, Analisar(json.ToString()).Situacao);
    }

    [Fact]
    public void ColchetesDentroDeTexto_NaoContamComoProfundidade()
    {
        string json = $$"""{"texto":"{{new string('[', 100)}}"}""";

        Assert.Equal(SituacaoAnalise.Analisado, Analisar(json).Situacao);
    }

    [Theory]
    [InlineData("""{"nome":"Parada Demonstração Centro"}""")]
    [InlineData("""{"letreiro":"8000-10 Terminal Lapa"}""")]
    [InlineData("""{"observadaEm":"2026-11-10T14:24:00-03:00"}""")]
    [InlineData("""{"codigoExterno":"SIM-P001","prefixoVeiculo":"SIM-12345"}""")]
    [InlineData("""{"origemRegistro":"operador-local"}""")]
    [InlineData("""{"cargo":"motorista","terminalPrincipal":"Terminal Bandeira"}""")]
    [InlineData("""{"mensagem":"Ônibus chega em 5 minutos na plataforma 2"}""")]
    [InlineData("""{"tratamentoDeDados":"anonimizado"}""")]
    [InlineData("""{"quantidade":12345678,"linhaId":4,"paradaId":1}""")]
    [InlineData("""{"observacao":"Senha de atendimento 42 chamada no guichê"}""")]
    public void TextosComunsDoPontoVoz_NaoSaoClassificados(string json)
    {
        Assert.False(Analisar(json).PossuiPii);
    }

    [Fact]
    public void NomeDeCampoComDadoPessoal_TambemEhProtegido()
    {
        ResultadoAnalisePii resultado = Analisar($$"""{"{{DadosFicticios.Cpf}}":"cadastro"}""");

        Assert.True(resultado.PossuiPii);
        DadosFicticios.AssertSemOriginais(Sanitizado(resultado));
    }

    [Fact]
    public void CamposDeQueryOuFormulario_SaoAnalisadosComoObjeto()
    {
        ResultadoAnalisePii resultado = _motor.AnalisarCampos([KeyValuePair.Create("texto", (string?)DadosFicticios.Cpf), KeyValuePair.Create("pagina", (string?)"1")]);

        Assert.Equal("$.texto", Unica(resultado).Caminho);
    }

    [Fact]
    public void Deteccoes_NaoCarregamOValorOriginal()
    {
        ResultadoAnalisePii resultado = Analisar(DadosFicticios.CadastroCompleto);

        string metadados = System.Text.Json.JsonSerializer.Serialize(resultado.Deteccoes);
        DadosFicticios.AssertSemOriginais(metadados);
    }
}

public sealed class ValidadorCpfTests
{
    [Theory]
    [InlineData("111.444.777-35", true)]
    [InlineData("11144477735", true)]
    [InlineData("123.456.789-09", true)]
    [InlineData("123.456.789-00", false)]
    [InlineData("111.111.111-11", false)]
    [InlineData("000.000.000-00", false)]
    [InlineData("1234567890", false)]
    [InlineData("123456789012", false)]
    [InlineData("abc.def.ghi-jk", false)]
    [InlineData(null, false)]
    public void Valido_ConfereDigitosVerificadores(string? cpf, bool esperado)
    {
        Assert.Equal(esperado, ValidadorCpf.Valido(cpf));
    }
}

public sealed class MascaradorPiiTests
{
    [Theory]
    [InlineData(CategoriaPii.Cpf, "123.456.789-00", "***.456.***-00")]
    [InlineData(CategoriaPii.Cpf, "11144477735", "***.444.***-35")]
    [InlineData(CategoriaPii.Rg, "12.345.678-X", "**.***.**8-X")]
    [InlineData(CategoriaPii.Telefone, "(11) 91234-5678", "(**) *****-5678")]
    [InlineData(CategoriaPii.Email, "passageiro.ficticio@exemplo.com.br", "p***@e***.br")]
    [InlineData(CategoriaPii.DocumentoIdentificador, "AB1234567", "*******67")]
    [InlineData(CategoriaPii.Senha, "Senha@Teste123", MascaradorPii.MarcadorSenha)]
    [InlineData(CategoriaPii.Saude, "asma", MascaradorPii.MarcadorSaude)]
    public void Mascarar_SegueORegraDaCategoria(CategoriaPii categoria, string valor, string esperado)
    {
        Assert.Equal(esperado, MascaradorPii.Mascarar(categoria, valor));
    }

    [Fact]
    public void MarcadorDeBloqueio_NaoTemNenhumTrechoDoValor()
    {
        Assert.Equal("[BLOQUEADO: CPF]", MascaradorPii.MarcadorBloqueio(CategoriaPii.Cpf));
    }
}
