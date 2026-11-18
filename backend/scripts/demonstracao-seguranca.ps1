<#
.SYNOPSIS
    Executa pela linha de comando os quatro cenários do painel Risco Cidadão contra a API em execução.

.DESCRIPTION
    Alternativa ao painel web para reproduzir a demonstração: reinicia a trilha de auditoria,
    faz uma consulta segura, envia um JSON fictício com dados pessoais, executa a tentativa
    controlada de saída insegura (resposta, exceção e gravação no banco) e pede a explicação do
    evento de maior risco. Mostra o que cada rota devolveu e o estado final do indicador.
    Todos os dados enviados são fictícios.

    Uso, com a API rodando (dotnet run --project backend/src/PontoVoz.Api --launch-profile http):
        pwsh ./backend/scripts/demonstracao-seguranca.ps1
    (ou powershell -ExecutionPolicy Bypass -File .\backend\scripts\demonstracao-seguranca.ps1)
#>
[CmdletBinding()]
param(
    [string] $Url = 'http://localhost:5080',
    [string] $ChaveAdministrativa = $env:PONTOVOZ_ADMIN_KEY
)

$ErrorActionPreference = 'Stop'
$cabecalhos = @{ Accept = 'application/json' }
if ($ChaveAdministrativa) { $cabecalhos['X-PontoVoz-Admin-Key'] = $ChaveAdministrativa }

function Chamar([string] $Metodo, [string] $Caminho, [string] $Corpo) {
    $parametros = @{ Uri = "$Url$Caminho"; Method = $Metodo; Headers = $cabecalhos; UseBasicParsing = $true }
    if ($Corpo) { $parametros['Body'] = [Text.Encoding]::UTF8.GetBytes($Corpo); $parametros['ContentType'] = 'application/json; charset=utf-8' }
    try {
        $resposta = Invoke-WebRequest @parametros
        $status = [int] $resposta.StatusCode
        $conteudo = $resposta.Content
        $protecao = $resposta.Headers['X-PontoVoz-Protecao']
    }
    catch [System.Net.WebException] {
        $status = [int] $_.Exception.Response.StatusCode
        $conteudo = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() }
        $protecao = $null
    }
    catch {
        if (-not $_.Exception.Response) { throw }
        $status = [int] $_.Exception.Response.StatusCode
        $conteudo = $_.ErrorDetails.Message
        $protecao = $null
    }
    [pscustomobject]@{ Status = $status; Json = if ($conteudo) { $conteudo | ConvertFrom-Json } else { $null }; Protecao = $protecao }
}

function Titulo([string] $Texto) { Write-Host ''; Write-Host "=== $Texto ===" -ForegroundColor Yellow }

$cadastro = '{"cpf":"111.444.777-35","senha":"Senha@Teste123","saude":{"condicao":"diabetes tipo 2 (dado fictício)"},"email":"passageiro.ficticio@exemplo.com.br"}'

Titulo 'Reinício da demonstração'
$r = Chamar 'POST' '/api/v1/seguranca/demonstracao/reiniciar'
Write-Host "HTTP $($r.Status)"

Titulo 'Cenário 1 · consulta segura (GET /api/v1/paradas?codigoExterno=SIM-P001)'
$r = Chamar 'GET' '/api/v1/paradas?codigoExterno=SIM-P001'
Write-Host "HTTP $($r.Status) · parada: $($r.Json.itens[0].nome)"
Write-Host "Risco: $((Chamar 'GET' '/api/v1/seguranca/painel').Json.risco.nivel)"

Titulo 'Cenário 2 · JSON fictício com dados pessoais (POST /api/v1/seguranca/analises)'
$r = Chamar 'POST' '/api/v1/seguranca/analises' $cadastro
$r.Json.deteccoes | Format-Table categoria, caminho, sensibilidade, regra, acao -AutoSize | Out-String | Write-Host
Write-Host "Corpo sanitizado: $($r.Json.corpoSanitizado | ConvertTo-Json -Compress -Depth 5)"
Write-Host "Risco: $((Chamar 'GET' '/api/v1/seguranca/painel').Json.risco.nivel)"

Titulo 'Cenário 3 · tentativa controlada de saída insegura'
$r = Chamar 'POST' '/api/v1/seguranca/demonstracao/vazamento-controlado' $cadastro
Write-Host "HTTP $($r.Status) · X-PontoVoz-Protecao: $($r.Protecao)"
Write-Host "Serviço externo: $($r.Json.servicoExterno)"
Write-Host "Cadastro devolvido: $($r.Json.cadastroDevolvido | ConvertTo-Json -Compress -Depth 5)"
$r = Chamar 'POST' '/api/v1/seguranca/demonstracao/vazamento-controlado?modo=erro' $cadastro
Write-Host "Exceção com o cadastro na mensagem: HTTP $($r.Status) · $($r.Json.codigo) · $($r.Json.detail)"

$parada = (Chamar 'GET' '/api/v1/paradas?codigoExterno=SIM-P001').Json.itens[0].id
$linha = (Chamar 'GET' "/api/v1/paradas/$parada").Json.linhas[0].id
$observadaEm = [DateTimeOffset]::UtcNow.ToOffset([TimeSpan]::FromHours(-3)).AddMinutes(-1).ToString("yyyy-MM-dd'T'HH:mm:sszzz")
$r = Chamar 'POST' '/api/v1/admin/observacoes-passagem' "{`"paradaId`":$parada,`"linhaId`":$linha,`"observadaEm`":`"$observadaEm`",`"origemRegistro`":`"11144477735`"}"
Write-Host "Rota real com CPF em origemRegistro: HTTP $($r.Status) · $($r.Json.codigo)"

Titulo 'Cenário 4 · explicação do evento de maior risco'
$painel = (Chamar 'GET' '/api/v1/seguranca/painel').Json
$r = Chamar 'POST' "/api/v1/seguranca/eventos/$($painel.risco.eventoReferenciaId)/explicacao"
Write-Host "Mensagem ao cidadão: $($r.Json.evento.mensagemCidadao)"
Write-Host "Origem: $($r.Json.evento.origemMensagem) $($r.Json.evento.motivoFallback) · chamada externa realizada: $($r.Json.chamadaExternaRealizada)"
Write-Host "Dados enviados ao LLM: $($r.Json.dadosEnviadosAoLlm | ConvertTo-Json -Compress)"

Titulo 'Estado final do painel'
$painel = (Chamar 'GET' '/api/v1/seguranca/painel').Json
Write-Host "Risco $($painel.risco.nivel): $($painel.risco.titulo)"
$painel.indicadores | Format-List | Out-String | Write-Host
$painel.eventos | Select-Object -First 12 | Format-Table @{ n = 'Horário'; e = { ([DateTimeOffset] $_.ocorridoEm).ToOffset([TimeSpan]::FromHours(-3)).ToString('HH:mm:ss') } }, codigo, nivelRisco, tipoDestino, decisao -AutoSize | Out-String | Write-Host
