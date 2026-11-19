# PontoVoz — Cybersecurity

**Global Solution FIAP 2026.2** · Engenharia de Software · Tema **CitizenTech** · Disciplina:
**Cybersecurity** · Prof. Vitor Lasse

Módulo de proteção de dados pessoais do PontoVoz — Totem Inteligente de Mobilidade Urbana.
Partimos do backend C#/.NET 10 do PontoVoz, que já disponibiliza as consultas de mobilidade, e
acrescentamos uma camada de segurança com as quatro partes pedidas na disciplina: **motor de
parsing PII**, **Taint Analysis**, **tradução de alertas por IA** e **Dashboard Risco Cidadão**.

A documentação acadêmica (PDF) e o vídeo da demonstração são entregues separadamente, como pedido

## O PontoVoz e por que ele precisa de proteção de dados

O PontoVoz propõe um totem no ponto de ônibus que informa linhas, destinos, previsões de chegada,
últimas passagens e alternativas de deslocamento em linguagem acessível, sem exigir smartphone.
O backend (API REST em ASP.NET Core, EF Core e SQLite) já existia; os dados de demonstração são
fictícios e não há totem instalado, GPS em produção nem integração operacional com a SPTrans.

O uso normal do totem não pede identificação do passageiro. Ainda assim, um passageiro pode
digitar o CPF no campo de busca, um operador pode preencher um campo administrativo com um
documento, e funcionalidades futuras (cadastro de acessibilidade, por exemplo) podem receber
dados de saúde. Para tratar esse risco, reconhecemos esses dados na entrada, acompanhamos cada
valor durante a requisição e impedimos que ele chegue a saídas inseguras: log, resposta HTTP,
banco de dados e serviços externos.

## Arquitetura

```
Requisição HTTP (query, corpo JSON, formulário, multipart)
        │
        ▼
InterceptadorDadosPessoais ── MotorPii (regras por campo + Regex + DV do CPF) ──► classificação
        │                         │
        │                  ContextoTaint (marcas e valores da requisição, só em memória)
        ▼                         │
Controllers do PontoVoz           ▼
        │               GuardaSinks + PoliticaSinks ──► Log · Resposta HTTP · SQLite · Serviço externo
        ▼                         │                       (mascarar ou bloquear)
   Resposta                       ▼
                     RegistroEventosSeguranca (auditoria sem valores)
                                  │
                   ┌──────────────┴──────────────┐
                   ▼                             ▼
     TradutorRiscoCidadao (LLM + fallback)   CalculadoraRiscoCidadao (verde/amarelo/vermelho)
                   └──────────────┬──────────────┘
                                  ▼
                     Painel Risco Cidadão (/seguranca)
```

| Componente | Arquivo | Responsabilidade |
|---|---|---|
| Motor PII | [`Pii/MotorPii.cs`](backend/src/PontoVoz.Api/Cybersecurity/Pii/MotorPii.cs), [`RegrasPii.cs`](backend/src/PontoVoz.Api/Cybersecurity/Pii/RegrasPii.cs), [`ValidadorCpf.cs`](backend/src/PontoVoz.Api/Cybersecurity/Pii/ValidadorCpf.cs), [`MascaradorPii.cs`](backend/src/PontoVoz.Api/Cybersecurity/Pii/MascaradorPii.cs) | Percorre JSON (objetos aninhados e listas), campos de query, formulário e multipart, e texto livre; classifica e mascara |
| Source do Taint | [`Taint/InterceptadorDadosPessoais.cs`](backend/src/PontoVoz.Api/Cybersecurity/Taint/InterceptadorDadosPessoais.cs), [`ContextoTaint.cs`](backend/src/PontoVoz.Api/Cybersecurity/Taint/ContextoTaint.cs) | Middleware no início do pipeline: analisa a entrada, cria as marcas e limita tamanho e profundidade |
| Política e guarda das saídas | [`Taint/PoliticaSinks.cs`](backend/src/PontoVoz.Api/Cybersecurity/Taint/PoliticaSinks.cs), [`GuardaSinks.cs`](backend/src/PontoVoz.Api/Cybersecurity/Taint/GuardaSinks.cs) | Decide mascarar ou bloquear e registra cada interceptação |
| Sinks | [`Sinks/ProvedorLogProtegido.cs`](backend/src/PontoVoz.Api/Cybersecurity/Sinks/ProvedorLogProtegido.cs), [`SinkPersistenciaInterceptor.cs`](backend/src/PontoVoz.Api/Cybersecurity/Sinks/SinkPersistenciaInterceptor.cs) e o buffer de resposta do interceptador | Log/console (mensagens, exceções e escopos), SQLite (EF Core) e resposta HTTP, inclusive de erro |
| Auditoria e risco | [`Auditoria/`](backend/src/PontoVoz.Api/Cybersecurity/Auditoria) | Eventos só com metadados; indicador de Risco Cidadão |
| IA | [`IA/`](backend/src/PontoVoz.Api/Cybersecurity/IA) | Prompt sanitizado, clientes Gemini e OpenAI, validação da resposta e fallback local |
| API do painel | [`Api/`](backend/src/PontoVoz.Api/Cybersecurity/Api) | Rotas `/api/v1/seguranca` e cenários de demonstração |
| Painel | [`wwwroot/seguranca/`](backend/src/PontoVoz.Api/wwwroot/seguranca) | Interface web que consome as rotas do módulo |

O módulo é registrado em [`Program.cs`](backend/src/PontoVoz.Api/Program.cs) por
`AddCybersecurityPontoVoz` e `UseInterceptadorDadosPessoais`. O contrato v1 do PontoVoz não
mudou: as rotas novas têm documento OpenAPI próprio (`/openapi/seguranca.json`).

## Tecnologias

C# 14 e .NET 10 · ASP.NET Core Web API · Entity Framework Core 10 + SQLite (interceptor de
gravação) · `System.Text.Json` · expressões regulares geradas em compilação (`GeneratedRegex`, com
tempo limite) · `HttpClient` tipado para o LLM · xUnit v3 · HTML, CSS e JavaScript sem
dependências externas no painel. Nenhum pacote NuGet foi acrescentado ao projeto original.

## Como executar

Pré-requisito: **.NET SDK 10** (10.0.100 ou superior; confira com `dotnet --list-sdks`). Não é
preciso instalar banco de dados.

```bash
git clone https://github.com/PONTOVOZ-GLOBAL-SOLUTION/pontovoz-cybersecurity.git
```

```bash
cd pontovoz-cybersecurity
```

```bash
dotnet build
```

```bash
dotnet run --project backend/src/PontoVoz.Api --launch-profile http
```

Na primeira execução em Development, a API cria o banco SQLite com os dados de demonstração.

| Recurso | Endereço |
|---|---|
| **Painel Risco Cidadão** | http://localhost:5080/seguranca |
| API original (Scalar) | http://localhost:5080/scalar |
| OpenAPI do módulo | http://localhost:5080/openapi/seguranca.json |

Em Development, sem `Admin:Chave` configurada, as rotas do painel ficam abertas para a
demonstração local (o mesmo comportamento das rotas administrativas do PontoVoz). Com a chave
configurada, o painel pede o valor do cabeçalho `X-PontoVoz-Admin-Key`.

## Como reproduzir os cenários

Organizamos a demonstração em quatro cenários, um para cada mecanismo. No painel, os botões
executam chamadas reais ao backend; os indicadores e o histórico são lidos de
`GET /api/v1/seguranca/painel` a cada 2,5 s.

| Cenário | Botão | O que acontece | Resultado esperado |
|---|---|---|---|
| 1. Consulta segura | Executar consulta | `GET /api/v1/paradas?codigoExterno=SIM-P001` | Evento `PII_ANALISE_SEM_DETECCAO`, risco **verde** |
| 2. Dado pessoal detectado | Analisar JSON | `POST /api/v1/seguranca/analises` com JSON fictício | Tabela de classificação, JSON mascarado, risco **amarelo** |
| 3. Tentativa de vazamento | Executar tentativa controlada | Código inseguro de propósito leva o cadastro ao log, a um serviço externo e à resposta | Log sanitizado, envio externo recusado, resposta mascarada, risco **vermelho** |
| 3. (variações) | Exceção com o cadastro · Gravar CPF no banco | Exceção com o payload na mensagem; rota real `POST /api/v1/admin/observacoes-passagem` com CPF em `origemRegistro` | 500 genérico e log sanitizado; 422 `DadoPessoalBloqueado` sem gravação |
| 4. Explicação por IA | Explicar evento com IA | `POST /api/v1/seguranca/eventos/{id}/explicacao` | Mensagem ao cidadão, origem (LLM ou fallback) e os dados sanitizados enviados |

**Reiniciar demonstração** limpa a trilha e volta ao verde. Clicar num evento do histórico mostra a
trilha da requisição: Source → Classificação → Sink → Ação.

O mesmo roteiro pode ser executado sem navegador, com a API rodando:

```bash
powershell -ExecutionPolicy Bypass -File backend/scripts/demonstracao-seguranca.ps1
```

As rotas de demonstração só existem em Development, com `Cybersecurity:Demonstracao:Habilitada`
verdadeira (já definida em `appsettings.Development.json`) e para chamadas cujo endereço remoto é
de loopback (`127.0.0.1` ou `::1`); sem endereço remoto conhecido, ou em qualquer outro caso,
respondem 404.

## Motor de parsing PII

| Categoria | Pelo nome do campo | Pelo conteúdo | Sensibilidade | Proteção |
|---|---|---|---|---|
| CPF | `cpf`, `cpfTitular`, `documento` com formato de CPF | `000.000.000-00` com dígitos verificadores válidos; 11 dígitos com DV válido; rótulo "CPF" + formato | Dado pessoal | `***.456.***-00` |
| RG | `rg`, `numeroRg`, `identidade`, `registroGeral` | rótulo "RG" + número; formato `00.000.000-0` | Dado pessoal | `**.***.**8-X` |
| Documento | `documento`, `cnh`, `passaporte`, `cns`, `pis` | — | Dado pessoal | últimos 2 caracteres |
| E-mail | `email` | padrão de e-mail | Dado pessoal | `p***@e***.br` |
| Telefone | `telefone`, `celular`, `whatsapp` | `(11) 91234-5678`, `+55 ...`, celular de 11 dígitos | Dado pessoal | `(**) *****-5678` |
| Saúde | `laudo`, `diagnostico`, `cid`, `saude`, `medicamento`, `alergia`, `deficiencia`... (a estrutura inteira sob o campo) | código CID-10; expressões como "laudo médico", "diagnosticado com", "portador de" | Dado pessoal sensível | suprimido |
| Senha | `senha`, `password`, `pin`, `token`, `apiKey`... | `senha: valor` | Segredo de autenticação | suprimida |

Os nomes de campo são comparados por palavra e sem acentos (`cargo` não é lido como RG). Cada
detecção registra categoria, sensibilidade, caminho JSON (`$.passageiro.contatos[1].valor`),
regra, confiança e ação; o valor detectado nunca entra nos metadados. Corpos acima de 64 KiB
recebem 413 e JSON com mais de 32 níveis ou 5.000 elementos recebe 400, antes dos controllers.
Em `multipart/form-data`, os campos de texto são analisados pelo nome, como num formulário comum;
partes com arquivo não são lidas (o PontoVoz não recebe arquivos).

## Taint Analysis

1. **Source:** o interceptador analisa query string e corpo e cria o `ContextoTaint` da
   requisição, com uma marca por ocorrência (`T1 Cpf/DadoPessoal em $.cpf`) e os valores originais
   apenas na memória da requisição.
2. **Propagação:** todas as saídas da requisição consultam o contexto. O valor é reconhecido mesmo
   dentro de outro texto, só com dígitos ou escapado por um serializador JSON. Nos logs, a
   verificação vale para a mensagem, para o texto das exceções e para os escopos (`BeginScope`).
3. **Sinks e política** ([`PoliticaSinks`](backend/src/PontoVoz.Api/Cybersecurity/Taint/PoliticaSinks.cs)):

| Saída | Dado pessoal | Dado sensível (saúde) | Segredo (senha) |
|---|---|---|---|
| Log / console | mascarar | bloquear | bloquear |
| Resposta HTTP (inclusive de erro) | mascarar | bloquear | bloquear |
| Persistência (SQLite) | bloquear a gravação | bloquear | bloquear |
| Serviço externo (inclui o LLM) | bloquear o envio | bloquear | bloquear |

Em log e resposta, "bloquear" troca o valor por `[BLOQUEADO: SENHA]`, sem nenhum trecho do
original; em persistência e serviço externo, a operação é recusada. Logs e respostas também passam
pelas regras de conteúdo, para dados que não vieram de uma fonte rastreada (por exemplo, um texto
de exceção). Cada interceptação gera o evento `PII_TAINT_SINK_BLOCKED`, ligado pela correlação à
detecção da entrada.

## Inteligência artificial

O `TradutorRiscoCidadao` monta o prompt só com enumerações do evento — código, categorias
genéricas ("CPF", "informação de saúde"), tipo de destino e ação — e pede a tradução "para um
cidadão leigo de 60 anos, em até 2 frases". O prompt passa pela mesma guarda das saídas externas
antes do envio. A resposta é validada (tamanho, até 3 frases, sem termos técnicos, sem afirmar
vazamento quando houve bloqueio, sem promessas absolutas, sem alarmismo, sem dado pessoal, em
português); se reprovada, ou se o provedor falhar, vale a mensagem local, e o motivo fica na
auditoria (`ChaveNaoConfigurada`, `TempoEsgotado`, `ServicoIndisponivel`, `RespostaInadequada:...`).

**Situação da credencial nesta entrega:** não tivemos uma chave de LLM disponível no ambiente de
desenvolvimento. A integração (Gemini por padrão, OpenAI opcional) está implementada e testada com
respostas HTTP simuladas, mas **nenhuma chamada real a um provedor foi feita**. As evidências e o
vídeo mostram o fallback, identificado como tal no painel.

Para ativar a chamada real, basta configurar a chave fora do repositório:

```bash
dotnet user-secrets set "Cybersecurity:Llm:ChaveApi" "<sua-chave>" --project backend/src/PontoVoz.Api
```

ou defina a variável de ambiente `GEMINI_API_KEY`. Para OpenAI, use também
`Cybersecurity:Llm:Provedor=OpenAI`, `Cybersecurity:Llm:Modelo=gpt-4o-mini` e
`Cybersecurity:Llm:VariavelAmbienteChave=OPENAI_API_KEY`. O painel mostra no topo se a chave está
configurada.

## Risco Cidadão

| Cor | Regra (código em [`CalculadoraRiscoCidadao`](backend/src/PontoVoz.Api/Cybersecurity/Auditoria/CalculadoraRiscoCidadao.cs)) |
|---|---|
| Verde | nenhum dado pessoal e nenhuma tentativa insegura nos últimos 30 minutos |
| Amarelo | dado pessoal detectado e mascarado, ou entrada recusada, sem tentativa de saída insegura |
| Vermelho | ao menos uma tentativa de levar dado protegido a uma saída não autorizada foi interceptada |

O vermelho indica a gravidade da **tentativa**, não um vazamento: o valor original não chegou ao
destino. O nível é calculado pelo backend a partir dos eventos; a IA apenas redige a explicação.

## Testes

```bash
dotnet test
```

Resultado registrado nesta entrega: **1001 testes, 1001 aprovados** — os 816 testes originais do
PontoVoz e 185 do módulo (pasta [`backend/tests/PontoVoz.Tests/Cybersecurity`](backend/tests/PontoVoz.Tests/Cybersecurity)):
motor PII e validação de CPF, máscaras, política e guarda das saídas, sink de log, auditoria e
risco, clientes do LLM com HTTP simulado, validação das mensagens, escopos de log, formulário
multipart, acesso às rotas de demonstração e testes de integração com a API real em memória. Nenhum teste chama um provedor externo. Para rodar só os testes do módulo:

```bash
dotnet test -- --filter-namespace PontoVoz.Tests.Cybersecurity
```

## Evidências

Em [`docs/evidencias/cybersecurity`](docs/evidencias/cybersecurity/README.md): capturas do painel
em cada cenário, trechos do código, saídas dos testes, o log do console durante a demonstração e
as respostas JSON exportadas da API. Com a API rodando, as capturas do painel são refeitas por
`backend/scripts/capturar-evidencias.py` e o vídeo por `backend/scripts/gravar-video-demonstracao.py`
(Python + Playwright, com o Google Chrome). As capturas de código e o PDF são gerados por
[`docs/documentacao`](docs/documentacao).

| Documento | Conteúdo |
|---|---|

## Limitações

- Nomes de pessoas e endereços residenciais não são detectados (exigiria reconhecimento de
  entidades, fora do escopo).
- RG não tem formato nacional único: fora de campos com nome de RG, só os formatos
  `00.000.000-0` e o rótulo "RG" são reconhecidos. Não há validação de dígito do RG.
- Falsos positivos possíveis: campos com "saude" no nome (ex.: `unidadeSaude`) são tratados como
  dado de saúde; 11 dígitos com DV de CPF válido em campo genérico são tratados como CPF.
- Valores com menos de 4 caracteres são mascarados na entrada, mas não são procurados nas saídas.
- Transformações do valor (codificação Base64, criptografia, reordenação) não são rastreadas.
- Em `multipart/form-data`, o conteúdo de arquivos anexados não é analisado.
- A trilha de auditoria fica em memória (últimos 500 eventos) e é perdida ao reiniciar a API;
  a exportação JSON (`GET /api/v1/seguranca/auditoria`) serve para guardar a evidência.
- A chamada real ao LLM não foi validada nesta entrega (ver "Inteligência artificial").

## Integrantes

| Nome | RM |
|---|---|
| Albert Katri | RM556544 |
| Bruno Biletsky | RM554739 |
| Guilherme Gomes Oliveira | RM554606 |
| Paulo Akira Okama | RM556840 |

## Uso de inteligência artificial

Utilizamos um assistente de programação baseado em IA como apoio no desenvolvimento do módulo,
dos testes e desta documentação, a partir das nossas orientações e dos documentos da disciplina.
