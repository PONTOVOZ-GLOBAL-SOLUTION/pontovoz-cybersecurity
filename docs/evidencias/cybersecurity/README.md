# Evidências · Cybersecurity

Capturas e saídas que geramos em 18/11/2026 com a API em execução local (Development), com a
chave do Gemini configurada (`gemini-3.5-flash-lite`). Todos os dados enviados
são fictícios. O vídeo da demonstração é entregue separadamente
(`PontoVoz_Cybersecurity_Demonstracao.mp4`).

## Parsing PII (3,0)

| Arquivo | Conteúdo |
|---|---|
| [codigo/01-regras-pii-por-campo.png](codigo/01-regras-pii-por-campo.png) | Regras pelo nome do campo |
| [codigo/02-regras-pii-regex.png](codigo/02-regras-pii-regex.png) | Expressões regulares |
| [codigo/03-regras-pii-conteudo.png](codigo/03-regras-pii-conteudo.png) | Regras de conteúdo com validação adicional |
| [codigo/04-validador-cpf.png](codigo/04-validador-cpf.png) | Dígitos verificadores do CPF |
| [codigo/05-motor-classificacao-por-campo.png](codigo/05-motor-classificacao-por-campo.png) | Classificação, inclusive o exemplo `documento: "123.456.789-00"` |
| [codigo/06-mascarador.png](codigo/06-mascarador.png) | Máscaras por categoria |
| [respostas/cenario2-requisicao.json](respostas/cenario2-requisicao.json) | JSON fictício enviado no cenário 2 |
| [telas/03-cenario2-classificacao-pii.png](telas/03-cenario2-classificacao-pii.png) | Classificação e corpo mascarado devolvidos pela API |

## Taint Analysis (3,0)

| Arquivo | Conteúdo |
|---|---|
| [codigo/07-interceptador-source.png](codigo/07-interceptador-source.png) | Source: interceptador da entrada |
| [codigo/07b-interceptador-multipart.png](codigo/07b-interceptador-multipart.png) | Campos de texto de `multipart/form-data` |
| [codigo/08-interceptador-sink-resposta.png](codigo/08-interceptador-sink-resposta.png) | Sink de resposta HTTP |
| [codigo/09-politica-sinks.png](codigo/09-politica-sinks.png) | Política explícita por saída |
| [codigo/10-guarda-sinks.png](codigo/10-guarda-sinks.png) | Verificação antes das saídas |
| [codigo/11-sink-log.png](codigo/11-sink-log.png) · [11b-sink-log-escopos.png](codigo/11b-sink-log-escopos.png) · [12-sink-persistencia.png](codigo/12-sink-persistencia.png) | Sinks de log (mensagens e escopos) e de banco |
| [codigo/13-demonstracao-codigo-inseguro.png](codigo/13-demonstracao-codigo-inseguro.png) | Código inseguro de propósito (tentativa controlada) |
| [codigo/20-pipeline-program.png](codigo/20-pipeline-program.png) | Posição do interceptador no pipeline |
| [telas/06-cenario3-resposta-sanitizada.png](telas/06-cenario3-resposta-sanitizada.png) | Resposta que chegou ao cliente |
| [telas/09-trilha-taint-analysis.png](telas/09-trilha-taint-analysis.png) | Trilha Source → Classificação → Sink → Ação |
| [telas/10-cenario3-excecao-resposta-generica.png](telas/10-cenario3-excecao-resposta-generica.png) | Exceção com o payload: resposta genérica |
| [telas/11-cenario3-persistencia-bloqueada.png](telas/11-cenario3-persistencia-bloqueada.png) | Rota real: gravação do CPF recusada (422) |
| [codigo/35-log-console-sanitizado.png](codigo/35-log-console-sanitizado.png) · [logs/console-api.log](logs/console-api.log) | O que o console efetivamente recebeu |
| [respostas/auditoria-exportada.json](respostas/auditoria-exportada.json) | Trilha de auditoria exportada |

## Inteligência artificial (2,0)

| Arquivo | Conteúdo |
|---|---|
| [codigo/14-prompt-sanitizado.png](codigo/14-prompt-sanitizado.png) · [15-dados-prompt.png](codigo/15-dados-prompt.png) | Montagem do prompt só com dados enumerados |
| [codigo/16-tradutor-ia.png](codigo/16-tradutor-ia.png) | Fluxo com guarda da saída externa, validação e fallback |
| [codigo/17-cliente-gemini.png](codigo/17-cliente-gemini.png) | Requisição ao Gemini |
| [codigo/18-validador-mensagem.png](codigo/18-validador-mensagem.png) | Validação da resposta do LLM |
| [telas/12-cenario4-explicacao-ia.png](telas/12-cenario4-explicacao-ia.png) | Mensagem gerada pelo Gemini, origem e dados sanitizados enviados |

As mensagens ao cidadão mostradas nas evidências foram geradas por chamadas reais ao Gemini: a tela do
cenário 4 mostra a origem `IA (Gemini/gemini-3.5-flash-lite)` e `chamada externa realizada: sim`,
e o log do console registra as requisições a `generativelanguage.googleapis.com` (sem a chave).

## Dashboard Risco Cidadão (2,0)

| Arquivo | Conteúdo |
|---|---|
| [telas/01-painel-inicial-verde.png](telas/01-painel-inicial-verde.png) | Estado inicial |
| [telas/02-cenario1-consulta-segura-verde.png](telas/02-cenario1-consulta-segura-verde.png) | Após a consulta segura (verde) |
| [telas/04-indicador-amarelo.png](telas/04-indicador-amarelo.png) · [05-painel-amarelo.png](telas/05-painel-amarelo.png) | Após o cenário 2 (amarelo) |
| [telas/07-indicador-vermelho.png](telas/07-indicador-vermelho.png) · [08-painel-vermelho.png](telas/08-painel-vermelho.png) | Após o cenário 3 (vermelho) |
| [telas/13-indicadores.png](telas/13-indicadores.png) · [14-historico-eventos.png](telas/14-historico-eventos.png) · [15-painel-final.png](telas/15-painel-final.png) | Totais, histórico e painel ao final |
| [codigo/19-calculadora-risco.png](codigo/19-calculadora-risco.png) | Regra do indicador em código |

## Testes e execução

| Arquivo | Conteúdo |
|---|---|
| [codigo/30-terminal-dotnet-test.png](codigo/30-terminal-dotnet-test.png) · [logs/testes-suite-completa.txt](logs/testes-suite-completa.txt) | `dotnet test`: suíte completa |
| [codigo/31-testes-cybersecurity-lista-1.png](codigo/31-testes-cybersecurity-lista-1.png) (e partes 2 e 3) · [logs/testes-cybersecurity-detalhado.txt](logs/testes-cybersecurity-detalhado.txt) · [logs/testes-cybersecurity.xml](logs/testes-cybersecurity.xml) | Resultado de cada teste do módulo |
| [codigo/34-terminal-demonstracao-cli.png](codigo/34-terminal-demonstracao-cli.png) · [logs/demonstracao-linha-de-comando.txt](logs/demonstracao-linha-de-comando.txt) | Os quatro cenários pela linha de comando |
