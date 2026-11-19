# PontoVoz · Prompts de aprendizado e debate em Cybersecurity

**Global Solution FIAP 2026.2**  
**Disciplina:** Cybersecurity  
**Projeto:** PontoVoz, Totem Inteligente de Mobilidade Urbana

Este documento reúne todos prompt utilizado no decorrer do projeto, todos voltados ao estudo e à discussão dos conceitos de segurança aplicados ao PontoVoz.

## 1. Mapeamento e classificação de dados pessoais (PII)

**Prompt 01 · Dados pessoais e LGPD**

"Estou estudando a aplicação da LGPD no PontoVoz. Qual é a diferença entre dado pessoal, dado pessoal sensível e informação confidencial? Gostaria de entender como classificar CPF, RG, informações médicas e senhas, e por que cada categoria exige cuidados diferentes."

**Prompt 02 · Regex e validação de CPF**

"Para identificar CPF em uma API C#, utilizar apenas expressões regulares é suficiente? Qual é a importância de validar os dígitos verificadores e como podemos evitar que números comuns, como códigos de linhas ou identificadores de paradas, sejam classificados incorretamente?"

**Prompt 03 · Identificação em campos JSON**

"Em uma API REST como a do PontoVoz, os dados pessoais podem aparecer em propriedades com nomes diferentes. Como funciona a identificação de uma informação sensível dentro de um campo genérico, como `observacao`, ou em objetos JSON aninhados? Quais são as vantagens de combinar análise do nome do campo com análise do conteúdo?"

**Prompt 04 · Mascaramento e proteção**

"Qual é a diferença entre mascarar, anonimizar, criptografar e simplesmente bloquear uma informação? Em quais situações faz sentido manter apenas parte de um CPF visível e por que dados de saúde e senhas exigem uma abordagem mais restritiva?"

## 2. Taint Analysis e prevenção de vazamentos

**Prompt 05 · Entendendo Source e Sink**

"Estou tentando compreender melhor o conceito de Taint Analysis. Pode explicar como uma informação passa da entrada de uma requisição HTTP até um possível destino inseguro? Gostaria de entender os conceitos de Source, Taint e Sink utilizando como exemplo um CPF enviado indevidamente para a API do PontoVoz."

**Prompt 06 · Acompanhamento de informações sensíveis**

"Depois que um middleware identifica e classifica um dado pessoal, como a aplicação pode acompanhar essa informação durante o processamento? Qual é a vantagem de manter metadados de classificação em vez de depender apenas de uma nova busca por padrões antes de cada saída?"

**Prompt 07 · Segurança dos logs**

"Por que os logs de uma aplicação podem representar um risco para a privacidade dos usuários? No ASP.NET Core, qual é a diferença entre registrar uma mensagem comum e utilizar logging estruturado com `BeginScope`? Que cuidados devem existir para evitar a exposição de dados pessoais nesses dois casos?"

**Prompt 08 · Respostas HTTP e tratamento de erros**

"Mesmo quando uma API identifica dados pessoais corretamente, ainda existe o risco de essas informações aparecerem numa resposta HTTP ou numa mensagem de exceção? Gostaria de entender como uma camada de proteção pode impedir isso sem esconder informações necessárias para diagnosticar problemas técnicos."

**Prompt 09 · Proteção na persistência**

"No PontoVoz utilizamos Entity Framework Core e SQLite. Qual é a diferença entre validar um dado antes de chegar ao banco e utilizar um interceptor no momento da persistência? Quais vantagens e limitações existem em cada abordagem para impedir que informações pessoais indevidas sejam armazenadas?"

## 3. Inteligência artificial aplicada à segurança

**Prompt 10 · Tradução de eventos técnicos**

"Como podemos transformar um evento técnico de segurança em uma mensagem que qualquer passageiro consiga compreender? Quero entender quais informações são importantes para o cidadão e quais detalhes técnicos, como códigos internos e exceções, devem permanecer somente na auditoria."

**Prompt 11 · Privacidade na integração com LLM**

"Se o PontoVoz utilizar o Gemini para explicar um bloqueio de segurança, quais são os riscos de enviar diretamente o conteúdo da requisição ao modelo? Como podemos construir um prompt dinâmico utilizando apenas a categoria do dado, o tipo de ocorrência e a ação realizada, sem transmitir informações pessoais?"

**Prompt 12 · Validação da resposta e fallback**

"Por que não devemos apresentar automaticamente qualquer texto gerado por um LLM ao usuário? Gostaria de discutir a importância de validar mensagens potencialmente alarmistas, afirmações incorretas sobre vazamentos e respostas excessivamente técnicas. Também quero compreender por que precisamos de um fallback quando a API de IA está indisponível."

## 4. Dashboard e indicador de Risco Cidadão

**Prompt 13 · Classificação de risco**

"No dashboard do PontoVoz utilizamos indicadores verde, amarelo e vermelho. Como podemos estabelecer critérios objetivos para cada nível? Qual é a diferença entre identificar um dado pessoal, realizar seu mascaramento e bloquear uma tentativa de saída insegura? Por que uma tentativa bloqueada não significa necessariamente que ocorreu um vazamento?"

**Prompt 14 · Auditoria e rastreabilidade**

"Quais informações um evento de auditoria de Cybersecurity precisa registrar para permitir a investigação de uma ocorrência? Gostaria de entender como relacionar a entrada, a classificação, o destino e a ação de proteção sem armazenar o CPF ou outro dado pessoal original."

## 5. Testes, qualidade e avaliação da solução

**Prompt 15 · Testes de segurança**

"Qual é a diferença entre testar se um método de mascaramento retorna o resultado esperado e comprovar que uma informação pessoal realmente não chegou ao log, ao banco ou à resposta HTTP? Como os testes unitários e de integração se complementam na avaliação da segurança do PontoVoz?"

**Prompt 16 · Limitações e evolução da segurança**

"Nosso módulo de Cybersecurity utiliza regras de classificação, interceptadores e políticas de proteção. Quais limitações esse tipo de solução pode apresentar diante de transformações de dados, formatos não reconhecidos e falsos positivos? Gostaria de entender como avaliar essas limitações e quais melhorias seriam prioritárias antes de utilizar o PontoVoz em um ambiente real."
