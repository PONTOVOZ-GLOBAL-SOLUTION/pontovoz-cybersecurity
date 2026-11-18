"use strict";

// Painel Risco Cidadão: todo o conteúdo exibido vem das rotas /api/v1/seguranca do backend.
// Os exemplos abaixo são apenas as entradas fictícias enviadas nos cenários.

const API = "/api/v1/seguranca";
const INTERVALO_ATUALIZACAO_MS = 2500;

const EXEMPLO_CENARIO_2 = {
  passageiro: {
    nome: "Passageiro Fictício",
    cpf: "123.456.789-09",
    rg: "12.345.678-X",
    contatos: [
      { tipo: "e-mail", valor: "passageiro.ficticio@exemplo.com.br" },
      { tipo: "celular", valor: "(11) 91234-5678" }
    ]
  },
  acessibilidade: { laudo: "CID-10 H54 — baixa visão (dado fictício)" },
  senha: "Senha@Teste123",
  observacao: "Meu documento é 111.444.777-35, avisar no ponto SIM-P001"
};

const CADASTRO_CENARIO_3 = {
  cpf: "111.444.777-35",
  senha: "Senha@Teste123",
  saude: { condicao: "diabetes tipo 2 (dado fictício)" },
  email: "passageiro.ficticio@exemplo.com.br"
};

// CPF fictício (dígitos verificadores válidos) digitado no campo origemRegistro da rota real.
const CPF_SEM_PONTUACAO = "11144477735";

const estado = { chave: lerChave(), eventoSelecionado: null, ultimoPainel: null };

function lerChave() {
  try { return sessionStorage.getItem("pontovoz-admin-key") || ""; } catch { return ""; }
}

function gravarChave(valor) {
  try { sessionStorage.setItem("pontovoz-admin-key", valor); } catch { /* armazenamento indisponível */ }
}

function el(id) { return document.getElementById(id); }

function escapar(texto) {
  return String(texto ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function hora(instante) {
  return new Date(instante).toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo" });
}

async function chamar(metodo, caminho, corpo) {
  const cabecalhos = { Accept: "application/json" };
  if (corpo !== undefined) cabecalhos["Content-Type"] = "application/json";
  if (estado.chave) cabecalhos["X-PontoVoz-Admin-Key"] = estado.chave;

  const resposta = await fetch(caminho, {
    method: metodo,
    headers: cabecalhos,
    body: corpo === undefined ? undefined : (typeof corpo === "string" ? corpo : JSON.stringify(corpo))
  });

  if (resposta.status === 401) el("area-chave").hidden = false;
  const texto = await resposta.text();
  let json = null;
  try { json = texto ? JSON.parse(texto) : null; } catch { json = null; }
  return { status: resposta.status, protecao: resposta.headers.get("X-PontoVoz-Protecao"), json, texto };
}

// ---------- Painel ----------

const ROTULO_CATEGORIA = {
  Cpf: "CPF", Rg: "RG", DocumentoIdentificador: "Documento", Email: "E-mail",
  Telefone: "Telefone", Saude: "Saúde", Senha: "Senha"
};

const ROTULO_SINK = { Log: "Log", RespostaHttp: "Resposta HTTP", Persistencia: "Banco de dados", ServicoExterno: "Serviço externo" };

function descreverOrigem(evento) {
  switch (evento.origemMensagem) {
    case "Llm": return `IA (${evento.modeloLlm})`;
    case "Fallback": return `Mensagem local · ${evento.motivoFallback}`;
    case "Padrao": return "Mensagem padrão (sem risco)";
    default: return "Aguardando IA…";
  }
}

async function atualizarPainel() {
  try {
    const r = await chamar("GET", `${API}/painel?limite=40`);
    if (r.status !== 200 || !r.json) {
      el("status-conexao").textContent = r.status === 401 ? "Chave administrativa necessária" : `Painel indisponível (HTTP ${r.status})`;
      el("status-conexao").className = "pilula pilula-erro";
      return;
    }
    estado.ultimoPainel = r.json;
    renderizarPainel(r.json);
    el("status-conexao").textContent = `Atualizado às ${hora(r.json.geradoEm)}`;
    el("status-conexao").className = "pilula";
  } catch {
    el("status-conexao").textContent = "Sem conexão com a API";
    el("status-conexao").className = "pilula pilula-erro";
  }
}

function renderizarPainel(painel) {
  const risco = painel.risco;
  el("farol").dataset.nivel = risco.nivel;
  el("farol").setAttribute("aria-label", `Nível de risco: ${risco.nivel}`);
  el("nivel-risco").dataset.nivel = risco.nivel;
  el("nivel-risco").textContent = `Risco ${risco.nivel}`;
  el("titulo-risco").textContent = risco.titulo;
  el("descricao-risco").textContent = risco.descricao;
  el("mensagem-cidadao").textContent = risco.mensagemCidadao;

  const referencia = painel.eventos.find(e => e.id === risco.eventoReferenciaId);
  el("origem-mensagem").textContent = referencia
    ? `Origem da mensagem: ${descreverOrigem(referencia)} · evento ${referencia.id}`
    : "Origem da mensagem: padrão do sistema (nenhum evento na janela)";

  const ind = painel.indicadores;
  el("kpi-analisados").textContent = ind.eventosAnalisados;
  el("kpi-identificados").textContent = ind.dadosPessoaisIdentificados;
  el("kpi-bloqueados").textContent = ind.tentativasBloqueadas;
  el("kpi-sem-risco").textContent = ind.eventosSemRisco;

  const ia = painel.ia;
  el("status-ia").textContent = ia.chaveConfigurada
    ? `IA: ${ia.provedor} (${ia.modelo}) configurada`
    : `IA: ${ia.provedor} sem chave · fallback local`;
  el("status-ia").className = ia.chaveConfigurada ? "pilula pilula-ok" : "pilula pilula-alerta";

  const protecao = el("status-protecao");
  protecao.textContent = risco.nivel === "Vermelho" ? "Proteção ativa · bloqueio recente" : "Proteção ativa";
  protecao.className = risco.nivel === "Vermelho" ? "pilula pilula-erro" : "pilula pilula-ok";

  el("cenario-3").disabled = el("cenario-3-erro").disabled = !painel.demonstracaoHabilitada;
  renderizarEventos(painel.eventos);
}

function renderizarEventos(eventos) {
  const corpo = el("tabela-eventos");
  if (!eventos.length) {
    corpo.innerHTML = '<tr><td colspan="8" class="vazio">Nenhum evento registrado.</td></tr>';
    return;
  }

  corpo.innerHTML = eventos.map(e => `
    <tr data-id="${escapar(e.id)}" class="${e.id === estado.eventoSelecionado ? "selecionado" : ""}">
      <td>${hora(e.ocorridoEm)}</td>
      <td><span class="selo selo-${escapar(e.nivelRisco)}">${escapar(e.nivelRisco)}</span></td>
      <td><code>${escapar(e.codigo)}</code><br><span class="origem">${escapar(e.id)}</span></td>
      <td>${e.categorias.length ? e.categorias.map(c => escapar(ROTULO_CATEGORIA[c] || c)).join(", ") : "—"}</td>
      <td>${escapar(e.fonte)}${e.tipoDestino ? ` → <strong>${escapar(ROTULO_SINK[e.tipoDestino] || e.tipoDestino)}</strong>` : ""}</td>
      <td>${escapar(e.decisao)}</td>
      <td>${escapar(e.mensagemCidadao || "Aguardando explicação…")}</td>
      <td class="origem">${escapar(descreverOrigem(e))}</td>
    </tr>`).join("");
}

async function mostrarTrilha(id) {
  estado.eventoSelecionado = id;
  const r = await chamar("GET", `${API}/eventos/${encodeURIComponent(id)}`);
  if (r.status !== 200) {
    el("trilha").innerHTML = `<p class="vazio">Evento indisponível (HTTP ${r.status}).</p>`;
    return;
  }

  const passos = r.json.mesmaRequisicao.map(e => {
    const categorias = e.categorias.map(c => ROTULO_CATEGORIA[c] || c).join(", ") || "nenhuma";
    let etapa = "Source · entrada";
    if (e.codigo === "PII_DETECTADO_PROTEGIDO") etapa = "Source → Classificação";
    if (e.codigo === "PII_TAINT_SINK_BLOCKED") etapa = `Sink → Ação (${ROTULO_SINK[e.tipoDestino] || e.tipoDestino})`;
    if (e.codigo === "PII_ENTRADA_REJEITADA") etapa = "Entrada recusada";
    return `
      <div class="passo">
        <strong>${escapar(etapa)}</strong>
        <code>${escapar(e.codigo)}</code> · ${hora(e.ocorridoEm)} · <span class="selo selo-${escapar(e.nivelRisco)}">${escapar(e.nivelRisco)}</span>
        <p>Categorias: ${escapar(categorias)}${e.caminhos.length ? ` · Caminhos: <code>${escapar(e.caminhos.join(", "))}</code>` : ""}</p>
        ${e.destino ? `<p>Destino: <code>${escapar(e.destino)}</code></p>` : ""}
        <p>Decisão: <strong>${escapar(e.decisao)}</strong> — ${escapar(e.resultado)}</p>
        <p>Mensagem técnica: <code>${escapar(e.mensagemTecnica)}</code></p>
      </div>`;
  }).join("");

  el("trilha").innerHTML = `
    <p>Requisição <code>${escapar(r.json.evento.correlacaoId)}</code> · ${escapar(r.json.evento.fonte)} · ${r.json.mesmaRequisicao.length} evento(s)</p>
    <div class="passos">${passos}</div>`;
  if (estado.ultimoPainel) renderizarEventos(estado.ultimoPainel.eventos);
}

// ---------- Resultado ----------

function mostrarResultado(titulo, resposta, extra) {
  const faixa = Math.floor(resposta.status / 100);
  el("resultado").innerHTML = `
    <h4>${escapar(titulo)}</h4>
    <p>Status: <span class="status-http status-${faixa}xx">HTTP ${resposta.status}</span>
      ${resposta.protecao ? ` · cabeçalho <code>X-PontoVoz-Protecao: ${escapar(resposta.protecao)}</code>` : ""}</p>
    ${extra || ""}
    <pre>${escapar(resposta.json ? JSON.stringify(resposta.json, null, 2) : resposta.texto)}</pre>`;
}

async function executar(botao, acao) {
  botao.disabled = true;
  try { await acao(); } catch (erro) {
    el("resultado").innerHTML = `<p class="vazio">Falha ao executar: ${escapar(erro.message)}</p>`;
  } finally {
    botao.disabled = false;
    await atualizarPainel();
  }
}

async function cenario1() {
  const r = await chamar("GET", "/api/v1/paradas?codigoExterno=SIM-P001");
  const parada = r.json?.itens?.[0];
  mostrarResultado("Cenário 1 · consulta segura", r,
    parada ? `<p>Parada encontrada: <strong>${escapar(parada.nome)}</strong> (${escapar(parada.codigoExterno)}). Nenhum dado pessoal na entrada.</p>` : "");
}

async function cenario2() {
  const texto = el("json-cenario-2").value;
  const r = await chamar("POST", `${API}/analises`, texto);
  let tabela = "";
  if (r.json?.deteccoes) {
    tabela = `<table><thead><tr><th>Categoria</th><th>Caminho</th><th>Sensibilidade</th><th>Regra</th><th>Ação</th></tr></thead><tbody>
      ${r.json.deteccoes.map(d => `<tr><td>${escapar(ROTULO_CATEGORIA[d.categoria] || d.categoria)}</td><td><code>${escapar(d.caminho)}</code></td>
        <td>${escapar(d.sensibilidade)}</td><td><code>${escapar(d.regra)}</code></td><td>${escapar(d.acao)}</td></tr>`).join("")}
      </tbody></table>`;
  }
  mostrarResultado(`Cenário 2 · ${r.json?.quantidadeDeteccoes ?? 0} ocorrência(s) de PII classificadas`, r, tabela);
}

async function cenario3(modo) {
  const r = await chamar("POST", `${API}/demonstracao/vazamento-controlado?modo=${modo}`, CADASTRO_CENARIO_3);
  const titulo = modo === "erro"
    ? "Cenário 3 · exceção com o cadastro na mensagem (log sanitizado, resposta genérica)"
    : "Cenário 3 · tentativa controlada de saída insegura";
  mostrarResultado(titulo, r, "<p>Compare o corpo enviado com o que a resposta e o log efetivamente receberam.</p>");
}

async function cenario3Banco() {
  const busca = await chamar("GET", "/api/v1/paradas?codigoExterno=SIM-P001");
  const paradaId = busca.json?.itens?.[0]?.id;
  const detalhe = await chamar("GET", `/api/v1/paradas/${paradaId}`);
  const linhaId = detalhe.json?.linhas?.[0]?.id;
  // Horário de São Paulo (UTC-3) um minuto atrás, com o fuso explícito exigido pela rota.
  const local = new Date(Date.now() - 3 * 3600 * 1000 - 60 * 1000).toISOString().slice(0, 19);
  const corpo = { paradaId, linhaId, observadaEm: `${local}-03:00`, prefixoVeiculo: null, origemRegistro: CPF_SEM_PONTUACAO };
  const r = await chamar("POST", "/api/v1/admin/observacoes-passagem", corpo);
  mostrarResultado("Cenário 3 · rota real tenta gravar um CPF no banco", r,
    "<p>O campo <code>origemRegistro</code> recebeu um CPF fictício sem pontuação. A gravação no SQLite foi recusada pelo sink de persistência.</p>");
}

async function cenario4() {
  const painel = estado.ultimoPainel;
  const alvo = painel?.eventos.find(e => e.id === painel.risco.eventoReferenciaId && e.nivelRisco !== "Verde")
    || painel?.eventos.find(e => e.nivelRisco === "Vermelho")
    || painel?.eventos.find(e => e.nivelRisco === "Amarelo");
  if (!alvo) {
    el("resultado").innerHTML = '<p class="vazio">Execute antes o cenário 2 ou 3 para gerar um evento com risco.</p>';
    return;
  }

  const r = await chamar("POST", `${API}/eventos/${encodeURIComponent(alvo.id)}/explicacao`);
  const dados = r.json;
  const extra = dados ? `
    <p><strong>Mensagem ao cidadão:</strong> ${escapar(dados.evento.mensagemCidadao)}</p>
    <p>Origem: <strong>${escapar(descreverOrigem(dados.evento))}</strong> · chamada externa realizada: <strong>${dados.chamadaExternaRealizada ? "sim" : "não"}</strong></p>
    <p>Estrutura sanitizada enviada (ou que seria enviada) ao LLM:</p>
    <pre>${escapar(JSON.stringify(dados.dadosEnviadosAoLlm, null, 2))}</pre>
    <p>Prompt do usuário:</p>
    <pre>${escapar(dados.promptUsuario)}</pre>` : "";
  el("resultado").innerHTML = `<h4>Cenário 4 · explicação do evento ${escapar(alvo.id)}</h4><p>Status: <span class="status-http">HTTP ${r.status}</span></p>${extra}`;
}

async function exportar() {
  const r = await chamar("GET", `${API}/auditoria`);
  if (r.status !== 200) return;
  const arquivo = new Blob([JSON.stringify(r.json, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(arquivo);
  link.download = `auditoria-seguranca-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

// ---------- Inicialização ----------

el("json-cenario-2").value = JSON.stringify(EXEMPLO_CENARIO_2, null, 2);
el("cenario-1").addEventListener("click", e => executar(e.currentTarget, cenario1));
el("cenario-2").addEventListener("click", e => executar(e.currentTarget, cenario2));
el("cenario-3").addEventListener("click", e => executar(e.currentTarget, () => cenario3("resposta")));
el("cenario-3-erro").addEventListener("click", e => executar(e.currentTarget, () => cenario3("erro")));
el("cenario-3-banco").addEventListener("click", e => executar(e.currentTarget, cenario3Banco));
el("cenario-4").addEventListener("click", e => executar(e.currentTarget, cenario4));
el("exportar").addEventListener("click", e => executar(e.currentTarget, exportar));
el("reiniciar").addEventListener("click", e => executar(e.currentTarget, async () => {
  const r = await chamar("POST", `${API}/demonstracao/reiniciar`);
  estado.eventoSelecionado = null;
  el("trilha").innerHTML = '<p class="vazio">Selecione um evento no histórico para ver a trilha Source → Classificação → Sink → Ação.</p>';
  el("resultado").innerHTML = `<p class="vazio">Demonstração reiniciada (HTTP ${r.status}).</p>`;
}));
el("tabela-eventos").addEventListener("click", e => {
  const linha = e.target.closest("tr[data-id]");
  if (linha) mostrarTrilha(linha.dataset.id);
});
el("salvar-chave").addEventListener("click", () => {
  estado.chave = el("chave-admin").value.trim();
  gravarChave(estado.chave);
  el("area-chave").hidden = true;
  atualizarPainel();
});

atualizarPainel();
setInterval(atualizarPainel, INTERVALO_ATUALIZACAO_MS);
