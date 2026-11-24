/* ==========================================================================
   Conector do Diário Técnico para o Claude (servidor MCP remoto, só leitura)
   Roda no Cloudflare Workers. Lê o Firestore do projeto com uma conta de serviço
   que só tem permissão de leitura (papel "Cloud Datastore Viewer").
   Nunca lê a coleção inventarioAcessos (logins e senhas).

   Segredos (Cloudflare > Worker > Settings > Variables and Secrets):
     FIREBASE_SA   conteúdo inteiro do arquivo .json da conta de serviço
     ACESSO_TOKEN  texto aleatório; o endereço do conector fica .../mcp/<ACESSO_TOKEN>
   ========================================================================== */

const VERSAO = "1.2.0";
const PROTOCOLO = "2025-06-18";
const SEM_REDE = ["OFFLINE", "FALHA"];
const OK = ["ONLINE", "OPERANDO"];

/* ---------------- texto ---------------- */
const semAc = (s) => String(s ?? "").normalize("NFD").replace(/[̀-ͯ]/g, "");
const norm = (s) => semAc(s).toUpperCase().replace(/[^A-Z0-9]+/g, " ").trim();
const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
const hojeISO = () => new Date(Date.now() - 3 * 3600e3).toISOString().slice(0, 10); // horário de Brasília
const dias = (iso) => (iso ? Math.max(0, Math.round((new Date(hojeISO()) - new Date(String(iso).slice(0, 10))) / 864e5)) : null);
const ehQuadro = (it) => /QUADRO|SWITCH/.test(norm(it && it.tipo));
const CAUSAS = { diag: "A diagnosticar", fibra: "Fibra rompida", cabo: "Cabo de rede rompido", switch: "Switch / PoE com defeito", radio: "Rádio / antena", conector: "Conector / patch cord", alim: "Falta de alimentação", fonte: "Fonte queimada", nobreak: "Nobreak / estabilizador", disjuntor: "Disjuntor desarmado", defeito: "Dispositivo com defeito (troca)", lente: "Lente / visão comprometida", ip: "IP em conflito / rede", senha: "Senha / usuário", firmware: "Firmware", canal: "Canal mal configurado no NVR", hd: "HD cheio ou com defeito", nvr: "NVR / DVR travado ou com defeito", obra: "Obra no local", desligado: "Desligado pelo cliente", vandal: "Vandalismo", removido: "Dispositivo removido", outro: "Outro" };
const nomeCausa = (c) => CAUSAS[c || "diag"] || c;

/* ---------------- Firestore (REST) ---------------- */
let tokenCache = { valor: "", expira: 0 };

const b64url = (buf) => {
  const s = typeof buf === "string" ? btoa(unescape(encodeURIComponent(buf))) : btoa(String.fromCharCode(...new Uint8Array(buf)));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

let tokenPedido = null;
function tokenGoogle(sa) {
  if (tokenCache.valor && Date.now() < tokenCache.expira) return Promise.resolve(tokenCache.valor);
  // várias consultas ao mesmo tempo usam o mesmo pedido de token
  return (tokenPedido = tokenPedido || pedeToken(sa).finally(() => (tokenPedido = null)));
}
async function pedeToken(sa) {
  const agora = Math.floor(Date.now() / 1000);
  const cab = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const corpo = b64url(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: agora, exp: agora + 3600 }));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const chave = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const ass = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", chave, new TextEncoder().encode(`${cab}.${corpo}`));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${cab}.${corpo}.${b64url(ass)}`,
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("Não consegui autenticar no Google: " + (j.error_description || j.error || r.status));
  tokenCache = { valor: j.access_token, expira: Date.now() + (j.expires_in - 120) * 1000 };
  return j.access_token;
}

// valor do Firestore (REST) → valor JS
function deValor(v) {
  if (!v) return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("nullValue" in v) return null;
  if ("timestampValue" in v) return v.timestampValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(deValor);
  if ("mapValue" in v) return deCampos(v.mapValue.fields || {});
  return null;
}
const deCampos = (f) => Object.fromEntries(Object.entries(f || {}).map(([k, v]) => [k, deValor(v)]));
const paraValor = (x) => (typeof x === "boolean" ? { booleanValue: x } : typeof x === "number" ? { integerValue: String(x) } : { stringValue: String(x) });

function criaFS(env) {
  const sa = JSON.parse(env.FIREBASE_SA);
  const base = `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents`;
  const PROIBIDAS = ["inventarioAcessos", "usuarios", "autorizacoes"];
  const cab = async () => ({ authorization: "Bearer " + (await tokenGoogle(sa)), "content-type": "application/json" });
  const guarda = (col) => {
    if (PROIBIDAS.includes(col)) throw new Error("coleção não permitida neste conector");
  };
  return {
    async get(col, id) {
      guarda(col);
      const r = await fetch(`${base}/${col}/${encodeURIComponent(id)}`, { headers: await cab() });
      if (r.status === 404) return null;
      const j = await r.json();
      if (j.error) throw new Error(j.error.message);
      return deCampos(j.fields);
    },
    // filtros: { campo: valor } (todos com ==)
    async lista(col, filtros = {}) {
      guarda(col);
      const w = Object.entries(filtros).map(([k, v]) => ({ fieldFilter: { field: { fieldPath: k }, op: "EQUAL", value: paraValor(v) } }));
      const sq = { from: [{ collectionId: col }] };
      if (w.length === 1) sq.where = w[0];
      else if (w.length > 1) sq.where = { compositeFilter: { op: "AND", filters: w } };
      const r = await fetch(`${base}:runQuery`, { method: "POST", headers: await cab(), body: JSON.stringify({ structuredQuery: sq }) });
      const j = await r.json();
      if (!Array.isArray(j)) throw new Error((j.error && j.error.message) || "erro na consulta");
      if (j[0] && j[0].error) throw new Error(j[0].error.message);
      return j.filter((x) => x.document).map((x) => deCampos(x.document.fields));
    },
  };
}

/* ---------------- dados do sistema ---------------- */
async function clientes(fs) {
  const [cl, metas] = await Promise.all([fs.lista("clientes"), fs.lista("inventarioMeta")]);
  const m = Object.fromEntries(metas.map((x) => [x.clienteId || x.id, x]));
  return cl.map((c) => ({ id: c.id, nome: c.unidade || c.nome || c.id, mp: c.mp || "", equipeId: c.equipeId || "", meta: m[c.id] || null }));
}

// acha o cliente pelo nome falado ("ecolab", "thera", "union")
async function achaCliente(fs, nome) {
  const L = await clientes(fs);
  const alvo = norm(nome);
  if (!alvo) throw new Error("Diga o nome do cliente.");
  const pal = alvo.split(" ").filter((w) => w.length > 1);
  const pont = L.map((c) => {
    const n = norm(c.nome + " " + c.mp);
    let p = n === alvo ? 100 : n.includes(alvo) ? 80 : 0;
    p += pal.filter((w) => n.includes(w)).length * 10;
    return [p, c];
  })
    .filter(([p]) => p > 0)
    .sort((a, b) => b[0] - a[0]);
  if (!pont.length) throw new Error(`Não achei o cliente "${nome}". Clientes: ${L.map((c) => c.nome).join(", ")}.`);
  if (pont.length > 1 && pont[0][0] === pont[1][0]) throw new Error(`"${nome}" pode ser: ${pont.filter(([p]) => p === pont[0][0]).map(([, c]) => c.nome).join(", ")}. Qual deles?`);
  return pont[0][1];
}

async function inventario(fs, cli) {
  const docs = await fs.lista("inventario", { clienteId: cli.id });
  return docs.map((d) => ({ sistema: d.sistema, atualizadoEm: d.atualizadoEm || "", itens: d.itens || [] }));
}

function contaStatus(itens) {
  const st = {};
  itens.forEach((i) => (st[i.status || "SEM STATUS"] = (st[i.status || "SEM STATUS"] || 0) + 1));
  const ok = (st.ONLINE || 0) + (st.OPERANDO || 0),
    base = itens.length - (st.VAZIO || 0) - (st["SEM STATUS"] || 0);
  return { total: itens.length, porStatus: st, online: ok, falha: st.FALHA || 0, offline: st.OFFLINE || 0, disponibilidade_pct: pct(ok, base), base_disponibilidade: base };
}

const filtraSis = (docs, sistema) => (sistema ? docs.filter((d) => norm(d.sistema) === norm(sistema) || norm(d.sistema).startsWith(norm(sistema))) : docs);

async function pendAbertas(fs, cli) {
  const f = { clienteId: cli.id, aberta: true };
  // desconsideradas (dispositivo marcado VAZIO no inventário) não contam como abertas
  return (await fs.lista("pendencias", f)).filter((p) => !p.desconsiderada).sort((a, b) => String(a.criada || "").localeCompare(String(b.criada || "")));
}

/* ---------------- ferramentas ---------------- */
const FERRAMENTAS = [
  {
    name: "listar_clientes",
    description: "Lista os clientes do Diário Técnico com o resumo do inventário de cada um (total de dispositivos, disponibilidade, offline, falha, pendências). Use para comparar clientes ou quando não souber o nome exato.",
    inputSchema: { type: "object", properties: {} },
    async run(fs) {
      const L = await clientes(fs);
      return L.map((c) => {
        const r = c.meta && c.meta.resumo;
        if (!r) return { cliente: c.nome, mp: c.mp, inventario: "sem inventário" };
        const st = r.status || {};
        const ok = (st.ONLINE || 0) + (st.OPERANDO || 0),
          base = (r.total || 0) - (st.VAZIO || 0) - (st["-"] || 0);
        return { cliente: c.nome, mp: c.mp, dispositivos: r.total, sistemas: r.sistemas, online: ok, falha: st.FALHA || 0, offline: st.OFFLINE || 0, disponibilidade_pct: pct(ok, base), senhas_a_confirmar: r.senhasPend, atualizado_em: c.meta.atualizadoEm || "" };
      });
    },
  },
  {
    name: "resumo_cliente",
    description: "Resumo do inventário de um cliente: quantidade de dispositivos, quantos online, em falha e offline, porcentagem de disponibilidade, por sistema (CFTV, SCA, SAI, SDAI, AUTOMAÇÃO, SONORIZAÇÃO) e quantas pendências abertas no diário.",
    inputSchema: { type: "object", properties: { cliente: { type: "string", description: "Nome do cliente, como falado (ex.: Ecolab, Thera, Union)" }, sistema: { type: "string", description: "Opcional: só um sistema (ex.: CFTV)" } }, required: ["cliente"] },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      const docs = filtraSis(await inventario(fs, cli), a.sistema);
      if (!docs.length) return { cliente: cli.nome, inventario: a.sistema ? `sem o sistema ${a.sistema}` : "sem inventário" };
      const todos = docs.flatMap((d) => d.itens);
      const pend = await pendAbertas(fs, cli);
      return {
        cliente: cli.nome,
        geral: contaStatus(todos),
        por_sistema: Object.fromEntries(docs.map((d) => [d.sistema, contaStatus(d.itens)])),
        pendencias_abertas: pend.length,
        pendencias_abertas_ha_mais_de_30_dias: pend.filter((p) => dias(p.criada) > 30).length,
        atualizado_em: docs.map((d) => d.atualizadoEm).sort().pop(),
        observacao: "Disponibilidade = (ONLINE + OPERANDO) ÷ dispositivos com status (sem contar VAZIO e sem status).",
      };
    },
  },
  {
    name: "dispositivos_por_status",
    description: "Lista os dispositivos de um cliente com um status (OFFLINE, FALHA, ONLINE, OPERANDO, VAZIO). Padrão: OFFLINE. Traz ID, TAG, IP, pavimento, sistema, NVR/canal e o quadro de distribuição de onde vem a rede.",
    inputSchema: {
      type: "object",
      properties: { cliente: { type: "string" }, status: { type: "string", description: "OFFLINE (padrão), FALHA, ONLINE, OPERANDO, VAZIO ou SEM_REDE (offline + falha)" }, sistema: { type: "string" }, limite: { type: "integer", description: "Máximo de dispositivos na lista (padrão 100)" } },
      required: ["cliente"],
    },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      const st = norm(a.status || "OFFLINE").replace(/ /g, "_");
      const quer = st === "SEM_REDE" ? SEM_REDE : st === "SEM_STATUS" ? [""] : [st];
      const docs = filtraSis(await inventario(fs, cli), a.sistema);
      const L = docs.flatMap((d) => d.itens.filter((i) => quer.includes(i.status || "")).map((i) => ({ id: i.id, tag: i.tag, ip: i.ip, pavimento: i.pav, sistema: d.sistema, tipo: i.tipo, status: i.status, nvr: i.nvr, canal: i.canal, quadro: i.quadro || "não informado", observacao: i.obs || undefined })));
      const lim = Math.min(Math.max(+a.limite || 100, 1), 500);
      const porQuadro = {};
      L.forEach((x) => (porQuadro[x.quadro] = (porQuadro[x.quadro] || 0) + 1));
      return { cliente: cli.nome, status: quer.join("/") || "sem status", quantidade: L.length, por_quadro: porQuadro, dispositivos: L.slice(0, lim), cortado: L.length > lim ? `mostrando ${lim} de ${L.length}` : undefined };
    },
  },
  {
    name: "pendencias_abertas",
    description: "Pendências em aberto no diário de um cliente: título, dispositivo, problema, há quantos dias está aberta, quem abriu e o status escrito pelo técnico.",
    inputSchema: { type: "object", properties: { cliente: { type: "string" }, dias_minimo: { type: "integer", description: "Opcional: só as abertas há pelo menos N dias" }, causa: { type: "string", description: "Opcional: só uma causa (ex.: fibra, alimentação, defeito)" }, limite: { type: "integer" } }, required: ["cliente"] },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      let L = (await pendAbertas(fs, cli)).map((p) => ({ causa: nomeCausa(p.causa), problema: p.problemaNome || "", titulo: p.titulo || "(sem título)", sistema: p.sis || p.dispSis || "", dispositivo: p.dispTag || p.dispId || "", situacao_do_dispositivo: p.dispStatus || "", problema: p.problema || "", status_no_diario: p.status || "", aberta_em: p.criada, dias_aberta: dias(p.criada), aberta_por: p.criadaPorNome || "", ja_tem_acoes: (p.acoes || []).length > 0 || !!p.diag }));
      if (a.dias_minimo) L = L.filter((p) => p.dias_aberta >= a.dias_minimo);
      if (a.causa) L = L.filter((p) => norm(p.causa).includes(norm(a.causa)));
      const porCausa = {};
      L.forEach((p) => (porCausa[p.causa] = (porCausa[p.causa] || 0) + 1));
      const lim = Math.min(Math.max(+a.limite || 60, 1), 300);
      return { cliente: cli.nome, quantidade: L.length, por_causa: porCausa, sem_nada_preenchido: L.filter((p) => !p.ja_tem_acoes).length, pendencias: L.slice(0, lim), cortado: L.length > lim ? `mostrando ${lim} de ${L.length}` : undefined };
    },
  },
  {
    name: "quadros_de_distribuicao",
    description: "Situação dos quadros de distribuição / switches PoE de um cliente: status de cada um, observação (ex.: fibra rompida), quantos dispositivos estão ligados e quantos estão sem rede.",
    inputSchema: { type: "object", properties: { cliente: { type: "string" } }, required: ["cliente"] },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      const docs = await inventario(fs, cli);
      const todos = docs.flatMap((d) => d.itens.map((i) => ({ ...i, sistema: d.sistema })));
      const Q = todos.filter(ehQuadro).map((q) => {
        const lig = todos.filter((i) => i.quadro && norm(i.quadro) === norm(q.tag) && i.id !== q.id);
        return { quadro: q.tag, id: q.id, tipo: q.tipo, status: q.status || "sem status", observacao: q.obs || "", recebe_rede_de: q.quadro || "", dispositivos_ligados: lig.length, sem_rede: lig.filter((i) => SEM_REDE.includes(i.status)).map((i) => i.tag || i.id) };
      });
      const semQuadro = todos.filter((i) => !ehQuadro(i) && !i.quadro);
      return { cliente: cli.nome, quadros: Q, sem_rede: Q.filter((q) => SEM_REDE.includes(q.status)).map((q) => q.quadro), dispositivos_sem_quadro_informado: semQuadro.length, offline_sem_quadro_informado: semQuadro.filter((i) => i.status === "OFFLINE").length };
    },
  },
  {
    name: "problemas",
    description: "Problemas (causas reais) registrados de um cliente, como 'Fibra 01 – ETE rompida': causa, situação (aberto, em andamento, resolvido), onde, há quantos dias e quantas pendências/dispositivos estão ligados. Use para 'por que as câmeras estão fora', 'quantas caíram por fibra'.",
    inputSchema: { type: "object", properties: { cliente: { type: "string" }, incluir_resolvidos: { type: "boolean" } }, required: ["cliente"] },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      const meta = await fs.get("inventarioMeta", cli.id);
      const P = ((meta && meta.problemas) || []).filter((x) => !x.excluido && (a.incluir_resolvidos || x.status !== "resolvido"));
      const pend = await pendAbertas(fs, cli);
      const docs = await inventario(fs, cli);
      const todos = docs.flatMap((d) => d.itens);
      return {
        cliente: cli.nome,
        problemas: P.map((x) => {
          const ps = pend.filter((p) => p.problemaId === x.id);
          const loc = todos.find((i) => i.id === x.localId);
          const lig = loc && ehQuadro(loc) ? todos.filter((i) => i.quadro && norm(i.quadro) === norm(loc.tag) && ["OFFLINE", "FALHA"].includes(i.status)).length : 0;
          return { problema: x.nome, causa: nomeCausa(x.causa), situacao: x.status, onde: x.localTag || "", aberto_em: x.criadoEm, dias: dias(x.criadoEm), resolvido_em: x.resolvidoEm || undefined, pendencias_abertas: ps.length, dispositivos: ps.map((p) => p.dispTag || p.titulo), dispositivos_sem_rede_no_quadro: lig || undefined, observacao: x.obs || undefined };
        }),
        pendencias_abertas_por_causa: pend.reduce((o, p) => ((o[nomeCausa(p.causa)] = (o[nomeCausa(p.causa)] || 0) + 1), o), {}),
      };
    },
  },
  {
    name: "capacidade",
    description: "Capacidade dos equipamentos de um cliente (NVRs/DVRs em canais, switches/quadros em portas, centrais em endereços ou zonas, controladoras em saídas): capacidade, quanto está em uso, quanto está livre e a ocupação em %. Use para perguntas como 'quantos canais livres tem nos NVRs' ou 'algum equipamento está lotado'.",
    inputSchema: { type: "object", properties: { cliente: { type: "string" }, sistema: { type: "string" } }, required: ["cliente"] },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      const docs = filtraSis(await inventario(fs, cli), a.sistema);
      const todos = docs.flatMap((d) => d.itens.map((i) => ({ ...i, sistema: d.sistema })));
      const nvrKey = (x) => {
        const m = norm(x).match(/^(?:NVR|DVR)? ?0*(\d+)$/);
        return m ? "N" + m[1] : norm(x);
      };
      const ehNvr = (i) => /\b(NVR|DVR)\b/.test(norm(i.tipo)) || /^(NVR|DVR)\b/.test(norm(i.tag));
      const ehCentral = (i) => /CENTRAL|PAINEL|REPETIDORA/.test(norm(i.tipo));
      const uso = (i) => {
        // "em uso" digitado no inventário vale mais que a contagem
        if (i.emUso !== undefined && i.emUso !== null && i.emUso !== "") return { n: +i.emUso || 0, auto: false };
        const L = todos.filter((x) => x.sistema === i.sistema && x.id !== i.id && x.status !== "VAZIO");
        if (ehNvr(i)) {
          const n = L.filter((x) => x.nvr && !ehNvr(x) && nvrKey(x.nvr) === nvrKey(i.tag)).length;
          return n ? { n, auto: true } : null;
        }
        if (ehQuadro(i)) {
          const n = todos.filter((x) => x.quadro && norm(x.quadro) === norm(i.tag) && x.id !== i.id && x.status !== "VAZIO").length;
          return n ? { n, auto: true } : null;
        }
        if (norm(i.sistema) === "SDAI" && ehCentral(i) && !/REPETIDORA/.test(norm(i.tipo)) && !L.some((x) => ehCentral(x) && !/REPETIDORA/.test(norm(x.tipo)))) {
          const n = L.filter((x) => !ehCentral(x)).length;
          return n ? { n, auto: true } : null;
        }
        return null;
      };
      const L = todos
        .map((i) => {
          const cap = +i.capacidade || 0,
            u = uso(i);
          if (!cap && !u) return null;
          const unid = i.capUnid || (ehNvr(i) ? "canais" : ehQuadro(i) ? "portas" : ehCentral(i) ? (norm(i.sistema) === "SDAI" ? "enderecos" : "zonas") : "");
          return { equipamento: i.tag || i.id, id: i.id, sistema: i.sistema, tipo: i.tipo, capacidade: cap || "não informada", unidade: unid, em_uso: u ? u.n : "não informado", uso_contado_pelo_sistema: !!(u && u.auto), livres: cap && u ? cap - u.n : null, ocupacao_pct: cap && u ? Math.round((u.n / cap) * 100) : null };
        })
        .filter(Boolean);
      const nv = L.filter((x) => x.unidade === "canais" && typeof x.capacidade === "number" && x.livres !== null);
      return { cliente: cli.nome, equipamentos: L, capacidade_maxima_atingida: L.filter((x) => x.livres === 0).map((x) => x.equipamento), acima_da_capacidade: L.filter((x) => x.livres < 0).map((x) => x.equipamento), acima_de_90_pct: L.filter((x) => x.ocupacao_pct >= 90).map((x) => x.equipamento), canais_de_nvr: nv.length ? { capacidade: nv.reduce((a, x) => a + x.capacidade, 0), em_uso: nv.reduce((a, x) => a + x.em_uso, 0), livres: nv.reduce((a, x) => a + x.livres, 0) } : undefined };
    },
  },
  {
    name: "buscar_dispositivo",
    description: "Procura dispositivos de um cliente por TAG, IP, ID ou parte do nome (ex.: 'portaria', '192.168.1.159', 'CFTV-0012') e diz a situação de cada um.",
    inputSchema: { type: "object", properties: { cliente: { type: "string" }, busca: { type: "string" } }, required: ["cliente", "busca"] },
    async run(fs, a) {
      const cli = await achaCliente(fs, a.cliente);
      const b = norm(a.busca);
      const docs = await inventario(fs, cli);
      const L = docs.flatMap((d) => d.itens.filter((i) => norm([i.id, i.tag, i.ip, i.tipo, i.pav, i.quadro, i.nvr].join(" ")).includes(b)).map((i) => ({ id: i.id, tag: i.tag, ip: i.ip, sistema: d.sistema, tipo: i.tipo, pavimento: i.pav, status: i.status || "sem status", quadro: i.quadro || "", nvr: i.nvr, canal: i.canal, observacao: i.obs || "", senha_confirmada_em: i.verificado ? new Date(i.verificado).toISOString().slice(0, 10) : "" })));
      return { cliente: cli.nome, encontrados: L.length, dispositivos: L.slice(0, 50) };
    },
  },
];

/* ---------------- MCP (JSON-RPC sobre HTTP) ---------------- */
const resp = (id, result) => ({ jsonrpc: "2.0", id, result });
const erro = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });

async function trata(msg, env) {
  const { id, method, params = {} } = msg;
  if (id === undefined || id === null) return null; // notificação: não responde
  if (method === "initialize")
    return resp(id, {
      protocolVersion: params.protocolVersion || PROTOCOLO,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "diario-tecnico", title: "Diário Técnico (Controller BMS)", version: VERSAO },
      instructions:
        "Consulta (somente leitura) o inventário de dispositivos e as pendências do Diário Técnico da Controller BMS. Responda em português do Brasil, curto e direto, pensando que a pessoa pode estar ouvindo por voz: números primeiro, sem tabelas longas. Nunca invente números: use as ferramentas.",
    });
  if (method === "ping") return resp(id, {});
  if (method === "tools/list") return resp(id, { tools: FERRAMENTAS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema, annotations: { readOnlyHint: true, openWorldHint: false } })) });
  if (method === "tools/call") {
    const f = FERRAMENTAS.find((x) => x.name === params.name);
    if (!f) return erro(id, -32602, "Ferramenta desconhecida: " + params.name);
    try {
      const r = await f.run(criaFS(env), params.arguments || {});
      return resp(id, { content: [{ type: "text", text: JSON.stringify(r) }], structuredContent: Array.isArray(r) ? { itens: r } : r });
    } catch (e) {
      return resp(id, { content: [{ type: "text", text: "Erro: " + (e.message || e) }], isError: true });
    }
  }
  return erro(id, -32601, "Método não suportado: " + method);
}

// compara sem vazar o tempo (o token fica no endereço)
const igual = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const m = url.pathname.match(/^\/mcp\/([^/]+)\/?$/);
    if (url.pathname === "/" || url.pathname === "") return new Response("Conector do Diário Técnico no ar.", { headers: { "content-type": "text/plain; charset=utf-8" } });
    if (!m || !igual(m[1], env.ACESSO_TOKEN || "")) return new Response("Não autorizado", { status: 401 });
    if (!env.FIREBASE_SA) return new Response("Falta o segredo FIREBASE_SA", { status: 500 });
    if (req.method === "GET") return new Response("Use POST (MCP Streamable HTTP).", { status: 405, headers: { allow: "POST" } });
    if (req.method === "DELETE") return new Response(null, { status: 204 });
    if (req.method !== "POST") return new Response("Método não permitido", { status: 405 });
    let corpo;
    try {
      corpo = await req.json();
    } catch {
      return Response.json(erro(null, -32700, "JSON inválido"), { status: 400 });
    }
    const lote = Array.isArray(corpo);
    const saidas = (await Promise.all((lote ? corpo : [corpo]).map((x) => trata(x, env)))).filter(Boolean);
    if (!saidas.length) return new Response(null, { status: 202 });
    return Response.json(lote ? saidas : saidas[0], { headers: { "mcp-protocol-version": PROTOCOLO } });
  },
};

// para os testes locais
export { trata, deValor, achaCliente, FERRAMENTAS, contaStatus };
