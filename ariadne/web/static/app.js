const $ = (id) => document.getElementById(id);
let view = "trace";
let network = null;
let liveTimer = null;

const NODE_COLORS = { seed: "#e63946", service: "#f4a261", address: "#6cc4c9" };
const CAT_COLORS = {
  sanctioned: "#9d0208", ransomware: "#d00000", darknet: "#6a040f",
  scam: "#dc2f02", mixer: "#e85d04", bridge: "#b5179e", dex: "#7209b7", exchange: "#f48c06",
};
const VIEWS = {
  trace: { title: "Trace the money", sub: "Follow value from a seed address to its cash-out points.", run: "Trace" },
  cluster: { title: "Entity cluster", sub: "Find every wallet controlled by the same actor.", run: "Cluster" },
  live: { title: "Live monitor", sub: "Score every transaction as it lands and auto-flag the suspicious.", run: "Scan now" },
};

// ---------- navigation ----------
document.querySelectorAll(".nav-item").forEach((n) => (n.onclick = () => setView(n.dataset.view)));
function setView(v) {
  view = v;
  document.querySelectorAll(".nav-item").forEach((x) => x.classList.toggle("active", x.dataset.view === v));
  $("view-title").textContent = VIEWS[v].title;
  $("view-sub").textContent = VIEWS[v].sub;
  $("run").textContent = VIEWS[v].run;
  $("depth-field").classList.toggle("hidden", v !== "trace");
  $("source-field").classList.toggle("hidden", v !== "live");
  $("live-toggle").classList.toggle("hidden", v !== "live");
  $("addr-field").classList.toggle("hidden", v === "live");
  stopLive();
  hideAll();
}

function hideAll() {
  ["trace-result", "cluster-result", "live-result", "error"].forEach((id) => $(id).classList.add("hidden"));
}

function investigateFromAlert(address) {
  if (!address) return;
  $("address").value = address;
  setView("trace");
  runTrace();
}
function loading(on, text) { $("loader-text").textContent = text || "Working…"; $("loader").classList.toggle("hidden", !on); }
function showError(msg) { $("error").textContent = "Error: " + msg; $("error").classList.remove("hidden"); }

async function api(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

// ---------- run / live buttons ----------
$("run").onclick = () => (view === "trace" ? runTrace() : view === "cluster" ? runCluster() : scanLive(true));
$("live-toggle").onclick = () => (liveTimer ? stopLive() : startLive());
function startLive() { $("live-toggle").textContent = "Stop"; $("live-toggle").classList.add("on"); scanLive(true).then(() => { liveTimer = setInterval(() => scanLive(false), 20000); }); }
function stopLive() { if (liveTimer) { clearInterval(liveTimer); liveTimer = null; } $("live-toggle").textContent = "Go live"; $("live-toggle").classList.remove("on"); $("live-status").innerHTML = ""; }

// ---------- case workspace ----------
async function loadCases() {
  try {
    const cases = await fetch('/api/cases', { headers: { 'Content-Type': 'application/json' } }).then((r) => r.json());
    const select = $('case-select');
    const current = select.value;
    select.innerHTML = cases.map((c) => `<option value="${esc(c.case_id)}">${esc(c.case_id)} · ${esc(c.title)}</option>`).join('');
    if (current && cases.some((c) => c.case_id === current)) select.value = current;
    if (!select.value && cases[0]) select.value = cases[0].case_id;
    renderCases(cases);
  } catch (e) {
    $('case-table').innerHTML = `<tr><td colspan="2" class="muted">${esc(e.message)}</td></tr>`;
  }
}

function renderCases(cases) {
  const selected = $('case-select').value;
  const caseData = cases.find((c) => c.case_id === selected) || cases[0];
  if (!caseData) {
    $('case-table').innerHTML = '<tr><td colspan="2" class="muted">No cases yet.</td></tr>';
    $('case-timeline').innerHTML = '<tr><td colspan="2" class="muted">No activity yet.</td></tr>';
    return;
  }
  const summary = `${esc(caseData.title || 'Untitled case')} — ${esc((caseData.notes || []).slice(-1)[0] || 'No analyst notes yet')} (${(caseData.evidence || []).length} evidence item(s), ${(caseData.tags || []).length} tag(s))`;
  $('case-summary').textContent = summary;

  const rows = [
    `<tr><th>Field</th><th>Value</th></tr>`,
    `<tr><td>Title</td><td>${esc(caseData.title || 'Untitled case')}</td></tr>`,
    `<tr><td>Investigator</td><td>${esc(caseData.investigator || 'operator')}</td></tr>`,
    `<tr><td>Notes</td><td>${esc((caseData.notes || []).join(' · ') || 'No notes yet')}</td></tr>`,
    `<tr><td>Evidence</td><td>${esc((caseData.evidence || []).map((e) => JSON.stringify(e)).join(' | ') || 'No evidence yet')}</td></tr>`,
    `<tr><td>Tags</td><td>${esc((caseData.tags || []).join(', ') || 'No tags')}</td></tr>`,
  ].join('');
  $('case-table').innerHTML = rows;

  const timelineRows = [
    `<tr><th>Time</th><th>Event</th></tr>`,
    ...((caseData.timeline || []).slice(-8).map((entry) => `<tr><td>${esc(entry.timestamp || '')}</td><td>${esc(entry.type || '')}: ${esc(typeof entry.detail === 'string' ? entry.detail : JSON.stringify(entry.detail))}</td></tr>`)),
  ].join('');
  $('case-timeline').innerHTML = timelineRows || '<tr><td colspan="2" class="muted">No activity yet.</td></tr>';
}

$('create-case').onclick = async () => {
  const payload = { case_id: $('case-id').value.trim() || `case-${Date.now()}`, title: $('case-title').value.trim() || 'Untitled case', note: 'Case created from dashboard' };
  const res = await fetch('/api/cases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Unable to create case');
  await loadCases();
  $('case-select').value = data.case_id;
  renderCases([data]);
};

$('save-case-note').onclick = async () => {
  const caseId = $('case-select').value;
  const note = $('case-note').value.trim();
  if (!caseId || !note) return;
  const res = await fetch(`/api/cases/${caseId}/update`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ note }) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Unable to save note');
  $('case-note').value = '';
  await loadCases();
  $('case-select').value = data.case_id;
  renderCases([data]);
};

$('save-case-evidence').onclick = async () => {
  const caseId = $('case-select').value;
  if (!caseId) return;
  const res = await fetch(`/api/cases/${caseId}/update`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ evidence: { type: 'manual', detail: 'Added from dashboard' } }) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Unable to save evidence');
  await loadCases();
  $('case-select').value = data.case_id;
  renderCases([data]);
};

$('export-case').onclick = async () => {
  const caseId = $('case-select').value;
  if (!caseId) return;
  const res = await fetch(`/api/cases/${caseId}/export`, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Unable to export case');
  const path = data.path || 'n/a';
  const link = `<a href="${esc(path)}" target="_blank" rel="noopener">Download bundle</a>`;
  $('case-table').innerHTML = `<tr><th>Export</th><th>Value</th></tr><tr><td>Bundle path</td><td>${esc(path)}</td></tr><tr><td>Signature</td><td class="mono">${esc(data.signature || 'n/a')}</td></tr><tr><td>Download</td><td>${link}</td></tr>`;
};

$('case-select').onchange = () => loadCases();

window.addEventListener('DOMContentLoaded', loadCases);
$("live-table").addEventListener("click", (e) => {
  const btn = e.target.closest(".investigate-btn");
  if (btn?.dataset.address) investigateFromAlert(btn.dataset.address);
});

// ================= TRACE =================
async function runTrace() {
  hideAll(); loading(true, "Following the thread…");
  try {
    const rep = await api("/api/trace", { address: $("address").value.trim(), chain: $("chain").value, depth: parseInt($("depth").value) });
    const pk = rep.prior_knowledge;
    const pkNote = pk && pk.known
      ? `Ariadne recognises this address — seen in ${pk.entity.times_seen} prior investigation(s), best grade ${(pk.entity.best_confidence || "info").toUpperCase()}. `
      : "";
    $("summary").textContent = " " + pkNote + rep.summary_text;
    const brief = rep.brief || {};
    $("brief-risk").innerHTML = `<div class="brief-pill ${brief.risk_level || "low"}">${esc(brief.risk_level || "low").toUpperCase()}</div><div class="brief-score">Risk score ${brief.risk_score || 0}/100</div><div class="brief-note">${esc(brief.summary || "Investigation summary unavailable.")}</div>`;
    const findings = (brief.priority_findings || []).map((f) => `<div class="brief-item"><div class="brief-item-title">${esc(f.address)}</div><div class="brief-item-meta">${esc(f.confidence || "info")} · ${esc(f.category || "unclassified")}</div></div>`).join("");
    $("brief-findings").innerHTML = findings || '<div class="brief-note">No priority findings surfaced yet.</div>';
    $("brief-actions").innerHTML = (brief.recommended_next_steps || []).map((step) => `<div class="brief-item"><div class="brief-item-title">${esc(step)}</div></div>`).join("");
    $("stats").innerHTML = [stat(rep.summary.addresses, "Addresses"), stat(rep.summary.flows, "Flows"), stat(rep.summary.findings, "Findings", rep.summary.findings > 0)].join("");
    const rows = rep.findings.map((f) => {
      const c = f.confidence;
      const links = (f.linked_activity || []).map((item) => `<div class="disp">• ${esc(item)}</div>`).join("");
      return `<tr>
        <td class="mono">${shorten(f.address)}</td>
        <td>${esc(f.label || f.type)}${f.category ? ` <span class="cat">(${f.category})</span>` : ""}<div class="disp">${esc(c.disposition)}</div>${links}</td>
        <td><span class="badge ${c.level}">${c.level}</span></td>
        <td>${f.dirty_received} ${rep.asset}</td></tr>`;
    }).join("");
    $("side-title").textContent = `Findings (${rep.findings.length}) — graded by illicit confidence`;
    $("side-table").innerHTML = `<tr><th>Address</th><th>Assessment</th><th>Confidence</th><th>Dirty</th></tr>` +
      (rows || `<tr><td colspan="4" class="muted">No flagged addresses.</td></tr>`);
    renderGraph(rep);
    $("trace-result").classList.remove("hidden");
  } catch (e) { showError(e.message); } finally { loading(false); }
}

function renderGraph(rep) {
  const nodes = rep.nodes.map((n) => ({
    id: n.address, label: n.label || shorten(n.address),
    title: `${n.address}\n${n.type}${n.category ? " · " + n.category : ""}\nactivity ${n.activity}`,
    color: CAT_COLORS[n.category] || NODE_COLORS[n.type] || "#6cc4c9",
    shape: n.type === "seed" ? "star" : n.type === "service" ? "square" : "dot",
    value: Math.max(1, n.dirty_received),
  }));
  const edges = rep.edges.map((e) => ({ from: e.src, to: e.dst, label: String(e.amount), arrows: "to" }));
  network = new vis.Network($("graph"), { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) }, {
    physics: { stabilization: true, barnesHut: { gravitationalConstant: -14000, springLength: 150 } },
    nodes: { font: { color: "#e7eaf0", size: 12 } },
    edges: { font: { color: "#868fa1", size: 10, strokeWidth: 0 }, color: { color: "#3a4152" } },
  });
}

// ================= CLUSTER =================
async function runCluster() {
  hideAll(); loading(true, "Unwinding the entity’s wallets…");
  try {
    const c = await api("/api/cluster", { address: $("address").value.trim(), chain: $("chain").value });
    $("cluster-summary").textContent = ` This actor controls ${c.wallet_count} wallet(s), linked by ${c.cospend_links.length} co-spend transaction(s). ${Object.keys(c.services_touched).length} service(s) touched — likely cash-out leads.`;
    const rows = c.entity_wallets.map((a) => {
      const lab = c.labels[a], svc = c.services_touched[a];
      return `<tr><td class="mono">${esc(a)}</td><td>${lab ? `<span class="cat">${esc(lab.category)}: ${esc(lab.name)}</span>` : svc ? `<span class="muted">${esc(svc)}</span>` : ""}</td></tr>`;
    }).join("");
    $("cluster-table").innerHTML = `<tr><th>Wallet</th><th>Note</th></tr>` + rows;
    $("cluster-result").classList.remove("hidden");
  } catch (e) { showError(e.message); } finally { loading(false); }
}

// ================= LIVE =================
async function scanLive(showLoader) {
  if (showLoader) { hideAll(); loading(true, "Scanning the chain…"); }
  $("live-status").innerHTML = liveTimer ? `<span class="live-dot"></span>LIVE · refreshing every 20s` : "";
  try {
    const mempool = $("source").value === "mempool";
    const m = await api("/api/monitor", { chain: $("chain").value, mempool });
    const where = mempool ? "mempool (unconfirmed)" : "block " + m.height;
    $("live-head").textContent = `${m.chain} · ${where} — ${m.flagged} flagged of ${m.count} scanned`;
    const rows = m.transactions.filter((t) => t.score > 0).map((t) => {
      const action = t.address
        ? `<button class="investigate-btn" type="button" data-address="${attrEsc(t.address)}" title="Trace from ${attrEsc(t.address)}">Investigate</button>`
        : `<span class="muted">—</span>`;
      return `<tr>
        <td class="mono">${shorten(t.txid)}</td>
        <td class="mono">${t.address ? shorten(t.address) : '<span class="muted">—</span>'}</td>
        <td>${t.score}</td>
        <td><span class="badge ${t.level}">${t.level}</span></td>
        <td class="muted">${esc(t.reasons.slice(0, 3).join("; ") || "—")}</td>
        <td>${action}</td></tr>`;
    }).join("");
    $("live-table").innerHTML = `<tr><th>Txid</th><th>Address</th><th>Score</th><th>Severity</th><th>Reasons</th><th></th></tr>` +
      (rows || `<tr><td colspan="6" class="muted">Nothing scored above zero in this sample.</td></tr>`);
    $("live-result").classList.remove("hidden");
  } catch (e) { showError(e.message); stopLive(); } finally { if (showLoader) loading(false); }
}

// ---------- helpers ----------
function stat(n, label, alert) { return `<div class="stat ${alert ? "alert" : ""}"><div class="n">${n}</div><div class="l">${label}</div></div>`; }
function shorten(a) { return a && a.length > 20 ? `${a.slice(0, 10)}…${a.slice(-6)}` : a; }
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
function attrEsc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;"); }
