const $ = (id) => document.getElementById(id);
let view = "trace";
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
  oversight: { title: "Lawful accountability", sub: "Authorizations, the tamper-evident audit chain, and the oversight record.", run: "Refresh" },
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
  $("taint-field").classList.toggle("hidden", v !== "trace");
  $("source-field").classList.toggle("hidden", v !== "live");
  $("live-toggle").classList.toggle("hidden", v !== "live");
  $("addr-field").classList.toggle("hidden", v === "live" || v === "oversight");
  stopLive();
  hideAll();
  if (v === "oversight") runOversight();
}

function hideAll() {
  ["trace-result", "cluster-result", "live-result", "oversight-result", "error"].forEach((id) => $(id).classList.add("hidden"));
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
$("run").onclick = () =>
  view === "trace" ? runTrace()
  : view === "cluster" ? runCluster()
  : view === "oversight" ? runOversight()
  : scanLive(true);
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
    const rep = await api("/api/trace", { address: $("address").value.trim(), chain: $("chain").value, depth: parseInt($("depth").value), taint_model: $("taint").value });
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
    renderIntel(rep);
    renderPoison(rep);
    renderFiat(rep);
    renderXrefs(rep);
    renderAtm(rep);
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

const RISK_PILL = { critical: "critical", high: "high", elevated: "medium", low: "low", minimal: "info" };
const SCREEN_PILL = { sanctioned_entity: "critical", direct_exposure: "critical", indirect_exposure: "high", high_risk_exposure: "medium", clear: "info" };

function renderIntel(rep) {
  const risk = rep.risk || {};
  const typ = (risk.typologies || []).slice(0, 4)
    .map((t) => `<div class="brief-item"><div class="brief-item-title">${esc(t.name)}</div><div class="brief-item-meta">severity ${t.severity}</div></div>`).join("");
  $("intel-risk").innerHTML =
    `<div class="brief-pill ${RISK_PILL[risk.level] || "info"}">${esc((risk.level || "minimal").toUpperCase())}</div>` +
    `<div class="brief-score">${risk.score || 0}/100 · ${esc(risk.primary_typology || "no typology identified")}</div>` +
    (typ || '<div class="brief-note">No laundering typology matched.</div>');

  const scr = rep.screening || {};
  const reasons = (scr.reasons || []).map((r) => `<div class="brief-note">${esc(r)}</div>`).join("");
  const hops = scr.nearest_hops != null
    ? `<div class="brief-item-meta">nearest illicit touchpoint: ${scr.nearest_hops} hop(s); exposed ${scr.exposed_value} ${esc(rep.asset)}</div>` : "";
  $("intel-screen").innerHTML =
    `<div class="brief-pill ${SCREEN_PILL[scr.verdict] || "info"}">${esc((scr.verdict || "clear").replace(/_/g, " ").toUpperCase())}</div>` + reasons + hops;

  const tp = rep.temporal || {};
  if (tp.events) {
    const off = tp.likely_utc_offset;
    const tz = off != null ? `UTC${off >= 0 ? "+" : ""}${off} — ${esc(tp.region_hint || "")}` : "indeterminate";
    $("intel-temporal").innerHTML =
      `<div class="brief-note">${tp.events} timestamped movement(s)</div>` +
      `<div class="brief-item"><div class="brief-item-title">Likely timezone: ${tz}</div><div class="brief-item-meta">probabilistic lead — not proof</div></div>` +
      `<div class="brief-note">${(tp.burstiness || 0) > 1 ? "bursty" : "regular"} movement cadence</div>`;
  } else {
    $("intel-temporal").innerHTML = '<div class="brief-note">No timestamped movements to profile.</div>';
  }
}

function renderFiat(rep) {
  const v = rep.valuation || {};
  const panel = $("fiat-panel");
  const fmt = (usd, eur) => usd == null ? "n/a" : "$" + Math.round(usd).toLocaleString() + (eur != null ? " / €" + Math.round(eur).toLocaleString() : "");
  if (v.seed_disbursed_usd == null && v.total_cashout_usd == null) { panel.classList.add("hidden"); return; }
  $("fiat-body").innerHTML = ` Value disbursed by seed: <b>${fmt(v.seed_disbursed_usd, v.seed_disbursed_eur)}</b> · reaching cash-outs: <b>${fmt(v.total_cashout_usd, v.total_cashout_eur)}</b>. <span class="muted">${esc(v.note || "")}</span>`;
  panel.classList.remove("hidden");
}

function renderXrefs(rep) {
  const xr = rep.cross_references || [];
  const panel = $("xref-panel");
  if (!xr.length) { panel.classList.add("hidden"); return; }
  $("xref-body").innerHTML = " " + xr.slice(0, 10).map((x) => {
    const others = (x.links || []).slice(0, 3).map((l) => `#${l.investigation_id} (seed ${shorten(l.other_seed)})`).join(", ");
    return `<div class="disp"><b>${shorten(x.address)}</b> also seen in: ${esc(others)}</div>`;
  }).join("");
  panel.classList.remove("hidden");
}

function renderAtm(rep) {
  const intel = rep.atm_intel || [];
  const panel = $("atm-panel");
  if (!intel.length) { panel.classList.add("hidden"); return; }
  const blocks = intel.map((hit) => {
    const locs = (hit.candidate_locations || []).slice(0, 8).map((m) => {
      const where = [m.street, m.city, m.country].filter(Boolean).join(", ") || "location on file";
      return `<div class="disp">📍 ${esc(where)} — <span class="mono">${m.lat.toFixed(5)}, ${m.lon.toFixed(5)}</span> · <a href="${attrEsc(m.osm_url)}" target="_blank" rel="noopener">map</a></div>`;
    }).join("");
    return `<div style="margin-top:8px"><b>${esc(hit.operator)}</b> — ${hit.machine_count} known machine(s):${locs}<div class="disp muted">${esc(hit.note)}</div></div>`;
  }).join("");
  $("atm-body").innerHTML = " " + blocks;
  panel.classList.remove("hidden");
}

// Self-contained, dependency-free money-flow graph. A deterministic left-to-right
// layered layout (column = hop depth) — reproducible for evidence, and it never
// phones home to a CDN, so it works on an air-gapped / Tor-routed workstation.
function renderPoison(rep) {
  const warns = rep.lookalike_warnings || [];
  const panel = $("poison-panel");
  if (!warns.length) { panel.classList.add("hidden"); return; }
  $("poison-body").innerHTML = " " + warns.length + " confusable look-alike address pair(s) in this graph — a mistaken-send"
    + " poisoning setup. Verify the FULL address before acting:"
    + warns.slice(0, 6).map((w) =>
        `<div class="disp"><span class="mono">${esc(shorten(w.a))}</span> ≈ <span class="mono">${esc(shorten(w.b))}</span>`
        + ` <span class="muted">(matches ${w.matched_prefix}+${w.matched_suffix} chars)</span></div>`).join("");
  panel.classList.remove("hidden");
}

// ================= ACCOUNTABILITY / OVERSIGHT =================
async function runOversight() {
  hideAll(); loading(true, "Reading the oversight record…");
  try {
    const r = await fetch("/api/oversight").then((x) => x.json());
    if (r.error) throw new Error(r.error);
    const chain = r.audit_chain || {};
    const ok = chain.ok;
    $("chain-card").style.borderLeftColor = ok ? "var(--green)" : "var(--confirmed)";
    $("chain-body").innerHTML = ok
      ? ` <b style="color:#7ee0a8">Intact</b> — ${chain.length || 0} action(s) recorded, tamper-evident. `
        + `<span class="muted">Any silent edit or deletion of a past entry would break the chain.</span>`
      : ` <b style="color:#ff6b78">BROKEN at entry ${chain.broken_at}</b> (${esc(chain.reason || "")}) — `
        + `the audit record was tampered with and is not admissible.`;

    const a = r.authorizations || {}, ac = r.actions || {};
    $("oversight-stats").innerHTML = [
      stat(a.total || 0, "Authorizations"),
      stat(a.active || 0, "Active"),
      stat(ac.total || 0, "Actions logged"),
      stat(ac.unauthorized || 0, "Unauthorized", (ac.unauthorized || 0) > 0),
    ].join("");

    const auths = r.authorizations_list || [];
    $("auth-table").innerHTML = `<tr><th>ID</th><th>Case</th><th>Legal basis</th><th>Authority</th><th>Status</th></tr>`
      + (auths.map((x) => {
          const st = x.status === "revoked" ? '<span class="badge info">revoked</span>'
            : x.valid ? '<span class="badge low">active</span>' : '<span class="badge medium">expired</span>';
          return `<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.case_ref)}</td><td>${esc(x.legal_basis)}</td>`
            + `<td>${esc(x.authority)}${x.scoped ? "" : ' <span class="muted">(case-level)</span>'}</td><td>${st}</td></tr>`;
        }).join("") || `<tr><td colspan="5" class="muted">No authorizations registered. Create one with <span class="mono">ariadne authorize</span>.</td></tr>`);

    const flags = r.compliance_flags || [];
    $("flags-title").textContent = `Compliance flags (${flags.length})`;
    $("flags-table").innerHTML = `<tr><th>Seq</th><th>Actor</th><th>Action</th><th>Target</th></tr>`
      + (flags.map((f) => `<tr><td>${f.seq}</td><td>${esc(f.actor)}</td><td>${esc(f.action)}</td>`
          + `<td class="mono">${esc(shorten(f.target))}</td></tr>`).join("")
        || `<tr><td colspan="4" class="muted">No unauthorized actions — every logged action was covered by a valid authorization.</td></tr>`);

    $("oversight-result").classList.remove("hidden");
  } catch (e) { showError(e.message); } finally { loading(false); }
}

const GRAPH_CAP = 60;   // keep the SVG legible + fast on large traces

function renderGraph(rep) {
  const host = $("graph");
  let nodes = rep.nodes || [];
  const total = nodes.length;
  if (!total) { host.innerHTML = '<div class="graph-empty muted">No money-flow graph to display.</div>'; return; }

  // On a large trace, render the most significant nodes: the seed plus the top
  // by dirty value. Keep only edges between kept nodes. Deterministic + fast.
  let capNote = "";
  if (total > GRAPH_CAP) {
    const seed = nodes.filter((n) => n.type === "seed");
    const rest = nodes.filter((n) => n.type !== "seed")
      .sort((a, b) => (b.dirty_received || 0) - (a.dirty_received || 0)).slice(0, GRAPH_CAP - seed.length);
    nodes = seed.concat(rest);
    capNote = `<div class="graph-cap muted">Showing the ${nodes.length} most significant of ${total} nodes (by dirty value). Full graph in the report export.</div>`;
  }
  const keep = new Set(nodes.map((n) => n.address));
  const edges = (rep.edges || []).filter((e) => keep.has(e.src) && keep.has(e.dst));

  const byDepth = {}; let maxDepth = 0;
  nodes.forEach((n) => { const d = n.depth || 0; (byDepth[d] = byDepth[d] || []).push(n); if (d > maxDepth) maxDepth = d; });
  Object.values(byDepth).forEach((col) => col.sort((a, b) => (b.dirty_received || 0) - (a.dirty_received || 0)));
  const maxRows = Math.max(1, ...Object.values(byDepth).map((c) => c.length));

  const colW = 210, rowH = 76, padX = 80, padY = 46;
  const W = padX * 2 + Math.max(1, maxDepth) * colW;
  const H = padY * 2 + Math.max(1, maxRows - 1) * rowH;
  const maxDirty = Math.max(1, ...nodes.map((n) => n.dirty_received || 0));
  const rad = (v) => 7 + 15 * Math.sqrt((v || 0) / maxDirty);

  const pos = {};
  Object.keys(byDepth).map(Number).sort((a, b) => a - b).forEach((d) => {
    const col = byDepth[d], colH = (col.length - 1) * rowH, y0 = (H - colH) / 2;
    col.forEach((n, i) => { pos[n.address] = { x: padX + d * colW, y: y0 + i * rowH, node: n }; });
  });

  let edgeSvg = "";
  edges.forEach((e) => {
    const a = pos[e.src], b = pos[e.dst];
    if (!a || !b) return;
    const dirty = (e.dirty_value || 0) > 0;
    let dx = b.x - a.x, dy = b.y - a.y; const len = Math.hypot(dx, dy) || 1; dx /= len; dy /= len;
    const sx = a.x + dx * (rad(a.node.dirty_received) + 2), sy = a.y + dy * (rad(a.node.dirty_received) + 2);
    const ex = b.x - dx * (rad(b.node.dirty_received) + 6), ey = b.y - dy * (rad(b.node.dirty_received) + 6);
    edgeSvg += `<line x1="${sx.toFixed(1)}" y1="${sy.toFixed(1)}" x2="${ex.toFixed(1)}" y2="${ey.toFixed(1)}" `
      + `stroke="${dirty ? "#e85d04" : "#3a4152"}" stroke-width="${dirty ? 2 : 1.2}" opacity="${dirty ? 0.85 : 0.55}" marker-end="url(#ar)"/>`;
    edgeSvg += `<text x="${((sx + ex) / 2).toFixed(1)}" y="${((sy + ey) / 2 - 4).toFixed(1)}" fill="#868fa1" font-size="10" text-anchor="middle">${esc(String(e.amount))}</text>`;
  });

  let nodeSvg = "";
  nodes.forEach((n) => {
    const p = pos[n.address]; if (!p) return;
    const color = CAT_COLORS[n.category] || NODE_COLORS[n.type] || "#6cc4c9";
    const r = rad(n.dirty_received);
    const shape = n.type === "seed"
      ? `<circle r="${(r + 3).toFixed(1)}" fill="none" stroke="${color}" stroke-width="2"/><circle r="${r.toFixed(1)}" fill="${color}"/>`
      : n.type === "service"
        ? `<rect x="${-r}" y="${-r}" width="${(2 * r).toFixed(1)}" height="${(2 * r).toFixed(1)}" rx="3" fill="${color}"/>`
        : `<circle r="${r.toFixed(1)}" fill="${color}"/>`;
    const ring = n.entered_mixer ? `<circle r="${(r + 5).toFixed(1)}" fill="none" stroke="#e85d04" stroke-width="1" stroke-dasharray="2 2"/>` : "";
    const tip = `${n.address}\n${n.type}${n.category ? " · " + n.category : ""} · activity ${n.activity}${n.dirty_received ? " · dirty " + n.dirty_received : ""}`;
    nodeSvg += `<g transform="translate(${p.x.toFixed(1)},${p.y.toFixed(1)})"><title>${esc(tip)}</title>${ring}${shape}`
      + `<text y="${(r + 13).toFixed(1)}" text-anchor="middle" fill="#c9cfda" font-size="10.5">${esc(n.label || shorten(n.address))}</text></g>`;
  });

  host.innerHTML = capNote + `<svg viewBox="0 0 ${W.toFixed(0)} ${H.toFixed(0)}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Money-flow graph">`
    + `<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#5b6474"/></marker></defs>`
    + edgeSvg + nodeSvg + `</svg>`;
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
