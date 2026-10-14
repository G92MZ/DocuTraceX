"use strict";

// --- Supported formats grid (upload section only) ----------------------------
const FORMATS = [
  { name: "Word", color: "#2b7cd3", glyph: "W",
    exts: [".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm"] },
  { name: "Excel", color: "#1f9e5f", glyph: "X",
    exts: [".xls", ".xlt", ".xla", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam", ".xlsb"] },
  { name: "PowerPoint", color: "#d35230", glyph: "P",
    exts: [".ppt", ".pot", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".ppam", ".sldx", ".sldm"] },
  { name: "PDF", color: "#c0392b", glyph: "PDF", exts: [".pdf"] },
  { name: "Email", color: "#7f93ad", glyph: "mail", exts: [".eml", ".emlx", ".msg"] },
];

// Playful document "character": page + eyes + smile, colored band + letter.
function docIcon(color, glyph) {
  const fontSize = glyph.length > 1 ? 6 : 8.5;
  const y = glyph.length > 1 ? 40.5 : 41.5;
  return `<svg viewBox="0 0 40 48" class="fmt-ico" aria-hidden="true">
    <path d="M6 2h18l10 10v32a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z" fill="#eef3f8" stroke="#cfd9e4" stroke-width="1"/>
    <path d="M24 2l10 10h-8a2 2 0 0 1-2-2z" fill="#cfd9e4"/>
    <circle cx="14" cy="20" r="3.2" fill="#fff" stroke="${color}" stroke-width="1.4"/>
    <circle cx="24" cy="20" r="3.2" fill="#fff" stroke="${color}" stroke-width="1.4"/>
    <circle cx="14.6" cy="20.6" r="1.3" fill="#1b2431"/>
    <circle cx="24.6" cy="20.6" r="1.3" fill="#1b2431"/>
    <path d="M14 26 q5 4 10 0" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round"/>
    <rect x="4" y="33" width="30" height="11" rx="2" fill="${color}"/>
    <text x="19" y="${y}" text-anchor="middle" font-size="${fontSize}" font-weight="700" fill="#fff" font-family="Segoe UI, sans-serif">${glyph}</text>
  </svg>`;
}

// Email envelope with a little face.
function mailIcon(color) {
  return `<svg viewBox="0 0 40 48" class="fmt-ico" aria-hidden="true">
    <rect x="3" y="11" width="34" height="26" rx="4" fill="#eef3f8" stroke="${color}" stroke-width="1.6"/>
    <path d="M4 13l16 12 16-12" fill="none" stroke="${color}" stroke-width="1.6" stroke-linejoin="round"/>
    <circle cx="14" cy="29" r="3" fill="#fff" stroke="#5c6f87" stroke-width="1.3"/>
    <circle cx="26" cy="29" r="3" fill="#fff" stroke="#5c6f87" stroke-width="1.3"/>
    <circle cx="14.5" cy="29.5" r="1.2" fill="#1b2431"/>
    <circle cx="26.5" cy="29.5" r="1.2" fill="#1b2431"/>
  </svg>`;
}

function renderFormats() {
  const grid = document.getElementById("formats-grid");
  if (!grid) return;
  grid.innerHTML = FORMATS.map((f) => {
    const icon = f.glyph === "mail" ? mailIcon(f.color) : docIcon(f.color, f.glyph);
    const chips = f.exts.map((e) => `<span class="ext-chip">${e}</span>`).join("");
    return `<div class="fmt-card">
      ${icon}
      <div class="fmt-name">${f.name}</div>
      <div class="fmt-exts">${chips}</div>
    </div>`;
  }).join("");
}

function fmtSize(bytes) {
  if (bytes == null) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = bytes, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

function shortHash(h) {
  return h ? h.slice(0, 12) + "…" : "";
}

function discrepancyBadge(status) {
  const map = {
    match: ["ok", "match"],
    mismatch: ["bad", "mismatch"],
    inconclusive: ["warn", "container"],
    unknown: ["warn", "unknown"],
  };
  const [cls, label] = map[status] || ["warn", status || "—"];
  return `<span class="badge badge-${cls}">${escapeHtml(label)}</span>`;
}

async function loadCases() {
  const body = document.getElementById("cases-body");
  try {
    const resp = await fetch("/api/cases");
    const cases = await resp.json();
    if (!cases.length) {
      body.innerHTML = '<tr><td colspan="8" class="empty">No cases yet.</td></tr>';
      return;
    }
    body.innerHTML = cases.map((c) => `
      <tr class="case-row" data-id="${escapeHtml(c.analysis_id)}" title="Open components">
        <td>${c.created_utc || ""}</td>
        <td class="file">${escapeHtml(c.filename || "")}</td>
        <td>${escapeHtml(c.declared_extension || "")}</td>
        <td class="mono" title="${escapeHtml(c.detected_name || "")}">${escapeHtml(c.detected_mime || "")}</td>
        <td>${discrepancyBadge(c.discrepancy)}</td>
        <td>${fmtSize(c.size_bytes)}</td>
        <td class="mono" title="${c.sha256 || ""}">${shortHash(c.sha256)}</td>
        <td><span class="badge">${escapeHtml(c.state || "")}</span></td>
      </tr>`).join("");
    body.querySelectorAll(".case-row").forEach((row) => {
      row.addEventListener("click", () => openComponents(row.getAttribute("data-id")));
    });
  } catch (err) {
    body.innerHTML = '<tr><td colspan="8" class="empty">Could not load cases.</td></tr>';
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

const fileInput = document.getElementById("file-input");
const fileName = document.getElementById("file-name");

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    fileName.textContent = fileInput.files[0].name;
    fileName.classList.add("has-file");
  } else {
    fileName.textContent = "No file selected";
    fileName.classList.remove("has-file");
  }
});

document.getElementById("upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.getElementById("upload-status");
  if (!fileInput.files.length) return;
  const data = new FormData();
  data.append("file", fileInput.files[0]);
  status.textContent = "Uploading…";
  try {
    const resp = await fetch("/api/cases", { method: "POST", body: data });
    if (!resp.ok) throw new Error("upload failed");
    const manifest = await resp.json();
    status.textContent = "Case created: " + manifest.analysis_id;
    fileInput.value = "";
    fileName.textContent = "No file selected";
    fileName.classList.remove("has-file");
    loadCases();
  } catch (err) {
    status.textContent = "Upload failed.";
  }
});

const STATUS_CLASS = { ok: "ok", warn: "warn", fail: "bad" };

async function loadDiagnostics() {
  const summary = document.getElementById("diag-summary");
  const groupsEl = document.getElementById("diag-groups");
  const dot = document.getElementById("diag-dot");
  try {
    const d = await fetch("/api/diagnostics").then((r) => r.json());
    const app = d.app_interpreter || {};
    const tools = d.tools_interpreter;
    const c = d.counts || { ok: 0, warn: 0, fail: 0 };

    summary.textContent = `${c.ok} ok · ${c.warn} warning · ${c.fail} failed`;
    summary.className = "status " + (d.ok ? "ok-text" : "bad-text");
    const toolsLine = tools
      ? `Tools: portable · Python ${tools.python_version || "?"} · ${tools.executable || ""}`
      : "Tools: portable not provisioned yet";
    document.getElementById("diag-interp").innerHTML =
      `App: Python ${app.python_version || "?"} · ${escapeHtml(app.executable || "")}<br>` +
      `${escapeHtml(toolsLine)}`;

    // Nav dot: red if any failure, amber if warnings, hidden otherwise.
    if (dot) {
      dot.className = "diag-dot" + (c.fail ? " dot-bad" : (c.warn ? " dot-warn" : ""));
    }

    // Group checks by category.
    const groups = {};
    (d.checks || []).forEach((ch) => { (groups[ch.category] ||= []).push(ch); });
    groupsEl.innerHTML = Object.entries(groups).map(([cat, items]) => {
      const rows = items.map((ch) => {
        const cls = STATUS_CLASS[ch.status] || "warn";
        const remedy = (ch.status !== "ok" && ch.remedy)
          ? `<div class="hint-line">${escapeHtml(ch.remedy)}</div>` : "";
        return `<tr>
          <td class="file">${escapeHtml(ch.name)}
            ${ch.purpose ? `<div class="hint-line">${escapeHtml(ch.purpose)}</div>` : ""}</td>
          <td>${escapeHtml(ch.detail || "")}${remedy}</td>
          <td><span class="badge badge-${cls}">${escapeHtml(ch.status)}</span></td>
        </tr>`;
      }).join("");
      return `<h3 class="formats-title">${escapeHtml(cat)}</h3>
        <table class="cases"><thead>
          <tr><th>Check</th><th>Detail</th><th>Status</th></tr>
        </thead><tbody>${rows}</tbody></table>`;
    }).join("");
  } catch (err) {
    summary.textContent = "Could not load diagnostics.";
  }
}

// --- Components view ---------------------------------------------------------
const ANOMALY_SEVERITY = {
  external_relationship: "bad",
  broken_relationship_target: "warn",
  malformed_xml: "warn",
  dangerous_path: "bad",
  duplicate_zip_entry: "warn",
  no_content_type: "warn",
  not_a_zip: "bad",
  missing_content_types: "warn",
};

function showTab(view) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("is-active", t.getAttribute("data-view") === view));
  document.querySelectorAll(".view").forEach((v) =>
    { v.hidden = v.getAttribute("data-view") !== view; });
}

async function openComponents(analysisId) {
  showTab("components");
  const caseLine = document.getElementById("comp-case");
  const summary = document.getElementById("comp-summary");
  const bodyEl = document.getElementById("comp-body");
  caseLine.textContent = "Loading…";
  summary.textContent = "";
  bodyEl.innerHTML = "";
  try {
    const d = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/components`).then((r) => r.json());
    caseLine.innerHTML = `Case <span class="mono">${escapeHtml(d.analysis_id)}</span> · ${escapeHtml(d.filename || "")} · state: ${escapeHtml(d.state || "")}`;
    const mods = d.modules || {};
    const ooxml = mods.ooxml;
    const sem = mods.word || mods.excel || mods.powerpoint;
    const iocs = d.iocs;
    if (!ooxml && !sem) {
      bodyEl.innerHTML = `<p class="hint-line">No component analysis for this case yet.</p>`;
      return;
    }
    const c = (ooxml && ooxml.counts) || {};
    const nf = (sem && sem.counts && sem.counts.findings) || 0;
    const ni = (iocs && iocs.counts && iocs.counts.total) || 0;
    summary.textContent =
      `${c.components || 0} parts · ${c.external_relationships || 0} external · ${(c.anomalies || 0) + nf} findings · ${ni} IOCs`;
    summary.className = "status " + ((c.anomalies || 0) + nf ? "bad-text" : "ok-text");
    bodyEl.innerHTML =
      (sem ? renderSemantic(sem) : "") +
      renderVba(mods.vba) +
      renderIocs(iocs) +
      (ooxml ? renderAnomalies(ooxml.anomalies) : "") +
      (ooxml ? renderRelationships(ooxml.relationships) : "") +
      (ooxml ? renderExtracted(ooxml.extracted) : "") +
      (ooxml ? renderParts(ooxml.components) : "");
  } catch (err) {
    bodyEl.innerHTML = `<p class="hint-line">Could not load components.</p>`;
  }
}

const SEV_CLASS = { high: "bad", medium: "warn", low: "warn", info: "ok" };

const IOC_TYPE_LABEL = {
  url: "URL", domain: "Domain", ipv4: "IPv4", ipv6: "IPv6", hash_like: "Hash-like",
};

function renderIocs(iocs) {
  if (!iocs || !iocs.iocs || !iocs.iocs.length) return "";
  const rows = iocs.iocs.map((i) => {
    const occ = i.occurrences || [];
    const where = occ.map((o) => `${o.module}/${o.location}`);
    const uniqWhere = [...new Set(where)].slice(0, 4).join(", ");
    return `<tr>
      <td>${escapeHtml(IOC_TYPE_LABEL[i.type] || i.type)}</td>
      <td class="mono">${escapeHtml(i.value)}</td>
      <td>${i.count}</td>
      <td class="mono" title="${escapeHtml(where.join(", "))}">${escapeHtml(uniqWhere)}</td>
    </tr>`;
  }).join("");
  const c = iocs.counts || {};
  const bits = Object.keys(c).filter((k) => k !== "total").map((k) => `${c[k]} ${k}`);
  return `<h3 class="formats-title">IOCs (${c.total || 0})</h3>
    ${bits.length ? `<p class="hint-line">${escapeHtml(bits.join(" · "))}</p>` : ""}
    <table class="cases"><thead><tr><th>Type</th><th>Value</th><th>Count</th><th>Provenance</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderSemantic(sem) {
  let html = "";
  // Findings
  const findings = sem.findings || [];
  if (findings.length) {
    const rows = findings.map((f) => `<tr>
      <td><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span></td>
      <td class="mono">${escapeHtml(f.rule)}</td>
      <td>${escapeHtml(f.detail || "")}</td>
      <td class="mono">${escapeHtml(f.location || "")}</td>
    </tr>`).join("");
    html += `<h3 class="formats-title">Findings (${sem.format})</h3>
      <table class="cases"><thead><tr><th>Severity</th><th>Rule</th><th>Detail</th><th>Location</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  // Metadata
  const meta = sem.metadata || {};
  const metaKeys = Object.keys(meta);
  if (metaKeys.length) {
    const rows = metaKeys.map((k) =>
      `<tr><td class="file">${escapeHtml(k)}</td><td>${escapeHtml(String(meta[k]))}</td></tr>`).join("");
    html += `<h3 class="formats-title">Metadata</h3>
      <table class="cases"><tbody>${rows}</tbody></table>`;
  }
  // Format-specific summary line
  const bits = [];
  if (sem.vba) bits.push(`VBA: ${sem.vba.present ? "yes" : "no"}`);
  if (sem.format === "excel") {
    bits.push(`${sem.sheet_count} sheets`);
    if (sem.hidden_sheets && sem.hidden_sheets.length) bits.push(`hidden: ${sem.hidden_sheets.join(", ")}`);
    bits.push(`${sem.formula_count} formulas`);
    if (sem.external_links) bits.push(`${sem.external_links} external link parts`);
  }
  if (sem.format === "powerpoint") bits.push(`${sem.slide_count} slides · ${sem.notes_count} notes`);
  if (typeof sem.text_length === "number") bits.push(`${sem.text_length} chars of text`);
  if (bits.length) html += `<p class="hint-line">${escapeHtml(bits.join(" · "))}</p>`;
  // Text sample
  if (sem.text_sample) {
    html += `<h3 class="formats-title">Text (sample)</h3>
      <pre class="text-sample">${escapeHtml(sem.text_sample.slice(0, 4000))}</pre>`;
  }
  return html;
}

function renderVba(vba) {
  if (!vba) return "";
  const tool = `oletools ${escapeHtml(vba.tool_version || "")}`;
  if (!vba.available) {
    return `<h3 class="formats-title">VBA (oletools)</h3>
      <p class="hint-line">Tool unavailable: ${escapeHtml(vba.error || "")}</p>`;
  }
  let html = `<h3 class="formats-title">VBA macros (${tool})</h3>`;
  if (!vba.macros) {
    html += `<p class="hint-line">No VBA macros extracted${vba.error ? " — " + escapeHtml(vba.error) : ""}.</p>`;
    return html;
  }
  const mods = (vba.vba_modules || []).map((m) =>
    `${escapeHtml(m.stream || "")} (${m.code_length} chars)`).join(", ");
  html += `<p class="hint-line">Modules: ${escapeHtml(mods)}</p>`;
  const findings = vba.findings || [];
  if (findings.length) {
    const rows = findings.map((f) => `<tr>
      <td><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span></td>
      <td class="mono">${escapeHtml(f.rule)}</td>
      <td>${escapeHtml(f.detail || "")}</td>
    </tr>`).join("");
    html += `<table class="cases"><thead><tr><th>Severity</th><th>Rule</th><th>Detail</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  if (vba.code_text) {
    html += `<pre class="text-sample">${escapeHtml(vba.code_text.slice(0, 4000))}</pre>`;
  }
  return html;
}

function renderAnomalies(items) {
  if (!items || !items.length) return "";
  const rows = items.map((a) => {
    const cls = ANOMALY_SEVERITY[a.kind] || "warn";
    const where = a.part || a.rels_file || a.target || "";
    const detail = a.detail || a.target || "";
    return `<tr>
      <td><span class="badge badge-${cls}">${escapeHtml(a.kind)}</span></td>
      <td class="mono">${escapeHtml(where)}</td>
      <td>${escapeHtml(detail)}</td>
    </tr>`;
  }).join("");
  return `<h3 class="formats-title">Anomalies</h3>
    <table class="cases"><thead><tr><th>Kind</th><th>Where</th><th>Detail</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderRelationships(rels) {
  if (!rels || !rels.length) return "";
  const rows = rels.map((r) => {
    const ext = r.mode === "External";
    const typeShort = (r.type || "").split("/").pop();
    return `<tr>
      <td class="mono">${escapeHtml(r.id || "")}</td>
      <td title="${escapeHtml(r.type || "")}">${escapeHtml(typeShort || "")}</td>
      <td class="mono">${escapeHtml(r.target || "")}</td>
      <td>${ext ? '<span class="badge badge-bad">external</span>' : '<span class="badge badge-ok">internal</span>'}</td>
    </tr>`;
  }).join("");
  return `<h3 class="formats-title">Relationships</h3>
    <table class="cases"><thead><tr><th>Id</th><th>Type</th><th>Target</th><th>Mode</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderExtracted(items) {
  if (!items || !items.length) return "";
  const rows = items.map((e) => `<tr>
    <td class="mono">${escapeHtml(e.id || "")}</td>
    <td>${fmtSize(e.size_bytes)}</td>
    <td class="mono" title="${escapeHtml(e.detected_name || "")}">${escapeHtml(e.detected_mime || "")}</td>
    <td class="mono" title="${escapeHtml(e.sha256 || "")}">${shortHash(e.sha256)}</td>
  </tr>`).join("");
  return `<h3 class="formats-title">Extracted media / objects</h3>
    <table class="cases"><thead><tr><th>Part</th><th>Size</th><th>Detected</th><th>SHA-256</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderParts(parts) {
  if (!parts || !parts.length) return "";
  const sorted = [...parts].sort((a, b) => (a.path > b.path ? 1 : -1));
  const rows = sorted.map((p) => {
    const flag = p.xml_malformed ? '<span class="badge badge-warn">malformed</span>' : "";
    const ct = (p.content_type || "").split("+")[0].split(".").pop();
    return `<tr>
      <td class="mono">${escapeHtml(p.path)}</td>
      <td title="${escapeHtml(p.content_type || "")}">${escapeHtml(ct || "")}</td>
      <td>${fmtSize(p.size_bytes)}</td>
      <td class="mono" title="${escapeHtml(p.sha256 || "")}">${shortHash(p.sha256)} ${flag}</td>
    </tr>`;
  }).join("");
  return `<h3 class="formats-title">Parts (${parts.length})</h3>
    <table class="cases"><thead><tr><th>Path</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

// --- Tab navigation ----------------------------------------------------------
function setupTabs() {
  const tabs = document.querySelectorAll(".tab");
  const views = document.querySelectorAll(".view");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.getAttribute("data-view");
      tabs.forEach((t) => t.classList.toggle("is-active", t === tab));
      views.forEach((v) => { v.hidden = v.getAttribute("data-view") !== target; });
      if (target === "diagnostics") loadDiagnostics();
    });
  });
}

const diagRefresh = document.getElementById("diag-refresh");
if (diagRefresh) diagRefresh.addEventListener("click", loadDiagnostics);

setupTabs();
renderFormats();
loadDiagnostics(); // initial load to set the nav indicator
loadCases();
