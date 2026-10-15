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
    status.textContent = "Case queued for analysis: " + manifest.analysis_id;
    fileInput.value = "";
    fileName.textContent = "No file selected";
    fileName.classList.remove("has-file");
    loadCases();
    startTaskPoller();
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

// --- Components view (sub-tabbed) --------------------------------------------
const ANOMALY_SEVERITY = {
  external_relationship: "high",
  broken_relationship_target: "medium",
  malformed_xml: "medium",
  dangerous_path: "high",
  duplicate_zip_entry: "medium",
  no_content_type: "low",
  not_a_zip: "high",
  missing_content_types: "medium",
};
const SEV_CLASS = { high: "bad", medium: "warn", low: "warn", info: "ok" };
const SEV_RANK = { high: 0, medium: 1, low: 2, info: 3 };
const IOC_TYPE_LABEL = {
  url: "URL", domain: "Domain", ipv4: "IPv4", ipv6: "IPv6", hash_like: "Hash-like",
};

// Manual classification (Marks). Order shown in selectors.
const MARK_STATES = [
  { id: "unreviewed", label: "Unreviewed", cls: "muted" },
  { id: "true_positive", label: "True positive", cls: "bad" },
  { id: "suspicious", label: "Suspicious", cls: "warn" },
  { id: "false_positive", label: "False positive", cls: "ok" },
  { id: "informational", label: "Informational", cls: "muted" },
];
const MARK_LABEL = Object.fromEntries(MARK_STATES.map((s) => [s.id, s.label]));
const MARK_CLS = Object.fromEntries(MARK_STATES.map((s) => [s.id, s.cls]));

// The currently open case (shared by Components and Marks views).
let _openCaseId = null;

function markBadge(state) {
  const cls = MARK_CLS[state] || "muted";
  return `<span class="badge badge-${cls} mark-badge">${escapeHtml(MARK_LABEL[state] || state)}</span>`;
}

function markControlsHtml(f) {
  const m = f.mark || { state: "unreviewed", comment: "", reviewed_utc: null };
  if (!f.id) return markBadge(m.state);
  const opts = MARK_STATES.map((s) =>
    `<option value="${s.id}"${s.id === m.state ? " selected" : ""}>${escapeHtml(s.label)}</option>`).join("");
  const date = m.reviewed_utc
    ? `<span class="hint-line mark-date">reviewed ${escapeHtml(m.reviewed_utc)}</span>` : "";
  return `<div class="mark-cell" data-fid="${escapeHtml(f.id)}">
    ${markBadge(m.state)}
    <select class="mark-select">${opts}</select>
    <input class="mark-comment" type="text" placeholder="comment…" value="${escapeHtml(m.comment || "")}" />
    ${date}
  </div>`;
}

async function saveMark(cell, analysisId, onSaved) {
  const fid = cell.getAttribute("data-fid");
  const sel = cell.querySelector(".mark-select");
  const comment = cell.querySelector(".mark-comment");
  const state = sel ? sel.value : "unreviewed";
  try {
    const resp = await fetch(
      `/api/cases/${encodeURIComponent(analysisId)}/marks/${encodeURIComponent(fid)}`,
      { method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ state, comment: comment ? comment.value : "" }) });
    if (!resp.ok) throw new Error("save failed");
    const data = await resp.json();
    const badge = cell.querySelector(".mark-badge");
    if (badge) badge.outerHTML = markBadge(data.mark.state);
    let date = cell.querySelector(".mark-date");
    const txt = data.mark.reviewed_utc ? `reviewed ${data.mark.reviewed_utc}` : "";
    if (date) date.textContent = txt;
    else if (txt) cell.insertAdjacentHTML("beforeend", `<span class="hint-line mark-date">${escapeHtml(txt)}</span>`);
    if (onSaved) onSaved(fid, data.mark);
  } catch (err) {
    const badge = cell.querySelector(".mark-badge");
    if (badge) badge.insertAdjacentHTML("afterend", ' <span class="bad-text">save failed</span>');
  }
}

// File actions for extracted items: open the containing folder / download.
function fileActions(rel) {
  if (!rel) return "";
  const r = escapeHtml(rel);
  return `<span class="file-actions">
    <button class="btn btn-ghost btn-sm" data-reveal="${r}" title="Open containing folder">📁 Folder</button>
    <button class="btn btn-ghost btn-sm" data-download="${r}" title="Download">↓</button>
  </span>`;
}

function wireFileActions(root, analysisId) {
  if (!analysisId) return;
  root.querySelectorAll("[data-reveal]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const label = btn.textContent;
      btn.textContent = "Opening…";
      try {
        const resp = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/reveal`,
          { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path: btn.getAttribute("data-reveal") }) });
        btn.textContent = resp.ok ? label : "unavailable here";
      } catch (err) { btn.textContent = "unavailable here"; }
    });
  });
  root.querySelectorAll("[data-download]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const rel = encodeURIComponent(btn.getAttribute("data-download"));
      window.open(`/api/cases/${encodeURIComponent(analysisId)}/file?path=${rel}`, "_blank");
    });
  });
}

function wireMarks(root, analysisId, onSaved) {
  if (!analysisId) return;
  root.querySelectorAll(".mark-cell").forEach((cell) => {
    const sel = cell.querySelector(".mark-select");
    const comment = cell.querySelector(".mark-comment");
    if (sel) sel.addEventListener("change", () => saveMark(cell, analysisId, onSaved));
    if (comment) {
      comment.addEventListener("keydown", (e) => { if (e.key === "Enter") saveMark(cell, analysisId, onSaved); });
      comment.addEventListener("blur", () => saveMark(cell, analysisId, onSaved));
    }
  });
}

function showTab(view) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("is-active", t.getAttribute("data-view") === view));
  document.querySelectorAll(".view").forEach((v) =>
    { v.hidden = v.getAttribute("data-view") !== view; });
}

function table(headers, rowsHtml) {
  const head = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("");
  return `<table class="cases"><thead><tr>${head}</tr></thead><tbody>${rowsHtml}</tbody></table>`;
}

// Collect all findings (anomalies + semantic + VBA) into one list with source.
function collectFindings(mods, ooxml) {
  const out = [];
  (ooxml && ooxml.anomalies || []).forEach((a) => out.push({
    severity: ANOMALY_SEVERITY[a.kind] || "medium",
    source: "ooxml",
    rule: a.kind,
    detail: a.detail || a.target || "",
    location: a.part || a.rels_file || a.target || "",
  }));
  ["word", "excel", "powerpoint"].forEach((name) => {
    const mod = mods[name];
    if (!mod) return;
    (mod.findings || []).forEach((f) => out.push({
      severity: f.severity, source: name, rule: f.rule,
      detail: f.detail || "", location: f.location || "",
    }));
  });
  // oletools suite: findings carry their own tool (olevba/oleid/mraptor/...).
  const ole = mods.oletools;
  if (ole) (ole.findings || []).forEach((f) => out.push({
    severity: f.severity, source: f.tool || "oletools", rule: f.rule,
    detail: f.detail || "", location: f.location || "",
  }));
  const cr = mods.msoffcrypto;
  if (cr) (cr.findings || []).forEach((f) => out.push({
    severity: f.severity, source: "msoffcrypto", rule: f.rule,
    detail: f.detail || "", location: f.location || "document",
  }));
  const xlm = mods.xlmdeobf;
  if (xlm) (xlm.findings || []).forEach((f) => out.push({
    severity: f.severity, source: "xlmdeobf", rule: f.rule,
    detail: f.detail || "", location: f.location || "xlm",
  }));
  const oms = mods.officemalscanner;
  if (oms) (oms.findings || []).forEach((f) => out.push({
    severity: f.severity, source: "officemalscanner", rule: f.rule,
    detail: f.detail || "", location: f.location || "officemalscanner",
  }));
  out.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  return out;
}

// Which Components sub-tab holds the fuller evidence for a finding's source.
function pivotTarget(source) {
  if (["olevba", "oleid", "mraptor", "msodde", "oleobj", "oletools", "msoffcrypto"].includes(source)) return "tools";
  if (source === "xlmdeobf") return "content";
  if (source === "officemalscanner") return "oms";
  if (["word", "excel", "powerpoint"].includes(source)) return "content";
  if (source === "ooxml") return "relationships";
  if (source === "pdf") return "pdf";
  if (source === "nested") return "nested";
  if (source === "email") return "auth";
  return null;
}

function paneFindings(findings) {
  if (!findings.length) return `<p class="hint-line">No findings.</p>`;
  const rows = findings.map((f) => {
    const ev = f.evidence
      ? `<div class="evidence mono" title="Matched content that produced this finding">${escapeHtml(f.evidence)}</div>` : "";
    const target = pivotTarget(f.source);
    const avail = (_compState.sections || []).some((s) => s.id === target);
    const pivot = (target && avail)
      ? `<button class="btn btn-ghost btn-sm" data-pivot="${target}" title="Go to the ${target} evidence">↗ view</button>` : "";
    return `<tr>
      <td><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span></td>
      <td>${escapeHtml(f.source)}</td>
      <td class="mono">${escapeHtml(f.rule)}</td>
      <td>${escapeHtml(f.detail)}${ev}</td>
      <td class="mono">${escapeHtml(f.location)}<div>${pivot}</div></td>
      <td>${markControlsHtml(f)}</td>
    </tr>`;
  }).join("");
  return table(["Severity", "Source", "Rule", "Detail", "Location", "Mark"], rows);
}

function wirePivots(root) {
  root.querySelectorAll("[data-pivot]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-pivot");
      if ((_compState.sections || []).some((s) => s.id === target)) {
        _compState.active = target;
        renderSubtabs();
      }
    });
  });
}

function paneIocs(iocs) {
  if (!iocs || !iocs.iocs || !iocs.iocs.length) return `<p class="hint-line">No IOCs.</p>`;
  const rows = iocs.iocs.map((i) => {
    const where = (i.occurrences || []).map((o) => `${o.module}/${o.location}`);
    const uniq = [...new Set(where)].slice(0, 4).join(", ");
    return `<tr>
      <td>${escapeHtml(IOC_TYPE_LABEL[i.type] || i.type)}</td>
      <td class="mono">${escapeHtml(i.value)}</td>
      <td>${i.count}</td>
      <td class="mono" title="${escapeHtml(where.join(", "))}">${escapeHtml(uniq)}</td>
    </tr>`;
  }).join("");
  const c = iocs.counts || {};
  const bits = Object.keys(c).filter((k) => k !== "total").map((k) => `${c[k]} ${k}`);
  return (bits.length ? `<p class="hint-line">${escapeHtml(bits.join(" · "))}</p>` : "") +
    table(["Type", "Value", "Count", "Provenance"], rows);
}

function paneMetadata(sem, ole) {
  let html = "";
  const meta = (sem && sem.metadata) || {};
  const keys = Object.keys(meta);
  if (keys.length) {
    const rows = keys.map((k) =>
      `<tr><td class="file">${escapeHtml(k)}</td><td>${escapeHtml(String(meta[k]))}</td></tr>`).join("");
    html += table(["Property", "Value"], rows);
  }
  const bits = [];
  if (sem && sem.format === "excel") {
    bits.push(`${sem.sheet_count} sheets`);
    if (sem.hidden_sheets && sem.hidden_sheets.length) bits.push(`hidden: ${sem.hidden_sheets.join(", ")}`);
    bits.push(`${sem.formula_count} formulas`);
    if (sem.external_links) bits.push(`${sem.external_links} external link parts`);
  }
  if (sem && sem.format === "powerpoint") bits.push(`${sem.slide_count} slides · ${sem.notes_count} notes`);
  if (sem && typeof sem.text_length === "number") bits.push(`${sem.text_length} chars of text`);
  const olevba = ole && ole.tools && ole.tools.olevba;
  if (olevba) bits.push(`VBA: ${olevba.macros ? "macros extracted" : "no macros"}`);
  if (bits.length) html += `<p class="hint-line">${escapeHtml(bits.join(" · "))}</p>`;
  return html || `<p class="hint-line">No metadata.</p>`;
}

function paneContent(sem, ole, xlm) {
  let html = "";
  if (sem && sem.text_sample) {
    html += `<p class="hint-line">Reconstructed text (sample)</p>
      <pre class="text-sample">${escapeHtml(sem.text_sample.slice(0, 8000))}</pre>`;
  }
  const olevba = ole && ole.tools && ole.tools.olevba;
  if (olevba && olevba.macros) {
    const modules = olevba.modules || [];
    html += `<p class="hint-line">VBA source — ${modules.length} module(s)</p>`;
    modules.forEach((m) => {
      const name = m.vba_filename || m.stream || "module";
      const trunc = m.code_truncated ? ` — truncated at ${(m.code || "").length} of ${m.code_length} chars` : "";
      const code = m.code != null ? m.code : "";
      html += `<p class="hint-line mono">${escapeHtml(name)} (${m.code_length} chars)${escapeHtml(trunc)}</p>
        <pre class="text-sample">${escapeHtml(code)}</pre>`;
    });
  }
  if (xlm && xlm.xlm_macros) {
    const formulas = xlm.formulas || [];
    html += `<p class="hint-line">Excel 4.0 (XLM) macros — ${formulas.length} deobfuscated formula(s)</p>
      <pre class="text-sample">${escapeHtml(formulas.join("\n").slice(0, 8000))}</pre>`;
  }
  return html || `<p class="hint-line">No reconstructed content.</p>`;
}

function paneTools(ole, crypto, xlm) {
  const rows = [];
  const add = (name, status, detail) => rows.push(`<tr>
    <td class="file">${escapeHtml(name)}</td>
    <td>${status}</td>
    <td>${escapeHtml(detail)}</td></tr>`);

  if (ole && ole.available) {
    const t = ole.tools || {};
    if (t.olevba) add("olevba", t.olevba.error ? '<span class="badge badge-warn">error</span>' : (t.olevba.macros ? '<span class="badge badge-bad">macros</span>' : '<span class="badge badge-ok">no macros</span>'),
      t.olevba.error || `${(t.olevba.modules || []).length} module(s)`);
    if (t.oleid) {
      const inds = t.oleid.indicators || [];
      const risky = inds.filter((i) => ["low", "medium", "high"].includes(i.risk));
      add("oleid", `<span class="badge badge-${risky.length ? "warn" : "ok"}">${inds.length} indicators</span>`,
        risky.map((i) => `${i.name}=${i.value}`).join(", ") || t.oleid.error || "nothing risky");
    }
    if (t.mraptor) add("mraptor", t.mraptor.suspicious ? '<span class="badge badge-bad">suspicious</span>' : '<span class="badge badge-ok">clean</span>',
      t.mraptor.error || `flags ${t.mraptor.flags || ""} ${(t.mraptor.matches || []).join(", ")}`);
    if (t.msodde) { const dde = t.msodde.dde_links || []; add("msodde", `<span class="badge badge-${dde.length ? "bad" : "ok"}">${dde.length} DDE</span>`, t.msodde.error || dde.join(" | ")); }
    if (t.oleobj) { const objs = t.oleobj.objects || []; add("oleobj", `<span class="badge badge-${objs.length ? "warn" : "ok"}">${objs.length} objects</span>`, t.oleobj.error || `${objs.length} embedded OLE object(s)`); }
  }
  if (crypto && crypto.available) {
    const st = crypto.encrypted
      ? (crypto.decrypted ? '<span class="badge badge-bad">encrypted (default pw)</span>' : '<span class="badge badge-warn">encrypted</span>')
      : '<span class="badge badge-ok">not encrypted</span>';
    const detail = crypto.encrypted
      ? (crypto.decrypted ? `decrypted with '${crypto.decrypted_password}'` : "encrypted; no default password worked")
      : (crypto.error ? "not applicable" : "");
    add("msoffcrypto", st, detail);
  }
  if (xlm && xlm.available) {
    const st = xlm.xlm_macros
      ? '<span class="badge badge-bad">XLM macros</span>'
      : '<span class="badge badge-ok">no XLM</span>';
    const detail = xlm.error
      ? xlm.error
      : (xlm.xlm_macros ? `${(xlm.formulas || []).length} deobfuscated formula(s)` : "no Excel 4.0 macros");
    add("XLMMacroDeobfuscator", st, detail);
  }
  if (!rows.length) return `<p class="hint-line">No external tools run.</p>`;
  return table(["Tool", "Status", "Detail"], rows.join(""));
}

function paneDidier(didier) {
  if (!didier || !didier.available) return `<p class="hint-line">Didier Stevens scripts not provisioned.</p>`;
  const tools = didier.tools || {};
  let html = "";
  Object.keys(tools).forEach((name) => {
    const t = tools[name];
    html += `<p class="hint-line">${escapeHtml(name)}${t.returncode != null ? ` (rc ${t.returncode})` : ""}</p>`;
    if (t.error) html += `<p class="hint-line">${escapeHtml(t.error)}</p>`;
    if (t.output) html += `<pre class="text-sample">${escapeHtml(t.output.slice(0, 8000))}</pre>`;
  });
  return html || `<p class="hint-line">No output.</p>`;
}

function paneOms(oms) {
  if (!oms || !oms.available) return `<p class="hint-line">OfficeMalScanner not provisioned.</p>`;
  const tools = oms.tools || {};
  let html = "";
  Object.keys(tools).forEach((name) => {
    const t = tools[name];
    const cmd = t.command ? ` — <span class="mono">${escapeHtml(t.command)}</span>` : "";
    html += `<p class="hint-line">${escapeHtml(name)}${t.returncode != null ? ` (rc ${t.returncode})` : ""}${cmd}</p>`;
    if (t.error) html += `<p class="hint-line">${escapeHtml(t.error)}</p>`;
    if (t.output) html += `<pre class="text-sample">${escapeHtml(t.output.slice(0, 8000))}</pre>`;
  });
  return html || `<p class="hint-line">No output.</p>`;
}

function paneRelationships(rels) {
  if (!rels || !rels.length) return `<p class="hint-line">No relationships.</p>`;
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
  return table(["Id", "Type", "Target", "Mode"], rows);
}

function paneParts(parts) {
  if (!parts || !parts.length) return `<p class="hint-line">No parts.</p>`;
  const sorted = [...parts].sort((a, b) => (a.path > b.path ? 1 : -1));
  const rows = sorted.map((p) => {
    const flag = p.xml_malformed ? ' <span class="badge badge-warn">malformed</span>' : "";
    const ct = (p.content_type || "").split("+")[0].split(".").pop();
    return `<tr>
      <td class="mono">${escapeHtml(p.path)}</td>
      <td title="${escapeHtml(p.content_type || "")}">${escapeHtml(ct || "")}</td>
      <td>${fmtSize(p.size_bytes)}</td>
      <td class="mono" title="${escapeHtml(p.sha256 || "")}">${shortHash(p.sha256)}${flag}</td>
    </tr>`;
  }).join("");
  return table(["Path", "Type", "Size", "SHA-256"], rows);
}

function paneExtracted(items) {
  if (!items || !items.length) return `<p class="hint-line">No extracted media/objects.</p>`;
  const rows = items.map((e) => `<tr>
    <td class="mono">${escapeHtml(e.id || "")}</td>
    <td>${fmtSize(e.size_bytes)}</td>
    <td class="mono" title="${escapeHtml(e.detected_name || "")}">${escapeHtml(e.detected_mime || "")}</td>
    <td class="mono" title="${escapeHtml(e.sha256 || "")}">${shortHash(e.sha256)}</td>
    <td>${fileActions(e.stored_path)}</td>
  </tr>`).join("");
  return table(["Part", "Size", "Detected", "SHA-256", "Actions"], rows);
}

// --- Email panes -------------------------------------------------------------

function fmtDelta(sec) {
  if (sec == null) return "";
  if (sec === 0) return "0s";
  const sign = sec < 0 ? "−" : "+";
  const s = Math.abs(sec);
  if (s < 60) return `${sign}${s}s`;
  if (s < 3600) return `${sign}${Math.round(s / 60)}m`;
  return `${sign}${(s / 3600).toFixed(1)}h`;
}

// The Received hop chain — shown prominently at the top of an email case.
function hopsTable(email) {
  const hops = (email && email.received_chain) || [];
  if (!hops.length) return `<p class="hint-line">No Received chain (no hops parsed).</p>`;
  const rows = hops.map((h, i) => `<tr>
    <td>${i + 1}</td>
    <td class="mono">${escapeHtml(h.from || "")}</td>
    <td class="mono">${escapeHtml(h.by || "")}</td>
    <td class="mono">${escapeHtml(h.ip || "")}</td>
    <td>${escapeHtml(h.with || "")}</td>
    <td class="mono">${escapeHtml(h.timestamp || "")}</td>
    <td class="mono">${escapeHtml(fmtDelta(h.delta_seconds))}</td>
  </tr>`).join("");
  return `<h3 class="formats-title">Received chain — ${hops.length} hop(s), origin → destination</h3>`
    + table(["#", "From", "By", "IP", "With", "Timestamp", "Δt"], rows);
}

function paneEmailHeaders(email) {
  const hs = (email && email.headers) || [];
  if (!hs.length) return `<p class="hint-line">No headers.</p>`;
  const rows = hs.map((h) =>
    `<tr><td class="file">${escapeHtml(h.name)}</td><td class="mono">${escapeHtml(h.value)}</td></tr>`).join("");
  return table(["Header", "Value"], rows);
}

function paneAuth(email) {
  const a = (email && email.authentication) || {};
  const addr = (email && email.addresses) || {};
  const verdict = (v) => {
    const cls = v === "pass" ? "ok" : (v === "fail" ? "bad" : "warn");
    return `<span class="badge badge-${cls}">${escapeHtml(v || "—")}</span>`;
  };
  let html = table(["Mechanism", "Result"], [
    `<tr><td>SPF</td><td>${verdict(a.spf)}</td></tr>`,
    `<tr><td>DKIM</td><td>${verdict(a.dkim)}${a.dkim_signature_present ? ' <span class="hint-line">signature present</span>' : ""}</td></tr>`,
    `<tr><td>DMARC</td><td>${verdict(a.dmarc)}</td></tr>`,
  ].join(""));
  const rows = Object.entries({
    From: addr.from, "From display": addr.from_display, "Return-Path": addr.return_path,
    "Reply-To": addr.reply_to, Sender: addr.sender, Subject: addr.subject,
    "Message-ID": addr.message_id, Date: addr.date, "X-Mailer": addr.x_mailer,
  }).filter(([, v]) => v).map(([k, v]) =>
    `<tr><td class="file">${escapeHtml(k)}</td><td class="mono">${escapeHtml(String(v))}</td></tr>`).join("");
  if (rows) html += `<h3 class="formats-title">Sender / routing</h3>` + table(["Field", "Value"], rows);
  return html;
}

function paneAttachments(email, nestedMod) {
  const items = (email && email.attachments) || [];
  if (!items.length) return `<p class="hint-line">No attachments.</p>`;
  // Recursive tool scan results per attachment (from the "nested" module).
  const byName = {};
  ((nestedMod && nestedMod.tree) || []).forEach((n) => { byName[n.filename] = (n.findings || []).length; });
  const rows = items.map((a) => {
    const nf = byName[a.filename];
    const scan = nf != null
      ? (nf ? `<span class="badge badge-bad">${nf} finding(s)</span>` : '<span class="badge badge-ok">clean</span>')
      : "";
    return `<tr>
      <td class="file">${escapeHtml(a.filename)}</td>
      <td>${fmtSize(a.size_bytes)}</td>
      <td class="mono">${escapeHtml(a.detected_mime || "")}</td>
      <td class="mono" title="${escapeHtml(a.sha256 || "")}">${shortHash(a.sha256)}</td>
      <td>${scan}</td>
      <td>${fileActions(a.stored_path)}</td>
    </tr>`;
  }).join("");
  return table(["Filename", "Size", "Detected", "SHA-256", "Tool scan", "Actions"], rows);
}

function paneEmailBody(email) {
  let html = "";
  if (email && email.mime_structure && email.mime_structure.length) {
    html += `<p class="hint-line">MIME structure: ${escapeHtml(email.mime_structure.join(" · "))}${email.has_html ? " · HTML present" : ""}</p>`;
  }
  const body = (email && email.body_sample) || "";
  html += body
    ? `<pre class="text-sample">${escapeHtml(body.slice(0, 8000))}</pre>`
    : `<p class="hint-line">No text body.</p>`;
  return html;
}

// --- PDF panes ---------------------------------------------------------------

function panePdf(pdf) {
  const bits = [`version ${escapeHtml(pdf.version || "?")}`];
  if (pdf.page_count != null) bits.push(`${pdf.page_count} page(s)`);
  if (pdf.incremental_updates) bits.push(`${pdf.incremental_updates} incremental update(s)`);
  if (pdf.encrypted) bits.push("encrypted");
  let html = `<p class="hint-line">${escapeHtml(bits.join(" · "))}</p>`;
  const kc = pdf.keyword_counts || {};
  const keys = Object.keys(kc);
  if (keys.length) {
    const rows = keys.map((k) =>
      `<tr><td class="mono">${escapeHtml(k)}</td><td>${kc[k]}</td></tr>`).join("");
    html += table(["Keyword", "Count"], rows);
  }
  const uris = pdf.uris || [];
  if (uris.length) {
    html += `<h3 class="formats-title">URIs (${uris.length})</h3>`
      + table(["URI"], uris.map((u) => `<tr><td class="mono">${escapeHtml(u)}</td></tr>`).join(""));
  }
  return html;
}

function panePdfMeta(pdf) {
  const md = pdf.metadata || {};
  const keys = Object.keys(md);
  if (!keys.length) return `<p class="hint-line">No document metadata.</p>`;
  return table(["Property", "Value"],
    keys.map((k) => `<tr><td class="file">${escapeHtml(k)}</td><td>${escapeHtml(String(md[k]))}</td></tr>`).join(""));
}

function panePdfEmbedded(pdf) {
  const items = pdf.embedded || [];
  if (!items.length) return `<p class="hint-line">No embedded files.</p>`;
  const rows = items.map((e) => `<tr>
    <td class="file">${escapeHtml(e.filename)}</td>
    <td>${fmtSize(e.size_bytes)}</td>
    <td class="mono" title="${escapeHtml(e.sha256 || "")}">${shortHash(e.sha256)}</td>
    <td>${fileActions(e.stored_path)}</td>
  </tr>`).join("");
  return table(["Filename", "Size", "SHA-256", "Actions"], rows);
}

// --- Nested (recursive child analysis) --------------------------------------

function nestedNode(n) {
  const fcount = (n.findings || []).length;
  const badge = fcount
    ? `<span class="badge badge-bad">${fcount} finding(s)</span>`
    : (n.kind === "other" ? '<span class="badge badge-muted">not analyzable</span>'
                          : '<span class="badge badge-ok">clean</span>');
  let html = `<div class="nested-node">
    <div class="nested-row">
      <span class="mono">${escapeHtml(n.filename)}</span>
      <span class="badge badge-muted">${escapeHtml(n.kind)}</span>
      ${badge}
      ${fileActions(n.stored_path)}
    </div>`;
  (n.findings || []).forEach((f) => {
    html += `<div class="nested-finding"><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span>
      <span class="mono">${escapeHtml(f.tool)}/${escapeHtml(f.rule)}</span> ${escapeHtml(f.detail)}</div>`;
  });
  if ((n.children || []).length) {
    html += `<div class="nested-children">` + n.children.map(nestedNode).join("") + `</div>`;
  }
  html += `</div>`;
  return html;
}

function paneNested(nested) {
  const tree = (nested && nested.tree) || [];
  if (!tree.length) return `<p class="hint-line">No extracted children.</p>`;
  const c = (nested.counts || {});
  return `<p class="hint-line">${c.nodes || tree.length} extracted item(s) scanned recursively · ${c.findings || 0} finding(s)</p>`
    + tree.map(nestedNode).join("");
}

let _compState = { sections: [], active: null, header: "" };

function renderSubtabs() {
  const bar = _compState.sections.map((s) =>
    `<button class="subtab${s.id === _compState.active ? " is-active" : ""}" data-sub="${s.id}">${escapeHtml(s.label)}</button>`
  ).join("");
  const pane = (_compState.sections.find((s) => s.id === _compState.active) || {}).html || "";
  const bodyEl = document.getElementById("comp-body");
  const header = _compState.header ? `<div class="comp-header">${_compState.header}</div>` : "";
  bodyEl.innerHTML = `${header}<div class="subtabs">${bar}</div><div class="subpane">${pane}</div>`;
  bodyEl.querySelectorAll(".subtab").forEach((btn) => {
    btn.addEventListener("click", () => {
      _compState.active = btn.getAttribute("data-sub");
      renderSubtabs();
    });
  });
  // Wire the mark controls present in the active pane (Findings).
  wireMarks(bodyEl, _openCaseId);
  wireFileActions(bodyEl, _openCaseId);
  wirePivots(bodyEl);
}

async function openComponents(analysisId) {
  showTab("components");
  _openCaseId = analysisId;
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
    const ole = mods.oletools;
    const crypto = mods.msoffcrypto;
    const xlm = mods.xlmdeobf;
    const didier = mods.didier;
    const oms = mods.officemalscanner;
    const email = mods.email;
    const pdf = mods.pdf;
    const nested = mods.nested;
    const iocs = d.iocs;
    if (!ooxml && !sem && !ole && !email && !pdf) {
      bodyEl.innerHTML = `<p class="hint-line">No component analysis for this case yet.</p>`;
      return;
    }
    // Prefer the server's consolidated findings (stable ids + marks);
    // fall back to the client-side collector for older cases.
    const findings = (d.findings && d.findings.length) ? d.findings : collectFindings(mods, ooxml);
    const ni = (iocs && iocs.counts && iocs.counts.total) || 0;
    let compLabel;
    if (email) compLabel = `${email.hop_count || 0} hops · ${email.attachment_count || 0} attachments`;
    else if (pdf) compLabel = `${pdf.page_count || 0} pages · ${(pdf.embedded || []).length} embedded`;
    else compLabel = `${(ooxml && ooxml.counts && ooxml.counts.components) || 0} parts`;
    summary.textContent = `${compLabel} · ${findings.length} findings · ${ni} IOCs`;
    summary.className = "status " + (findings.length ? "bad-text" : "ok-text");

    // Build only the sub-tabs that have content.
    const sections = [];
    const headerHtml = email ? hopsTable(email) : "";
    sections.push({ id: "findings", label: `Findings (${findings.length})`, html: paneFindings(findings) });
    sections.push({ id: "iocs", label: `IOCs (${ni})`, html: paneIocs(iocs) });
    if (email) {
      sections.push({ id: "auth", label: "Authentication", html: paneAuth(email) });
      sections.push({ id: "headers", label: `Headers (${(email.headers || []).length})`, html: paneEmailHeaders(email) });
      sections.push({ id: "attachments", label: `Attachments (${email.attachment_count || 0})`, html: paneAttachments(email, nested) });
      sections.push({ id: "body", label: "Body", html: paneEmailBody(email) });
    }
    if (pdf) {
      sections.push({ id: "pdf", label: "PDF", html: panePdf(pdf) });
      sections.push({ id: "pdfmeta", label: "Metadata", html: panePdfMeta(pdf) });
      sections.push({ id: "embedded", label: `Embedded (${(pdf.embedded || []).length})`, html: panePdfEmbedded(pdf) });
      sections.push({ id: "pdftext", label: "Text", html: `<pre class="text-sample">${escapeHtml((pdf.text_sample || "").slice(0, 8000)) || "(no text)"}</pre>` });
    }
    if (nested && (nested.tree || []).length) {
      sections.push({ id: "nested", label: `Nested (${(nested.counts || {}).nodes || 0})`, html: paneNested(nested) });
    }
    if (ole || crypto || (xlm && xlm.available)) {
      sections.push({ id: "tools", label: "Tools", html: paneTools(ole, crypto, xlm) });
    }
    if (didier && didier.available) sections.push({ id: "didier", label: "Didier", html: paneDidier(didier) });
    if (oms && oms.available) sections.push({ id: "oms", label: "OfficeMalScanner", html: paneOms(oms) });
    if (sem || (ole && ole.available) || (xlm && xlm.xlm_macros)) {
      sections.push({ id: "metadata", label: "Metadata", html: paneMetadata(sem, ole) });
      sections.push({ id: "content", label: "Content", html: paneContent(sem, ole, xlm) });
    }
    if (ooxml) {
      sections.push({ id: "relationships", label: `Relationships (${(ooxml.relationships || []).length})`, html: paneRelationships(ooxml.relationships) });
      sections.push({ id: "parts", label: `Parts (${(ooxml.components || []).length})`, html: paneParts(ooxml.components) });
      if ((ooxml.extracted || []).length) {
        sections.push({ id: "extracted", label: `Extracted (${ooxml.extracted.length})`, html: paneExtracted(ooxml.extracted) });
      }
    }
    _compState = { sections, active: sections[0].id, header: headerHtml };
    renderSubtabs();
    renderRerun(analysisId, d);
  } catch (err) {
    bodyEl.innerHTML = `<p class="hint-line">Could not load components.</p>`;
  }
}

// Re-run control: whole case, or one module in isolation (marks preserved).
function renderRerun(analysisId, d) {
  const el = document.getElementById("comp-actions");
  if (!el) return;
  const ran = ((d.modules && Object.keys(d.modules)) || []).filter((m) => m !== "iocs");
  const opts = ['<option value="full">Full case</option>']
    .concat(ran.map((m) => `<option value="${escapeHtml(m)}">${escapeHtml(m)}</option>`)).join("");
  el.innerHTML = `<span class="hint-line">Re-run:</span>
    <select id="rerun-target">${opts}</select>
    <button id="rerun-btn" class="btn btn-ghost btn-sm" type="button">Re-run</button>
    <span id="rerun-status" class="hint-line"></span>`;
  document.getElementById("rerun-btn").addEventListener("click", async () => {
    const target = document.getElementById("rerun-target").value;
    const body = target === "full" ? {} : { module: target };
    document.getElementById("rerun-status").textContent = "Queued…";
    try {
      await fetch(`/api/cases/${encodeURIComponent(analysisId)}/rerun`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      startTaskPoller();
      // Refresh this view when the queue drains.
      setTimeout(() => openComponents(analysisId), 1200);
    } catch (err) {
      document.getElementById("rerun-status").textContent = "Could not queue re-run.";
    }
  });
}

// --- Tasks view --------------------------------------------------------------
const TASK_STATE_CLS = {
  queued: "muted", running: "warn", cancelling: "warn", cancelled: "muted",
  completed: "ok", failed: "bad",
};
const TASK_ACTIVE = new Set(["queued", "running", "cancelling"]);
let _tasksPoll = null;

function taskProgress(t) {
  if (TASK_ACTIVE.has(t.state)) {
    return t.progress == null
      ? '<span class="spin" aria-label="working">●</span> working'
      : `${Math.round(t.progress * 100)}%`;
  }
  return "—";
}

function renderTasks(data) {
  const summary = document.getElementById("tasks-summary");
  const body = document.getElementById("tasks-body");
  const tasks = (data && data.tasks) || [];
  summary.textContent = `${data.active || 0} active · ${tasks.length} total`;
  summary.className = "status " + ((data.active || 0) ? "" : "ok-text");
  if (!tasks.length) { body.innerHTML = `<p class="hint-line">No tasks yet.</p>`; return; }
  const rows = tasks.map((t) => {
    const cls = TASK_STATE_CLS[t.state] || "muted";
    const target = t.target && t.target !== "full" ? t.target : "full case";
    const cancel = TASK_ACTIVE.has(t.state)
      ? `<button class="btn btn-ghost btn-sm" data-cancel="${escapeHtml(t.id)}">Cancel</button>` : "";
    const err = t.error ? `<div class="hint-line bad-text">${escapeHtml(t.error)}</div>` : "";
    return `<tr>
      <td class="mono">${escapeHtml(t.id)}</td>
      <td class="file">${escapeHtml(t.filename || "")}<div class="hint-line">${escapeHtml(t.type)} · ${escapeHtml(target)}</div></td>
      <td><span class="badge badge-${cls}">${escapeHtml(t.state)}</span></td>
      <td>${taskProgress(t)}</td>
      <td class="mono">${t.duration_s != null ? t.duration_s + "s" : ""}</td>
      <td>${cancel}${err}</td>
    </tr>`;
  }).join("");
  body.innerHTML = table(["Task", "Case / action", "State", "Progress", "Duration", ""], rows);
  body.querySelectorAll("[data-cancel]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/tasks/${encodeURIComponent(btn.getAttribute("data-cancel"))}/cancel`, { method: "POST" });
      loadTasks();
    });
  });
}

async function loadTasks() {
  try {
    const data = await fetch("/api/tasks").then((r) => r.json());
    renderTasks(data);
    return data;
  } catch (err) {
    document.getElementById("tasks-body").innerHTML = `<p class="hint-line">Could not load tasks.</p>`;
    return { active: 0, tasks: [] };
  }
}

// Poll while any task is active: refresh Tasks (if visible) and the cases list.
function startTaskPoller() {
  if (_tasksPoll) return;
  _tasksPoll = setInterval(async () => {
    const data = await loadTasks();
    loadCases();
    if (!data.active) { clearInterval(_tasksPoll); _tasksPoll = null; }
  }, 2500);
}

// --- Marks view --------------------------------------------------------------
let _marksFilter = "all";

function marksTable(findings) {
  if (!findings.length) return `<p class="hint-line">No findings match this filter.</p>`;
  const rows = findings.map((f) => `<tr>
    <td><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span></td>
    <td>${escapeHtml(f.source)}</td>
    <td class="mono">${escapeHtml(f.rule)}</td>
    <td>${escapeHtml(f.detail)}</td>
    <td class="mono">${escapeHtml(f.location)}</td>
    <td>${markControlsHtml(f)}</td>
  </tr>`).join("");
  return table(["Severity", "Source", "Rule", "Detail", "Origin", "Mark"], rows);
}

async function loadMarks(analysisId) {
  const summary = document.getElementById("marks-summary");
  const caseLine = document.getElementById("marks-case");
  const filters = document.getElementById("marks-filters");
  const body = document.getElementById("marks-body");
  if (!analysisId) {
    caseLine.textContent = "";
    filters.innerHTML = "";
    summary.textContent = "";
    body.innerHTML = `<p class="hint-line">Select a case in Overview to triage its findings.</p>`;
    return;
  }
  caseLine.textContent = "Loading…";
  try {
    const d = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/marks`).then((r) => r.json());
    caseLine.innerHTML = `Case <span class="mono">${escapeHtml(d.analysis_id)}</span> · ${escapeHtml(d.filename || "")}`;
    const c = d.counts || {};
    const reviewed = c.reviewed || 0;
    summary.textContent = `${reviewed}/${c.total || 0} reviewed`;
    summary.className = "status " + (reviewed === (c.total || 0) ? "ok-text" : "");

    // Filter chips: All + each state (with count) + orphans.
    const chips = [{ id: "all", label: `All (${c.total || 0})` }].concat(
      MARK_STATES.map((s) => ({ id: s.id, label: `${s.label} (${c[s.id] || 0})` })));
    if ((d.orphans || []).length) chips.push({ id: "orphans", label: `Needs review (${d.orphans.length})` });
    filters.innerHTML = chips.map((ch) =>
      `<button class="subtab${ch.id === _marksFilter ? " is-active" : ""}" data-filter="${ch.id}">${escapeHtml(ch.label)}</button>`).join("");
    filters.querySelectorAll(".subtab").forEach((btn) => {
      btn.addEventListener("click", () => { _marksFilter = btn.getAttribute("data-filter"); loadMarks(analysisId); });
    });

    let shown = d.findings || [];
    if (_marksFilter === "orphans") {
      // Orphans are marks with no matching finding after re-analysis; surface
      // the note (the findings themselves are gone, so list the ids).
      body.innerHTML = `<p class="hint-line">${d.orphans.length} mark(s) no longer match a current finding (re-review): `
        + `<span class="mono">${d.orphans.map(escapeHtml).join(", ")}</span></p>`;
      return;
    }
    if (_marksFilter !== "all") shown = shown.filter((f) => (f.mark && f.mark.state) === _marksFilter);
    body.innerHTML = marksTable(shown);
    wireMarks(body, analysisId, () => loadMarks(analysisId));
  } catch (err) {
    body.innerHTML = `<p class="hint-line">Could not load marks.</p>`;
  }
}

// --- Reports view ------------------------------------------------------------
function loadReports(analysisId) {
  const summary = document.getElementById("reports-summary");
  const caseLine = document.getElementById("reports-case");
  const actions = document.getElementById("reports-actions");
  const frame = document.getElementById("report-frame");
  if (!analysisId) {
    caseLine.textContent = "";
    summary.textContent = "";
    actions.innerHTML = "";
    frame.removeAttribute("src");
    frame.srcdoc = `<p style="font:14px sans-serif;color:#8a98ab;padding:16px">Select a case in Overview to generate its report.</p>`;
    return;
  }
  const url = `/api/cases/${encodeURIComponent(analysisId)}/report`;
  caseLine.innerHTML = `Case <span class="mono">${escapeHtml(analysisId)}</span>`;
  summary.textContent = "";
  actions.innerHTML = `<button id="report-refresh" class="btn btn-ghost btn-sm" type="button">Regenerate</button>
    <a class="btn btn-ghost btn-sm" href="${url}" target="_blank" rel="noopener">Open in new tab</a>
    <span class="hint-line">Use your browser's Print → Save as PDF to export.</span>`;
  frame.removeAttribute("srcdoc");
  frame.src = url + "?t=" + Date.now();
  const btn = document.getElementById("report-refresh");
  if (btn) btn.addEventListener("click", () => { frame.src = url + "?t=" + Date.now(); });
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
      if (target === "marks") loadMarks(_openCaseId);
      if (target === "tasks") loadTasks();
      if (target === "reports") loadReports(_openCaseId);
    });
  });
}

const diagRefresh = document.getElementById("diag-refresh");
if (diagRefresh) diagRefresh.addEventListener("click", loadDiagnostics);

setupTabs();
renderFormats();
loadDiagnostics(); // initial load to set the nav indicator
loadCases();
