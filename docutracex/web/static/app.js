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
  { name: "RTF", color: "#6c5ce7", glyph: "RTF", exts: [".rtf"] },
  { name: "Archive", color: "#9a7b4f", glyph: "ZIP",
    exts: [".zip", ".7z", ".tar", ".gz", ".cab", ".iso", ".img"],
    title: "Archives and containers — ZIP/7z, tar(.gz), Microsoft Cabinet and ISO/disk images (a Mark-of-the-Web bypass): extracted and scanned recursively" },
  { name: "OneNote", color: "#7719aa", glyph: "ONE",
    exts: [".one", ".onepkg"],
    title: "OneNote notebooks: embedded-file lures (fake 'click to view' hiding an .hta/.vbs/.exe) carved out and scanned recursively" },
  { name: "Scripting files", color: "#d9a441", glyph: "SH",
    exts: [".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".hta", ".wsf", ".sct", ".html", ".svg", ".mht", ".py", ".pyc"],
    title: "JavaScript, VBScript, PowerShell, batch, HTA/WSF/HTML and Python (.py/.pyc: decompiled/disassembled): deobfuscated and scanned for malicious behaviour" },
  { name: "Shortcuts", color: "#2aa198", glyph: "LNK",
    exts: [".lnk", ".url", ".website"],
    title: "Windows shortcuts: target, arguments and metadata parsed; the launched command runs through the scripting engine (LOLBins, hidden windows, UNC icon NTLM leaks, remote-file URLs)" },
  { name: "Java", color: "#e76f51", glyph: "JAR",
    exts: [".jar", ".war", ".ear", ".class", ".jsp"],
    title: "Java archives and classes: MANIFEST, web.xml, signing, nested jars, and .class/JSP scanned for malicious behaviour (constant pool, or decompiled with CFR); JSP webshells, JNDI/Log4Shell, deserialization" },
  { name: "Binaries / PE", color: "#b58900", glyph: "MSI",
    exts: [".msi", ".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl"],
    title: "MSI installers get real analysis (CustomAction/sequence/Binary tables, string mining, embedded CABs); PyInstaller EXEs are unpacked and their Python recovered; other PE images get static triage (sections/entropy, imports, resources, signing, packer detection) with pefile" },
  { name: "Any other file", color: "#5f6b7a", glyph: "BIN", exts: [".img", ".iso", ".bin", "…"],
    title: "Anything else (disk images, data...): YARA, marks and the report" },
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
// sJkzUVgDiA
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
    return `<div class="fmt-card"${f.title ? ` title="${f.title}"` : ""}>
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
  const n = fileInput.files.length;
  if (n) {
    fileName.textContent = n === 1 ? fileInput.files[0].name : `${n} files selected`;
    fileName.classList.add("has-file");
  } else {
    fileName.textContent = "No file selected";
    fileName.classList.remove("has-file");
  }
});

document.getElementById("upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.getElementById("upload-status");
  const files = Array.from(fileInput.files || []);
  if (!files.length) return;
  const pwInput = document.getElementById("upload-password");
  const pw = pwInput && pwInput.value ? pwInput.value : "";
  const submitBtn = e.target.querySelector('button[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;

  let ok = 0;
  const failed = [];
  // Upload sequentially so the browser isn't flooded; the backend queue then
  // analyses them a couple at a time (see the Tasks tab).
  for (let i = 0; i < files.length; i++) {
    status.textContent = files.length === 1
      ? "Uploading…" : `Uploading ${i + 1}/${files.length}: ${files[i].name}`;
    const data = new FormData();
    data.append("file", files[i]);
    if (pw) data.append("password", pw);
    try {
      const resp = await fetch("/api/cases", { method: "POST", body: data });
      if (!resp.ok) throw new Error("upload failed");
      await resp.json();
      ok++;
      loadCases();
    } catch (err) {
      failed.push(files[i].name);
    }
  }

  if (failed.length) {
    status.textContent = `${ok} queued, ${failed.length} failed (${failed.slice(0, 3).join(", ")}${failed.length > 3 ? "…" : ""}).`;
  } else if (ok === 1) {
    status.textContent = "Case queued for analysis.";
  } else {
    status.textContent = `${ok} files queued — analysed a couple at a time (see Tasks).`;
  }
  fileInput.value = "";
  if (pwInput) pwInput.value = "";
  fileName.textContent = "No file selected";
  fileName.classList.remove("has-file");
  if (submitBtn) submitBtn.disabled = false;
  loadCases();
  startTaskPoller();
});

// --- concurrency control (how many files analysed at once) -------------------
const concInput = document.getElementById("conc-input");
const concStatus = document.getElementById("conc-status");

async function loadConcurrency() {
  if (!concInput) return;
  try {
    const d = await fetch("/api/settings/analysis").then((r) => r.json());
    concInput.value = d.concurrency;
    concInput.min = d.min;
    concInput.max = d.max;
  } catch (err) { /* leave the input as-is */ }
}

if (concInput) {
  concInput.addEventListener("change", async () => {
    const n = Math.max(1, Math.min(8, parseInt(concInput.value, 10) || 1));
    concInput.value = n;
    concStatus.textContent = "Saving…";
    try {
      const d = await fetch("/api/settings/analysis", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ concurrency: n }),
      }).then((r) => r.json());
      concInput.value = d.concurrency;
      concStatus.textContent = `Saved — ${d.concurrency} at a time.`;
      setTimeout(() => { concStatus.textContent = ""; }, 2500);
    } catch (err) {
      concStatus.textContent = "Could not save.";
    }
  });
}

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
  email: "Email", filepath: "File path", registry_key: "Registry key",
  named_pipe: "Named pipe", mac_address: "MAC address", command: "Command",
  user_agent: "User agent",
};
// Group order and plural labels in the IOCs tab.
const IOC_GROUPS = [
  ["ipv4", "IPv4"], ["ipv6", "IPv6"], ["domain", "Domains"], ["url", "URLs"],
  ["email", "Emails"], ["user_agent", "User agents"], ["filepath", "File paths"],
  ["registry_key", "Registry keys"], ["named_pipe", "Named pipes"],
  ["command", "Commands"], ["mac_address", "MAC addresses"], ["hash_like", "Hash-like"],
];

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

// "Findings (12)" -> name + count badge.
function subtabLabel(label) {
  const m = /^(.*?) \((.+)\)$/.exec(label || "");
  return m ? `${escapeHtml(m[1])}<span class="subtab-count">${escapeHtml(m[2])}</span>` : escapeHtml(label || "");
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

// Which Components sub-tab holds the fuller evidence for a finding. Uses the
// finding's location + rule + source, and only returns a tab that actually
// exists for this case (ids), so "view" never lands on an empty/absent pane.
function pivotTarget(f, ids) {
  const has = (id) => ids.includes(id);
  const src = f.source || "";
  const loc = (f.location || "").toLowerCase();
  const rule = f.rule || "";
  // A child-scan finding (attachment / embedded) lives in the Nested tree.
  if (loc.startsWith("nested")) return has("nested") ? "nested" : null;
  // Email: route by what the finding is about, not just the source.
  if (src === "email") {
    if (loc.startsWith("attachment") || /attachment|double_extension/.test(rule)) return has("attachments") ? "attachments" : null;
    if (loc === "body" || rule === "url_display_mismatch") return has("body") ? "body" : null;
    return has("auth") ? "auth" : null;
  }
  if (["olevba", "oleid", "mraptor", "msodde", "oleobj", "oletools", "msoffcrypto"].includes(src)) return has("tools") ? "tools" : null;
  if (src === "officemalscanner") return has("oms") ? "oms" : null;
  if (src === "vipermonkey" || src === "vbatools" || src === "vba_deobf") {
    if (/xlm_very_hidden/.test(rule)) return has("tools") ? "tools" : null;
    return has("vba") ? "vba" : null;
  }
  if (src === "officerules") {
    if (/author_local_path|custom_property|remote_template_name/.test(rule)) return has("metadata") ? "metadata" : null;
    if (/xlm_/.test(rule)) return has("content") ? "content" : null;
    if (/remote_template|external_ole|mshtml|follina|subdocument|remote_image|search_ms|protocol_handler|unc_file/.test(rule)
        && !/field/.test(loc)) return has("relationships") ? "relationships" : null;
    return null;
  }
  if (src === "archive") return has("archive") ? "archive" : null;
  if (src === "yara") return has("yara") ? "yara" : null;
  if (src === "netcheck" || loc.startsWith("netcheck:")) return has("checks") ? "checks" : null;
  if (src === "ole") return has("ole") ? "ole" : null;
  if (src === "pdf") return has("pdf") ? "pdf" : null;
  if (src === "pdftools") return has("pdftools") ? "pdftools" : null;
  if (src === "javascript") return has("javascript") ? "javascript" : null;
  if (src === "powershell" || src === "boxps") return has("powershell") ? "powershell" : null;
  if (src === "vbscript") return has("vbscript") ? "vbscript" : null;
  if (src === "batch") return has("batch") ? "batch" : null;
  // The Binary tab's id is "msi" (MSI and PE share it; label "Binary" for a PE).
  if (src === "python" || src === "pyinstaller") return has("python") ? "python" : (has("msi") ? "msi" : null);
  if (src === "pe" || src === "msi") return has("msi") ? "msi" : null;
  if (src === "java") return has("java") ? "java" : null;
  if (src === "onenote") return has("onenote") ? "onenote" : null;
  if (src === "rtf") {
    if (loc.startsWith("object")) return has("rtfobjects") ? "rtfobjects" : null;
    if (loc.startsWith("field") || loc.includes("template") || loc.includes("docvar")) return has("rtftext") ? "rtftext" : null;
    if (loc.includes("info") || loc.includes("userprops")) return has("rtfmeta") ? "rtfmeta" : null;
    return has("rtfstructure") ? "rtfstructure" : null;
  }
  if (src === "mailrules") {
    if (loc.startsWith("attachment")) return has("attachments") ? "attachments" : null;
    if (/dkim|lookalike|idn_domain|homoglyph|mass_mailer|messageid|missing_message/.test(rule)) return has("auth") ? "auth" : null;
    if (/received|date_header/.test(rule)) return has("headers") ? "headers" : null;
    if (/^qr_code/.test(rule)) return has("body") ? "body" : null;
    return has("body") ? "body" : null;
  }
  if (src === "xlmdeobf") return has("content") ? "content" : null;
  // excel formulas / word field codes are shown in Content; hidden-sheet info in Metadata.
  if (src === "excel") {
    if (/hidden_sheet|external_workbook|unhidden/.test(rule)) return has("metadata") ? "metadata" : null;
    return has("content") ? "content" : (has("metadata") ? "metadata" : null);
  }
  if (src === "word" || src === "powerpoint") return has("content") ? "content" : null;
  if (src === "ooxml") return has("relationships") ? "relationships" : (has("parts") ? "parts" : null);
  return null;
}

// --- Manual marks on component items -------------------------------------------
// Any row of the components (IOC, attachment, header, hop, relationship, part,
// ...) can be added by hand as a finding and marked (TP/FP/...), so something
// the tools missed still reaches the report.
let _manualByKey = {};

function manualKey(kind, location, detail) { return `${kind}\u001f${location}\u001f${detail}`; }

function addMarkCell(kind, detail, location, evidence) {
  const f = _manualByKey[manualKey(kind, location || "", detail)];
  if (f) {
    const st = (f.mark && f.mark.state) || "unreviewed";
    return `<span class="manual-marked">${markBadge(st)}
      <button class="btn btn-ghost btn-sm" data-unmark="${escapeHtml(f.id)}" title="Remove this manual finding">✕</button></span>`;
  }
  const states = MARK_STATES.filter((x) => x.id !== "unreviewed").map((x) =>
    `<option value="${x.id}">${escapeHtml(x.label)}</option>`).join("");
  return `<details class="add-mark" data-kind="${escapeHtml(kind)}" data-detail="${escapeHtml(detail)}"
      data-location="${escapeHtml(location || "")}" data-evidence="${escapeHtml(evidence || "")}">
    <summary title="Add this item as a finding and mark it">＋ mark</summary>
    <div class="add-mark-form">
      <select class="am-state">${states}</select>
      <select class="am-sev"><option value="high">high</option><option value="medium" selected>medium</option><option value="low">low</option><option value="info">info</option></select>
      <input class="am-comment" type="text" placeholder="comment…" />
      <button class="btn btn-primary btn-sm am-add" type="button">Add</button>
    </div>
  </details>`;
}

function wireAddMarks(root, analysisId) {
  if (!analysisId) return;
  const reload = () => openComponents(analysisId, _compState.active, _openViewId);
  root.querySelectorAll("details.add-mark").forEach((d) => {
    const btn = d.querySelector(".am-add");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const body = {
        kind: d.dataset.kind, detail: d.dataset.detail, location: d.dataset.location,
        evidence: d.dataset.evidence, state: d.querySelector(".am-state").value,
        severity: d.querySelector(".am-sev").value, comment: d.querySelector(".am-comment").value,
      };
      const r = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/manual-findings`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (r.ok) reload(); else { btn.disabled = false; btn.textContent = "failed"; }
    });
  });
  root.querySelectorAll("[data-unmark]").forEach((b) => {
    b.addEventListener("click", async () => {
      await fetch(`/api/cases/${encodeURIComponent(analysisId)}/manual-findings/${encodeURIComponent(b.dataset.unmark)}`,
        { method: "DELETE" });
      reload();
    });
  });
}

function findingRowsHtml(findings, ids) {
  return findings.map((f) => {
    const ev = f.evidence
      ? `<div class="evidence mono" title="Matched content that produced this finding">${escapeHtml(f.evidence)}</div>` : "";
    const target = pivotTarget(f, ids);
    const pivot = target
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
}

const FINDING_HEADERS = ["Severity", "Source", "Rule", "Detail", "Location", "Mark"];
let _findingsView = (() => { try { return localStorage.getItem("dtx.findingsView") || "tree"; } catch (e) { return "tree"; } })();

// ctx: { filename, kind, tree } — the case file and its nested tree, so the
// findings can be shown per file (default) or as one flat list.
function paneFindings(findings, ids, ctx) {
  if (!findings.length) return `<p class="hint-line">No findings.</p>`;
  ids = ids || (_compState.sections || []).map((s) => s.id);
  ctx = ctx || {};
  const toggle = `<div class="findings-toolbar">
      <span class="seg"><button type="button" class="btn btn-ghost btn-sm${_findingsView === "tree" ? " is-on" : ""}" data-fview="tree">By file</button><button type="button" class="btn btn-ghost btn-sm${_findingsView === "list" ? " is-on" : ""}" data-fview="list">List</button></span>
      ${_findingsView === "tree" ? `<button class="btn btn-ghost btn-sm" type="button" onclick="this.closest('.subpane').querySelectorAll('details.ftree-findings').forEach(e=>e.open=true)">Expand all</button>
      <button class="btn btn-ghost btn-sm" type="button" onclick="this.closest('.subpane').querySelectorAll('details.ftree-findings').forEach(e=>e.open=false)">Collapse all</button>` : ""}
    </div>`;
  if (_findingsView !== "tree" || !(ctx.tree || []).length) {
    return toggle + table(FINDING_HEADERS, findingRowsHtml(findings, ids));
  }
  // group: "nested:<a › b › c>" -> that child; everything else -> the case file
  const byChain = {};
  const root = [];
  findings.forEach((f) => {
    const loc = String(f.location || "");
    if (loc.startsWith("nested:")) {
      const chain = loc.slice(7).split(" › ").filter(Boolean);
      // longest known chain prefix (a location may add a sub-part after the file)
      for (let i = chain.length; i > 0; i--) {
        const key = chain.slice(0, i).join(" › ");
        if (_ftreeChains.has(key)) { (byChain[key] = byChain[key] || []).push(f); return; }
      }
    }
    root.push(f);
  });
  const worst = (fs) => fs.some((f) => f.severity === "high") ? "bad" : (fs.length ? "warn" : "ok");
  const card = (name, kind, fs, childrenHtml, open, extra) => {
    const body = fs.length
      ? `<details class="ftree-findings"${open ? " open" : ""}><summary><span class="badge badge-${worst(fs)}">${fs.length} finding(s)</span></summary>
          ${table(FINDING_HEADERS, findingRowsHtml(fs, ids))}</details>`
      : `<span class="badge badge-ok">no findings</span>`;
    return `<div class="nested-card nested-${worst(fs)}">
      <div class="nested-row"><b class="mono nested-name">${escapeHtml(name)}</b>
        ${kind ? `<span class="badge badge-muted">${escapeHtml(kind)}</span>` : ""}${extra || ""}</div>
      ${body}${childrenHtml ? `<div class="nested-children">${childrenHtml}</div>` : ""}</div>`;
  };
  const subtreeCount = (n, chain) => (byChain[chain] || []).length
    + (n.children || []).reduce((a, c) => a + subtreeCount(c, `${chain} › ${c.filename}`), 0);
  const node = (n, chain) => {
    if (!subtreeCount(n, chain)) return "";       // files with nothing found below them stay in Nested
    const kids = (n.children || []).map((c) => node(c, `${chain} › ${c.filename}`)).join("");
    const extra = (n.decrypted_from ? `<span class="badge badge-warn">🔓 decrypted stage</span>` : "")
      + (n.view_id ? `<button class="btn btn-sm nested-open" type="button" data-open-view="${escapeHtml(n.view_id)}" title="Open this file's own analysis (its tabs)">Open analysis ↗</button>` : "");
    return card(n.filename, n.kind, byChain[chain] || [], kids, false, extra);
  };
  const kids = (ctx.tree || []).map((n) => node(n, n.filename)).join("");
  return toggle + `<div class="nested-tree">${card(ctx.filename || "case file", ctx.kind ? `${ctx.kind} · case file` : "case file", root, kids, true)}</div>`;
}

// chains present in the current nested tree (set while building the pane)
let _ftreeChains = new Set();
function collectChains(tree) {
  const out = new Set();
  const walk = (ns, prefix) => (ns || []).forEach((n) => {
    const c = prefix ? `${prefix} › ${n.filename}` : n.filename;
    out.add(c);
    walk(n.children, c);
  });
  walk(tree, "");
  return out;
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

// k: MH22fELbKP
function paneIocs(iocs, net) {
  if (!iocs || !iocs.iocs || !iocs.iocs.length) return `<p class="hint-line">No IOCs.</p>`;
  const checked = {};
  ((net && net.checks) || []).forEach((c) => { checked[`${c.kind}|${c.target}`] = c; });
  const safe = iocs.iocs.filter((i) => ["domain", "ipv4", "ipv6"].includes(i.type)).map((i) => [netKindOf(i.type), i.value]);
  const row = (i) => {
    const kind = netKindOf(i.type);
    const done = kind && checked[`${kind}|${i.value}`];
    const nf = done ? (done.findings || []).length : 0;
    const netCell = kind ? netButton(kind, i.value, done ? "Re-check" : "Check")
      + (done ? ` <button class="btn btn-ghost btn-sm" type="button" data-pivot="checks"><span class="badge badge-${nf ? "bad" : "ok"}">${nf} finding(s)</span></button>` : "") : "";
    const where = (i.occurrences || []).map((o) => `${o.module}/${o.location}`);
    const uniq = [...new Set(where)].slice(0, 4).join(", ");
    const hay = `${i.value} ${where.join(" ")}`.toLowerCase();
    return `<tr data-ioc-row data-hay="${escapeHtml(hay)}">
      <td class="mono">${escapeHtml(i.value)}</td>
      <td>${i.count}</td>
      <td class="mono" title="${escapeHtml(where.join(", "))}">${escapeHtml(uniq)}</td>
      <td>${addMarkCell("ioc", `${IOC_TYPE_LABEL[i.type] || i.type}: ${i.value}`, "iocs",
        (i.occurrences || []).slice(0, 5).map((o) => `${o.module}/${o.location}: ${o.context || ""}`).join("\n"))}</td>
      ${kind ? `<td>${netCell}</td>` : ""}
    </tr>`;
  };
  // group by type, known types first in a fixed order, then any new type
  const byType = {};
  iocs.iocs.forEach((i) => { (byType[i.type] = byType[i.type] || []).push(i); });
  const order = IOC_GROUPS.filter(([t]) => byType[t]);
  Object.keys(byType).filter((t) => !IOC_GROUPS.some(([g]) => g === t)).sort()
    .forEach((t) => order.push([t, IOC_TYPE_LABEL[t] || t]));
  const total = iocs.iocs.length;
  const opts = `<option value="">All types (${total})</option>` +
    order.map(([t, l]) => `<option value="${escapeHtml(t)}">${escapeHtml(l)} (${byType[t].length})</option>`).join("");
  const chips = order.map(([t, l]) =>
    `<button type="button" class="ioc-chip" data-ioc-chip="${escapeHtml(t)}">${escapeHtml(l)} <b data-ioc-count="${escapeHtml(t)}">${byType[t].length}</b></button>`).join("");
  const groups = order.map(([t, l]) => `<details class="ioc-group" data-ioc-group="${escapeHtml(t)}" open>
      <summary><b>${escapeHtml(l)}</b> <span class="muted">· <span data-ioc-gcount="${escapeHtml(t)}">${byType[t].length}</span></span></summary>
      ${table(["Value", "Count", "Provenance", "Mark"].concat(netKindOf(t) ? ["Network"] : []), byType[t].map(row).join(""))}
    </details>`).join("");
  const allBtn = safe.length ? `<button class="btn btn-ghost btn-sm" type="button" data-net-all='${escapeHtml(JSON.stringify(safe))}' title="Domains: DNS, RDAP, certificates and a visit to the website (screenshot, page). IPs: owner, ASN, Tor. Through the proxy.">Check all domains &amp; IPs</button>` : "";
  return `<div class="ioc-pane">
    <div class="ioc-toolbar">
      <select class="ioc-type">${opts}</select>
      <input class="ioc-q" type="search" placeholder="filter values…" aria-label="Filter IOC values">
      <button class="btn btn-ghost btn-sm ioc-reset" type="button">Reset</button>
      ${allBtn}
    </div>
    <p class="hint-line ioc-summary">${total} distinct IOC(s) across ${order.length} type(s)</p>
    <div class="ioc-chips">${chips}</div>
    <div class="ioc-toolbar">
      <button class="btn btn-ghost btn-sm ioc-expand" type="button">Expand all</button>
      <button class="btn btn-ghost btn-sm ioc-collapse" type="button">Collapse all</button>
    </div>
    ${groups}
    <p class="hint-line ioc-empty" hidden>No IOC matches the filter.</p>
  </div>`;
}

function wireIocs(root) {
  const pane = root.querySelector(".ioc-pane");
  if (!pane) return;
  const sel = pane.querySelector(".ioc-type"), q = pane.querySelector(".ioc-q");
  const groups = [...pane.querySelectorAll("[data-ioc-group]")];
  const apply = () => {
    const type = sel.value, needle = q.value.trim().toLowerCase();
    let shown = 0, types = 0;
    groups.forEach((g) => {
      const t = g.dataset.iocGroup;
      let n = 0;
      g.querySelectorAll("[data-ioc-row]").forEach((r) => {
        const ok = !needle || r.dataset.hay.includes(needle);
        r.hidden = !ok; if (ok) n++;
      });
      pane.querySelector(`[data-ioc-gcount="${CSS.escape(t)}"]`).textContent = n;
      pane.querySelector(`[data-ioc-count="${CSS.escape(t)}"]`).textContent = n;
      const chip = pane.querySelector(`[data-ioc-chip="${CSS.escape(t)}"]`);
      chip.classList.toggle("active", type === t);
      chip.classList.toggle("empty", n === 0);
      const vis = n > 0 && (!type || type === t);
      g.hidden = !vis;
      if (vis) { shown += n; types++; }
    });
    pane.querySelector(".ioc-summary").textContent =
      `${shown} distinct IOC(s) across ${types} type(s)` + (type || needle ? " (filtered)" : "");
    pane.querySelector(".ioc-empty").hidden = shown > 0;
  };
  sel.addEventListener("change", apply);
  q.addEventListener("input", apply);
  pane.querySelector(".ioc-reset").addEventListener("click", () => { sel.value = ""; q.value = ""; apply(); });
  pane.querySelector(".ioc-expand").addEventListener("click", () => groups.forEach((g) => { g.open = true; }));
  pane.querySelector(".ioc-collapse").addEventListener("click", () => groups.forEach((g) => { g.open = false; }));
  pane.querySelectorAll("[data-ioc-chip]").forEach((c) => c.addEventListener("click", () => {
    const t = c.dataset.iocChip;
    sel.value = sel.value === t ? "" : t;   // click again to show all
    apply();
    const g = pane.querySelector(`[data-ioc-group="${CSS.escape(t)}"]`);
    if (g && sel.value) { g.open = true; g.scrollIntoView({ block: "nearest", behavior: "smooth" }); }
  }));
}

function paneMetadata(sem, ole, rules) {
  let html = "";
  const meta = (sem && sem.metadata) || {};
  const keys = Object.keys(meta);
  if (keys.length) {
    const rows = keys.map((k) =>
      `<tr><td class="file">${escapeHtml(k)}</td><td>${escapeHtml(String(meta[k]))}</td>
       <td>${addMarkCell("metadata", `${k}: ${meta[k]}`, "metadata", "")}</td></tr>`).join("");
    html += table(["Property", "Value", "Mark"], rows);
  }
  // Attribution extras from the own Office rules (what the table above lacks).
  const att = (rules && rules.attribution) || {};
  const seen = new Set(keys.map((k) => k.toLowerCase()));
  const attRows = Object.entries(att)
    .filter(([k]) => !["custom_properties", "local_paths"].includes(k) && !seen.has(k.toLowerCase()))
    .map(([k, v]) => `<tr><td class="file">${escapeHtml(k)}</td><td class="mono">${escapeHtml(String(v))}</td>
      <td>${addMarkCell("metadata", `${k}: ${v}`, "attribution", "")}</td></tr>`).join("");
  if (attRows) html += `<h3 class="formats-title">Attribution</h3>` + table(["Field", "Value", "Mark"], attRows);
  if ((att.local_paths || []).length) {
    html += `<p class="hint-line">Local paths of the author's machine</p><pre class="text-sample">${escapeHtml(att.local_paths.join("\n"))}</pre>`;
  }
  const cp = att.custom_properties || {};
  if (Object.keys(cp).length) {
    html += `<p class="hint-line">Custom document properties</p>` + table(["Name", "Value"],
      Object.entries(cp).map(([k, v]) => `<tr><td class="file">${escapeHtml(k)}</td><td class="mono">${escapeHtml(v)}</td></tr>`).join(""));
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
  // Excel: show the formulas (the evidence behind WEBSERVICE/FILTERXML/… findings).
  if (sem && sem.format === "excel" && (sem.formulas || []).length) {
    const SUS = /WEBSERVICE|FILTERXML|HYPERLINK/i;
    const rows = sem.formulas.map((f) => {
      const sus = SUS.test(f);
      return `<tr><td class="mono"${sus ? ' style="color:#e8795a"' : ""}>=${escapeHtml(f)}</td></tr>`;
    }).join("");
    html += `<p class="hint-line">Formulas (${sem.formulas.length}${sem.formula_count > sem.formulas.length ? " of " + sem.formula_count : ""})</p>`
      + table(["Formula"], rows);
  }
  if (sem && (sem.field_codes || []).length) {
    html += `<p class="hint-line">Field codes (${sem.field_codes.length})</p>`
      + table(["Field code"], sem.field_codes.map((f) => `<tr><td class="mono">${escapeHtml(f)}</td></tr>`).join(""));
  }
  const olevba = ole && ole.tools && ole.tools.olevba;
  if (olevba && olevba.macros) {
    html += `<p class="hint-line">VBA source: see the <strong>VBA</strong> tab (${(olevba.modules || []).length} module(s)).</p>`;
  }
  if (xlm && xlm.xlm_macros) {
    const formulas = xlm.formulas || [];
    html += `<p class="hint-line">Excel 4.0 (XLM) macros — ${formulas.length} deobfuscated formula(s)${xlm.code_file ? " " + fileActions(xlm.code_file) : ""}</p>
      <pre class="text-sample">${escapeHtml(formulas.join("\n").slice(0, 8000))}</pre>`;
  }
  return html || `<p class="hint-line">No reconstructed content.</p>`;
}

// Collapsible raw output of one external tool run (command, rc, output).
// tag: 9qwDpeYpKo
function toolOutputBlock(name, o, open) {
  if (!o || (!o.output && !o.error)) return "";
  const rc = o.returncode != null ? ` · rc ${o.returncode}` : "";
  const cmd = o.command ? ` · <span class="mono">${escapeHtml(o.command)}</span>` : "";
  const dur = o.duration_s != null ? ` · ${o.duration_s}s` : "";
  const trunc = o.output_truncated ? '<p class="hint-line">(output truncated)</p>' : "";
  return `<details class="disclose"${open ? " open" : ""}><summary>${escapeHtml(name)}${cmd}${rc}${dur}</summary>
    <pre class="text-sample">${escapeHtml(o.output || o.error || "")}</pre>${trunc}</details>`;
}

// VBA: source modules, project status (hidden modules / locked), ViperMonkey
// emulation, code rebuilt from p-code and the oledump VBA plugins.
// rev: pzFQkCWMlr
function paneVba(ole, vt, vm) {
  const olevba = (ole && ole.tools && ole.tools.olevba) || {};
  const modules = olevba.modules || [];
  const proj = (vt && vt.project) || {};
  const tools = (vt && vt.tools) || {};
  const chips = [`${modules.length} module(s)`];
  if ((proj.hidden_modules || []).length) chips.push(`<span class="bad-text">hidden: ${escapeHtml(proj.hidden_modules.join(", "))}</span>`);
  if (proj.locked) chips.push('<span class="bad-text">project locked</span>');
  const stomp = (olevba.analysis || []).some((a) => /stomping/i.test(a.keyword || ""));
  if (stomp) chips.push('<span class="bad-text">VBA stomping</span>');
  let html = `<p class="hint-line">${chips.join(" · ")}</p>`;

  if (vm) {
    const acts = vm.actions || [];
    html += `<h3 class="formats-title">Emulation (ViperMonkey) — ${acts.length} action(s)</h3>`;
    if (vm.error) html += `<p class="hint-line">${escapeHtml(vm.error)}</p>`;
    if (acts.length) {
      const danger = /execute|shell|run|download|http|write|powershell|cmd|createobject|registry/i;
      html += table(["Action", "Parameters", "Description"], acts.map((a) => `<tr>
        <td${danger.test(a.action + " " + a.parameters) ? ' class="bad-text"' : ""}>${escapeHtml(a.action)}</td>
        <td class="mono">${escapeHtml(a.parameters)}</td><td>${escapeHtml(a.description || "")}</td></tr>`).join(""));
    }
    if ((vm.potential_iocs || []).length) {
      html += `<p class="hint-line">Values assembled in VBA variables during emulation</p>
        <pre class="text-sample">${escapeHtml(vm.potential_iocs.join("\n"))}</pre>`;
    }
    if ((vm.artifacts || []).length) {
      html += `<p class="hint-line">Files the emulated macro dropped</p>` + table(["File", "Actions"],
        vm.artifacts.map((a) => `<tr><td class="mono">${escapeHtml(a)}</td><td>${fileActions(a)}</td></tr>`).join(""));
    }
    html += toolOutputBlock("ViperMonkey output", vm.tool, false);
  }

  if (olevba.deobfuscated) {
    const dTrunc = olevba.deob_truncated ? (ole.code_file_deob ? ` (preview truncated — download has the full source)` : " (truncated)") : "";
    html += `<h3 class="formats-title">Deobfuscated VBA (static string resolver)${ole && ole.code_file_deob ? " " + fileActions(ole.code_file_deob) : ""}</h3>`;
    html += `<p class="hint-line"><span class="badge badge-warn">deobfuscated</span> ${escapeHtml((olevba.deob_methods || []).join(", ") || "string resolver")}${escapeHtml(dTrunc)}</p>`;
    html += `<pre class="text-sample js-code">${escapeHtml(olevba.deobfuscated)}</pre>`;
  }
  html += `<h3 class="formats-title">VBA source (olevba)${ole && ole.code_file ? " " + fileActions(ole.code_file) : ""}</h3>`;
  modules.forEach((m) => {
    const name = m.vba_filename || m.stream || "module";
    const hidden = (proj.hidden_modules || []).some((h) => (m.stream || "").endsWith("/" + h));
    const trunc = m.code_truncated ? ` — truncated at ${(m.code || "").length} of ${m.code_length} chars` : "";
    html += `<details class="disclose" open><summary><span class="mono">${escapeHtml(name)}</span>
        <span class="hint-line">${escapeHtml(m.stream || "")} · ${m.code_length} chars${escapeHtml(trunc)}</span>
        ${hidden ? '<span class="badge badge-bad">hidden from the VBA editor</span>' : ""}</summary>
      <pre class="text-sample">${escapeHtml(m.code || "")}</pre></details>`;
  });
  if (!modules.length) html += `<p class="hint-line">No VBA source extracted.</p>`;

  html += `<h3 class="formats-title">Compiled p-code</h3>`;
  html += toolOutputBlock("VBA rebuilt from p-code (pcode2code)", tools.pcode2code, false);
  html += toolOutputBlock("p-code disassembly (pcodedmp)", tools.pcodedmp, false);
  const plugins = Object.keys(tools).filter((k) => k.startsWith("oledump plugin_vba") || k.includes("http_heuristics"));
  if (plugins.length) {
    html += `<h3 class="formats-title">oledump plugins</h3>`;
    plugins.forEach((k) => { html += toolOutputBlock(k, tools[k], false); });
  }
  return html;
}

function paneTools(ole, crypto, xlm, vt) {
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
  // Raw output of each tool as it ran, so every finding can be traced back.
  const outs = [];
  const t = (ole && ole.tools) || {};
  ["olevba", "oleid", "mraptor", "msodde", "oleobj"].forEach((n) => { if (t[n]) outs.push([n, t[n]]); });
  if (crypto && crypto.available) outs.push(["msoffcrypto", crypto]);
  if (xlm && xlm.available) outs.push(["XLMMacroDeobfuscator", xlm]);
  // OLE structure tools (timeline, metadata, directory, BIFF records).
  const vtools = (vt && vt.tools) || {};
  ["oletimes", "olemeta", "oledir", "oledump plugin_biff -x"].forEach((n) => { if (vtools[n]) outs.push([n, vtools[n]]); });
  let html = table(["Tool", "Status", "Detail"], rows.join(""));
  outs.forEach(([name, o]) => {
    if (!o.output && !o.error) return;
    const rc = o.returncode != null ? ` · rc ${o.returncode}` : "";
    const cmd = o.command ? ` · <span class="mono">${escapeHtml(o.command)}</span>` : "";
    const trunc = o.output_truncated ? '<p class="hint-line">(output truncated)</p>' : "";
    html += `<details class="disclose"><summary>${escapeHtml(name)} output${cmd}${rc}</summary>
      <pre class="text-sample">${escapeHtml(o.output || o.error || "")}</pre>${trunc}</details>`;
  });
  return html;
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

// trace: 9qwDpeYpKo
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
      <td>${addMarkCell("relationship", `${typeShort} ${r.mode || ""} → ${r.target || ""}`, r.rels_file || "relationships", r.type || "")}</td>
    </tr>`;
  }).join("");
  return table(["Id", "Type", "Target", "Mode", "Mark"], rows);
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
      <td>${addMarkCell("part", `Part ${p.path}`, "parts", `${p.content_type || ""} · sha256 ${p.sha256 || ""}`)}</td>
    </tr>`;
  }).join("");
  return table(["Path", "Type", "Size", "SHA-256", "Mark"], rows);
}

function paneExtracted(items) {
  if (!items || !items.length) return `<p class="hint-line">No extracted media/objects.</p>`;
  const rows = items.map((e) => `<tr>
    <td class="mono">${escapeHtml(e.id || "")}</td>
    <td>${fmtSize(e.size_bytes)}</td>
    <td class="mono" title="${escapeHtml(e.detected_name || "")}">${escapeHtml(e.detected_mime || "")}</td>
    <td class="mono" title="${escapeHtml(e.sha256 || "")}">${shortHash(e.sha256)}</td>
    <td>${fileActions(e.stored_path)}</td>
    <td>${addMarkCell("extracted", `Extracted ${e.id || e.stored_path || ""}`, e.stored_path || "extracted", `${e.detected_mime || ""} · sha256 ${e.sha256 || ""}`)}</td>
  </tr>`).join("");
  return table(["Part", "Size", "Detected", "SHA-256", "Actions", "Mark"], rows);
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
    <td>${addMarkCell("hop", `Hop ${i + 1}: from ${h.from || "?"} by ${h.by || "?"}${h.ip ? " [" + h.ip + "]" : ""}`, "received", h.raw || h.timestamp || "")}</td>
  </tr>`).join("");
  return `<h3 class="formats-title">Received chain — ${hops.length} hop(s), origin → destination</h3>`
    + table(["#", "From", "By", "IP", "With", "Timestamp", "Δt", "Mark"], rows);
}

function paneEmailHeaders(email) {
  const hs = (email && email.headers) || [];
  if (!hs.length) return `<p class="hint-line">No headers.</p>`;
  const rows = hs.map((h) =>
    `<tr><td class="file">${escapeHtml(h.name)}</td><td class="mono">${escapeHtml(h.value)}</td>
     <td>${addMarkCell("header", `${h.name}: ${h.value}`, "headers", "")}</td></tr>`).join("");
  return table(["Header", "Value", "Mark"], rows);
}

// Offline DKIM check, look-alike domains and the sender fingerprint.
function emailRulesAuth(mr) {
  if (!mr) return "";
  let html = "";
  const dk = mr.dkim || [];
  if (dk.length) {
    html += `<h3 class="formats-title">DKIM (offline check)</h3>` + table(
      ["Domain", "Selector", "Algorithm", "Canonicalization", "Body hash", "Signed headers"], dk.map((d) => {
        const bh = d.body_hash_ok === true ? '<span class="badge badge-ok">matches</span>'
          : d.body_hash_ok === false ? '<span class="badge badge-bad">MISMATCH</span>' : '<span class="badge badge-muted">n/a</span>';
        return `<tr><td class="mono">${escapeHtml(d.domain)}</td><td class="mono">${escapeHtml(d.selector)}</td>
          <td>${escapeHtml(d.algorithm)}</td><td>${escapeHtml(d.canonicalization)}</td><td>${bh}</td>
          <td class="mono">${escapeHtml((d.signed_headers || []).join(":"))}</td></tr>`;
      }).join("")) + `<p class="hint-line">Without DNS the signature itself cannot be verified; the body hash can — a mismatch means the body changed after signing.</p>`;
  }
  const la = mr.lookalikes || [];
  if (la.length) {
    html += `<h3 class="formats-title">Look-alike domains (${la.length})</h3>` + table(
      ["Where", "Domain", "Why"], la.map((x) => `<tr><td>${escapeHtml(x.where)}</td>
        <td class="mono bad-text">${escapeHtml(x.domain)}</td><td>${escapeHtml(x.why)}</td></tr>`).join(""));
  }
  const fp = mr.fingerprint || {};
  if (fp.mailer || fp.message_id_domain) {
    html += `<h3 class="formats-title">Sender fingerprint</h3>` + table(["Field", "Value"],
      [["Mailer / User-Agent", fp.mailer], ["Message-ID domain", fp.message_id_domain]].filter(([, v]) => v)
        .map(([k, v]) => `<tr><td class="file">${escapeHtml(k)}</td><td class="mono">${escapeHtml(v)}</td></tr>`).join(""));
  }
  return html;
}

function paneAuth(email, mr) {
  const a = (email && email.authentication) || {};
  const addr = (email && email.addresses) || {};
  const verdict = (v) => {
    const cls = v === "pass" ? "ok" : (v === "fail" ? "bad" : "warn");
    return `<span class="badge badge-${cls}">${escapeHtml(v || "—")}</span>`;
  };
  let html = table(["Mechanism", "Result", "Mark"], [
    `<tr><td>SPF</td><td>${verdict(a.spf)}</td><td>${addMarkCell("auth", `SPF: ${a.spf || "none"}`, "authentication", "")}</td></tr>`,
    `<tr><td>DKIM</td><td>${verdict(a.dkim)}${a.dkim_signature_present ? ' <span class="hint-line">signature present</span>' : ""}</td><td>${addMarkCell("auth", `DKIM: ${a.dkim || "none"}`, "authentication", "")}</td></tr>`,
    `<tr><td>DMARC</td><td>${verdict(a.dmarc)}</td><td>${addMarkCell("auth", `DMARC: ${a.dmarc || "none"}`, "authentication", "")}</td></tr>`,
  ].join(""));
  const rows = Object.entries({
    From: addr.from, "From display": addr.from_display, "Return-Path": addr.return_path,
    "Reply-To": addr.reply_to, Sender: addr.sender, Subject: addr.subject,
    "Message-ID": addr.message_id, Date: addr.date, "X-Mailer": addr.x_mailer,
  }).filter(([, v]) => v).map(([k, v]) =>
    `<tr><td class="file">${escapeHtml(k)}</td><td class="mono">${escapeHtml(String(v))}</td>
     <td>${addMarkCell("sender", `${k}: ${v}`, "authentication", "")}</td></tr>`).join("");
  if (rows) html += `<h3 class="formats-title">Sender / routing</h3>` + table(["Field", "Value", "Mark"], rows);
  html += emailRulesAuth(mr);
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
      <td>${addMarkCell("attachment", `Attachment ${a.filename}`, a.stored_path || "attachments", `${a.detected_mime || ""} · ${a.size_bytes || 0} bytes · sha256 ${a.sha256 || ""}`)}</td>
    </tr>`;
  }).join("");
  return table(["Filename", "Size", "Detected", "SHA-256", "Tool scan", "Actions", "Mark"], rows);
}

function paneEmailBody(email, mr) {
  let html = "";
  if (email && email.mime_structure && email.mime_structure.length) {
    html += `<p class="hint-line">MIME structure: ${escapeHtml(email.mime_structure.join(" · "))}${email.has_html ? " · HTML present" : ""}</p>`;
  }
  const body = (email && email.body_sample) || "";
  const htmlText = (email && email.html_text_sample) || "";
  const htmlSrc = (email && email.html_source_sample) || "";
  const links = (email && email.html_links) || [];
  html += `<p class="hint-line"><strong>Text body</strong></p>`;
  html += body
    ? `<pre class="text-sample">${escapeHtml(body.slice(0, 8000))}</pre>`
    : `<p class="hint-line">No text body.</p>`;
  if (htmlText || htmlSrc) {
    html += `<p class="hint-line"><strong>HTML body (interpreted as text; not rendered, nothing loaded)</strong></p>`;
    html += htmlText
      ? `<pre class="text-sample">${escapeHtml(htmlText.slice(0, 8000))}</pre>`
      : `<p class="hint-line">HTML body has no visible text.</p>`;
    if (links.length) {
      html += `<p class="hint-line"><strong>Links in HTML body (${links.length})</strong></p>`;
      html += `<pre class="text-sample">${escapeHtml(links.join("\n"))}</pre>`;
    }
    if (htmlSrc) {
      html += `<details class="disclose"><summary>HTML source</summary><pre class="text-sample">${escapeHtml(htmlSrc.slice(0, 20000))}</pre></details>`;
    }
  }
  html += emailRulesBody(mr);
  return html;
}

// Email rules shown with the body: decoded gateway links, QR codes, emldump parts.
function emailRulesBody(mr) {
  if (!mr) return "";
  let html = "";
  const dec = mr.decoded_urls || [];
  if (dec.length) {
    html += `<h3 class="formats-title">Links rewritten by a mail gateway (${dec.length})</h3>` + table(
      ["Original destination", "Gateway", "Mark"], dec.map((d) => `<tr>
        <td class="mono">${escapeHtml(d.original)}</td><td>${escapeHtml((d.services || []).join(" → "))}</td>
        <td>${addMarkCell("link", `Link to ${d.original}`, "body", d.wrapped)}</td></tr>`).join(""));
  }
  const qr = mr.qr || [];
  if (qr.length) {
    html += `<h3 class="formats-title">QR codes in images (${qr.length})</h3>` + table(
      ["Image", "Content", "Mark"], qr.map((c) => `<tr><td class="file">${escapeHtml(c.image || "")}</td>
        <td class="mono">${escapeHtml(c.text || "")}</td>
        <td>${addMarkCell("qr", `QR in ${c.image}: ${c.text}`, "attachments", c.format || "")}</td></tr>`).join(""));
  }
  const tools = mr.tools || {};
  const names = Object.keys(tools);
  if (names.length) {
    html += `<h3 class="formats-title">emldump (MIME parts)</h3>`;
    names.forEach((n) => { html += toolOutputBlock(n, tools[n], false); });
  }
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
  // Extracted JavaScript — expandable, not executed.
  const js = pdf.javascript || [];
  if (js.length) {
    html += `<h3 class="formats-title">Extracted JavaScript (${js.length})</h3>`;
    js.forEach((j, i) => {
      html += `<details class="disclose" open><summary>JS block ${i + 1} · ${escapeHtml(j.encoding)}</summary>
        <pre class="text-sample">${escapeHtml(j.code || "")}</pre></details>`;
    });
  }
  // All objects — expandable. Dangerous ones first (red), the rest browsable.
  const objs = pdf.objects || [];
  if (objs.length) {
    const sus = objs.filter((o) => (o.dangerous || []).length).length;
    html += `<h3 class="formats-title">Objects (${objs.length}${sus ? ` · ${sus} suspicious` : ""})</h3>`;
    html += '<div class="row" style="margin:4px 0 8px"><button class="btn btn-ghost btn-sm" onclick="document.querySelectorAll(\'#comp-body .pdf-obj\').forEach(e=>e.open=true)">Expand all</button> <button class="btn btn-ghost btn-sm" onclick="document.querySelectorAll(\'#comp-body .pdf-obj\').forEach(e=>e.open=false)">Collapse all</button></div>';
    objs.forEach((o) => {
      const bad = (o.dangerous || []).length > 0;
      const tags = (o.dangerous || []).map((d) => `<span class="badge badge-bad">${escapeHtml(d)}</span>`).join(" ");
      const type = o.type ? `<span class="badge badge-muted">${escapeHtml(o.type)}</span>` : "";
      const trunc = o.snippet_truncated ? '<div class="hint-line">(truncated)</div>' : "";
      html += `<details class="disclose pdf-obj"${bad ? " open" : ""}><summary><span class="mono">${escapeHtml(o.id)}</span> ${type} ${tags}${o.has_stream ? ' <span class="badge badge-muted">stream</span>' : ""}</summary>
        <pre class="text-sample">${escapeHtml(o.snippet || "")}</pre>${trunc}</details>`;
    });
  }
  return html;
}

// PDF tools: QR codes, signatures, revisions (incremental updates), peepdf and
// the raw output of every tool run on the PDF.
function panePdfTools(pt) {
  let html = "";
  const qr = pt.qr || [];
  html += `<h3 class="formats-title">QR / barcodes (${qr.length})</h3>`;
  html += qr.length ? table(["Page", "Format", "Content", "Mark"], qr.map((c) => `<tr>
      <td>${escapeHtml(String(c.page))}</td><td>${escapeHtml(c.format || "")}</td>
      <td class="mono">${escapeHtml(c.text || "")}</td>
      <td>${addMarkCell("qr", `QR on page ${c.page}: ${c.text}`, "pdf qr", c.format || "")}</td></tr>`).join(""))
    : `<p class="hint-line">${escapeHtml(pt.qr_error || "No QR codes or barcodes found on the rendered pages.")}</p>`;

  const sigs = pt.signatures || [];
  if (sigs.length) {
    html += `<h3 class="formats-title">Digital signatures (${sigs.length})</h3>` + table(
      ["Field", "Signer", "Issuer", "Signing time", "Coverage"], sigs.map((g) => `<tr>
        <td class="mono">${escapeHtml(g.field || "")}</td><td>${escapeHtml(g.signer || "")}</td>
        <td>${escapeHtml(g.issuer || "")}</td><td class="mono">${escapeHtml(g.signing_time || "")}</td>
        <td class="${/ENTIRE_FILE/.test(g.coverage || "") ? "" : "bad-text"}">${escapeHtml(g.coverage || "")}</td></tr>`).join(""));
  }
  const revs = pt.revisions || [];
  if (revs.length) {
    html += `<h3 class="formats-title">Revisions (${revs.length})</h3>` + table(
      ["Revision", "Objects", "Active content", "Signed"], revs.map((r) => `<tr>
        <td>${r.revision === 0 ? "original" : "update #" + r.revision}</td><td>${r.objects}</td>
        <td class="${r.active.length && r.revision ? "bad-text" : ""}">${escapeHtml(r.active.join(", "))}</td>
        <td>${r.signed ? "yes" : ""}</td></tr>`).join(""));
  }
  const pp = pt.peepdf || {};
  if ((pp.versions || []).length) {
    html += `<h3 class="formats-title">peepdf</h3>`;
    if ((pp.cves || []).length) html += `<p class="bad-text">Known CVEs: ${escapeHtml(pp.cves.join(", "))}</p>`;
    html += table(["Version", "Objects", "Triggers", "Actions", "Elements", "JS objects"], pp.versions.map((v) => {
      const fmt = (o) => Object.entries(o || {}).map(([k, ids]) => `${k} (${ids.join(",")})`).join(" · ");
      return `<tr><td>${escapeHtml(String(v.version))} ${escapeHtml(v.type || "")}</td><td>${v.objects}</td>
        <td class="mono">${escapeHtml(fmt(v.triggers))}</td><td class="mono">${escapeHtml(fmt(v.actions))}</td>
        <td class="mono">${escapeHtml((v.elements || []).join(", "))}</td><td>${escapeHtml((v.js_objects || []).join(", "))}</td></tr>`;
    }).join(""));
  }
  const tools = pt.tools || {};
  const names = Object.keys(tools);
  if (names.length) {
    html += `<h3 class="formats-title">Tool output (${names.length})</h3>`;
    names.forEach((n) => { html += toolOutputBlock(n, tools[n], false); });
  }
  return html;
}

// JavaScript: every script found in the case — origin, suspicious lines
// (highlighted), what the STPyV8 sandbox recorded, decoded strings, code.
function paneJavascript(js) {
  const scripts = js.scripts || [];
  if (!scripts.length) return `<p class="hint-line">No JavaScript found.</p>`;
  let html = `<p class="hint-line">${scripts.length} script(s). Analysed statically and run in an isolated V8 sandbox (no file system, network or processes; only recording stubs).</p>`;
  html += '<div class="row" style="margin:4px 0 10px"><button class="btn btn-ghost btn-sm" type="button" onclick="this.closest(\'.subpane\').querySelectorAll(\'details.js-card\').forEach(e=>e.open=true)">Expand all</button> <button class="btn btn-ghost btn-sm" type="button" onclick="this.closest(\'.subpane\').querySelectorAll(\'details.js-card\').forEach(e=>e.open=false)">Collapse all</button></div>';
  scripts.forEach((sc) => {
    const hits = sc.hits || [];
    const sev = hits.some((h) => h.severity === "high") ? "bad" : (hits.length ? "warn" : "ok");
    const rules = [...new Set(hits.map((h) => h.label))];
    const m = sc.metrics || {};
    const sb = sc.sandbox || {};
    const logs = sb.log || [];
    const hitLines = new Set(hits.map((h) => h.line_no));
    const codeHtml = (sc.code || "").split("\n").map((ln, i) => {
      const t = escapeHtml(ln);
      return hitLines.has(i + 1) ? `<mark>${t}</mark>` : t;
    }).join("\n");
    let body = "";
    if (sc.note) body += `<p class="hint-line">${escapeHtml(sc.note)}</p>`;
    body += `<p class="hint-line">${m.lines || 0} lines · ${sc.size} chars · longest line ${m.longest_line || 0} · entropy ${m.entropy || 0} · obfuscation score ${m.obfuscation_score || 0}</p>`;
    if (sc.code_is_deobfuscated) {
      const methods = (sc.deob_methods || []).join(", ");
      const schemes = (sc.deob_schemes || []).length ? ` · scheme(s): ${(sc.deob_schemes || []).join(", ")}` : "";
      body += `<p class="hint-line"><span class="badge badge-warn">deobfuscated</span> Recovered payload analysed below (${escapeHtml(methods || "static decoding")}${escapeHtml(schemes)}).</p>`;
    } else if ((sc.deob_schemes || []).length) {
      body += `<p class="hint-line"><span class="badge badge-bad">obfuscated</span> Scheme detected: ${escapeHtml((sc.deob_schemes || []).join(", "))} — unfolded by the sandbox.</p>`;
    }
    const jsLoc = sc.location || `javascript:${sc.id}`;
    body += jsTechniquesHtml(sc.techniques || []);
    if (hits.length) {
      body += table(["Line", "Why", "Code", "Mark"], hits.map((h) => `<tr><td>${h.line_no}</td>
        <td class="${h.severity === "high" ? "bad-text" : ""}">${escapeHtml(h.label)}</td>
        <td class="mono">${escapeHtml(h.line)}</td>
        <td>${addMarkCell("js_hit", `JavaScript (${sc.origin}): ${h.label} — line ${h.line_no}`, jsLoc, h.line)}</td></tr>`).join(""));
    }
    if (logs.length || sb.error) {
      body += `<p class="hint-line"><strong>Sandbox</strong>${sb.timed_out ? " — stopped by the time limit" : ""}${sb.error && !sb.timed_out ? " — " + escapeHtml(sb.error) : ""}</p>`;
      if (logs.length) {
        body += table(["Event", "Name", "Arguments", "Mark"], logs.slice(0, 200).map((e) => {
          const args = (e.args || []).join(" | ");
          return `<tr><td>${escapeHtml(e.kind)}</td><td class="mono">${escapeHtml(e.name)}</td>
          <td class="mono">${escapeHtml(args.slice(0, 1500))}</td>
          <td>${addMarkCell("js_sandbox", `JavaScript sandbox (${sc.origin}): ${e.name} ${args}`.slice(0, 300), jsLoc, args.slice(0, 1500))}</td></tr>`;
        }).join(""));
      }
    }
    if ((sc.decoded || []).length) {
      body += `<p class="hint-line"><strong>Decoded strings</strong></p>` + table(["Method", "Decoded", "Mark"],
        sc.decoded.map((d) => `<tr><td>${escapeHtml(d.method)}</td><td class="mono">${escapeHtml(d.decoded)}</td>
          <td>${addMarkCell("js_decoded", `JavaScript decoded (${d.method}): ${d.decoded}`.slice(0, 300), jsLoc, d.encoded || d.decoded)}</td></tr>`).join(""));
    }
    if (sc.code_is_deobfuscated) {
      // Primary view = the recovered (deobfuscated) payload; the original stays
      // one click away. Downloads: the deobfuscated artifact and the original.
      const dTrunc = sc.code_truncated ? (sc.code_file_deob ? ` (preview truncated — download has the full ${sc.deob_size || 0} chars)` : " (truncated)") : "";
      body += `<details class="disclose"${hits.length ? " open" : ""}><summary>Deobfuscated code${dTrunc}${sc.code_file_deob ? " " + fileActions(sc.code_file_deob) : ""}</summary><pre class="text-sample js-code">${codeHtml}</pre></details>`;
      const oTrunc = sc.original_truncated ? (sc.code_file ? ` (preview truncated — download has the full ${sc.size} chars)` : " (truncated)") : "";
      const origHtml = escapeHtml(sc.original_code || "");
      body += `<details class="disclose"><summary>Original (obfuscated)${oTrunc}${sc.code_file ? " " + fileActions(sc.code_file) : ""}</summary><pre class="text-sample js-code">${origHtml}</pre></details>`;
    } else {
      const jsTrunc = sc.code_truncated ? (sc.code_file ? ` (preview truncated — download has the full ${sc.size} chars)` : " (truncated)") : "";
      body += `<details class="disclose"${hits.length ? " open" : ""}><summary>Code${jsTrunc}${sc.code_file ? " " + fileActions(sc.code_file) : ""}</summary><pre class="text-sample js-code">${codeHtml}</pre></details>`;
    }
    if (sc.pretty) body += `<details class="disclose"><summary>Pretty-printed</summary><pre class="text-sample">${escapeHtml(sc.pretty)}</pre></details>`;
    html += `<details class="disclose js-card"${sev === "bad" ? " open" : ""}>
      <summary><span class="badge badge-${sev}">${hits.length} hit(s)</span>
        <span class="mono">${escapeHtml(sc.origin)}</span>
        <span class="badge badge-muted">${escapeHtml(sc.kind)}</span>
        <span class="hint-line">${escapeHtml(rules.slice(0, 4).join(" · "))}</span></summary>
      <div style="padding:8px 10px">${body}</div></details>`;
  });
  return html;
}

// "Confirmed obfuscation techniques": numbered, technique in bold, concrete
// evidence, and whether it was seen statically or resolved in the sandbox.
function jsTechniquesHtml(techs) {
  if (!techs.length) return "";
  const sevCls = { high: "bad", medium: "warn", low: "muted", info: "muted" };
  const items = techs.map((t, i) => `<li class="js-tech">
      <span class="js-tech-n">${i + 1}.</span>
      <b>${escapeHtml(t.name)}</b>
      <span class="badge badge-${t.phase === "sandbox" ? "ok" : "muted"}" title="${t.phase === "sandbox" ? "Resolved by running the script in the sandbox" : "Detected by reading the original code"}">${t.phase === "sandbox" ? "sandbox" : "static"}</span>
      <span class="badge badge-${sevCls[t.severity] || "warn"}">${escapeHtml(t.severity)}</span>
      <div class="evidence mono">${escapeHtml(t.evidence || "")}</div>
      ${t.payload ? `<button class="btn btn-ghost btn-sm" type="button" data-pivot="nested" title="The decrypted payload is a nested child, re-analysed by whatever fits it (JavaScript, PowerShell, VBScript, batch, PE…)">↗ next stage in Nested</button>` : ""}
      ${t.payload ? `<details class="disclose"><summary>Payload (${t.payload.length} chars)</summary><pre class="text-sample">${escapeHtml(t.payload.slice(0, 20000))}</pre></details>` : ""}
    </li>`).join("");
  const nS = techs.filter((t) => t.phase !== "sandbox").length, nB = techs.length - nS;
  return `<div class="js-techs"><p class="hint-line"><strong>Confirmed obfuscation techniques</strong> — ${nS} static · ${nB} resolved in the sandbox</p><ol class="js-tech-list">${items}</ol></div>`;
}

// Generic code-language pane (PowerShell, VBScript, …): same pattern as the
// JavaScript tab — suspicious lines, a Deobfuscated view (hits highlighted) and
// an Original view, each with Folder/Download of the complete file. No V8
// sandbox table (that is JavaScript-specific).
function paneCodeLanguage(mod, opts) {
  opts = opts || {};
  const scripts = (mod && mod.scripts) || [];
  const noun = opts.noun || "command";
  if (!scripts.length) return `<p class="hint-line">No ${escapeHtml(opts.label || "code")} found.</p>`;
  let html = `<p class="hint-line">${scripts.length} ${escapeHtml(noun)}(s). Collected from the case and deobfuscated statically (nothing is executed).</p>`;
  html += '<div class="row" style="margin:4px 0 10px"><button class="btn btn-ghost btn-sm" type="button" onclick="this.closest(\'.subpane\').querySelectorAll(\'details.js-card\').forEach(e=>e.open=true)">Expand all</button> <button class="btn btn-ghost btn-sm" type="button" onclick="this.closest(\'.subpane\').querySelectorAll(\'details.js-card\').forEach(e=>e.open=false)">Collapse all</button></div>';
  scripts.forEach((sc) => {
    const hits = sc.hits || [];
    const sev = hits.some((h) => h.severity === "high") ? "bad" : (hits.length ? "warn" : "ok");
    const rules = [...new Set(hits.map((h) => h.label))];
    const m = sc.metrics || {};
    const hitLines = new Set(hits.map((h) => h.line_no));
    const codeHtml = (sc.code || "").split("\n").map((ln, i) => {
      const t = escapeHtml(ln);
      return hitLines.has(i + 1) ? `<mark>${t}</mark>` : t;
    }).join("\n");
    const loc = sc.location || `${opts.src}:${sc.id}`;
    let body = "";
    if (sc.note) body += `<p class="hint-line">${escapeHtml(sc.note)}</p>`;
    body += `<p class="hint-line">${m.lines || 0} lines · ${sc.size} chars · longest line ${m.longest_line || 0} · entropy ${m.entropy || 0} · obfuscation score ${m.obfuscation_score || 0}</p>`;
    if (sc.code_is_deobfuscated) {
      const methods = (sc.deob_methods || []).join(", ");
      body += `<p class="hint-line"><span class="badge badge-warn">deobfuscated</span> Recovered ${escapeHtml(noun)} analysed below (${escapeHtml(methods || "static decoding")}).</p>`;
    }
    if (hits.length) {
      body += table(["Line", "Why", "Code", "Mark"], hits.map((h) => `<tr><td>${h.line_no}</td>
        <td class="${h.severity === "high" ? "bad-text" : ""}">${escapeHtml(h.label)}</td>
        <td class="mono">${escapeHtml(h.line)}</td>
        <td>${addMarkCell(opts.markKind || "code_hit", `${escapeHtml(opts.label || "code")} (${sc.origin}): ${h.label} — line ${h.line_no}`, loc, h.line)}</td></tr>`).join(""));
    }
    if (sc.sandbox && (sc.sandbox.actions || []).length) {
      body += `<p class="hint-line"><strong>Sandbox (box-ps)</strong> — emulated behaviour${sc.sandbox.error ? " · " + escapeHtml(sc.sandbox.error) : ""}</p>`;
      body += table(["Behaviours", "Line"], sc.sandbox.actions.slice(0, 30).map((a) => `<tr>
        <td class="${(a.behaviours || []).join(" ").match(/network|exec|file|inject|registry|persist/i) ? "bad-text" : ""}">${escapeHtml((a.behaviours || []).join(", "))}</td>
        <td class="mono">${escapeHtml(a.line || "")}</td></tr>`).join(""));
      if ((sc.sandbox.iocs || []).length) {
        body += `<p class="hint-line">Sandbox IOCs</p><pre class="text-sample">${escapeHtml(sc.sandbox.iocs.join("\n"))}</pre>`;
      }
    } else if (sc.sandbox && sc.sandbox.error) {
      body += `<p class="hint-line">Sandbox (box-ps): ${escapeHtml(sc.sandbox.error)}</p>`;
    }
    if (sc.code_is_deobfuscated) {
      const dTrunc = sc.code_truncated ? (sc.code_file_deob ? ` (preview truncated — download has the full ${sc.deob_size || 0} chars)` : " (truncated)") : "";
      body += `<details class="disclose"${hits.length ? " open" : ""}><summary>Deobfuscated${dTrunc}${sc.code_file_deob ? " " + fileActions(sc.code_file_deob) : ""}</summary><pre class="text-sample js-code">${codeHtml}</pre></details>`;
      const oTrunc = sc.original_truncated ? (sc.code_file ? ` (preview truncated — download has the full ${sc.size} chars)` : " (truncated)") : "";
      body += `<details class="disclose"><summary>Original (obfuscated)${oTrunc}${sc.code_file ? " " + fileActions(sc.code_file) : ""}</summary><pre class="text-sample js-code">${escapeHtml(sc.original_code || "")}</pre></details>`;
    } else {
      const jsTrunc = sc.code_truncated ? (sc.code_file ? ` (preview truncated — download has the full ${sc.size} chars)` : " (truncated)") : "";
      body += `<details class="disclose"${hits.length ? " open" : ""}><summary>Code${jsTrunc}${sc.code_file ? " " + fileActions(sc.code_file) : ""}</summary><pre class="text-sample js-code">${codeHtml}</pre></details>`;
    }
    html += `<details class="disclose js-card"${sev === "bad" ? " open" : ""}>
      <summary><span class="badge badge-${sev}">${hits.length} hit(s)</span>
        <span class="mono">${escapeHtml(sc.origin)}</span>
        ${sc.code_is_deobfuscated ? '<span class="badge badge-warn">deobfuscated</span>' : ""}
        <span class="hint-line">${escapeHtml(rules.slice(0, 4).join(" · "))}</span></summary>
      <div style="padding:8px 10px">${body}</div></details>`;
  });
  return html;
}

// RTF: embedded objects (rtfobj + the \\object group flags), structure,
// text/fields and the \\info attribution data.
function paneRtfObjects(rtf) {
  const objs = rtf.objects || [];
  const groups = rtf.object_groups || [];
  if (!objs.length && !groups.length) return `<p class="hint-line">No \\object / \\objdata found.</p>`;
  const groupFor = (o) => groups.filter((g) => g.offset <= (o.offset || 0)).sort((a, b) => b.offset - a.offset)[0] || {};
  let html = `<p class="hint-line">Objects decoded by rtfobj from \\objdata (OLE 1.0). Extracted to <span class="mono">extracted/rtfobj</span> and scanned recursively (see Nested).</p>`;
  html += table(["#", "Offset", "Class", "Group flags", "CLSID", "Size", "Package / extracted", "SHA-256"], objs.map((o) => {
    const g = groupFor(o);
    const pkg = o.is_package ? `<strong>${escapeHtml(o.filename || "")}</strong><br><span class="hint-line">${escapeHtml(o.source_path || "")}</span>` : "";
    const cve = /CVE/.test(o.clsid_desc || "");
    return `<tr><td>${o.index}</td><td class="mono">0x${(o.offset || 0).toString(16).toUpperCase()}</td>
      <td class="mono">${escapeHtml(o.class_name || g.class || "")}</td>
      <td class="mono">${escapeHtml((g.flags || []).join(" "))}</td>
      <td class="mono${cve ? " bad-text" : ""}">${escapeHtml(o.clsid || "")}${o.clsid_desc ? "<br>" + escapeHtml(o.clsid_desc) : ""}</td>
      <td>${o.ole_size != null ? o.ole_size : o.raw_size}</td>
      <td>${pkg}${o.stored_path ? `<div class="mono">${escapeHtml(o.stored_path)}</div>` : ""}</td>
      <td class="mono">${escapeHtml((o.sha256 || "").slice(0, 16))}…</td></tr>`;
  }).join(""));
  const orphan = groups.filter((g) => !objs.some((o) => groupFor(o) === g));
  if (orphan.length) {
    html += `<h3 class="formats-title">\\object groups without decodable data (${orphan.length})</h3>` + table(["Offset", "Class", "Flags"],
      orphan.map((g) => `<tr><td class="mono">0x${g.offset.toString(16).toUpperCase()}</td><td class="mono">${escapeHtml(g.class || "")}</td><td class="mono">${escapeHtml(g.flags.join(" "))}</td></tr>`).join(""));
  }
  return html;
}

function paneRtfStructure(rtf) {
  const st = rtf.structure || {};
  const rows = [
    ["Header", rtf.header || ""], ["Size", `${st.size || 0} bytes`], ["Groups", st.groups],
    ["Max nesting depth", st.max_depth], ["Control words", st.control_words],
    ["Fonts in \\fonttbl", `${st.font_count} (max index ${st.font_max_index})`],
    ["\\bin blocks", `${st.bin_count} (${st.bin_bytes} bytes; ${st.bin_in_objdata} inside \\objdata)`],
    ["\\objdata junk", `${st.objdata_junk} non-hex chars · ${st.objdata_groups} groups · ${st.objdata_cwords} control words`],
    ["End of document", st.end_offset != null ? `offset 0x${st.end_offset.toString(16).toUpperCase()}` : "never closed"],
    ["Data after the end", `${st.trailing_bytes || 0} bytes`], ["Unbalanced braces", st.unbalanced ? "yes" : "no"],
  ];
  let html = table(["Property", "Value"], rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="mono">${escapeHtml(String(v))}</td></tr>`).join(""));
  const dest = Object.entries(rtf.destinations || {});
  if (dest.length) {
    html += `<h3 class="formats-title">Destinations</h3>` + table(["Destination", "Count"],
      dest.map(([k, v]) => `<tr><td class="mono">\\${escapeHtml(k)}</td><td>${v}</td></tr>`).join(""));
  }
  const tools = rtf.tools || {};
  const blocks = [];
  if (tools.rtfobj) blocks.push(toolOutputBlock("rtfobj", tools.rtfobj, false));
  const rd = tools.rtfdump || {};
  if (rd.objects) blocks.push(toolOutputBlock("rtfdump -O", rd.objects, false));
  if (rd.groups) blocks.push(toolOutputBlock("rtfdump", rd.groups, false));
  if (tools.rtfscan) blocks.push(toolOutputBlock("RTFScan", tools.rtfscan, false));
  if (rd.available === false) blocks.push(`<p class="hint-line">rtfdump: ${escapeHtml(rd.error || "not provisioned")}</p>`);
  if (blocks.length) html += `<h3 class="formats-title">Tool output</h3>` + blocks.join("");
  return html;
}

function paneRtfText(rtf) {
  let html = "";
  const fields = rtf.fields || [];
  if (rtf.template) html += `<h3 class="formats-title">Attached template</h3><p class="mono">${escapeHtml(rtf.template)}</p>`;
  html += `<h3 class="formats-title">Fields (${fields.length})</h3>`;
  html += fields.length ? table(["#", "Instruction", "Displayed result", "Mark"], fields.map((f, i) => `<tr><td>${i + 1}</td>
      <td class="mono">${escapeHtml(f.instr)}</td><td>${escapeHtml(f.result || "")}</td>
      <td>${addMarkCell("rtf_field", `Field: ${f.instr}`.slice(0, 300), `field#${i + 1}`, f.result || "")}</td></tr>`).join(""))
    : `<p class="hint-line">No fields.</p>`;
  const dv = rtf.docvars || [];
  if (dv.length) {
    html += `<h3 class="formats-title">Document variables (${dv.length})</h3>` + table(["Name", "Value"],
      dv.map(([n, v]) => `<tr><td class="mono">${escapeHtml(n)}</td><td class="mono">${escapeHtml((v || "").slice(0, 2000))}</td></tr>`).join(""));
  }
  html += `<h3 class="formats-title">Visible text</h3><pre class="text-sample">${escapeHtml((rtf.text || "").slice(0, 12000)) || "(no text)"}</pre>`;
  return html;
}

function paneRtfMeta(rtf) {
  const att = Object.assign({}, rtf.attribution || {});
  const rsids = att.rsids || [];
  delete att.rsids;
  const up = att.user_properties || {};
  delete att.user_properties;
  const label = { creatim: "created", revtim: "revised", printim: "printed", buptim: "backed up", operator: "last saved by (operator)" };
  let html = Object.keys(att).length ? table(["Field", "Value"], Object.entries(att).map(([k, v]) =>
    `<tr><td>${escapeHtml(label[k] || k)}</td><td class="mono">${escapeHtml(String(v))}</td></tr>`).join(""))
    : `<p class="hint-line">No \\info group (builders and hand-crafted RTF often omit it).</p>`;
  if (Object.keys(up).length) {
    html += `<h3 class="formats-title">User properties</h3>` + table(["Name", "Value"],
      Object.entries(up).map(([k, v]) => `<tr><td class="mono">${escapeHtml(k)}</td><td class="mono">${escapeHtml(v)}</td></tr>`).join(""));
  }
  if (rsids.length) {
    html += `<h3 class="formats-title">Revision save ids (${att.rsid_count})</h3><p class="hint-line">Each \\rsid is one editing session; shared rsids link documents edited from the same source.</p><p class="mono">${escapeHtml(rsids.join(" "))}</p>`;
  }
  return html;
}

function panePdfMeta(pdf) {
  const md = pdf.metadata || {};
  const keys = Object.keys(md);
  if (!keys.length) return `<p class="hint-line">No document metadata.</p>`;
  return table(["Property", "Value", "Mark"],
    keys.map((k) => `<tr><td class="file">${escapeHtml(k)}</td><td>${escapeHtml(String(md[k]))}</td>
      <td>${addMarkCell("metadata", `${k}: ${md[k]}`, "pdf metadata", "")}</td></tr>`).join(""));
}

function panePdfEmbedded(pdf) {
  const items = pdf.embedded || [];
  if (!items.length) return `<p class="hint-line">No embedded files.</p>`;
  const rows = items.map((e) => `<tr>
    <td class="file">${escapeHtml(e.filename)}</td>
    <td>${fmtSize(e.size_bytes)}</td>
    <td class="mono" title="${escapeHtml(e.sha256 || "")}">${shortHash(e.sha256)}</td>
    <td>${fileActions(e.stored_path)}</td>
    <td>${addMarkCell("embedded", `Embedded file ${e.filename}`, e.stored_path || "pdf embedded", `${e.size_bytes || 0} bytes · sha256 ${e.sha256 || ""}`)}</td>
  </tr>`).join("");
  return table(["Filename", "Size", "SHA-256", "Actions", "Mark"], rows);
}

// --- Nested (recursive child analysis) --------------------------------------

const PW_SOURCE = { user: "your password", email: "the password from the email", default: "the default password",
  empty: "the empty password", email_words: "a word of the email", none: "not encrypted" };

// Encrypted children anywhere in the nested tree that could not be opened.
function lockedNested(nodes, out = []) {
  (nodes || []).forEach((n) => {
    const lk = n.unlock || n.archive;
    if (lk && lk.encrypted && !lk.decrypted) out.push(n.filename);
    lockedNested(n.children, out);
  });
  return out;
}

// Banner above the sub-tabs: how an encrypted original/archive was opened, or
// a password box to unlock it (and any encrypted attachment) and re-analyse.
function lockBanner(mods) {
  const u = mods.unlock || mods.archive;
  const locked = lockedNested((mods.nested || {}).tree);
  const pwc = (mods.email && mods.email.password_candidates) || [];
  const found = pwc.length
    ? `<div>🔑 The email gives ${pwc.length > 1 ? "passwords" : "a password"}: ${pwc.map((c) => `<span class="mono" title="${escapeHtml(c.context || "")}">'${escapeHtml(c.password)}'</span>`).join(", ")} — tried on its encrypted attachments.</div>`
    : "";
  if (!(u && u.encrypted) && !locked.length) return found ? `<div class="unlock-banner">${found}</div>` : "";
  const what = u && u.kind ? ({ office: "Office document", pdf: "PDF", zip: "ZIP archive", "7z": "7z archive" }[u.kind] || u.kind) : "";
  let msg;
  let needPw = false;
  if (u && u.encrypted && u.decrypted) {
    msg = `🔓 Encrypted ${escapeHtml(what)} (${escapeHtml(u.detail || "")}) — opened with ${escapeHtml(PW_SOURCE[u.password_source] || u.password_source)}`
      + (u.password_source !== "user" ? ` <span class="mono">'${escapeHtml(u.password || "")}'</span>` : "")
      + (u.decrypted_path ? ` · the analysis covers the <b>decrypted copy</b> <span class="mono">${escapeHtml(u.decrypted_path)}</span> ${fileActions(u.decrypted_path)}` : ` · ${(u.entries || []).filter((e) => e.stored_path).length} entries extracted`);
  } else if (u && u.encrypted) {
    needPw = true;
    msg = `🔒 Encrypted ${escapeHtml(what)} (${escapeHtml(u.detail || "")}) — none of the known passwords opened it (${u.tried || 0} tried), so its content was <b>not</b> analysed.`;
  }
  if (locked.length) {
    needPw = true;
    msg = (msg ? msg + "<br>" : "") + `🔒 Encrypted attachment(s)/entries not opened: <span class="mono">${escapeHtml(locked.join(", "))}</span>`;
  }
  // Email with attachments still locked: offer to try every word of it.
  const wl = mods.email && mods.email.wordlist;
  let words = "";
  if (needPw && mods.email && locked.length) {
    words = wl && wl.enabled
      ? `<div class="hint-line">Every word of the email was tried (${wl.candidates || 0} candidates) — none opened them.</div>`
      : `<button class="btn btn-ghost btn-sm" id="unlock-words" title="Body text, subject, attachment names, sender/recipient addresses, names and domains — every word is tried as the password. No time limit: it can take a while with many words.">🔑 Try every word of the email</button>`;
  }
  const form = needPw
    ? `<div class="unlock-form"><input type="password" id="unlock-pw" autocomplete="off" placeholder="Password">
        <button class="btn btn-primary btn-sm" id="unlock-go">Unlock &amp; re-analyse</button>
        ${words}
        <span id="unlock-status" class="status"></span></div>`
    : "";
  return `<div class="unlock-banner ${needPw ? "is-locked" : ""}">${found}${msg || ""}${form}</div>`;
}

function wireUnlock(root, analysisId) {
  const go = root.querySelector("#unlock-go");
  if (!go) return;
  const pw = root.querySelector("#unlock-pw");
  const st = root.querySelector("#unlock-status");
  const wordsBtn = root.querySelector("#unlock-words");
  // Queue the re-analysis, then reopen this case when it is done.
  const queue = async (path, body, msg) => {
    go.disabled = true;
    if (wordsBtn) wordsBtn.disabled = true;
    st.textContent = msg;
    try {
      const r = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/${path}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error((await r.json()).detail || r.status);
      startTaskPoller();
      const iv = setInterval(async () => {
        try {
          const t = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/tasks`).then((x) => x.json());
          if ((t.live || []).some((x) => ["queued", "running", "cancelling"].includes(x.state))) return;
        } catch (e) { return; }
        clearInterval(iv);
        if (_openCaseId === analysisId) openComponents(analysisId, _compState && _compState.active, _openViewId);
      }, 2500);
      return true;
    } catch (err) {
      st.textContent = "Failed: " + err.message;
      go.disabled = false;
      if (wordsBtn) wordsBtn.disabled = false;
      return false;
    }
  };
  const submit = async () => {
    if (!pw.value) { st.textContent = "Enter the password."; return; }
    if (await queue("password", { password: pw.value }, "Queued: decrypting and re-analysing…")) pw.value = "";
  };
  go.addEventListener("click", submit);
  pw.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  if (wordsBtn) wordsBtn.addEventListener("click", () => queue("wordlist", { enabled: true },
    "Queued: trying every word of the email (no time limit — see Tasks)…"));
}

// Any file no parser covers: the basic record; YARA, marks and report apply.
function paneFile(f) {
  const h = f.hashes || {};
  const rows = [
    ["File", `<span class="mono">${escapeHtml(f.filename || "")}</span> ${fileActions(f.stored_path)}`],
    ["Detected type", escapeHtml([f.detected_name, f.detected_mime].filter(Boolean).join(" · ") || "unknown")],
    ["Size", escapeHtml(f.size_bytes != null ? `${f.size_bytes} bytes` : "")],
    ...["md5", "sha1", "sha256"].filter((k) => h[k]).map((k) => [k.toUpperCase(), `<span class="mono">${escapeHtml(h[k])}</span>`]),
  ].map(([k, v]) => `<div>${k}</div><div>${v}</div>`).join("");
  return `<p class="hint-line">${escapeHtml(f.note || "")}</p>
    <div class="kv">${rows}</div>
    <p style="margin-top:10px">${addMarkCell("file", `File ${f.filename || ""}`, f.stored_path || "file", (h.sha256 || ""))}</p>`;
}

function paneArchive(arc) {
  const rows = (arc.entries || []).map((e) => `<tr>
    <td class="mono">${escapeHtml(e.name || "")}</td>
    <td>${e.size != null ? escapeHtml(String(e.size)) : ""}</td>
    <td>${e.encrypted ? "🔒" : ""}</td>
    <td>${e.skipped ? `<span class="badge badge-warn">${escapeHtml(e.skipped)}</span>` : fileActions(e.stored_path)}</td></tr>`).join("");
  const head = `<p class="hint-line">${escapeHtml(arc.detail || "")}${arc.encrypted ? (arc.decrypted
    ? ` · opened with ${escapeHtml(PW_SOURCE[arc.password_source] || "")}` : " · locked") : ""}
    ${arc.error ? ` · <span class="bad-text">${escapeHtml(arc.error)}</span>` : ""} · entries are scanned recursively (Nested tab)</p>`;
  return head + (rows ? `<table class="cases"><thead><tr><th>Entry</th><th>Size</th><th></th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : `<p class="hint-line">No entries extracted.</p>`);
}

function paneShortcut(scm) {
  const parts = (scm.items || []).map((it) => {
    let rows;
    if (it.kind === "lnk") {
      rows = kv([
        ["File", it.file], ["Target", it.target], ["Arguments", it.arguments],
        ["Command", it.command], ["Working dir", it.working_directory],
        ["Icon", it.icon_location], ["Show", it.show_command],
        ["Size", it.file_size != null ? `${it.file_size} bytes` : ""],
        ["Description", it.description], ["Creating machine ID", it.machine_id],
      ]);
    } else {
      rows = kv([
        ["File", it.file], ["URL", it.url], ["Icon file", it.icon_file],
        ["Working dir", it.working_directory],
      ]);
    }
    const err = it.error ? `<p class="bad-text">${escapeHtml(it.error)}</p>` : "";
    return `<div class="sub-item"><div class="hint-line">${escapeHtml(it.kind === "lnk" ? "Shell Link (.lnk)" : "Internet shortcut (.url)")}</div>
      ${rows}${err}${netFindingsList(it.findings || [])}</div>`;
  }).join("");
  return `<p class="hint-line">Windows shortcut — target and metadata parsed; the launched command is run through the scripting engine.</p>${parts}`;
}

// FLOSS / capa (Binary tab): one status line each, so a missing result always
// says why (skipped for PyInstaller, not provisioned, timeout, error).
function peToolLine(t) {
  if (!t) return "";
  const st = { ok: "ran", skipped: "skipped", not_provisioned: "not provisioned",
               timeout: "timed out", error: "error", none: "not packed" }[t.status] || t.status || "";
  const dur = t.duration_s != null && t.status === "ok" ? ` · ${t.duration_s}s` : "";
  const ver = t.version ? ` · v${t.version}` : "";
  return `${st}${t.detail ? ` — ${t.detail}` : ""}${ver}${dur}`;
}

function paneCapa(c) {
  if (!c || c.status !== "ok") return "";
  const caps = c.capabilities || [];
  if (!caps.length) return `<p class="hint-line">capa: no capabilities matched.</p>`;
  const rows = caps.map((x) => `<tr><td>${escapeHtml(x.name || "")}</td>
      <td class="mono">${escapeHtml(x.namespace || "")}</td>
      <td class="mono">${escapeHtml((x.attack || []).map((a) => a.id).filter(Boolean).join(", "))}</td>
      <td class="mono">${escapeHtml((x.mbc || []).join(", "))}</td>
      <td>${escapeHtml(String(x.matches || 0))}</td></tr>`).join("");
  const more = (c.total || 0) > caps.length ? ` (showing ${caps.length} of ${c.total})` : "";
  return `<details class="disclose"><summary>capa capabilities — ${escapeHtml(String(c.total || caps.length))}${escapeHtml(more)}
      · ATT&amp;CK: ${escapeHtml((c.attack_ids || []).join(", ") || "none")}</summary>
    <table class="cases"><thead><tr><th>Capability</th><th>Namespace</th><th>ATT&amp;CK</th><th>MBC</th><th>Matches</th></tr></thead>
    <tbody>${rows}</tbody></table></details>`;
}

function paneFloss(it) {
  const fl = it.floss;
  const ss = it.floss_strings || [];
  if (!fl || fl.status !== "ok") return "";
  if (!ss.length) return `<p class="hint-line">FLOSS: no decoded / stack / tight strings.</p>`;
  return `<details class="disclose"><summary>FLOSS decoded / stack / tight strings — ${escapeHtml(String(ss.length))}</summary>
    <pre class="text-sample">${escapeHtml(ss.join("\n"))}</pre></details>`;
}

// Inner tabs (one per analysis inside a sub-tab, e.g. Binary → File · pefile ·
// LIEF · FLOSS · capa). Pure CSS/DOM toggle, wired by wireInnerTabs(); the last
// choice per group is remembered while the case is open.
const _itabActive = {};
function innerTabs(group, tabs) {
  tabs = tabs.filter((t) => t && t.html);
  if (!tabs.length) return "";
  const act = tabs.some((t) => t.id === _itabActive[group]) ? _itabActive[group] : tabs[0].id;
  const bar = tabs.map((t) => `<button type="button" class="itab${t.id === act ? " is-active" : ""}"
      data-itab-group="${escapeHtml(group)}" data-itab="${escapeHtml(t.id)}">${escapeHtml(t.label)}${
      t.status ? ` <span class="itab-status itab-${escapeHtml(t.status)}">${escapeHtml(t.statusLabel || t.status)}</span>` : ""}</button>`).join("");
  const panes = tabs.map((t) => `<div class="ipane" data-ipane-group="${escapeHtml(group)}" data-ipane="${escapeHtml(t.id)}"${
      t.id === act ? "" : " hidden"}>${t.html}</div>`).join("");
  return `<div class="itabs" role="tablist">${bar}</div>${panes}`;
}

function wireInnerTabs(root) {
  root.querySelectorAll(".itab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const g = btn.getAttribute("data-itab-group"), id = btn.getAttribute("data-itab");
      _itabActive[g] = id;
      root.querySelectorAll(`.itab[data-itab-group="${CSS.escape(g)}"]`).forEach((b) =>
        b.classList.toggle("is-active", b === btn));
      root.querySelectorAll(`.ipane[data-ipane-group="${CSS.escape(g)}"]`).forEach((p) => {
        p.hidden = p.getAttribute("data-ipane") !== id;
      });
    });
  });
}

const _TOOL_STATUS = { ok: ["ok", "ran"], skipped: ["skip", "skipped"], not_provisioned: ["off", "not provisioned"],
                       not_installed: ["off", "not installed"], timeout: ["bad", "timeout"], error: ["bad", "error"],
                       unpacked: ["ok", "unpacked"], none: ["ok", "not packed"], detected: ["skip", "detected"],
                       failed: ["bad", "failed"], no_static: ["bad", "protector"],
                       debloated: ["bad", "padded"], clean: ["ok", "no padding"] };
function toolTab(id, label, rec, html) {
  const st = rec ? (_TOOL_STATUS[rec.status] || ["off", rec.status || ""]) : null;
  const line = rec ? `<p class="hint-line">${escapeHtml(peToolLine(rec))}</p>` : "";
  return { id, label, status: st ? st[0] : "", statusLabel: st ? st[1] : "", html: line + (html || "") || "<p class=\"hint-line\">No result.</p>" };
}

function itable(head, rows) {
  if (!rows.length) return "";
  return `<table class="cases"><thead><tr>${head.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td class="mono">${escapeHtml(c == null ? "" : String(c))}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function paneLief(lf) {
  if (!lf || lf.status !== "ok") return "";
  const mit = lf.mitigations || {};
  const yn = (b) => (b ? "yes" : "no");
  const chk = lf.checksum || {};
  const head = kv([
    ["Format", lf.format], ["LIEF", lf.version], ["imphash", lf.imphash],
    ["Image base", lf.imagebase], ["Entry point", lf.entrypoint], ["Linker", lf.linker], ["OS version", lf.os_version],
    ["ASLR / DEP / CFG", lf.format === "PE" ? `${yn(mit.aslr)} / ${yn(mit.dep)} / ${yn(mit.cfg)}` : ""],
    ["High-entropy VA", lf.format === "PE" ? yn(mit.high_entropy_va) : ""],
    ["Checksum", chk.declared ? `${chk.declared} (computed ${chk.computed}) ${chk.valid ? "✓" : "✗ mismatch"}` : ""],
    ["Authenticode", lf.format === "PE" ? ((lf.signatures || []).length ? `signed — ${lf.signature_check}` : "not signed") : ""],
    ["Authentihash", lf.authentihash_sha256],
    ["TLS callbacks", (lf.tls_callbacks || []).join(", ")],
    ["CFG flags", (lf.load_config || {}).guard_flags],
    ["Export name", lf.export_name],
    // ELF / Mach-O
    ["Type", lf.type], ["Machine", lf.machine || lf.cpu], ["Class", lf.class], ["Interpreter", lf.interpreter],
    ["PIE / NX", lf.format === "ELF" ? `${yn(lf.pie)} / ${yn(lf.nx)}` : ""],
    ["Linking", lf.format === "ELF" ? (lf.static ? "static" : "dynamic") + (lf.stripped ? ", stripped" : "") : ""],
    ["Code signature", lf.format === "MachO" ? yn(lf.signed) : ""],
    ["RPATH / RUNPATH", (lf.rpath || []).join("; ")],
  ]);
  const pdb = itable(["PDB path", "GUID", "Age"], (lf.pdb || []).map((p) => [p.path, p.guid, p.age]));
  const rich = lf.rich_header ? `<details class="disclose"><summary>Rich header — ${(lf.rich_header.entries || []).length} entries (key ${escapeHtml(lf.rich_header.key)})</summary>
    ${itable(["Product id", "Build", "Count"], (lf.rich_header.entries || []).map((e) => [e.id, e.build_id, e.count]))}</details>` : "";
  const sigs = (lf.signatures || []).map((sg, n) => `<details class="disclose"${n ? "" : " open"}><summary>Signature ${n + 1} — ${escapeHtml(sg.digest || "")}</summary>
    ${itable(["Subject", "Issuer", "Serial", "Valid from", "Valid to"], (sg.certificates || []).map((c) => [c.subject, c.issuer, c.serial, c.valid_from, c.valid_to]))}</details>`).join("");
  const ver = itable(["Version info", "Value"], (lf.version_info || []).map((v) => [v.key, v.value]));
  const res = (lf.resource_types || []).length ? kv([["Resource types", lf.resource_types.join(", ")], ["Icons", lf.icons]]) : "";
  const man = lf.manifest ? `<details class="disclose"><summary>Manifest</summary><pre class="text-sample">${escapeHtml(lf.manifest)}</pre></details>` : "";
  const ov = lf.overlay ? kv([["Overlay", `${lf.overlay.size} bytes at ${lf.overlay.offset} · entropy ${lf.overlay.entropy} · head ${lf.overlay.head}`]]) : "";
  const libs = (lf.libraries || []).length ? kv([["Libraries", lf.libraries.join(", ")]]) : "";
  const syms = (lf.imported || []).length ? `<details class="disclose"><summary>Imported symbols — ${lf.imported.length}</summary>
    <pre class="text-sample">${escapeHtml(lf.imported.join("\n"))}</pre></details>` : "";
  const exps = (lf.exported || []).length ? `<details class="disclose"><summary>Exported symbols — ${lf.exported.length}</summary>
    <pre class="text-sample">${escapeHtml(lf.exported.join("\n"))}</pre></details>` : "";
  const secs = lf.format !== "PE" ? itable(["Section", "Size", "Offset", "Entropy", "Flags"],
    (lf.sections || []).map((x) => [x.name, x.size, x.offset, x.entropy, (x.flags || []).join(" ")])) : "";
  return head + pdb + sigs + ver + res + man + ov + rich + libs + syms + exps + secs;
}

function paneImportsExports(it) {
  const lf = it.lief || {};
  const imps = (lf.imports || []).map((l) => `<details class="disclose"><summary>${escapeHtml(l.library)} — ${l.count}</summary>
    <pre class="text-sample">${escapeHtml((l.functions || []).join("\n"))}</pre></details>`).join("");
  const fallback = !imps && (it.imports_dll || []).length ? kv([["DLLs", it.imports_dll.join(", ")]]) : "";
  const delay = (lf.delay_imports || []).map((l) => `<details class="disclose"><summary>${escapeHtml(l.library)} (delay-load) — ${(l.functions || []).length}</summary>
    <pre class="text-sample">${escapeHtml((l.functions || []).join("\n"))}</pre></details>`).join("");
  const exps = (lf.exports || []).length
    ? itable(["Export", "Ordinal", "Forwarded to"], lf.exports.map((e) => [e.name, e.ordinal, e.forward]))
    : ((it.exports || []).length ? kv([["Exports", it.exports.join(", ")]]) : "");
  const head = `<p class="hint-line">${escapeHtml(String(it.imports_count != null ? it.imports_count : "?"))} imported function(s) from ${(lf.imports || it.imports_dll || []).length} DLL(s).</p>`;
  return head + imps + fallback + delay + (exps ? `<h4>Exports</h4>${exps}` : "");
}

function paneDebloat(d) {
  if (!d) return "";
  const mb = (n) => (n == null ? "" : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1024).toFixed(1)} KB`);
  const rows = kv([["Status", d.status], ["Method", d.method], ["Size before", mb(d.size_before)],
                   ["Size after", mb(d.size_after)], ["Junk removed", mb(d.removed)]]);
  const hint = d.status === "debloated"
    ? `<p class="hint-line">Binary padding (T1027.001) stripped with debloat. The real binary is analysed as a child — see the <strong>Nested</strong> tab (recipe <span class="mono">debloat → ${escapeHtml(d.method || "")}</span>); unpacking, FLOSS and capa run there.</p>`
    : `<p class="hint-line">debloat looks for padding (overlay junk, bloated sections/resources, junk after the signature) on PEs of 1 MB or more.</p>`;
  return hint + rows;
}

function paneUnpack(up) {
  if (!up) return "";
  const det = itable(["Packer / installer", "Detected by", "Evidence"], (up.detected || []).map((h) => [h.label, h.by, h.evidence]));
  const die = up.die ? `<p class="hint-line">Detect It Easy: ${escapeHtml(peToolLine(up.die))}</p>` : "";
  const files = itable(["Unpacked file", "Size"], (up.files || []).map((f) => [f.name, f.size]))
    + ((up.files || []).length ? `<p class="hint-line">Each unpacked file is analysed as a child — see the <strong>Nested</strong> tab (recipe <span class="mono">unpack → ${escapeHtml(up.family || up.tool || "")}</span>).</p>` : "");
  return kv([["Status", up.status], ["Detail", up.detail], ["Tool", up.tool],
             ["No static unpacker", (up.no_static || []).join(", ")]]) + die + det + files;
}

function panePeItem(it, n, fileRec) {
  const g = `bin${n}`;
  const byTool = (t) => (it.findings || []).filter((f) => f.tool === t);
  const secs = (it.sections || []).map((s) => [s.name, s.vsize, s.rawsize, s.entropy, s.wx ? "W+X" : ""]);
  const overview = kv([
    ["File", it.file], ["Size", it.size != null ? `${it.size} bytes` : ""],
    ["Looks like PE", it.is_pe ? "yes (MZ)" : "no"],
    ["Type", it.is_dll ? "DLL" : (it.is_pe ? "EXE" : "")], ["Architecture", it.machine],
    ["Subsystem", it.subsystem], ["Compiled", it.compiled], ["Entry point", it.entrypoint],
    ["Imports", it.imports_count != null ? `${it.imports_count} (${(it.imports_dll || []).slice(0, 5).join(", ")})` : ""],
    ["Exports", (it.exports || []).slice(0, 8).join(", ")],
    ["Signed", it.signed ? "yes (Authenticode)" : (it.is_pe ? "no" : "")],
  ]);
  const err = it.error ? `<p class="bad-text">${escapeHtml(it.error)}</p>` : "";
  const lf = it.lief;
  return innerTabs(g, [
    fileRec ? { id: "file", label: "File", html: paneFile(fileRec) } : null,
    { id: "findings", label: `Findings (${(it.findings || []).length})`, html: netFindingsList(it.findings || []) },
    { id: "pefile", label: "pefile", html: `<p class="hint-line">Header, sections and imports parsed with pefile.</p>${overview}${err}${netFindingsList(byTool("pe"))}` },
    { id: "sections", label: `Sections (${secs.length})`, html: itable(["Section", "Virtual size", "Raw size", "Entropy", ""], secs)
        + (lf && lf.status === "ok" && lf.format === "PE" ? `<h4>LIEF flags</h4>${itable(["Section", "Offset", "Flags"], (lf.sections || []).map((s) => [s.name, s.offset, (s.flags || []).join(" ")]))}` : "") },
    { id: "imports", label: "Imports / Exports", html: paneImportsExports(it) },
    lf ? toolTab("lief", "LIEF", lf, paneLief(lf) + netFindingsList(byTool("lief"))) : null,
    it.debloat ? toolTab("debloat", "Debloat", { status: it.debloat.status, detail: it.debloat.detail },
                         paneDebloat(it.debloat) + netFindingsList(byTool("debloat"))) : null,
    it.unpack ? toolTab("unpack", "Packer / unpack", { status: it.unpack.status,
                          detail: it.unpack.detail || (it.unpack.status === "none" ? "no packer detected" : "") },
                        paneUnpack(it.unpack) + netFindingsList(byTool("unpack"))) : null,
    it.floss ? toolTab("floss", "FLOSS", it.floss, paneFloss(it)) : null,
    it.capa ? toolTab("capa", "capa", it.capa, paneCapa(it.capa)) : null,
  ]);
}

function paneNativeItem(it, n, fileRec) {
  const lf = it.lief || {};
  return innerTabs(`bin${n}`, [
    fileRec ? { id: "file", label: "File", html: paneFile(fileRec) } : null,
    { id: "findings", label: `Findings (${(it.findings || []).length})`, html: netFindingsList(it.findings || []) },
    toolTab("lief", `LIEF (${lf.format || "?"})`, lf, paneLief(lf)),
  ]);
}

function paneMsi(msim, fileRec) {
  const parts = (msim.items || []).map((it, n) => {
    if (it.kind === "pe") {
      return `<div class="sub-item">${panePeItem(it, n, n === 0 ? fileRec : null)}</div>`;
    }
    if (it.kind === "native") {
      return `<div class="sub-item">${paneNativeItem(it, n, n === 0 ? fileRec : null)}</div>`;
    }
    const meta = it.metadata || {};
    const rows = kv([
      ["File", it.file],
      ["Tables", (it.tables || []).join(", ")],
      ["Embedded streams", (it.binary_streams || []).join(", ")],
      ["Command", it._full_code || ""],
      ...Object.keys(meta).map((k) => [`meta:${k}`, meta[k]]),
    ]);
    const err = it.error ? `<p class="bad-text">${escapeHtml(it.error)}</p>` : "";
    return `<div class="sub-item"><div class="hint-line">Windows Installer (.msi) — OLE tables decoded, strings mined into the scripting engine.</div>${rows}${err}${netFindingsList(it.findings || [])}</div>`;
  }).join("");
  return parts;
}

function paneOnenote(onm) {
  const rows = (onm.embedded || []).map((e) => `<tr>
    <td class="mono">${escapeHtml(e.name || "")}</td>
    <td>${escapeHtml(e.ext || "")}</td>
    <td>${e.size != null ? escapeHtml(String(e.size)) : ""}</td></tr>`).join("");
  const table = rows ? `<table class="cases"><thead><tr><th>Embedded file</th><th>Type</th><th>Size</th></tr></thead>
    <tbody>${rows}</tbody></table>` : "";
  return `<p class="hint-line">OneNote lure — embedded files carved from the notebook and scanned in the
    <strong>Nested</strong> tree (a fake "click to view" button hides these).</p>
    ${netFindingsList(onm.findings || [])}${table}`;
}

function paneJava(jvm) {
  const mf = jvm.manifest || {};
  const sign = jvm.signing || {};
  const web = jvm.web_xml || {};
  const meta = kv([
    ["Kind", jvm.kind],
    ["Main-Class", mf["Main-Class"]],
    ["Premain-Class", mf["Premain-Class"] || mf["Launcher-Agent-Class"] || mf["Agent-Class"]],
    ["Class-Path", mf["Class-Path"]],
    ["Signed", sign.signed ? (sign.signer || "yes") : (jvm.kind === "jar" || jvm.kind === "war" ? "no" : "")],
    ["Servlets", (web.servlets || []).join(", ")],
    ["Classes scanned", jvm.classes != null ? String(jvm.classes) : ""],
    ["JSP scanned", jvm.jsp != null ? String(jvm.jsp) : ""],
  ]);
  const head = `<p class="hint-line">Java analysis — MANIFEST, web.xml, signing and the flagged
    <code>.class</code>/JSP (constant pool, or decompiled with CFR when a JVM is present).</p>${meta}`;
  const code = (jvm.scripts || []).length
    ? paneCodeLanguage(jvm, { label: "Java", noun: "class/JSP", src: "java", markKind: "java_hit" })
    : `<p class="hint-line">No flagged classes or JSP to display.</p>${netFindingsList(jvm.findings || [])}`;
  return head + code;
}

function panePyinstaller(pim) {
  const _TYPES = { s: "entry script", m: "module", M: "package", z: "PYZ archive",
                   Z: "PYZ archive", b: "binary", x: "data", d: "dependency" };
  const rows = kv([
    ["Python version", pim.python_version || "unknown"],
    ["Bundled runtime", pim.pylib],
    ["Archive entries", String((pim.entries || []).length)],
    ["PYZ modules recovered", pim.pyz_modules != null ? String(pim.pyz_modules) : ""],
  ]);
  const entries = (pim.entries || []).slice(0, 60).map((e) => `<tr>
    <td class="mono">${escapeHtml(e.name || "")}</td>
    <td>${escapeHtml(_TYPES[e.type] || e.type || "")}</td>
    <td>${e.size != null ? escapeHtml(String(e.size)) : ""}</td></tr>`).join("");
  const table = entries ? `<table class="cases"><thead><tr><th>Entry</th><th>Type</th><th>Size</th></tr></thead>
    <tbody>${entries}</tbody></table>` : "";
  return `<p class="hint-line">PyInstaller-frozen executable — the CArchive and PYZ were unpacked and the
    recovered Python is analysed in the <strong>Python</strong> tab and the <strong>Nested</strong> tree.</p>
    ${rows}${netFindingsList(pim.findings || [])}${table}`;
}

function nestedNode(n) {
  const fcount = (n.findings || []).length;
  const worst = (n.findings || []).some((f) => f.severity === "high") ? "bad"
    : (fcount ? "warn" : "ok");
  const lk = n.unlock || n.archive;
  const lock = lk && lk.encrypted
    ? (lk.decrypted
      ? `<span class="badge badge-warn" title="${escapeHtml(lk.detail || "")}">🔓 decrypted (${escapeHtml(PW_SOURCE[lk.password_source] || lk.password_source || "")})</span>`
      : `<span class="badge badge-bad" title="${escapeHtml(lk.detail || "")}">🔒 encrypted — not opened</span>`)
    : "";
  const pwc = (n.password_candidates || []).length
    ? `<span class="badge badge-muted" title="${escapeHtml(n.password_candidates.map((c) => c.context).join("\n"))}">🔑 ${n.password_candidates.length} password(s) in body</span>` : "";
  const TAB = { javascript: "JavaScript", powershell: "PowerShell", vbscript: "VBScript", batch: "Batch", python: "Python" };
  const codeLinks = Object.keys(n.code || {}).filter((k) => TAB[k]).map((k) =>
    `<button class="btn btn-ghost btn-sm" type="button" data-pivot="${k}" title="Full analysis of this file's code (layers, behaviour hits, sandbox) in the ${TAB[k]} tab">↗ ${TAB[k]}</button>`).join("");
  const open = n.view_id
    ? `<button class="btn btn-sm nested-open" type="button" data-open-view="${escapeHtml(n.view_id)}" title="Open this file's own analysis (its tabs), like a case">Open analysis ↗</button>` : "";
  // findings collapsed behind their count (click to expand)
  const fList = fcount
    ? `<details class="nested-findings"><summary><span class="badge badge-${worst}">${fcount} finding(s)</span></summary>
        ${(n.findings || []).map((f) => `<div class="nested-finding"><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span>
          <span class="mono">${escapeHtml(f.tool)}/${escapeHtml(f.rule)}</span> ${escapeHtml(f.detail)}</div>`).join("")}
      </details>`
    : (n.kind === "other"
      ? (n.entropy != null
        ? `<span class="badge badge-${n.entropy >= 7.5 ? "warn" : "muted"}" title="Shannon entropy of the bytes (8 = random: encrypted or compressed)">opaque data · entropy ${n.entropy}${n.entropy >= 7.5 ? " (encrypted/compressed?)" : ""}</span>`
        : '<span class="badge badge-muted">not analyzable</span>')
      : '<span class="badge badge-ok">clean</span>');
  let html = `<div class="nested-card nested-${worst}">
    <div class="nested-row">
      <b class="mono nested-name">${escapeHtml(n.filename)}</b>
      <span class="badge badge-muted">${escapeHtml(n.kind)}</span>
      ${n.decrypted_from ? `<span class="badge badge-warn" title="Recovered by decrypting/decoding: ${escapeHtml(n.decrypted_from)}">🔓 decrypted stage</span>` : ""}
      ${lock}${pwc}
      ${fcount ? "" : fList}
      ${open}${codeLinks}
      <span class="nested-tools">${fileActions(n.stored_path)}
      ${addMarkCell("nested", `Nested item ${n.filename}`, n.stored_path || "nested", n.kind || "")}</span>
    </div>`;
  if (n.decrypted_from) html += `<div class="nested-origin hint-line">↳ from ${escapeHtml(n.decrypted_from)}</div>`;
  if ((n.recipe || []).length) {
    // the transformations that produced this stage, CyberChef-style
    html += `<div class="nested-origin recipe" title="Transformations that produced this file">recipe: ${n.recipe.map((r) => `<span class="badge badge-muted mono">${escapeHtml(r)}</span>`).join(" → ")}</div>`;
  }
  if (fcount) html += fList;
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
  return `<p class="hint-line">${c.nodes || tree.length} extracted item(s) scanned recursively · ${c.findings || 0} finding(s)
      <button class="btn btn-ghost btn-sm" type="button" onclick="this.closest('.subpane').querySelectorAll('details.nested-findings').forEach(e=>e.open=true)">Expand findings</button>
      <button class="btn btn-ghost btn-sm" type="button" onclick="this.closest('.subpane').querySelectorAll('details.nested-findings').forEach(e=>e.open=false)">Collapse findings</button></p>
    <div class="nested-tree">${tree.map(nestedNode).join("")}</div>`;
}

function paneOle(ole) {
  const bits = [];
  if (ole.kind) bits.push(`kind: ${ole.kind}`);
  bits.push(ole.vba ? "VBA project present" : "no VBA storage");
  let html = `<p class="hint-line">${escapeHtml(bits.join(" · "))}</p>`;
  const md = ole.metadata || {};
  if (Object.keys(md).length) {
    html += `<h3 class="formats-title">Summary information</h3>`
      + table(["Property", "Value"], Object.entries(md).map(([k, v]) =>
        `<tr><td class="file">${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join(""));
  }
  const streams = ole.streams || [];
  if (streams.length) {
    html += `<h3 class="formats-title">Streams / storages (${streams.length})</h3>`
      + table(["Path"], streams.map((s) => `<tr><td class="mono">${escapeHtml(s)}</td></tr>`).join(""));
  }
  return html;
}

let _compState = { sections: [], active: null, header: "" };
let _openViewId = null;   // a nested child opened like a case (null = the case itself)

// Kind label of a nested child's own analysis, for its direct tab; null when
// it has none worth a tab (plain data, or a script already in the code tabs).
function childTabKind(n) {
  const name = (n.filename || "").toLowerCase();
  switch (n.kind) {
    case "binary": return name.endsWith(".msi") ? "MSI" : "PE";
    case "pdf": return "PDF";
    case "ooxml": case "ole": return "Office";
    case "rtf": return "RTF";
    case "email": return "Email";
    case "shortcut": return "Shortcut";
    case "java": return "Java";
    case "onenote": return "OneNote";
    case "archive": return "Archive";
    default: return null;
  }
}

function renderSubtabs() {
  const bar = _compState.sections.map((s) =>
    `<button class="subtab${s.id === _compState.active ? " is-active" : ""}" data-sub="${s.id}">${subtabLabel(s.label)}</button>`
  ).join("");
  const sec = _compState.sections.find((s) => s.id === _compState.active) || {};
  const pane = (sec.render ? sec.render() : sec.html) || "";
  const bodyEl = document.getElementById("comp-body");
  const header = _compState.header ? `<div class="comp-header">${_compState.header}</div>` : "";
  const findBar = `<div class="code-find">
      <input id="code-find-input" type="search" autocomplete="off" spellcheck="false"
             placeholder="🔍 Find in code — VBA, JavaScript, formulas, decoded…" value="${escapeHtml(_compState.search || "")}">
      <span id="code-find-count" class="hint-line"></span>
      <button class="btn btn-ghost btn-sm" id="code-find-prev" type="button" title="Previous match">↑</button>
      <button class="btn btn-ghost btn-sm" id="code-find-next" type="button" title="Next match">↓</button>
    </div>`;
  bodyEl.innerHTML = `${header}${findBar}<div class="subtabs">${bar}</div><div class="subpane">${pane}</div>`;
  bodyEl.querySelectorAll(".subtab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sec2 = _compState.sections.find((s) => s.id === btn.getAttribute("data-sub")) || {};
      if (sec2.openView) { openComponents(_openCaseId, null, sec2.openView); return; }
      _compState.active = btn.getAttribute("data-sub");
      renderSubtabs();
    });
  });
  bodyEl.querySelectorAll("[data-fview]").forEach((btn) => {
    btn.addEventListener("click", () => {
      _findingsView = btn.getAttribute("data-fview");
      try { localStorage.setItem("dtx.findingsView", _findingsView); } catch (e) { /* per-viewer preference only */ }
      renderSubtabs();
    });
  });
  bodyEl.querySelectorAll("[data-open-view]").forEach((btn) => {
    btn.addEventListener("click", () => openComponents(_openCaseId, null, btn.getAttribute("data-open-view")));
  });
  // Wire the mark controls present in the active pane (Findings / YARA) and
  // keep the in-memory findings in sync so other panes show the new mark.
  wireMarks(bodyEl, _openCaseId, (fid, mark) => {
    (_compState.findings || []).forEach((f) => { if (f.id === fid) f.mark = mark; });
  });
  wireFileActions(bodyEl, _openCaseId);
  wireAddMarks(bodyEl, _openCaseId);
  wirePivots(bodyEl);
  wireIocs(bodyEl);
  wireNet(bodyEl, _openCaseId);
  wireUnlock(bodyEl, _openCaseId);
  wireFind(bodyEl);
  wireInnerTabs(bodyEl);
  wireMlFamily(bodyEl);
  applyFind();
}

// --- "Find in code" (lupa) --------------------------------------------------
// Searches the code the parsers extracted (VBA, JavaScript, formulas, decoded
// strings...). Matches in the open sub-tab are highlighted and navigable; the
// other code tabs get a count badge so the analyst can see where else it hits.
let _findMarks = [];
let _findIndex = -1;
let _findTotal = 0;
let _findTimer = null;

function findCorpus() {
  if (_compState.corpus) return _compState.corpus;
  const tmp = document.createElement("div");
  const corpus = {};
  (_compState.sections || []).forEach((s) => {
    let html = s.html;
    if (!html && s.render) { try { html = s.render(); } catch (e) { html = ""; } }
    tmp.innerHTML = html || "";
    corpus[s.id] = (tmp.textContent || "").toLowerCase();
  });
  _compState.corpus = corpus;
  return corpus;
}

function _countIn(text, ql) {
  if (!ql) return 0;
  let n = 0, i = text.indexOf(ql);
  while (i >= 0) { n++; i = text.indexOf(ql, i + ql.length); }
  return n;
}

function _findQuery() {
  const q = (_compState.search || "").trim();
  return q.length >= 2 ? q.toLowerCase() : "";
}

function clearFindMarks(root) {
  root.querySelectorAll("mark.find-hit").forEach((m) => {
    const parent = m.parentNode;
    parent.replaceChild(document.createTextNode(m.textContent), m);
    parent.normalize();
  });
}

function highlightContainer(el, ql, out) {
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null);
  const nodes = [];
  let n;
  while ((n = walker.nextNode())) nodes.push(n);
  nodes.forEach((node) => {
    const text = node.nodeValue;
    const lower = text.toLowerCase();
    let idx = lower.indexOf(ql);
    if (idx < 0) return;
    const frag = document.createDocumentFragment();
    let pos = 0;
    while (idx >= 0) {
      if (idx > pos) frag.appendChild(document.createTextNode(text.slice(pos, idx)));
      const mark = document.createElement("mark");
      mark.className = "find-hit";
      mark.textContent = text.slice(idx, idx + ql.length);
      frag.appendChild(mark);
      out.push(mark);
      pos = idx + ql.length;
      idx = lower.indexOf(ql, pos);
    }
    if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
    node.parentNode.replaceChild(frag, node);
  });
}

function updateFindBadges(ql) {
  const corpus = ql ? findCorpus() : {};
  document.querySelectorAll("#comp-body .subtab").forEach((btn) => {
    const id = btn.getAttribute("data-sub");
    let badge = btn.querySelector(".find-badge");
    const count = ql ? _countIn(corpus[id] || "", ql) : 0;
    if (count > 0) {
      if (!badge) { badge = document.createElement("span"); badge.className = "find-badge"; btn.appendChild(badge); }
      badge.textContent = count;
    } else if (badge) { badge.remove(); }
  });
}

function setFindCount() {
  const el = document.getElementById("code-find-count");
  if (!el) return;
  if (!_findQuery()) { el.textContent = ""; return; }
  if (_findMarks.length) {
    el.textContent = `${_findIndex + 1}/${_findMarks.length} here`
      + (_findTotal > _findMarks.length ? ` · ${_findTotal} in all tabs` : "");
  } else {
    el.textContent = _findTotal ? `0 here · ${_findTotal} in other tabs` : "no matches";
  }
}

function focusFindMark() {
  _findMarks.forEach((m, i) => m.classList.toggle("current", i === _findIndex));
  const m = _findMarks[_findIndex];
  if (m) m.scrollIntoView({ block: "center", behavior: "smooth" });
  setFindCount();
}

function applyFind() {
  const sub = document.querySelector("#comp-body .subpane");
  if (!sub) return;
  clearFindMarks(sub);
  _findMarks = []; _findIndex = -1;
  const ql = _findQuery();
  updateFindBadges(ql);
  if (!ql) { _findTotal = 0; setFindCount(); return; }
  _findTotal = (() => { const c = findCorpus(); let t = 0; Object.keys(c).forEach((k) => { t += _countIn(c[k], ql); }); return t; })();
  sub.querySelectorAll("pre, .mono, code").forEach((el) => highlightContainer(el, ql, _findMarks));
  _findMarks.forEach((m) => {
    let d = m.closest("details");
    while (d) { d.open = true; d = d.parentElement ? d.parentElement.closest("details") : null; }
  });
  if (_findMarks.length) { _findIndex = 0; focusFindMark(); } else { setFindCount(); }
}

function stepFind(dir) {
  if (!_findMarks.length) return;
  _findIndex = (_findIndex + dir + _findMarks.length) % _findMarks.length;
  focusFindMark();
}

function wireFind(root) {
  const input = root.querySelector("#code-find-input");
  if (!input) return;
  input.addEventListener("input", () => {
    _compState.search = input.value;
    clearTimeout(_findTimer);
    _findTimer = setTimeout(applyFind, 150);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); stepFind(e.shiftKey ? -1 : 1); }
  });
  const next = root.querySelector("#code-find-next");
  const prev = root.querySelector("#code-find-prev");
  if (next) next.addEventListener("click", () => stepFind(1));
  if (prev) prev.addEventListener("click", () => stepFind(-1));
}

async function openComponents(analysisId, keepTab, viewId) {
  showTab("components");
  _openCaseId = analysisId;
  _openViewId = viewId || null;
  const caseLine = document.getElementById("comp-case");
  const summary = document.getElementById("comp-summary");
  const bodyEl = document.getElementById("comp-body");
  caseLine.textContent = "Loading…";
  summary.textContent = "";
  bodyEl.innerHTML = "";
  try {
    const url = viewId
      ? `/api/cases/${encodeURIComponent(analysisId)}/nested/${encodeURIComponent(viewId)}/components`
      : `/api/cases/${encodeURIComponent(analysisId)}/components`;
    const d = await fetch(url).then((r) => r.json());
    caseLine.innerHTML = viewId
      // a nested child opened like a case: breadcrumb back to the case
      ? `<button class="btn btn-ghost btn-sm" type="button" data-back-case="${escapeHtml(analysisId)}">← Back to case</button>
         <span class="mono">${escapeHtml(analysisId)}</span> › Nested › <b>${escapeHtml(d.chain || d.filename || "")}</b>
         <span class="badge badge-muted">nested ${escapeHtml(d.kind || "")}</span>`
      : `Case <span class="mono">${escapeHtml(d.analysis_id)}</span> · ${escapeHtml(d.filename || "")} · state: ${escapeHtml(d.state || "")}`;
    const back = caseLine.querySelector("[data-back-case]");
    if (back) back.addEventListener("click", (e) => { e.preventDefault(); openComponents(analysisId, "nested"); });
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
    const oleLegacy = mods.ole;
    let nested = mods.nested;
    const iocs = d.iocs;
    const rtf = mods.rtf;
    if (!Object.keys(mods).length) {
      bodyEl.innerHTML = `<p class="hint-line">No component analysis for this case yet.</p>`;
      return;
    }
    // Prefer the server's consolidated findings (stable ids + marks);
    // fall back to the client-side collector for older cases.
    const findings = (d.findings && d.findings.length) ? d.findings : collectFindings(mods, ooxml);
    _manualByKey = {};
    findings.filter((f) => f.source === "manual").forEach((f) => {
      _manualByKey[manualKey(f.rule.replace(/^manual:/, ""), f.location || "", f.detail)] = f;
    });
    const ni = (iocs && iocs.counts && iocs.counts.total) || 0;
    let compLabel;
    if (viewId) compLabel = `nested ${d.kind || "file"}`;
    else if (email) compLabel = `${email.hop_count || 0} hops · ${email.attachment_count || 0} attachments`;
    else if (pdf) compLabel = `${pdf.page_count || 0} pages · ${(pdf.embedded || []).length} embedded`;
    else if (rtf) compLabel = `RTF · ${(rtf.objects || []).length} objects · ${(rtf.fields || []).length} fields`;
    else if (oleLegacy) compLabel = `${oleLegacy.kind || "ole"} · ${(oleLegacy.streams || []).length} streams`;
    else if (mods.file && !mods.javascript) compLabel = `${mods.file.detected_name || mods.file.detected_mime || "file"}`;
    else if (mods.archive) compLabel = `${(mods.archive.entries || []).filter((e) => e.stored_path).length} archive entries`;
    else if (!ooxml && mods.javascript) compLabel = `${(mods.javascript.scripts || []).length} script(s)`;
    else compLabel = `${(ooxml && ooxml.counts && ooxml.counts.components) || 0} parts`;
    summary.textContent = `${compLabel} · ${findings.length} findings · ${ni} IOCs`;
    summary.className = "status " + (findings.length ? "bad-text" : "ok-text");

    // Build only the sub-tabs that have content.
    const sections = [];
    const headerHtml = lockBanner(mods) + (email ? hopsTable(email) : "");
    sections.push({ id: "findings", label: `Findings (${findings.length})`, render: () => paneFindings(findings) });
    sections.push({ id: "iocs", label: `IOCs (${ni})`, html: paneIocs(iocs, mods.netcheck) });
    if (mods.netcheck && (mods.netcheck.checks || []).length) {
      sections.push({ id: "checks", label: `Checks (${mods.netcheck.checks.length})`, html: paneChecks(analysisId, mods.netcheck) });
    }
    if (email) {
      sections.push({ id: "auth", label: "Authentication", html: paneAuth(email, mods.mailrules) });
      sections.push({ id: "headers", label: `Headers (${(email.headers || []).length})`, html: paneEmailHeaders(email) });
      sections.push({ id: "attachments", label: `Attachments (${email.attachment_count || 0})`, html: paneAttachments(email, nested) });
      sections.push({ id: "body", label: "Body", html: paneEmailBody(email, mods.mailrules) });
    }
    if (mods.file) {
      sections.push({ id: "file", label: "File", html: paneFile(mods.file) });
    }
    if (mods.archive) {
      sections.push({ id: "archive", label: `Archive (${(mods.archive.entries || []).filter((e) => e.stored_path).length})`, html: paneArchive(mods.archive) });
    }
    if (oleLegacy) {
      sections.push({ id: "ole", label: "OLE", html: paneOle(oleLegacy) });
    }
    if (rtf) {
      sections.push({ id: "rtfobjects", label: `Objects (${(rtf.objects || []).length})`, html: paneRtfObjects(rtf) });
      sections.push({ id: "rtfstructure", label: "Structure", html: paneRtfStructure(rtf) });
      sections.push({ id: "rtftext", label: `Text & fields (${(rtf.fields || []).length})`, html: paneRtfText(rtf) });
      sections.push({ id: "rtfmeta", label: "Metadata", html: paneRtfMeta(rtf) });
    }
    if (pdf) {
      sections.push({ id: "pdf", label: "PDF", html: panePdf(pdf) });
      if (mods.pdftools) {
        const nqr = (mods.pdftools.qr || []).length;
        sections.push({ id: "pdftools", label: nqr ? `PDF tools (${nqr} QR)` : "PDF tools", html: panePdfTools(mods.pdftools) });
      }
      sections.push({ id: "pdfmeta", label: "Metadata", html: panePdfMeta(pdf) });
      sections.push({ id: "embedded", label: `Embedded (${(pdf.embedded || []).length})`, html: panePdfEmbedded(pdf) });
      sections.push({ id: "pdftext", label: "Text", html: `<pre class="text-sample">${escapeHtml((pdf.text_sample || "").slice(0, 8000)) || "(no text)"}</pre>` });
    }
    const netTrees = ((mods.netcheck && mods.netcheck.checks) || []).flatMap((c) =>
      [c.nested, ...(c.submissions || []).map((s) => s.nested)].filter((n) => n && (n.tree || []).length)
        .flatMap((n) => n.tree.map((t) => Object.assign({}, t, { filename: `${t.filename}  ← ${c.target}` }))));
    if (netTrees.length) {
      const base = nested || { tree: [], counts: {} };
      const merged = { tree: (base.tree || []).concat(netTrees), counts: Object.assign({}, base.counts) };
      merged.counts.nodes = (merged.counts.nodes || (base.tree || []).length) + netTrees.length;
      nested = merged;
    }
    if (nested && (nested.tree || []).length) {
      sections.push({ id: "nested", label: `Nested (${(nested.counts || {}).nodes || 0})`, html: paneNested(nested) });
      if (!viewId) {
        // a direct tab per FIRST-level child that has its own analysis
        // (deeper ones: "Open analysis" in the Nested tree)
        (nested.tree || []).filter((n) => n.view_id && childTabKind(n)).forEach((n) => {
          sections.push({ id: `child-${n.view_id}`, label: `${childTabKind(n)} · ${n.filename}`, openView: n.view_id });
        });
      }
    }
    const yara = mods.yara;
    if (yara && yara.rule_count) {
      sections.push({ id: "yara", label: `YARA (${yara.match_count || 0})`, render: () => paneYara(yara, d.yara_findings || findings, analysisId) });
    }
    const mlm = mods.ml;
    if (mlm && (mlm.items || []).length) {
      sections.push({ id: "ml", label: `Machine Learning (${(mlm.items || []).filter((x) => x.status === "ok").length})`,
                      render: () => paneMl(mlm, d.ml_findings || []) });
    }
    const jsm = mods.javascript;
    if (jsm && (jsm.scripts || []).length) {
      sections.push({ id: "javascript", label: `JavaScript (${jsm.scripts.length})`, html: paneJavascript(jsm) });
    }
    const psm = mods.powershell;
    if (psm && (psm.scripts || []).length) {
      sections.push({ id: "powershell", label: `PowerShell (${psm.scripts.length})`,
        html: paneCodeLanguage(psm, { label: "PowerShell", noun: "command", src: "powershell", markKind: "ps_hit" }) });
    }
    const vbsm = mods.vbscript;
    if (vbsm && (vbsm.scripts || []).length) {
      sections.push({ id: "vbscript", label: `VBScript (${vbsm.scripts.length})`,
        html: paneCodeLanguage(vbsm, { label: "VBScript", noun: "script", src: "vbscript", markKind: "vbs_hit" }) });
    }
    const batm = mods.batch;
    if (batm && (batm.scripts || []).length) {
      sections.push({ id: "batch", label: `Batch (${batm.scripts.length})`,
        html: paneCodeLanguage(batm, { label: "Batch", noun: "script", src: "batch", markKind: "bat_hit" }) });
    }
    const pym = mods.python;
    if (pym && (pym.scripts || []).length) {
      sections.push({ id: "python", label: `Python (${pym.scripts.length})`,
        html: paneCodeLanguage(pym, { label: "Python", noun: "module", src: "python", markKind: "py_hit" }) });
    }
    const pim = mods.pyinstaller;
    if (pim && pim.is_pyinstaller) {
      sections.push({ id: "pyinstaller", label: "PyInstaller", html: panePyinstaller(pim) });
    }
    const onm = mods.onenote;
    if (onm && onm.is_onenote) {
      sections.push({ id: "onenote", label: `OneNote (${(onm.embedded || []).length})`, html: paneOnenote(onm) });
    }
    const jvm = mods.java;
    if (jvm && (jvm.kind || (jvm.scripts || []).length || (jvm.findings || []).length)) {
      const n = (jvm.classes || 0) + (jvm.jsp || 0);
      sections.push({ id: "java", label: n ? `Java (${n})` : "Java", html: paneJava(jvm) });
    }
    const scm = mods.shortcut;
    if (scm && (scm.items || []).length) {
      sections.push({ id: "shortcut", label: `Shortcut (${scm.items.length})`, html: paneShortcut(scm) });
    }
    const msim = mods.msi;
    if (msim && (msim.items || []).length) {
      const k0 = (msim.items[0] || {}).kind;
      const isBin = k0 === "pe" || k0 === "native";
      // the generic File record lives inside Binary as its first analysis tab
      const fileIdx = isBin ? sections.findIndex((x) => x.id === "file") : -1;
      if (fileIdx >= 0) sections.splice(fileIdx, 1);
      sections.push({ id: "msi", label: isBin ? "Binary" : `MSI (${((msim.items[0] || {}).tables || []).length} tables)`,
        html: paneMsi(msim, isBin ? mods.file : null) });
    }
    const vbat = mods.vbatools;
    const vmon = mods.vipermonkey;
    if ((ole && ole.tools && ole.tools.olevba && ole.tools.olevba.macros) || vmon) {
      const nAct = vmon ? (vmon.actions || []).length : 0;
      sections.push({ id: "vba", label: vmon ? `VBA (${nAct} emulated)` : "VBA", html: paneVba(ole, vbat, vmon) });
    }
    if (ole || crypto || (xlm && xlm.available) || vbat) {
      sections.push({ id: "tools", label: "Tools", html: paneTools(ole, crypto, xlm, vbat) });
    }
    if (didier && didier.available) sections.push({ id: "didier", label: "Didier", html: paneDidier(didier) });
    if (oms && oms.available) sections.push({ id: "oms", label: "OfficeMalScanner", html: paneOms(oms) });
    if (!rtf && (sem || (ole && ole.available) || (xlm && xlm.xlm_macros))) {
      sections.push({ id: "metadata", label: "Metadata", html: paneMetadata(sem, ole, mods.officerules) });
      sections.push({ id: "content", label: "Content", html: paneContent(sem, ole, xlm) });
    }
    if (ooxml) {
      sections.push({ id: "relationships", label: `Relationships (${(ooxml.relationships || []).length})`, html: paneRelationships(ooxml.relationships) });
      sections.push({ id: "parts", label: `Parts (${(ooxml.components || []).length})`, html: paneParts(ooxml.components) });
      if ((ooxml.extracted || []).length) {
        sections.push({ id: "extracted", label: `Extracted (${ooxml.extracted.length})`, html: paneExtracted(ooxml.extracted) });
      }
    }
    // Rebuild the Findings pane now that all sub-tabs exist, so each "↗ view"
    // pivot points at a tab that is actually present for this case.
    const ids = sections.map((s) => s.id);
    const fIdx = sections.findIndex((s) => s.id === "findings");
    const fctx = { filename: d.filename, kind: viewId ? d.kind : "", tree: (nested && nested.tree) || [] };
    _ftreeChains = collectChains(fctx.tree);
    if (fIdx >= 0) sections[fIdx].render = () => paneFindings(findings, ids, fctx);
    const active = keepTab && sections.some((x) => x.id === keepTab) ? keepTab : sections[0].id;
    _compState = { sections, active, header: headerHtml, findings };
    renderSubtabs();
    if (viewId) {
      // re-runs act on the whole case: offered from the case view only
      const act = document.getElementById("comp-actions");
      if (act) act.innerHTML = `<span class="hint-line">Nested file — analysed as part of the case. Re-run from the case view.</span>`;
    } else {
      renderRerun(analysisId, d);
    }
  } catch (err) {
    bodyEl.innerHTML = `<p class="hint-line">Could not load components.</p>`; console.error("components", err);
  }
}

// Re-run control: whole case, or one module in isolation (marks preserved).
function renderRerun(analysisId, d) {
  const el = document.getElementById("comp-actions");
  if (!el) return;
  const ran = ((d.modules && Object.keys(d.modules)) || []).filter((m) => !["iocs", "netcheck"].includes(m));
  if (!ran.includes("yara")) ran.push("yara");  // YARA runs only on demand
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
    // the step being run now (live), e.g. "● nested: recursive scan…"
    const run = [...(t.steps || [])].reverse().find((s) => s.status === "running");
    const now = t.state === "running" && t.phase && !["analyzing", "network check", "queued"].includes(t.phase)
      ? escapeHtml(t.phase.split(" · ")[0].slice(0, 60)) + (run && run.detail ? ` — ${escapeHtml(run.detail)}` : "")
      : "working";
    return t.progress == null
      ? `<span class="spin" aria-label="working">●</span> ${now}`
      : `${Math.round(t.progress * 100)}%`;
  }
  return "—";
}

const STEP_STATE_CLS = {
  ok: "ok", ok_with_findings: "warn", error: "bad", unavailable: "muted", skipped: "muted", running: "warn",
};

function stepsTable(steps) {
  if (!steps || !steps.length) return `<p class="hint-line">No sub-steps recorded.</p>`;
  const rows = steps.map((s) => {
    const cls = STEP_STATE_CLS[s.status] || "muted";
    const extra = [];
    if (s.findings != null) extra.push(`${s.findings} finding(s)`);
    if (s.iocs != null) extra.push(`${s.iocs} IOC(s)`);
    if (s.status === "running" && s.detail) extra.push(`<b>${escapeHtml(s.detail)}</b>`);
    if (s.note) extra.push(escapeHtml(s.note));
    return `<tr>
      <td>${escapeHtml(s.step)}</td>
      <td><span class="badge badge-${cls}">${escapeHtml(s.status)}</span></td>
      <td class="mono">${s.duration_s != null ? fmtDuration(s.duration_s)
        : (s.status === "running" && s.started_utc ? `<span data-elapsed-from="${escapeHtml(s.started_utc)}">${fmtDuration(elapsedSince(s.started_utc))}</span>` : "")}</td>
      <td class="hint-line">${extra.join(" · ")}</td>
    </tr>`;
  }).join("");
  return table(["Sub-step (tool executed)", "Status", "Time", "Result"], rows);
}

function fmtDuration(sec) {
  if (sec == null || isNaN(sec)) return "";
  sec = Math.max(0, Number(sec));
  if (sec < 10) return `${sec.toFixed(1)}s`;
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
  return h ? `${h}h ${m}m ${s}s` : (m ? `${m}m ${s}s` : `${s}s`);
}

function elapsedSince(iso) {
  const t = Date.parse(iso);
  return isNaN(t) ? null : (Date.now() - t) / 1000;
}

function fmtWhen(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const p = (n) => String(n).padStart(2, "0");
  const today = new Date().toDateString() === d.toDateString();
  return (today ? "" : `${p(d.getDate())}/${p(d.getMonth() + 1)} `) + `${p(d.getHours())}:${p(d.getMinutes())}`;
}

// Live "running for…" counters in the Tasks tab (cheap: only existing spans).
setInterval(() => {
  document.querySelectorAll("[data-elapsed-from]").forEach((el) => {
    el.textContent = fmtDuration(elapsedSince(el.dataset.elapsedFrom));
  });
}, 1000);

function renderTasks(data) {
  const summary = document.getElementById("tasks-summary");
  const body = document.getElementById("tasks-body");
  const tasks = (data && data.tasks) || [];
  summary.textContent = `${data.active || 0} active · ${tasks.length} total`;
  summary.className = "status " + ((data.active || 0) ? "" : "ok-text");
  if (!tasks.length) { body.innerHTML = `<p class="hint-line">No tasks yet.</p>`; return; }
  body.innerHTML = tasks.map((t) => {
    const cls = TASK_STATE_CLS[t.state] || "muted";
    const target = t.target && t.target !== "full" ? t.target : "full case";
    const cancel = TASK_ACTIVE.has(t.state)
      ? `<button class="btn btn-ghost btn-sm" data-cancel="${escapeHtml(t.id)}">Cancel</button>` : "";
    const err = t.error ? `<div class="hint-line bad-text">${escapeHtml(t.error)}</div>` : "";
    // finished: how long it took; running: live elapsed time (ticks every second)
    const dur = t.duration_s != null
      ? ` · took ${fmtDuration(t.duration_s)}`
      : (t.state === "running" && t.started_utc
        ? ` · <span data-elapsed-from="${escapeHtml(t.started_utc)}">${fmtDuration(elapsedSince(t.started_utc))}</span>`
        : "");
    const when = t.finished_utc && !TASK_ACTIVE.has(t.state) ? ` · finished ${fmtWhen(t.finished_utc)}` : "";
    const nsteps = (t.steps || []).length;
    return `<details class="disclose"${TASK_ACTIVE.has(t.state) ? " open" : ""}>
      <summary>
        <span class="mono">${escapeHtml(t.id)}</span>
        <span class="file">${escapeHtml(t.filename || "")}</span>
        <span class="badge badge-${cls}">${escapeHtml(t.state)}</span>
        <span class="hint-line">${escapeHtml(t.type)} · ${escapeHtml(target)}${dur}${when}${TASK_ACTIVE.has(t.state) ? ` · ${taskProgress(t)}` : ""}${nsteps ? ` · ${nsteps} sub-steps` : ""}</span>
        ${cancel}
      </summary>
      <div style="padding:8px 10px">${err}${stepsTable(t.steps)}</div>
    </details>`;
  }).join("");
  body.querySelectorAll("[data-cancel]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
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
    <td>${markControlsHtml(f)}${f.source === "manual"
      ? `<button class="btn btn-ghost btn-sm" data-unmark="${escapeHtml(f.id)}" title="Delete this manual entry">✕ delete</button>` : ""}</td>
  </tr>`).join("");
  return table(["Severity", "Source", "Rule", "Detail", "Origin", "Mark"], rows);
}

// Free-text entry: something the analyst concluded that no tool reported,
// triaged like any finding (state + justification) and, as TP, reported.
function noteFormHtml() {
  const states = MARK_STATES.filter((x) => x.id !== "unreviewed").map((x) =>
    `<option value="${x.id}">${escapeHtml(x.label)}</option>`).join("");
  return `<details class="disclose note-box" id="note-box">
    <summary>＋ Add note (free text, not based on a finding)</summary>
    <form class="note-form" id="note-form">
      <label>Observation<input type="text" id="note-detail" maxlength="4000" required
        placeholder="e.g. Sender domain registered 2 days before the email" /></label>
      <label>Justification<textarea id="note-comment" rows="3" maxlength="4000"
        placeholder="Why you classify it this way: evidence, sources, reasoning…"></textarea></label>
      <div class="note-row">
        <label>Mark<select id="note-state">${states}</select></label>
        <label>Severity<select id="note-sev"><option value="high">high</option><option value="medium" selected>medium</option><option value="low">low</option><option value="info">info</option></select></label>
        <label class="note-where">Where (optional)<input type="text" id="note-location" maxlength="200" placeholder="e.g. body, attachment invoice.html" /></label>
        <button class="btn btn-primary" type="submit">Add</button>
        <span id="note-status" class="status"></span>
      </div>
    </form>
  </details>`;
}

function wireNoteForm(root, analysisId) {
  const form = root.querySelector("#note-form");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const status = form.querySelector("#note-status");
    const body = {
      kind: "note",
      detail: form.querySelector("#note-detail").value.trim(),
      comment: form.querySelector("#note-comment").value.trim(),
      state: form.querySelector("#note-state").value,
      severity: form.querySelector("#note-sev").value,
      location: form.querySelector("#note-location").value.trim() || "analyst note",
    };
    if (!body.detail) { status.textContent = "Write the observation first."; return; }
    const r = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/manual-findings`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) { status.textContent = "Could not add the note."; return; }
    loadMarks(analysisId);
  });
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
      `<button class="subtab${ch.id === _marksFilter ? " is-active" : ""}" data-filter="${ch.id}">${subtabLabel(ch.label)}</button>`).join("");
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
    body.innerHTML = noteFormHtml() + marksTable(shown);
    wireMarks(body, analysisId, () => loadMarks(analysisId));
    wireNoteForm(body, analysisId);
    body.querySelectorAll("[data-unmark]").forEach((b) => {
      b.addEventListener("click", async () => {
        if (!confirm("Delete this manual entry and its mark?")) return;
        await fetch(`/api/cases/${encodeURIComponent(analysisId)}/manual-findings/${encodeURIComponent(b.dataset.unmark)}`,
          { method: "DELETE" });
        loadMarks(analysisId);
      });
    });
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

// --- YARA management ---------------------------------------------------------
// Rules list / compile errors come from the cached last compilation: opening
// the tab never compiles. Long lists are collapsible, filterable and rendered
// lazily (a ruleset can hold tens of thousands of rules).
const _YARA_MAX_ROWS = 500;
let _yaraRules = [];

function yaraRuleRows(filter) {
  const q = (filter || "").toLowerCase();
  const hits = q ? _yaraRules.filter((r) => r.name.toLowerCase().includes(q)
    || (r.description || "").toLowerCase().includes(q)) : _yaraRules;
  const rows = hits.slice(0, _YARA_MAX_ROWS).map((r) => `<tr>
      <td class="mono">${escapeHtml(r.name)}</td>
      <td class="hint-line">${escapeHtml(r.description || "")}</td>
    </tr>`).join("");
  const more = hits.length > _YARA_MAX_ROWS
    ? `<p class="hint-line">Showing ${_YARA_MAX_ROWS} of ${hits.length}; refine the filter to see others.</p>` : "";
  return `<table class="cases yara-rules-table"><thead><tr><th>Rule</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>${more}`;
}

async function loadYara() {
  const summary = document.getElementById("yara-summary");
  const errors = document.getElementById("yara-errors");
  const body = document.getElementById("yara-body");
  loadYaraCases();
  try {
    const d = await fetch("/api/yara").then((r) => r.json());
    if (!d.compiled) {
      summary.textContent = "Not compiled yet";
      summary.className = "status";
      errors.innerHTML = "";
      body.innerHTML = `<p class="hint-line">Register a path or upload rules, then press Recompile.</p>`;
      return;
    }
    summary.textContent = `${d.rule_count || 0} rules · ${d.file_count || 0} files · compiled ${d.compiled_utc || ""}`
      + (d.stale ? " · rules changed, recompile" : "");
    summary.className = "status " + (d.stale ? "bad-text" : "ok-text");
    const errs = d.errors || [];
    errors.innerHTML = errs.length
      ? `<details class="disclose"${errs.length <= 10 ? " open" : ""}><summary>Compile errors (${errs.length})</summary>`
        + `<table class="cases yara-rules-table"><thead><tr><th>File</th><th>Error</th></tr></thead><tbody>`
        + errs.map((e) => `<tr><td class="mono">${escapeHtml(e.path)}</td><td class="hint-line">${escapeHtml(e.error)}</td></tr>`).join("")
        + `</tbody></table></details>`
      : "";
    _yaraRules = d.rules || [];
    if (!_yaraRules.length) { body.innerHTML = `<p class="hint-line">No rules compiled.</p>`; return; }
    body.innerHTML = `<details class="disclose" id="yara-rules-box"${_yaraRules.length <= 20 ? " open" : ""}>
        <summary>Compiled rules (${_yaraRules.length})</summary>
        <div style="padding:8px 10px"><input type="text" id="yara-filter" class="yara-path-input" placeholder="Filter by rule name or description…" />
        <div id="yara-rules-list"></div></div>
      </details>`;
    const box = document.getElementById("yara-rules-box");
    const list = document.getElementById("yara-rules-list");
    const filter = document.getElementById("yara-filter");
    const render = () => { list.innerHTML = yaraRuleRows(filter.value); };
    if (box.open) render();
    box.addEventListener("toggle", () => { if (box.open && !list.innerHTML) render(); });
    let t = null;
    filter.addEventListener("input", () => { clearTimeout(t); t = setTimeout(render, 200); });
  } catch (err) {
    summary.textContent = "Could not load YARA rules.";
  }
}

async function loadYaraCases() {
  const sel = document.getElementById("yara-case");
  if (!sel) return;
  try {
    const cases = await fetch("/api/cases").then((r) => r.json());
    const current = sel.value || _openCaseId || "";
    sel.innerHTML = cases.length
      ? cases.map((c) => `<option value="${escapeHtml(c.analysis_id)}"${c.analysis_id === current ? " selected" : ""}>${escapeHtml(c.filename || "")} · ${escapeHtml(c.analysis_id)}</option>`).join("")
      : '<option value="">(no cases)</option>';
  } catch (err) { /* keep previous options */ }
}

async function showYaraResults(analysisId) {
  const out = document.getElementById("yara-results");
  const d = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/components`).then((r) => r.json());
  const yara = (d.modules || {}).yara;
  const findings = d.yara_findings || d.findings || [];
  out.innerHTML = `<h3 class="formats-title">Results · ${escapeHtml(d.filename || "")}
      <button class="btn btn-ghost btn-sm" type="button" id="yara-open-case">Open case</button></h3>`
    + paneYara(yara, findings, analysisId);
  document.getElementById("yara-open-case").addEventListener("click", () => {
    openComponents(analysisId).then(() => {
      if ((_compState.sections || []).some((x) => x.id === "yara")) { _compState.active = "yara"; renderSubtabs(); }
    });
  });
  wireMarks(out, analysisId, (fid, mark) => {
    findings.forEach((f) => { if (f.id === fid) f.mark = mark; });
  });
  wireFileActions(out, analysisId);
}

async function scanCaseWithYara() {
  const sel = document.getElementById("yara-case");
  const status = document.getElementById("yara-scan-status");
  const btn = document.getElementById("yara-scan");
  const cid = sel && sel.value;
  if (!cid) { status.textContent = "Choose a case first."; return; }
  btn.disabled = true;
  status.textContent = "Scanning…";
  try {
    const rr = await fetch(`/api/cases/${encodeURIComponent(cid)}/rerun`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ module: "yara" }) }).then((r) => r.json());
    const tid = rr.task && rr.task.id;
    startTaskPoller();
    for (let i = 0; i < 3600 && tid; i++) {
      const t = (await fetch("/api/tasks").then((r) => r.json())).tasks.find((x) => x.id === tid) || {};
      if (["completed", "failed", "cancelled"].includes(t.state)) {
        status.textContent = t.state === "completed" ? "Scan finished." : `Scan ${t.state}.`;
        break;
      }
      status.textContent = `Scanning… (${t.state || "queued"})`;
      await new Promise((res) => setTimeout(res, 1000));
    }
    await showYaraResults(cid);
  } catch (err) {
    status.textContent = "Scan failed.";
  } finally {
    btn.disabled = false;
  }
}

// ref: gmzpt
function setupYara() {
  const fileInput = document.getElementById("yara-file");
  const fileName = document.getElementById("yara-file-name");
  if (fileInput) fileInput.addEventListener("change", () => {
    fileName.textContent = fileInput.files.length ? fileInput.files[0].name : "No file selected";
  });
  const form = document.getElementById("yara-upload-form");
  if (form) form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const status = document.getElementById("yara-add-status");
    if (!fileInput.files.length) return;
    status.textContent = "Uploading…";
    const data = new FormData();
    data.append("file", fileInput.files[0]);
    try {
      const resp = await fetch("/api/yara/upload", { method: "POST", body: data });
      const j = await resp.json();
      status.textContent = resp.ok ? `Added ${j.count} file(s). Press Recompile to compile them.` : "Upload failed.";
      fileInput.value = ""; fileName.textContent = "No file selected";
      loadYara();
    } catch (err) { status.textContent = "Upload failed."; }
  });
  const recompile = document.getElementById("yara-recompile");
  if (recompile) recompile.addEventListener("click", async () => {
    const status = document.getElementById("yara-add-status");
    const prog = document.getElementById("yara-prog");
    prog.style.display = ""; prog.value = 0;
    status.textContent = "Compiling…";
    try {
      const r = await fetch("/api/yara/compile/stream", { method: "POST" });
      const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
          if (!line) continue;
          let x; try { x = JSON.parse(line); } catch (_) { continue; }
          if (x.fatal) { status.textContent = x.fatal; prog.style.display = "none"; return; }
          if (x.done) { status.textContent = `Compiled ${x.rule_count} rules from ${x.file_count} files · ${(x.errors || []).length} error(s)`; prog.value = 100; }
          else if (x.total > 0 && x.i) { prog.value = Math.round(x.i / x.total * 100); status.textContent = `Compiling ${x.i}/${x.total} · ${x.file || ""}`; }
        }
      }
      setTimeout(() => { prog.style.display = "none"; }, 800);
      loadYara();
    } catch (err) { status.textContent = "Compile failed."; prog.style.display = "none"; }
  });
  const scanBtn = document.getElementById("yara-scan");
  if (scanBtn) scanBtn.addEventListener("click", scanCaseWithYara);
  const pathBtn = document.getElementById("yara-path-btn");
  if (pathBtn) pathBtn.addEventListener("click", async () => {
    const status = document.getElementById("yara-add-status");
    const path = document.getElementById("yara-path").value.trim();
    if (!path) return;
    status.textContent = "Registering…";
    try {
      const resp = await fetch("/api/yara/path", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }) });
      const j = await resp.json();
      status.textContent = resp.ok ? `Registered · ${j.rule_files || 0} rule file(s). Press Recompile to compile them.` : (j.detail || "Failed.");
      loadYara();
    } catch (err) { status.textContent = "Failed."; }
  });
}

// YARA results as collapsible per-rule cards. Each hit (rule x file) is a
// finding triaged right here with a mark (TP / FP / ...); only TP reaches the
// report. A card shows the rule source, what matched and the local file path.
// Hexdump of the bytes around a match (16 per line: offset, hex, ASCII), with
// the matched bytes highlighted, to judge true vs false positive.
function hexContext(x) {
  const c = x.context || {};
  const hex = c.data || "";
  const start = c.start || 0;
  const mFrom = x.offset, mTo = x.offset + Math.max(1, x.length || 1);
  const lines = [];
  for (let i = 0; i < hex.length / 2; i += 16) {
    const off = start + i;
    let h = "", a = "";
    for (let j = 0; j < 16; j++) {
      const k = i + j;
      if (k * 2 >= hex.length) { h += "   "; continue; }
      const byte = parseInt(hex.substr(k * 2, 2), 16);
      const ch = byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".";
      const inMatch = off + j >= mFrom && off + j < mTo;
      const hb = hex.substr(k * 2, 2) + " ";
      h += inMatch ? `<mark>${hb}</mark>` : hb;
      a += inMatch ? `<mark>${escapeHtml(ch)}</mark>` : escapeHtml(ch);
    }
    lines.push(`${off.toString(16).padStart(8, "0")}  ${h} ${a}`);
  }
  return `<pre class="hexdump">${lines.join("\n")}</pre>`;
}

function paneYara(yara, findings, analysisId) {
  if (!yara) return `<p class="hint-line">YARA did not run for this case.</p>`;
  if (!yara.rule_count) return `<p class="hint-line">${escapeHtml(yara.error || "No compiled YARA rules.")} Compile rules in the YARA tab, then scan the case.</p>`;
  const scanned = yara.scanned || [];
  let html = `<p class="hint-line">${yara.rule_count} rule(s) · ${yara.files_scanned} file(s) scanned · ${yara.match_count} match(es). Runs automatically on every analysed object (original, extracted, nested, decoded stages). <b>Hits are not findings until you mark them</b> (True positive, False positive, …): a marked hit joins Findings, and True positives reach the report.</p>`;
  if (!scanned.length) return html + `<p class="hint-line">No matches.</p>`;
  const byId = {};
  (findings || []).forEach((f) => { byId[f.id] = f; });
  const info = yara.rules_info || {};
  const byRule = {};
  scanned.forEach((s) => (s.matches || []).forEach((m) => {
    const key = `${m.namespace || ""}:${m.rule}`;
    const g = (byRule[key] ||= { rule: m.rule, namespace: m.namespace, tags: m.tags || [],
      meta: m.meta || {}, info: info[key] || {}, hits: [] });
    g.hits.push({ file: s.file, path: s.path || "", stored: s.stored_path || "",
      strings: m.strings || [], finding: byId[m.finding_id] });
  }));
  // Expand/Collapse act on the pane they live in (case view or YARA tab).
  const exportBtn = analysisId
    ? ` <a class="btn btn-ghost btn-sm" href="/api/cases/${encodeURIComponent(analysisId)}/yara.csv">Export CSV</a>`
    : "";
  html += '<div class="row" style="margin:4px 0 10px"><button class="btn btn-ghost btn-sm" type="button" onclick="this.closest(\'.yara-pane\').querySelectorAll(\'details\').forEach(e=>e.open=true)">Expand all</button> <button class="btn btn-ghost btn-sm" type="button" onclick="this.closest(\'.yara-pane\').querySelectorAll(\'details.yara-card\').forEach(e=>e.open=false)">Collapse all</button>' + exportBtn + '</div>';
  Object.values(byRule).forEach((g) => {
    const tags = g.tags.length ? ` · ${escapeHtml(g.tags.join(" "))}` : "";
    const states = g.hits.map((h) => (h.finding && h.finding.mark && h.finding.mark.state) || "unreviewed");
    const marked = states.filter((x) => x !== "unreviewed").length;
    const desc = g.meta.description || g.meta.desc || "";
    const src = g.info.source
      ? `<details class="disclose"><summary>Rule source · <span class="mono">${escapeHtml(g.info.file || "")}</span></summary><pre class="text-sample">${escapeHtml(g.info.source)}</pre></details>`
      : `<p class="hint-line">Rule file: <span class="mono">${escapeHtml(g.info.file || "unknown")}</span> (source not available)</p>`;
    const hits = g.hits.map((h) => {
      const rows = h.strings.map((x) => `<tr>
        <td class="mono">${escapeHtml(x.id || "")}</td>
        <td class="mono">${x.offset != null ? "0x" + Number(x.offset).toString(16) + " (" + x.offset + ")" : ""}</td>
        <td>${x.length != null ? x.length : ""}</td>
        <td class="mono">${escapeHtml(x.text || "")}</td>
        <td class="mono">${escapeHtml((x.data || "").replace(/(..)/g, "$1 ").trim())}</td>
        <td>${x.context ? `<details class="yara-ctx" open><summary>context</summary>${hexContext(x)}</details>` : ""}</td>
      </tr>`).join("");
      const mark = h.finding ? markControlsHtml(h.finding) : '<span class="hint-line">re-run YARA to mark</span>';
      return `<div class="yara-hit">
        <div class="yara-hit-head">
          <span><strong>${escapeHtml(h.file)}</strong> · <span class="mono">${escapeHtml(h.path)}</span></span>
          ${fileActions(h.stored)}
        </div>
        ${mark}
        ${rows ? table(["String", "Offset", "Length", "Matched (text)", "Matched (hex)", "Context"], rows)
               : '<p class="hint-line">Condition-only match (no strings).</p>'}
      </div>`;
    }).join("");
    html += `<details class="disclose yara-card">
      <summary>
        <span class="mono">${escapeHtml(g.rule)}</span>
        <span class="badge badge-muted">${marked}/${g.hits.length} marked</span>
        <span class="hint-line">${escapeHtml(g.namespace || "")} · ×${g.hits.length}${tags}${desc ? " · " + escapeHtml(desc) : ""}</span>
      </summary>
      <div style="padding:8px 10px">${src}${hits}</div>
    </details>`;
  });
  return `<div class="yara-pane">${html}</div>`;
}

// --- Machine Learning (EMBER2024) ---------------------------------------------------
// One row per classified object (original + nested PE / PDF / ELF); each row opens
// with the score, the calibrated threshold and WHY (feature blocks + top features).
// Like YARA: not a finding until the analyst marks it.
function paneMl(ml, findings) {
  const byId = {};
  (findings || []).forEach((f) => { byId[f.id] = f; });
  const items = ml.items || [];
  const pct = (x) => (x == null ? "" : `${(100 * x).toFixed(1)}%`);
  const head = `<p class="hint-line">Static classifier <b>${escapeHtml(ml.engine || "EMBER2024 · LightGBM")}</b> on every PE, .NET, PDF and ELF object of the case
    (original, extracted, unpacked, debloated, decrypted). The score is compared with a threshold calibrated at a <b>1% false-positive rate</b>
    on the EMBER2024 test set of that file type. It is a <b>complementary indicator, not a verdict</b>: on evasive malware that no antivirus
    detected at first (EMBER2024 challenge set) only part is caught at that threshold (shown per model).
    <b>Results are not findings until you mark them</b>; a marked result joins Findings and True positives reach the report.</p>`;
  const extras = `<p class="hint-line">Tag models: ${escapeHtml((ml.tag_models || []).join(", ") || "not installed")} ·
    family model: ${ml.family_model ? "installed"
      : `not installed <button class="btn btn-ghost btn-sm" type="button" data-ml-family>Download family model (459 MB)</button>
         <span class="hint-line" data-ml-family-state></span>`}</p>`;
  if (!items.length) return head + extras + `<p class="hint-line">${escapeHtml(ml.detail || "No PE, PDF or ELF object in this case.")}</p>`;
  const rows = items.map((it, i) => {
    const f = byId[it.finding_id];
    const verdict = it.status !== "ok" ? `<span class="badge badge-muted">${escapeHtml(it.status)}</span>`
      : it.threshold == null ? '<span class="badge badge-muted">uncalibrated</span>'
      : it.score >= it.threshold ? '<span class="badge badge-bad">above threshold</span>'
      : '<span class="badge badge-ok">below threshold</span>';
    const mk = f && f.mark && f.mark.state && f.mark.state !== "unreviewed" ? `<span class="badge badge-muted">${escapeHtml(f.mark.state)}</span>` : "";
    return `<details class="disclose ml-item"${i === 0 && it.status === "ok" ? " open" : ""}>
      <summary>
        <span class="mono">${escapeHtml(it.label || "")}</span>
        <span class="hint-line">${escapeHtml(it.format || it.file_type || "")}</span>
        ${it.status === "ok" ? `<span class="mono"><b>${escapeHtml(it.score.toFixed(4))}</b></span>` : ""}
        ${verdict} ${mk}
        ${(((it.labels || {}).family || [])[0] || {}).confidence === "high" ? `<span class="hint-line">family? ${escapeHtml(it.labels.family[0].name)}</span>` : ""}
      </summary>
      <div style="padding:8px 10px">${mlDetail(it, f, pct)}</div>
    </details>`;
  }).join("");
  return `<div class="ml-pane">${head}${extras}${rows}</div>`;
}

// "Download family model": background download in the web service, polled here;
// when it is done the Machine Learning module is re-run for this case.
function wireMlFamily(root) {
  const btn = root.querySelector("[data-ml-family]");
  if (!btn) return;
  const out = root.querySelector("[data-ml-family-state]");
  const mb = (n) => `${Math.round((n || 0) / 1048576)} MB`;
  let started = false;
  const poll = async () => {
    const st = await fetch("/api/settings/ml/family").then((r) => r.json()).catch(() => ({}));
    if (st.state === "downloading") {
      btn.disabled = true;
      out.textContent = `downloading ${mb(st.done)} / ${mb(st.total || st.size)}…`;
      setTimeout(poll, 1500);
    } else if ((st.installed || st.state === "done") && !started) {
      btn.textContent = "Re-run Machine Learning with families";
      btn.disabled = false;
      out.textContent = "family model already downloaded.";
    } else if (st.installed || st.state === "done") {
      out.textContent = "downloaded — re-running Machine Learning…";
      const r = await fetch(`/api/cases/${encodeURIComponent(_openCaseId)}/rerun`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ module: "ml" }) });
      out.textContent = r.ok ? "downloaded — Machine Learning re-run queued (Tasks); reopen the case when it finishes."
                             : "downloaded — re-run Machine Learning from the case to see families.";
    } else if (st.state === "error") {
      btn.disabled = false;
      out.textContent = `error: ${st.error || "download failed"}`;
    }
  };
  btn.addEventListener("click", async () => {
    if (started) return;
    started = true;
    btn.disabled = true;
    out.textContent = "starting…";
    await fetch("/api/settings/ml/family", { method: "POST" });
    poll();
  });
  poll();
}

const _ML_KIND = { family: "Family", behavior: "Behaviour", packer: "Packer / protector",
                   file_property: "File property", exploit: "Exploit", group: "Threat group" };
function mlLabels(it) {
  const lab = it.labels || {};
  const kinds = Object.keys(_ML_KIND).filter((k) => (lab[k] || []).length);
  if (!kinds.length) return "";
  const chip = (x) => `<span class="badge ${x.confidence === "high" ? "badge-ok" : "badge-muted"}" title="model probability ${(100 * x.prob).toFixed(1)}% · name ${escapeHtml(x.confidence)} confidence">${escapeHtml(x.name)} ${(100 * x.prob).toFixed(0)}%</span>`;
  const rows = kinds.map((k) => `<div><span class="hint-line">${_ML_KIND[k]}</span></div><div>${lab[k].map(chip).join(" ")}</div>`).join("");
  return `<h4>What it looks like</h4>
    <p class="hint-line">EMBER2024 family and tag models. Their output names were <b>reconstructed by DocuTraceX</b> (the authors did not publish them)
      by matching each output with labelled EMBER2024 files — green: high-confidence name, grey: medium. Hints for triage, trained on malware only.</p>
    <div class="kv">${rows}</div>`;
}

function mlDetail(it, f, pct) {
  if (it.status !== "ok") return `<p class="hint-line">${escapeHtml(it.detail || it.status)}</p>`;
  const m = it.metrics || {};
  const info = kv([
    ["Object", it.label], ["Model", it.model], ["Score", it.score.toFixed(6)],
    ["Threshold (1% FPR)", it.threshold != null ? it.threshold.toFixed(6) : "not calibrated"],
    ["Detection at that threshold", m["tpr_at_fpr_0.01"] != null ? `${pct(m["tpr_at_fpr_0.01"])} of the EMBER2024 test malware` : ""],
    ["On evasive malware", m.challenge_detected_at_1pct_fpr != null ? `${pct(m.challenge_detected_at_1pct_fpr)} of the challenge set` : ""],
    ["Recipe", (it.recipe || []).join(" → ")],
  ]);
  const mark = f ? markControlsHtml(f) : '<span class="hint-line">re-run Machine Learning to mark</span>';
  const blocks = Object.entries(it.blocks || {}).filter(([, v]) => Math.abs(v) >= 0.01);
  const max = Math.max(0.0001, ...blocks.map(([, v]) => Math.abs(v)));
  const bars = blocks.map(([k, v]) => `<div class="ml-bar"><span class="ml-bar-label">${escapeHtml(k)}</span>
      <span class="ml-bar-track"><span class="ml-bar-fill ${v > 0 ? "ml-pos" : "ml-neg"}" style="width:${(100 * Math.abs(v) / max).toFixed(1)}%"></span></span>
      <span class="mono">${v > 0 ? "+" : ""}${v.toFixed(2)}</span></div>`).join("");
  const top = itable(["Feature", "Block", "Value", "Contribution", "In this file"],
    (it.top_features || []).map((t) => [t.feature, t.block, Number.isInteger(t.value) ? t.value : t.value.toFixed(4),
      `${t.contribution > 0 ? "+" : ""}${t.contribution.toFixed(3)} ${t.contribution > 0 ? "→ malicious" : "→ benign"}`,
      (t.matches || []).join(", ")]));
  return `${mark}${info}${mlLabels(it)}
    <h4>Why — contribution by feature block</h4>
    <p class="hint-line">LightGBM TreeSHAP: positive pushes towards malicious, negative towards benign (log-odds; base ${escapeHtml((it.bias || 0).toFixed(2))}).</p>
    <div class="ml-bars">${bars}</div>
    <h4>Top features</h4>${top}`;
}

// --- Settings (network) --------------------------------------------------------
async function loadSettings() {
  const st = document.getElementById("settings-status");
  try {
    const n = await fetch("/api/settings/network").then((r) => r.json());
    const p = n.proxy || {};
    document.getElementById("proxy-enabled").checked = !!p.enabled;
    document.getElementById("proxy-scheme").value = p.scheme || "http";
    document.getElementById("proxy-host").value = p.host || "";
    document.getElementById("proxy-port").value = p.port || "";
    document.getElementById("proxy-user").value = p.username || "";
    const pw = document.getElementById("proxy-pass");
    pw.value = "";
    pw.placeholder = p.password_set ? "unchanged (saved)" : "";
    const fi = p.free_info || {};
    st.textContent = n.proxy_active
      ? `Proxy active: ${p.scheme}://${p.host}:${p.port}` + (p.free ? ` · free proxy${fi.country ? " " + fi.country : ""}${fi.egress_ip ? " · exit IP " + fi.egress_ip : ""}${fi.latency_ms ? " · " + fi.latency_ms + " ms" : ""}` : "")
      : "No proxy";
    if (p.free) document.getElementById("free-proto").value = p.scheme;
    const fl = n.free_lists || {};
    document.getElementById("free-lists").textContent = "Free lists: " + ["http", "socks4", "socks5"].map((k) =>
      `${k.toUpperCase()} ${(fl[k] || {}).count || 0}${(fl[k] || {}).fetched ? " (" + fl[k].fetched + ")" : ""}`).join(" · ");
    st.className = "status " + (n.proxy_active ? "ok-text" : "bad-text");
    const risk = document.getElementById("risk-line");
    risk.innerHTML = n.risk_accepted
      ? `You chose to run network checks without a proxy (from this machine's IP). <button class="btn btn-ghost btn-sm" type="button" id="risk-reset">Ask again</button>`
      : "Without a proxy, DocuTraceX asks once before the first network check.";
    const rr = document.getElementById("risk-reset");
    if (rr) rr.addEventListener("click", async () => { await putNetwork({ risk_accepted: false }); loadSettings(); });
    const db = n.ipdb || {};
    document.getElementById("ipdb-line").innerHTML =
      `DB-IP Lite ASN: ${escapeHtml(db.dbip_asn || "missing")} · country: ${escapeHtml(db.dbip_country || "missing")} · iptoasn: ${escapeHtml(db.ip2asn || "missing")} · Chromium: ${n.chromium ? "tools/playwright" : "not provisioned"}<br>${escapeHtml(db.attribution || "")}`;
    renderTlds(n.tlds);
  } catch (err) { st.textContent = "Could not load settings."; }
}

function renderTlds(t) {
  t = t || {};
  document.getElementById("tlds-line").textContent = t.source === "iana"
    ? `Official IANA list: ${t.count} TLDs (updated ${t.updated}). Used to validate domains, URLs and emails in IOCs.`
    : "IANA list not downloaded yet: using a built-in list (any 2-letter TLD + common generic ones).";
}

document.getElementById("tlds-refresh").addEventListener("click", async (ev) => {
  const btn = ev.currentTarget, msg = document.getElementById("tlds-msg");
  btn.disabled = true; msg.className = "status"; msg.textContent = "Downloading…";
  try {
    const r = await fetch("/api/settings/tlds/refresh", { method: "POST" });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail || r.statusText);
    renderTlds(j); msg.className = "status ok-text"; msg.textContent = "Updated.";
  } catch (err) { msg.className = "status bad-text"; msg.textContent = String(err.message || err); }
  btn.disabled = false;
});

function proxyFormValues() {
  const pw = document.getElementById("proxy-pass").value;
  return {
    enabled: document.getElementById("proxy-enabled").checked,
    scheme: document.getElementById("proxy-scheme").value,
    host: document.getElementById("proxy-host").value.trim(),
    port: parseInt(document.getElementById("proxy-port").value, 10) || 0,
    username: document.getElementById("proxy-user").value.trim(),
    password: pw ? pw : null,   // null = keep the saved one
  };
}

async function putNetwork(body) {
  const r = await fetch("/api/settings/network", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(j.detail || "error");
  return j;
}

async function connectFreeProxy(rotate) {
  const status = document.getElementById("free-status");
  const btns = [document.getElementById("free-connect"), document.getElementById("free-rotate")];
  btns.forEach((b) => { b.disabled = true; });
  status.className = "status";
  status.textContent = "Testing random proxies from the list (up to ~90 s)…";
  try {
    const r = await fetch("/api/settings/network/free-proxy", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ protocol: document.getElementById("free-proto").value,
        country: document.getElementById("free-country").value.trim(), rotate }) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail || "error");
    const f = j.found;
    status.textContent = `Connected: ${f.protocol}://${f.host}:${f.port}${f.country ? " (" + f.country + ")" : ""} · exit IP ${f.egress_ip} · ${f.latency_ms} ms · ${f.tried} tested in ${f.search_s}s`;
    status.className = "status ok-text";
    loadSettings();
    loadDiagnostics();
  } catch (err) {
    status.textContent = String(err.message || err);
    status.className = "status bad-text";
  } finally {
    btns.forEach((b) => { b.disabled = false; });
  }
}

function setupSettings() {
  const form = document.getElementById("proxy-form");
  if (!form) return;
  document.getElementById("free-connect").addEventListener("click", () => connectFreeProxy(false));
  document.getElementById("free-rotate").addEventListener("click", () => connectFreeProxy(true));
  const status = document.getElementById("proxy-status");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await putNetwork({ proxy: proxyFormValues() });
      status.textContent = "Saved.";
      status.className = "status ok-text";
      loadSettings();
      loadDiagnostics();
    } catch (err) { status.textContent = err.message; status.className = "status bad-text"; }
  });
  document.getElementById("proxy-test").addEventListener("click", async () => {
    status.textContent = "Testing…";
    status.className = "status";
    const v = proxyFormValues();
    try {
      const r = await fetch("/api/settings/network/test", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(v.enabled ? { proxy: v } : {}) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || "error");
      status.textContent = j.ok ? `Public IP ${j.ip} (${j.via}, ${j.elapsed_s}s)` : `Failed (${j.via}): ${j.error}`;
      status.className = "status " + (j.ok ? "ok-text" : "bad-text");
    } catch (err) { status.textContent = err.message; status.className = "status bad-text"; }
  });
}

// --- Modal ---------------------------------------------------------------------
function showModal(title, bodyHtml, actions) {
  const m = document.getElementById("modal");
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML = bodyHtml;
  const box = document.getElementById("modal-actions");
  box.innerHTML = "";
  return new Promise((resolve) => {
    actions.forEach((a) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "btn " + (a.primary ? "btn-primary" : "btn-ghost");
      b.textContent = a.label;
      b.addEventListener("click", () => { m.hidden = true; resolve(a.value); });
      box.appendChild(b);
    });
    m.hidden = false;
    box.querySelector("button:last-child").focus();
  });
}

// Before anything goes to the Internet: proxy configured, or risk accepted once.
async function ensureNetConsent() {
  const n = await fetch("/api/settings/network").then((r) => r.json());
  if (n.proxy_active || n.risk_accepted) return true;
  const choice = await showModal("No proxy configured",
    `<p>Network checks contact the URL, domain or IP being investigated. Without a proxy they leave from <b>this machine's public IP</b>, which the attacker can see (and may use to tell an analyst from a victim).</p>
     <p>Configure a proxy (HTTP, HTTPS or SOCKS5/Tor) or continue under your own responsibility. You will not be asked again; you can change it in Settings.</p>`,
    [{ label: "Cancel", value: "cancel" }, { label: "Configure proxy", value: "config" },
     { label: "Continue at my own risk", value: "risk", primary: true }]);
  if (choice === "config") { showTab("settings"); loadSettings(); return false; }
  if (choice === "risk") { await putNetwork({ risk_accepted: true }); return true; }
  return false;
}

// Queue a network check, wait for it, then reopen the case on the Checks tab.
async function runNetCheck(analysisId, payload, btn) {
  if (!(await ensureNetConsent())) return;
  const label = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "Queued…"; }
  try {
    const r = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/netcheck`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail || "error");
    const tid = j.task.id;
    startTaskPoller();
    let t = {};
    for (let i = 0; i < 900; i++) {
      t = (await fetch("/api/tasks").then((x) => x.json())).tasks.find((x) => x.id === tid) || {};
      if (["completed", "failed", "cancelled"].includes(t.state)) break;
      if (btn) btn.textContent = t.state === "running" ? "Checking…" : "Queued…";
      await new Promise((res) => setTimeout(res, 1000));
    }
    if (t.state !== "completed") throw new Error(t.error || t.state || "failed");
    await openComponents(analysisId, "checks");
  } catch (err) {
    if (btn) { btn.disabled = false; btn.textContent = "Failed — retry"; btn.title = String(err.message || err); }
    return;
  }
  if (btn) { btn.disabled = false; btn.textContent = label; }
}

function netKindOf(iocType) {
  return { url: "url", domain: "domain", ipv4: "ip", ipv6: "ip" }[iocType] || null;
}

function netButton(kind, target, label) {
  return `<button class="btn btn-ghost btn-sm net-btn" type="button" data-net-kind="${escapeHtml(kind)}" data-net-target="${escapeHtml(target)}">${escapeHtml(label || "Check")}</button>`;
}

function wireNet(root, analysisId) {
  if (!analysisId) return;
  root.querySelectorAll("[data-net-kind]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const p = { kind: btn.getAttribute("data-net-kind") };
      if (btn.hasAttribute("data-net-target")) p.target = btn.getAttribute("data-net-target");
      if (btn.hasAttribute("data-net-check")) p.check_id = btn.getAttribute("data-net-check");
      if (btn.hasAttribute("data-net-form")) p.form = parseInt(btn.getAttribute("data-net-form"), 10);
      runNetCheck(analysisId, p, btn);
    });
  });
  const all = root.querySelector("[data-net-all]");
  if (all) {
    all.addEventListener("click", async () => {
      if (!(await ensureNetConsent())) return;
      const targets = JSON.parse(all.getAttribute("data-net-all"));
      all.disabled = true;
      const ids = [];
      for (let i = 0; i < targets.length; i++) {
        const [kind, target] = targets[i];
        all.textContent = `Queuing ${i + 1}/${targets.length}…`;
        const r = await fetch(`/api/cases/${encodeURIComponent(analysisId)}/netcheck`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind, target }) });
        if (r.ok) ids.push((await r.json()).task.id);
      }
      startTaskPoller();
      for (let n = 0; n < 1800; n++) {
        const tasks = (await fetch("/api/tasks").then((x) => x.json())).tasks.filter((t) => ids.includes(t.id));
        const done = tasks.filter((t) => ["completed", "failed", "cancelled"].includes(t.state)).length;
        all.textContent = `Checking… ${done}/${ids.length}`;
        if (done >= ids.length) break;
        await new Promise((res) => setTimeout(res, 1000));
      }
      await openComponents(analysisId, "checks");
    });
  }
  root.querySelectorAll("[data-preview]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const box = btn.parentElement.querySelector(".net-preview-box");
      if (box.innerHTML) { box.innerHTML = ""; btn.textContent = "Safe preview"; return; }
      const src = `/api/cases/${encodeURIComponent(analysisId)}/netcheck/asset?path=${encodeURIComponent(btn.getAttribute("data-preview"))}`;
      box.innerHTML = `<iframe class="net-preview" sandbox="" referrerpolicy="no-referrer" src="${src}" title="Safe preview"></iframe>`;
      btn.textContent = "Hide preview";
    });
  });
}

// --- Checks pane -----------------------------------------------------------------
function netAsset(analysisId, rel) {
  return `/api/cases/${encodeURIComponent(analysisId)}/netcheck/asset?path=${encodeURIComponent(rel)}`;
}

function kv(pairs) {
  return `<div class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `<div>${escapeHtml(k)}</div><div class="mono">${escapeHtml(String(v))}</div>`).join("")}</div>`;
}

function netFindingsList(fs) {
  if (!fs.length) return `<p class="hint-line">No findings.</p>`;
  return fs.map((f) => `<div class="nested-finding"><span class="badge badge-${SEV_CLASS[f.severity] || "warn"}">${escapeHtml(f.severity)}</span>
    <span class="mono">${escapeHtml(f.rule)}</span> ${escapeHtml(f.detail)}${f.evidence ? `<div class="hint-line mono">${escapeHtml(f.evidence).slice(0, 600)}</div>` : ""}</div>`).join("");
}

function netViewHtml(analysisId, v, title, rec, isDesktop) {
  if (!v) return "";
  let h = `<div class="net-view"><h4>${escapeHtml(title)}</h4>`;
  if (v.error) h += `<p class="bad-text">${escapeHtml(v.error)}</p>`;
  h += kv([["Status", v.status], ["Final URL", v.final_url], ["Type", v.content_type], ["Size", v.size != null ? `${v.size} bytes${v.truncated ? " (truncated)" : ""}` : ""],
    ["SHA-256", v.sha256], ["Time", v.elapsed_s != null ? `${v.elapsed_s}s` : ""], ["User-Agent", v.user_agent]]);
  const hops = v.hops || [];
  if (hops.length) {
    h += `<p class="hint-line"><b>Redirect chain</b></p><ol class="hop-list">${hops.map((x) => `<li><span class="mono">${x.status}</span> ${escapeHtml(x.url)}${x.meta_refresh ? " (meta refresh)" : ""}${x.tls_error ? ' <span class="bad-text">invalid TLS</span>' : ""}</li>`).join("")}</ol>`;
    const tls = hops.map((x) => x.tls).filter(Boolean).pop();
    if (tls) h += `<p class="hint-line"><b>TLS certificate</b></p>` + kv([["Subject", tls.subject], ["Issuer", `${tls.issuer} (${tls.issuer_org})`], ["Valid", `${tls.not_before} → ${tls.not_after}`], ["SANs", (tls.sans || []).slice(0, 10).join(", ")]]);
  }
  const pg = v.page;
  if (pg) {
    h += `<p class="hint-line"><b>Page</b></p>` + kv([["Title", pg.title], ["Brands", (pg.brands || []).join(", ")], ["Meta refresh", pg.meta_refresh],
      ["Scripts", `${(pg.inline_scripts || []).length} inline, ${(pg.scripts_src || []).length} external`], ["Iframes", (pg.iframes || []).join(", ")]]);
    (pg.forms || []).forEach((f, i) => {
      const fields = (f.inputs || []).filter((x) => x.type !== "hidden").map((x) => `${x.name || "?"}:${x.type}`).join(", ");
      h += `<div class="ident-box"><b>Form #${i + 1}</b> ${f.has_password ? '<span class="badge badge-bad">password</span>' : ""} ${f.external ? '<span class="badge badge-warn">other host</span>' : ""}
        <div class="mono">${escapeHtml(f.method)} ${escapeHtml(f.action)}</div><div class="hint-line">fields: ${escapeHtml(fields)} · hidden: ${(f.inputs || []).filter((x) => x.type === "hidden").length}</div>
        ${isDesktop ? `<button class="btn btn-ghost btn-sm" type="button" data-net-kind="submit" data-net-check="${rec.id}" data-net-form="${i}" title="Sends the fake identity (never real data) through this form">Send fake credentials</button>` : ""}</div>`;
    });
    if ((pg.links || []).length) {
      h += `<details class="disclose"><summary>Links (${pg.links.length})</summary><table class="cases"><tbody>${pg.links.slice(0, 60).map((l) =>
        `<tr><td class="mono">${escapeHtml(l)}</td><td>${/^https?:/i.test(l) ? netButton("url", l) : ""}</td></tr>`).join("")}</tbody></table></details>`;
    }
    if ((v.scripts || []).length) {
      h += `<details class="disclose"><summary>Inline scripts (${v.scripts.length}) — static analysis + V8 sandbox</summary>${v.scripts.map((sc) => {
        const logs = ((sc.sandbox || {}).log || []).slice(0, 30);
        return `<div style="margin:6px 0"><span class="hint-line">#${sc.id} · ${sc.size} chars · ${(sc.hits || []).map((x) => x.label).join(" · ")}</span>
          ${logs.length ? table(["Event", "Name", "Args", "Mark"], logs.map((e) => `<tr><td>${escapeHtml(e.kind)}</td><td class="mono">${escapeHtml(e.name)}</td><td class="mono">${escapeHtml((e.args || []).join(" | ").slice(0, 400))}</td>
            <td>${addMarkCell("js_sandbox", `Page script sandbox (${rec.target}): ${e.name} ${(e.args || []).join(" | ")}`.slice(0, 300), `netcheck:url:${rec.target}/script#${sc.id}`, (e.args || []).join(" | ").slice(0, 1500))}</td></tr>`).join("")) : ""}
          <pre class="text-sample">${escapeHtml((sc.code || "").slice(0, 4000))}</pre></div>`;
      }).join("")}</details>`;
    }
  }
  if (v.screenshot) {
    h += v.screenshot.ok ? `<p class="hint-line"><b>Screenshot</b> — rendered from the downloaded HTML, JavaScript off, every request blocked</p><img class="net-shot" alt="screenshot" src="${netAsset(analysisId, v.screenshot.path)}">`
      : `<p class="hint-line">Screenshot unavailable: ${escapeHtml(v.screenshot.error || "")}</p>`;
  }
  if (v.preview_path) {
    h += `<div style="margin-top:8px"><button class="btn btn-ghost btn-sm" type="button" data-preview="${escapeHtml(v.preview_path)}">Safe preview</button>
      ${v.html_path ? fileActions(v.html_path) : ""}<div class="net-preview-box"></div></div>`;
  }
  if (v.download) h += `<p class="hint-line"><b>File served:</b> ${escapeHtml(v.download.filename)} (${v.download.size} bytes) ${fileActions(v.download.path)}</p>`;
  return h + `</div>`;
}

function netUrlCard(analysisId, c) {
  let body = `<div class="ident-box"><b>Fake identity used:</b> <span class="mono">${escapeHtml(c.identity.email)}</span> · password <span class="mono">${escapeHtml(c.identity.password)}</span>
    ${(c.replacements || []).length ? `<div class="hint-line">Victim data replaced in the URL: ${c.replacements.map((r) => `${escapeHtml(r.where)} (${escapeHtml(r.encoding)}): ${escapeHtml(r.original)} → ${escapeHtml(r.replacement)}`).join("<br>")}</div>
      <div class="hint-line">Fetched: <span class="mono">${escapeHtml(c.fetched_url)}</span></div>` : '<div class="hint-line">No victim data found in the URL.</div>'}
    ${c.referer ? `<div class="hint-line">Referer sent: ${escapeHtml(c.referer)} (link clicked from webmail)</div>` : ""}</div>`;
  return body + netWebHtml(analysisId, c);
}

// The website part of a check (URL, or a domain's site): both views, live
// screenshot, submissions, served files and the findings.
function netWebHtml(analysisId, c) {
  const views = c.views || {};
  let body = `<div class="net-views">${netViewHtml(analysisId, views.desktop, "Desktop — Edge on Windows", c, true)}${netViewHtml(analysisId, views.iphone, "Mobile — Safari on iPhone", c, false)}</div>`;
  const live = c.live_screenshot;
  body += `<div style="margin-top:10px"><button class="btn btn-ghost btn-sm" type="button" data-net-kind="shot_live" data-net-check="${c.id}" title="Loads the page with its images and CSS (JavaScript still off) — contacts the server again, through the proxy">Live screenshot (loads resources)</button></div>`;
  if (live) {
    body += live.ok ? `<p class="hint-line">Live screenshot · ${escapeHtml(live.taken_utc || "")} · ${escapeHtml(live.via || "")}</p><img class="net-shot" alt="live screenshot" src="${netAsset(analysisId, live.path)}">`
      : `<p class="hint-line bad-text">Live screenshot failed: ${escapeHtml(live.error || "")}</p>`;
  }
  (c.submissions || []).forEach((s) => {
    body += `<h4 style="margin:14px 0 4px">Submission #${s.n} — form #${s.form_index + 1} · ${escapeHtml(s.method)} ${escapeHtml(s.action)} · ${escapeHtml(s.submitted_utc)}</h4>
      <div class="hint-line">Sent: <span class="mono">${escapeHtml(Object.entries(s.sent || {}).map(([k, v]) => `${k}=${v}`).join("  "))}</span></div>
      <div class="net-views">${netViewHtml(analysisId, s.view, "Kit response", c, false)}</div>`;
    if (s.nested && (s.nested.tree || []).length) body += paneNested(s.nested);
  });
  if (c.nested && (c.nested.tree || []).length) body += `<h4 style="margin:14px 0 4px">Files served by the URL</h4>` + paneNested(c.nested);
  body += `<h4 style="margin:14px 0 4px">Findings (${(c.findings || []).length})</h4>` + netFindingsList(c.findings || []);
  return body;
}

function netDomainCard(analysisId, c) {
  const d = c.data || {};
  if (d.note) return `<p class="hint-line">${escapeHtml(d.note)}</p>` + netFindingsList(c.findings || []);
  if (c.views && c.views.desktop) {
    return netDomainInfo(d) + `<h4 style="margin:14px 0 4px">Website — <span class="mono">${escapeHtml(c.fetched_url || "")}</span></h4>`
      + `<div class="ident-box">Fake identity for forms: <span class="mono">${escapeHtml((c.identity || {}).email || "")}</span></div>`
      + netWebHtml(analysisId, c);
  }
  return netDomainInfo(d) + `<p class="hint-line">Website not visited (the domain does not resolve).</p>`
    + `<h4 style="margin:14px 0 4px">Findings (${(c.findings || []).length})</h4>` + netFindingsList(c.findings || []);
}

function netDomainInfo(d) {
  const dns = (d.dns || {}).records || {};
  let h = `<div class="net-views"><div class="net-view"><h4>DNS</h4>${(d.dns || {}).nxdomain ? '<p class="bad-text">NXDOMAIN — does not resolve</p>' : ""}`
    + kv(Object.entries(dns).map(([k, v]) => [k, v.join(", ")])) + `</div>`;
  const r = d.rdap || {};
  h += `<div class="net-view"><h4>RDAP (${escapeHtml(d.registrable || "")})</h4>${r.error ? `<p class="hint-line">${escapeHtml(r.error)}</p>` : kv([["Registrar", r.registrar], ["Created", r.created], ["Age", r.age_days != null ? `${r.age_days} days` : ""], ["Expires", r.expires], ["Updated", r.updated], ["Status", (r.status || []).join(", ")], ["Name servers", (r.nameservers || []).join(", ")], ["Abuse", r.abuse_email]])}</div>`;
  const ct = d.ct || {};
  h += `<div class="net-view"><h4>Certificate Transparency (crt.sh)</h4>${ct.error || ct.note ? `<p class="hint-line">${escapeHtml(ct.error || ct.note)}</p>` : kv([["Certificates", ct.count], ["First seen", ct.first_seen ? `${ct.first_seen} (${ct.first_seen_days} days ago)` : ""], ["Issuers", (ct.issuers || []).join(", ")]])
    + ((ct.names || []).length ? `<details class="disclose"><summary>Names (${ct.names.length})</summary><p class="mono">${escapeHtml(ct.names.join("  "))}</p></details>` : "")}</div></div>`;
  return h;
}

function netIpCard(c) {
  const d = c.data || {};
  if (d.note) return `<p class="hint-line">${escapeHtml(d.note)}</p>`;
  const o = d.offline || {};
  const r = d.rdap || {};
  return `<div class="net-views"><div class="net-view"><h4>Network owner</h4>` + kv([["ASN", o.asn ? `AS${o.asn}` : ""], ["AS organisation / ISP", o.as_org], ["Country", `${o.country || ""} ${o.country_name ? "(" + o.country_name + ")" : ""}`], ["Hosting / cloud", d.hosting || "no"], ["Reverse DNS", d.ptr], ["Tor exit", d.tor_exit === null ? "unknown" : (d.tor_exit ? "YES" : "no")], ["Source", o.source]])
    + `<p class="hint-line">${escapeHtml(d.attribution || "")}</p></div>`
    + `<div class="net-view"><h4>RDAP</h4>${r.error ? `<p class="hint-line">${escapeHtml(r.error)}</p>` : kv([["Network", r.network], ["Range", r.range], ["CIDR", r.cidr], ["Owner", r.org], ["Country", r.country], ["Type", r.type], ["Abuse contact", r.abuse_email]])}</div></div>`
    + `<h4 style="margin:14px 0 4px">Findings (${(c.findings || []).length})</h4>` + netFindingsList(c.findings || []);
}

function paneChecks(analysisId, net) {
  const checks = (net && net.checks) || [];
  if (!checks.length) return `<p class="hint-line">No network checks yet. Use <b>Check</b> next to a URL, domain or IP in the IOCs tab.</p>`;
  const order = { url: 0, domain: 1, ip: 2 };
  return checks.slice().sort((a, b) => (order[a.kind] - order[b.kind]) || a.target.localeCompare(b.target)).map((c) => {
    const fs = c.findings || [];
    const sev = fs.some((f) => f.severity === "high") ? "bad" : (fs.length ? "warn" : "ok");
    const body = c.kind === "url" ? netUrlCard(analysisId, c) : (c.kind === "domain" ? netDomainCard(analysisId, c) : netIpCard(c));
    return `<details class="net-card"${sev === "bad" ? " open" : ""}><summary>
        <span class="badge badge-muted">${escapeHtml(c.kind)}</span><span class="mono">${escapeHtml(c.target)}</span>
        <span class="badge badge-${sev}">${fs.length} finding(s)</span>
        <span class="hint-line">${escapeHtml(c.checked_utc || "")} · ${escapeHtml(c.via || "")}${c.runs > 1 ? ` · run ${c.runs}` : ""}</span>
        ${netButton(c.kind, c.target, "Re-check")}</summary><div class="net-body">${body}</div></details>`;
  }).join("");
}

// --- AI tab: AI (API), AI (local), MCP ---------------------------------------------
const AI_HIST = { api: [], local: [] };
const AI_FIELDS = {
  api: { base: "ai-api-base", model: "ai-api-model", key: "ai-api-key", user: "ai-api-user", hdr: "ai-api-hdr", q: "ai-api-q", out: "ai-api-out" },
  local: { base: "ai-local-base", model: "ai-local-model", key: "ai-local-key", q: "ai-local-q", out: "ai-local-out" },
};
const aiVal = (id) => { const e = document.getElementById(id); return e ? e.value.trim() : ""; };
const aiSet = (id, v) => { const e = document.getElementById(id); if (e && v) e.value = v; };

function saveAiCfg(ns) {
  const f = AI_FIELDS[ns];
  const cfg = { base: aiVal(f.base), model: aiVal(f.model), key: aiVal(f.key),
    user: f.user ? aiVal(f.user) : "", hdr: f.hdr ? aiVal(f.hdr) : "" };
  try { localStorage.setItem("docutracex_ai_" + ns, JSON.stringify(cfg)); } catch (err) { /* storage blocked */ }
  aiMsg(ns, "bot", "Config saved in this browser ✓");
}

function loadAiCfg(ns) {
  const f = AI_FIELDS[ns];
  let cfg = {};
  try { cfg = JSON.parse(localStorage.getItem("docutracex_ai_" + ns) || "{}"); } catch (err) { cfg = {}; }
  aiSet(f.base, cfg.base); aiSet(f.model, cfg.model); aiSet(f.key, cfg.key);
  if (f.user) aiSet(f.user, cfg.user);
  if (f.hdr) aiSet(f.hdr, cfg.hdr);
}

function aiMsg(ns, who, html, extra) {
  const out = document.getElementById(AI_FIELDS[ns].out);
  const div = document.createElement("div");
  div.className = `ai-msg ${who}`;
  div.innerHTML = html + (extra || "");
  out.prepend(div);
  return div;
}

function aiTrace(trace) {
  if (!trace || !trace.length) return "";
  return `<div class="ai-trace">${trace.map((t) => `· ${escapeHtml(t.tool)}(${escapeHtml(JSON.stringify(t.args))})${t.error ? " ⚠ " + escapeHtml(t.error) : ` → ${t.chars} chars`}`).join("\n")}</div>`;
}

async function askAi(ns) {
  const f = AI_FIELDS[ns];
  const q = aiVal(f.q);
  if (!q) return;
  const base = aiVal(f.base), model = aiVal(f.model);
  if (!base || !model) { aiMsg(ns, "bot", '<span class="bad-text">Fill in base_url and model first.</span>'); return; }
  let extra = null;
  if (f.hdr && aiVal(f.hdr)) {
    try { extra = JSON.parse(aiVal(f.hdr)); } catch (err) { aiMsg(ns, "bot", '<span class="bad-text">Extra headers are not valid JSON.</span>'); return; }
  }
  document.getElementById(f.q).value = "";
  aiMsg(ns, "me", `<b>You:</b> ${escapeHtml(q)}`);
  const pending = aiMsg(ns, "bot", "Thinking… (the model is reading the case with the tools)");
  const body = { message: q, base_url: base, model, api_key: aiVal(f.key), history: AI_HIST[ns].slice(-8),
    case_id: document.getElementById("ai-case").value || null };
  if (f.user && aiVal(f.user)) body.user = aiVal(f.user);
  if (extra) body.extra_headers = extra;
  try {
    const r = await fetch("/api/ai/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    pending.remove();
    if (!r.ok) { aiMsg(ns, "bot", `<span class="bad-text">${escapeHtml(j.detail || "error")}</span>`); return; }
    AI_HIST[ns].push({ role: "user", content: q }, { role: "assistant", content: j.reply || "" });
    aiMsg(ns, "bot", `<b>AI</b> <span class="hint-line">(${escapeHtml(j.model || model)})</span>\n${escapeHtml(j.reply || "(no reply)")}`, aiTrace(j.tool_trace));
  } catch (err) {
    pending.remove();
    aiMsg(ns, "bot", `<span class="bad-text">${escapeHtml(String(err))}</span>`);
  }
}

async function loadAiCases() {
  const sel = document.getElementById("ai-case");
  if (!sel) return;
  try {
    const cases = await fetch("/api/cases").then((r) => r.json());
    const current = _openCaseId || sel.value || (cases[0] && cases[0].analysis_id) || "";
    sel.innerHTML = '<option value="">(no case — the AI will list them)</option>' + cases.map((c) =>
      `<option value="${escapeHtml(c.analysis_id)}"${c.analysis_id === current ? " selected" : ""}>${escapeHtml(c.filename || "")} · ${escapeHtml(c.analysis_id)}</option>`).join("");
  } catch (err) { /* keep previous options */ }
}

function mcpBlock(title, text) {
  return `<h3 class="formats-title">${title}</h3><div class="mcp-block"><button class="btn btn-ghost btn-sm mcp-copy" type="button" data-copy="${escapeHtml(text)}">Copy</button><pre class="text-sample">${escapeHtml(text)}</pre></div>`;
}

async function loadMcpInfo() {
  const el = document.getElementById("ai-mcp-body");
  try {
    const j = await fetch("/api/mcp/info").then((r) => r.json());
    let h = `<p class="hint-line">The <b>MCP server</b> exposes your cases as <b>read-only</b> tools to an MCP client (Claude Desktop, Claude Code or another), so you can investigate them in natural language from your own client, without this web page. It reads the same cases folder (<span class="mono">${escapeHtml(j.cases_dir)}</span>) and never modifies a case or touches the network.</p>`;
    if (!j.mcp_installed) h += `<p class="bad-text">The <span class="mono">mcp</span> package is not installed in ${escapeHtml(j.python)} — run scripts/setup_portable_python.py.</p>`;
    h += mcpBlock("1 · Start the server (stdio) — to test it", (j.env ? Object.entries(j.env).map(([k, v]) => `${k}=${v}`).join(" ") + " " : "") + j.run);
    h += mcpBlock("2 · Claude Desktop — Settings → Developer → Edit Config (claude_desktop_config.json)", j.claude_desktop);
    h += mcpBlock("2 · (alternative) Claude Code", j.claude_code);
    h += `<h3 class="formats-title">3 · Available tools</h3><ul class="hint-list">${(j.tools || []).map((t) => `<li><span class="mono">${escapeHtml(t.signature)}</span> — ${escapeHtml(t.description)}</li>`).join("")}</ul>`;
    h += `<p class="hint-line">All read-only. Paths above are this installation's (portable Python ${escapeHtml(j.mcp_version ? "· mcp " + j.mcp_version : "")}).</p>`;
    el.innerHTML = h;
    el.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.getAttribute("data-copy")); b.textContent = "Copied ✓"; }
      catch (err) { b.textContent = "Select and copy"; }
    }));
  } catch (err) { el.innerHTML = `<p class="bad-text">Could not load MCP info.</p>`; }
}

function showAiPane(name) {
  document.querySelectorAll("#ai-subtabs .subtab").forEach((b) => b.classList.toggle("is-active", b.getAttribute("data-ai") === name));
  document.querySelectorAll("[data-ai-pane]").forEach((p) => { p.hidden = p.getAttribute("data-ai-pane") !== name; });
  if (name === "mcp") loadMcpInfo();
}

function setupAi() {
  if (!document.getElementById("ai-subtabs")) return;
  document.querySelectorAll("#ai-subtabs .subtab").forEach((b) => b.addEventListener("click", () => showAiPane(b.getAttribute("data-ai"))));
  document.querySelectorAll("[data-ai-save]").forEach((b) => b.addEventListener("click", () => saveAiCfg(b.getAttribute("data-ai-save"))));
  document.querySelectorAll("[data-ai-ask]").forEach((b) => b.addEventListener("click", () => askAi(b.getAttribute("data-ai-ask"))));
  ["api", "local"].forEach((ns) => {
    loadAiCfg(ns);
    document.getElementById(AI_FIELDS[ns].q).addEventListener("keydown", (e) => { if (e.key === "Enter") askAi(ns); });
  });
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
      if (target === "yara") loadYara();
      if (target === "settings") loadSettings();
      if (target === "ai") loadAiCases();
    });
  });
}

const diagRefresh = document.getElementById("diag-refresh");
if (diagRefresh) diagRefresh.addEventListener("click", loadDiagnostics);

setupTabs();
setupYara();
setupSettings();
setupAi();
renderFormats();
loadDiagnostics(); // initial load to set the nav indicator
loadCases();
loadConcurrency();
