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
      <tr>
        <td>${c.created_utc || ""}</td>
        <td class="file">${escapeHtml(c.filename || "")}</td>
        <td>${escapeHtml(c.declared_extension || "")}</td>
        <td class="mono" title="${escapeHtml(c.detected_name || "")}">${escapeHtml(c.detected_mime || "")}</td>
        <td>${discrepancyBadge(c.discrepancy)}</td>
        <td>${fmtSize(c.size_bytes)}</td>
        <td class="mono" title="${c.sha256 || ""}">${shortHash(c.sha256)}</td>
        <td><span class="badge">${escapeHtml(c.state || "")}</span></td>
      </tr>`).join("");
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
