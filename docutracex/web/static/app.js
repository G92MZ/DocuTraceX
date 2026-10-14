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

function docIcon(color, glyph) {
  const fontSize = glyph.length > 1 ? 6.5 : 10;
  return `<svg viewBox="0 0 40 48" class="fmt-ico" aria-hidden="true">
    <path d="M6 2h18l10 10v32a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z" fill="#1b2431" stroke="#2f3b4d" stroke-width="1.2"/>
    <path d="M24 2l10 10h-8a2 2 0 0 1-2-2z" fill="#2f3b4d"/>
    <rect x="4" y="29" width="30" height="13" rx="2" fill="${color}"/>
    <text x="19" y="${glyph.length > 1 ? 37.5 : 38.5}" text-anchor="middle" font-size="${fontSize}" font-weight="700" fill="#fff" font-family="Segoe UI, sans-serif">${glyph}</text>
  </svg>`;
}

function mailIcon(color) {
  return `<svg viewBox="0 0 40 48" class="fmt-ico" aria-hidden="true">
    <rect x="3" y="11" width="34" height="24" rx="3" fill="#1b2431" stroke="${color}" stroke-width="2"/>
    <path d="M4 13l16 13 16-13" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>
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

async function loadDiagnostics() {
  const body = document.getElementById("diag-body");
  const summary = document.getElementById("diag-summary");
  try {
    const d = await fetch("/api/diagnostics").then((r) => r.json());
    const it = d.interpreter || {};
    const kind = it.is_portable ? "portable" : (it.source || "current");
    summary.textContent = `${d.present}/${d.total} present` +
      (d.ok ? "" : " — missing required: " + d.missing_required.join(", "));
    summary.className = "status " + (d.ok ? "ok-text" : "bad-text");
    const interpLine = document.getElementById("diag-interp");
    if (interpLine) {
      interpLine.textContent =
        `Interpreter: ${kind} · Python ${it.python_version || "?"} · ${it.executable || ""}`;
    }
    body.innerHTML = d.dependencies.map((x) => {
      let cls, label;
      if (x.installed) { cls = "ok"; label = "installed"; }
      else if (x.required) { cls = "bad"; label = "missing (required)"; }
      else { cls = "warn"; label = "missing (optional)"; }
      const hint = (!x.installed && x.install_hint)
        ? `<div class="hint-line">${escapeHtml(x.install_hint)}</div>` : "";
      return `<tr>
        <td class="file">${escapeHtml(x.name)}</td>
        <td>${escapeHtml(x.purpose)}${hint}</td>
        <td class="mono">${escapeHtml(x.version || "")}</td>
        <td><span class="badge badge-${cls}">${escapeHtml(label)}</span></td>
      </tr>`;
    }).join("");
  } catch (err) {
    summary.textContent = "Could not load diagnostics.";
  }
}

renderFormats();
loadDiagnostics();
loadCases();
