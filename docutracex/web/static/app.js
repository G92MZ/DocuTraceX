"use strict";

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
    summary.textContent = `${d.present}/${d.total} present` +
      (d.ok ? "" : " — missing required: " + d.missing_required.join(", "));
    summary.className = "status " + (d.ok ? "ok-text" : "bad-text");
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

loadDiagnostics();
loadCases();
