"""Network checks of a case's IOCs — on demand, through the configured proxy.

Kinds of check (one task each, queued like any other analysis task):

- ``url``: fetch the URL twice as a real browser (desktop Edge on Windows and
  Safari on iPhone) after replacing the victim's data with a fake identity;
  follow and record redirects, TLS certificate, cloaking (the two views
  differ), read the page statically (forms, brand, scripts through the V8
  sandbox), render a screenshot with every request blocked, and analyse any
  file the URL serves as a nested child of the case.
- ``submit``: post a fake identity through one of the page's forms to see the
  kit's next stage (explicit button, never automatic).
- ``shot_live``: screenshot of the live page with its images/CSS, JavaScript
  still off (contacts the server again, through the proxy).
- ``domain``: DNS, RDAP (age, registrar) and Certificate Transparency.
- ``ip``: ASN/AS org/country offline (DB-IP Lite), RDAP owner and abuse
  contact, PTR, Tor exit list.

Results are kept in ``results/netcheck.json`` (one record per target, the latest
run), their findings join the consolidated findings, and the URLs they reveal
(redirect hops, form targets, downloads) join the IOCs.

    python -m docutracex.netcheck <case_root> '<json params>'
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..logging_config import get_logger
from ..storage import CasePaths, read_json, write_subresult

log = get_logger(__name__)

_EMAIL_REFERER = "https://outlook.office.com/"
SHOT_TIMEOUT = 150   # one screenshot process (Chromium start + up to ~60 s for a slow page)
TASK_TIMEOUT = 1200  # a whole check: two fetches of up to ~90 s each, screenshot, analysis
_HTML_TYPES = ("text/html", "application/xhtml", "text/plain")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_id(kind: str, target: str) -> str:
    return hashlib.sha1(f"{kind}|{target}".encode()).hexdigest()[:12]


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _load(paths: CasePaths) -> dict[str, Any]:
    data = read_json(paths.subresult("netcheck")) or {}
    data.setdefault("module", "netcheck")
    data.setdefault("checks", [])
    return data


def _save(paths: CasePaths, data: dict[str, Any]) -> None:
    findings = [f for c in data["checks"] for f in c.get("findings", [])]
    data["findings"] = findings
    data["counts"] = {"findings": len(findings), "checks": len(data["checks"])}
    data["status"] = "ok_with_findings" if findings else "ok"
    write_subresult(paths, "netcheck", data)


def _upsert(data: dict[str, Any], rec: dict[str, Any]) -> None:
    for i, c in enumerate(data["checks"]):
        if c["id"] == rec["id"]:
            rec["runs"] = c.get("runs", 1) + 1
            data["checks"][i] = rec
            return
    rec["runs"] = 1
    data["checks"].append(rec)


def _proxy_label(proxy: str | None) -> str:
    from .. import appsettings

    if not proxy:
        return "direct (no proxy — your own IP)"
    p = urlsplit(proxy)
    if appsettings.proxy_is_free():
        info = appsettings.load()["network"]["proxy"].get("free_info") or {}
        where = f", {info['country']}" if info.get("country") else ""
        return f"free proxy (untrusted, strict TLS) {p.scheme}://{p.hostname}:{p.port}{where}"
    return f"proxy {p.scheme}://{p.hostname}:{p.port}"


def _is_html(res: dict[str, Any]) -> bool:
    ct = (res.get("content_type") or "").lower()
    if "attachment" in (res.get("disposition") or "").lower():
        return False
    if any(t in ct for t in _HTML_TYPES):
        return True
    head = (res.get("body") or b"")[:300].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def _decode(body: bytes, ctype: str) -> str:
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I)
    for enc in ([m.group(1)] if m else []) + ["utf-8", "cp1252"]:
        try:
            return body.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", "replace")


def _shot(mode: str, target: str, out: Path, proxy: str | None = None, ua: str | None = None) -> dict[str, Any]:
    from . import shot
    from .. import native

    from . import http as _http
    strict = "strict" if getattr(_http, "_STRICT_DEFAULT", False) else ""
    cmd = [sys.executable, "-m", "docutracex.netcheck.shot", mode, target, str(out), proxy or "", ua or "", strict]
    env = {**native.subprocess_env(), **{k: v for k, v in shot.env().items() if k == "PLAYWRIGHT_BROWSERS_PATH"}}
    root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = root + (";" if sys.platform.startswith("win") else ":") + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SHOT_TIMEOUT, env=env, cwd=root)
        line = (proc.stdout or "").strip().splitlines()[-1:] or ["{}"]
        res = json.loads(line[0])
        if not res.get("ok") and not res.get("error"):
            res["error"] = (proc.stderr or "screenshot failed")[-300:]
    except Exception as exc:  # noqa: BLE001
        res = {"ok": False, "error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    if res.get("ok"):
        res["path"] = out.as_posix()
    return res


def _rel(paths: CasePaths, p: Path) -> str:
    return p.relative_to(paths.root).as_posix()


def _view(paths: CasePaths, workdir: Path, name: str, res: dict[str, Any], loc: str,
          shot: bool) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Analyse one fetched response. Returns (view summary, findings, downloads)."""
    from . import page

    view: dict[str, Any] = {k: res.get(k) for k in ("requested_url", "final_url", "status", "content_type",
                                                    "truncated", "error", "elapsed_s")}
    view["hops"] = res.get("hops", [])
    view["size"] = len(res.get("body") or b"")
    findings: list[dict[str, Any]] = []
    downloads: list[dict[str, Any]] = []
    body = res.get("body")
    if body is None:
        return view, findings, downloads
    view["sha256"] = hashlib.sha256(body).hexdigest()
    final = res.get("final_url") or res.get("requested_url")
    if _is_html(res):
        html = _decode(body, res.get("content_type", ""))
        raw = workdir / f"{name}.html"
        raw.write_text(html, encoding="utf-8")
        view["html_path"] = _rel(paths, raw)
        info = page.parse(html, final)
        info["_html"] = html
        view["page"] = {k: v for k, v in info.items() if k != "_html"}
        view["page"]["brands"] = page.brands(info, final)
        findings += page.findings(info, final, loc)
        scripts, sf = page.scripts_analysis(info, loc)
        view["scripts"] = scripts
        findings += sf
        prev = workdir / f"{name}.preview.html"
        prev.write_text(page.safe_document(html, final), encoding="utf-8")
        view["preview_path"] = _rel(paths, prev)
        if shot:
            view["screenshot"] = _shot("offline", str(raw), workdir / f"{name}.png")
            if view["screenshot"].get("ok"):
                view["screenshot"]["path"] = _rel(paths, workdir / f"{name}.png")
    else:
        cd = res.get("disposition") or ""
        m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", cd, re.I)
        fname = (m.group(1) if m else Path(urlsplit(final).path).name) or "download.bin"
        fname = re.sub(r"[^\w.\-]", "_", fname)[:100]
        dest = workdir / f"download_{fname}"
        dest.write_bytes(body)
        downloads.append({"filename": fname, "path": _rel(paths, dest), "size": len(body),
                          "sha256": view["sha256"], "content_type": res.get("content_type", ""), "url": final})
        view["download"] = downloads[-1]
    return view, findings, downloads


def _transport_findings(view: dict[str, Any], loc: str) -> list[dict[str, Any]]:
    out = []
    hops = view.get("hops") or []
    hosts = [_host(h["url"]) for h in hops]
    if len(hops) > 1 and len(set(hosts)) > 1:
        out.append({"tool": "netcheck", "rule": "web_redirect_chain", "severity": "low",
                    "detail": f"{len(hops) - 1} redirect(s) across {len(set(hosts))} hosts",
                    "location": loc, "evidence": "\n".join(f"{h['status']} {h['url']}" for h in hops)})
    for h in hops:
        if h.get("tls_error"):
            out.append({"tool": "netcheck", "rule": "web_invalid_certificate", "severity": "medium",
                        "detail": f"Invalid TLS certificate on {_host(h['url'])}", "location": loc,
                        "evidence": h["tls_error"]})
        t = h.get("tls") or {}
        if t.get("not_before"):
            try:
                age = (datetime.now(timezone.utc) - datetime.strptime(t["not_before"], "%Y-%m-%d")
                       .replace(tzinfo=timezone.utc)).days
            except ValueError:
                age = None
            if age is not None and age < 14:
                out.append({"tool": "netcheck", "rule": "web_new_certificate", "severity": "medium",
                            "detail": f"TLS certificate of {_host(h['url'])} issued {age} day(s) ago",
                            "location": loc, "evidence": f"{t.get('issuer')} · {t.get('not_before')} → {t.get('not_after')}"})
    return out


def _norm_text(v: dict[str, Any]) -> str:
    return re.sub(r"[\d\s]+", " ", ((v.get("page") or {}).get("text") or ""))[:3000]


def _cloaking(desk: dict[str, Any], mob: dict[str, Any], loc: str) -> list[dict[str, Any]]:
    diffs = []
    if (desk.get("status") or 0) != (mob.get("status") or 0):
        diffs.append(f"status {desk.get('status')} vs {mob.get('status')}")
    if _host(desk.get("final_url") or "") != _host(mob.get("final_url") or ""):
        diffs.append(f"final host {_host(desk.get('final_url') or '')} vs {_host(mob.get('final_url') or '')}")
    dp, mp = desk.get("page") or {}, mob.get("page") or {}
    if bool(dp.get("forms")) != bool(mp.get("forms")):
        diffs.append(f"forms {len(dp.get('forms') or [])} vs {len(mp.get('forms') or [])}")
    if dp and mp and difflib.SequenceMatcher(None, _norm_text(desk), _norm_text(mob)).ratio() < 0.6:
        diffs.append(f"content differs (titles: '{dp.get('title', '')}' vs '{mp.get('title', '')}')")
    if not diffs:
        return []
    return [{"tool": "netcheck", "rule": "web_cloaking", "severity": "medium",
             "detail": "The page serves different content to desktop and mobile browsers (cloaking)",
             "location": loc, "evidence": "\n".join(diffs)}]


def _downloads_nested(paths: CasePaths, downloads: list[dict[str, Any]], loc: str):
    if not downloads:
        return None, []
    from .. import nested

    items = [{"path": str(paths.root / d["path"]), "filename": d["filename"]} for d in downloads]
    res = nested.scan_children(items, paths)
    out = []
    for d in downloads:
        out.append({"tool": "netcheck", "rule": "web_file_download", "severity": "high",
                    "detail": f"The URL serves a file: {d['filename']} ({d['size']} bytes)", "location": loc,
                    "evidence": f"{d['content_type']}\nsha256 {d['sha256']}\n{d['url']}"})
    for f in res.get("findings", []):
        f = dict(f)
        f["location"] = f"{loc} › {f.get('location', '')}"
        out.append(f)
    return res, out


def _visit(paths: CasePaths, rec: dict[str, Any], proxy: str | None, loc: str) -> None:
    """Fetch ``rec['fetched_url']`` as desktop and mobile browsers and fill the
    record: views (page, screenshot, preview), findings, cloaking, downloads."""
    from . import http

    workdir = paths.extracted_dir / "netcheck" / rec["id"]
    workdir.mkdir(parents=True, exist_ok=True)
    referer = rec.get("referer")
    downloads: list[dict[str, Any]] = []
    for prof in ("desktop", "iphone"):
        s = http.session(proxy)
        res = http.fetch(s, rec["fetched_url"], http.profile(prof, referer))
        view, f, d = _view(paths, workdir, prof, res, loc, shot=(prof == "desktop"))
        view["user_agent"] = http.profile(prof)["User-Agent"]
        if prof == "desktop":
            view["cookies"] = res.get("cookies", {})
            rec["findings"] += f + _transport_findings(view, loc)
            downloads += d
        else:
            # Only what the mobile view adds (e.g. a payload served to phones only).
            known = {x["rule"] for x in rec["findings"]}
            rec["findings"] += [x for x in f if x["rule"] not in known]
            downloads += [x for x in d if x["sha256"] not in {y["sha256"] for y in downloads}]
        rec["views"][prof] = view
    rec["findings"] += _cloaking(rec["views"]["desktop"], rec["views"]["iphone"], loc)
    from ..parsers.mail_rules import check_domain
    known = {(x["rule"], x["evidence"]) for x in rec["findings"]}
    for h in {_host(v.get("final_url") or "") for v in rec["views"].values()} - {""}:
        for rule, sev, why in check_domain(h):
            if (rule, h) not in known:
                rec["findings"].append({"tool": "netcheck", "rule": rule, "severity": sev, "detail": why,
                                        "location": loc, "evidence": h})
    rec["nested"], extra = _downloads_nested(paths, downloads, loc)
    rec["findings"] += extra
    rec["downloads"] = downloads


def check_url(paths: CasePaths, url: str, proxy: str | None, email_case: bool) -> dict[str, Any]:
    from . import identity

    ident = identity.new_identity()
    target, changes = identity.rewrite_url(url, ident)
    rec: dict[str, Any] = {"id": check_id("url", url), "kind": "url", "target": url, "checked_utc": _now(),
                           "via": _proxy_label(proxy), "identity": ident, "fetched_url": target,
                           "replacements": changes, "referer": _EMAIL_REFERER if email_case else None,
                           "views": {}, "findings": []}
    _visit(paths, rec, proxy, f"netcheck:url:{url}")
    return rec


def site_candidates(host: str) -> list[str]:
    """Where a domain's website is tried: HTTPS first, then plain HTTP."""
    return [f"https://{host}/", f"http://{host}/"]


def check_domain(paths: CasePaths, host: str, proxy: str | None) -> dict[str, Any]:
    """DNS / RDAP / CT, plus a visit to the domain's website (screenshot, page,
    cloaking...) like a URL check, when the name resolves."""
    from . import domain, http, identity

    s = http.session(proxy)
    d, f = domain.check(s, host)
    rec: dict[str, Any] = {"id": check_id("domain", host), "kind": "domain", "target": host, "checked_utc": _now(),
                           "via": _proxy_label(proxy), "data": d, "findings": f}
    if d.get("note") or (d.get("dns") or {}).get("nxdomain"):
        return rec  # reserved name or no such domain: nothing to visit
    rec.update(identity=identity.new_identity(), replacements=[], referer=None, views={})
    loc = f"netcheck:domain:{host}"
    for url in site_candidates(host):
        rec["fetched_url"] = url
        rec["views"], rec["findings"] = {}, list(f)
        _visit(paths, rec, proxy, loc)
        if rec["views"]["desktop"].get("status"):
            break  # the site answered (any HTTP status); otherwise try plain HTTP
    return rec


def submit_form(paths: CasePaths, cid: str, form_index: int, proxy: str | None, data: dict[str, Any]) -> dict[str, Any]:
    from . import http, identity

    rec = next((c for c in data["checks"] if c["id"] == cid), None)
    if rec is None:
        raise ValueError("check not found")
    view = rec["views"]["desktop"]
    forms = (view.get("page") or {}).get("forms") or []
    if not 0 <= form_index < len(forms):
        raise ValueError("form not found")
    form = forms[form_index]
    values = identity.form_values(form, rec["identity"])
    s = http.session(proxy)
    for k, v in (view.get("cookies") or {}).items():
        s.cookies.set(k, v)
    final = view.get("final_url") or rec["fetched_url"]
    p = urlsplit(final)
    headers = {**http.profile("desktop", final), "Origin": f"{p.scheme}://{p.netloc}",
               "Sec-Fetch-Site": "same-origin" if _host(form["action"]) == _host(final) else "cross-site"}
    method = "POST" if form.get("method", "GET").upper() == "POST" else "GET"
    target = form["action"]
    if method == "GET":
        from urllib.parse import urlencode
        target = target.split("?")[0] + "?" + urlencode(values)
        res = http.fetch(s, target, headers)
    else:
        res = http.fetch(s, target, headers, method="POST", data=values)
    workdir = paths.extracted_dir / "netcheck" / cid
    workdir.mkdir(parents=True, exist_ok=True)
    n = len(rec.get("submissions", [])) + 1
    loc = f"netcheck:{rec['kind']}:{rec['target']} › form#{form_index + 1}"
    sview, f, d = _view(paths, workdir, f"submit{n}", res, loc, shot=True)
    nested_res, extra = _downloads_nested(paths, d, loc)
    sub = {"n": n, "form_index": form_index, "method": method, "action": form["action"], "sent": values,
           "submitted_utc": _now(), "via": _proxy_label(proxy), "view": sview, "nested": nested_res,
           "downloads": d}
    rec.setdefault("submissions", []).append(sub)
    rec["findings"] = [x for x in rec["findings"] if not x["location"].startswith(loc)]
    rec["findings"].append({"tool": "netcheck", "rule": "web_credentials_accepted", "severity": "high"
                            if (sview.get("status") or 0) < 400 else "medium",
                            "detail": f"Fake credentials sent through form #{form_index + 1}: the kit answered "
                                      f"HTTP {sview.get('status')} ({_host(sview.get('final_url') or '')})",
                            "location": loc, "evidence": "\n".join(f"{h['status']} {h['url']}" for h in sview.get("hops", []))})
    rec["findings"] += f + extra
    return rec


def run(case_root: Path, params: dict[str, Any]) -> dict[str, Any]:
    """Run one network check on a case and refresh the derived results."""
    from .. import appsettings

    case_root = Path(case_root)
    paths = CasePaths(case_root.name, cases_dir=case_root.parent)
    from . import freeproxy, http as _http

    free = appsettings.proxy_is_free()
    # A free proxy may have died since it was picked: re-test it, rotate if needed.
    proxy = freeproxy.ensure_alive() if free else appsettings.proxy_url()
    _http.set_strict_default(free)
    kind, target = params.get("kind"), (params.get("target") or "").strip()
    data = _load(paths)
    if kind == "url":
        email_case = read_json(paths.subresult("email")) is not None
        rec = check_url(paths, target, proxy, email_case)
    elif kind == "submit":
        rec = submit_form(paths, params["check_id"], int(params.get("form", 0)), proxy, data)
    elif kind == "shot_live":
        from . import http
        rec = next(c for c in data["checks"] if c["id"] == params["check_id"])
        workdir = paths.extracted_dir / "netcheck" / rec["id"]
        workdir.mkdir(parents=True, exist_ok=True)
        out = workdir / "live.png"
        res = _shot("live", rec["fetched_url"], out, proxy, http.profile("desktop")["User-Agent"])
        if res.get("ok"):
            res["path"] = _rel(paths, out)
        res["taken_utc"], res["via"] = _now(), _proxy_label(proxy)
        rec["live_screenshot"] = res
    elif kind == "domain":
        rec = check_domain(paths, target, proxy)
    elif kind == "ip":
        from . import http, ipinfo
        s = http.session(proxy)
        d, f = ipinfo.check(s, target)
        rec = {"id": check_id(kind, target), "kind": kind, "target": target, "checked_utc": _now(),
               "via": _proxy_label(proxy), "data": d, "findings": f}
    else:
        raise ValueError(f"unknown check kind {kind!r}")
    if kind in ("url", "domain", "ip"):
        _upsert(data, rec)
    _save(paths, data)
    from .. import analyze
    analyze.refresh_derived(paths, "netcheck")
    return {"id": rec["id"], "kind": rec["kind"], "findings": len(rec.get("findings", []))}


def run_task(case_root: Path, params: dict[str, Any]) -> None:
    """Run a check on the portable interpreter (like the analysis), else in-process."""
    from .. import native
    from ..config import settings

    portable = settings.portable_python()
    try:
        same = portable is not None and portable.resolve() == Path(sys.executable).resolve()
    except OSError:
        same = False
    if portable and not same:
        cmd = [str(portable), "-m", "docutracex.netcheck", str(case_root), json.dumps(params)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=TASK_TIMEOUT, env=native.subprocess_env())
            if proc.returncode == 0:
                return
            raise RuntimeError(proc.stderr.strip()[-500:] or f"exit {proc.returncode}")
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("network check timed out") from exc
    run(case_root, params)


def main(argv: list[str]) -> int:
    run(Path(argv[0]), json.loads(argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
