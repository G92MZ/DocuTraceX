"""Noise seen in a real signed MSI bundling CPython (RVTools): bundled JS,
CPython license text, certificate metadata, printf formats, build-agent paths."""

from docutracex import ioc


def _vals(text, module="text", location="text"):
    res = ioc.extract([{"module": module, "location": location, "text": text}])
    return {i["value"] for i in res["iocs"]} if "iocs" in res else {
        v["value"] for group in res.values() if isinstance(group, list) for v in group if isinstance(v, dict)}


JS = ("!function(e,t){var n=this.top;return e.top+i.data.data};" * 40
      + 'fetch("cdn-update.example.net/x");')


def test_bundled_js_members_are_not_domains():
    v = _vals(JS)
    assert not {"e.top", "this.top", "i.data.data"} & v
    assert "cdn-update.example.net" in v


def test_identifiers_reserved_and_property_tlds():
    v = _vals("builtins.id collections.abc self.af thread.local 1.invalid action.name "
              "microsoft.windows os.py [RuntimeVsdnetRTName].NET evil-host.example.com")
    assert v & {"builtins.id", "collections.abc", "self.af", "thread.local", "1.invalid",
                "action.name", "microsoft.windows", "os.py", "runtimevsdnetrtname.net"} == set()
    assert "evil-host.example.com" in v


def test_pki_and_license_hosts():
    v = _vals("http://crl3.digicert.com/x.crl cacerts.digicert.com https://sectigo.com/CPS "
              "http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt www.pythonlabs.com "
              "http://hdl.handle.net/1895.22/1013 jseward@acm.org http://203.0.113.47/gate.php")
    assert not any("digicert" in x or "sectigo" in x or "pythonlabs" in x or "handle.net" in x
                   or "/pki/" in x or x == "jseward@acm.org" for x in v)
    assert "http://203.0.113.47/gate.php" in v


def test_code_commands_printf_and_build_paths():
    v = _vals("type %.100s doesn\nat %p\ncmd = 'LIST'\nnc += prev\nType \"help\"\n"
              "D:\\a\\1\\s\\Objects\\object.c D:\\a\\1\\b\\bin\\amd64\\python311.pdb "
              "C:\\Users\\Public\\invoice_update.exe\ncmd.exe /c whoami")
    assert not any(x.lower().startswith(("type", "at ", "cmd =", "nc ")) or x.startswith("D:\\a\\") for x in v)
    assert "C:\\Users\\Public\\invoice_update.exe" in v
    assert any(x.startswith("cmd.exe /c") for x in v)


def test_hex_blob_lines_and_cert_head_and_oid():
    line = "0c895fcf6720192de6bf3b9e89ecdbd6596cbcdd8eb28e7c365ecc4ec1ff1460"
    v = _vals("\n".join([line + line] * 3) + "\n102f00000002020030822f0006092a86 policy 2.23.140.1.3.6.1")
    assert not any(len(x) in (32, 64, 128) for x in v)
    assert "1.3.6.1" not in v


def test_msi_certificate_metadata_paths_skipped():
    src = ioc.sources_from_modules({"msi": {"items": [{"signature": {"signer": {
        "serial_number": "2a675af2bbf9d9477854be7409a5da44", "issuer": "CN=SSL.com Code Signing",
        "certificate_policies": ["1.3.6.1 https://www.ssl.com/repository"]}}}]},
        "c2": {"timings": [{"name": "5060393f45d86e4be342d7067f6c154b"}],
               "configs": [{"tools": {"1768": {"tool": "1768.py"}}}]}})
    assert src == []
