"""The common family layer: one card shape for every RAT / stealer configuration."""

from __future__ import annotations

from docutracex.c2 import familyspec as fs

SPEC = fs.Spec(
    family="ExampleRAT",
    fields={"host": "hosts", "port": "ports", "mutex": "mutex", "inst": "install", "dir": "install_folder",
            "exe": "install_name", "smtp": "smtp_server", "user": "smtp_user", "pass": "smtp_password",
            "to": "smtp_to", "tg": "telegram_token", "chat": "telegram_chat", "usb": "usb", "sleep": "delay"},
    options={"usb": ("flag", "spreads through USB drives"), "delay": ("seconds", "waits {v} s before starting")},
    persistence="install_name",
    defaults={"mutex": {"ExampleMutex": "builder default mutex"}},
    traces=((b"ExampleRAT.Config", "config class"), (b"ExampleStub", "stub name"), (b"exrat_key", "key name")))


def test_interpret_roles_into_the_common_card() -> None:
    s, hosts = fs.interpret(SPEC, {"Host": "relay.invoice-support.example", "Port": "4444", "Mutex": "ExampleMutex",
                                   "Inst": "true", "Dir": "ApplicationData", "Exe": "svc.exe", "USB": "true",
                                   "Sleep": "5"})
    assert s["C2"] == ["relay.invoice-support.example:4444"] and hosts == ["relay.invoice-support.example"]
    assert s["Install path"] == "%AppData%\\svc.exe" and s["Persistence"][1].endswith("Run\\svc (otherwise)")
    assert s["Options"] == ["spreads through USB drives", "waits 5 s before starting"]
    assert s["Builder defaults"] == ["ExampleMutex — builder default mutex"]


def test_exfiltration_and_sensitive_credentials() -> None:
    s, hosts = fs.interpret(SPEC, {"smtp": "mail.factura-soporte.example", "user": "ops@factura-soporte.example",
                                   "pass": "inert-not-a-password", "to": "drop@factura-soporte.example",
                                   "tg": "0000000000:AAinertInertInertInertInertInertInert", "chat": "-100000"})
    assert "SMTP server: mail.factura-soporte.example" in s["Exfiltration"] and "Sensitive" in s
    assert hosts == ["mail.factura-soporte.example"]


def test_unknown_names_and_traces() -> None:
    assert not fs.known(SPEC, {"\u0002": "x", "a": "y"}) and fs.known(SPEC, {"Host": "x"})
    t = fs.traces(SPEC, b"MZ ExampleRAT.Config ExampleStub exrat_key")
    assert t["kind"] == "indicators" and len(t["indicators"]) == 3
    assert fs.traces(SPEC, b"MZ ExampleStub") is None
