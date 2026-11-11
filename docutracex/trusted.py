"""Generic legitimate domains (Settings → *Generic legitimate domains*).

Well-known providers whose domains must never be reported as look-alikes of
your domains or brands — ``outlook.office.com`` carries "outlook" and is
Microsoft's own — without having to list them as own domains or brands.

Two kinds, because not every legitimate domain is the same:

- **Services**: the whole domain belongs to the provider (``office.com``,
  ``gmail.com``). A host on it, or on any subdomain, is never compared.
- **Platforms**: anyone, an attacker too, picks the subdomain
  (``<tenant>.sharepoint.com``, ``<name>.github.io``). The platform name is not
  compared, but the tenant part still is: ``micros0ft-secure.onmicrosoft.com``
  is reported, ``contoso.sharepoint.com`` is not. A tenant named exactly like
  your domain or brand is not reported either (that name is usually taken by
  its owner).

Only the look-alike checks read this list. It never makes a domain benign
anywhere else: phishing hosted on SharePoint or Google Docs is still judged by
every other rule. The defaults below are global providers only; the user adds
or removes entries in Settings, and an update adds new defaults without undoing
the user's changes.
"""

from __future__ import annotations

from typing import Any

SERVICES: tuple[str, ...] = (
    # Microsoft
    "microsoft.com", "microsoftonline.com", "microsoftonline-p.com", "office.com", "office.net", "office365.com",
    "outlook.com", "live.com", "live.net", "hotmail.com", "msn.com", "msftauth.net", "msauth.net",
    "msftauthimages.net", "msauthimages.net", "msocdn.com", "aka.ms", "1drv.ms", "bing.com", "skype.com",
    "lync.com", "windows.com", "windowsupdate.com", "azure.com", "msecnd.net", "onenote.com", "sway.com",
    "microsoftstream.com", "dynamics.com", "powerbi.com", "sharepointonline.com", "xbox.com", "linkedin.com",
    "github.com",
    # Google
    "google.com", "gmail.com", "googlemail.com", "googleapis.com", "gstatic.com", "youtube.com", "ytimg.com",
    "googlevideo.com", "withgoogle.com", "goo.gl",
    # Apple
    "apple.com", "icloud.com", "me.com", "mac.com",
    # Other mail providers
    "yahoo.com", "ymail.com", "aol.com", "proton.me", "protonmail.com", "protonmail.ch", "pm.me", "zoho.com",
    "gmx.com", "gmx.net", "mail.com", "yandex.com", "fastmail.com", "tutanota.com",
    # Collaboration, signatures, social
    "zoom.us", "zoom.com", "slack.com", "webex.com", "docusign.com", "docusign.net", "adobe.com",
    "adobelogin.com", "dropbox.com", "box.com", "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "whatsapp.net", "x.com", "twitter.com", "twimg.com", "amazon.com", "cloudflare.com",
    # Mail security gateways (rewritten links)
    "mimecast.com", "mimecastprotect.com", "proofpoint.com", "pphosted.com", "barracudanetworks.com",
)

PLATFORMS: tuple[str, ...] = (
    # Microsoft
    "sharepoint.com", "onmicrosoft.com", "blob.core.windows.net", "web.core.windows.net", "azurewebsites.net",
    "azureedge.net", "azurefd.net", "azurestaticapps.net", "cloudapp.azure.com", "trafficmanager.net",
    "servicebus.windows.net",
    # Google
    "googleusercontent.com", "storage.googleapis.com", "appspot.com", "firebaseapp.com", "web.app", "page.link",
    # Amazon
    "amazonaws.com", "cloudfront.net", "awsapps.com",
    # Hosting / developer platforms
    "github.io", "githubusercontent.com", "gitlab.io", "pages.dev", "workers.dev", "r2.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "glitch.me", "onrender.com", "fly.dev", "surge.sh", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com",
    # Site builders, SaaS tenants
    "wixsite.com", "weebly.com", "webflow.io", "blogspot.com", "wordpress.com", "myshopify.com", "square.site",
    "godaddysites.com", "notion.site", "force.com", "my.salesforce.com", "my.site.com", "atlassian.net",
    "zendesk.com", "freshdesk.com", "dweb.link",
)

MAX_ENTRIES = 1000


def _clean(xs: Any) -> list[str]:
    out = []
    for x in xs or []:
        v = str(x).strip().lower().lstrip("*.").lstrip("@").rstrip(".")
        if v and "." in v and " " not in v and "/" not in v and v not in out:
            out.append(v)
    return out[:MAX_ENTRIES]


def _stored() -> dict[str, Any]:
    try:
        from . import appsettings
        return appsettings.load().get("trusted_domains") or {}
    except Exception:  # noqa: BLE001  (settings unreadable: defaults)
        return {}


def lists(stored: dict[str, Any] | None = None) -> dict[str, list[str]]:
    """The lists in force: defaults minus what the user removed, plus what the user added."""
    st = _stored() if stored is None else stored
    out: dict[str, list[str]] = {}
    for kind, dft in (("services", SERVICES), ("platforms", PLATFORMS)):
        removed = set(_clean(st.get(f"{kind}_removed")))
        out[kind] = [d for d in dft if d not in removed] + [d for d in _clean(st.get(f"{kind}_added")) if d not in dft]
    return out


def to_stored(services: list[str], platforms: list[str]) -> dict[str, list[str]]:
    """What Settings keeps: only the differences from the defaults."""
    s, p = _clean(services), _clean(platforms)
    return {"services_added": [d for d in s if d not in SERVICES],
            "services_removed": [d for d in SERVICES if d not in s],
            "platforms_added": [d for d in p if d not in PLATFORMS],
            "platforms_removed": [d for d in PLATFORMS if d not in p]}


class Matcher:
    """Classifies hosts against the lists (longest suffix wins, so
    ``storage.googleapis.com`` is a platform although ``googleapis.com`` is a service)."""

    def __init__(self, data: dict[str, list[str]] | None = None) -> None:
        data = data if data is not None else lists()
        self.entries = sorted([(d, "service") for d in data.get("services", [])]
                              + [(d, "platform") for d in data.get("platforms", [])],
                              key=lambda x: -len(x[0]))

    def match(self, host: str) -> tuple[str, str] | None:
        """(kind, entry) for a host on a listed domain, else None."""
        h = (host or "").lower().strip(".")
        for d, kind in self.entries:
            if h == d or h.endswith("." + d):
                return kind, d
        return None

    def view(self, host: str) -> tuple[str | None, str]:
        """The part of ``host`` worth comparing, and the platform it sits on.

        Not listed → (host, ""); service → (None, "") (never compared); platform →
        (``<tenant>.invalid``, platform) so the tenant's last label is the name compared;
        the bare platform host → (None, platform)."""
        m = self.match(host)
        if m is None:
            return host, ""
        kind, d = m
        if kind == "service":
            return None, ""
        tenant = (host or "").lower().strip(".")[: -len(d)].rstrip(".")
        return (f"{tenant}.invalid" if tenant else None), d


def matcher() -> Matcher:
    return Matcher()
