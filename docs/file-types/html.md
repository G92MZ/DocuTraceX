# HTML and SVG pages

An HTML, SVG or MHT file — a phishing attachment, a page inside an archive, the HTML body of an
email — gets an **HTML** tab: what the victim would see, and where what they type would go.
**Nothing in the page runs.**

## Tabs

??? abstract "HTML — preview, structure, victim and findings"

    - **Preview**: a picture of the page rendered by the Chromium of the
      [network checks](../engines/network-checks.md) in its offline mode — **JavaScript off and
      every network request blocked**, in its own process — so the page never tells its author
      it was opened. Remote images, CSS and fonts show as gaps (they are listed below).
    - **Loaders**: when the page is only a script that writes itself (`document.write(atob(…))`,
      `unescape`, `String.fromCharCode`, escaped strings), the next layer is **decoded from its
      literals, never executed**, and the preview shows the recovered page.
    - **Structure**: forms with their action, method and fields (password and hidden ones
      flagged), external resources (scripts, images, frames, CSS, fonts), redirects (meta refresh,
      `location`, `window.open`) and what the page says it is — title, headings, favicon, login /
      lure words.
    - **Victim**: an address **prefilled** in the page (a field's value, a variable — also in
      Base64 —, a link) is the person it was made for. It becomes an email IOC tagged **victim**
      — the user's own mailbox, never one to block — and, when the case is an email, it says
      whether it is one of the **recipients** (made for that person) or not (reused, forwarded).
    - **QR codes drawn with HTML, CSS or SVG** (table cells, `<div>`s, `<rect>`s: there is no
      image to extract) are read from the preview.
    - **Findings**: the email engine's HTML phishing rules (credential and payment forms, forms
      that post elsewhere or by email, exfiltration to chat bots and webhooks, smuggling,
      obfuscation, URI schemes…) on any page, plus: the victim's address prefilled, typed data
      **sent by script** (fetch / XHR / sendBeacon), **anti-analysis** (devtools detection, F12 /
      right-click / copy blocked, IP / geolocation lookups, automation checks, a CAPTCHA in
      front), **loader pages**, and a page that **names one domain but sends to another**. No
      brand lists: the page is compared with itself.

The HTML body of an email gets the same preview and QR reading in its HTML tab; its rules stay
in the email's own tabs. Pages downloaded by a network check are not rendered again (the check
has its own screenshots), and a case renders at most 12 nested pages.
