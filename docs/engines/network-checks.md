# Network checks

Checking an indicator means contacting the attacker's infrastructure, so it only happens when
you press **Check**, and always through your proxy (HTTP, HTTPS, SOCKS — Tor works — or a free
public proxy picked and rotated for you).

- **URLs** are visited like a real victim would: desktop and mobile (to catch cloaking), with a
  **fake identity** replacing the victim's address in the link. You get redirects, certificate,
  forms, the impersonated brand, a screenshot and a safe preview rendered offline; served files
  are analysed, and **Send fake credentials** shows the next stage of a phishing kit.
- **Domains**: DNS, registration age, certificates and their website.
- **IPs** are never contacted: owner, ASN, country, reverse DNS and Tor come from public
  registries and a local database.

The page's scripts never run, and nothing else is downloaded.

!!! tip "Practise safely"
    `python scripts/phish_lab.py` starts a local phishing-kit simulator; analyse
    `email/phish_lab.eml` from the samples and press **Check** on its link.
