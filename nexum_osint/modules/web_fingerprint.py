import re

from ..core.entities import Kind
from ..core.module import Module

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS", "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}
SOCIAL = {"facebook.com": "Facebook", "instagram.com": "Instagram", "x.com": "X", "twitter.com": "X",
          "linkedin.com": "LinkedIn", "youtube.com": "YouTube", "tiktok.com": "TikTok",
          "github.com": "GitHub", "t.me": "Telegram", "wa.me": "WhatsApp", "threads.net": "Threads"}
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
TEL = re.compile(r'href=["\']tel:([+0-9()\s.\-]{7,20})["\']', re.I)
HREF = re.compile(r'href=["\'](https?://[^"\'#\s]+)', re.I)
TRACKERS = [re.compile(p) for p in (r"\bUA-\d{4,10}-\d{1,3}\b", r"\bG-[A-Z0-9]{8,12}\b", r"\bGTM-[A-Z0-9]{5,8}\b",
                                    r"\bca-pub-\d{10,20}\b", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]")]
IMAGE_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")


class WebFingerprint(Module):
    name = "web_fingerprint"
    description = "Tecnologías, cabeceras de seguridad, contactos, redes y analítica de la web del dominio"
    consumes = (Kind.DOMAIN,)
    active = True
    rate = 2

    async def run(self, ctx, node):
        if node.depth > 1:
            return
        resp = None
        for scheme in ("https", "http"):
            try:
                resp = await ctx.http.get(f"{scheme}://{node.value}/", ttl=3600, retries=0)
                break
            except ConnectionError:
                continue
        if resp is None:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:600_000]
        node.attrs["http_status"] = resp.status
        for key in ("server", "x-powered-by", "x-generator", "via"):
            if headers.get(key):
                node.attrs[f"http_{key.replace('-', '_')}"] = headers[key][:80]
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if title:
            node.attrs["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:120]
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if gen:
            node.attrs["generator"] = gen.group(1)[:80]

        if resp.url.startswith("https://"):
            missing = [label for key, label in SECURITY_HEADERS.items() if key not in headers]
            node.attrs["security_headers_missing"] = missing
            if len(missing) >= 4:
                ctx.graph.note(self.name, f"Faltan {len(missing)} de 5 cabeceras de seguridad",
                               ", ".join(missing), "low", node)
        else:
            ctx.graph.note(self.name, "El sitio no responde por HTTPS", "", "medium", node)

        for mail in sorted({m.lower() for m in EMAIL.findall(body)}):
            if not mail.endswith(IMAGE_SUFFIX) and "example" not in mail and "sentry" not in mail:
                ctx.emit(node, Kind.EMAIL, mail, "published_on_site", self.name)
        for tel in sorted({re.sub(r"[^0-9+]", "", t) for t in TEL.findall(body)}):
            ctx.emit(node, Kind.PHONE, tel, "published_on_site", self.name)
        seen = set()
        for url in HREF.findall(body):
            host = re.sub(r"^www\.", "", url.split("/")[2].lower())
            site = SOCIAL.get(host)
            if site and url.rstrip("/") not in seen and not url.rstrip("/").endswith(host):
                seen.add(url.rstrip("/"))
                ctx.emit(node, Kind.PROFILE, url, "linked_from_site", self.name, pivot=False, site=site)
        ids = sorted({m.group(1) if m.groups() else m.group(0) for rx in TRACKERS for m in rx.finditer(body)})
        if ids:
            node.attrs["analytics"] = ids

        try:
            robots = await ctx.http.get(f"https://{node.value}/robots.txt", ttl=3600, retries=0)
        except ConnectionError:
            robots = None
        if robots is not None and robots.ok and "<html" not in robots.text[:200].lower():
            paths = sorted({l.split(":", 1)[1].strip() for l in robots.text.splitlines()
                            if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip() not in ("", "/")})
            if paths:
                node.attrs["robots_disallow"] = paths[:25]
        sec = await ctx.http.get(f"https://{node.value}/.well-known/security.txt", ttl=3600, retries=0)
        if sec.ok and "contact:" in sec.text.lower():
            node.attrs["security_txt"] = True
            for line in sec.text.splitlines():
                if line.lower().startswith("contact:") and "@" in line:
                    ctx.emit(node, Kind.EMAIL, line.split(":", 1)[1].replace("mailto:", "").strip(), "security_contact", self.name)
