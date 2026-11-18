"""Módulos de correo electrónico: dominio, Gravatar y reputación."""
import hashlib

from ..core.entities import Kind
from ..core.module import Module


class EmailDomain(Module):
    name = "email_domain"
    description = "Extrae el usuario y el dominio del correo y los usa como pivote"
    consumes = (Kind.EMAIL,)

    async def run(self, ctx, node):
        local, domain = node.value.split("@", 1)
        ctx.emit(node, Kind.DOMAIN, domain, "mailbox_on", self.name)
        # Usuario del correo como posible alias en redes (solo si no es genérico)
        if len(local) >= 4 and not local.isdigit():
            ctx.emit(node, Kind.USERNAME, local.split("+")[0], "possible_alias", self.name,
                     confidence="baja")


class Gravatar(Module):
    name = "gravatar"
    description = "Perfil público de Gravatar asociado al correo (nombre, cuentas enlazadas)"
    consumes = (Kind.EMAIL,)
    rate = 2
    hosts = ("gravatar.com", "en.gravatar.com")

    async def run(self, ctx, node):
        digest = hashlib.md5(node.value.encode()).hexdigest()  # noqa: S324 (lo exige Gravatar)
        resp = await ctx.http.get(f"https://en.gravatar.com/{digest}.json", ttl=24 * 3600)
        if resp.status != 200:
            return
        entry = resp.json().get("entry", [{}])[0]
        node.attrs["gravatar"] = True
        node.attrs["gravatar_name"] = entry.get("displayName")
        node.attrs["gravatar_location"] = entry.get("currentLocation")
        node.attrs["gravatar_avatar"] = entry.get("thumbnailUrl")
        if entry.get("preferredUsername"):
            ctx.emit(node, Kind.USERNAME, entry["preferredUsername"], "gravatar_user", self.name)
        for acc in entry.get("accounts", []):
            url, shortname = acc.get("url"), acc.get("shortname")
            if url:
                ctx.emit(node, Kind.PROFILE, url, "linked_account", self.name,
                         pivot=False, site=shortname, username=acc.get("username"))
        for link in entry.get("urls", []):
            if link.get("value"):
                ctx.emit(node, Kind.URL, link["value"], "listed_link", self.name, pivot=False)


class EmailRep(Module):
    name = "emailrep"
    description = "Reputación del correo, brechas conocidas y perfiles vistos (emailrep.io)"
    consumes = (Kind.EMAIL,)
    optional_key = "emailrep"
    rate = 0.3
    hosts = ("emailrep.io",)

    async def run(self, ctx, node):
        headers = {"accept": "application/json"}
        if key := ctx.config.key("emailrep"):
            headers["Key"] = key
        resp = await ctx.http.get(f"https://emailrep.io/{node.value}", headers=headers,
                                  ttl=24 * 3600, retries=1)
        if resp.status == 429:
            ctx.graph.note(self.name, "Cuota gratuita de EmailRep agotada",
                           "Define NEXUM_EMAILREP con una key gratuita para ampliarla.", "info", node)
            return
        if not resp.ok:
            return
        data = resp.json()
        details = data.get("details", {})
        node.attrs["reputation"] = data.get("reputation")
        node.attrs["suspicious"] = data.get("suspicious")
        node.attrs["references"] = data.get("references")
        node.attrs["first_seen"] = details.get("first_seen")
        node.attrs["last_seen"] = details.get("last_seen")
        node.attrs["disposable"] = details.get("disposable")
        node.attrs["free_provider"] = details.get("free_provider")
        for profile in details.get("profiles", []):
            ctx.emit(node, Kind.PROFILE, f"{profile} (vía emailrep)", "seen_on", self.name,
                     pivot=False, site=profile)
        if details.get("credentials_leaked"):
            ctx.graph.note(self.name, "Credenciales expuestas en filtraciones públicas",
                           f"Primera vez visto: {details.get('first_seen')}", "high", node)
        if details.get("disposable"):
            ctx.graph.note(self.name, "Correo desechable", "", "low", node)


DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com",
    "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mailnesia.com", "mintemail.com",
    "emailondeck.com", "tempail.com", "moakt.com", "mohmal.com", "burnermail.io",
}


class EmailChecks(Module):
    name = "email_checks"
    description = "Sintaxis, dominio desechable y servidores MX (DNS-over-HTTPS)"
    consumes = (Kind.EMAIL,)
    rate = 8
    hosts = ("cloudflare-dns.com",)

    async def run(self, ctx, node):
        domain = node.value.split("@", 1)[1]
        node.attrs["disposable_domain"] = domain in DISPOSABLE
        if domain in DISPOSABLE:
            ctx.graph.note(self.name, "Dominio de correo desechable", domain, "low", node)
        resp = await ctx.http.get("https://cloudflare-dns.com/dns-query",
                                  params={"name": domain, "type": "MX"},
                                  headers={"accept": "application/dns-json"}, ttl=1800)
        if resp.ok:
            mx = [a["data"] for a in resp.json().get("Answer", []) if a.get("type") == 15]
            node.attrs["mx_records"] = mx[:5]
            if not mx:
                ctx.graph.note(self.name, "El dominio no tiene servidores MX",
                               "El buzón no puede recibir correo: dirección probablemente inexistente.",
                               "medium", node)


class XposedOrNot(Module):
    name = "xposedornot"
    description = "Filtraciones públicas del correo con detalle: fecha, registros, datos y riesgo (XposedOrNot, sin key)"
    consumes = (Kind.EMAIL,)
    rate = 1
    hosts = ("api.xposedornot.com",)

    async def run(self, ctx, node):
        resp = await ctx.http.get("https://api.xposedornot.com/v1/breach-analytics",
                                  params={"email": node.value}, ttl=24 * 3600)
        if resp.ok:
            data = resp.json() or {}
            details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
            if details:
                self._report(ctx, node, data, details)
                return
            if data.get("ExposedBreaches") is None:
                return
        await self._basic(ctx, node)

    def _report(self, ctx, node, data, details):
        names = sorted({d.get("breach") for d in details if d.get("breach")})
        classes = sorted({c.strip() for d in details for c in (d.get("xposed_data") or "").split(";") if c.strip()})
        metrics = data.get("BreachMetrics") or {}
        risk = ((metrics.get("risk") or [{}])[0]) or {}
        pwd = ((metrics.get("passwords_strength") or [{}])[0]) or {}
        node.attrs["breaches"] = names
        node.attrs["datos_expuestos"] = classes
        if risk.get("risk_label"):
            node.attrs["riesgo_xposedornot"] = f"{risk['risk_label']} ({risk.get('risk_score', '?')}/100)"
        node.attrs["eventos_filtracion"] = [
            {"fecha": str(d.get("xposed_date") or ""), "detalle": f"Filtración {d.get('breach')}: {d.get('xposed_data') or 's/d'}"[:110]}
            for d in details if str(d.get("xposed_date") or "").isdigit()]
        ordered = sorted(details, key=lambda d: str(d.get("xposed_date") or ""), reverse=True)
        lines = [f"{d.get('breach')} ({d.get('xposed_date') or '?'}, {d.get('xposed_records') or '?'} registros): "
                 f"{d.get('xposed_data') or 's/d'}" for d in ordered[:12]]
        label = f" · riesgo {node.attrs['riesgo_xposedornot']}" if "riesgo_xposedornot" in node.attrs else ""
        ctx.graph.note(self.name, f"Correo presente en {len(names)} filtraciones públicas{label}", "\n".join(lines), "high", node)
        plain, weak = pwd.get("PlainText", 0) or 0, pwd.get("EasyToCrack", 0) or 0
        if plain or weak or any("password" in c.lower() for c in classes):
            ctx.graph.note(self.name, "Contraseñas expuestas en filtraciones",
                           f"En texto plano: {plain} · fáciles de descifrar: {weak}. Si el titular las reutiliza, "
                           "conviene cambiarlas y activar verificación en dos pasos.", "high", node)

    async def _basic(self, ctx, node):
        resp = await ctx.http.get(f"https://api.xposedornot.com/v1/check-email/{node.value}", ttl=24 * 3600)
        if resp.status == 404 or not resp.ok:
            return
        breaches = resp.json().get("breaches") or []
        names = sorted({b for group in breaches for b in (group if isinstance(group, list) else [group])})
        if names:
            node.attrs["breaches"] = names
            ctx.graph.note(self.name, f"Correo presente en {len(names)} filtraciones públicas",
                           ", ".join(names[:25]), "high", node)


class LeakCheckPublic(Module):
    name = "leakcheck"
    description = "Filtraciones y tipo de dato expuesto (LeakCheck API pública, gratis y sin key)"
    consumes = (Kind.EMAIL,)
    rate = 0.5
    hosts = ("leakcheck.io",)

    async def run(self, ctx, node):
        resp = await ctx.http.get("https://leakcheck.io/api/public", params={"check": node.value}, ttl=24 * 3600)
        if not resp.ok:
            return
        data = resp.json()
        if not data.get("success") or not data.get("found"):
            return
        sources = [s.get("name") for s in data.get("sources", []) if s.get("name")]
        fields = data.get("fields", [])
        node.attrs["leakcheck_found"] = data["found"]
        node.attrs["leakcheck_fields"] = fields
        sev = "high" if "password" in fields else "medium"
        ctx.graph.note(self.name, f"{data['found']} registros en filtraciones (campos: {', '.join(fields)})",
                       ", ".join(sources[:25]), sev, node)


class GithubEmail(Module):
    name = "github_email"
    description = "Commits y cuentas de GitHub asociados a un correo (búsqueda pública)"
    consumes = (Kind.EMAIL,)
    optional_key = "github"
    rate = 0.3
    hosts = ("api.github.com",)

    async def run(self, ctx, node):
        h = {"accept": "application/vnd.github+json"}
        if key := ctx.config.key("github"):
            h["authorization"] = f"Bearer {key}"
        users = await ctx.http.get("https://api.github.com/search/users",
                                   params={"q": f"{node.value} in:email"}, headers=h, ttl=12 * 3600)
        if users.ok:
            for item in users.json().get("items", [])[:3]:
                ctx.emit(node, Kind.USERNAME, item["login"], "github_account", self.name)
        commits = await ctx.http.get("https://api.github.com/search/commits",
                                     params={"q": f"author-email:{node.value}", "per_page": 20},
                                     headers=h, ttl=12 * 3600)
        if commits.ok:
            items = commits.json().get("items", [])
            names = {i.get("commit", {}).get("author", {}).get("name") for i in items}
            names.discard(None)
            for nm in sorted(names):
                ctx.emit(node, Kind.NAME, nm, "commit_author_name", self.name, pivot=False)
            repos = sorted({i.get("repository", {}).get("full_name") for i in items if i.get("repository")})
            if repos:
                node.attrs["github_repos"] = repos[:10]
                ctx.graph.note(self.name, f"El correo firma commits en {len(repos)} repositorios",
                               ", ".join(repos[:10]), "medium", node)


class HunterEmail(Module):
    name = "hunter_email"
    description = "Verificación de entregabilidad del correo (Hunter.io, key gratuita)"
    consumes = (Kind.EMAIL,)
    needs_key = "hunter"
    rate = 0.5
    hosts = ("api.hunter.io",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://api.hunter.io/v2/email-verifier",
                               params={"email": node.value, "api_key": ctx.config.key("hunter")}, ttl=24 * 3600)
        if r.ok:
            d = r.json().get("data", {})
            node.attrs["hunter_status"] = d.get("status")
            node.attrs["hunter_score"] = d.get("score")
            node.attrs["hunter_webmail"] = d.get("webmail")


class IpqsEmail(Module):
    name = "ipqs_email"
    description = "Puntuación de fraude, filtración y validez del correo (IPQualityScore, key gratuita)"
    consumes = (Kind.EMAIL,)
    needs_key = "ipqs"
    rate = 1
    hosts = ("ipqualityscore.com",)

    async def run(self, ctx, node):
        key = ctx.config.key("ipqs")
        r = await ctx.http.get(f"https://ipqualityscore.com/api/json/email/{key}/{node.value}", ttl=24 * 3600)
        if not r.ok:
            return
        d = r.json()
        if not d.get("success", True):
            return
        for k in ("valid", "disposable", "fraud_score", "recent_abuse", "leaked", "dns_valid", "honeypot"):
            node.attrs[f"ipqs_{k}"] = d.get(k)
        if d.get("leaked"):
            ctx.graph.note(self.name, "IPQS reporta el correo en filtraciones", "", "high", node)
        if d.get("recent_abuse"):
            ctx.graph.note(self.name, "Abuso reciente asociado al correo", "", "medium", node)
