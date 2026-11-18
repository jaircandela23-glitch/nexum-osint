"""Perfiles de alias en servicios con API pública: devuelven datos reales, no solo "existe"."""
from __future__ import annotations

import asyncio
import re

from ..core.entities import Kind
from ..core.module import Module

NOREPLY = re.compile(r"(noreply|no-reply)", re.I)


class GithubUser(Module):
    name = "github_user"
    description = "Perfil de GitHub: nombre, empresa, ubicación, sitio web y correos en commits públicos"
    consumes = (Kind.USERNAME,)
    optional_key = "github"
    rate = 1
    hosts = ("api.github.com",)

    def _headers(self, ctx):
        h = {"accept": "application/vnd.github+json"}
        if key := ctx.config.key("github"):
            h["authorization"] = f"Bearer {key}"
        return h

    async def run(self, ctx, node):
        h = self._headers(ctx)
        resp = await ctx.http.get(f"https://api.github.com/users/{node.value}", headers=h, ttl=6 * 3600)
        if resp.status == 403:
            ctx.graph.note(self.name, "Límite de la API de GitHub alcanzado",
                           "Define NEXUM_GITHUB con un token gratuito para ampliarlo.", "info", node)
            return
        if not resp.ok:
            return
        d = resp.json()
        url = d.get("html_url") or f"https://github.com/{node.value}"
        prof = ctx.emit(node, Kind.PROFILE, url, "has_profile", self.name, pivot=False,
                        site="GitHub", category="dev", username=node.value,
                        full_name=d.get("name"), company=d.get("company"),
                        location=d.get("location"), bio=d.get("bio"), blog=d.get("blog"),
                        followers=d.get("followers"), repos=d.get("public_repos"),
                        created=d.get("created_at"), twitter=d.get("twitter_username"))
        if d.get("name"):
            ctx.emit(node, Kind.NAME, d["name"], "display_name", self.name, pivot=False)
        if d.get("email"):
            ctx.emit(node, Kind.EMAIL, d["email"], "public_email", self.name)
        if d.get("blog"):
            blog = d["blog"] if d["blog"].startswith("http") else "https://" + d["blog"]
            ctx.emit(node, Kind.URL, blog, "listed_link", self.name, pivot=False)
        if d.get("twitter_username"):
            ctx.emit(node, Kind.PROFILE, f"https://x.com/{d['twitter_username']}", "linked_account",
                     self.name, pivot=False, site="Twitter / X", username=d["twitter_username"])

        ev = await ctx.http.get(f"https://api.github.com/users/{node.value}/events/public",
                                headers=h, ttl=3 * 3600)
        if ev.ok:
            emails: dict[str, str] = {}
            for event in ev.json():
                for c in event.get("payload", {}).get("commits", []) or []:
                    a = c.get("author", {})
                    mail = (a.get("email") or "").lower()
                    if mail and not NOREPLY.search(mail):
                        emails[mail] = a.get("name") or ""
            for mail, nm in sorted(emails.items()):
                ctx.emit(node, Kind.EMAIL, mail, "commit_email", self.name, commit_author=nm or None)
            if emails:
                ctx.graph.note(self.name, f"{len(emails)} correo(s) expuestos en commits públicos de GitHub",
                               ", ".join(sorted(emails)[:10]), "medium", node)


class ProfileApis(Module):
    name = "profile_apis"
    description = "Consulta directa a APIs públicas (GitLab, Reddit, Keybase, HN, Dev.to, Docker Hub, Lichess, Chess.com, Bluesky, npm)"
    consumes = (Kind.USERNAME,)
    rate = 3

    async def run(self, ctx, node):
        u = node.value
        jobs = [self._gitlab, self._reddit, self._keybase, self._hn, self._devto,
                self._docker, self._lichess, self._chess, self._bluesky, self._npm]
        await asyncio.gather(*(self._safe(j, ctx, node, u) for j in jobs))

    async def _safe(self, fn, ctx, node, u):
        try:
            await fn(ctx, node, u)
        except Exception as exc:  # una API caída no debe frenar a las demás
            ctx.graph.note(self.name, f"{fn.__name__[1:]} no respondió", str(exc)[:120], "info", node)

    def _profile(self, ctx, node, url, site, **attrs):
        ctx.emit(node, Kind.PROFILE, url, "has_profile", self.name, pivot=False,
                 site=site, username=node.value, **attrs)

    async def _gitlab(self, ctx, node, u):
        r = await ctx.http.get("https://gitlab.com/api/v4/users", params={"username": u}, ttl=6 * 3600, retries=1)
        if r.ok and (rows := r.json()):
            self._profile(ctx, node, rows[0].get("web_url", f"https://gitlab.com/{u}"), "GitLab",
                          full_name=rows[0].get("name"), state=rows[0].get("state"))

    async def _reddit(self, ctx, node, u):
        r = await ctx.http.get(f"https://www.reddit.com/user/{u}/about.json", ttl=6 * 3600, retries=1)
        if r.ok:
            d = r.json().get("data", {})
            if d.get("name"):
                self._profile(ctx, node, f"https://www.reddit.com/user/{d['name']}", "Reddit",
                              created_utc=d.get("created_utc"), link_karma=d.get("link_karma"),
                              comment_karma=d.get("comment_karma"))

    async def _keybase(self, ctx, node, u):
        r = await ctx.http.get("https://keybase.io/_/api/1.0/user/lookup.json",
                               params={"usernames": u, "fields": "basics,profile,proofs_summary"},
                               ttl=6 * 3600, retries=1)
        if not r.ok:
            return
        them = (r.json().get("them") or [None])[0]
        if not them:
            return
        prof = them.get("profile") or {}
        self._profile(ctx, node, f"https://keybase.io/{u}", "Keybase",
                      full_name=prof.get("full_name"), location=prof.get("location"))
        if prof.get("full_name"):
            ctx.emit(node, Kind.NAME, prof["full_name"], "display_name", self.name, pivot=False)
        for proof in (them.get("proofs_summary") or {}).get("all", []):
            link = proof.get("service_url") or proof.get("proof_url")
            if link:
                ctx.emit(node, Kind.PROFILE, link, "verified_proof", self.name, pivot=False,
                         site=proof.get("proof_type"), username=proof.get("nametag"),
                         note="cuenta verificada criptográficamente en Keybase")

    async def _hn(self, ctx, node, u):
        r = await ctx.http.get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json", ttl=6 * 3600, retries=1)
        if r.ok and (d := r.json()):
            self._profile(ctx, node, f"https://news.ycombinator.com/user?id={u}", "Hacker News",
                          karma=d.get("karma"), created=d.get("created"), about=(d.get("about") or "")[:200])

    async def _devto(self, ctx, node, u):
        r = await ctx.http.get("https://dev.to/api/users/by_username", params={"url": u}, ttl=6 * 3600, retries=1)
        if r.ok:
            d = r.json()
            self._profile(ctx, node, f"https://dev.to/{u}", "Dev.to", full_name=d.get("name"),
                          location=d.get("location"), summary=d.get("summary"), joined=d.get("joined_at"))
            for key, site, base in (("github_username", "GitHub", "https://github.com/"),
                                    ("twitter_username", "Twitter / X", "https://x.com/")):
                if d.get(key):
                    ctx.emit(node, Kind.PROFILE, base + d[key], "linked_account", self.name,
                             pivot=False, site=site, username=d[key])

    async def _docker(self, ctx, node, u):
        r = await ctx.http.get(f"https://hub.docker.com/v2/users/{u}/", ttl=6 * 3600, retries=1)
        if r.ok:
            d = r.json()
            if d.get("username"):
                self._profile(ctx, node, f"https://hub.docker.com/u/{u}", "Docker Hub",
                              full_name=d.get("full_name"), location=d.get("location"),
                              company=d.get("company"), joined=d.get("date_joined"))

    async def _lichess(self, ctx, node, u):
        r = await ctx.http.get(f"https://lichess.org/api/user/{u}", ttl=6 * 3600, retries=1)
        if r.ok:
            d = r.json()
            p = d.get("profile") or {}
            self._profile(ctx, node, f"https://lichess.org/@/{d.get('username', u)}", "Lichess",
                          country=p.get("country"), location=p.get("location"),
                          real_name=" ".join(x for x in (p.get("firstName"), p.get("lastName")) if x) or None,
                          created=d.get("createdAt"))

    async def _chess(self, ctx, node, u):
        r = await ctx.http.get(f"https://api.chess.com/pub/player/{u.lower()}", ttl=6 * 3600, retries=1)
        if r.ok:
            d = r.json()
            self._profile(ctx, node, d.get("url", f"https://www.chess.com/member/{u}"), "Chess.com",
                          full_name=d.get("name"), joined=d.get("joined"),
                          country=(d.get("country") or "").rsplit("/", 1)[-1] or None)

    async def _bluesky(self, ctx, node, u):
        handle = u if "." in u else f"{u}.bsky.social"
        r = await ctx.http.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                               params={"actor": handle}, ttl=6 * 3600, retries=1)
        if r.ok:
            d = r.json()
            self._profile(ctx, node, f"https://bsky.app/profile/{d.get('handle', handle)}", "Bluesky",
                          display_name=d.get("displayName"), bio=(d.get("description") or "")[:200],
                          followers=d.get("followersCount"), did=d.get("did"))

    async def _npm(self, ctx, node, u):
        r = await ctx.http.get("https://registry.npmjs.org/-/v1/search",
                               params={"text": f"maintainer:{u}", "size": 20}, ttl=6 * 3600, retries=1)
        if not r.ok:
            return
        objs = r.json().get("objects", [])
        if not objs:
            return
        self._profile(ctx, node, f"https://www.npmjs.com/~{u}", "npm", packages=len(objs))
        for o in objs:
            for m in o.get("package", {}).get("maintainers", []):
                if m.get("username", "").lower() == u.lower() and m.get("email") and not NOREPLY.search(m["email"]):
                    ctx.emit(node, Kind.EMAIL, m["email"], "npm_maintainer_email", self.name)
