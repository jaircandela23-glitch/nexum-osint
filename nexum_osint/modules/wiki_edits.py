"""Wikipedia: ediciones anónimas desde una IP y cuentas de usuario."""
from ..core.entities import Kind
from ..core.module import Module

API = "https://en.wikipedia.org/w/api.php"


class WikipediaIp(Module):
    name = "wiki_ip"
    description = "Artículos de Wikipedia editados de forma anónima desde la IP"
    consumes = (Kind.IP,)
    rate = 2
    hosts = ("en.wikipedia.org",)

    async def run(self, ctx, node):
        resp = await ctx.http.get(API, params={"action": "query", "list": "usercontribs",
                                               "ucuser": node.value, "uclimit": 25, "format": "json"},
                                  ttl=24 * 3600)
        if not resp.ok:
            return
        edits = resp.json().get("query", {}).get("usercontribs", [])
        if edits:
            titles = sorted({e["title"] for e in edits})
            node.attrs["wikipedia_edits"] = len(edits)
            ctx.graph.note(self.name, f"{len(edits)} ediciones anónimas en Wikipedia desde esta IP",
                           "; ".join(titles[:8]), "info", node)


class WikipediaUser(Module):
    name = "wiki_user"
    description = "Cuenta de Wikipedia con ese alias: fecha de alta y cantidad de ediciones"
    consumes = (Kind.USERNAME,)
    rate = 2
    hosts = ("en.wikipedia.org",)

    async def run(self, ctx, node):
        resp = await ctx.http.get(API, params={"action": "query", "list": "users",
                                               "ususers": node.value, "usprop": "registration|editcount",
                                               "format": "json"}, ttl=24 * 3600)
        if not resp.ok:
            return
        users = resp.json().get("query", {}).get("users", [])
        if not users or "missing" in users[0] or "invalid" in users[0]:
            return
        user = users[0]
        node.attrs["wikipedia_edits"] = user.get("editcount")
        node.attrs["wikipedia_since"] = user.get("registration")
        ctx.emit(node, Kind.PROFILE, f"https://en.wikipedia.org/wiki/User:{user['name'].replace(' ', '_')}",
                 "account_on", self.name, pivot=False, site="Wikipedia", username=user["name"])
