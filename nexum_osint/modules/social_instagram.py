"""Instagram: datos que el titular publica en su perfil.

Consulta los mismos endpoints que usa la app móvil y requiere el `sessionid` de una cuenta
propia (key `instagram_session`). Usa una cuenta secundaria: Instagram puede limitar o
suspender sesiones que hacen consultas automatizadas.

Solo se leen datos que el titular decidió publicar (nombre, biografía, enlace, contacto
de empresa). No se consultan los flujos de recuperación de cuenta.
"""
from ..core.entities import Kind
from ..core.module import Module

APP_ID_WEB = "936619743392459"


def _cookie(session: str) -> dict:
    return {"Cookie": f"sessionid={session}"}


class InstagramProfile(Module):
    name = "instagram"
    description = "Perfil de Instagram: nombre, biografía, enlaces y contacto publicado por el titular"
    consumes = (Kind.USERNAME,)
    needs_key = "instagram_session"
    rate = 0.5
    hosts = ("i.instagram.com",)

    async def run(self, ctx, node):
        session = ctx.config.key("instagram_session")
        uid = await self._user_id(ctx, node, session)
        if not uid:
            return
        resp = await ctx.http.get(
            f"https://i.instagram.com/api/v1/users/{uid}/info/",
            headers={"User-Agent": "Instagram 64.0.0.14.96", **_cookie(session)}, ttl=3600)
        if resp.status == 429:
            ctx.graph.note(self.name, "Instagram limitó las consultas",
                           "Espera unos minutos antes de volver a intentarlo.", "info", node)
            return
        if not resp.ok:
            return
        info = (resp.json() or {}).get("user")
        if not info:
            return
        self._fill(ctx, node, info, uid)

    async def _user_id(self, ctx, node, session):
        resp = await ctx.http.get(
            "https://i.instagram.com/api/v1/users/web_profile_info/",
            params={"username": node.value},
            headers={"User-Agent": "iphone_ua", "x-ig-app-id": APP_ID_WEB, **_cookie(session)},
            ttl=3600)
        if resp.status == 404:
            return None
        if resp.status in (401, 403):
            ctx.graph.note(self.name, "Sesión de Instagram rechazada",
                           "El sessionid venció o es incorrecto: vuelve a copiarlo del navegador.",
                           "info", node)
            return None
        try:
            return str(resp.json()["data"]["user"]["id"])
        except (ValueError, KeyError, TypeError):
            return None   # límite de consultas o cuenta inexistente

    def _fill(self, ctx, node, info, uid):
        node.attrs.update({
            "instagram_id": uid,
            "instagram_name": info.get("full_name"),
            "instagram_private": info.get("is_private"),
            "instagram_verified": info.get("is_verified"),
            "instagram_business": info.get("is_business"),
            "instagram_followers": info.get("follower_count"),
            "instagram_following": info.get("following_count"),
            "instagram_posts": info.get("media_count"),
            "instagram_bio": (info.get("biography") or "").strip() or None,
            "instagram_whatsapp": info.get("is_whatsapp_linked"),
            "instagram_memorial": info.get("is_memorialized"),
        })
        pic = (info.get("hd_profile_pic_url_info") or {}).get("url")
        if pic:
            node.attrs["instagram_avatar"] = pic
        if info.get("full_name"):
            ctx.emit(node, Kind.NAME, info["full_name"], "profile_name", self.name,
                     pivot=False, confidence="media")
        if info.get("external_url"):
            ctx.emit(node, Kind.URL, info["external_url"], "listed_link", self.name, pivot=False)
        if info.get("public_email"):
            ctx.emit(node, Kind.EMAIL, info["public_email"], "public_contact", self.name)
        number = str(info.get("public_phone_number") or "").strip()
        if number:
            prefix = str(info.get("public_phone_country_code") or "").lstrip("+")
            ctx.emit(node, Kind.PHONE, f"+{prefix}{number}" if prefix else number,
                     "public_contact", self.name)
