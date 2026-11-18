import io
import json
import unittest
import zipfile

from nexum_osint.core.cache import Cache
from nexum_osint.core.config import Config
from nexum_osint.core.engine import Engine
from nexum_osint.core.entities import Graph, Kind
from nexum_osint.core.http import Http, Response
from nexum_osint.core.module import discover
from nexum_osint.core.ratelimit import RateLimiter
from nexum_osint.modules import (cloud_buckets, doc_metadata, domain_lookalikes,
                                 domain_takeover, pgp_keys, reputation_dnsbl)
from tests.fakes import fake_fetch


def _json(body, status=200):
    return Response(status, json.dumps(body), {}, "")


async def fetch_v31(method, url, params=None, headers=None, data=None):
    params = params or {}
    if "i.instagram.com/api/v1/users/web_profile_info" in url:
        if headers.get("Cookie") != "sessionid=abc123":
            return _json({}, 401)
        return _json({"data": {"user": {"id": "4242"}}}) if params["username"] == "ana" else _json({}, 404)
    if "i.instagram.com/api/v1/users/4242/info" in url:
        return _json({"user": {
            "username": "ana", "full_name": "Ana Prueba", "is_private": False, "is_verified": False,
            "is_business": True, "follower_count": 120, "following_count": 80, "media_count": 9,
            "biography": "Fotos", "external_url": "https://ana.test", "public_email": "ana@ana.test",
            "public_phone_number": "987654321", "public_phone_country_code": "51",
            "hd_profile_pic_url_info": {"url": "https://cdn.test/a.jpg"}}})
    if "i.instagram.com/api/v1/users/lookup" in url:
        raise AssertionError("el módulo no debe consultar los flujos de recuperación de cuenta")
    if "keyserver.ubuntu.com" in url:
        return Response(200, "info:1:2\npub:ABCD:1:4096:1500000000::\n"
                             "uid:Ana%20Prueba%20%3Cana%40demo.test%3E:1500000000::\n"
                             "uid:Ana%20P%20%3Cotra%40demo.test%3E:1500000000::\n", {}, url)
    if "freeapi.robtex.com/pdns/forward" in url:
        return Response(200, '{"rrtype":"A","rrdata":"203.0.113.9"}\nbasura\n'
                             '{"rrtype":"NS","rrdata":"ns1.demo-dns.test."}\n', {}, url)
    if "freeapi.robtex.com/ipquery" in url:
        return _json({"status": "ok", "routedesc": "DEMO-NET", "pas": [{"o": "host1.demo.test."}]})
    if "en.wikipedia.org" in url and params.get("list") == "users":
        return _json({"query": {"users": [{"name": "Ana", "editcount": 42, "registration": "2012-01-01T00:00:00Z"}]}})
    if "en.wikipedia.org" in url and params.get("list") == "usercontribs":
        return _json({"query": {"usercontribs": [{"title": "Demo SA"}, {"title": "Lima"}]}})
    if "cloudflare-dns.com" in url and params.get("name", "").endswith(".zen.spamhaus.org"):
        return _json({"Answer": [{"type": 1, "data": "127.0.0.2"}]})
    if "cloudflare-dns.com" in url and params.get("name", "") == "mail.demo.test" and params["type"] == "CNAME":
        return _json({"Answer": [{"type": 5, "data": "demo.github.io."}]})
    if "cloudflare-dns.com" in url and params.get("name") == "demo.github.io":
        return _json({"Answer": [{"type": 1, "data": "185.199.108.153"}]})
    if "mail.demo.test/" in url and url.startswith("http://"):
        return Response(200, "<h1>There isn't a GitHub Pages site here.</h1>", {}, url)
    return await fake_fetch(method, url, params, headers, data)


def make_engine(graph, modules, cfg=None, depth=1, active=False):
    cfg = cfg or Config()
    http = Http(cfg, Cache(None, enabled=False), RateLimiter(default_rate=1000), fetch=fetch_v31)
    reg = {k: v for k, v in discover().items() if k in modules}
    eng = Engine(http, graph, cfg, reg, depth=depth, allow_active=active, options={})
    for host in list(http.limiter._buckets):
        http.limiter.configure(host, 1000, 50)
    return eng


class InstagramTests(unittest.IsolatedAsyncioTestCase):
    async def test_profile_published_data_only(self):
        g = Graph()
        cfg = Config(keys={"instagram_session": "abc123"})
        await make_engine(g, {"instagram"}, cfg, depth=0).run([(Kind.USERNAME, "ana")])
        node = g.nodes["username:ana"]
        self.assertEqual(node.attrs["instagram_followers"], 120)
        self.assertFalse([k for k in node.attrs if "obfusc" in k])
        values = {n.value for n in g.nodes.values()}
        self.assertIn("ana@ana.test", values)
        self.assertIn("+51987654321", values)

    async def test_unknown_user_and_bad_session(self):
        g = Graph()
        await make_engine(g, {"instagram"}, Config(keys={"instagram_session": "abc123"}),
                          depth=0).run([(Kind.USERNAME, "nadie")])
        self.assertNotIn("instagram_id", g.nodes["username:nadie"].attrs)
        g2 = Graph()
        await make_engine(g2, {"instagram"}, Config(keys={"instagram_session": "mala"}),
                          depth=0).run([(Kind.USERNAME, "ana")])
        self.assertTrue(any("Sesión" in n["title"] for n in g2.notes))

    def test_module_needs_session(self):
        self.assertFalse(discover()["instagram"].available(Config()))


class PassiveSourceTests(unittest.IsolatedAsyncioTestCase):
    def test_pgp_parse(self):
        out = pgp_keys.parse_index("uid:Ana%20Prueba%20%3Cana%40demo.test%3E:1::\nuid:sin-correo:1::\n")
        self.assertEqual(out, [("Ana Prueba", "ana@demo.test")])

    async def test_pgp_domain_only_keeps_own_mail(self):
        g = Graph()
        await make_engine(g, {"pgp_keys"}, depth=1).run([(Kind.DOMAIN, "demo.test")])
        emails = {n.value for n in g.nodes.values() if n.kind is Kind.EMAIL}
        self.assertEqual(emails, {"ana@demo.test", "otra@demo.test"})

    async def test_robtex(self):
        g = Graph()
        await make_engine(g, {"robtex_domain"}, depth=1).run([(Kind.DOMAIN, "demo.test")])
        kinds = {(n.kind, n.value) for n in g.nodes.values()}
        self.assertIn((Kind.IP, "203.0.113.9"), kinds)
        self.assertIn((Kind.DOMAIN, "ns1.demo-dns.test"), kinds)

    async def test_wikipedia(self):
        g = Graph()
        await make_engine(g, {"wiki_user", "wiki_ip"}, depth=0).run(
            [(Kind.USERNAME, "Ana"), (Kind.IP, "93.184.216.34")])
        user = next(n for n in g.nodes.values() if n.kind is Kind.USERNAME)
        self.assertEqual(user.attrs["wikipedia_edits"], 42)
        self.assertTrue(any("ediciones anónimas" in n["title"] for n in g.notes))

    def test_dnsbl_ignores_service_errors(self):
        self.assertEqual(reputation_dnsbl.listed([{"type": 1, "data": "127.255.255.254"}]), [])
        self.assertEqual(reputation_dnsbl.listed([{"type": 1, "data": "127.0.0.2"}]), ["127.0.0.2"])

    async def test_dnsbl_ip(self):
        g = Graph()
        await make_engine(g, {"dnsbl_ip"}, depth=0).run([(Kind.IP, "93.184.216.34")])
        self.assertEqual(g.nodes["ip:93.184.216.34"].attrs["blocklists"], ["Spamhaus ZEN"])
        self.assertTrue(any(n["severity"] == "medium" for n in g.notes))
        g2 = Graph()
        await make_engine(g2, {"dnsbl_ip"}, depth=0).run([(Kind.IP, "10.0.0.1")])
        self.assertEqual(g2.notes, [])   # las IP privadas no se consultan


class ActiveModuleTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_modules_need_flag(self):
        g = Graph()
        eng = make_engine(g, {"subdomain_brute", "takeover", "lookalikes", "cloud_buckets", "tls_cert"})
        await eng.run([(Kind.DOMAIN, "demo.test")])
        self.assertEqual(len(eng.stats.skipped), 5)

    async def test_brute_finds_known_hosts(self):
        g = Graph()
        await make_engine(g, {"subdomain_brute"}, depth=1, active=True).run([(Kind.DOMAIN, "demo.test")])
        names = {n.value for n in g.nodes.values() if n.kind is Kind.DOMAIN}
        self.assertTrue({"www.demo.test", "api.demo.test", "mail.demo.test"} <= names)

    async def test_takeover_detects_unclaimed_service(self):
        g = Graph()
        await make_engine(g, {"takeover"}, depth=0, active=True).run([(Kind.DOMAIN, "mail.demo.test")])
        self.assertTrue(any("sin reclamar" in n["title"] and n["severity"] == "high" for n in g.notes))

    def test_takeover_service_match(self):
        self.assertEqual(domain_takeover.match_service("demo.github.io."), "github.io")
        self.assertIsNone(domain_takeover.match_service("github.io.evil.test"))
        self.assertIsNone(domain_takeover.match_service("otro.test"))

    def test_lookalike_permutations(self):
        perms = domain_lookalikes.permutations("ejemplo.com")
        self.assertIn("ejmplo.com", perms)        # omisión
        self.assertIn("ejemplo.net", perms)       # otro TLD
        self.assertIn("ejempl0.com", perms)       # homoglifo
        self.assertNotIn("ejemplo.com", perms)
        self.assertLessEqual(len(perms), domain_lookalikes.MAX_CANDIDATES)

    def test_bucket_candidates(self):
        names = cloud_buckets.candidates("acme.com.pe")
        self.assertIn("acme-backup", names)
        self.assertIn("acme.com.pe", names)


class DocumentMetadataTests(unittest.TestCase):
    def _docx(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("docProps/core.xml", "<cp:coreProperties><dc:creator>jperez</dc:creator>"
                       "<cp:lastModifiedBy>Maria Lopez</cp:lastModifiedBy></cp:coreProperties>")
            z.writestr("docProps/app.xml", "<Properties><Application>Microsoft Office Word</Application>"
                       "<Company>Demo SA</Company></Properties>")
        return buf.getvalue()

    def test_office(self):
        meta = doc_metadata.read_document("https://demo.test/informe.docx", self._docx())
        self.assertEqual((meta["author"], meta["modified_by"], meta["company"]),
                         ("jperez", "Maria Lopez", "Demo SA"))

    def test_pdf(self):
        meta = doc_metadata.read_document("x.pdf", b"%PDF-1.4 ... /Author (Carlos Ruiz) /Creator (Word) ...")
        self.assertEqual((meta["author"], meta["software"]), ("Carlos Ruiz", "Word"))

    def test_corrupt_file_is_ignored(self):
        self.assertEqual(doc_metadata.read_document("x.docx", b"no es un zip"), {})


if __name__ == "__main__":
    unittest.main()
