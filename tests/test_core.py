import importlib.util
import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from nexum_osint.core.cache import Cache
from nexum_osint.core.config import Config
from nexum_osint.core.engine import Engine
from nexum_osint.core.entities import Graph, Kind, guess_kind, normalize
from nexum_osint.core.http import Http
from nexum_osint.core.module import discover
from nexum_osint.core.ratelimit import RateLimiter
from nexum_osint.reporting import exporters
from tests.fakes import fake_fetch


def make_engine(graph, depth=2, modules=None, allow_active=False):
    cfg = Config()
    http = Http(cfg, Cache(None, enabled=False), RateLimiter(default_rate=500), fetch=fake_fetch)
    reg = discover()
    if modules:
        reg = {k: v for k, v in reg.items() if k in modules}
    eng = Engine(http, graph, cfg, reg, depth=depth, allow_active=allow_active)
    # sin esperas en pruebas
    for host in list(http.limiter._buckets):
        http.limiter.configure(host, 1000, 50)
    return eng


class EntityTests(unittest.TestCase):
    def test_guess_kind(self):
        self.assertIs(guess_kind("8.8.8.8"), Kind.IP)
        self.assertIs(guess_kind("2606:4700::1111"), Kind.IP)
        self.assertIs(guess_kind("a.b@mail.com"), Kind.EMAIL)
        self.assertIs(guess_kind("Sub.Example.COM"), Kind.DOMAIN)
        self.assertIs(guess_kind("jair.d3v"), Kind.USERNAME)  # "d3v" no es un TLD válido
        self.assertIs(guess_kind("jdoe"), Kind.USERNAME)

    def test_registrable(self):
        from nexum_osint.core.entities import registrable
        self.assertEqual(registrable("www.sub.example.com"), "example.com")
        self.assertEqual(registrable("mail.empresa.com.pe"), "empresa.com.pe")
        self.assertEqual(registrable("portal.sunat.gob.pe"), "sunat.gob.pe")
        self.assertEqual(registrable("bbc.co.uk"), "bbc.co.uk")

    def test_normalize_and_merge(self):
        g = Graph()
        a, created = g.add(Kind.DOMAIN, "WWW.Demo.test.", "a")
        b, created2 = g.add(Kind.DOMAIN, "www.demo.test", "b", registrar="X")
        self.assertTrue(created and not created2)
        self.assertIs(a, b)
        self.assertEqual(a.sources, {"a", "b"})
        self.assertEqual(a.attrs["registrar"], "X")
        with self.assertRaises(ValueError):
            normalize(Kind.IP, "999.1.1.1")

    def test_correlation_shared_ip(self):
        g = Graph()
        ip, _ = g.add(Kind.IP, "203.0.113.10", "dns")
        for d in ("a.test", "b.test"):
            n, _ = g.add(Kind.DOMAIN, d, "dns")
            g.link(n, ip, "resolves_to", "dns")
        kinds = [c["type"] for c in g.correlations()]
        self.assertIn("shared_infrastructure", kinds)


class InfraTests(unittest.IsolatedAsyncioTestCase):
    async def test_cache_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Cache(Path(tmp) / "c.sqlite")
            k = Cache.make_key("GET", "https://x", {"a": 1})
            self.assertIsNone(c.get(k))
            c.set(k, {"v": 1}, ttl=0.2)
            self.assertEqual(c.get(k), {"v": 1})
            time.sleep(0.3)
            self.assertIsNone(c.get(k))
            c.close()

    async def test_cache_avoids_second_fetch(self):
        calls = []

        async def counting(method, url, **kw):
            calls.append(url)
            return await fake_fetch(method, url, **kw)

        with tempfile.TemporaryDirectory() as tmp:
            cache = Cache(Path(tmp) / "c.sqlite")
            http = Http(Config(), cache, RateLimiter(500), fetch=counting)
            await http.get("https://rdap.org/domain/demo.test", ttl=60)
            r = await http.get("https://rdap.org/domain/demo.test", ttl=60)
            self.assertTrue(r.from_cache)
            self.assertEqual(len(calls), 1)
            cache.close()

    async def test_rate_limiter_spaces_requests(self):
        rl = RateLimiter()
        rl.configure("h", rate=20, burst=1)
        start = time.monotonic()
        for _ in range(4):
            await rl.wait("h")
        self.assertGreaterEqual(time.monotonic() - start, 0.13)

    async def test_retry_on_failure(self):
        attempts = {"n": 0}

        async def flaky(method, url, **kw):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise OSError("timeout")
            return await fake_fetch(method, url, **kw)

        http = Http(Config(), Cache(None, enabled=False), RateLimiter(500), fetch=flaky)
        r = await http.get("https://rdap.org/domain/demo.test", ttl=0)
        self.assertTrue(r.ok)
        self.assertEqual(attempts["n"], 3)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_domain_pivot_and_findings(self):
        g = Graph()
        eng = make_engine(g, depth=2)
        await eng.run([(Kind.DOMAIN, "demo.test")])

        self.assertIn("domain:api.demo.test", g.nodes)
        self.assertIn("domain:mail.demo.test", g.nodes)
        self.assertIn("ip:203.0.113.10", g.nodes)
        self.assertIn("asn:AS64500", g.nodes)
        self.assertEqual(g.nodes["ip:203.0.113.10"].attrs["country"], "Peru")
        self.assertEqual(g.nodes["domain:demo.test"].attrs["registrar"], "Demo Registrar SA")
        titles = " | ".join(n["title"] for n in g.notes)
        self.assertIn("CVE", titles)
        self.assertIn("Servicios sensibles", titles)
        self.assertIn("SPF permisivo", titles)
        self.assertEqual(titles.count("Dominio próximo a expirar"), 1)  # solo el dominio registrable
        self.assertTrue(any(c["type"] == "shared_infrastructure" for c in g.correlations()))
        self.assertEqual(eng.stats.errors, [])

    async def test_depth_zero_does_not_pivot(self):
        g = Graph()
        eng = make_engine(g, depth=0)
        await eng.run([(Kind.DOMAIN, "demo.test")])
        # La IP se descubre (profundidad 1) pero no se enriquece con más consultas.
        self.assertIn("ip:203.0.113.10", g.nodes)
        self.assertEqual(g.nodes["ip:203.0.113.10"].attrs, {})
        self.assertNotIn("asn:AS64500", g.nodes)

    async def test_username_filters_false_positives(self):
        g = Graph()
        eng = make_engine(g, depth=0, modules={"username_sites"})
        await eng.run([(Kind.USERNAME, "jdoe")])
        profiles = {n.attrs["site"] for n in g.nodes.values() if n.kind is Kind.PROFILE}
        self.assertIn("GitHub", profiles)
        self.assertIn("GitLab", profiles)
        self.assertIn("Hacker News", profiles)
        self.assertNotIn("Dev.to", profiles)      # SPA que devuelve 200 a todo
        self.assertNotIn("Medium", profiles)
        self.assertTrue(any("falsos positivos" in n["title"] for n in g.notes))

    async def test_email_graceful_degradation(self):
        g = Graph()
        eng = make_engine(g, depth=0)
        await eng.run([(Kind.EMAIL, "jdoe@demo.test")])
        self.assertIn("domain:demo.test", g.nodes)
        self.assertIn("username:jdoe", g.nodes)
        self.assertTrue(any("EmailRep" in n["title"] for n in g.notes))
        self.assertEqual(eng.stats.errors, [])

    async def test_module_error_is_isolated(self):
        async def broken(method, url, **kw):
            if "crt.sh" in url:
                raise RuntimeError("boom")
            return await fake_fetch(method, url, **kw)

        g = Graph()
        eng = make_engine(g, depth=0)
        eng.http._fetch = broken
        await eng.run([(Kind.DOMAIN, "demo.test")])
        self.assertTrue(any(e["module"] == "crtsh" for e in eng.stats.errors))
        self.assertIn("ip:203.0.113.10", g.nodes)   # el resto siguió funcionando


class ReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_exports(self):
        g = Graph()
        eng = make_engine(g, depth=2)
        await eng.run([(Kind.DOMAIN, "demo.test")])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            html = exporters.to_html(g, eng.stats, ["demo.test"], 2, out / "r.html").read_text(encoding="utf-8")
            self.assertIn("NEXUM OSINT", html)
            self.assertIn("Jair Muñoz Candela", html)
            self.assertIn("github.com/jaircandela23-glitch", html)
            self.assertIn("CVE-2019-0708", html)
            self.assertNotIn("</script><script>alert", html)
            js = exporters.to_json(g, eng.stats, ["demo.test"], 2, out / "r.json")
            self.assertGreater(js.stat().st_size, 500)
            files = exporters.to_csv(g, out, "r")
            self.assertEqual(len(files), 2)
            if importlib.util.find_spec("reportlab"):
                pdf = exporters.to_pdf(g, eng.stats, ["demo.test"], 2, out / "r.pdf")
                self.assertTrue(pdf.read_bytes().startswith(b"%PDF"))

    async def test_html_escapes_hostile_values(self):
        g = Graph()
        g.add(Kind.USERNAME, "<script>alert(1)</script>", "seed")
        eng = make_engine(g, depth=0)
        with tempfile.TemporaryDirectory() as tmp:
            html = exporters.to_html(g, eng.stats, ["x"], 0, Path(tmp) / "r.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()


class PhoneTests(unittest.IsolatedAsyncioTestCase):
    async def test_peru_mobile(self):
        g = Graph()
        eng = make_engine(g, depth=0, modules={"phone"})
        await eng.run([(Kind.PHONE, "+51987654321")])
        n = g.nodes["phone:+51987654321"]
        self.assertEqual(n.attrs["country"], "Perú")
        self.assertEqual(n.attrs["line_type"], "móvil")
        self.assertEqual(n.attrs["operator_block_original"], "Claro")
        self.assertIn("no están ligados a una región", n.attrs["location_precision"])

    async def test_peru_fixed_line(self):
        g = Graph()
        eng = make_engine(g, depth=0, modules={"phone"})
        await eng.run([(Kind.PHONE, "+5144123456")])
        n = g.nodes["phone:+5144123456"]
        self.assertEqual(n.attrs["line_type"], "fija")
        self.assertEqual(n.attrs["area"], "La Libertad (Trujillo)")
        self.assertTrue(any("Trujillo" in note["title"] for note in g.notes))

    async def test_foreign_country(self):
        g = Graph()
        eng = make_engine(g, depth=0, modules={"phone"})
        await eng.run([(Kind.PHONE, "+34911234567")])
        n = g.nodes["phone:+34911234567"]
        self.assertEqual(n.attrs["country"], "España")
        self.assertEqual(n.attrs["location_precision"].split(" ")[0], "país")

    async def test_unrecognized_code(self):
        g = Graph()
        eng = make_engine(g, depth=0, modules={"phone"})
        await eng.run([(Kind.PHONE, "+9999999999")])
        self.assertTrue(any("no reconocido" in n["title"] for n in g.notes))

    async def test_invalid_phone_rejected_at_cli_level(self):
        from nexum_osint.core.entities import normalize
        with self.assertRaises(ValueError):
            normalize(Kind.PHONE, "123")

    async def test_guess_kind_phone(self):
        self.assertIs(guess_kind("+51987654321"), Kind.PHONE)
        self.assertIs(guess_kind("987654321"), Kind.PHONE)
        self.assertIs(guess_kind("+1 202 555 0143"), Kind.PHONE)

    async def test_no_network_calls_without_key(self):
        calls = []

        async def spy(method, url, **kw):
            calls.append(url)
            raise AssertionError("no debería llamar a la red sin api key configurada")

        g = Graph()
        eng = make_engine(g, depth=0, modules={"phone"})
        eng.http._fetch = spy
        await eng.run([(Kind.PHONE, "+51987654321")])
        self.assertEqual(calls, [])
