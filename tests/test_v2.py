import asyncio
import importlib.util
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from nexum_osint import branding, cli
from nexum_osint.core.cache import Cache
from nexum_osint.core.config import Config
from nexum_osint.core.engine import Engine
from nexum_osint.core.entities import Graph, Kind, guess_kind, normalize
from nexum_osint.core.http import Http
from nexum_osint.core.module import discover
from nexum_osint.core.ratelimit import RateLimiter
from nexum_osint.darkweb import guard
from nexum_osint.darkweb.sources import load_sources, parse_ahmia
from nexum_osint.modules import id_intel, name_intel
from nexum_osint.reporting import exporters
from tests.fakes import fake_fetch

HAS_REPORTLAB = importlib.util.find_spec("reportlab") is not None


def make_http(cfg=None):
    http = Http(cfg or Config(), Cache(None, enabled=False), RateLimiter(default_rate=500), fetch=fake_fetch)
    return http


def make_engine(graph, modules, depth=1, cfg=None, options=None, tor=False, active=False):
    cfg = cfg or Config()
    http = make_http(cfg)
    reg = {k: v for k, v in discover().items() if k in modules}
    eng = Engine(http, graph, cfg, reg, depth=depth, allow_active=active, options=options or {},
                 tor_http=make_http(cfg) if tor else None)
    for host in list(http.limiter._buckets):
        http.limiter.configure(host, 1000, 50)
    return eng


class EntityV2Tests(unittest.TestCase):
    def test_name_detection(self):
        self.assertIs(guess_kind("Jair Muñoz Candela"), Kind.NAME)
        self.assertIs(guess_kind("María de la Cruz"), Kind.NAME)
        self.assertIs(guess_kind("jdoe"), Kind.USERNAME)
        self.assertIs(guess_kind("+51987654321"), Kind.PHONE)

    def test_doc_normalization(self):
        self.assertEqual(normalize(Kind.DOC, "20-131312955"), "20131312955")
        with self.assertRaises(ValueError):
            normalize(Kind.DOC, "12")


class IdTests(unittest.TestCase):
    def test_ruc_checksum(self):
        self.assertTrue(id_intel.ruc_valid("20131312955"))
        self.assertFalse(id_intel.ruc_valid("20131312956"))

    def test_nit_checksum(self):
        self.assertTrue(id_intel.nit_valid("8999990681"))
        self.assertFalse(id_intel.nit_valid("8999990682"))

    def test_classify(self):
        self.assertEqual(id_intel.classify("20131312955")[0][0], "RUC (Perú)")
        self.assertEqual(id_intel.classify("12345678")[0][0], "DNI (Perú)")
        self.assertEqual(id_intel.classify("???"), [])


class IdModuleTests(unittest.IsolatedAsyncioTestCase):
    async def test_doc_scan_and_no_titular_lookup(self):
        g = Graph()
        await make_engine(g, {"id_validate", "id_links"}).run([(Kind.DOC, "12345678")])
        titles = " ".join(n["title"] for n in g.notes)
        self.assertIn("no es pública", titles)
        self.assertTrue(all(n.attrs.get("manual") for n in g.nodes.values() if n.kind is Kind.URL))

    async def test_invalid_ruc_flagged(self):
        g = Graph()
        await make_engine(g, {"id_validate"}).run([(Kind.DOC, "20131312956")])
        self.assertTrue(any("incorrecto" in n["title"] for n in g.notes))


class NameTests(unittest.IsolatedAsyncioTestCase):
    def test_variants(self):
        v = name_intel.username_variants("Jair Muñoz Candela")
        self.assertIn("jair.candela", v)
        self.assertIn("jcandela", v)
        self.assertEqual(name_intel.username_variants("Solo"), [])

    async def test_name_links_and_open_sources(self):
        g = Graph()
        await make_engine(g, {"name_links", "name_wikidata", "name_orcid", "name_github"}).run(
            [(Kind.NAME, "Jair Munoz")])
        manual = [n for n in g.nodes.values() if n.attrs.get("manual")]
        self.assertGreaterEqual(len(manual), 15)
        self.assertTrue(any("wikidata.org/wiki/Q42" in n.value for n in g.nodes.values()))
        self.assertTrue(any(n.kind is Kind.PROFILE and "orcid" in n.value for n in g.nodes.values()))

    async def test_permute_is_opt_in(self):
        g = Graph()
        await make_engine(g, {"name_variants"}).run([(Kind.NAME, "Jair Munoz Candela")])
        self.assertEqual([n for n in g.nodes.values() if n.kind is Kind.USERNAME], [])
        g2 = Graph()
        await make_engine(g2, {"name_variants"}, options={"permute": True}).run([(Kind.NAME, "Jair Munoz Candela")])
        self.assertTrue([n for n in g2.nodes.values() if n.kind is Kind.USERNAME])


class ProfileTests(unittest.IsolatedAsyncioTestCase):
    async def test_github_extracts_real_data(self):
        g = Graph()
        await make_engine(g, {"github_user"}, depth=0).run([(Kind.USERNAME, "jdoe")])
        kinds = {n.kind for n in g.nodes.values()}
        self.assertIn(Kind.EMAIL, kinds)
        self.assertIn(Kind.NAME, kinds)
        emails = [n.value for n in g.nodes.values() if n.kind is Kind.EMAIL]
        self.assertEqual(emails, ["john.doe@corp.test"])  # el correo noreply se descarta
        self.assertTrue(any("commits públicos" in n["title"] for n in g.notes))

    async def test_profile_apis_isolated_failures(self):
        g = Graph()
        await make_engine(g, {"profile_apis"}, depth=0).run([(Kind.USERNAME, "jdoe")])
        sites = {n.attrs.get("site") for n in g.nodes.values() if n.kind is Kind.PROFILE}
        self.assertIn("Hacker News", sites)


class EmailTests(unittest.IsolatedAsyncioTestCase):
    async def test_breaches_flagged_high(self):
        g = Graph()
        await make_engine(g, {"xposedornot", "leakcheck"}, depth=0).run([(Kind.EMAIL, "leaked@demo.test")])
        highs = [n for n in g.notes if n["severity"] == "high"]
        self.assertEqual(len(highs), 2)
        node = g.nodes["email:leaked@demo.test"]
        self.assertIn("Adobe", node.attrs["breaches"])

    async def test_clean_email_has_no_findings(self):
        g = Graph()
        await make_engine(g, {"xposedornot", "leakcheck"}, depth=0).run([(Kind.EMAIL, "clean@demo.test")])
        self.assertEqual([n for n in g.notes if n["severity"] == "high"], [])

    async def test_mx_check(self):
        g = Graph()
        await make_engine(g, {"email_checks"}, depth=0).run([(Kind.EMAIL, "a@demo.test")])
        self.assertTrue(g.nodes["email:a@demo.test"].attrs["mx_records"])


class PhoneV2Tests(unittest.IsolatedAsyncioTestCase):
    async def test_links_without_network(self):
        calls = []

        async def spy(method, url, params=None, headers=None):
            calls.append(url)
            return await fake_fetch(method, url, params, headers)
        cfg = Config()
        http = Http(cfg, Cache(None, enabled=False), RateLimiter(default_rate=500), fetch=spy)
        reg = {k: v for k, v in discover().items() if k in ("phone_links", "veriphone", "ipqs_phone")}
        g = Graph()
        await Engine(http, g, cfg, reg, depth=0).run([(Kind.PHONE, "+51987654321")])
        self.assertEqual(calls, [])  # sin keys no hay consultas
        self.assertGreaterEqual(len([n for n in g.nodes.values() if n.attrs.get("manual")]), 10)

    async def test_keyed_modules(self):
        cfg = Config(keys={"ipqs": "k", "veriphone": "k"})
        g = Graph()
        await make_engine(g, {"ipqs_phone", "veriphone"}, depth=0, cfg=cfg).run([(Kind.PHONE, "+51987654321")])
        node = g.nodes["phone:+51987654321"]
        self.assertEqual(node.attrs["veriphone_carrier"], "Claro")
        self.assertTrue(node.attrs["ipqs_leaked"])


class DomainV2Tests(unittest.IsolatedAsyncioTestCase):
    async def test_extra_sources_add_subdomains(self):
        g = Graph()
        await make_engine(g, {"otx_domain", "urlscan", "hackertarget"}, depth=0).run([(Kind.DOMAIN, "demo.test")])
        subs = {n.value for n in g.nodes.values() if n.kind is Kind.DOMAIN}
        self.assertTrue({"vpn.demo.test", "shop.demo.test", "dev.demo.test"} <= subs)
        self.assertNotIn("other.example", subs)

    async def test_keyed_modules_skipped_without_key(self):
        g = Graph()
        eng = make_engine(g, {"vt_domain", "securitytrails", "hunter_domain"})
        self.assertEqual(eng.modules, {})
        self.assertEqual(len(eng.stats.skipped), 3)


class UrlTests(unittest.IsolatedAsyncioTestCase):
    async def test_image_url_gets_reverse_search(self):
        g = Graph()
        await make_engine(g, {"url_intel"}, depth=1).run([(Kind.URL, "https://demo.test/foto.jpg")])
        labels = [n.attrs.get("label", "") for n in g.nodes.values() if n.attrs.get("manual")]
        self.assertTrue(any("TinEye" in l for l in labels))
        self.assertIn("domain:demo.test", g.nodes)


class DarkwebTests(unittest.IsolatedAsyncioTestCase):
    async def test_module_skipped_without_tor(self):
        g = Graph()
        eng = make_engine(g, {"darkweb_index"}, options={"darkweb": True}, tor=False)
        self.assertEqual(eng.modules, {})
        self.assertTrue(any("dark web" in s for s in eng.stats.skipped))

    async def test_module_skipped_without_flag(self):
        g = Graph()
        eng = make_engine(g, {"darkweb_index"}, options={}, tor=True)
        self.assertEqual(eng.modules, {})

    async def test_search_through_tor(self):
        g = Graph()
        await make_engine(g, {"darkweb_index"}, depth=0, options={"darkweb": True}, tor=True).run(
            [(Kind.DOMAIN, "demo.test")])
        hits = [n for n in g.nodes.values() if n.attrs.get("darkweb")]
        self.assertEqual(len(hits), 1)  # misma dirección en ambos índices: una sola entidad
        self.assertTrue(any(n["severity"] == "high" and "dark web" in n["title"] for n in g.notes))

    def test_parse_ahmia_and_sources(self):
        body = ('<li class="result"><a href="/search/redirect?redirect_url=http://'
                'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/x">T&iacute;tulo</a><p>desc</p></li>')
        out = parse_ahmia(body)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["url"].endswith(".onion/x"))
        self.assertGreaterEqual(len(load_sources()), 1)


class FakeProbes(guard.Probes):
    def __init__(self, platform="linux", osr='ID=kali\nID_LIKE=debian', tor=True, ifaces=("lo", "eth0", "tun0")):
        self._p, self._o, self._t, self._i = platform, osr, tor, list(ifaces)

    def platform(self): return self._p
    def os_release(self): return self._o
    def tor_port_open(self, host, port): return self._t
    def interfaces(self): return self._i


class GuardTests(unittest.TestCase):
    URL = "socks5h://127.0.0.1:9050"

    def ok(self, **kw):
        probes = kw.pop("probes")
        return all(c.ok for c in guard.static_checks(self.URL, probes=probes, **kw))

    def test_all_good(self):
        self.assertTrue(self.ok(probes=FakeProbes()))

    def test_blocks_without_vpn_unless_acknowledged(self):
        p = FakeProbes(ifaces=("lo", "eth0"))
        self.assertFalse(self.ok(probes=p))
        self.assertTrue(self.ok(probes=p, no_vpn=True))

    def test_blocks_without_tor(self):
        self.assertFalse(self.ok(probes=FakeProbes(tor=False)))

    def test_blocks_non_kali_unless_forced(self):
        p = FakeProbes(osr="ID=ubuntu")
        self.assertFalse(self.ok(probes=p))
        self.assertTrue(self.ok(probes=p, force_env=True))

    def test_blocks_non_linux(self):
        self.assertFalse(self.ok(probes=FakeProbes(platform="win32"), force_env=True))

    def test_acknowledgement(self):
        self.assertTrue(guard.acknowledged(True))
        with mock.patch.object(guard.sys.stdin, "isatty", return_value=False):
            self.assertFalse(guard.acknowledged(False))  # sin TTY y sin bandera: no se acepta
        with mock.patch.object(guard.sys.stdin, "isatty", return_value=True):
            self.assertTrue(guard.acknowledged(False, ask=lambda _: "acepto"))
            self.assertFalse(guard.acknowledged(False, ask=lambda _: "no"))

    async def _tor(self):
        return await guard.tor_check(make_http())

    def test_tor_check(self):
        self.assertTrue(asyncio.run(self._tor()).ok)


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_gate_refuses_when_environment_fails(self):
        args = type("A", (), {"force_env": False, "sin_vpn": False, "acepto_riesgos": True})()
        ui = cli.UI(quiet=True)
        with mock.patch.object(guard.Probes, "tor_port_open", return_value=False), \
             mock.patch.object(guard.Probes, "platform", return_value="linux"):
            self.assertIsNone(await cli._darkweb_gate(args, Config(), ui))


class SitesTests(unittest.TestCase):
    def test_site_database_integrity(self):
        from nexum_osint.modules import username_sites
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(username_sites.sitesync, "path", return_value=Path(tmp) / "none.json"), \
                mock.patch.object(username_sites, "config_dir", return_value=Path(tmp)):
            sites = username_sites.load_sites()
        self.assertGreaterEqual(len(sites), 200)
        names = [s["name"] for s in sites]
        self.assertEqual(len(names), len(set(names)))
        for s in sites:
            self.assertIn("{u}", s["url"], s["name"])
            self.assertIn(s.get("check", "status"), ("status", "text_present", "text_absent", "json_nonempty"))
            if s.get("check") in ("text_present", "text_absent"):
                self.assertTrue(s.get("pattern"), s["name"])


class SetupAndMenuTests(unittest.TestCase):
    def test_setup_writes_private_config(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
            answers = iter(["ghp_test", "", "", "-"] + [""] * 20)
            with redirect_stdout(io.StringIO()):
                cli._setup(cli.UI(quiet=True), ask=lambda _: next(answers))
            path = Path(tmp) / "nexum-osint" / "config.toml"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(Config.load(path).keys.get("github"), "ghp_test")

    def test_menu_navigation_and_credits(self):
        out = io.StringIO()
        answers = iter(["xx", "", "25", "", "0"])
        with redirect_stdout(out):
            self.assertEqual(cli._menu(cli.UI(), ask=lambda _: next(answers)), 0)
        text = out.getvalue()
        self.assertIn("Opción no válida", text)
        self.assertIn(branding.AUTHOR, text)
        self.assertIn("Fundador de NEXUM Intelligence Systems", text)

    def test_api_registry_matches_modules(self):
        reg = discover()
        keys = {a["key"] for a in cli._apis()}
        for mod in reg.values():
            for k in (mod.needs_key, mod.optional_key):
                if k:
                    self.assertIn(k, keys, f"{mod.name} usa la key '{k}' que no está en apis.json")


class ReportV2Tests(unittest.IsolatedAsyncioTestCase):
    async def test_reports_have_sections_and_credits(self):
        g = Graph()
        eng = make_engine(g, {"name_links", "phone_links", "darkweb_index", "github_user"}, depth=1,
                          options={"darkweb": True}, tor=True)
        await eng.run([(Kind.NAME, "Jair Munoz Candela"), (Kind.PHONE, "+51987654321"), (Kind.USERNAME, "jdoe")])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            html = exporters.to_html(g, eng.stats, ["x"], 1, out / "r.html").read_text(encoding="utf-8")
            if HAS_REPORTLAB:
                exporters.to_pdf(g, eng.stats, ["x"], 1, out / "r.pdf")
                self.assertGreater((out / "r.pdf").stat().st_size, 2000)
        self.assertIn("Consultas manuales sugeridas", html)
        self.assertIn("Perfiles encontrados", html)
        self.assertIn("Jair Muñoz Candela", html)
        self.assertIn("NEXUM Intelligence Systems", html)

    def test_branding(self):
        self.assertEqual(branding.AUTHOR, "Jair Muñoz Candela")
        self.assertEqual(branding.COMPANY, "NEXUM Intelligence Systems")


if __name__ == "__main__":
    unittest.main()
