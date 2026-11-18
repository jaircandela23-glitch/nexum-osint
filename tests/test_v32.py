import io
import json
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from nexum_osint import cli, history, tools
from nexum_osint.analysis import dossier
from nexum_osint.core.cache import Cache
from nexum_osint.core.config import Config
from nexum_osint.core.engine import Engine
from nexum_osint.core.entities import Graph, Kind
from nexum_osint.core.http import Http, Response
from nexum_osint.core.module import discover
from nexum_osint.core.ratelimit import RateLimiter
from nexum_osint.modules.reputation_lists import parse_hosts, parse_ips
from tests.fakes import fake_fetch


def js(body, status=200):
    return Response(status, json.dumps(body), {}, "")


def txt(body, status=200, content=b""):
    return Response(status, body, {}, "", content=content or body.encode())


async def fetch(method, url, params=None, headers=None, data=None):
    params = params or {}
    if "breach-analytics" in url:
        if params["email"] == "clean@demo.test":
            return js({"ExposedBreaches": None})
        return js({"ExposedBreaches": {"breaches_details": [
            {"breach": "Adobe", "xposed_date": "2013", "xposed_records": 152000000,
             "xposed_data": "Email addresses;Password hints;Passwords"},
            {"breach": "Canva", "xposed_date": "2019", "xposed_records": 137000000,
             "xposed_data": "Email addresses;Names;Passwords"}]},
            "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 82}],
                              "passwords_strength": [{"PlainText": 1, "EasyToCrack": 1, "StrongHash": 0}]}})
    if "lists.blocklist.de" in url:
        return txt("# lista\n203.0.113.9\n198.51.100.2\n")
    if any(h in url for h in ("cinsscore", "rules.emergingthreats", "greensnow", "feodotracker")):
        return txt("192.0.2.1\n")
    if "openphish.com" in url:
        return txt("http://malo.demo.test/login\nhttps://otro.example/x\n")
    if "urlhaus" in url or "StevenBlack" in url:
        return txt("0.0.0.0 ads.example\n")
    if "rdap.org/ip" in url:
        return js({"name": "DEMO-NET", "country": "PE", "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
                   "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Demo Telecom SAC"],
                                                                                    ["kind", {}, "text", "org"]]]},
                                {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"],
                                                                              ["email", {}, "text", "abuse@demo-net.test"]]]}]})
    if "jldc.me/anubis" in url:
        return js(["vpn.demo.test", "dev.demo.test", "otro.example"])
    if "rapiddns.io" in url:
        return txt("<table><tr><td>mail.demo.test</td></tr><tr><td>vpn.demo.test</td></tr></table>")
    if "collinfo.json" in url:
        return js([{"id": "CC-MAIN-2026-01", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-01-index"}])
    if "commoncrawl.org/CC-MAIN" in url:
        return txt('{"url": "https://app.demo.test/informe.pdf"}\n{"url": "https://demo.test/index.html"}\n')
    if "demo.test/.git/HEAD" in url:
        return txt("ref: refs/heads/main\n")
    if "demo.test/.env" in url:
        return txt("<html>no encontrado</html>", 404)
    if url.startswith("https://demo.test/") and url.endswith(".php"):
        return txt("no existe", 404)
    if url.startswith("https://demo.test/"):
        return txt("no existe", 404)
    if "open.kickbox.com" in url:
        return js({"disposable": "mailinator.test" in url})
    if "api.domainsdb.info" in url:
        return js({"domains": [{"domain": "demo.net", "isDead": False}, {"domain": "demo.org", "isDead": True},
                               {"domain": "demo.test", "isDead": False}]})
    if "peeringdb.com" in url:
        return js({"data": [{"name": "Demo Networks", "info_type": "NSP", "website": "https://demo-net.test",
                             "policy_general": "Open"}]})
    return await fake_fetch(method, url, params, headers)


def engine(graph, modules, depth=0, active=False, cfg=None):
    cfg = cfg or Config()
    http = Http(cfg, Cache(None, enabled=False), RateLimiter(default_rate=1000), fetch=fetch)
    reg = {k: v for k, v in discover().items() if k in modules}
    eng = Engine(http, graph, cfg, reg, depth=depth, allow_active=active, options={})
    for host in list(http.limiter._buckets):
        http.limiter.configure(host, 1000, 50)
    return eng


class PhoneTests(unittest.IsolatedAsyncioTestCase):
    async def test_libphonenumber(self):
        g = Graph()
        await engine(g, {"phone_libphone"}).run([(Kind.PHONE, "+51987654321")])
        n = g.nodes["phone:+51987654321"]
        self.assertTrue(n.attrs["valido"])
        self.assertEqual(n.attrs["tipo_linea"], "móvil")
        self.assertEqual(n.attrs["zonas_horarias"], ["America/Lima"])
        self.assertIn("formato_internacional", n.attrs)

    async def test_invalid_number(self):
        g = Graph()
        await engine(g, {"phone_libphone"}).run([(Kind.PHONE, "+51555555555")])
        self.assertFalse(g.nodes["phone:+51555555555"].attrs["valido"])
        self.assertTrue(any("no es válido" in n["title"] for n in g.notes))


class BreachTests(unittest.IsolatedAsyncioTestCase):
    async def test_detail_risk_and_timeline(self):
        g = Graph()
        await engine(g, {"xposedornot"}).run([(Kind.EMAIL, "persona@demo.test")])
        n = g.nodes["email:persona@demo.test"]
        self.assertEqual(n.attrs["breaches"], ["Adobe", "Canva"])
        self.assertIn("Passwords", n.attrs["datos_expuestos"])
        self.assertEqual(n.attrs["riesgo_xposedornot"], "High (82/100)")
        self.assertEqual(len([x for x in g.notes if x["severity"] == "high"]), 2)
        years = [e["fecha"] for e in dossier.timeline(g)]
        self.assertEqual(years, ["2013", "2019"])

    async def test_clean_email(self):
        g = Graph()
        await engine(g, {"xposedornot"}).run([(Kind.EMAIL, "clean@demo.test")])
        self.assertEqual(g.notes, [])


class ReputationTests(unittest.IsolatedAsyncioTestCase):
    def test_parsers(self):
        self.assertEqual(parse_ips("# x\n1.2.3.4 ; comentario\nno-ip\n5.6.7.8\n"), {"1.2.3.4", "5.6.7.8"})
        self.assertEqual(parse_hosts("0.0.0.0 a.example\n127.0.0.1\tb.example\n# c"), {"a.example", "b.example"})
        self.assertEqual(parse_hosts("https://x.example/p?q=1\n"), {"x.example"})

    async def test_ip_listed(self):
        g = Graph()
        await engine(g, {"ip_blocklists"}).run([(Kind.IP, "203.0.113.9")])
        self.assertEqual(g.nodes["ip:203.0.113.9"].attrs["listas_negras"], ["blocklist.de"])
        self.assertTrue(any(n["severity"] == "high" for n in g.notes))

    async def test_domain_listed_in_phishing_feed(self):
        g = Graph()
        await engine(g, {"domain_blocklists"}).run([(Kind.DOMAIN, "malo.demo.test")])
        self.assertEqual(g.nodes["domain:malo.demo.test"].attrs["listas_dominio"], ["OpenPhish"])


class NetworkSourcesTests(unittest.IsolatedAsyncioTestCase):
    async def test_rdap(self):
        g = Graph()
        await engine(g, {"ip_rdap"}).run([(Kind.IP, "203.0.113.10")])
        self.assertEqual(g.nodes["ip:203.0.113.10"].attrs["pais_registro"], "PE")
        self.assertIn("org:Demo Telecom SAC", g.nodes)
        self.assertIn("email:abuse@demo-net.test", g.nodes)

    async def test_subdomain_sources(self):
        g = Graph()
        await engine(g, {"anubis", "rapiddns", "commoncrawl"}).run([(Kind.DOMAIN, "demo.test")])
        subs = {n.value for n in g.nodes.values() if n.kind is Kind.DOMAIN}
        self.assertTrue({"vpn.demo.test", "dev.demo.test", "mail.demo.test", "app.demo.test"} <= subs)
        self.assertNotIn("otro.example", subs)
        self.assertEqual(g.nodes["domain:demo.test"].attrs["archivos_publicos"], ["https://app.demo.test/informe.pdf"])

    async def test_domainsdb_and_peeringdb(self):
        g = Graph()
        await engine(g, {"domainsdb"}).run([(Kind.DOMAIN, "demo.test")])
        similar = {n.value for n in g.nodes.values() if n.kind is Kind.DOMAIN} - {"demo.test"}
        self.assertEqual(similar, {"demo.net"})
        g2 = Graph()
        await engine(g2, {"peeringdb"}).run([(Kind.ASN, "AS64500")])
        self.assertEqual(g2.nodes["asn:AS64500"].attrs["tipo_red"], "NSP")
        self.assertIn("org:Demo Networks", g2.nodes)

    async def test_disposable_domain(self):
        g = Graph()
        await engine(g, {"email_disposable"}).run([(Kind.EMAIL, "x@mailinator.test")])
        self.assertTrue(g.nodes["email:x@mailinator.test"].attrs["dominio_desechable"])


class ExposedFilesTests(unittest.IsolatedAsyncioTestCase):
    async def test_requires_active(self):
        self.assertEqual(engine(Graph(), {"exposed_files"}).modules, {})

    async def test_finds_git_repo_only(self):
        g = Graph()
        await engine(g, {"exposed_files"}, active=True).run([(Kind.DOMAIN, "demo.test")])
        self.assertEqual(g.nodes["domain:demo.test"].attrs["archivos_expuestos"], ["/.git/HEAD"])
        self.assertTrue(any("Git" in n["title"] and n["severity"] == "high" for n in g.notes))


class InstagramScopeTests(unittest.TestCase):
    def test_no_recovery_flow(self):
        src = Path(cli.__file__).parent.joinpath("modules", "social_instagram.py").read_text(encoding="utf-8")
        self.assertNotIn("users/lookup", src)
        self.assertNotIn("obfuscated", src)


# ---------------------------------------------------------------- directorio
def make_library_zip(path: Path):
    tool = ("# Demo Finder\n\n| **Demo Finder** | **Quick Overview** |\n| --- | --- |\n"
            "| URL | [https://demo.test/](https://demo.test/) |\n| What it does | Finds demo things. |\n"
            "| How to use it | Type a name. |\n| Cost | Free. |\n| Account required | Yes. |\n")
    cat = "# Phone Number OSINT\n\n| Tool | Link |\n| --- | --- |\n| Demo Finder | [Find out more](../osint-tools/demo-finder.md) |\n"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Lib/osint-tools/demo-finder.md", tool)
        z.writestr("Lib/tool-categories/phone-number-osint.md", cat)


class ToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name, "XDG_CACHE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_builtin_catalog(self):
        catalog = tools.load()
        self.assertGreaterEqual(len(catalog), 60)
        for t in catalog:
            self.assertTrue(t["url"].startswith("https://"), t["name"])
            self.assertTrue(t["what"] and t["category"] and t["cost"], t["name"])
        self.assertEqual(len({t["name"] for t in catalog}), len(catalog))

    def test_search(self):
        catalog = tools.load()
        self.assertTrue(any(t["name"] == "Sherlock" for t in tools.search(catalog, "alias sherlock")))
        self.assertEqual(tools.search(catalog, "zzzz-no-existe"), [])

    def test_import_zip_and_merge(self):
        z = Path(self.tmp.name) / "lib.zip"
        make_library_zip(z)
        self.assertEqual(tools.import_library(z), 1)
        merged = {t["name"]: t for t in tools.load()}
        item = merged["Demo Finder"]
        self.assertEqual(item["category"], "Teléfono")
        self.assertEqual(item["cost"], "Gratis")
        self.assertTrue(item["account"])
        self.assertEqual(item["origin"], "OSINT Tools Library")

    def test_import_rejects_wrong_folder(self):
        empty = Path(self.tmp.name) / "vacio"
        empty.mkdir()
        with self.assertRaises(ValueError):
            tools.import_library(empty)

    def test_import_folder(self):
        root = Path(self.tmp.name) / "lib"
        (root / "osint-tools").mkdir(parents=True)
        (root / "tool-categories").mkdir()
        z = Path(self.tmp.name) / "tmp.zip"
        make_library_zip(z)
        with zipfile.ZipFile(z) as zf:
            (root / "osint-tools" / "demo-finder.md").write_text(zf.read("Lib/osint-tools/demo-finder.md").decode())
        self.assertEqual(tools.import_library(root), 1)

    def test_menu_browse_and_search(self):
        answers = iter(["1", "1", "", "", "sherlock", "", ""])
        out = io.StringIO()
        with redirect_stdout(out):
            cli._tools_menu(cli.UI(), ask=lambda _: next(answers))
        text = out.getvalue()
        self.assertIn("Directorio de herramientas", text)
        self.assertIn("Sherlock", text)


class HistoryAndMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name, "XDG_CACHE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_history_roundtrip(self):
        out = Path(self.tmp.name) / "r"
        out.mkdir()
        f = out / "a.html"
        f.write_text("x")
        history.record(["demo.test"], out, [f], 2)
        history.record(["otro"], out, [f], 0)
        items = history.load()
        self.assertEqual([i["objetivos"] for i in items], [["otro"], ["demo.test"]])

    def test_history_menu_lists_reports(self):
        out = Path(self.tmp.name) / "r"
        out.mkdir()
        history.record(["demo.test"], out, [out / "a.html"], 3)
        buf = io.StringIO()
        answers = iter(["1", "n"])
        with redirect_stdout(buf):
            cli._history_menu(cli.UI(), lambda _: next(answers))
        self.assertIn("demo.test", buf.getvalue())

    def test_menu_has_every_action(self):
        actions = set(cli.ACTIONS.values())
        self.assertTrue({"quick", "tools", "history", "darkweb", "setup", "about", "exit"} <= actions)
        keys = list(cli.ACTIONS)
        self.assertEqual(len(keys), len(set(keys)))

    def test_quick_scan_detects_type(self):
        calls = []
        answers = iter(["1", "persona@demo.test", "", "2", "", "", "0"])
        with mock.patch.object(cli, "main", side_effect=lambda argv: calls.append(argv) or 0), redirect_stdout(io.StringIO()):
            cli._menu(cli.UI(), ask=lambda _: next(answers))
        self.assertEqual(calls[0][:4], ["scan", "persona@demo.test", "-t", "email"])
        self.assertIn("-d", calls[0])
        self.assertNotIn("--caso", calls[0])

    def test_menu_scan_can_be_saved_in_a_case(self):
        calls = []
        answers = iter(["5", "ana.t", "2", "Caso: Lima/1", "", "0"])
        with mock.patch.object(cli, "main", side_effect=lambda argv: calls.append(argv) or 0), redirect_stdout(io.StringIO()):
            cli._menu(cli.UI(), ask=lambda _: next(answers))
        self.assertEqual(calls[0][calls[0].index("--caso") + 1], "Caso Lima1")

    def test_modules_markdown(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli._list_modules(cli.UI(), markdown=True)
        text = buf.getvalue()
        self.assertIn("| `xposedornot` |", text)
        self.assertIn("## Entrada: ", text)

    def test_about_shows_author_and_licenses(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli._about(cli.UI())
        text = buf.getvalue()
        for needle in ("Jair Muñoz Candela", "NEXUM Intelligence Systems", "SpiderFoot", "GPL-3.0", "MIT"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
