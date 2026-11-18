import asyncio
import random
import tempfile
import unittest
from pathlib import Path

from nexum_osint.core import tor
from nexum_osint.core.cache import Cache
from nexum_osint.core.config import Config
from nexum_osint.core.http import Http, Response
from nexum_osint.core.ratelimit import RateLimiter
from nexum_osint.core.tor import TorControl
from nexum_osint.core.useragents import LANGUAGES, USER_AGENTS, browser_headers


class FakeTorControl:
    """Servidor de control mínimo que habla el protocolo real de Tor (PROTOCOLINFO, AUTHENTICATE, SIGNAL)."""

    def __init__(self, methods="NULL", password=None, cookie=None):
        self.methods, self.password, self.cookie = methods, password, cookie
        self.received: list[str] = []
        self.server = None

    async def handle(self, reader, writer):
        authed = False
        while line := await reader.readline():
            cmd = line.decode().strip()
            self.received.append(cmd)
            if cmd.startswith("PROTOCOLINFO"):
                extra = f' COOKIEFILE="{self.cookie}"' if self.cookie else ""
                writer.write(f'250-PROTOCOLINFO 1\r\n250-AUTH METHODS={self.methods}{extra}\r\n250 OK\r\n'.encode())
            elif cmd.startswith("AUTHENTICATE"):
                given = cmd.partition(" ")[2]
                quoted = '"' + (self.password or "").replace("\\", "\\\\").replace('"', '\\"') + '"'
                ok = {"NULL": given == "", "HASHEDPASSWORD": given == quoted,
                      "COOKIE": given == "0a0b0c"}[self.methods]
                authed = ok
                writer.write(b"250 OK\r\n" if ok else b"515 Authentication failed\r\n")
            elif cmd == "SIGNAL NEWNYM":
                writer.write(b"250 OK\r\n" if authed else b"514 Authentication required\r\n")
            elif cmd == "QUIT":
                writer.write(b"250 closing connection\r\n")
                break
            await writer.drain()
        writer.close()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


class TorRotationTests(unittest.IsolatedAsyncioTestCase):
    async def test_newnym_without_authentication(self):
        async with FakeTorControl() as srv:
            self.assertTrue(await TorControl(port=srv.port).renew())
        self.assertIn("SIGNAL NEWNYM", srv.received)

    async def test_newnym_with_password(self):
        async with FakeTorControl("HASHEDPASSWORD", password='clave"x') as srv:
            self.assertTrue(await TorControl(port=srv.port, password='clave"x').renew())
            self.assertFalse(await TorControl(port=srv.port, password="mala").renew())

    async def test_newnym_with_cookie_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cookie = Path(tmp) / "control.authcookie"
            cookie.write_bytes(bytes([0x0A, 0x0B, 0x0C]))
            async with FakeTorControl("COOKIE", cookie=cookie) as srv:
                self.assertTrue(await TorControl(port=srv.port).renew())

    async def test_unreachable_control_port_is_not_fatal(self):
        self.assertFalse(await TorControl(port=1).renew())

    def test_setting_parser(self):
        self.assertEqual((TorControl.from_setting("9151").host, TorControl.from_setting("9151").port),
                         ("127.0.0.1", 9151))
        self.assertEqual(TorControl.from_setting("10.0.0.2:9051").host, "10.0.0.2")


class BlockedSiteTests(unittest.IsolatedAsyncioTestCase):
    def make_http(self, statuses, rotator):
        calls = iter(statuses)

        async def fetch(method, url, **kw):
            return Response(next(calls), "ok", {}, url)

        http = Http(Config(), Cache(None, enabled=False), RateLimiter(default_rate=500), fetch=fetch)
        http.rotator, http.blocks_before_rotate = rotator, 2
        return http

    async def test_rotates_circuit_after_repeated_blocks_and_retries(self):
        class Rotator:
            renewals = 0

            async def renew(self):
                Rotator.renewals += 1
                return True

        http = self.make_http([429, 429, 200], Rotator())
        resp = await http.get("https://sitio.pe/u", retries=3, ttl=0)
        self.assertEqual((resp.status, Rotator.renewals, http.rotations), (200, 1, 1))

    async def test_no_rotator_keeps_normal_behaviour(self):
        http = self.make_http([403], None)
        self.assertEqual((await http.get("https://sitio.pe/u", retries=0, ttl=0)).status, 403)


class HeaderRotationTests(unittest.IsolatedAsyncioTestCase):
    def test_headers_come_from_the_pool_and_vary(self):
        rng = random.Random(7)
        seen = [browser_headers(rng) for _ in range(30)]
        self.assertTrue(all(h["User-Agent"] in USER_AGENTS and h["Accept-Language"] in LANGUAGES for h in seen))
        self.assertGreater(len({h["User-Agent"] for h in seen}), 2)

    async def test_only_requests_that_ask_for_it_rotate(self):
        sent = []

        async def fetch(method, url, headers=None, **kw):
            sent.append(headers)
            return Response(200, "", {}, url)

        http = Http(Config(), Cache(None, enabled=False), RateLimiter(default_rate=500), fetch=fetch)
        await http.get("https://a.pe/", ttl=0)
        await http.get("https://a.pe/", ttl=0, rotate_ua=True)
        await http.get("https://a.pe/", ttl=0, rotate_ua=True, headers={"Accept-Language": "fr"})
        self.assertIsNone(sent[0])
        self.assertIn(sent[1]["User-Agent"], USER_AGENTS)
        self.assertEqual(sent[2]["Accept-Language"], "fr")


class DorkTests(unittest.IsolatedAsyncioTestCase):
    def engine(self, mods):
        from nexum_osint.core.entities import Graph
        from tests.test_v2 import make_engine
        graph = Graph()
        eng = make_engine(graph, mods, depth=0)
        for module in eng.modules.values():
            if hasattr(module, "pause"):
                module.pause = (0, 0)
        return graph, eng

    async def test_links_for_each_kind(self):
        from nexum_osint.core.entities import Kind
        graph, eng = self.engine({"dorks"})
        await eng.run([(Kind.DOMAIN, "demo.test"), (Kind.EMAIL, "ana@demo.test"), (Kind.USERNAME, "ana.t")])
        urls = [n.value for n in graph.nodes.values() if n.kind is Kind.URL]
        self.assertGreaterEqual(len(urls), 8 + 6 + 5)
        self.assertTrue(any("filetype%3Apdf" in u and "site%3Ademo.test" in u for u in urls))
        self.assertTrue(any("%22ana%40demo.test%22" in u for u in urls))
        self.assertTrue(all(n.attrs.get("manual") for n in graph.nodes.values() if n.kind is Kind.URL))

    async def test_live_results_are_parsed_and_filtered(self):
        from nexum_osint.core.entities import Kind
        graph, eng = self.engine({"dork_results"})
        await eng.run([(Kind.DOMAIN, "demo.test")])
        urls = sorted(n.value for n in graph.nodes.values() if n.kind is Kind.URL)
        self.assertEqual(urls, ["https://docs.demo.test/plan.pdf", "https://otro.test/p"])
        titles = {n.attrs["label"] for n in graph.nodes.values() if n.kind is Kind.URL}
        self.assertIn("Plan 2024", titles)

    async def test_block_page_is_reported_not_crashed(self):
        from nexum_osint.core.entities import Kind
        graph, eng = self.engine({"dork_results"})
        await eng.run([(Kind.USERNAME, "blocked")])
        self.assertTrue(any("no devolvió resultados" in n["title"] for n in graph.notes))

    def test_parser_unwraps_redirect_links(self):
        from nexum_osint.modules.search_dorks import parse_results
        page = '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fa.test%2F%3Fq%3D1">A</a>'
        self.assertEqual(parse_results(page), [("A", "https://a.test/?q=1")])


class AliasConfidenceTests(unittest.TestCase):
    def test_content_checks_confirm_and_status_only_is_probable(self):
        from nexum_osint.modules.username_sites import confidence
        self.assertEqual(confidence({"check": "errmsg"}, False), "confirmado")
        self.assertEqual(confidence({"check": "status"}, True), "confirmado")
        self.assertEqual(confidence({"check": "status"}, False), "probable")
        self.assertEqual(confidence({}, False), "probable")


class CaseBookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        from nexum_osint import cases
        self.cases = cases
        self.book = cases.CaseBook(Path(self.tmp.name) / "c.sqlite")

    def tearDown(self):
        self.book.close()
        self.tmp.cleanup()

    def graph(self, *values, high=()):
        from nexum_osint.core.entities import Graph, Kind
        g = Graph()
        for v in values:
            node, _ = g.add(Kind.DOMAIN, v, source="dns", depth=0)
        for title in high:
            g.note("xposedornot", title, "", "high", node)
        return g

    def test_runs_are_stored_and_listed(self):
        self.book.add_run("Caso Lima", ["demo.pe"], 1, self.graph("a.pe", "b.pe", high=["Filtración"]), 40)
        self.book.add_run("caso lima", ["demo.pe"], 1, self.graph("a.pe"), 20)
        self.assertEqual(len(self.book.cases()), 1)          # el nombre no distingue mayúsculas
        runs = self.book.runs("Caso Lima")
        self.assertEqual([(r["entidades"], r["hallazgos_altos"], r["exposicion"]) for r in runs],
                         [(2, 1, 40), (1, 0, 20)])

    def test_compare_last_two_runs(self):
        self.book.add_run("c", ["x"], 1, self.graph("a.pe", "b.pe", high=["Filtración"]))
        self.assertIsNone(self.book.compare("c"))
        self.book.add_run("c", ["x"], 1, self.graph("a.pe", "nuevo.pe", high=["Otro hallazgo"]))
        diff = self.book.compare("c")
        self.assertEqual(diff["entidades_nuevas"], ["domain:nuevo.pe"])
        self.assertEqual(diff["entidades_ausentes"], ["domain:b.pe"])
        self.assertEqual(diff["hallazgos_nuevos"], ["high: Otro hallazgo"])
        self.assertEqual(diff["hallazgos_resueltos"], ["high: Filtración"])

    def test_export_and_delete(self):
        import json
        self.book.add_run("c", ["x"], 1, self.graph("a.pe", high=["Filtración"]))
        out = self.book.export("c", Path(self.tmp.name) / "c.json")
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["investigaciones"][0]["datos"][0]["valor"], "a.pe")
        self.assertTrue(self.book.delete("c"))
        self.assertEqual(self.book.runs("c"), [])
        self.assertFalse(self.book.delete("c"))
        self.assertEqual(self.book.db.execute("SELECT COUNT(*) FROM entities").fetchone()[0], 0)

    def test_unsafe_or_empty_names(self):
        self.assertEqual(self.cases.clean_name("  ../Caso/<1>  "), "..Caso1")
        with self.assertRaises(ValueError):
            self.book.add_run("///", ["x"], 1, self.graph("a.pe"))

    def test_cli_lists_compares_and_exports(self):
        from unittest import mock
        from nexum_osint import cli
        self.book.add_run("c", ["x"], 1, self.graph("a.pe"))
        self.book.add_run("c", ["x"], 1, self.graph("a.pe", "b.pe"))
        out = Path(self.tmp.name) / "o.json"
        with mock.patch.object(self.cases, "default_path", return_value=self.book.path):
            ui = cli.UI(quiet=True)
            parse = cli.build_parser().parse_args
            self.assertEqual(cli._cases_cli(ui, parse(["casos"])), 0)
            self.assertEqual(cli._cases_cli(ui, parse(["casos", "c", "--comparar", "--exportar", str(out)])), 0)
            self.assertTrue(out.exists())
            self.assertEqual(cli._cases_cli(ui, parse(["casos", "no-existe"])), 2)
            self.assertEqual(cli._cases_cli(ui, parse(["casos", "c", "--borrar"])), 0)


if __name__ == "__main__":
    unittest.main()
