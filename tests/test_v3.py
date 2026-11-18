import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from nexum_osint import sitesync
from nexum_osint.analysis import dossier
from nexum_osint.core.entities import Graph, Kind, crypto_kind, guess_kind, normalize
from nexum_osint.modules.image_exif import read_exif
from nexum_osint.modules.username_sites import classify
from nexum_osint.reporting import exporters
from tests.test_v2 import make_engine

WMN = {"sites": [
    {"name": "Foro", "uri_check": "https://foro.test/u/{account}", "e_code": 200, "e_string": "perfil-de",
     "m_code": 404, "m_string": "no existe", "cat": "social"},
    {"name": "Adulto", "uri_check": "https://x.test/{account}", "e_code": 200, "e_string": "a", "cat": "xx NSFW xx"},
    {"name": "Roto", "uri_check": "https://roto.test/{account}", "e_code": 200, "valid": False, "cat": "tech"}]}
SHERLOCK = {"Uno": {"url": "https://uno.test/{}", "errorType": "status_code"},
            "Dos": {"url": "https://dos.test/{}", "errorType": "message", "errorMsg": "not found", "regexCheck": "^[a-z]{3,8}$"},
            "Tres": {"url": "https://tres.test/{}", "errorType": "response_url", "errorUrl": "https://tres.test/gone"},
            "$schema": "x"}


class SitesyncTests(unittest.TestCase):
    def test_conversion_filters_nsfw_and_invalid(self):
        out = sitesync.from_wmn(WMN)
        self.assertEqual([s["name"] for s in out], ["Foro"])
        self.assertIn("{u}", out[0]["url"])

    def test_sherlock_conversion(self):
        out = {s["name"]: s for s in sitesync.from_sherlock(SHERLOCK)}
        self.assertEqual(set(out), {"Uno", "Dos", "Tres"})
        self.assertEqual(out["Dos"]["check"], "errmsg")

    def test_merge_dedupes_by_normalized_name(self):
        merged = sitesync.merge([{"name": "Dev.to"}], [{"name": "dev to"}, {"name": "Otro"}])
        self.assertEqual(len(merged), 2)

    def test_classify_wmn(self):
        site = sitesync.from_wmn(WMN)[0]
        self.assertTrue(classify(site, 200, "<h1>perfil-de ana</h1>"))
        self.assertFalse(classify(site, 404, "no existe"))
        self.assertIsNone(classify(site, 200, "pagina en blanco"))
        self.assertIsNone(classify(site, 503, ""))

    def test_classify_sherlock(self):
        s = {s["name"]: s for s in sitesync.from_sherlock(SHERLOCK)}
        self.assertFalse(classify(s["Dos"], 200, "User not found".replace("User n", "n") ))
        self.assertTrue(classify(s["Dos"], 200, "perfil real"))
        self.assertFalse(classify(s["Tres"], 200, "", "https://tres.test/gone"))
        self.assertTrue(classify(s["Tres"], 200, "", "https://tres.test/ana"))


class CryptoTests(unittest.IsolatedAsyncioTestCase):
    def test_validation(self):
        self.assertEqual(crypto_kind("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "bitcoin")
        self.assertEqual(crypto_kind("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "bitcoin")
        self.assertIsNone(crypto_kind("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"))
        self.assertEqual(crypto_kind("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"), "ethereum")
        self.assertIs(guess_kind("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), Kind.CRYPTO)
        with self.assertRaises(ValueError):
            normalize(Kind.CRYPTO, "no-es-una-direccion")

    async def test_bitcoin_balance(self):
        g = Graph()
        await make_engine(g, {"btc_address", "crypto_links"}, depth=0).run(
            [(Kind.CRYPTO, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")])
        node = next(n for n in g.nodes.values() if n.kind is Kind.CRYPTO)
        self.assertEqual(node.attrs["saldo_btc"], 4.0)
        self.assertEqual(node.attrs["ultima_actividad"], "2023-11-14")
        self.assertTrue(any(n.attrs.get("manual") for n in g.nodes.values()))


class OrgNetTests(unittest.IsolatedAsyncioTestCase):
    async def test_org(self):
        g = Graph()
        await make_engine(g, {"org_gleif", "org_links"}, depth=0).run([(Kind.ORG, "Demo SA")])
        self.assertTrue(any("gleif.org" in n.value or "search.gleif" in n.value for n in g.nodes.values()))
        self.assertGreaterEqual(len([n for n in g.nodes.values() if n.attrs.get("manual")]), 10)

    async def test_ip_and_asn(self):
        g = Graph()
        await make_engine(g, {"ip_abuse_contact", "reverse_ip", "ripestat_asn", "ipgeo"}, depth=2).run(
            [(Kind.IP, "203.0.113.10")])
        ip = g.nodes["ip:203.0.113.10"]
        self.assertEqual(ip.attrs["abuse_contact"], "abuse@demo-net.test")
        self.assertEqual(ip.attrs["dominios_en_misma_ip"], 2)
        self.assertEqual(g.nodes["asn:AS64500"].attrs["prefijos"], 1)


class WebTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_only_with_flag(self):
        g = Graph()
        eng = make_engine(g, {"web_fingerprint"})
        self.assertEqual(eng.modules, {})

    async def test_fingerprint(self):
        g = Graph()
        await make_engine(g, {"web_fingerprint"}, depth=0, active=True).run([(Kind.DOMAIN, "demo.test")])
        d = g.nodes["domain:demo.test"]
        self.assertEqual(d.attrs["title"], "Demo SA")
        self.assertEqual(d.attrs["generator"], "WordPress 6.5")
        self.assertEqual(d.attrs["analytics"], ["UA-1234567-1"])
        self.assertEqual(d.attrs["robots_disallow"], ["/admin/"])
        self.assertIn("email:ventas@demo.test", g.nodes)
        self.assertIn("phone:+5115550100", g.nodes)
        profiles = [n.value for n in g.nodes.values() if n.kind is Kind.PROFILE]
        self.assertEqual(profiles, ["https://www.facebook.com/demosa"])
        self.assertTrue(any("cabeceras" in n["title"] for n in g.notes))

    def test_shared_analytics_correlation(self):
        g = Graph()
        g.add(Kind.DOMAIN, "a.test", "web", analytics=["UA-9-1"])
        g.add(Kind.DOMAIN, "b.test", "web", analytics=["UA-9-1", "G-ABCDEFGH12"])
        self.assertTrue(any(c["type"] == "shared_analytics" for c in g.correlations()))


class ExifTests(unittest.IsolatedAsyncioTestCase):
    async def test_gps_extracted(self):
        g = Graph()
        await make_engine(g, {"image_exif"}, depth=0, active=True).run([(Kind.URL, "https://demo.test/foto.jpg")])
        node = g.nodes["url:https://demo.test/foto.jpg"]
        self.assertEqual(node.attrs["exif_marca"], "ACME")
        lat, lon = node.attrs["exif_coords"]
        self.assertAlmostEqual(lat, -12.05, places=3)
        self.assertAlmostEqual(lon, -77.025, places=3)
        self.assertTrue(any(n["severity"] == "high" for n in g.notes))


class DossierTests(unittest.TestCase):
    def sample(self):
        g = Graph()
        g.add(Kind.USERNAME, "jdoe", "seed")
        g.add(Kind.PROFILE, "https://github.com/jdoe", "github_user", site="GitHub", full_name="John Doe",
              location="Lima", created="2015-03-02T10:00:00Z")
        g.add(Kind.PROFILE, "https://dev.to/jdoe", "profile_apis", site="Dev.to", full_name="john doe",
              joined_at="2016-01-05T00:00:00Z")
        g.add(Kind.EMAIL, "john@corp.test", "github_user")
        g.add(Kind.NAME, "Otro Nombre", "name_variants", confidence="baja")
        return g

    def test_merges_and_scores(self):
        card = dossier.build(self.sample())
        names = {r["valor"].lower(): r for r in card["Nombres"]}
        self.assertEqual(names["john doe"]["confianza"], "alta")
        self.assertEqual(names["otro nombre"]["confianza"], "baja")
        self.assertEqual(len([r for r in card["Nombres"] if "doe" in r["valor"].lower()]), 1)

    def test_timeline_sorted(self):
        events = dossier.timeline(self.sample())
        self.assertEqual([e["fecha"] for e in events], ["2015-03-02", "2016-01-05"])

    def test_date_parsing(self):
        self.assertEqual(dossier.parse_date(1700000000).year, 2023)
        self.assertEqual(dossier.parse_date("20200505000000").month, 5)
        self.assertIsNone(dossier.parse_date("no es fecha"))


class ExportTests(unittest.IsolatedAsyncioTestCase):
    async def test_markdown_graphml_and_report_sections(self):
        g = Graph()
        eng = make_engine(g, {"github_user", "name_links"}, depth=1)
        await eng.run([(Kind.USERNAME, "jdoe")])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            md = exporters.to_markdown(g, eng.stats, ["jdoe"], 1, out / "r.md").read_text(encoding="utf-8")
            gml = exporters.to_graphml(g, out / "r.graphml").read_text(encoding="utf-8")
            html = exporters.to_html(g, eng.stats, ["jdoe"], 1, out / "r.html").read_text(encoding="utf-8")
            if importlib.util.find_spec("reportlab"):
                exporters.to_pdf(g, eng.stats, ["jdoe"], 1, out / "r.pdf")
        self.assertIn("## Expediente consolidado", md)
        self.assertIn("Fundador" if False else "NEXUM Intelligence Systems", md)
        self.assertIn("<graphml", gml)
        self.assertIn("Expediente consolidado", html)
        self.assertIn("Línea de tiempo", html)


if __name__ == "__main__":
    unittest.main()
