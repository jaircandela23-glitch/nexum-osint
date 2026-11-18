import asyncio
import csv
import io
import json
import os
import tempfile
import unittest
import zipfile
from email.message import EmailMessage
from pathlib import Path
from unittest import mock

from nexum_osint import cli, extract
from nexum_osint.core.entities import Kind
from nexum_osint.core.http import Response

SAMPLE = """Contacto: Juan Pérez <juan.perez@empresa.pe>, tel +51 987 654 321 o 987654321, también +34 600 11 22 33.
Web https://www.empresa.pe/contacto y www.otraweb.com. IP 8.8.8.8, 192.168.1.5 y 999.1.1.1.
https://twitter.com/jaircandela https://x.com/share https://instagram.com/jair.m
BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (válida) 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb (checksum roto)
ETH 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe  RUC 20100070970 y 20123456789 (inválido)
md5 d41d8cd98f00b204e9800998ecf8427e  CVE-2021-44228  logo icon@2x.png"""


def make_docx(path: Path, body: str, creator: str = "Ana Torres") -> None:
    core = (f'<cp:coreProperties xmlns:cp="x" xmlns:dc="y" xmlns:dcterms="z"><dc:creator>{creator}</dc:creator>'
            '<cp:lastModifiedBy>Luis Ríos</cp:lastModifiedBy><dcterms:created>2024-03-01T10:00:00Z</dcterms:created>'
            '</cp:coreProperties>')
    doc = f'<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>'
    app = '<Properties><Application>Microsoft Office Word</Application><Company>Empresa SAC</Company></Properties>'
    rels = ('<Relationships><Relationship Id="1" Type="t" Target="https://enlace-oculto.test/x" '
            'TargetMode="External"/></Relationships>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        z.writestr("word/document.xml", doc)
        z.writestr("word/_rels/document.xml.rels", rels)


class TextExtractionTests(unittest.TestCase):
    def setUp(self):
        self.found = extract.from_text(SAMPLE)
        self.items = self.found.items

    def test_emails_and_phones_are_normalised(self):
        self.assertEqual(self.items["emails"], ["juan.perez@empresa.pe"])
        self.assertEqual(self.items["phones"], ["+34600112233", "+51987654321"])

    def test_profiles_skip_non_account_paths(self):
        self.assertEqual(self.items["profiles"], ["Instagram: jair.m", "X / Twitter: jaircandela"])

    def test_peruvian_mobile_at_the_end_of_a_sentence(self):
        found = extract.from_text("Llámame al 987 654 321. O al 912-345-678, gracias. Código 1987654321 y 9.876.543.210")
        self.assertEqual(found.items["phones"], ["+51912345678", "+51987654321"])

    def test_ips_are_validated(self):
        self.assertEqual(self.items["ips"], ["192.168.1.5", "8.8.8.8"])

    def test_crypto_requires_valid_checksum(self):
        coins = " ".join(self.items["crypto"])
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", coins)
        self.assertNotIn("DivfNb", coins)
        self.assertIn("ethereum: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", coins)

    def test_ruc_requires_check_digit(self):
        self.assertEqual(len(self.items["ruc"]), 1)
        self.assertTrue(self.items["ruc"][0].startswith("20100070970"))

    def test_ethereum_address_is_not_reported_as_hash(self):
        self.assertEqual(self.items["hashes"], ["MD5: d41d8cd98f00b204e9800998ecf8427e"])

    def test_domains_include_bare_and_exclude_images(self):
        self.assertIn("otraweb.com", self.items["domains"])
        self.assertIn("empresa.pe", self.items["domains"])
        self.assertFalse([d for d in self.items["domains"] if d.endswith(".png")])
        self.assertNotIn("icon@2x.png", self.items["emails"])

    def test_page_assets_are_not_listed_as_links(self):
        found = extract.from_text("https://avatars.githubusercontent.com/u/1?v=4 https://img.shields.io/badge/x "
                                  "https://sitio.pe/logo.png https://sitio.pe/contacto")
        self.assertEqual(found.items["urls"], ["https://sitio.pe/contacto"])
        self.assertEqual(found.items["domains"], ["sitio.pe"])

    def test_noise_that_looks_like_ips_hashes_and_domains(self):
        sha = "a" * 8 + "1" * 32
        found = extract.from_text(f"path c1.7.75.75 loopback 127.0.0.1 real 203.0.113.9 "
                                  f"https://git.test/commit/{sha} suelto {sha} url %2Fgithub.com")
        self.assertEqual(found.items["ips"], ["203.0.113.9"])
        self.assertEqual(found.items["hashes"], [f"SHA-1: {sha}"])
        self.assertNotIn("2fgithub.com", found.items.get("domains", []))

    def test_invalid_email_shapes_are_dropped(self):
        found = extract.from_text("tiktok-@nexum.sec  ok@empresa.pe  foto@2x.png  .raro@x.com")
        self.assertEqual(found.items["emails"], ["ok@empresa.pe"])

    def test_targets_skip_private_ips_and_big_platforms(self):
        targets = extract.to_targets(extract.from_text(SAMPLE + " https://github.com/x https://www.google.com/a"))
        values = [v for _, _, v in targets]
        self.assertIn("8.8.8.8", values)
        self.assertNotIn("192.168.1.5", values)
        self.assertNotIn("google.com", values)
        self.assertIn(Kind.USERNAME, {k for _, k, _ in targets})


class FileExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_docx_text_links_and_metadata(self):
        path = self.dir / "informe.docx"
        make_docx(path, "Escribir a contacto@empresa.pe")
        found = extract.from_file(path)
        self.assertIn("contacto@empresa.pe", found.items["emails"])
        self.assertIn("enlace-oculto.test", found.items["domains"])
        meta = found.metadata[str(path)]
        self.assertEqual(meta["autor"], "Ana Torres")
        self.assertEqual(meta["modificado_por"], "Luis Ríos")
        self.assertEqual(meta["empresa"], "Empresa SAC")

    def test_hostile_xml_is_ignored(self):
        path = self.dir / "malo.docx"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("docProps/core.xml", '<!DOCTYPE x [<!ENTITY a "b">]><cp:coreProperties/>')
            z.writestr("word/document.xml", '<!DOCTYPE x [<!ENTITY a "b">]><w:t>no@debe.pe</w:t>')
        self.assertEqual(extract.from_file(path).items, {})

    def test_pdf_metadata_and_links(self):
        path = self.dir / "doc.pdf"
        path.write_bytes(b"%PDF-1.4\n1 0 obj<</Author (Jair M)/Producer (LibreOffice)/Title (Plan)>>endobj\n"
                         b"2 0 obj<</S /URI /URI (https://enlace.test/pdf)>>endobj\n%%EOF")
        found = extract.from_file(path)
        self.assertEqual(found.metadata[str(path)]["autor"], "Jair M")
        self.assertIn("enlace.test", found.items["domains"])

    def test_eml_headers(self):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = "Ana <ana@origen.pe>", "yo@destino.pe", "Factura"
        msg["X-Originating-IP"] = "203.0.113.77"
        msg["Received"] = "from mail.origen.pe (mail.origen.pe [198.51.100.9]) by mx.destino.pe"
        msg.set_content("Mi teléfono es +51 999 888 777")
        path = self.dir / "caso.eml"
        path.write_bytes(bytes(msg))
        found = extract.from_file(path)
        self.assertIn("203.0.113.77", found.items["ips"])
        self.assertIn("198.51.100.9", found.items["ips"])
        self.assertIn("+51999888777", found.items["phones"])
        self.assertEqual(found.metadata[str(path)]["asunto"], "Factura")

    def test_html_meta_mailto_and_tel(self):
        path = self.dir / "pagina.html"
        path.write_text('<html><head><title>Estudio Gómez</title><meta name="author" content="M. Gómez">'
                        '<meta name="generator" content="WordPress 6.4"></head><body>'
                        '<a href="mailto:info@estudio.pe?subject=hola">escribir</a>'
                        '<a href="tel:+5112345678">llamar</a></body></html>', encoding="utf-8")
        found = extract.from_file(path)
        self.assertIn("info@estudio.pe", found.items["emails"])
        self.assertIn("+5112345678", found.items["phones"])
        meta = found.metadata[str(path)]
        self.assertEqual((meta["titulo"], meta["generador"]), ("Estudio Gómez", "WordPress 6.4"))

    def test_image_exif_gps(self):
        from PIL import Image
        exif = Image.Exif()
        exif[271], exif[272] = "Canon", "EOS 90D"
        exif[0x8825] = {1: "S", 2: (12.0, 3.0, 0.0), 3: "W", 4: (77.0, 2.0, 0.0)}
        path = self.dir / "foto.jpg"
        Image.new("RGB", (8, 8)).save(path, exif=exif)
        meta = extract.from_file(path).metadata[str(path)]
        self.assertEqual(meta["marca"], "Canon")
        self.assertAlmostEqual(meta["coords"][0], -12.05, places=2)
        self.assertIn("openstreetmap.org", meta["mapa"])

    def test_folder_merges_and_skips_hidden(self):
        (self.dir / "a.txt").write_text("uno@a.pe", encoding="utf-8")
        sub = self.dir / "sub"
        sub.mkdir()
        (sub / "b.txt").write_text("dos@b.pe uno@a.pe", encoding="utf-8")
        (self.dir / ".oculto.txt").write_text("secreto@x.pe", encoding="utf-8")
        found = extract.from_folder(self.dir)
        self.assertEqual(found.items["emails"], ["dos@b.pe", "uno@a.pe"])
        self.assertIn("2 archivos analizados", found.notes[-1])

    def test_export_json_and_csv(self):
        found = extract.from_text("a@b.pe 8.8.8.8", "demo")
        data = json.loads(extract.export(found, self.dir / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(data["datos"]["emails"], ["a@b.pe"])
        with extract.export(found, self.dir / "r.csv").open(encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(rows[0], ["categoria", "valor", "fuente"])
        self.assertIn(["emails", "a@b.pe", "demo"], rows)


class StubHttp:
    def __init__(self, pages):
        self.pages, self.requested = pages, []

    async def get(self, url, **kw):
        self.requested.append(url)
        body = self.pages.get(url)
        return Response(200 if body is not None else 404, body or "", {}, url)


class UrlExtractionTests(unittest.TestCase):
    PAGES = {
        "https://sitio.pe/": '<title>Inicio</title><a href="/contacto">c</a><a href="https://otro.pe/x">o</a>'
                               '<a href="/logo.png">l</a>',
        "https://sitio.pe/contacto": '<a href="mailto:hola@sitio.pe">m</a> <a href="https://t.me/sitio_bot">t</a>',
        "https://otro.pe/x": "no debe visitarse otro@malo.pe",
    }

    def test_crawl_stays_on_the_same_host(self):
        http = StubHttp(self.PAGES)
        found = asyncio.run(extract.from_url(http, "https://sitio.pe/", pages=5))
        self.assertEqual(http.requested, ["https://sitio.pe/", "https://sitio.pe/contacto"])
        self.assertIn("hola@sitio.pe", found.items["emails"])
        self.assertIn("Telegram: sitio_bot", found.items["profiles"])
        self.assertEqual(found.items["urls"], ["https://otro.pe/x", "https://t.me/sitio_bot"])
        self.assertNotIn("sitio.pe", found.items["domains"])
        self.assertNotIn("otro@malo.pe", found.items.get("emails", []))

    def test_single_page_by_default(self):
        http = StubHttp(self.PAGES)
        asyncio.run(extract.from_url(http, "https://sitio.pe/"))
        self.assertEqual(http.requested, ["https://sitio.pe/"])

    def test_failed_page_is_reported(self):
        found = asyncio.run(extract.from_url(StubHttp({}), "https://caido.pe/"))
        self.assertTrue(any("HTTP 404" in n for n in found.notes))


class CliExtractTests(unittest.TestCase):
    def test_command_and_missing_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "n.txt"
            path.write_text("ana@demo.pe", encoding="utf-8")
            args = cli.build_parser().parse_args(["extract", str(path), "-o", str(Path(tmp) / "o.json")])
            self.assertEqual(cli._extract(cli.UI(quiet=True), args), 0)
            self.assertTrue((Path(tmp) / "o.json").exists())
            missing = cli.build_parser().parse_args(["extract", str(Path(tmp) / "no.txt")])
            self.assertEqual(cli._extract(cli.UI(quiet=True), missing), 2)

    def test_menu_flow_offers_to_investigate_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "n.txt"
            path.write_text("ana@demo.pe y +51987654321", encoding="utf-8")
            answers = iter(["13", str(path), "", "s", "", "0"])
            with mock.patch.object(cli, "main", return_value=0) as main:
                self.assertEqual(cli._menu(cli.UI(quiet=True), ask=lambda _: next(answers)), 0)
            scan = main.call_args_list[0].args[0]
            self.assertEqual(scan[0], "scan")
            self.assertIn("ana@demo.pe", scan)

    def test_typing_a_path_in_the_menu_extracts_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "n.txt"
            path.write_text("sin datos", encoding="utf-8")
            answers = iter([str(path), "", "0"])
            self.assertEqual(cli._menu(cli.UI(quiet=True), ask=lambda _: next(answers)), 0)

    def test_menu_has_extraction_section(self):
        titles = [t for t, _ in cli._menu_sections()]
        self.assertIn("Extracción", titles)
        self.assertEqual(cli.ACTIONS["13"], "extract_file")


if __name__ == "__main__":
    unittest.main()
