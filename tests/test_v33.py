import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from nexum_osint import branding, cli, doctor
from nexum_osint.analysis import exposure, narrative, snapshots
from nexum_osint.core.entities import Graph, Kind
from tests.test_v2 import make_engine

ROOT = Path(__file__).resolve().parent.parent


class DoctorTests(unittest.TestCase):
    def test_environment_detection(self):
        self.assertEqual(doctor.detect_env("ID=kali\nID_LIKE=debian", "linux", {}), "kali")
        self.assertEqual(doctor.detect_env("ID=ubuntu\nID_LIKE=debian", "linux", {}), "debian")
        self.assertEqual(doctor.detect_env("ID=arch", "linux", {}), "arch")
        self.assertEqual(doctor.detect_env("ID=fedora", "linux", {}), "fedora")
        self.assertEqual(doctor.detect_env("", "darwin", {}), "macos")
        self.assertEqual(doctor.detect_env("ID=kali", "linux", {"TERMUX_VERSION": "0.118"}), "termux")
        self.assertEqual(doctor.detect_env("", "linux", {"PREFIX": "/data/data/com.termux/files/usr"}), "termux")
        self.assertEqual(doctor.detect_env("ID=plan9", "linux", {}), "otro")

    def test_inspect_flags_missing_libraries(self):
        report = doctor.inspect(find_spec=lambda m: None if m in ("jinja2", "socksio") else object(),
                                which=lambda t: None, env="kali")
        self.assertEqual([l[0] for l in report.missing_core], ["jinja2"])
        self.assertEqual([l[0] for l in report.missing_darkweb_libs], ["socksio"])
        self.assertTrue(all(not t[2] for t in report.tools))

    def test_old_python_is_reported(self):
        report = doctor.inspect(find_spec=lambda m: object(), which=lambda t: None, env="kali", version=(3, 9, 1))
        self.assertFalse(report.python_ok)
        self.assertTrue(any("3.11" in s for s in doctor.guidance(report)))

    def test_termux_guidance_uses_pkg_for_pillow(self):
        report = doctor.inspect(find_spec=lambda m: None, which=lambda t: None, env="termux")
        steps = " | ".join(doctor.guidance(report))
        self.assertIn("pkg install -y python-pillow", steps)
        self.assertNotIn("Pillow", steps.split("pip install")[1].split("|")[0])
        self.assertIn("Dark web: no disponible en Termux", steps)
        cmd = doctor.pip_command(report.missing_pip, "termux")
        self.assertNotIn("Pillow", cmd)
        self.assertIn("httpx[socks]", cmd)

    def test_kali_outside_venv_points_to_installer(self):
        report = doctor.inspect(find_spec=lambda m: None, which=lambda t: None, env="kali")
        with mock.patch.object(doctor, "in_virtualenv", return_value=False):
            self.assertTrue(any("install.sh" in s for s in doctor.guidance(report)))
        with mock.patch.object(doctor, "in_virtualenv", return_value=True):
            self.assertTrue(any(s.startswith("pip install") for s in doctor.guidance(report)))

    def test_system_commands(self):
        self.assertIn("pkg install -y python python-pillow libxml2 libxslt openssl", doctor.system_commands("termux"))
        joined = " ".join(doctor.system_commands("kali", darkweb=True))
        self.assertIn("apt install -y tor torsocks proxychains4 openvpn wireguard-tools", joined)
        self.assertNotIn("tor", " ".join(doctor.system_commands("termux", darkweb=True)).replace("libxslt", ""))

    def test_preflight(self):
        ok = doctor.Report("kali", True, [(m, p, l, u, True) for m, p, l, u in doctor.LIBS], [])
        with mock.patch.object(doctor, "inspect", return_value=ok):
            self.assertTrue(doctor.preflight(cli.UI(quiet=True), interactive=False))
        broken = doctor.Report("kali", True, [(m, p, l, u, False) for m, p, l, u in doctor.LIBS], [])
        with mock.patch.object(doctor, "inspect", return_value=broken):
            self.assertFalse(doctor.preflight(cli.UI(quiet=True), interactive=False))

    def test_run_reports_all_good(self):
        good = doctor.Report("kali", True, [(m, p, l, u, True) for m, p, l, u in doctor.LIBS], [])
        out = io.StringIO()
        with mock.patch.object(doctor, "inspect", return_value=good), redirect_stdout(out):
            self.assertEqual(doctor.run(cli.UI()), 0)
        self.assertIn("Todo lo necesario está instalado", out.getvalue())

    def test_fix_runs_pip_for_missing(self):
        libs = [(m, p, l, u, m != "jinja2") for m, p, l, u in doctor.LIBS]
        before = doctor.Report("kali", True, libs, [])
        after = doctor.Report("kali", True, [(m, p, l, u, True) for m, p, l, u in doctor.LIBS], [])
        calls = []
        with mock.patch.object(doctor, "inspect", side_effect=[before, after]), \
             mock.patch.object(doctor, "in_virtualenv", return_value=True), \
             mock.patch.object(doctor.subprocess, "run", side_effect=lambda cmd, **k: calls.append(cmd) or mock.Mock(returncode=0)), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(doctor.run(cli.UI(), fix=True, assume_yes=True), 0)
        self.assertEqual(calls[0][-1], "jinja2")
        self.assertEqual(calls[0][1:4], ["-m", "pip", "install"])


class ExposureTests(unittest.TestCase):
    def graph(self, *severities):
        g = Graph()
        n = g.add(Kind.DOMAIN, "demo.test", "seed")[0]
        for i, s in enumerate(severities):
            g.note("m", f"hallazgo {i}", "", s, n)
        return g

    def test_empty_is_low(self):
        r = exposure.score(self.graph())
        self.assertEqual((r["puntaje"], r["nivel"]), (0, "Bajo"))

    def test_levels_increase_with_severity(self):
        scores = [exposure.score(self.graph(*["high"] * n))["puntaje"] for n in (0, 1, 3, 6, 12)]
        self.assertEqual(scores, sorted(scores))
        self.assertLessEqual(scores[-1], 100)
        self.assertEqual(exposure.score(self.graph(*["high"] * 12))["nivel"], "Crítico")

    def test_minor_notices_do_not_equal_a_breach(self):
        many_low = exposure.score(self.graph(*["low"] * 20))["puntaje"]
        one_high = exposure.score(self.graph("high", "high"))["puntaje"]
        self.assertLess(many_low, one_high)

    def test_factors_list_most_severe_first(self):
        r = exposure.score(self.graph("medium", "high", "info"))
        self.assertEqual(r["factores"][0], "hallazgo 1")
        self.assertEqual((r["criticos"], r["medios"]), (1, 1))


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": self.tmp.name, "XDG_CONFIG_HOME": self.tmp.name})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def build(self, domains, notes=()):
        g = Graph()
        for d in domains:
            g.add(Kind.DOMAIN, d, "seed")
        node = next(iter(g.nodes.values()))
        for sev, title in notes:
            g.note("m", title, "", sev, node)
        return g

    def test_first_run_has_no_comparison(self):
        self.assertIsNone(snapshots.compare(snapshots.load(["demo.test"]), self.build(["demo.test"])))

    def test_detects_changes(self):
        snapshots.save(["demo.test"], self.build(["demo.test", "a.demo.test"], [("high", "Filtración")]))
        diff = snapshots.compare(snapshots.load(["demo.test"]),
                                 self.build(["demo.test", "b.demo.test"], [("medium", "Cabeceras")]))
        self.assertEqual(diff["entidades_nuevas"], ["domain:b.demo.test"])
        self.assertEqual(diff["entidades_ausentes"], ["domain:a.demo.test"])
        self.assertEqual(diff["hallazgos_nuevos"], [["medium", "Cabeceras"]])
        self.assertEqual(diff["hallazgos_resueltos"], [["high", "Filtración"]])

    def test_manual_links_are_ignored(self):
        g = self.build(["demo.test"])
        g.add(Kind.URL, "https://x.test/", "m", manual=True)
        snapshots.save(["demo.test"], g)
        self.assertEqual(snapshots.load(["demo.test"])["nodes"], ["domain:demo.test"])

    def test_key_is_order_independent(self):
        snapshots.save(["B", "a"], self.build(["demo.test"]))
        self.assertIsNotNone(snapshots.load(["a", "b"]))


class NarrativeTests(unittest.TestCase):
    def test_summary_mentions_counts_and_level(self):
        g = Graph()
        g.add(Kind.EMAIL, "a@demo.test", "seed")
        g.add(Kind.EMAIL, "b@demo.test", "m")
        n = g.add(Kind.USERNAME, "ana", "seed")[0]
        g.note("m", "Filtración grave", "", "high", n)
        text = narrative.resumen(g, ["ana"], exposure.score(g))
        self.assertIn("2 correos", text)
        self.assertIn("1 alias", text)
        self.assertIn("exposición es", text)
        one = Graph()
        one.add(Kind.EMAIL, "a@demo.test", "seed")
        self.assertIn("se reunió 1 entidad", narrative.resumen(one, ["a@demo.test"], exposure.score(one)))
        self.assertIn("Filtración grave", text)


class InputAndWatchTests(unittest.TestCase):
    def test_read_targets_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "t.txt"
            f.write_text("# lista\n\ndemo.test  # sitio principal\n  persona@demo.test  \n#otro\n", encoding="utf-8")
            self.assertEqual(cli._read_targets(f), ["demo.test", "persona@demo.test"])

    def test_scan_accepts_file_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "t.txt"
            f.write_text("demo.test\n+51987654321\n", encoding="utf-8")
            args = cli.build_parser().parse_args(["scan", "-i", str(f)])
            seeds = cli._build_seeds(args, cli.UI(quiet=True))
        self.assertEqual([k for k, _ in seeds], [Kind.DOMAIN, Kind.PHONE])

    def test_scan_without_targets_is_rejected(self):
        args = cli.build_parser().parse_args(["scan"])
        self.assertIsNone(cli._build_seeds(args, cli.UI(quiet=True)))

    def test_watch_repeats_and_stops(self):
        args = cli.build_parser().parse_args(["watch", "demo.test", "--veces", "2", "--cada", "1"])
        calls = []

        async def fake_scan(a, ui):
            calls.append(1)
            return 0
        with mock.patch.object(cli, "_scan", fake_scan), mock.patch("time.sleep") as sleep, redirect_stdout(io.StringIO()):
            self.assertEqual(cli._watch(args, cli.UI()), 0)
        self.assertEqual(len(calls), 2)
        sleep.assert_called_once_with(60)


class EmailProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_free_provider_needs_no_lookup(self):
        g = Graph()
        await make_engine(g, {"email_provider"}, depth=0).run([(Kind.EMAIL, "ana@gmail.com")])
        self.assertEqual(g.nodes["email:ana@gmail.com"].attrs["tipo_buzon"], "servicio gratuito personal")

    async def test_google_workspace_detected(self):
        from nexum_osint.core.http import Response
        from tests.fakes import fake_fetch

        async def fetch(method, url, params=None, headers=None, data=None):
            if "cloudflare-dns.com" in url and (params or {}).get("type") == "MX":
                return Response(200, json.dumps({"Answer": [{"type": 15, "data": "10 aspmx.l.google.com."}]}), {}, "")
            return await fake_fetch(method, url, params, headers)
        from nexum_osint.core.cache import Cache
        from nexum_osint.core.config import Config
        from nexum_osint.core.engine import Engine
        from nexum_osint.core.http import Http
        from nexum_osint.core.module import discover
        from nexum_osint.core.ratelimit import RateLimiter
        http = Http(Config(), Cache(None, enabled=False), RateLimiter(default_rate=1000), fetch=fetch)
        g = Graph()
        await Engine(http, g, Config(), {"email_provider": discover()["email_provider"]}, depth=0).run(
            [(Kind.EMAIL, "ana@empresa.test")])
        self.assertEqual(g.nodes["email:ana@empresa.test"].attrs["proveedor_correo"], "Google Workspace / Gmail")


class LogoAndInstallTests(unittest.TestCase):
    def banner(self, columns):
        with mock.patch.dict(os.environ, {"COLUMNS": str(columns)}):
            out = io.StringIO()
            with redirect_stdout(out):
                cli.UI().banner("estado")
        return out.getvalue()

    def test_large_logo_on_wide_terminals(self):
        text = self.banner(100)
        self.assertIn("███╗   ██╗███████╗", text)
        self.assertIn("╔═╗╔═╗╦╔╗╔╔╦╗", text)
        self.assertIn(branding.AUTHOR, text)

    def test_compact_logo_on_narrow_terminals(self):
        text = self.banner(48)
        self.assertIn("█▄ █ █▀▀", text)
        self.assertNotIn("███╗", text)

    def test_logo_widths_fit(self):
        self.assertLessEqual(max(len(l) for l in branding.LOGO.splitlines()), 56)
        self.assertLessEqual(max(len(l) for l in branding.LOGO_SMALL.splitlines()), 44)
        self.assertGreaterEqual(len(branding.GRADIENT), 6)

    def test_scripts_have_valid_syntax(self):
        for name in ("install.sh", "uninstall.sh"):
            self.assertEqual(subprocess.run(["bash", "-n", str(ROOT / name)]).returncode, 0, name)

    def dry_run(self, extra_env, binname):
        with tempfile.TemporaryDirectory() as tmp:
            shims = Path(tmp) / "shims"
            shims.mkdir()
            for name in ("python", "python3"):
                (shims / name).symlink_to(shutil.which("python3"))
            env = {**os.environ, "HOME": tmp, "PATH": f"{shims}:{os.environ['PATH']}", "NEXUM_DRY_RUN": "1", **extra_env}
            env.pop("TERMUX_VERSION", None) if "TERMUX_VERSION" not in extra_env else None
            r = subprocess.run(["bash", str(ROOT / "install.sh")], env=env, capture_output=True, text=True, timeout=120)
            return r.stdout + r.stderr, Path(tmp)

    def test_termux_dry_run(self):
        prefix = tempfile.mkdtemp()
        (Path(prefix) / "bin").mkdir()
        out, home = self.dry_run({"TERMUX_VERSION": "0.118", "PREFIX": prefix}, "termux")
        self.assertIn("Entorno: Termux", out)
        self.assertIn("pkg install -y python python-pillow", out)
        self.assertIn("Dark web: no disponible en Termux", out)
        self.assertTrue((Path(prefix) / "bin" / "nexum-osint").is_symlink())
        shutil.rmtree(prefix, ignore_errors=True)

    def test_debian_dry_run_with_darkweb(self):
        with tempfile.TemporaryDirectory() as tmp:
            shims = Path(tmp) / "shims"
            shims.mkdir()
            (shims / "python3").symlink_to(shutil.which("python3"))
            env = {**os.environ, "HOME": tmp, "PATH": f"{shims}:{os.environ['PATH']}", "NEXUM_DRY_RUN": "1", "NEXUM_FORCE_SYSTEM": "1"}
            env.pop("TERMUX_VERSION", None)
            env["PREFIX"] = ""
            r = subprocess.run(["bash", str(ROOT / "install.sh"), "--darkweb"], env=env, capture_output=True, text=True, timeout=120)
            out = r.stdout + r.stderr
            self.assertIn("apt-get install -y python3 python3-venv python3-pip", out)
            self.assertIn("tor torsocks proxychains4 openvpn wireguard-tools", out)
            self.assertTrue((Path(tmp) / ".local" / "bin" / "nexum-osint").is_symlink())


class InstallerResilienceTests(unittest.TestCase):
    def run_script(self, tmp, fake_apt_ok: bool, force=False, python_ok=True):
        bin_dir = Path(tmp) / "bin"
        bin_dir.mkdir()
        (bin_dir / "python3").symlink_to(shutil.which("python3"))
        # sudo falso: apt-get update falla como un espejo desincronizado; install según el caso
        (bin_dir / "sudo").write_text("#!/bin/sh\nif [ \"$2\" = update ]; then echo 'E: Fallo al obtener Contents-amd64' >&2; exit 100; fi\n"
                                     f"exit {0 if fake_apt_ok else 100}\n")
        (bin_dir / "sudo").chmod(0o755)
        env = {**os.environ, "HOME": tmp, "PATH": f"{bin_dir}:{os.environ['PATH']}", "NEXUM_DRY_RUN": "0", "NEXUM_SUDO": "sudo"}
        env.pop("TERMUX_VERSION", None)
        env["PREFIX"] = ""
        if force:
            env["NEXUM_FORCE_SYSTEM"] = "1"
        # simula un sistema Debian/Kali y evita pip y descargas reales
        script = (ROOT / "install.sh").read_text().replace('ENV_NAME="$(detect_env)"', 'ENV_NAME="kali"')
        script = script.replace('run "$VENV/bin/pip" install --quiet "$DIR"', 'true').replace('run "$VENV/bin/pip" install --quiet --upgrade pip', 'true')
        script = script.replace('"$VENV/bin/nexum-osint" doctor', 'true').replace('"$VENV/bin/nexum-osint" sites --update', 'true')
        patched = Path(tmp) / "install_test.sh"
        patched.write_text(script)
        patched.chmod(0o755)
        patched.parent.joinpath("config.example.toml").write_text("")
        shutil.copy(ROOT / "config.example.toml", Path(tmp) / "config.example.toml")
        return subprocess.run(["bash", str(patched)], env=env, capture_output=True, text=True, timeout=120, cwd=tmp)

    def test_failed_apt_update_does_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_script(tmp, fake_apt_ok=True, force=True)
            out = r.stdout + r.stderr
            self.assertEqual(r.returncode, 0, out)
            self.assertIn("Instalación completa", out)
            self.assertIn("espejo desincronizado", out)

    def test_failed_apt_install_continues_when_python_is_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_script(tmp, fake_apt_ok=False, force=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("Instalación completa", r.stdout)

    def test_apt_is_skipped_when_python_is_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_script(tmp, fake_apt_ok=False, force=False)
            out = r.stdout + r.stderr
            self.assertEqual(r.returncode, 0, out)
            self.assertIn("se omite la actualización de paquetes", out)
            self.assertNotIn("apt-get update", out)


class MenuV33Tests(unittest.TestCase):
    def test_menu_entries(self):
        actions = set(cli.ACTIONS.values())
        self.assertTrue({"watch", "doctor", "quick", "tools"} <= actions)
        self.assertEqual(len(cli.ACTIONS), len(set(cli.ACTIONS)))
        self.assertEqual(cli.ACTIONS["25"], "about")

    def test_modules_total_in_docs_is_current(self):
        from nexum_osint.core.module import discover
        docs = (ROOT / "docs" / "MODULES.md").read_text(encoding="utf-8")
        self.assertIn(f"{len(discover())} módulos.", docs)


if __name__ == "__main__":
    unittest.main()
