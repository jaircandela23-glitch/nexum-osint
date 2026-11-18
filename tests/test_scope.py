import unittest

from nexum_osint.core import scope
from nexum_osint.core.cache import Cache
from nexum_osint.core.config import Config
from nexum_osint.core.http import Http
from nexum_osint.core.ratelimit import RateLimiter
from tests.fakes import fake_fetch
from nexum_osint.core.engine import Engine
from nexum_osint.core.entities import Graph, Kind
from nexum_osint.core.module import discover


class ScopeTests(unittest.TestCase):
    def setUp(self):
        mods = discover()
        cfg = Config()
        cfg.keys = {}
        http = Http(cfg, Cache(None, enabled=False), RateLimiter(default_rate=500), fetch=fake_fetch)
        self.eng = Engine(http, Graph(), cfg, mods, allow_active=True)
        self.graph = self.eng.graph

    def node(self, value, depth=1):
        return self.graph.add(Kind.DOMAIN, value, source="t", depth=depth)[0]

    def test_freemail_detection(self):
        self.assertTrue(scope.is_freemail("hotmail.com"))
        self.assertTrue(scope.is_freemail("mail.gmail.com"))
        self.assertFalse(scope.is_freemail("empresa.pe"))

    def test_freemail_seed_adds_no_scope(self):
        self.eng._add_scope(Kind.EMAIL, "a@hotmail.com")
        self.assertEqual(self.eng.scope, set())
        self.eng._add_scope(Kind.EMAIL, "a@empresa.pe")
        self.assertEqual(self.eng.scope, {"empresa.pe"})

    def test_third_party_domains_only_resolve_dns(self):
        self.eng._add_scope(Kind.DOMAIN, "www.empresa.pe")
        mods = self.eng.modules
        own = self.node("api.empresa.pe")
        other = self.node("ns1.proveedor.com")
        self.assertTrue(self.eng._allowed(mods["subdomain_brute"], own))
        self.assertFalse(self.eng._allowed(mods["subdomain_brute"], other))
        self.assertFalse(self.eng._allowed(mods["crtsh"], other))
        self.assertTrue(self.eng._allowed(mods["dns"], other))
        self.assertFalse(self.eng._allowed(mods["dns"], self.node("hotmail.com")))


if __name__ == "__main__":
    unittest.main()
