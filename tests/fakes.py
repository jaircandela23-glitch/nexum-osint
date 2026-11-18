"""Respuestas simuladas para probar el motor sin red."""
import json
import re

from nexum_osint.core.http import Response


def _resp(status=200, body="", url=""):
    text = body if isinstance(body, str) else json.dumps(body)
    return Response(status, text, {}, url)


async def fake_fetch(method, url, params=None, headers=None, data=None):
    params = params or {}
    if "html.duckduckgo.com" in url:
        if "blocked" in params.get("q", ""):
            return _resp(202, "<html>anomaly: unusual traffic</html>")
        return _resp(body=(
            '<div><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.demo.test%2Fplan.pdf&amp;rut=x">'
            'Plan <b>2024</b></a></div><div><a class="result__a" href="https://otro.test/p">Otro</a></div>'
            '<a class="result__a" href="https://duckduckgo.com/y">interno</a>'))
    if url.startswith("https://crt.sh"):
        return _resp(body=[
            {"name_value": "www.demo.test\napi.demo.test", "not_after": "2027-01-01", "issuer_name": "O=Let's Encrypt, CN=R3"},
            {"name_value": "*.demo.test\nmail.demo.test", "not_after": "2027-02-01", "issuer_name": "O=Let's Encrypt, CN=R3"},
        ])
    if "cloudflare-dns.com" in url:
        name, rtype = params["name"], params["type"]
        code = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5}[rtype]
        if rtype == "A" and name in ("demo.test", "www.demo.test", "api.demo.test"):
            return _resp(body={"Answer": [{"type": 1, "data": "203.0.113.10"}]})
        if rtype == "A" and name == "mail.demo.test":
            return _resp(body={"Answer": [{"type": 1, "data": "203.0.113.25"}]})
        if rtype == "MX" and name == "demo.test":
            return _resp(body={"Answer": [{"type": 15, "data": "10 mail.demo.test."}]})
        if rtype == "TXT" and name == "demo.test":
            return _resp(body={"Answer": [{"type": 16, "data": '"v=spf1 include:_spf.demo-mail.test +all"'}]})
        return _resp(body={})
    if "rdap.org/domain" in url:
        return _resp(body={
            "events": [{"eventAction": "registration", "eventDate": "2015-03-01T00:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "2026-11-20T00:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Demo Registrar SA"]]]}],
            "nameservers": [{"ldhName": "ns1.demo-dns.test"}],
        })
    if "web.archive.org/cdx" in url:
        return _resp(body=[["timestamp", "original", "statuscode"],
                           ["20160101000000", "http://demo.test/", "200"],
                           ["20200505000000", "http://demo.test/admin/login.php", "200"]])
    if "internetdb.shodan.io/203.0.113.10" in url:
        return _resp(body={"ports": [80, 443, 3389], "hostnames": [], "vulns": ["CVE-2019-0708"],
                           "cpes": [], "tags": ["cloud"]})
    if "internetdb.shodan.io" in url:
        return _resp(404, {"detail": "No information available"})
    if "ip-api.com" in url:
        return _resp(body={"status": "success", "country": "Peru", "city": "Lima", "isp": "DemoNet",
                           "org": "DemoNet", "as": "AS64500 Demo Networks", "asname": "DEMO",
                           "lat": -12.04, "lon": -77.03, "hosting": True, "proxy": False})
    if "gravatar.com" in url:
        return _resp(404, "not found")
    if "emailrep.io" in url:
        return _resp(429, "")
    # --- v2: nuevas fuentes ---
    if "api.github.com/users/jdoe/events" in url:
        return _resp(body=[{"payload": {"commits": [
            {"author": {"name": "John Doe", "email": "john.doe@corp.test"}},
            {"author": {"name": "bot", "email": "123+bot@users.noreply.github.com"}}]}}])
    if "api.github.com/users/jdoe" in url:
        return _resp(body={"login": "jdoe", "html_url": "https://github.com/jdoe", "name": "John Doe",
                           "company": "Corp", "location": "Lima", "blog": "johndoe.test",
                           "email": None, "followers": 5, "public_repos": 3, "twitter_username": "jdoe_x",
                           "created_at": "2015-03-02T10:00:00Z"})
    if "api.github.com/search/users" in url:
        return _resp(body={"items": [{"login": "jdoe", "html_url": "https://github.com/jdoe"}]})
    if "api.github.com/search/commits" in url:
        return _resp(body={"items": [{"commit": {"author": {"name": "John Doe"}}, "repository": {"full_name": "jdoe/tool"}}]})
    if "api.github.com" in url:
        return _resp(404, {})
    if "xposedornot.com" in url:
        if "leaked@" in url:
            return _resp(body={"breaches": [["Adobe", "LinkedIn"]]})
        return _resp(404, {"Error": "Not found"})
    if "leakcheck.io" in url:
        if params.get("check", "").startswith("leaked@"):
            return _resp(body={"success": True, "found": 3, "fields": ["email", "password"],
                               "sources": [{"name": "Collection1", "date": "2019-01"}]})
        return _resp(body={"success": True, "found": 0})
    if "wikidata.org" in url:
        return _resp(body={"search": [{"id": "Q42", "label": "Jair Munoz", "description": "ejemplo"}]})
    if "pub.orcid.org" in url:
        return _resp(body={"result": [{"orcid-identifier": {"path": "0000-0001-2345-6789"}}]})
    if "otx.alienvault.com" in url and "passive_dns" in url:
        return _resp(body={"passive_dns": [
            {"hostname": "vpn.demo.test", "address": "203.0.113.50", "record_type": "A"},
            {"hostname": "demo.test", "address": "203.0.113.10", "record_type": "A"}]})
    if "otx.alienvault.com" in url:
        return _resp(body={"pulse_info": {"count": 2}})
    if "urlscan.io" in url:
        return _resp(body={"results": [{"page": {"domain": "shop.demo.test", "ip": "203.0.113.77", "server": "nginx"}}]})
    if "hackertarget.com" in url:
        return _resp(200, "dev.demo.test,203.0.113.88\nother.example,1.1.1.1")
    if "onionoo.torproject.org" in url:
        return _resp(body={"relays": []})
    if "archive.org/wayback/available" in url:
        return _resp(body={"archived_snapshots": {"closest": {"url": "http://web.archive.org/x", "timestamp": "2020"}}})
    if "check.torproject.org" in url:
        return _resp(body={"IsTor": True, "IP": "198.51.100.7"})
    if "ahmia.fi" in url or url.endswith(".onion/search/?q=demo.test") or ".onion/search" in url:
        return _resp(200, '<li class="result"><h4><a href="/search/redirect?search_term=x&amp;redirect_url=http://'
                     'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/">Foro demo</a></h4>'
                     '<p>menciona demo.test</p></li>')
    if "ipqualityscore.com" in url:
        return _resp(body={"success": True, "valid": True, "fraud_score": 80, "leaked": True, "VOIP": True})
    if "api.veriphone.io" in url:
        return _resp(body={"phone_valid": True, "phone_type": "mobile", "carrier": "Claro"})
    if "keybase.io" in url:
        return _resp(body={"them": [None]})
    # --- v3 ---
    if url == "https://demo.test/" or url == "http://demo.test/":
        html = ('<html><head><title>Demo SA</title><meta name="generator" content="WordPress 6.5">'
                '<script>ga("create","UA-1234567-1")</script></head><body>'
                '<a href="mailto:ventas@demo.test">ventas@demo.test</a> <a href="tel:+51 1 555 0100">llamar</a>'
                '<a href="https://www.facebook.com/demosa">fb</a><a href="https://www.facebook.com/">home</a></body></html>')
        return Response(200, html, {"Server": "nginx", "Strict-Transport-Security": "max-age=1"}, "https://demo.test/")
    if url.endswith("demo.test/robots.txt"):
        return _resp(200, "User-agent: *\nDisallow: /admin/\nDisallow: /")
    if url.endswith("demo.test/.well-known/security.txt"):
        return _resp(404, "")
    if "mempool.space" in url and url.endswith("/txs"):
        return _resp(body=[{"status": {"block_time": 1700000000}}])
    if "mempool.space" in url:
        return _resp(body={"chain_stats": {"funded_txo_sum": 500000000, "spent_txo_sum": 100000000, "tx_count": 4}})
    if "api.gleif.org" in url:
        return _resp(body={"data": [{"id": "529900T8BM49AURSDO55", "attributes": {"entity": {
            "legalName": {"name": "DEMO SA"}, "legalAddress": {"country": "PE", "city": "Lima"}, "status": "ACTIVE"}}}]})
    if "stat.ripe.net" in url and "as-overview" in url:
        return _resp(body={"data": {"holder": "DEMO-NET Demo Networks"}})
    if "stat.ripe.net" in url and "announced-prefixes" in url:
        return _resp(body={"data": {"prefixes": [{"prefix": "203.0.113.0/24"}]}})
    if "stat.ripe.net" in url:
        return _resp(body={"data": {"abuse_contacts": ["abuse@demo-net.test"]}})
    if "reverseiplookup" in url:
        return _resp(200, "a.demo.test\nb.demo.test")
    if url.endswith("/foto.jpg") and "demo.test" in url:
        import io
        from PIL import Image
        img = Image.new("RGB", (8, 8))
        ex = Image.Exif()
        ex[271], ex[272] = "ACME", "Cam 1"
        gps = ex.get_ifd(0x8825)
        gps[1], gps[2], gps[3], gps[4] = "S", (12.0, 3.0, 0.0), "W", (77.0, 1.0, 30.0)
        buf = io.BytesIO()
        img.save(buf, "JPEG", exif=ex)
        return Response(200, "", {}, url, content=buf.getvalue())
    # --- sitios de alias ---
    if url.startswith("https://github.com/jdoe") or "gitlab.com/api/v4/users?username=jdoe" in url:
        return _resp(200, "[{\"id\":1}]" if "gitlab" in url else "profile")
    if "dev.to/" in url or "medium.com/@" in url:   # SPA que responde 200 a todo
        return _resp(200, "<html>spa</html>")
    if re.search(r"hacker-news.*user/jdoe", url):
        return _resp(200, '{"id":"jdoe"}')
    if "hacker-news" in url:
        return _resp(200, "null")
    if "gitlab.com/api" in url:
        return _resp(200, "[]")
    return _resp(404, "not found")
