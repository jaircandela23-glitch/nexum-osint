from ..core.entities import Kind
from ..core.links import dork, enc, manual
from ..core.module import Module


class OrgGleif(Module):
    name = "org_gleif"
    description = "Entidades legales registradas con ese nombre (GLEIF, base global de LEI, sin key)"
    consumes = (Kind.ORG,)
    rate = 1
    hosts = ("api.gleif.org",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://api.gleif.org/api/v1/lei-records",
                               params={"filter[entity.legalName]": node.value, "page[size]": 5}, ttl=24 * 3600)
        if not r.ok:
            return
        rows = r.json().get("data", [])
        for row in rows:
            ent = row.get("attributes", {}).get("entity", {})
            lei = row.get("id") or row.get("attributes", {}).get("lei")
            addr = ent.get("legalAddress", {})
            ctx.emit(node, Kind.URL, f"https://search.gleif.org/#/record/{lei}", "gleif_record", self.name,
                     pivot=False, label=(ent.get("legalName") or {}).get("name"), lei=lei,
                     pais=addr.get("country"), ciudad=addr.get("city"), estado=ent.get("status"),
                     jurisdiccion=ent.get("jurisdiction"))
        if rows:
            ctx.graph.note(self.name, f"{len(rows)} entidad(es) con LEI y nombre similar",
                           "Verifica jurisdicción y dirección: pueden ser empresas distintas con nombre parecido.",
                           "info", node)


class OrgLinks(Module):
    name = "org_links"
    description = "Registros mercantiles, listas de sanciones y búsquedas dirigidas de la organización"
    consumes = (Kind.ORG,)

    async def run(self, ctx, node):
        n, s = node.value, self.name
        q = enc(f'"{n}"')
        for label, url, purpose in [
            ("OpenCorporates: empresas", f"https://opencorporates.com/companies?q={enc(n)}", "empresas"),
            ("ICIJ Offshore Leaks", f"https://offshoreleaks.icij.org/search?q={enc(n)}", "empresas"),
            ("OpenSanctions", f"https://www.opensanctions.org/search/?q={enc(n)}", "listas"),
            ("SEC EDGAR (EE. UU.)", f"https://www.sec.gov/edgar/search/#/q={q}", "registro_oficial"),
            ("Perú: SUNAT consulta RUC", "https://e-consultaruc.sunat.gob.pe/cl-ti-itmrconsruc/FrameCriterioBusquedaWeb.jsp", "registro_oficial"),
            ("Perú: OSCE proveedores del Estado", "https://www.osce.gob.pe/", "registro_oficial"),
            ("Colombia: RUES", "https://www.rues.org.co/", "registro_oficial"),
            ("España: BORME", "https://www.boe.es/diario_borme/", "registro_oficial"),
            ("LinkedIn: empresas", f"https://www.linkedin.com/search/results/companies/?keywords={enc(n)}", "profesional"),
            ("Google: nombre exacto", dork(f'"{n}"'), "buscador"),
            ("Google: LinkedIn empresa", dork(f'"{n}" site:linkedin.com/company'), "profesional"),
            ("Google: reclamos y estafas", dork(f'"{n}" estafa OR reclamo OR denuncia'), "reputacion"),
            ("Google: documentos PDF", dork(f'"{n}" filetype:pdf'), "documentos"),
        ]:
            manual(ctx, node, s, label, url, purpose)
