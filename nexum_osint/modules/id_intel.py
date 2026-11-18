"""Documentos e identificadores: validación de formato y enlaces oficiales.

No consulta bases de datos de titulares de DNI/cédula: esos datos no son
públicos y esta herramienta no los expone. Sí valida el formato y el dígito
verificador de identificadores tributarios (RUC, NIT), que son públicos por ley.
"""
from __future__ import annotations

import re

from ..core.entities import Kind
from ..core.links import dork, manual
from ..core.module import Module

RUC_PREFIX = {"10": "persona natural", "15": "no domiciliado", "16": "extranjero",
              "17": "sucesión indivisa", "20": "persona jurídica"}


def ruc_valid(ruc: str) -> bool:
    if not re.fullmatch(r"\d{11}", ruc):
        return False
    weights = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
    d = 11 - sum(int(a) * b for a, b in zip(ruc[:10], weights)) % 11
    return {10: 0, 11: 1}.get(d, d) == int(ruc[10])


def nit_valid(nit: str) -> bool:
    if not re.fullmatch(r"\d{6,16}", nit):
        return False
    weights = (3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71)
    body = nit[:-1][::-1]
    if len(body) > len(weights):
        return False
    r = sum(int(c) * weights[i] for i, c in enumerate(body)) % 11
    return (r if r < 2 else 11 - r) == int(nit[-1])


def classify(value: str) -> list[tuple[str, bool | None, str]]:
    """Devuelve posibles tipos: (tipo, formato válido, detalle)."""
    out = []
    if re.fullmatch(r"\d{11}", value) and value[:2] in RUC_PREFIX:
        out.append(("RUC (Perú)", ruc_valid(value), RUC_PREFIX[value[:2]]))
    if re.fullmatch(r"\d{8}", value):
        out.append(("DNI (Perú)", None, "8 dígitos; el formato no permite más validación pública"))
    if re.fullmatch(r"\d{9,10}", value) and not value.startswith(("10", "20")):
        out.append(("NIT (Colombia)", nit_valid(value), "dígito verificador DIAN"))
    if re.fullmatch(r"[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}", value):
        out.append(("RFC (México)", None, "persona moral" if len(value) == 12 else "persona física"))
    if re.fullmatch(r"[A-Z]\d{7}[A-Z0-9]", value) or re.fullmatch(r"\d{8}[A-Z]", value):
        out.append(("NIF/NIE (España)", None, "formato español"))
    if re.fullmatch(r"\d{10}|\d{13}", value) and not out:
        out.append(("Cédula/RUC (Ecuador)", None, "10 o 13 dígitos"))
    return out


class IdValidate(Module):
    name = "id_validate"
    description = "Detecta el tipo de documento por formato y valida dígitos verificadores (RUC, NIT)"
    consumes = (Kind.DOC,)

    async def run(self, ctx, node):
        kinds = classify(node.value)
        if not kinds:
            ctx.graph.note(self.name, "Formato de documento no reconocido",
                           "Se probó contra formatos de Perú, Colombia, México, España y Ecuador.", "info", node)
            return
        node.attrs["possible_types"] = [k for k, _, _ in kinds]
        for kind, valid, detail in kinds:
            if valid is True:
                ctx.graph.note(self.name, f"{kind}: formato y dígito verificador válidos", detail, "info", node)
            elif valid is False:
                ctx.graph.note(self.name, f"{kind}: dígito verificador incorrecto", detail, "medium", node)
            else:
                ctx.graph.note(self.name, f"{kind}: formato compatible", detail, "info", node)


class IdLinks(Module):
    name = "id_links"
    description = "Enlaces a consultas oficiales públicas según el tipo de documento"
    consumes = (Kind.DOC,)

    async def run(self, ctx, node):
        v, s = node.value, self.name
        types = {k for k, _, _ in classify(v)}
        if "RUC (Perú)" in types:
            manual(ctx, node, s, "SUNAT: consulta RUC", "https://e-consultaruc.sunat.gob.pe/cl-ti-itmrconsruc/FrameCriterioBusquedaWeb.jsp", "registro_oficial")
            manual(ctx, node, s, "OSCE: proveedores del Estado", "https://www.osce.gob.pe/", "registro_oficial")
        if "NIT (Colombia)" in types:
            manual(ctx, node, s, "RUES: registro mercantil", "https://www.rues.org.co/", "registro_oficial")
            manual(ctx, node, s, "DIAN: consulta de RUT", "https://muisca.dian.gov.co/WebRutMuisca/DefConsultaEstadoRUT.faces", "registro_oficial")
        if "RFC (México)" in types:
            manual(ctx, node, s, "SAT: validación de RFC", "https://www.sat.gob.mx/aplicacion/operacion/31274/consulta-tu-clave-de-rfc-y-verifica-si-esta-inscrito-en-el-rfc", "registro_oficial")
        manual(ctx, node, s, "Google: documento exacto", dork(f'"{v}"'), "buscador")
        if "DNI (Perú)" in types or "Cédula/RUC (Ecuador)" in types:
            ctx.graph.note(self.name, "La consulta de titular por DNI/cédula no es pública",
                           "Solo la entidad emisora puede darla, con base legal o consentimiento. "
                           "Si el documento corresponde a una empresa, usa su RUC/NIT.", "info", node)
