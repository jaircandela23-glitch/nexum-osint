from ..core.entities import Kind
from ..core.module import Module

TIPOS = {0: "fija", 1: "móvil", 2: "fija o móvil", 3: "gratuita", 4: "tarifa premium", 5: "costo compartido",
         6: "VOIP", 7: "personal", 8: "buscapersonas", 9: "UAN", 10: "correo de voz"}


class PhoneLibphone(Module):
    name = "phone_libphone"
    description = "Validación, tipo de línea, operador original y región con la base de libphonenumber"
    consumes = (Kind.PHONE,)

    async def run(self, ctx, node):
        try:
            import phonenumbers as pn
            from phonenumbers import carrier, geocoder, timezone
        except ImportError:
            ctx.graph.note(self.name, "phonenumbers no está instalado", "pip install phonenumbers", "info", node)
            return
        try:
            num = pn.parse(node.value)
        except pn.NumberParseException:
            return
        valid = pn.is_valid_number(num)
        node.attrs["valido"] = valid
        node.attrs["posible"] = pn.is_possible_number(num)
        node.attrs["formato_internacional"] = pn.format_number(num, pn.PhoneNumberFormat.INTERNATIONAL)
        node.attrs["formato_nacional"] = pn.format_number(num, pn.PhoneNumberFormat.NATIONAL)
        if not valid:
            ctx.graph.note(self.name, "El número no es válido en el plan de numeración de su país",
                           "Revisa el indicativo y la cantidad de dígitos.", "medium", node)
            return
        kind = pn.number_type(num)
        if kind in TIPOS:
            node.attrs["tipo_linea"] = TIPOS[kind]
        if (region := geocoder.description_for_number(num, "es")):
            node.attrs["region"] = region
        if (op := carrier.name_for_number(num, "es")):
            node.attrs["operador_original"] = op
        if (zones := timezone.time_zones_for_number(num)) and zones != ("Etc/Unknown",):
            node.attrs["zonas_horarias"] = list(zones)
        if kind == 6:
            ctx.graph.note(self.name, "Línea VOIP", "No está ligada a una SIM de operador móvil.", "low", node)
        if kind == 4:
            ctx.graph.note(self.name, "Número de tarifa premium", "Su uso suele estar asociado a cobros altos.", "medium", node)
        if op:
            ctx.graph.note(self.name, f"Operador original del bloque: {op}",
                           "La portabilidad numérica puede haber cambiado el operador actual.", "info", node)
