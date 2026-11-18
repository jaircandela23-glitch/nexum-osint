"""Datos públicos de planes de numeración telefónica (ITU-T E.164 / E.123).

Esta tabla es la misma clase de dato público que usan las libphonenumber de
Google o cualquier operador: asigna un indicativo de país a un territorio y,
cuando aplica, a una zona horaria representativa. Para Perú se detalla además
el plan nacional de OSIPTEL (Organismo Supervisor de Inversión Privada en
Telecomunicaciones), que es público y se actualiza aquí a mano.

Nada de esto consulta ubicación en tiempo real: es el mismo tipo de
aproximación "por rango asignado" que hace cualquier herramienta seria de
validación telefónica (son datos de *plan de numeración*, no de GPS).
"""
from __future__ import annotations

from dataclasses import dataclass

# Indicativo E.164 -> (país/territorio, zona(s) horaria representativa)
# Ordenado de más largo a más corto se resuelve en tiempo de carga (abajo).
COUNTRY_CODES: dict[str, tuple[str, tuple[str, ...]]] = {
    "1": ("Estados Unidos / Canadá / Caribe (NANP)", ("America/New_York", "America/Los_Angeles")),
    "7": ("Rusia / Kazajistán", ("Europe/Moscow",)),
    "20": ("Egipto", ("Africa/Cairo",)),
    "27": ("Sudáfrica", ("Africa/Johannesburg",)),
    "30": ("Grecia", ("Europe/Athens",)),
    "31": ("Países Bajos", ("Europe/Amsterdam",)),
    "32": ("Bélgica", ("Europe/Brussels",)),
    "33": ("Francia", ("Europe/Paris",)),
    "34": ("España", ("Europe/Madrid",)),
    "39": ("Italia", ("Europe/Rome",)),
    "40": ("Rumania", ("Europe/Bucharest",)),
    "41": ("Suiza", ("Europe/Zurich",)),
    "43": ("Austria", ("Europe/Vienna",)),
    "44": ("Reino Unido", ("Europe/London",)),
    "45": ("Dinamarca", ("Europe/Copenhagen",)),
    "46": ("Suecia", ("Europe/Stockholm",)),
    "47": ("Noruega", ("Europe/Oslo",)),
    "48": ("Polonia", ("Europe/Warsaw",)),
    "49": ("Alemania", ("Europe/Berlin",)),
    "51": ("Perú", ("America/Lima",)),
    "52": ("México", ("America/Mexico_City", "America/Tijuana")),
    "53": ("Cuba", ("America/Havana",)),
    "54": ("Argentina", ("America/Argentina/Buenos_Aires",)),
    "55": ("Brasil", ("America/Sao_Paulo", "America/Manaus")),
    "56": ("Chile", ("America/Santiago",)),
    "57": ("Colombia", ("America/Bogota",)),
    "58": ("Venezuela", ("America/Caracas",)),
    "60": ("Malasia", ("Asia/Kuala_Lumpur",)),
    "61": ("Australia", ("Australia/Sydney", "Australia/Perth")),
    "62": ("Indonesia", ("Asia/Jakarta",)),
    "63": ("Filipinas", ("Asia/Manila",)),
    "64": ("Nueva Zelanda", ("Pacific/Auckland",)),
    "65": ("Singapur", ("Asia/Singapore",)),
    "66": ("Tailandia", ("Asia/Bangkok",)),
    "81": ("Japón", ("Asia/Tokyo",)),
    "82": ("Corea del Sur", ("Asia/Seoul",)),
    "84": ("Vietnam", ("Asia/Ho_Chi_Minh",)),
    "86": ("China", ("Asia/Shanghai",)),
    "90": ("Turquía", ("Europe/Istanbul",)),
    "91": ("India", ("Asia/Kolkata",)),
    "92": ("Pakistán", ("Asia/Karachi",)),
    "93": ("Afganistán", ("Asia/Kabul",)),
    "94": ("Sri Lanka", ("Asia/Colombo",)),
    "95": ("Myanmar", ("Asia/Yangon",)),
    "98": ("Irán", ("Asia/Tehran",)),
    "211": ("Sudán del Sur", ("Africa/Juba",)),
    "212": ("Marruecos", ("Africa/Casablanca",)),
    "213": ("Argelia", ("Africa/Algiers",)),
    "234": ("Nigeria", ("Africa/Lagos",)),
    "254": ("Kenia", ("Africa/Nairobi",)),
    "351": ("Portugal", ("Europe/Lisbon",)),
    "352": ("Luxemburgo", ("Europe/Luxembourg",)),
    "353": ("Irlanda", ("Europe/Dublin",)),
    "354": ("Islandia", ("Atlantic/Reykjavik",)),
    "355": ("Albania", ("Europe/Tirane",)),
    "356": ("Malta", ("Europe/Malta",)),
    "357": ("Chipre", ("Asia/Nicosia",)),
    "358": ("Finlandia", ("Europe/Helsinki",)),
    "359": ("Bulgaria", ("Europe/Sofia",)),
    "370": ("Lituania", ("Europe/Vilnius",)),
    "371": ("Letonia", ("Europe/Riga",)),
    "372": ("Estonia", ("Europe/Tallinn",)),
    "376": ("Andorra", ("Europe/Andorra",)),
    "380": ("Ucrania", ("Europe/Kyiv",)),
    "381": ("Serbia", ("Europe/Belgrade",)),
    "385": ("Croacia", ("Europe/Zagreb",)),
    "386": ("Eslovenia", ("Europe/Ljubljana",)),
    "420": ("República Checa", ("Europe/Prague",)),
    "421": ("Eslovaquia", ("Europe/Bratislava",)),
    "502": ("Guatemala", ("America/Guatemala",)),
    "503": ("El Salvador", ("America/El_Salvador",)),
    "504": ("Honduras", ("America/Tegucigalpa",)),
    "505": ("Nicaragua", ("America/Managua",)),
    "506": ("Costa Rica", ("America/Costa_Rica",)),
    "507": ("Panamá", ("America/Panama",)),
    "591": ("Bolivia", ("America/La_Paz",)),
    "593": ("Ecuador", ("America/Guayaquil",)),
    "595": ("Paraguay", ("America/Asuncion",)),
    "598": ("Uruguay", ("America/Montevideo",)),
    "972": ("Israel", ("Asia/Jerusalem",)),
    "971": ("Emiratos Árabes Unidos", ("Asia/Dubai",)),
    "974": ("Catar", ("Asia/Qatar",)),
    "886": ("Taiwán", ("Asia/Taipei",)),
}
# Resolución por prefijo más largo primero (algunos indicativos de 1-3 dígitos se solapan)
_SORTED_CODES = sorted(COUNTRY_CODES, key=len, reverse=True)


def lookup_country(e164_digits: str) -> tuple[str, str, tuple[str, ...]] | None:
    """digits sin '+'. Devuelve (indicativo, país, husos) o None si no coincide."""
    for code in _SORTED_CODES:
        if e164_digits.startswith(code):
            country, tzs = COUNTRY_CODES[code]
            return code, country, tzs
    return None


@dataclass(frozen=True)
class PeruArea:
    code: str
    place: str


# Plan Nacional de Numeración de Perú (OSIPTEL) - indicativos de área de red fija.
# Fuente: resoluciones públicas de OSIPTEL sobre numeración geográfica.
PERU_AREA_CODES: tuple[PeruArea, ...] = (
    PeruArea("1", "Lima y Callao"),
    PeruArea("41", "Loreto (Iquitos)"),
    PeruArea("42", "San Martín (Moyobamba/Tarapoto)"),
    PeruArea("43", "Amazonas (Chachapoyas)"),
    PeruArea("44", "La Libertad (Trujillo)"),
    PeruArea("46", "Áncash (Chimbote/Huaraz)"),
    PeruArea("51", "Puno"),
    PeruArea("52", "Tacna"),
    PeruArea("53", "Moquegua"),
    PeruArea("54", "Arequipa"),
    PeruArea("56", "Ica"),
    PeruArea("58", "Apurímac (Abancay)"),
    PeruArea("61", "Junín (Huancayo)"),
    PeruArea("62", "Pasco (Cerro de Pasco)"),
    PeruArea("63", "Huánuco"),
    PeruArea("64", "Huancavelica"),
    PeruArea("65", "Ucayali (Pucallpa)"),
    PeruArea("66", "Madre de Dios (Puerto Maldonado)"),
    PeruArea("67", "Cusco"),
    PeruArea("72", "Cajamarca"),
    PeruArea("73", "Piura"),
    PeruArea("74", "Lambayeque (Chiclayo)"),
    PeruArea("76", "Tumbes"),
)
_PERU_SORTED = sorted(PERU_AREA_CODES, key=lambda a: len(a.code), reverse=True)

# Prefijos de operador móvil asignados originalmente (portabilidad numérica puede
# haber cambiado el operador real; esto es la asignación de bloque, no en vivo).
# Fuente: cuadro de atribución de numeración móvil de OSIPTEL (series 9XX XXX XXX).
PERU_MOBILE_BLOCKS: tuple[tuple[str, str], ...] = (
    ("900", "Movistar"), ("901", "Movistar"), ("902", "Movistar"), ("903", "Movistar"),
    ("904", "Claro"), ("905", "Claro"), ("906", "Claro"), ("907", "Claro"),
    ("908", "Entel"), ("909", "Entel"),
    ("910", "Movistar"), ("911", "Movistar"), ("912", "Movistar"), ("913", "Movistar"),
    ("914", "Claro"), ("915", "Claro"), ("916", "Claro"), ("917", "Claro"), ("918", "Claro"), ("919", "Claro"),
    ("920", "Bitel"), ("921", "Bitel"), ("922", "Bitel"), ("923", "Bitel"),
    ("924", "Entel"), ("925", "Entel"), ("926", "Entel"), ("927", "Entel"), ("928", "Entel"), ("929", "Entel"),
    ("930", "Claro"), ("931", "Claro"), ("932", "Claro"), ("933", "Claro"), ("934", "Claro"),
    ("940", "Movistar"), ("941", "Movistar"), ("942", "Movistar"), ("943", "Movistar"), ("944", "Movistar"),
    ("945", "Movistar"), ("946", "Movistar"), ("947", "Movistar"), ("948", "Movistar"), ("949", "Movistar"),
    ("950", "Claro"), ("951", "Claro"), ("952", "Claro"), ("953", "Claro"), ("954", "Claro"),
    ("955", "Entel"), ("956", "Entel"), ("957", "Entel"), ("958", "Entel"), ("959", "Entel"),
    ("960", "Movistar"), ("961", "Movistar"), ("962", "Movistar"), ("963", "Movistar"), ("964", "Movistar"),
    ("965", "Bitel"), ("966", "Bitel"), ("967", "Bitel"), ("968", "Bitel"), ("969", "Bitel"),
    ("970", "Claro"), ("971", "Claro"), ("972", "Claro"), ("973", "Claro"), ("974", "Claro"),
    ("975", "Entel"), ("976", "Entel"), ("977", "Entel"), ("978", "Entel"), ("979", "Entel"),
    ("980", "Movistar"), ("981", "Movistar"), ("982", "Movistar"), ("983", "Movistar"), ("984", "Movistar"),
    ("985", "Claro"), ("986", "Claro"), ("987", "Claro"), ("988", "Claro"), ("989", "Claro"),
    ("990", "Entel"), ("991", "Entel"), ("992", "Entel"), ("993", "Entel"), ("994", "Entel"),
    ("995", "Bitel"), ("996", "Bitel"), ("997", "Bitel"), ("998", "Bitel"), ("999", "Bitel"),
)
_PERU_MOBILE_MAP = dict(PERU_MOBILE_BLOCKS)


def peru_fixed_area(national_number: str) -> PeruArea | None:
    for area in _PERU_SORTED:
        if national_number.startswith(area.code):
            return area
    return None


def peru_mobile_block(national_number: str) -> str | None:
    if len(national_number) != 9 or not national_number.startswith("9"):
        return None
    return _PERU_MOBILE_MAP.get(national_number[:3])
