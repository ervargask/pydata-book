"""Taxonomía común de datos personales usada por scanner, contratos y ledger.

Alineada con la Ley 21.719 (Chile) — que distingue datos personales y datos
sensibles — y con las categorías especiales del art. 9 GDPR.
"""

from __future__ import annotations

from enum import Enum


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"  # dato sensible (Ley 21.719 art. 2 g) / GDPR art. 9


class DataCategory(str, Enum):
    IDENTIFIER = "identifier"  # nombre, ID interno
    NATIONAL_ID = "national_id"  # RUT, DNI, pasaporte
    CONTACT = "contact"  # email, teléfono
    ADDRESS = "address"
    FINANCIAL = "financial"  # tarjeta, cuenta, sueldo
    HEALTH = "health"
    BIOMETRIC = "biometric"
    GENETIC = "genetic"
    MINORS = "minors"  # datos de niños, niñas y adolescentes
    POLITICAL = "political"
    RELIGION = "religion"
    SEXUAL_ORIENTATION = "sexual_orientation"
    LOCATION = "location"
    EMPLOYMENT = "employment"
    CREDENTIALS = "credentials"  # secretos, contraseñas, tokens
    BEHAVIORAL = "behavioral"
    OTHER = "other"


SENSITIVE_CATEGORIES: frozenset[DataCategory] = frozenset(
    {
        DataCategory.HEALTH,
        DataCategory.BIOMETRIC,
        DataCategory.GENETIC,
        DataCategory.MINORS,
        DataCategory.POLITICAL,
        DataCategory.RELIGION,
        DataCategory.SEXUAL_ORIENTATION,
    }
)


def default_sensitivity(category: DataCategory) -> Sensitivity:
    if category in SENSITIVE_CATEGORIES:
        return Sensitivity.SENSITIVE
    if category in (DataCategory.OTHER,):
        return Sensitivity.INTERNAL
    return Sensitivity.PERSONAL


# Palabras clave (es/en) que, en identificadores de código o nombres de campo,
# sugieren que un agente manipula cierta categoría de datos.
CATEGORY_HINTS: dict[DataCategory, tuple[str, ...]] = {
    DataCategory.NATIONAL_ID: ("rut", "dni", "passport", "pasaporte", "ssn", "national_id", "cedula"),
    DataCategory.CONTACT: ("email", "correo", "phone", "telefono", "celular", "mobile"),
    DataCategory.ADDRESS: ("address", "direccion", "domicilio", "comuna", "zip", "postal"),
    DataCategory.FINANCIAL: ("card", "tarjeta", "iban", "cuenta_bancaria", "bank", "salary", "sueldo", "renta", "credit", "credito", "invoice", "factura", "payment", "pago"),
    DataCategory.HEALTH: ("health", "salud", "diagnos", "medical", "medico", "patient", "paciente", "licencia_medica", "isapre", "fonasa"),
    DataCategory.BIOMETRIC: ("biometric", "biometr", "fingerprint", "huella", "face_embedding", "facial"),
    DataCategory.GENETIC: ("genetic", "genetic", "genoma", "dna", "adn"),
    DataCategory.MINORS: ("minor", "menor", "child", "nino", "alumno", "student"),
    DataCategory.POLITICAL: ("political", "politic", "afiliacion", "sindicato", "union_member"),
    DataCategory.RELIGION: ("religion", "religio"),
    DataCategory.SEXUAL_ORIENTATION: ("sexual_orientation", "orientacion_sexual"),
    DataCategory.LOCATION: ("geoloc", "latitude", "longitude", "gps", "ubicacion"),
    DataCategory.EMPLOYMENT: ("candidate", "candidato", "resume", "curriculum", "cv_", "employee", "empleado", "hiring", "contratacion", "performance_review"),
    DataCategory.CREDENTIALS: ("password", "contrasena", "secret", "api_key", "token"),
    DataCategory.BEHAVIORAL: ("clickstream", "browsing", "tracking", "segment", "profiling", "perfilamiento"),
}
