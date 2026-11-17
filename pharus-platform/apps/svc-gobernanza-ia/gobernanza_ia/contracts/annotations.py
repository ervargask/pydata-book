"""Anotaciones de datos personales para modelos Pydantic.

Uso::

    from typing import Annotated
    from pydantic import BaseModel
    from gobernanza_ia.contracts import PII, DataCategory, Redaction

    class Paciente(BaseModel):
        nombre: Annotated[str, PII(DataCategory.IDENTIFIER)]
        rut: Annotated[str, PII(DataCategory.NATIONAL_ID, redaction=Redaction.TOKENIZE)]
        diagnostico: Annotated[str, PII(DataCategory.HEALTH)]

La anotación vive en `FieldInfo.metadata`, así que el contrato la lee sin
cambiar la validación ni la serialización del modelo.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, get_args, get_origin

from pydantic import BaseModel

from gobernanza_ia.governance.taxonomy import DataCategory, Sensitivity, default_sensitivity


class Redaction(str, Enum):
    NONE = "none"  # se envía tal cual
    MASK = "mask"  # «J*** P***»
    HASH = "hash"  # huella estable no reversible (permite joins)
    TOKENIZE = "tokenize"  # token reversible guardado en bóveda (llavero de PII)
    DROP = "drop"  # se elimina el campo


@dataclass(frozen=True)
class PII:
    category: DataCategory
    sensitivity: Sensitivity | None = None
    redaction: Redaction | None = None  # sobrescribe la regla del contrato para este campo
    subject: str = "titular"  # titular de datos: cliente, paciente, trabajador, menor...

    @property
    def effective_sensitivity(self) -> Sensitivity:
        return self.sensitivity or default_sensitivity(self.category)


@dataclass(frozen=True)
class FieldPII:
    path: str  # ruta con puntos: «paciente.rut», «contactos[].email»
    pii: PII


def _pii_of(metadata: list[Any]) -> PII | None:
    return next((m for m in metadata if isinstance(m, PII)), None)


def _nested_models(annotation: Any) -> list[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    out: list[type[BaseModel]] = []
    if get_origin(annotation) is not None:
        for a in get_args(annotation):
            out.extend(_nested_models(a))
    return out


def pii_fields(model: type[BaseModel], prefix: str = "", _seen: set[type] | None = None) -> list[FieldPII]:
    """Inventario recursivo de campos PII declarados en un modelo."""
    _seen = _seen or set()
    if model in _seen:
        return []
    _seen = _seen | {model}
    out: list[FieldPII] = []
    for name, info in model.model_fields.items():
        path = f"{prefix}{name}"
        pii = _pii_of(info.metadata)
        if pii is not None:
            out.append(FieldPII(path=path, pii=pii))
        is_seq = get_origin(info.annotation) in (list, tuple, set, frozenset)
        for sub in _nested_models(info.annotation):
            out.extend(pii_fields(sub, f"{path}{'[]' if is_seq else ''}.", _seen))
    return out
