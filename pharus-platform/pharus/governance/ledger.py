"""Ledger de evidencia encadenado por hash (append-only).

Inspirado en `trust_ledger` de ArgorixLang: cada entrada referencia el hash de
la anterior (`previous_hash`), partiendo de `GENESIS`. Cualquier manipulación
de una entrada rompe la cadena y `verify()` lo detecta. Nunca se guardan
valores de datos personales: sólo categorías, decisiones y huellas.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

EvidenceKind = Literal[
    "scan",
    "contract.registered",
    "contract.check",
    "enforcement",
    "tool.authorization",
    "model.request",
    "model.response",
    "review",
]

GENESIS = "GENESIS"


def _canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


class EvidenceEntry(BaseModel):
    id: str = Field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:12]}")
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    kind: EvidenceKind
    subject: str  # agente, contrato o activo afectado
    decision: str | None = None  # ALLOW | REDACT | DENY | REVIEW
    detail: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = GENESIS
    entry_hash: str = ""

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"entry_hash"})
        return "sha256:" + hashlib.sha256(_canonical(body).encode()).hexdigest()


class EvidenceLedger:
    """Ledger en memoria, thread-safe. En producción: Postgres + firma (ML-DSA)."""

    def __init__(self) -> None:
        self._entries: list[EvidenceEntry] = []
        self._lock = threading.Lock()

    def append(self, kind: EvidenceKind, subject: str, decision: str | None = None, **detail: Any) -> EvidenceEntry:
        with self._lock:
            prev = self._entries[-1].entry_hash if self._entries else GENESIS
            entry = EvidenceEntry(kind=kind, subject=subject, decision=decision, detail=detail, previous_hash=prev)
            entry.entry_hash = entry.compute_hash()
            self._entries.append(entry)
            return entry

    @property
    def entries(self) -> list[EvidenceEntry]:
        return list(self._entries)

    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS

    def verify(self) -> tuple[bool, str | None]:
        """Devuelve (ok, id_de_la_primera_entrada_inválida)."""
        prev = GENESIS
        for e in self._entries:
            if e.previous_hash != prev or e.compute_hash() != e.entry_hash:
                return False, e.id
            prev = e.entry_hash
        return True, None

    def export_bundle(self) -> dict[str, Any]:
        ok, bad = self.verify()
        return {
            "format": "pharus.evidence-bundle/v1",
            "hash_algorithm": "sha256",
            "chain_policy": "append_only",
            "head": self.head(),
            "verified": ok,
            "first_invalid": bad,
            "entries": [e.model_dump(mode="json") for e in self._entries],
        }
