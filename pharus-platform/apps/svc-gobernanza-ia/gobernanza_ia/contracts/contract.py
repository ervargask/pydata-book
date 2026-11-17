"""Contrato de privacidad de un agente de IA, expresado en Pydantic.

El contrato es la versión ejecutable de lo que el RAT declara: finalidades,
base de licitud, categorías de datos, destinatarios (proveedores de modelo),
transferencias internacionales, herramientas permitidas y retención. Es
*fail-closed* como las políticas de ArgorixLang: lo no declarado se deniega.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from gobernanza_ia.contracts.annotations import Redaction
from gobernanza_ia.governance.taxonomy import SENSITIVE_CATEGORIES, DataCategory


class LegalBasis(str, Enum):
    """Bases de licitud. Valores idénticos a `rat_treatment.legal_basis` del RAT
    de Pharus (Ley 21.719 arts. 12 y 13; GDPR art. 6)."""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    ECONOMIC_OBLIGATIONS = "economic_obligations"
    LEGITIMATE_INTEREST = "legitimate_interest"
    LEGAL_CLAIMS = "legal_claims"
    VITAL_INTEREST = "vital_interest"
    PUBLIC_INTEREST = "public_interest"


# Bases admitidas para datos sensibles (Ley 21.719 art. 16; GDPR art. 9.2).
SENSITIVE_OK = {LegalBasis.CONSENT, LegalBasis.LEGAL_OBLIGATION, LegalBasis.VITAL_INTEREST, LegalBasis.PUBLIC_INTEREST, LegalBasis.LEGAL_CLAIMS}


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    REVIEW = "REVIEW"  # requiere aprobación humana (acción `manual_verify`)
    DENY = "DENY"


class Purpose(BaseModel):
    id: str
    description: str
    legal_basis: LegalBasis
    retention_days: int = Field(ge=0)
    rat_ref: str | None = None  # id del tratamiento en svc-rat


class DataRule(BaseModel):
    category: DataCategory
    purposes: list[str]  # finalidades para las que se puede usar
    to_model: Redaction = Redaction.MASK  # cómo viaja hacia un modelo
    in_output: bool = False  # ¿puede aparecer en la respuesta del agente?


class ToolRule(BaseModel):
    tool: str
    purposes: list[str]
    decision: Decision = Decision.ALLOW  # ALLOW o REVIEW (HITL); DENY para bloquear explícitamente
    data_allowed: list[DataCategory] = Field(default_factory=list)  # categorías que pueden ir en los argumentos


class ModelProviderRule(BaseModel):
    provider: str  # openai, anthropic, google, ollama...
    region: str  # dónde se procesan los datos: US, EU, CL...
    transfer_safeguard: str | None = None  # cláusulas tipo, adecuación, DPA firmado...


class PrivacyContract(BaseModel):
    id: str
    version: str = "1.0.0"
    controller: str  # responsable del tratamiento (la empresa)
    agent_id: str | None = None  # activo del inventario (svc-gobernanza-ia)
    description: str = ""
    purposes: list[Purpose]
    data_rules: list[DataRule] = Field(default_factory=list)
    tool_rules: list[ToolRule] = Field(default_factory=list)
    providers: list[ModelProviderRule] = Field(default_factory=list)
    data_residency: list[str] = Field(default_factory=lambda: ["CL"])
    prohibited_uses: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=lambda: ["ley-21719", "gdpr", "eu-ai-act", "iso-42001"])

    @model_validator(mode="after")
    def _coherence(self) -> PrivacyContract:
        ids = {p.id for p in self.purposes}
        errors = []
        for r in self.data_rules:
            unknown = set(r.purposes) - ids
            if unknown:
                errors.append(f"data_rules[{r.category.value}] usa finalidades no declaradas: {sorted(unknown)}")
            if r.category in SENSITIVE_CATEGORIES:
                weak = [p.id for p in self.purposes if p.id in r.purposes and p.legal_basis not in SENSITIVE_OK]
                if weak:
                    errors.append(f"dato sensible «{r.category.value}» con base de licitud insuficiente en {weak} (Ley 21.719 art. 16)")
        for t in self.tool_rules:
            unknown = set(t.purposes) - ids
            if unknown:
                errors.append(f"tool_rules[{t.tool}] usa finalidades no declaradas: {sorted(unknown)}")
        for p in self.providers:
            if p.region not in self.data_residency and not p.transfer_safeguard:
                errors.append(f"proveedor «{p.provider}» procesa en {p.region} sin garantía de transferencia internacional")
        if errors:
            raise ValueError("; ".join(errors))
        return self

    # --- consultas --------------------------------------------------------
    def purpose(self, pid: str) -> Purpose | None:
        return next((p for p in self.purposes if p.id == pid), None)

    def rule_for(self, category: DataCategory) -> DataRule | None:
        return next((r for r in self.data_rules if r.category == category), None)

    def tool_rule(self, tool: str) -> ToolRule | None:
        return next((t for t in self.tool_rules if t.tool == tool), None)

    def provider_rule(self, provider: str) -> ModelProviderRule | None:
        return next((p for p in self.providers if p.provider == provider), None)

    def fingerprint(self) -> str:
        canon = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(canon.encode()).hexdigest()
