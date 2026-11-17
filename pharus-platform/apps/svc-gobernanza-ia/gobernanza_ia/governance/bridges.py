"""Puentes E2E hacia los demás módulos de Pharus (sin PII, por ID).

- Contrato de privacidad → **borrador de tratamiento en el RAT**
  (`POST svc-rat /internas/gobernanza-ia/tratamientos`, mismo patrón que
  PharusScan: nunca cambia el estado, queda `draft` para revisión del DPO).
- Activo de alto riesgo → **propuesta de EIPD** (riesgo = probabilidad ×
  impacto, 1-3 cada uno; R-130/R-131).
- Hallazgo crítico/alto → **propuesta de incidente**
  (evento `gobernanza_ia.hallazgo.detectado`, como ciberseguridad).
- Los eventos siguen el sobre común de `arquitectura.md` §7.2.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from gobernanza_ia.contracts.contract import PrivacyContract
from gobernanza_ia.governance.taxonomy import SENSITIVE_CATEGORIES
from gobernanza_ia.scanner.models import AgentAsset, RiskTier, Severity

# Mapeo de categoría Pharus → texto del RAT original (data_categories / sensitive_data_categories)
RAT_CATEGORY_LABEL = {
    "identifier": "Identificación",
    "national_id": "Identificación (RUT)",
    "contact": "Contacto",
    "address": "Domicilio",
    "financial": "Datos financieros",
    "health": "Salud",
    "biometric": "Biométricos",
    "genetic": "Genéticos",
    "minors": "Niños, niñas y adolescentes",
    "political": "Opiniones políticas",
    "religion": "Creencias religiosas",
    "sexual_orientation": "Vida u orientación sexual",
    "location": "Geolocalización",
    "employment": "Laborales",
    "credentials": "Credenciales",
    "behavioral": "Comportamiento / perfilamiento",
    "other": "Otros",
}


class RatTreatmentDraft(BaseModel):
    """Payload compatible con `rat_treatment` (campos del original)."""

    name: str
    purpose: str
    legal_basis: str
    legal_basis_context: str = ""
    status: str = "draft"
    data_categories: list[str]
    data_subjects: list[str]
    retention_period: str
    security_measures: list[str]
    transfers: bool
    transfer_countries: list[str]
    transfer_instrument: str
    sensitive_data_categories: list[str]
    high_risk: bool
    dpia: bool
    origen: str = "gobernanza_ia"
    contrato_id: str
    contrato_huella: str


def contract_to_rat(contract: PrivacyContract, purpose_id: str, *, high_risk: bool, subjects: list[str] | None = None) -> RatTreatmentDraft:
    p = contract.purpose(purpose_id)
    if p is None:
        raise ValueError(f"finalidad {purpose_id} no existe")
    cats = [r.category for r in contract.data_rules if purpose_id in r.purposes]
    foreign = sorted({pr.region for pr in contract.providers if pr.region not in contract.data_residency})
    return RatTreatmentDraft(
        name=f"Agente de IA: {contract.description or contract.id}",
        purpose=p.description,
        legal_basis=p.legal_basis.value,
        legal_basis_context=f"Declarado en el contrato de privacidad {contract.id} v{contract.version}",
        data_categories=[RAT_CATEGORY_LABEL[c.value] for c in cats if c not in SENSITIVE_CATEGORIES],
        sensitive_data_categories=[RAT_CATEGORY_LABEL[c.value] for c in cats if c in SENSITIVE_CATEGORIES],
        data_subjects=subjects or ["Clientes"],
        retention_period=f"{p.retention_days} días",
        security_measures=[
            "Redacción/tokenización de PII antes del modelo (contrato de privacidad)",
            "Herramientas autorizadas por finalidad (fail-closed)",
            "Ledger de evidencia encadenado por hash",
        ],
        transfers=bool(foreign),
        transfer_countries=foreign,
        transfer_instrument="; ".join(f"{pr.provider}: {pr.transfer_safeguard}" for pr in contract.providers if pr.transfer_safeguard),
        high_risk=high_risk,
        dpia=high_risk,
        contrato_id=contract.id,
        contrato_huella=contract.fingerprint(),
    )


class EipdRiskProposal(BaseModel):
    description: str
    probability: int = Field(ge=1, le=3)
    impact: int = Field(ge=1, le=3)

    @property
    def level(self) -> str:  # R-131
        v = self.probability * self.impact
        return "alto" if v >= 6 else "medio" if v >= 4 else "bajo"


def asset_to_eipd_risks(asset: AgentAsset) -> list[EipdRiskProposal]:
    """Traduce los factores de riesgo del activo a riesgos de la matriz EIPD."""
    out = []
    for f in (asset.risk.factors if asset.risk else []):
        if f.points <= 0:
            continue
        impact = 3 if f.name in {"datos sensibles", "acciones sin supervisión humana", "ejecución de código"} else 2
        prob = 3 if f.points >= 20 else 2 if f.points >= 10 else 1
        out.append(EipdRiskProposal(description=f"[{asset.name}] {f.reason}", probability=prob, impact=impact))
    return out


def event(tipo: str, tenant_id: int, datos: dict[str, Any], actor: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sobre común de eventos de Pharus (arquitectura §7.2). `datos` nunca lleva PII."""
    return {
        "id": str(uuid.uuid4()),
        "tipo": tipo,
        "version": 1,
        "tenant_id": tenant_id,
        "ocurrido_en": datetime.now(timezone.utc).isoformat(),
        "actor": actor or {"usuario_id": None, "membresia_id": None},
        "correlacion_id": str(uuid.uuid4()),
        "datos": datos,
    }


def events_for_asset(asset: AgentAsset, tenant_id: int) -> list[dict[str, Any]]:
    evs = [
        event(
            "gobernanza_ia.activo.descubierto",
            tenant_id,
            {
                "activo_id": asset.id,
                "tipo": asset.kind.value,
                "framework": asset.framework.value,
                "nivel": asset.risk.tier.value if asset.risk else None,
                "puntaje": asset.risk.score if asset.risk else None,
                "shadow": asset.shadow,
                "categorias": sorted(c.value for c in asset.data_categories),
            },
        )
    ]
    for f in asset.findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            evs.append(
                event(
                    "gobernanza_ia.hallazgo.detectado",
                    tenant_id,
                    {"activo_id": asset.id, "codigo": f.code, "severidad": f.severity.value},
                )
            )
    if asset.risk and asset.risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL):
        evs.append(event("gobernanza_ia.eipd.sugerida", tenant_id, {"activo_id": asset.id, "puntaje": asset.risk.score}))
    return evs
