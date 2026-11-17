"""Mapa de controles de gobernanza de IA → marcos normativos.

Inspirado en `governance_profile` / `regulatory_mapping` de ArgorixLang: cada
control tiene un requisito, los marcos que lo exigen y una regla que calcula
su estado a partir del inventario. Orientativo; no constituye asesoría legal.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel

from gobernanza_ia.scanner.models import AgentAsset, RiskTier, SideEffect

Status = Literal["cumple", "parcial", "brecha", "no_aplica"]


class Control(BaseModel):
    id: str
    title: str
    requirement: str
    frameworks: dict[str, str]  # marco -> artículo/cláusula
    status: Status = "no_aplica"
    coverage: float = 0.0  # 0..1
    affected: list[str] = []  # ids de activos con brecha


def _ratio(assets: list[AgentAsset], ok: Callable[[AgentAsset], bool], scope: Callable[[AgentAsset], bool] = lambda a: True) -> tuple[float, list[str]]:
    sc = [a for a in assets if scope(a)]
    if not sc:
        return 1.0, []
    bad = [a.id for a in sc if not ok(a)]
    return 1 - len(bad) / len(sc), bad


CONTROLS: list[tuple[Control, Callable[[list[AgentAsset]], tuple[float, list[str]]]]] = [
    (
        Control(
            id="GIA-01",
            title="Inventario de sistemas y agentes de IA",
            requirement="Todo agente o integración con IA está inventariado, con responsable asignado.",
            frameworks={"ISO/IEC 42001": "A.4 / 6.1", "EU AI Act": "art. 49 (registro)", "NIST AI RMF": "MAP 1.6", "Ley 21.719": "art. 15 bis (RAT)"},
        ),
        lambda xs: _ratio(xs, lambda a: not a.shadow),
    ),
    (
        Control(
            id="GIA-02",
            title="Base de licitud y finalidad por agente",
            requirement="Los agentes que tratan datos personales operan bajo un contrato de privacidad con finalidad y base de licitud.",
            frameworks={"Ley 21.719": "arts. 3, 12, 13", "GDPR": "arts. 5, 6", "ISO/IEC 42001": "A.7"},
        ),
        lambda xs: _ratio(xs, lambda a: a.has_privacy_contract or a.has_passport, lambda a: bool(a.data_categories)),
    ),
    (
        Control(
            id="GIA-03",
            title="Supervisión humana de acciones con efectos",
            requirement="Herramientas que pagan, envían correos, escriben en BD o ejecutan código requieren aprobación humana.",
            frameworks={"EU AI Act": "art. 14", "Ley 21.719": "art. 8 bis (decisiones automatizadas)", "NIST AI RMF": "MANAGE 2.4"},
        ),
        lambda xs: _ratio(
            xs,
            lambda a: a.human_in_loop,
            lambda a: bool({e for t in a.tools for e in t.side_effects} & {SideEffect.PAYMENT, SideEffect.EMAIL, SideEffect.DATABASE, SideEffect.CODE_EXEC}),
        ),
    ),
    (
        Control(
            id="GIA-04",
            title="Transferencias internacionales a proveedores de modelos",
            requirement="Los datos personales enviados a modelos fuera de Chile tienen garantía de transferencia declarada.",
            frameworks={"Ley 21.719": "Título VII (arts. 27-28)", "GDPR": "cap. V"},
        ),
        lambda xs: _ratio(
            xs,
            lambda a: a.has_privacy_contract,
            lambda a: bool(a.data_categories) and any(m.is_external for m in a.models),
        ),
    ),
    (
        Control(
            id="GIA-05",
            title="Evaluación de impacto para agentes de alto riesgo",
            requirement="Los agentes de nivel alto o crítico tienen una EIPD / FRIA vigente.",
            frameworks={"Ley 21.719": "art. 15 ter (EIPD)", "EU AI Act": "art. 27 (FRIA)", "ISO/IEC 42001": "6.1.4"},
        ),
        lambda xs: _ratio(xs, lambda a: False, lambda a: bool(a.risk and a.risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL))),
    ),
    (
        Control(
            id="GIA-06",
            title="Gestión de secretos de IA",
            requirement="Ninguna credencial de proveedor de IA está escrita en el código o la configuración.",
            frameworks={"Ley 21.663": "art. 8 (medidas de seguridad)", "ISO/IEC 27001": "A.8.24", "NIST AI RMF": "MANAGE 4.1"},
        ),
        lambda xs: _ratio(xs, lambda a: a.hardcoded_secrets == 0),
    ),
    (
        Control(
            id="GIA-07",
            title="Identidad verificable del agente",
            requirement="Cada agente tiene pasaporte (identidad, finalidad, residencia de datos, usos prohibidos).",
            frameworks={"ArgorixLang": "passport / atrust_identity", "EU AI Act": "art. 13 (transparencia)", "ISO/IEC 42001": "A.6.2"},
        ),
        lambda xs: _ratio(xs, lambda a: a.has_passport, lambda a: a.kind.value in ("agent", "declared_agent")),
    ),
]


def evaluate(assets: list[AgentAsset]) -> list[Control]:
    out = []
    for ctrl, fn in CONTROLS:
        cov, bad = fn(assets)
        c = ctrl.model_copy()
        c.coverage = round(cov, 2)
        c.affected = bad
        c.status = "cumple" if cov >= 0.999 else "parcial" if cov >= 0.5 else "brecha"
        out.append(c)
    return out
