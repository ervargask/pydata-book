"""Emisión de pasaportes de agente a partir del inventario.

Genera (1) un `AgentPassport` Pydantic que Pharus guarda y versiona, y (2) su
equivalente en ArgorixLang (`passport` + `policy`) para que el agente pueda
compilarse y ejecutarse bajo el runtime gobernado de Argorix.
"""

from __future__ import annotations

import re
from datetime import date

from pydantic import BaseModel, Field

from gobernanza_ia.scanner.models import AgentAsset, RiskTier


class AgentPassport(BaseModel):
    agent: str
    agent_name: str
    global_id: str
    identity: str
    provider: str
    version: str = "1.0.0"
    country: str = "CL"
    jurisdiction: str = "CL"
    data_residency: list[str] = Field(default_factory=lambda: ["CL"])
    model: str
    risk_level: str
    data_scope: list[str]
    intent: str
    intended_use: list[str]
    prohibited_use: list[str]
    attestations: list[str]
    issued: date = Field(default_factory=date.today)


def _ident(name: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", name)
    s = "".join(p[:1].upper() + p[1:] for p in parts if p)
    return s if s and s[0].isalpha() else f"Agent{s}"


def passport_from_asset(asset: AgentAsset, *, owner: str = "Empresa", intent: str = "por-definir") -> AgentPassport:
    ident = _ident(asset.name)
    tier = asset.risk.tier if asset.risk else RiskTier.LIMITED
    risk_level = {RiskTier.MINIMAL: "low", RiskTier.LIMITED: "medium", RiskTier.HIGH: "high", RiskTier.CRITICAL: "high"}[tier]
    model = asset.models[0] if asset.models else None
    residency = ["CL"] + (["US"] if any(m.is_external for m in asset.models) else [])
    prohibited = ["credential-access", "profiling-without-consent"]
    if not asset.human_in_loop:
        prohibited.append("automated-decision-without-review")
    return AgentPassport(
        agent=ident,
        agent_name=asset.name,
        global_id=f"pharus:agent:{asset.id}",
        identity=f"did:argorix:{asset.id}",
        provider=asset.owner or owner,
        data_residency=residency,
        model=f"{model.provider}:{model.model}" if model and model.model else (model.provider if model else "unknown"),
        risk_level=risk_level,
        data_scope=sorted(c.value for c in asset.data_categories) or ["internal"],
        intent=intent,
        intended_use=[intent],
        prohibited_use=prohibited,
        attestations=["pharus-scan", "evidence-bundle"] + (["privacy-contract"] if asset.has_privacy_contract else []),
    )


def _q(v: str) -> str:
    return '"' + v.replace('"', "'") + '"'


def _ql(vs: list[str]) -> str:
    return "[" + ", ".join(_q(v) for v in vs) + "]"


def to_argorix(p: AgentPassport) -> str:
    """Serializa el pasaporte y una política de gobernanza en sintaxis ArgorixLang."""
    return f"""module passports.{p.agent.lower()}

passport {p.agent}Passport {{
    agent {p.agent}
    agent_name {_q(p.agent_name)}

    global_id {_q(p.global_id)}
    identity {_q(p.identity)}
    provider {_q(p.provider)}
    version {_q(p.version)}

    country {_q(p.country)}
    jurisdiction {_q(p.jurisdiction)}
    data_residency {_ql(p.data_residency)}

    model {_q(p.model)}
    risk_level {_q(p.risk_level)}
    data_scope {_ql(p.data_scope)}

    intent {_q(p.intent)}
    intended_use {_ql(p.intended_use)}
    prohibited_use {_ql(p.prohibited_use)}

    attestations {_ql(p.attestations)}
}}

policy {p.agent}Governance {{
    require agent_passport_declared
    require agent_identity_declared
    require agent_data_residency_declared
    require agent_passport_attested

    on violation {{
        action {"block" if p.risk_level == "high" else "review"}
        trace required
    }}
}}
"""
