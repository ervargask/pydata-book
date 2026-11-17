"""Puntaje de riesgo de un activo de IA (0-100) y clasificación orientativa.

El puntaje es explicable: cada factor suma puntos con una razón legible, para
que el DPO pueda justificar la decisión ante la Agencia (APDP) o un auditor.
La clase EU AI Act es orientativa (no es asesoría legal).
"""

from __future__ import annotations

from gobernanza_ia.governance.taxonomy import SENSITIVE_CATEGORIES, DataCategory
from gobernanza_ia.scanner.models import (
    AgentAsset,
    AssetKind,
    Finding,
    RiskAssessment,
    RiskFactor,
    RiskTier,
    Severity,
    SideEffect,
)

# Dominios del Anexo III del EU AI Act detectables por categorías de datos.
ANNEX_III_HINTS: dict[DataCategory, str] = {
    DataCategory.EMPLOYMENT: "Alto riesgo (Anexo III §4: empleo y selección de personal)",
    DataCategory.BIOMETRIC: "Alto riesgo (Anexo III §1: biometría)",
    DataCategory.MINORS: "Alto riesgo probable (educación / menores, Anexo III §3)",
}


def assess(asset: AgentAsset) -> tuple[RiskAssessment, list[Finding]]:
    f: list[RiskFactor] = []
    findings: list[Finding] = []
    fx = {e for t in asset.tools for e in t.side_effects}
    sensitive = asset.data_categories & SENSITIVE_CATEGORIES
    external = [m for m in asset.models if m.is_external]

    if asset.kind in (AssetKind.AGENT, AssetKind.MCP_SERVER):
        f.append(RiskFactor(name="autonomía", points=10, reason="Ejecuta un loop con herramientas (decide acciones)."))

    if sensitive:
        f.append(RiskFactor(name="datos sensibles", points=25, reason=f"Trata datos sensibles: {', '.join(sorted(c.value for c in sensitive))}."))
    elif asset.data_categories - {DataCategory.CREDENTIALS}:
        f.append(RiskFactor(name="datos personales", points=10, reason="Trata datos personales."))

    if external and (asset.data_categories - {DataCategory.CREDENTIALS}) and not asset.has_privacy_contract:
        f.append(RiskFactor(name="transferencia internacional", points=15, reason=f"Envía datos personales a proveedores externos ({', '.join(sorted({m.provider for m in external}))}) sin contrato de privacidad."))
        findings.append(
            Finding(
                code="PH-IA-001",
                title="Datos personales hacia un modelo externo sin contrato de privacidad",
                severity=Severity.HIGH,
                location=asset.location,
                recommendation="Declarar un PrivacyContract (finalidad, base de licitud, redacción para modelo) y verificar las garantías de transferencia (Ley 21.719 Título VII / GDPR cap. V).",
            )
        )

    risky_fx = fx & {SideEffect.CODE_EXEC, SideEffect.PAYMENT, SideEffect.EMAIL, SideEffect.DATABASE}
    if risky_fx and not asset.human_in_loop:
        f.append(RiskFactor(name="acciones sin supervisión humana", points=20, reason=f"Herramientas con efectos ({', '.join(sorted(e.value for e in risky_fx))}) sin aprobación humana."))
        findings.append(
            Finding(
                code="PH-IA-002",
                title="Herramientas con efectos irreversibles sin aprobación humana",
                severity=Severity.HIGH,
                location=asset.location,
                recommendation="Marcar las herramientas con requires_approval=True o exigir ApprovalRequired desde el contrato (art. 8 bis Ley 21.719: decisiones automatizadas).",
            )
        )
    if SideEffect.CODE_EXEC in fx:
        f.append(RiskFactor(name="ejecución de código", points=15, reason="Puede ejecutar código o comandos del sistema."))

    if asset.hardcoded_secrets:
        f.append(RiskFactor(name="secretos expuestos", points=15, reason=f"{asset.hardcoded_secrets} credencial(es) en el código o la configuración."))

    if asset.shadow:
        f.append(RiskFactor(name="shadow AI", points=10, reason="Sin pasaporte, contrato ni responsable registrado."))
        findings.append(
            Finding(
                code="PH-IA-003",
                title="Agente sin registrar (shadow AI)",
                severity=Severity.MEDIUM,
                location=asset.location,
                recommendation="Asignar responsable, emitir pasaporte del agente y vincularlo a un tratamiento del RAT.",
            )
        )

    if asset.has_privacy_contract:
        f.append(RiskFactor(name="contrato de privacidad", points=-10, reason="Las entradas y salidas pasan por un contrato verificable."))
    if asset.has_passport:
        f.append(RiskFactor(name="pasaporte declarado", points=-5, reason="Identidad, finalidad y residencia declaradas (Argorix)."))

    score = max(0, min(100, sum(x.points for x in f)))
    tier = RiskTier.MINIMAL if score < 25 else RiskTier.LIMITED if score < 50 else RiskTier.HIGH if score < 75 else RiskTier.CRITICAL

    eu = "Riesgo limitado (art. 50: obligaciones de transparencia)" if asset.kind != AssetKind.MCP_SERVER else "Componente (herramientas de un sistema de IA)"
    for cat, label in ANNEX_III_HINTS.items():
        if cat in asset.data_categories:
            eu = label
            break
    ref = (asset.name + " " + asset.location.file).lower()
    if DataCategory.HEALTH in asset.data_categories and any(k in ref for k in ("triage", "urgencia", "emergenc")):
        eu = "Alto riesgo (Anexo III §5d: triaje de pacientes en urgencias)"
    if DataCategory.FINANCIAL in asset.data_categories and "credit" in (asset.name + asset.location.file).lower():
        eu = "Alto riesgo (Anexo III §5b: evaluación de solvencia)"

    return RiskAssessment(score=score, tier=tier, factors=f, eu_ai_act_class=eu), findings
