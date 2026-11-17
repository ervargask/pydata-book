from conftest import ESTATE

from gobernanza_ia.governance.ledger import EvidenceLedger
from gobernanza_ia.scanner.engine import scan_path
from gobernanza_ia.scanner.models import AssetKind, Framework, RiskTier, SideEffect
from gobernanza_ia.scanner.passport import passport_from_asset, to_argorix


def _report():
    return scan_path(ESTATE, label="clinica-aurora")


def by_fw(r, fw):
    return [a for a in r.assets if a.framework is fw]


def test_descubre_todos_los_frameworks():
    r = _report()
    fws = {a.framework for a in r.assets}
    assert {Framework.PYDANTIC_AI, Framework.LANGGRAPH, Framework.CREWAI, Framework.ANTHROPIC_SDK,
            Framework.GOOGLE_GENAI, Framework.MCP_SERVER, Framework.ARGORIX} <= fws
    assert len(r.assets) == 9


def test_agente_pydantic_ai_gobernado_no_es_shadow():
    (a,) = by_fw(_report(), Framework.PYDANTIC_AI)
    assert a.name == "Asistente de agendamiento"
    assert a.models[0].provider == "openai" and a.models[0].model == "gpt-5.2"
    assert {t.name for t in a.tools} == {"buscar_horas", "reservar_hora"}
    assert next(t for t in a.tools if t.name == "reservar_hora").requires_approval
    assert a.has_privacy_contract and not a.shadow
    assert a.risk.tier in (RiskTier.MINIMAL, RiskTier.LIMITED)


def test_seleccion_de_personal_es_alto_riesgo_y_shadow():
    (a,) = by_fw(_report(), Framework.LANGGRAPH)
    assert a.shadow
    assert SideEffect.EMAIL in {e for t in a.tools for e in t.side_effects}
    assert "Anexo III §4" in a.risk.eu_ai_act_class
    assert a.risk.tier is RiskTier.CRITICAL
    codes = {f.code for f in a.findings}
    assert {"PH-IA-001", "PH-IA-002", "PH-IA-003"} <= codes
    assert "OPENAI_API_KEY" in a.secret_refs


def test_secreto_literal_y_pagos_sin_aprobacion():
    (a,) = by_fw(_report(), Framework.CREWAI)
    assert a.hardcoded_secrets == 1
    assert "PH-IA-010" in {f.code for f in a.findings}
    assert SideEffect.PAYMENT in a.tools[0].side_effects


def test_mcp_y_pasaporte_argorix():
    r = _report()
    mcp = {a.name: a for a in by_fw(r, Framework.MCP_SERVER)}
    assert set(mcp) == {"fichas-postgres", "filesystem", "busqueda-web"}
    assert mcp["fichas-postgres"].hardcoded_secrets == 1  # PGPASSWORD literal
    assert mcp["busqueda-web"].hardcoded_secrets == 0  # usa ${VAR}
    (arg,) = by_fw(r, Framework.ARGORIX)
    assert arg.kind is AssetKind.DECLARED_AGENT and arg.has_passport and not arg.shadow
    assert arg.declared["jurisdiction"] == "CL"


def test_triaje_clasificado_anexo_iii():
    (a,) = by_fw(_report(), Framework.ANTHROPIC_SDK)
    assert "triaje" in a.risk.eu_ai_act_class


def test_ids_estables_y_ledger_sin_pii():
    led = EvidenceLedger()
    r1 = scan_path(ESTATE, label="clinica-aurora", ledger=led)
    r2 = scan_path(ESTATE, label="clinica-aurora", ledger=led)
    assert [a.id for a in r1.assets] == [a.id for a in r2.assets]
    ok, _ = led.verify()
    assert ok and len(led.entries) == 2
    assert "aurora-2026" not in led.entries[0].model_dump_json()


def test_pasaporte_argorix_generado():
    (a,) = by_fw(_report(), Framework.LANGGRAPH)
    p = passport_from_asset(a, intent="seleccion-personal")
    src = to_argorix(p)
    assert "passport ScreeningAgentPassport" in src
    assert 'risk_level "high"' in src and "action block" in src
    assert '"automated-decision-without-review"' in src
