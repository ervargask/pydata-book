import pytest
from pydantic import ValidationError

from gobernanza_ia.contracts import (
    ContractEnforcer, DataCategory, DataRule, Decision, LegalBasis, ModelProviderRule,
    PrivacyContract, Purpose, find_pii,
)
from gobernanza_ia.demo import Paciente, contrato_agendamiento
from gobernanza_ia.governance.bridges import contract_to_rat
from gobernanza_ia.governance.ledger import EvidenceLedger

PACIENTE = Paciente(nombre="Juana Pérez", rut="12.345.678-5", email="juana@correo.cl",
                    especialidad="cardiología", motivo_consulta="dolor torácico")


def test_detecta_rut_valido_y_no_invalido():
    cats = [m.category for m in find_pii("RUT 12.345.678-5 y 12.345.678-9, mail a@b.cl, tarjeta 4111 1111 1111 1111")]
    assert cats.count(DataCategory.NATIONAL_ID) == 1
    assert DataCategory.CONTACT in cats and DataCategory.FINANCIAL in cats


def test_dato_sensible_exige_base_reforzada():
    with pytest.raises(ValidationError, match="art. 16"):
        PrivacyContract(
            id="x", controller="c",
            purposes=[Purpose(id="mk", description="marketing", legal_basis=LegalBasis.LEGITIMATE_INTEREST, retention_days=10)],
            data_rules=[DataRule(category=DataCategory.HEALTH, purposes=["mk"])],
        )


def test_transferencia_sin_garantia_rechazada():
    with pytest.raises(ValidationError, match="transferencia internacional"):
        PrivacyContract(
            id="x", controller="c",
            purposes=[Purpose(id="p", description="d", legal_basis=LegalBasis.CONTRACT, retention_days=1)],
            providers=[ModelProviderRule(provider="openai", region="US")],
        )


def test_check_schema_marca_salud_fuera_de_finalidad():
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento")
    res = enf.check_schema(Paciente)
    assert res.decision is Decision.DENY
    assert [v.path for v in res.violations] == ["motivo_consulta"]


def test_sanitize_redacta_tokeniza_y_retira():
    led = EvidenceLedger()
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento", ledger=led)
    res = enf.sanitize(PACIENTE)
    p = res.payload
    assert "motivo_consulta" not in p  # salud retirada
    assert p["nombre"] == "J**** P****"
    assert p["rut"].startswith("<NATIONAL_ID_") and p["email"].startswith("<CONTACT_")
    assert enf.detokenize(p["rut"]) == "12.345.678-5"
    assert p["especialidad"] == "cardiología"
    entry = led.entries[-1].model_dump_json()
    assert "juana" not in entry.lower() and "12.345" not in entry


def test_autorizacion_de_herramientas():
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento")
    assert enf.authorize_tool("buscar_horas", {"especialidad": "x"}).decision is Decision.ALLOW
    assert enf.authorize_tool("reservar_hora", {"paciente_email": "a@b.cl"}).decision is Decision.REVIEW
    assert enf.authorize_tool("borrar_ficha").decision is Decision.DENY  # no declarada
    assert enf.authorize_tool("enviar_recordatorio").decision is Decision.DENY  # otra finalidad
    assert enf.authorize_tool("buscar_horas", {"q": "12.345.678-5"}).decision is Decision.DENY  # RUT en args


def test_salida_no_expone_pii():
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento")
    res = enf.check_output("Listo, le escribiremos a juana@correo.cl")
    assert "juana@" not in res.payload and res.violations


def test_finalidad_no_declarada():
    with pytest.raises(ValueError):
        ContractEnforcer(contrato_agendamiento(), "marketing")


def test_puente_contrato_a_rat():
    d = contract_to_rat(contrato_agendamiento(), "agendamiento", high_risk=False, subjects=["Pacientes"])
    assert d.legal_basis == "contract" and d.status == "draft"
    assert d.transfers and d.transfer_countries == ["US"]
    assert "Identificación (RUT)" in d.data_categories
    assert d.retention_period == "365 días"


def test_ledger_detecta_manipulacion():
    led = EvidenceLedger()
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento", ledger=led)
    enf.authorize_tool("buscar_horas")
    enf.authorize_tool("borrar_ficha")
    assert led.verify() == (True, None)
    led._entries[0].decision = "ALLOW"  # alguien reescribe la historia
    led._entries[1].decision = "ALLOW"
    ok, bad = led.verify()
    assert not ok and bad == led.entries[1].id
