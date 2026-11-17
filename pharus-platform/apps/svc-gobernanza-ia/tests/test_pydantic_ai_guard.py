"""El guard se prueba con un agente Pydantic AI real y un FunctionModel que
registra exactamente lo que el «proveedor» recibe."""
import pytest
from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart, ToolReturnPart, UserPromptPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from gobernanza_ia.contracts import ContractEnforcer, PrivacyViolation
from gobernanza_ia.contracts.pydantic_ai_guard import PrivacyGuard
from gobernanza_ia.demo import contrato_agendamiento
from gobernanza_ia.governance.ledger import EvidenceLedger


def make_agent(enf, script):
    seen: list[str] = []

    def model_fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        for m in messages:
            for p in getattr(m, "parts", []):
                if isinstance(p, (UserPromptPart, ToolReturnPart)):
                    seen.append(str(p.content))
        return script(messages)

    agent = Agent(FunctionModel(model_fn), name="agenda", capabilities=[PrivacyGuard(enf)])
    calls = []

    @agent.tool
    def buscar_horas(ctx: RunContext[None], especialidad: str) -> str:
        calls.append(("buscar_horas", especialidad))
        return "Lunes 10:00 (contacto de la recepción: recepcion@aurora.cl)"

    @agent.tool
    def borrar_ficha(ctx: RunContext[None], rut: str) -> str:
        calls.append(("borrar_ficha", rut))
        return "borrada"

    return agent, seen, calls


def _n_responses(messages):
    return sum(isinstance(m, ModelResponse) for m in messages)


def test_redacta_pii_antes_del_modelo():
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento", ledger=EvidenceLedger())

    def script(messages):
        if _n_responses(messages) == 0:
            return ModelResponse(parts=[ToolCallPart("buscar_horas", {"especialidad": "cardiología"})])
        return ModelResponse(parts=[TextPart("Hay hora el lunes a las 10:00")])

    agent, seen, calls = make_agent(enf, script)
    r = agent.run_sync("Soy Juana, RUT 12.345.678-5, mi correo es juana@correo.cl. Quiero hora en cardiología")
    joined = " ".join(seen)
    assert "12.345.678-5" not in joined and "juana@correo.cl" not in joined
    assert "<NATIONAL_ID_" in joined and "<CONTACT_" in joined
    assert "recepcion@aurora.cl" not in joined  # el resultado de la tool también se redacta
    assert calls == [("buscar_horas", "cardiología")]
    assert r.output == "Hay hora el lunes a las 10:00"
    assert enf.ledger.verify()[0]


def test_herramienta_no_declarada_bloqueada():
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento")

    def script(messages):
        if _n_responses(messages) == 0:
            return ModelResponse(parts=[ToolCallPart("borrar_ficha", {"rut": "1-9"})])
        last = messages[-1].parts[0]
        return ModelResponse(parts=[TextPart(f"no pude: {last.content}")])

    agent, seen, calls = make_agent(enf, script)
    r = agent.run_sync("borra mi ficha")
    assert calls == []
    assert "contrato de privacidad" in r.output


class FakeOpenAI(FunctionModel):
    """FunctionModel que se presenta como proveedor «openai» (sin red)."""

    @property
    def system(self) -> str:
        return "openai"


def test_proveedor_no_declarado_falla_cerrado():
    contrato = contrato_agendamiento()
    contrato.providers = [p for p in contrato.providers if p.provider != "openai"]
    enf = ContractEnforcer(contrato, "agendamiento")
    called = []

    def fn(messages, info):
        called.append(1)
        return ModelResponse(parts=[TextPart("hola")])

    agent = Agent(FakeOpenAI(fn), name="x", capabilities=[PrivacyGuard(enf)])
    with pytest.raises(PrivacyViolation, match="openai"):
        agent.run_sync("hola")
    assert called == []  # el modelo nunca recibió la petición


def test_proveedor_declarado_permitido():
    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento")
    agent = Agent(FakeOpenAI(lambda m, i: ModelResponse(parts=[TextPart("ok")])), name="y", capabilities=[PrivacyGuard(enf)])
    assert agent.run_sync("hola").output == "ok"


def test_herramienta_review_queda_pendiente_de_aprobacion():
    from pydantic_ai import DeferredToolRequests, DeferredToolResults

    enf = ContractEnforcer(contrato_agendamiento(), "agendamiento", ledger=EvidenceLedger())
    reservas = []

    def script(messages):
        if _n_responses(messages) == 0:
            return ModelResponse(parts=[ToolCallPart("reservar_hora", {"hora": "lunes 10:00"}, tool_call_id="c1")])
        return ModelResponse(parts=[TextPart("Reserva confirmada")])

    agent = Agent(FakeOpenAI(lambda m, i: script(m)), name="z", output_type=[str, DeferredToolRequests],
                  capabilities=[PrivacyGuard(enf)])

    @agent.tool
    def reservar_hora(ctx: RunContext[None], hora: str) -> str:
        reservas.append(hora)
        return "ok"

    r1 = agent.run_sync("reserva el lunes")
    assert isinstance(r1.output, DeferredToolRequests) and r1.output.approvals[0].tool_name == "reservar_hora"
    assert reservas == []
    # El DPO / operador aprueba en Pharus (acción manual_verify) y se reanuda:
    r2 = agent.run_sync(message_history=r1.all_messages(), deferred_tool_results=DeferredToolResults(approvals={"c1": True}))
    assert reservas == ["lunes 10:00"] and r2.output == "Reserva confirmada"
