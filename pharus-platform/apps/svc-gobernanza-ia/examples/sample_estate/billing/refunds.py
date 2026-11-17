"""Agente de reembolsos (CrewAI) con acceso a pagos."""
from crewai import Agent
from crewai.tools import tool
import stripe

stripe.api_key = "sk-FAKEdemo00000000000000000000000000"  # ¡no hacer esto!


@tool("emitir_reembolso")
def emitir_reembolso(pago_id: str, monto: int) -> str:
    """Emite un reembolso con Stripe sobre el cobro de la tarjeta del paciente."""
    return str(stripe.Refund.create(payment_intent=pago_id, amount=monto))


reembolsos = Agent(
    role="Agente de reembolsos",
    goal="Resolver reclamos de cobro y emitir reembolsos",
    backstory="Revisa facturas, tarjeta y cuenta_bancaria del paciente",
    tools=[emitir_reembolso],
    llm="anthropic:claude-sonnet-4-6",
)
