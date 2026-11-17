"""Asistente de agendamiento de la Clínica Aurora (gobernado por contrato)."""
from pydantic_ai import Agent, RunContext

from gobernanza_ia.contracts import ContractEnforcer
from gobernanza_ia.contracts.pydantic_ai_guard import PrivacyGuard

owner = "equipo-atencion@clinica-aurora.demo"

agenda_agent = Agent(
    "openai:gpt-5.2",
    name="Asistente de agendamiento",
    instructions="Agenda horas médicas. Nunca pidas el diagnóstico.",
)


@agenda_agent.tool
def buscar_horas(ctx: RunContext[None], especialidad: str) -> str:
    """Busca horas libres por especialidad."""
    return "Lunes 10:00, Martes 12:30"


@agenda_agent.tool(requires_approval=True)
def reservar_hora(ctx: RunContext[None], paciente_email: str, hora: str) -> str:
    """Reserva una hora para el paciente (requiere aprobación)."""
    return "reservada"
