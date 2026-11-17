"""Datos de demostración: «Clínica Aurora Demo» (tenant del recorrido comercial)."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel

from gobernanza_ia.contracts import (
    PII,
    DataCategory,
    DataRule,
    Decision,
    LegalBasis,
    ModelProviderRule,
    PrivacyContract,
    Purpose,
    Redaction,
    ToolRule,
)


class Paciente(BaseModel):
    """Esquema que el asistente de agendamiento recibe del portal."""

    nombre: Annotated[str, PII(DataCategory.IDENTIFIER, subject="paciente")]
    rut: Annotated[str, PII(DataCategory.NATIONAL_ID, redaction=Redaction.TOKENIZE, subject="paciente")]
    email: Annotated[str, PII(DataCategory.CONTACT, subject="paciente")]
    especialidad: str
    motivo_consulta: Annotated[str | None, PII(DataCategory.HEALTH, subject="paciente")] = None


def contrato_agendamiento() -> PrivacyContract:
    return PrivacyContract(
        id="pc-aurora-agendamiento",
        version="1.2.0",
        controller="Clínica Aurora Demo SpA",
        description="Asistente de agendamiento de horas médicas",
        purposes=[
            Purpose(
                id="agendamiento",
                description="Agendar, confirmar y reprogramar horas médicas solicitadas por el paciente",
                legal_basis=LegalBasis.CONTRACT,
                retention_days=365,
                rat_ref="rat:aurora:agenda",
            ),
            Purpose(
                id="recordatorios",
                description="Enviar recordatorios de horas agendadas",
                legal_basis=LegalBasis.CONSENT,
                retention_days=30,
            ),
        ],
        data_rules=[
            DataRule(category=DataCategory.IDENTIFIER, purposes=["agendamiento", "recordatorios"], to_model=Redaction.MASK, in_output=False),
            DataRule(category=DataCategory.NATIONAL_ID, purposes=["agendamiento"], to_model=Redaction.TOKENIZE),
            DataRule(category=DataCategory.CONTACT, purposes=["agendamiento", "recordatorios"], to_model=Redaction.TOKENIZE),
            # salud: NO permitida para agendamiento → se retira antes del modelo
        ],
        tool_rules=[
            ToolRule(tool="buscar_horas", purposes=["agendamiento"]),
            ToolRule(tool="reservar_hora", purposes=["agendamiento"], decision=Decision.REVIEW, data_allowed=[DataCategory.CONTACT]),
            ToolRule(tool="enviar_recordatorio", purposes=["recordatorios"], data_allowed=[DataCategory.CONTACT]),
        ],
        providers=[
            ModelProviderRule(provider="openai", region="US", transfer_safeguard="DPA + cláusulas contractuales tipo (art. 28 Ley 21.719)"),
            ModelProviderRule(provider="google", region="CL", transfer_safeguard=None),
        ],
        data_residency=["CL"],
        prohibited_uses=["perfilamiento comercial", "decisiones clínicas automatizadas"],
    )
