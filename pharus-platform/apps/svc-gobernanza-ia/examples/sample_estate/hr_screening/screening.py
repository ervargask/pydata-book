"""Preselección automática de candidatos (sin registrar en Pharus)."""
import os
import smtplib

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

llm = ChatOpenAI(model="gpt-4o", api_key=os.environ["OPENAI_API_KEY"])


@tool
def leer_curriculum(candidato_id: str) -> str:
    """Lee el CV (resume) del candidato con su RUT, email y salud declarada."""
    return open(f"/cvs/{candidato_id}.txt").read()


@tool
def enviar_rechazo(candidato_email: str) -> str:
    """Envía el correo de rechazo al candidato."""
    with smtplib.SMTP("smtp.clinica-aurora.demo") as s:
        s.sendmail("rrhh@clinica-aurora.demo", candidato_email, "Gracias por postular")
    return "ok"


screening_agent = create_react_agent(llm, tools=[leer_curriculum, enviar_rechazo])
