"""Clasificador de urgencia: resume la ficha del paciente con Claude."""
import anthropic

client = anthropic.Anthropic()


def clasificar(ficha_paciente: str, diagnostico_previo: str) -> str:
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=300,
        messages=[{"role": "user", "content": f"Paciente: {ficha_paciente}\nDiagnóstico: {diagnostico_previo}"}],
    )
    return msg.content[0].text
