# Roadmap de Gobierno de IA (borrador para la sesión de roadmap)

> Punto de partida para la próxima sesión, donde se definirá el roadmap con las demandas concretas.
> Formato del product owner de Pharus: horizontes Now / Next / Later y prioridad MoSCoW.
> Encaja como **fase 8** de `plan-fases.md`.

## Now (antes y justo después del 01-12-2026, entrada en vigencia de la Ley 21.719)

| Entregable | Por qué ahora | Historias |
|---|---|---|
| Inventario de agentes (repos + MCP + pasaportes) con shadow AI y riesgo explicable | La Ley 21.719 exige el RAT; los agentes tratan datos y hoy no están en él | GIA-HU-01, 02, 03, 09 |
| Puente a RAT y EIPD (borrador de tratamiento, EIPD con riesgos prellenados) | Convierte el hallazgo en cumplimiento dentro de Pharus | GIA-HU-04, 07 |
| SDK del contrato de privacidad para Pydantic AI (beta, clientes piloto) | Diferenciador frente a Securiti: el control vive en el código del cliente | GIA-HU-05 |
| Cumplimiento GIA + evidencia encadenada | Lo que pide un auditor o la Agencia | GIA-HU-08, 11 |

## Next (primer semestre de 2027)

- Bandeja de aprobaciones y trazas con el guard en producción; pausa global del agente.
- Descubrimiento por Google Cloud / Vertex (reutiliza el conector GCP) y por consentimientos OAuth.
- Revisión mensual de autonomía con semáforo (de la base de Angelique: `/autonomy-check`).
- Guardrail de entrada contra inyección de instrucciones con evaluación adversarial (inspirada en la de ArgorixLang).
- Exportación AI-BOM (CycloneDX) e informe PDF.
- Aviso de transparencia del art. 50 del EU AI Act y de decisiones automatizadas (Ley 21.719) para el portal del cliente.

## Later (antes del 02-12-2027, Anexo III del EU AI Act)

- SDK del contrato para TypeScript (Vercel AI SDK) y proxy para proveedores sin SDK.
- Contratos A2A y MCP (ArgorixLang `a2a_bridge_contract`, `mcp_bridge_contract`), OWASP ASI07.
- Agente guardián independiente (*guardian agent*) que supervisa a los agentes del cliente.
- FRIA del EU AI Act sobre la EIPD existente y mapa al proyecto de ley de IA de Chile cuando se apruebe.
- Descubrimiento por tráfico (solo metadatos) y líneas base de comportamiento.
- Deshacer acciones de agentes donde el sistema de destino lo permita.

## Preguntas para la sesión de roadmap

1. ¿El escáner queda en Python (imagen propia) o se porta a TypeScript?
2. ¿El SDK del contrato se publica abierto (PyPI) para adopción, o solo para clientes?
3. ¿Qué cliente piloto (sector salud, como Clínica Aurora, o financiero)?
4. ¿Pasaportes en formato ArgorixLang desde el inicio o solo JSON?
5. ¿Precio: módulo aparte o incluido en el plan con PharusScan?
