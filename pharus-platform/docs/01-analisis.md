# Análisis: Pharus como plataforma E2E de datos, privacidad e IA

> Fecha: 17-11-2026. Fuentes: repositorio ArgorixLang (zip `argorixlang-main`), contexto del monorepo
> Pharus Privacy NX (`CONTEXTO.md`, `arquitectura.md`, `plan-fases.md`, `docs/original/*`), base de
> conocimiento de Angelique (rama `codex/cloud-migration-20261116` de `angelique-knowledge-base`),
> documentación de Pydantic / Pydantic AI y búsquedas públicas sobre gobierno y seguridad de IA (al final).
> Los sitios pharusprivacy.com y securiti.ai no fueron accesibles desde el entorno de trabajo; lo de
> Securiti proviene de búsquedas públicas.

## 1. Dónde está Pharus hoy

Pharus Privacy (Gobierna Tus Datos) es un SaaS multiempresa para cumplir las leyes 21.719, 21.663 y
19.628. El clon NX ya tiene: RAT, ARSOP, terceros, consentimientos, políticas, EIPD, evidencias,
incidentes, catálogo, PharusScan (webscan y Discovery), ciberseguridad, integraciones/API v1, conector
GCP e IA propia sobre Vertex (WizardAI, Pharus AI, S0).

**Lo que falta para ser «la única plataforma E2E de datos, privacidad e IA»:** Pharus gobierna *datos*
y *privacidad*, y usa IA, pero **no gobierna la IA de sus clientes**. Hoy un DPO no puede responder
con Pharus: ¿qué agentes de IA tenemos?, ¿qué datos personales mandan a qué modelo y a qué país?,
¿quién aprueba lo que hacen?, ¿cómo lo pruebo ante la Agencia?

## 2. Qué aporta ArgorixLang

ArgorixLang (Argorix Labs, Apache-2.0, Rust) es un lenguaje y runtime para comunicación entre agentes
bajo políticas, capacidades, evidencia y fronteras de proveedor. Piezas reutilizables como **concepto**
(no como dependencia) para Pharus:

| Concepto Argorix | Qué hace | Cómo lo usa Pharus |
|---|---|---|
| `passport` | Identidad del agente: DID, proveedor, jurisdicción, residencia de datos, riesgo, `data_scope`, usos permitidos y prohibidos, atestaciones | **Pasaporte del agente** en el inventario. Pharus lo genera desde el escaneo y lo exporta en `.argx` |
| `capability … requires approval` | Capacidades con nivel `safe`/`restricted` y aprobación | **Zonas de acción** y reglas de herramientas del contrato (ALLOW / REVIEW / DENY) |
| `policy { require … on violation { action review/block } }` | Políticas *fail-closed* | El **contrato de privacidad** es *fail-closed*: lo no declarado se bloquea |
| `trust_ledger` (append-only, `previous_hash`, `GENESIS`) | Cadena de evidencia | **Ledger de evidencia** encadenado por hash del módulo |
| `governance_profile` + `regulatory_mapping` | Controles → obligaciones → evidencia | **Mapa de cumplimiento** GIA-01…07 → Ley 21.719, EU AI Act, ISO 42001, NIST, OWASP |
| `mcp_bridge_contract`, `a2a_bridge_contract` | Contratos para MCP y agente-a-agente | Siguiente fase: contratos A2A/MCP (OWASP ASI07) |
| Evidencia verificable (`verify-evidence`) y evaluación adversarial | Prueba que la política se aplicó | Verificación de la cadena y campañas de prueba de guardrails |

Argorix declara honestamente sus límites (no es sandbox general ni certificación). Pharus debe hacer
lo mismo: lo que muestra es **orientativo**, no asesoría legal ni certificación.

## 3. Qué aporta Pydantic / Pydantic AI

- **Pydantic** permite marcar campos con metadatos (`Annotated[str, PII(...)]`) sin cambiar la
  validación. Con eso el contrato puede **revisar un esquema antes de ejecutar** (como `argorixc check`)
  y **redactar un objeto** campo a campo.
- **Pydantic AI** tiene *capabilities* con *hooks* de ciclo de vida: `before_model_request`,
  `before_tool_execute`, `after_tool_execute`, `after_run`, y excepciones `ToolFailed` y
  `ApprovalRequired`. Un `PrivacyGuard` se agrega a cualquier agente sin tocar sus herramientas.
  Es el punto de mediación que Argorix llama *host mediation*.

El demo local (`apps/svc-gobernanza-ia`) prueba ambos con un agente Pydantic AI real y un
`FunctionModel` que registra lo que el proveedor recibe: el RUT y el correo llegan tokenizados, el dato
de salud se retira, la herramienta no declarada se bloquea y la de zona ámbar queda pendiente de
aprobación hasta que una persona la aprueba.

## 4. Referencia de mercado: Securiti

Securiti (Data Command Center) es el referente de «datos + IA» en un solo producto. Según sus
materiales públicos y el producto Agent Commander (Veeam, sobre tecnología de Securiti):

- **Descubrimiento** de agentes, copilotos y LLM que tocan datos de producción, con un grafo de datos.
- **Guardrails en ejecución** que inspeccionan prompts, recuperaciones y respuestas (fuga de datos
  sensibles, inyección de instrucciones).
- **Controles en la capa de datos** (permisos, clasificación) además de los del agente.
- **Deshacer** errores de IA con reversiones precisas.
- Mapeo a OWASP Agentic Top 10 con controles empresariales.

**Dónde Pharus puede ganar** frente a Securiti en Chile y LatAm:

1. Ya es dueño del **RAT, la EIPD, ARSOP, incidentes y evidencias**: el agente no es un objeto suelto,
   queda vinculado al tratamiento, a su evaluación de impacto y a sus plazos legales.
2. Norma local de primera clase: Ley 21.719 (vigente el 01-12-2026), Ley 21.663, proyecto de ley de IA.
3. Contrato de privacidad **en el código del cliente** (Pydantic AI), no solo un proxy.
4. Metodología propia (**PROA**) como columna vertebral del producto.
5. Precio y operación para medianas empresas que no compran Securiti.

## 5. Base de conocimiento de Angelique: qué se reutiliza

| Fuente | Idea | Feature en la maqueta |
|---|---|---|
| `personas/product-owner-pharus.md` | «PHARUS es PROA hecho software»; el mejor feature quita trabajo manual al DPO; Now/Next/Later; MoSCoW | Roadmap en horizontes y priorización MoSCoW |
| PROA (`proa-implementation-guide`) | 4 dimensiones: **P**rotección, **R**egulación, **O**rganización, **A**cción | Tarjeta «PROA aplicado a la IA» en el Centro de control |
| `docs/autonomy-model.md` | Niveles N1–N4 (computador completo, contenedor, proyecto, flujo) y ciclo propuesta → vista previa → aprobación → ejecución → bitácora → evidencia | Columna **Autonomía** del inventario y **Bandeja de aprobaciones** |
| `docs/agent-architecture.md` | `ACTION_ZONES` y capa de guardrails + HITL | **Zonas de acción** verde/ámbar/roja/negra |
| `docs/agent-observability-and-evals.md` | AgentRun con `toolsPlanned`, `toolsExecuted`, `actionZone`, `guardrailResults`, sin PII | **Guardrails y trazas** |
| `docs/agent-tool-registry.md` | Herramientas externas bloqueadas por defecto | Contrato *fail-closed* |
| `/autonomy-check` mensual con semáforo | Revisión periódica | Informe mensual de autonomía (roadmap «Next») |

## 6. Novedades de gobierno y seguridad de IA que la maqueta incorpora

- **OWASP Top 10 for Agentic Applications** (dic-2025, ASI01–ASI10) y el informe *State of Agentic AI
  Security and Governance* v2.01 (jun-2026), cuyo modelo de madurez parte en **AT0 = shadow AI**. La
  guía pide inventariar cada agente y cada herramienta, seguir servidores MCP, mínimo privilegio y
  registrar llamadas a herramientas.
- **AI-BOM** (agentes, modelos, herramientas, MCP) como artefacto que piden los auditores.
- **Identidad del agente**: Gartner pide una identidad única por agente; el 92 % de CISOs encuestados no
  ve todas las identidades de sus agentes; NIST NCCoE prepara un proyecto de identidad y autorización
  de agentes. La CSA recomienda descubrimiento continuo con telemetría de consentimientos OAuth,
  inventario de identidades no humanas, tráfico MCP y líneas base de comportamiento.
- **Guardian agents** (Gartner, feb-2026): capas independientes que supervisan agentes.
- **Cadena de suministro MCP**: paquetes MCP maliciosos y CVE-2025-6514; con varios servidores MCP
  conectados, uno comprometido basta.
- **EU AI Act**: el Digital Omnibus (acuerdo de trílogo del 07-05-2026) aplaza el Anexo III al
  **02-12-2027** y el Anexo I al 02-08-2028; el **art. 50** (transparencia) rige desde agosto de 2026.
- **ISO/IEC 42001** es certificable (38 controles) pero anterior a los agentes con herramientas;
  necesita extensiones para sistemas multiagente.
- **Chile**: Ley 21.719 vigente el **01-12-2026**; el proyecto de ley de IA fue aprobado en general por
  la Comisión de Desafíos del Futuro del Senado el 26-10-2026 y sigue en segundo trámite.

## Fuentes

- OWASP Top 10 for Agentic Applications — https://cycode.com/blog/owasp-top-10-agentic-applications/
- CSA, OWASP agentic governance maturity v2 — https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/07/CSA_research_note_owasp_agentic_ai_governance_maturity_v2_20260703-csa-styled.pdf
- CSA, Shadow AI agent detection — https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_shadow_ai_agent_detection_governance_20260529-csa-styled.pdf
- O'Reilly, Shadow agents — https://www.oreilly.com/radar/shadow-agents-standing-privileges-and-the-governance-gap-between-deployment-and-discovery/
- Invicti, Agentic AI security risks — https://www.invicti.com/blog/web-security/agentic-ai-security-risks-governance-enterprise
- CSA, AI agent governance gap — https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/
- NIST e ISO sobre identidad de agentes — https://nhimg.org/nhi-news/nist-iso-ai-agent-identity-governance-frameworks
- Gartner guardian agents (resumen) — https://thehackernews.com/2026/03/5-learnings-from-first-ever-gartner.html
- Securiti, Agent Commander — https://securiti.ai/solution-brief/agent-commander/
- Securiti, OWASP Top 10 con controles empresariales — https://securiti.ai/infographics/agentic-ai-security-owasp-top-10-enterprise-controls/
- Veeam, Introducing Agent Commander — https://www.veeam.com/blog/veeam-introduces-agent-commander-detect-protect-undo-ai-data-risks.html
- Digital Omnibus y EU AI Act — https://www.winstontaylor.com/insights/ai-act-rules-on-high-risk-ai-delayed-as-ai-digital-omnibus-agreed
- Cooley, Digital AI Omnibus — https://cdp.cooley.com/digital-ai-omnibus-delays-key-deadlines-introduces-new-rules/
- Proyecto de ley de IA en Chile — https://www.diarioconstitucional.cl/opinion/ley-de-ia-en-chile-el-riesgo-de-llegar-tarde-a-regular-el-futuro
- Proyecto de ley de IA, tramitación — https://www.diarioconstitucional.cl/2026/02/23/proyecto-de-ley-que-regula-integralmente-la-inteligencia-artificial-en-chile-prosigue-su-tramitacion-en-el-senado
