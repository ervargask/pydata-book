# Especificación de la maqueta: módulo «Gobierno de IA»

> Para el equipo de diseño y desarrollo de Pharus Privacy NX. La maqueta (`apps/svc-gobernanza-ia/gobernanza_ia/web/index.html`)
> es **de referencia**: muestra pantallas, textos, estados y flujos. La implementación real va como
> microfrontend Angular (`mf-gobernanza-ia`) y microservicio (`svc-gobernanza-ia`) siguiendo
> `docs/arquitectura.md`. El código Python del demo es una **prueba de concepto local** del escáner y
> del contrato de privacidad, no código de producción.

## 0. Cómo ver la maqueta

```bash
cd pharus-platform/apps/svc-gobernanza-ia
pip install -e ".[dev]"
gobernanza-ia servir          # http://localhost:3130
```

Sin backend: abrir `gobernanza_ia/web/index.html` servido por cualquier servidor estático junto a
`demo-data.js` (snapshot generado con `python tools/exportar_demo.py`). Tenant de demo: **Clínica Aurora
Demo** (el mismo del recorrido comercial).

## 1. Encaje en el monorepo

| Pieza | Propuesta |
|---|---|
| Código de módulo | `gobernanza_ia`, **ID 41** en `tenancy.module`, sección nueva «Gobierno de IA» |
| Servicio | `svc-gobernanza-ia`, puerto **3130**, esquema `gobernanza_ia`, rol `pharus_gobernanza_ia`, RLS por `company_id` |
| Microfrontend | `mf-gobernanza-ia`, puerto **4230**, entrada destacada en el menú con la etiqueta «Nuevo» (como Webscan) |
| Worker | `worker-gobernanza-ia` (fase 2): ejecuta escaneos de fuentes con cola en BD (patrón de ciberseguridad) |
| Interruptores | `GOBERNANZA_IA_ENABLED`, `GOBERNANZA_IA_GUARD_ENABLED`; encendidos en desarrollo, apagados en producción |
| Lenguaje del escáner | El escáner AST de Python puede quedar en Python (imagen propia) o portarse a TS. El **SDK del contrato** sí es Python (Pydantic AI) y, en una fase posterior, TS (Vercel AI SDK) |

### Permisos (matriz de 10 acciones)

| Acción | Uso en el módulo |
|---|---|
| `view` | Ver inventario, contratos, trazas, cumplimiento |
| `create` | Registrar agente a mano, conectar fuentes, crear contrato |
| `edit` | Asignar responsable, pausar agente, editar contrato en borrador |
| `delete` | Dar de baja un agente del inventario |
| `export` | Exportar AI-BOM (CycloneDX) e informe de cumplimiento |
| `view_pii` | Ver valores reales tras un token en trazas o aprobaciones (siempre auditado) |
| `manual_verify` | **Aprobar o rechazar** acciones de agentes en la bandeja (sin bypass de admin, como la revisión del portal ARSOP) |
| `approve` | Publicar versiones de contrato y emitir pasaportes |
| `use_ai` | Usar el asistente que sugiere contratos desde el RAT |

## 2. Pantallas

Cada botón lleva `ppAyuda` (qué hace y qué norma lo exige). La maqueta tiene el texto de cada ayuda
en el atributo `data-ayuda`.

### 2.1 Centro de control IA (`/gobierno-ia`)
- 5 KPIs: activos de IA, shadow AI, críticos+altos, % de cumplimiento, acciones esperando aprobación.
- Barras por nivel de riesgo y **madurez agéntica AT0–AT4** (modelo de OWASP), marcando dónde está el cliente.
- **Plazos que importan**: Ley 21.719 (01-12-2026), EU AI Act art. 50, Anexo III aplazado, proyecto de ley de IA en Chile. Reutilizar `pp-plazo`.
- «Atender primero»: hallazgos críticos y altos con acceso a la ficha.
- **PROA aplicado a la IA**: % por dimensión P, R, O, A (derivado de los controles GIA).
- Proveedores de modelos que reciben datos de la empresa.

### 2.2 Inventario de agentes (AI-BOM)
- Tabla: activo (+ chip Shadow), tipo/framework, modelo, categorías de datos (sensibles en rojo), **autonomía N1–N4**, puntaje y nivel.
- Filtros: texto, nivel, tipo, «solo shadow AI».
- Ficha lateral con 5 pestañas:
  - **Resumen**: identidad DID, ubicación, responsable (asignar), modelos, datos, autonomía, secretos (solo nombres), contrato, clase EU AI Act, hallazgos con recomendación.
  - **Riesgo**: puntaje explicable (cada factor con puntos y razón) y riesgos propuestos para la EIPD (probabilidad × impacto, R-130/R-131).
  - **Herramientas**: efectos (red, correo, pagos, BD, ejecuta código), **zona de acción** y si falta aprobación.
  - **Pasaporte**: `.argx` de ArgorixLang, emitir y copiar.
  - **Vínculos**: RAT (proponer tratamiento), EIPD (iniciar con riesgos prellenados), Incidentes (crear desde hallazgo), Evidencias.

### 2.3 Descubrimiento
Tarjetas de fuente con estado: repositorios (funciona en el demo), configuraciones MCP, pasaportes
Argorix, Google Cloud / Vertex (reutiliza el conector GCP), consentimientos OAuth (Workspace / M365),
tráfico hacia proveedores de IA (solo metadatos). Cada fuente es un plugin con el contrato de los
motores de ciberseguridad.

### 2.4 Contratos de privacidad
- Vista del contrato: finalidades con base de licitud (valores de `rat_treatment.legal_basis`) y retención; reglas por categoría de datos (cómo viaja al modelo: tal cual, enmascarar, huella, tokenizar, retirar; si puede salir en la respuesta); herramientas por finalidad; proveedores y transferencias con su garantía; huella SHA-256 y versión.
- **Simulador**: finalidad + herramienta + mensaje → «lo que escribió la persona» vs «lo que recibe el modelo», con decisiones (ALLOW, REDACT, REVIEW, DENY) y código de regla. Incluye aislamiento de instrucciones inyectadas.
- Bloque de código Pydantic / Pydantic AI que muestra cómo lo usa el equipo del cliente.
- Acciones: crear borrador en el RAT y publicar versión (requiere `approve`).

### 2.5 Guardrails y trazas
- Ejecuciones (AgentRun) con id, estado, zona, entrada resumida sin PII y pasos: guardrail de entrada, herramientas, aprobaciones, guardrail de salida. Cada paso con decisión y el riesgo OWASP ASI que mitiga.
- Explicación de las 4 zonas con ejemplos reales del inventario.
- **Pausar agente** (kill switch global, auditado).

### 2.6 Bandeja de aprobaciones
Tarjetas por acción pendiente: agente, herramienta, zona, argumentos **ya protegidos**, motivo y
antigüedad. Aprobar, rechazar o pedir contexto. Al aprobar, Pydantic AI recibe `DeferredToolResults`
y el agente continúa (probado en `tests/test_pydantic_ai_guard.py`).

### 2.7 Cumplimiento
Controles **GIA-01…GIA-07** calculados desde el inventario, con marcos (Ley 21.719, 21.663, EU AI Act,
ISO/IEC 42001, NIST AI RMF, GDPR, ArgorixLang), estado y % de cobertura; tabla OWASP ASI01–ASI10 →
mitigación en Pharus → estado. Botón «Generar informe» → evidencia.

### 2.8 Evidencia
Cadena encadenada por hash (`GENESIS` → … → head) con tipo, sujeto, decisión y detalle sin PII.
«Verificar cadena» y «Simular manipulación» (solo demo) para mostrar que un cambio se detecta.

## 3. Historias de usuario (MoSCoW)

| # | Historia | Prioridad | Criterio de aceptación (resumen) |
|---|---|---|---|
| GIA-HU-01 | Como **DPO**, quiero ver todos los agentes de IA de la empresa en un inventario para saber qué tratamientos automatizados existen | Must | Dado un repo con agentes LangGraph, CrewAI y MCP, cuando se escanea, entonces cada uno aparece con modelo, herramientas, datos y riesgo; el ID es estable entre escaneos |
| GIA-HU-02 | Como DPO, quiero que los agentes sin responsable ni contrato se marquen como **shadow AI** | Must | Un agente sin pasaporte, contrato ni responsable muestra el chip «Shadow» y el hallazgo PH-IA-003 |
| GIA-HU-03 | Como DPO, quiero un **puntaje de riesgo explicable** para justificar ante la Agencia | Must | Cada factor muestra puntos y razón; la suma es el puntaje (0–100) |
| GIA-HU-04 | Como DPO, quiero que un agente de alto riesgo **proponga una EIPD** con riesgos prellenados | Must | Botón «Iniciar EIPD» crea la EIPD vinculada; solo quien tiene `approve` la cierra (R-132) |
| GIA-HU-05 | Como **desarrollador del cliente**, quiero declarar un **contrato de privacidad** en Pydantic y aplicarlo a mi agente Pydantic AI con una línea | Must | `capabilities=[PrivacyGuard(...)]`; el RUT llega tokenizado al modelo y la salud no llega |
| GIA-HU-06 | Como DPO, quiero que las acciones con efectos esperen una **aprobación humana** | Must | Herramienta con regla REVIEW queda en la bandeja; no se ejecuta hasta aprobar; el aprobador queda en la evidencia |
| GIA-HU-07 | Como DPO, quiero **crear el borrador del RAT** desde el contrato | Should | El borrador tiene finalidad, base, categorías, transferencias e instrumento; estado `draft` |
| GIA-HU-08 | Como **auditor**, quiero una **cadena de evidencia** verificable | Should | Alterar una entrada hace fallar la verificación e indica cuál |
| GIA-HU-09 | Como CISO, quiero ver **servidores MCP** y secretos escritos en configuraciones | Should | Detecta servidores, herramientas y `env` literal (PH-IA-011) |
| GIA-HU-10 | Como CISO, quiero **pausar** un agente al instante | Should | Kill switch auditado; las ejecuciones siguientes quedan bloqueadas |
| GIA-HU-11 | Como DPO, quiero ver **cumplimiento** por marco y por dimensión PROA | Should | Controles GIA con cobertura y activos con brecha |
| GIA-HU-12 | Como responsable de un agente, quiero **emitir su pasaporte** | Could | Pasaporte `.argx` con identidad, finalidad, residencia, usos prohibidos y política |
| GIA-HU-13 | Como CISO, quiero descubrir IA por **OAuth y tráfico** | Could | Fuentes conectadas, solo metadatos |
| GIA-HU-14 | Como auditor, quiero exportar el **AI-BOM** en CycloneDX | Could | Archivo válido CycloneDX 1.6 ML-BOM |
| GIA-HU-15 | Deshacer acciones de agentes (rollback) | Won't (por ahora) | Requiere integración con cada sistema de destino |

## 4. Contratos de datos (resumen)

Ver los modelos Pydantic en `gobernanza_ia/scanner/models.py` y `gobernanza_ia/contracts/contract.py`.
Se recomienda generar `libs/contratos/src/gobernanza-ia.ts` desde el JSON Schema de esos modelos.

| Rutas (detrás del gateway) | Descripción |
|---|---|
| `GET /api/gobernanza-ia/resumen` | KPIs del Centro de control |
| `POST /api/gobernanza-ia/escaneos` | Nuevo escaneo |
| `GET /api/gobernanza-ia/activos[/:id]` | Inventario y ficha (eventos, riesgos EIPD) |
| `GET /api/gobernanza-ia/activos/:id/pasaporte[.argx]` | Pasaporte |
| `GET/POST /api/gobernanza-ia/contratos` | Contratos |
| `GET /api/gobernanza-ia/contratos/:id/esquema` | Revisión estática del esquema |
| `POST /api/gobernanza-ia/contratos/:id/probar` | Simulador |
| `GET /api/gobernanza-ia/contratos/:id/rat?finalidad=` | Borrador para svc-rat |
| `GET /api/gobernanza-ia/marcos` | Controles GIA |
| `GET /api/gobernanza-ia/evidencias` | Paquete de evidencia |

### Eventos (sin PII, sobre común de `arquitectura.md` §7.2)

| Evento | Consumidores |
|---|---|
| `gobernanza_ia.activo.descubierto` | inicio (conteos), auditoría |
| `gobernanza_ia.hallazgo.detectado` (crítico/alto) | incidentes (**propuesta**, nunca automático) |
| `gobernanza_ia.eipd.sugerida` | eipd |
| `gobernanza_ia.contrato.publicado` | rat (proyección «tiene contrato») |
| `gobernanza_ia.accion.pendiente_aprobacion` | notificaciones |

### Reglas propuestas (R-GIA)

| Regla | Contenido |
|---|---|
| R-GIA-01 | El escáner nunca lee ni guarda valores de secretos ni de datos personales: solo nombres y ubicaciones |
| R-GIA-02 | Contrato *fail-closed*: herramienta, proveedor o finalidad no declarados → DENY |
| R-GIA-03 | Dato sensible solo con base `consent`, `legal_obligation`, `vital_interest`, `public_interest` o `legal_claims` (Ley 21.719 art. 16) |
| R-GIA-04 | Proveedor fuera de la residencia declarada exige garantía de transferencia |
| R-GIA-05 | Aprobar acciones exige `manual_verify` en el módulo, sin bypass de admin |
| R-GIA-06 | La evidencia es *append-only* y encadenada; la verificación indica la primera entrada inválida |
| R-GIA-07 | Un hallazgo crítico genera una **propuesta** de incidente; crearlo exige «Crear» en Incidentes |
| R-GIA-08 | El borrador de RAT nunca cambia el estado de un tratamiento existente |

## 5. Hallazgos del escáner

| Código | Severidad | Hallazgo |
|---|---|---|
| PH-IA-001 | Alta | Datos personales hacia un modelo externo sin contrato |
| PH-IA-002 | Alta | Herramientas con efectos sin aprobación humana |
| PH-IA-003 | Media | Agente sin registrar (shadow AI) |
| PH-IA-010 | Crítica | Credencial de proveedor de IA en el código |
| PH-IA-011 | Alta | Secreto literal en configuración MCP |
| PH-PC-0xx | — | Decisiones del contrato (esquema, datos, proveedor, herramientas, salida) |

## 6. Lo que la maqueta simula y el demo no hace

- Descubrimiento por GCP, OAuth y tráfico; exportación CycloneDX; informe PDF; emisión firmada del pasaporte; trazas y aprobaciones de producción (son datos de ejemplo); deshacer.
- El simulador del navegador es un port simplificado del `ContractEnforcer` (detecta salud por palabras clave); el servidor usa el enforcer real.
