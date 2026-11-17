# Pharus · Gobierno de IA (maqueta y demo local)

Maqueta del módulo **Gobierno de IA** de Pharus Privacy para que el equipo de diseño y desarrollo la
lleve al monorepo NX. Pharus pasa de gobernar datos y privacidad a gobernar también **la IA de sus
clientes**: inventario de agentes, contratos de privacidad ejecutables, aprobaciones humanas,
cumplimiento y evidencia.

Esto **no es código de producción**. Es una referencia visual y funcional que corre en local.

## Qué hay

| Ruta | Contenido |
|---|---|
| `docs/01-analisis.md` | Análisis: ArgorixLang, Pydantic/Pydantic AI, Securiti, base de conocimiento de Angelique y novedades de gobierno y seguridad de IA (con fuentes) |
| `docs/02-especificacion-maqueta.md` | **Para desarrollo**: pantallas, permisos, historias de usuario, rutas, eventos, reglas R-GIA y hallazgos |
| `docs/03-roadmap-borrador.md` | Borrador Now / Next / Later para la sesión de roadmap |
| `apps/svc-gobernanza-ia/gobernanza_ia/web/index.html` | **La maqueta** (8 vistas, design system Faro, modo oscuro, ayuda en cada botón) |
| `apps/svc-gobernanza-ia/gobernanza_ia/scanner/` | Prueba de concepto del escáner de agentes (AST, sin ejecutar código) |
| `apps/svc-gobernanza-ia/gobernanza_ia/contracts/` | Prueba de concepto del contrato de privacidad (Pydantic) y su guard para Pydantic AI |
| `apps/svc-gobernanza-ia/examples/sample_estate/` | «Clínica Aurora Demo»: agentes de ejemplo para escanear |

## Demo local

```bash
cd apps/svc-gobernanza-ia
pip install -e ".[dev]"
gobernanza-ia servir                                # maqueta + API en http://localhost:3130
gobernanza-ia escanear examples/sample_estate       # inventario en la terminal
pytest -q                                           # 26 pruebas
```

Si se cambian los datos de demo: `python tools/exportar_demo.py` regenera `web/demo-data.js`, que
permite abrir la maqueta sin backend.
