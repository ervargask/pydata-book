"""Genera gobernanza_ia/web/demo-data.js: snapshot de la API para que el
mockup funcione sin backend (p. ej. publicado como página estática)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from gobernanza_ia.api.app import app  # noqa: E402

c = TestClient(app)
activos = c.get("/api/gobernanza-ia/activos").json()
data = {
    "resumen": c.get("/api/gobernanza-ia/resumen").json(),
    "activos": activos,
    "detalle": {a["id"]: c.get(f"/api/gobernanza-ia/activos/{a['id']}").json() for a in activos},
    "pasaportes": {a["id"]: c.get(f"/api/gobernanza-ia/activos/{a['id']}/pasaporte").json() for a in activos},
    "contratos": c.get("/api/gobernanza-ia/contratos").json(),
    "rat": c.get("/api/gobernanza-ia/contratos/pc-aurora-agendamiento/rat", params={"finalidad": "agendamiento"}).json(),
    "esquema": c.get("/api/gobernanza-ia/contratos/pc-aurora-agendamiento/esquema").json(),
    "marcos": c.get("/api/gobernanza-ia/marcos").json(),
    "evidencias": c.get("/api/gobernanza-ia/evidencias").json(),
    "eventos": c.get("/api/gobernanza-ia/eventos").json(),
}
out = ROOT / "gobernanza_ia" / "web" / "demo-data.js"
out.write_text("window.PHARUS_DEMO = " + json.dumps(data, ensure_ascii=False, default=str) + ";\n", encoding="utf-8")
print(out, out.stat().st_size, "bytes")
