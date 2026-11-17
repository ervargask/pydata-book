from fastapi.testclient import TestClient

from gobernanza_ia.api.app import app

c = TestClient(app)


def test_salud_y_resumen():
    assert c.get("/api/healthz").json()["ok"]
    r = c.get("/api/gobernanza-ia/resumen").json()
    assert r["resumen"]["assets"] == 9 and r["ledger"]["verificado"]


def test_activos_pasaporte_y_contrato():
    activos = c.get("/api/gobernanza-ia/activos").json()
    top = activos[0]
    assert top["risk"]["tier"] == "critical"
    d = c.get(f"/api/gobernanza-ia/activos/{top['id']}").json()
    assert d["eipd_riesgos"] and d["eventos"]
    argx = c.get(f"/api/gobernanza-ia/activos/{top['id']}/pasaporte.argx").text
    assert argx.startswith("module passports.")
    p = c.post("/api/gobernanza-ia/contratos/pc-aurora-agendamiento/probar",
               json={"finalidad": "agendamiento", "texto": "RUT 12.345.678-5 mail a@b.cl", "herramienta": "reservar_hora"}).json()
    assert "12.345.678-5" not in p["al_modelo"]["payload"]
    assert p["herramienta"]["decision"] == "DENY"  # RUT en los argumentos
    rat = c.get("/api/gobernanza-ia/contratos/pc-aurora-agendamiento/rat", params={"finalidad": "agendamiento"}).json()
    assert rat["status"] == "draft"


def test_marcos_y_evidencia():
    m = {x["id"]: x for x in c.get("/api/gobernanza-ia/marcos").json()}
    assert m["GIA-01"]["status"] in ("brecha", "parcial") and m["GIA-01"]["affected"]
    b = c.get("/api/gobernanza-ia/evidencias").json()
    assert b["verified"] and b["entries"][0]["previous_hash"] == "GENESIS"
