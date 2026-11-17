"""svc-gobernanza-ia — API HTTP (mockup).

En el monorepo real este servicio vive detrás del api-gateway (sesión, CSRF,
tenant y JWT interno) y sus rutas públicas cuelgan de `/api/gobernanza-ia/…`.
Aquí el estado es en memoria y el tenant es fijo (Clínica Aurora Demo, id 2)
para poder mostrar el producto de punta a punta.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from gobernanza_ia import __version__
from gobernanza_ia.contracts import ContractEnforcer, PrivacyContract
from gobernanza_ia.demo import Paciente, contrato_agendamiento
from gobernanza_ia.governance import frameworks
from gobernanza_ia.governance.bridges import asset_to_eipd_risks, contract_to_rat, events_for_asset
from gobernanza_ia.governance.ledger import EvidenceLedger
from gobernanza_ia.scanner.engine import scan_path
from gobernanza_ia.scanner.models import AgentAsset, ScanReport
from gobernanza_ia.scanner.passport import passport_from_asset, to_argorix

ROOT = Path(__file__).resolve().parents[2]
WEB = Path(__file__).resolve().parents[1] / "web"
DEMO_ESTATE = Path(os.environ.get("GOBERNANZA_IA_DEMO_RAIZ", ROOT / "examples" / "sample_estate"))
TENANT_DEMO = 2

app = FastAPI(title="Pharus · svc-gobernanza-ia", version=__version__)


class Store:
    def __init__(self) -> None:
        self.ledger = EvidenceLedger()
        self.scans: list[ScanReport] = []
        self.assets: dict[str, AgentAsset] = {}
        self.contracts: dict[str, PrivacyContract] = {}
        self.events: list[dict[str, Any]] = []

    def reset(self) -> None:
        self.__init__()
        c = contrato_agendamiento()
        self.contracts[c.id] = c
        self.ledger.append("contract.registered", subject=c.id, decision=None, version=c.version, fingerprint=c.fingerprint())
        self.run_scan()

    def run_scan(self) -> ScanReport:
        rep = scan_path(DEMO_ESTATE, label="clinica-aurora", ledger=self.ledger)
        self.scans.append(rep)
        for a in rep.assets:
            if a.has_privacy_contract and not a.declared:
                # el inventario vincula el agente con su contrato publicado
                for c in self.contracts.values():
                    if c.agent_id in (None, a.id):
                        c.agent_id = a.id
            self.assets[a.id] = a
            self.events.extend(events_for_asset(a, TENANT_DEMO))
        return rep


store = Store()
store.reset()


# ----------------------------------------------------------------------------- salud
@app.get("/api/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "servicio": "svc-gobernanza-ia", "version": __version__}


# ----------------------------------------------------------------------------- inventario
@app.get("/api/gobernanza-ia/resumen")
def resumen() -> dict[str, Any]:
    rep = store.scans[-1]
    s = rep.summary()
    controls = frameworks.evaluate(list(store.assets.values()))
    return {
        "empresa": "Clínica Aurora Demo",
        "ultimo_escaneo": {"id": rep.scan_id, "fecha": rep.started_at, "archivos": rep.files_scanned},
        "resumen": s.model_dump(mode="json"),
        "hallazgos": sum(len(a.findings) for a in store.assets.values()),
        "contratos": len(store.contracts),
        "cumplimiento": round(sum(c.coverage for c in controls) / len(controls), 2),
        "ledger": {"entradas": len(store.ledger.entries), "verificado": store.ledger.verify()[0], "head": store.ledger.head()},
    }


@app.post("/api/gobernanza-ia/escaneos")
def nuevo_escaneo() -> dict[str, Any]:
    rep = store.run_scan()
    return {"id": rep.scan_id, "activos": len(rep.assets), "archivos": rep.files_scanned}


@app.get("/api/gobernanza-ia/activos")
def activos() -> list[dict[str, Any]]:
    return [a.model_dump(mode="json") for a in sorted(store.assets.values(), key=lambda a: -(a.risk.score if a.risk else 0))]


def _asset(aid: str) -> AgentAsset:
    a = store.assets.get(aid)
    if a is None:
        raise HTTPException(404, "Activo no encontrado")
    return a


@app.get("/api/gobernanza-ia/activos/{aid}")
def activo(aid: str) -> dict[str, Any]:
    a = _asset(aid)
    return {
        **a.model_dump(mode="json"),
        "eventos": [e for e in store.events if e["datos"].get("activo_id") == aid][-5:],
        "eipd_riesgos": [dict(r.model_dump(), nivel=r.level) for r in asset_to_eipd_risks(a)],
    }


@app.get("/api/gobernanza-ia/activos/{aid}/pasaporte")
def pasaporte(aid: str) -> dict[str, Any]:
    a = _asset(aid)
    p = passport_from_asset(a, owner="Clínica Aurora Demo SpA")
    return {"pasaporte": p.model_dump(mode="json"), "argorix": to_argorix(p)}


@app.get("/api/gobernanza-ia/activos/{aid}/pasaporte.argx", response_class=PlainTextResponse)
def pasaporte_argx(aid: str) -> str:
    return to_argorix(passport_from_asset(_asset(aid), owner="Clínica Aurora Demo SpA"))


# ----------------------------------------------------------------------------- contratos
@app.get("/api/gobernanza-ia/contratos")
def contratos() -> list[dict[str, Any]]:
    return [dict(c.model_dump(mode="json"), huella=c.fingerprint()) for c in store.contracts.values()]


@app.post("/api/gobernanza-ia/contratos", status_code=201)
def publicar_contrato(c: PrivacyContract) -> dict[str, Any]:
    store.contracts[c.id] = c
    e = store.ledger.append("contract.registered", subject=c.id, version=c.version, fingerprint=c.fingerprint())
    return {"id": c.id, "huella": c.fingerprint(), "evidencia": e.id}


def _contract(cid: str) -> PrivacyContract:
    c = store.contracts.get(cid)
    if c is None:
        raise HTTPException(404, "Contrato no encontrado")
    return c


@app.get("/api/gobernanza-ia/contratos/{cid}/esquema")
def contrato_esquema(cid: str) -> dict[str, Any]:
    """Verificación estática del esquema de entrada del agente (como `argorixc check`)."""
    c = _contract(cid)
    return {p.id: ContractEnforcer(c, p.id, store.ledger).check_schema(Paciente).model_dump(mode="json") for p in c.purposes}


class Prueba(BaseModel):
    finalidad: str
    texto: str
    herramienta: str | None = None


@app.post("/api/gobernanza-ia/contratos/{cid}/probar")
def probar_contrato(cid: str, body: Prueba) -> dict[str, Any]:
    """Simulador: qué vería el modelo y qué decide el contrato."""
    c = _contract(cid)
    try:
        enf = ContractEnforcer(c, body.finalidad, store.ledger)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    entrada = enf.redact_text(body.texto)
    store.ledger.append("enforcement", subject=c.id, decision=entrada.decision.value, purpose=body.finalidad, redacted=entrada.redacted)
    out: dict[str, Any] = {"al_modelo": entrada.model_dump(mode="json")}
    if body.herramienta:
        out["herramienta"] = enf.authorize_tool(body.herramienta, {"texto": body.texto}).model_dump(mode="json")
    out["salida"] = enf.check_output(body.texto).model_dump(mode="json")
    return out


@app.get("/api/gobernanza-ia/contratos/{cid}/rat")
def contrato_rat(cid: str, finalidad: str) -> dict[str, Any]:
    """Borrador de tratamiento para svc-rat (`POST /internas/gobernanza-ia/tratamientos`)."""
    c = _contract(cid)
    a = store.assets.get(c.agent_id or "")
    high = bool(a and a.risk and a.risk.tier.value in ("high", "critical"))
    try:
        return contract_to_rat(c, finalidad, high_risk=high, subjects=["Pacientes"]).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


# ----------------------------------------------------------------------------- marcos / evidencia
@app.get("/api/gobernanza-ia/marcos")
def marcos() -> list[dict[str, Any]]:
    return [c.model_dump(mode="json") for c in frameworks.evaluate(list(store.assets.values()))]


@app.get("/api/gobernanza-ia/evidencias")
def evidencias() -> dict[str, Any]:
    return store.ledger.export_bundle()


@app.get("/api/gobernanza-ia/eventos")
def eventos() -> list[dict[str, Any]]:
    return store.events[-50:]


@app.post("/internas/demo/reiniciar")
def reiniciar() -> dict[str, bool]:
    store.reset()
    return {"ok": True}


# ----------------------------------------------------------------------------- mockup (mf-gobernanza-ia)
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB / "index.html")
