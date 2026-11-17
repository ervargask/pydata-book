"""Motor del escáner: recorre una raíz (repositorio, carpeta o carga ZIP
descomprimida), despacha cada archivo a su detector, calcula el riesgo y
registra la corrida en el ledger de evidencia."""

from __future__ import annotations

import uuid
from pathlib import Path

from gobernanza_ia.governance.ledger import EvidenceLedger
from gobernanza_ia.scanner import detectors
from gobernanza_ia.scanner.models import ScanReport
from gobernanza_ia.scanner.risk import assess

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".nx", ".angular", "coverage", "_temporal"}
MAX_FILE_BYTES = 1_000_000  # tope por archivo (como los topes de PharusScan)
MAX_FILES = 20_000

MCP_CONFIG_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json"}


def _detector_for(path: Path):
    name = path.name.lower()
    if name in MCP_CONFIG_NAMES or name.endswith(".mcp.json"):
        return detectors.scan_mcp_config
    suf = path.suffix.lower()
    if suf == ".py":
        return detectors.scan_python
    if suf in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
        return detectors.scan_js
    if suf == ".argx":
        return detectors.scan_argorix
    return None


def scan_path(root: str | Path, *, label: str | None = None, ledger: EvidenceLedger | None = None) -> ScanReport:
    root = Path(root).resolve()
    label = label or root.name
    report = ScanReport(scan_id=f"scan_{uuid.uuid4().hex[:10]}", root=label)

    for path in sorted(root.rglob("*")):
        if report.files_scanned >= MAX_FILES:
            break
        if not path.is_file() or any(p in SKIP_DIRS for p in path.relative_to(root).parts):
            continue
        det = _detector_for(path)
        if det is None or path.stat().st_size > MAX_FILE_BYTES:
            continue
        report.files_scanned += 1
        rel = path.relative_to(root).as_posix()
        res = det(path, rel, label)
        report.assets.extend(res.assets)
        report.findings.extend(res.findings)

    # Los hallazgos de archivo (secretos) se asocian al activo del mismo archivo.
    loose = []
    for fnd in report.findings:
        owner = next((a for a in report.assets if fnd.location and a.location.file == fnd.location.file), None)
        (owner.findings if owner else loose).append(fnd)
    report.findings = loose

    for asset in report.assets:
        risk, fnds = assess(asset)
        asset.risk = risk
        asset.findings.extend(fnds)

    if ledger is not None:
        s = report.summary()
        # Evidencia sin PII: sólo conteos e IDs (regla de eventos de Pharus).
        ledger.append(
            "scan",
            subject=label,
            decision=None,
            scan_id=report.scan_id,
            files=report.files_scanned,
            assets=s.assets,
            shadow=s.shadow,
            by_tier={k.value: v for k, v in s.by_tier.items()},
            asset_ids=[a.id for a in report.assets],
        )
    return report
