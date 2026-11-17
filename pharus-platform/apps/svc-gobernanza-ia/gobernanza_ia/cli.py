"""CLI: `gobernanza-ia escanear <ruta>` y `gobernanza-ia servir`."""
from __future__ import annotations

import argparse
import json
import os


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="gobernanza-ia")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("escanear", help="Inventario de agentes de IA de una carpeta o repositorio")
    s.add_argument("ruta")
    s.add_argument("--json", action="store_true")
    v = sub.add_parser("servir", help="Levanta la API y el mockup")
    v.add_argument("--puerto", type=int, default=int(os.environ.get("PORT", os.environ.get("PUERTO", 3130))))
    args = ap.parse_args(argv)

    if args.cmd == "escanear":
        from gobernanza_ia.scanner.engine import scan_path

        rep = scan_path(args.ruta)
        if args.json:
            print(rep.model_dump_json(indent=2))
            return
        print(f"{len(rep.assets)} activos de IA en {rep.files_scanned} archivos")
        for a in sorted(rep.assets, key=lambda a: -a.risk.score):
            flag = " [SHADOW]" if a.shadow else ""
            print(f"  {a.risk.score:>3} {a.risk.tier.value:<8} {a.framework.value:<14} {a.name}{flag}  ({a.location.file}:{a.location.line})")
            for f in a.findings:
                print(f"        {f.severity.value:<8} {f.code} {f.title}")
        print(json.dumps(rep.summary().model_dump(mode="json"), ensure_ascii=False))
    else:
        import uvicorn

        uvicorn.run("gobernanza_ia.api.app:app", host="0.0.0.0", port=args.puerto)


if __name__ == "__main__":
    main()
