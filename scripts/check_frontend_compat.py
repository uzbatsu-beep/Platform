#!/usr/bin/env python3
"""Verify Vite 8 compatibility with @vitejs/plugin-react (>=6.0.0), @tailwindcss/vite (>=4.2.2), and vitest (>=4.0.0)."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse_semver(spec: str) -> tuple[int, int, int] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", spec)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def check_package_json(pkg_path: Path) -> list[str]:
    data = json.loads(pkg_path.read_text(encoding="utf-8"))
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    errors: list[str] = []

    vite = parse_semver(deps.get("vite", ""))
    plugin_react = parse_semver(deps.get("@vitejs/plugin-react", ""))
    tw_vite = parse_semver(deps.get("@tailwindcss/vite", ""))
    vitest = parse_semver(deps.get("vitest", ""))

    if not vite or vite[0] != 8:
        errors.append(f"Expected vite 8.x, got {deps.get('vite')!r}")
    if not plugin_react or plugin_react < (6, 0, 0):
        errors.append(f"Vite 8 requires @vitejs/plugin-react >= 6.0.0, got {deps.get('@vitejs/plugin-react')!r}")
    if not tw_vite or tw_vite < (4, 2, 2):
        errors.append(f"Vite 8 requires @tailwindcss/vite >= 4.2.2, got {deps.get('@tailwindcss/vite')!r}")
    if not vitest or vitest < (4, 0, 0):
        errors.append(f"Vite 8 requires vitest >= 4.0.0, got {deps.get('vitest')!r}")

    return errors


def main() -> int:
    pkg_path = ROOT / "frontend" / "package.json"
    errors = check_package_json(pkg_path)
    if errors:
        print("FRONTEND COMPATIBILITY CHECK FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("OK: Frontend Vite 8 + React/Tailwind/Vitest compatibility check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
