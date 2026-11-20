#!/usr/bin/env python3
"""Verify NEON Modular Monolith crate boundaries across ALL dependency sections and renamed `package = "..."` deps."""

import argparse
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_PATTERNS = [
    (re.compile(r"\bAnyPool\b"), "Forbidden sqlx::AnyPool usage (ADR-002 requires explicit PG/SQLite adapters)"),
    (re.compile(r"\bAnyConnection\b"), "Forbidden sqlx::AnyConnection usage (ADR-002)"),
]


def _extract_dep_names(section_table: dict) -> list[tuple[str, str]]:
    """Return list of (alias_key, effective_package_name) accounting for renamed `package = "..."` dependencies."""
    result: list[tuple[str, str]] = []
    for key, spec in section_table.items():
        if isinstance(spec, dict) and isinstance(spec.get("package"), str):
            result.append((key, spec["package"]))
        else:
            result.append((key, key))
    return result


def collect_all_dependencies(cargo_data: dict) -> list[tuple[str, str, str]]:
    """Collect (section_name, alias_key, effective_package_name) from dependencies, dev-, build-, and target.*."""
    collected: list[tuple[str, str, str]] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for alias, pkg in _extract_dep_names(cargo_data.get(section, {})):
            collected.append((section, alias, pkg))

    for target_cfg, target_table in cargo_data.get("target", {}).items():
        if not isinstance(target_table, dict):
            continue
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for alias, pkg in _extract_dep_names(target_table.get(section, {})):
                collected.append((f"target.{target_cfg}.{section}", alias, pkg))

    return collected


def check_cargo_dependencies(crates_dir: Path) -> list[str]:
    errors: list[str] = []
    for cargo_toml in sorted(crates_dir.rglob("Cargo.toml")):
        data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        pkg_name = data.get("package", {}).get("name", str(cargo_toml))
        all_deps = collect_all_dependencies(data)

        if pkg_name == "platform-sdk":
            for section, alias, dep in all_deps:
                if dep.startswith("platform-") or dep.startswith("mod-") or dep in {"axum", "sqlx", "tokio"}:
                    errors.append(f"{pkg_name} [{section}]: forbidden dependency '{dep}' (alias '{alias}') in platform-sdk")

        if pkg_name == "platform-core":
            for section, alias, dep in all_deps:
                if dep.startswith("mod-") or dep in {"platform-db-pg", "platform-db-sqlite", "sqlx"}:
                    errors.append(f"{pkg_name} [{section}]: forbidden dependency '{dep}' (alias '{alias}') in platform-core")

        if pkg_name.startswith("mod-"):
            for section, alias, dep in all_deps:
                if dep.startswith("mod-") and not dep.endswith("-contract"):
                    errors.append(f"{pkg_name} [{section}]: direct dependency on module crate '{dep}' (alias '{alias}') is forbidden")

    return errors


def check_source_patterns(crates_dir: Path, root: Path) -> list[str]:
    errors: list[str] = []
    for rs_file in sorted(crates_dir.rglob("*.rs")):
        text = rs_file.read_text(encoding="utf-8")
        for regex, message in FORBIDDEN_PATTERNS:
            if regex.search(text):
                errors.append(f"{rs_file.relative_to(root)}: {message}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crates-dir", type=Path, default=ROOT / "crates")
    args = parser.parse_args()

    errors = check_cargo_dependencies(args.crates_dir) + check_source_patterns(args.crates_dir, args.crates_dir.parent)
    if errors:
        print("ARCH BOUNDARY CHECK FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("OK: Architecture boundary and SQLx adapter checks passed (all sections + renamed deps).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
