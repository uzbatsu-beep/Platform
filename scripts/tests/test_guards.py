#!/usr/bin/env python3
"""Positive and negative tests for NEON architecture, air-gapped, deny.toml v2, and frontend compatibility guards."""

import importlib.util
import tempfile
import tomllib
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SCRIPTS_DIR.parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


airgap = load_module("check_airgapped_assets", "check_airgapped_assets.py")
arch = load_module("check_arch_boundaries", "check_arch_boundaries.py")
compat = load_module("check_frontend_compat", "check_frontend_compat.py")


class AirgappedGuardTests(unittest.TestCase):
    def test_allows_standard_svg_and_xml_namespaces(self) -> None:
        svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"></svg>'
        self.assertEqual(airgap.scan_text(svg, "icon.svg"), [])

    def test_allows_exact_local_and_internal_hosts_and_js_comments(self) -> None:
        js = (
            "// local dev comment\n"
            "const a = 'http://127.0.0.1:8080/health/live';\n"
            "const b = 'http://localhost:5173/api';\n"
            "const c = 'https://platform.internal/errors/forbidden';\n"
        )
        self.assertEqual(airgap.scan_text(js, "app.ts"), [])

    def test_rejects_spoofed_prefix_hostnames(self) -> None:
        cases = [
            'const a = "http://localhost.evil.example/a.js";',
            'const b = "https://127.0.0.1.evil.example/b.css";',
            'const c = "https://platform.internal.evil.example/c.woff2";',
        ]
        for snippet in cases:
            with self.subTest(snippet=snippet):
                errors = airgap.scan_text(snippet, "spoof.ts")
                self.assertEqual(len(errors), 1)

    def test_rejects_bare_and_pathed_protocol_relative_cdn_urls(self) -> None:
        cases = [
            '<script src="//cdn.example.com"></script>',
            'const bare = "//cdn.example.com";',
            '<link rel="stylesheet" href="//fonts.googleapis.com/css2?family=Inter" />',
            'body { background: url("//cdn.example.com/bg.png"); }',
        ]
        for snippet in cases:
            with self.subTest(snippet=snippet):
                errors = airgap.scan_text(snippet, "cdn.html")
                self.assertEqual(len(errors), 1)


class ArchBoundaryGuardTests(unittest.TestCase):
    def test_rejects_forbidden_dev_build_target_and_renamed_package_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            core = crates / "platform-core"
            core.mkdir(parents=True)
            (core / "Cargo.toml").write_text(
                """[package]
name = "platform-core"
version = "0.1.0"

[dependencies]
db = { package = "sqlx", version = "0.9.0" }

[dev-dependencies]
eq = { package = "mod-equipment", path = "../modules/mod-equipment" }

[build-dependencies]
mod-equipment = { path = "../modules/mod-equipment" }

[target.'cfg(unix)'.dependencies]
pg = { package = "platform-db-pg", path = "../platform-db-pg" }
""",
                encoding="utf-8",
            )
            errors = arch.check_cargo_dependencies(crates)
            self.assertEqual(len(errors), 4)
            self.assertTrue(any("sqlx" in e and "alias 'db'" in e for e in errors))
            self.assertTrue(any("mod-equipment" in e and "alias 'eq'" in e for e in errors))
            self.assertTrue(any("build-dependencies" in e for e in errors))
            self.assertTrue(any("target.cfg(unix).dependencies" in e and "platform-db-pg" in e for e in errors))


class FrontendCompatGuardTests(unittest.TestCase):
    def test_rejects_incompatible_vite8_plugin_react_v4(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "package.json"
            pkg.write_text(
                '{"devDependencies": {"vite": "8.0.0", "@vitejs/plugin-react": "4.3.4", "@tailwindcss/vite": "4.1.3", "vitest": "3.1.1"}}',
                encoding="utf-8",
            )
            errors = compat.check_package_json(pkg)
            self.assertEqual(len(errors), 3)


class DenyConfigTests(unittest.TestCase):
    def test_deny_toml_contains_no_removed_v1_advisory_fields(self) -> None:
        deny_path = REPO_ROOT / "deny.toml"
        data = tomllib.loads(deny_path.read_text(encoding="utf-8"))
        adv = data.get("advisories", {})
        for removed in ("vulnerability", "notice", "severity-threshold"):
            self.assertNotIn(removed, adv, f"Removed cargo-deny v1 field '{removed}' found in [advisories]")
        self.assertIn(adv.get("unmaintained"), ("all", "workspace", "transitive", "none"))


if __name__ == "__main__":
    unittest.main()
