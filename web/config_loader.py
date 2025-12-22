"""Config helpers for the RustSL NiceGUI app."""

from pathlib import Path
import json
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent


def load_plugins_manifest() -> Dict[str, Any]:
    path = ROOT / "config" / "plugins.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _safe_default_id(items: List[Dict[str, Any]], prefer: str | None) -> str:
    ids = [it.get("id", "") for it in items if it.get("id")]
    if prefer in ids:
        return prefer
    return ids[0] if ids else ""


def get_defaults(manifest: Dict[str, Any]) -> Dict[str, str]:
    defaults = manifest.get("defaults", {}) or {}
    return {
        "encryption": defaults.get("encryption"),
        "run_mode": defaults.get("run_mode"),
        "alloc_mem_mode": defaults.get("alloc_mem_mode"),
        "encoding": defaults.get("encoding"),
        "syscall_method": defaults.get("syscall_method") or defaults.get("syscall_methods"),
        "load_payload_mode": defaults.get("load_payload_mode"),
    }


def get_encodings(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    return manifest.get("encodings", [])


def build_feature_maps(manifest: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    return {
        "encryption_map": {e["id"]: e.get("encrypt_arg", e["id"]) for e in manifest.get("encryption", [])},
        "encryption_feature_map": {e["id"]: e.get("feature", "") for e in manifest.get("encryption", [])},
        "encoding_feature_map": {e["id"]: e.get("feature", "") for e in manifest.get("encodings", [])},
        "vm_checks_map": {v["id"]: v.get("feature", "") for v in manifest.get("vm_checks", [])},
        "run_mode_map": {r["id"]: r.get("feature", "") for r in manifest.get("run_modes", [])},
        "alloc_mem_feature_map": {m["id"]: m.get("feature", "") for m in manifest.get("alloc_mem_modes", [])},
        "load_payload_feature_map": {m["id"]: m.get("feature", "") for m in manifest.get("load_payload_modes", [])},
        "syscall_feature_map": {s["id"]: s.get("feature", "") for s in manifest.get("syscall_methods", [])},
    }


__all__ = [
    "ROOT",
    "load_plugins_manifest",
    "_safe_default_id",
    "get_defaults",
    "get_encodings",
    "build_feature_maps",
]
