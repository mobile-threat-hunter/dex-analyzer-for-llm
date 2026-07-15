#!/usr/bin/env python3
"""jadx reference oracle for the jadx-port verification gate.

The jadx *runtime* is forbidden in the product (embedded-only policy — no JVM/subprocess
decompiler ships). This harness runs jadx ONLY as a DEV/CI reference oracle to validate a
ported jadx algorithm against jadx's own output — exactly how the DAD port uses androguard
as a test-time reference (a ``[dev]`` dependency, never shipped). It is availability-gated:
if jadx is not present it returns ``None`` / skips, like the AOSP-dataset-gated tooling.

jadx CLI resolution order: ``$JADX`` (full path) → ``$JADX_HOME/bin/jadx`` →
``/tmp/jadx-ref/build/jadx/bin/jadx`` (the gradle ``dist`` build) → ``jadx`` on PATH.
Build one with ``cd jadx && ./gradlew dist`` (source: github.com/skylot/jadx, Apache-2.0).

Usage:
    from scripts.jadx_ref import jadx_available, jadx_class_java
    src = jadx_class_java("app.apk", "Lcom/foo/Bar;")   # jadx's Java for that class
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

_CACHE = Path(
    os.environ.get("JADX_REF_CACHE")
    or (Path(__file__).resolve().parents[1] / "build" / "jadx_ref_cache")
)


def jadx_cli() -> str | None:
    """Locate the jadx CLI, or None if unavailable (gate skips when None)."""
    for cand in (
        os.environ.get("JADX"),
        (
            (os.environ.get("JADX_HOME") or "") + "/bin/jadx"
            if os.environ.get("JADX_HOME")
            else None
        ),
        "/tmp/jadx-dist/bin/jadx",  # prebuilt release
        "/tmp/jadx-ref/build/jadx/bin/jadx",  # gradle `dist` build
    ):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return shutil.which("jadx")


def jadx_available() -> bool:
    """Return True iff a runnable jadx CLI is resolvable."""
    return jadx_cli() is not None


def _apk_out_dir(apk_path: str) -> Path:
    key = hashlib.sha256(str(Path(apk_path).resolve()).encode()).hexdigest()[:16]
    return _CACHE / key


def decompile_apk(apk_path: str, *, timeout: int = 600) -> Path | None:
    """Decompile the whole APK with jadx once (cached), returning its source root.

    Returns None if jadx is unavailable. Raises on a jadx failure with no output (so a
    broken reference is loud, not a silent empty comparison).
    """
    cli = jadx_cli()
    if cli is None:
        return None
    out = _apk_out_dir(apk_path)
    src = out / "sources"
    if src.is_dir() and any(src.rglob("*.java")):
        return src  # cached
    out.mkdir(parents=True, exist_ok=True)
    # --no-res: skip resources (faster, we only compare code); --no-debug-info off so jadx
    # uses debug var names when present (its quality edge — the axis we validate against).
    subprocess.run(
        [
            cli,
            "-d",
            str(out),
            "--no-res",
            "--escape-unicode",
            str(Path(apk_path).resolve()),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if not (src.is_dir() and any(src.rglob("*.java"))):
        raise RuntimeError(f"jadx produced no sources for {apk_path} (out={out})")
    return src


def _descriptor_to_relpath(class_descriptor: str) -> str:
    """Lcom/foo/Bar$Inner; → com/foo/Bar.java (jadx emits the outer class file)."""
    body = class_descriptor
    if body.startswith("L") and body.endswith(";"):
        body = body[1:-1]
    outer = body.split("$", 1)[0]  # nested classes live in the outer file
    return outer + ".java"


def jadx_class_java(apk_path: str, class_descriptor: str) -> str | None:
    """Return jadx's Java for a class (the file text; nested classes share the outer file).

    None if jadx is unavailable or the class file is not in jadx's output (external /
    stripped). The caller compares this against our engine's output on the ported axis.
    """
    src = decompile_apk(apk_path)
    if src is None:
        return None
    f = src / _descriptor_to_relpath(class_descriptor)
    return f.read_text(encoding="utf-8", errors="replace") if f.is_file() else None


if __name__ == "__main__":
    import sys

    if not jadx_available():
        print(
            "jadx CLI not found — set $JADX / $JADX_HOME or build jadx (./gradlew dist)"
        )
        sys.exit(2)
    if len(sys.argv) >= 3:
        print(jadx_class_java(sys.argv[1], sys.argv[2]) or "(class not in jadx output)")
    else:
        print(f"jadx: {jadx_cli()}\nusage: jadx_ref.py <apk> <Lclass/descriptor;>")
