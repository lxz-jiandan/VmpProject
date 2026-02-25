#!/usr/bin/env python3
"""Shared process/environment helpers for tools scripts."""

import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional, Sequence


def runCmd(
    cmd: Sequence[str],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    check: bool = True,
):
    # Unified subprocess execution:
    # 1) print command for reproducibility;
    # 2) stream captured output back to console;
    # 3) optionally raise on non-zero exit code.
    print(f"$ {' '.join(cmd)}")
    proc = subprocess.run(
        list(cmd),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def rmtreeOnError(func, path, _exc_info):
    # Windows often leaves read-only bits on generated outputs.
    # Try flipping permission and retry the failing operation once.
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def removeDirRetry(path: Path, retries: int = 6, base_delay_seconds: float = 0.3):
    # Best-effort directory cleanup with backoff for transient Windows file locks.
    target = Path(path)
    if not target.exists():
        return True

    for attempt in range(1, retries + 1):
        try:
            shutil.rmtree(target, onerror=rmtreeOnError)
        except FileNotFoundError:
            return True
        except OSError:
            if attempt == retries:
                break
        else:
            if not target.exists():
                return True
        time.sleep(base_delay_seconds * attempt)
    return not target.exists()


def parseLocalProperties(path: Path):
    # Parse sdk.dir from Gradle local.properties.
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("sdk.dir="):
            continue
        raw = stripped[len("sdk.dir="):]
        return raw.replace("\\\\", "\\").replace("\\:", ":")
    return None


def locateAdb(project_root: Path, local_properties_candidates: Iterable[Path]):
    sdk_dir = None
    for candidate in local_properties_candidates:
        candidate_path = candidate if candidate.is_absolute() else (project_root / candidate)
        sdk_dir = parseLocalProperties(candidate_path)
        if sdk_dir:
            break
    if not sdk_dir:
        sdk_dir = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if not sdk_dir:
        raise RuntimeError("failed to locate Android SDK (local.properties or ANDROID_SDK_ROOT)")

    adb = Path(sdk_dir) / "platform-tools" / "adb.exe"
    if not adb.exists():
        adb = Path(sdk_dir) / "platform-tools" / "adb"
    if not adb.exists():
        raise RuntimeError(f"adb not found under SDK: {sdk_dir}")
    return str(adb)


def locateJavaHome():
    java_home = os.environ.get("JAVA_HOME")
    if java_home and Path(java_home).exists():
        return java_home
    candidates = [
        Path(r"C:\Program Files\Android\Android Studio\jbr"),
        Path(r"C:\Program Files\JetBrains\CLion 2022.2.5\jbr"),
    ]
    for candidate in candidates:
        if (candidate / "bin" / "java.exe").exists():
            return str(candidate)
    raise RuntimeError("JAVA_HOME not set and no bundled JBR found")
