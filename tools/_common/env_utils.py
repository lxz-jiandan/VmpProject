#!/usr/bin/env python3
"""Shared process/environment helpers for tools scripts."""
#
# [VMP_FLOW_NOTE] 模块级说明
# - 该模块聚焦“环境定位 + 外部命令执行 + 目录清理重试”三类横向能力。
# - 设计目标是让 tools 下脚本把业务流程逻辑与系统交互细节解耦。
# - 所有函数默认面向 Windows 优先场景，同时保持跨平台最小兼容。
#
# 维护说明（质量约束）：
# 1) runCmd 必须保持“命令可复现”输出，禁止静默吞命令。
# 2) runCmd 的 check 语义只能控制抛错，不应改变 stdout/stderr 打印行为。
# 3) removeDirRetry 需要继续容忍短时文件锁，不应改成单次删除。
# 4) parseLocalProperties 仅解析 sdk.dir，避免引入与本工程无关的配置耦合。
# 5) locateAdb 的搜索优先级（local.properties > 环境变量）要保持稳定。
# 6) locateJavaHome 的返回值必须是目录路径，供 JAVA_HOME 直接使用。
# 7) 工具函数异常文本需要可读，便于 CI 日志快速定位。
# 8) Windows 路径转义行为属于兼容要求，修改前需回归验证。

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
    """执行外部命令并回显输出。

    输入：
    - cmd/cwd/env/check：与 subprocess.run 同语义。
    输出：
    - 返回 CompletedProcess，供调用方继续读取 stdout/stderr。
    """
    # 统一打印命令本体，确保日志可复现。
    # 后续脚本排障时可直接复制执行。
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
    """shutil.rmtree 的 onerror 回调。

    用途：
    - 当 Windows 只读位导致删除失败时，先改写权限再重试一次。
    """
    # 这里不抛异常，保持 rmtree 尽力清理语义。
    # Windows often leaves read-only bits on generated outputs.
    # Try flipping permission and retry the failing operation once.
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def removeDirRetry(path: Path, retries: int = 6, base_delay_seconds: float = 0.3):
    """带退避重试的目录删除。

    场景：
    - 处理 Windows 构建缓存目录被短暂句柄占用导致的删除抖动。
    返回：
    - bool，表示目录最终是否被清理干净。
    """
    # 每次失败后按 attempt 线性退避，兼顾速度与稳定性。
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
    """解析 local.properties 中的 sdk.dir。

    返回：
    - 找到则返回解析后的 SDK 路径字符串。
    - 未找到或文件不存在返回 None。
    """
    # 仅关注 sdk.dir，其他键值由调用方自行处理。
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
    """定位 adb 可执行文件路径。

    优先级：
    1) local.properties -> sdk.dir
    2) ANDROID_SDK_ROOT / ANDROID_HOME
    """
    # local.properties 允许传相对路径，统一在项目根目录下解析。
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
    """定位可用的 JAVA_HOME。

    优先使用环境变量；若缺失则回退到团队常见 IDE 内置 JBR 目录。
    """
    # 保持返回值为目录路径（非 java.exe 路径），与 JAVA_HOME 语义一致。
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
