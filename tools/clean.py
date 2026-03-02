#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 工程缓存清理脚本：清理构建缓存、临时目录，并校验工作区是否干净。
# - 目标：只清理缓存，不改动业务源码；用于回归前统一环境。

import argparse
import os
import fnmatch
from pathlib import Path
from typing import List

from _common.env_utils import removeDirRetry, runCmd


def is_unc_path(path: Path):
    # Windows UNC 路径以 "\\" 开头，cmd 在此 cwd 下无法直接运行 bat。
    return str(path).startswith("\\\\")


def stop_gradle_daemons(project_root: Path):
    # 尝试停止 demo/VmEngine 的 Gradle daemon，降低 Windows 文件占用导致的删目录失败概率。
    gradle_projects = [
        project_root / "demo",
        project_root / "VmEngine",
    ]
    for project_dir in gradle_projects:
        gradlew = project_dir / "gradlew.bat"
        if not gradlew.exists():
            continue
        if is_unc_path(project_dir):
            print(f"[WARN] skip gradle stop on UNC cwd: {project_dir}")
            continue
        runCmd(
            ["cmd", "/c", "gradlew.bat", "--stop"],
            cwd=str(project_dir),
            check=False,
        )


def collect_cache_dirs(project_root: Path) -> List[Path]:
    # 固定缓存目录（native/cmake/intermediate）。
    dirs = [
        project_root / "demo" / ".gradle",
        project_root / "demo" / "app" / ".cxx",
        project_root / "demo" / "app" / "build",
        project_root / "VmEngine" / ".gradle",
        project_root / "VmEngine" / "app" / ".cxx",
        project_root / "VmEngine" / "app" / "build",
        project_root / "tools" / "__pycache__",
        project_root / "tools" / "_common" / "__pycache__",
    ]
    # VmProtect 下 CMake 构建目录统一按前缀扫描，避免遗漏 Debug/Release 等变体。
    vmprotect_dir = project_root / "VmProtect"
    if vmprotect_dir.exists():
        for item in vmprotect_dir.iterdir():
            if item.is_dir() and item.name.startswith("cmake-build-"):
                dirs.append(item)

    # tools 下所有 tmp_* 临时目录。
    tools_dir = project_root / "tools"
    if tools_dir.exists():
        for item in tools_dir.iterdir():
            if item.is_dir() and item.name.startswith("tmp_"):
                dirs.append(item)
    return dirs


def collect_cache_files(project_root: Path) -> List[Path]:
    # 根目录常见导出缓存文件（由 export/protect 生成）。
    files: List[Path] = [
        project_root / "coverage_report.md",
        project_root / "branch_addr_list.txt",
        project_root / "libdemo_expand.so",
        project_root / "mz_zip_get_error_string.bin",
        project_root / "mz_zip_get_error_string.txt",
    ]

    # 清理根目录下函数导出产物：fun_*.txt / fun_*.bin。
    for item in project_root.iterdir():
        if not item.is_file():
            continue
        if fnmatch.fnmatch(item.name, "fun_*.txt") or fnmatch.fnmatch(item.name, "fun_*.bin"):
            files.append(item)

    # tools 下历史 tmp_* 临时文件（日志/映射快照等）。
    tools_dir = project_root / "tools"
    if tools_dir.exists():
        for item in tools_dir.iterdir():
            if item.is_file() and item.name.startswith("tmp_"):
                files.append(item)
    # 根目录下历史 tmp_* 文件（通常来自一次性调试脚本输出）。
    for item in project_root.iterdir():
        if item.is_file() and item.name.startswith("tmp_"):
            files.append(item)
    return files


def remove_cache_dirs(cache_dirs: List[Path], dry_run: bool):
    removed = 0
    missing = 0
    failed = 0
    for cache_dir in cache_dirs:
        if not cache_dir.exists():
            missing += 1
            continue
        if dry_run:
            print(f"[DRYRUN] remove dir: {cache_dir}")
            removed += 1
            continue
        ok = removeDirRetry(cache_dir)
        if ok:
            print(f"[INFO] removed cache dir: {cache_dir}")
            removed += 1
        else:
            print(f"[WARN] failed to remove cache dir: {cache_dir}")
            failed += 1
    print(
        "[INFO] cache dir cleanup summary: "
        f"removed={removed} missing={missing} failed={failed}"
    )
    return failed == 0


def remove_cache_files(cache_files: List[Path], dry_run: bool):
    removed = 0
    missing = 0
    failed = 0
    for cache_file in cache_files:
        if not cache_file.exists():
            missing += 1
            continue
        if dry_run:
            print(f"[DRYRUN] remove file: {cache_file}")
            removed += 1
            continue
        try:
            cache_file.unlink()
            print(f"[INFO] removed cache file: {cache_file}")
            removed += 1
        except OSError:
            print(f"[WARN] failed to remove cache file: {cache_file}")
            failed += 1
    print(
        "[INFO] cache file cleanup summary: "
        f"removed={removed} missing={missing} failed={failed}"
    )
    return failed == 0


def verify_git_clean(project_root: Path):
    # 校验工作区干净度；用于保证“清理后源码不脏”。
    proc = runCmd(
        ["git", "status", "--porcelain"],
        cwd=str(project_root),
        check=False,
    )
    status_text = (proc.stdout or "").strip()
    if not status_text:
        print("[OK] git working tree is clean.")
        return True
    print("[ERROR] git working tree is not clean after cache cleanup:")
    for line in status_text.splitlines():
        print(f"  {line}")
    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Clean VmpProject caches and verify source tree cleanliness."
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Path to VmpProject root (default: current working directory).",
    )
    parser.add_argument(
        "--skip-gradle-stop",
        action="store_true",
        help="Skip 'gradlew --stop' before cleanup.",
    )
    parser.add_argument(
        "--no-verify-clean",
        action="store_true",
        help="Skip 'git status --porcelain' cleanliness check.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print cleanup actions without deleting anything.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    project_root = Path(os.path.abspath(args.project_root))
    if not (project_root / ".git").exists():
        raise RuntimeError(f"invalid project root (missing .git): {project_root}")

    if args.dry_run and not args.skip_gradle_stop:
        print("[DRYRUN] stop gradle daemons in: demo, VmEngine")
    elif not args.skip_gradle_stop:
        stop_gradle_daemons(project_root)
    else:
        print("[INFO] skip gradle daemon stop by --skip-gradle-stop")

    cache_dirs = collect_cache_dirs(project_root)
    cache_files = collect_cache_files(project_root)
    dir_ok = remove_cache_dirs(cache_dirs, dry_run=args.dry_run)
    file_ok = remove_cache_files(cache_files, dry_run=args.dry_run)

    if args.no_verify_clean:
        print("[INFO] skip git cleanliness verification by --no-verify-clean")
        return 0 if (dir_ok and file_ok) else 1

    clean_ok = verify_git_clean(project_root)
    return 0 if (dir_ok and file_ok and clean_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
