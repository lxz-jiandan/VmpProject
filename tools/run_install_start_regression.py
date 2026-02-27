#!/usr/bin/env python3
"""Install + startactivity regression for demo protect route."""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from _common.env_utils import locateAdb, locateJavaHome, runCmd


def extract_relevant_log_lines(log_text: str):
    keys = (
        "VMP_DEMO",
        "route_",
        "vm_init",
        "Fatal signal",
        "FATAL EXCEPTION",
        "UnsatisfiedLinkError",
        "JNI_ERR",
    )
    lines = []
    for line in log_text.splitlines():
        if any(key in line for key in keys):
            lines.append(line)
    return lines


def delete_children_recursive(path: Path):
    for child in list(path.iterdir()):
        if child.is_dir():
            delete_children_recursive(child)
            try:
                child.rmdir()
            except OSError:
                subprocess.run(
                    ["cmd", "/c", "rmdir", "/s", "/q", str(child)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        else:
            try:
                child.unlink()
            except OSError:
                subprocess.run(
                    ["cmd", "/c", "del", "/f", "/q", str(child)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )


def remove_dir_if_exists(path: Path, timeout_seconds: float):
    if not path.exists():
        return False
    if not path.is_dir():
        return False
    deadline = time.time() + max(timeout_seconds, 0.0)
    while True:
        try:
            delete_children_recursive(path)
        except OSError:
            pass
        try:
            path.rmdir()
        except OSError:
            subprocess.run(
                ["cmd", "/c", "rmdir", "/s", "/q", str(path)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if not path.exists():
            print(f"[INFO] removed stale native cache: {path}")
            return True
        if time.time() >= deadline:
            try:
                remaining = sum(1 for _ in path.iterdir())
            except OSError:
                remaining = -1
            print(
                f"[WARN] stale native cache remains after timeout={timeout_seconds:.1f}s: "
                f"{path} remaining_entries={remaining}"
            )
            return False
        time.sleep(0.3)


def clean_native_caches(project_root: Path, timeout_seconds: float):
    cache_dirs = [
        project_root / "demo" / "app" / ".cxx",
        project_root / "demo" / "app" / "build" / "intermediates" / "cxx",
        project_root / "demo" / "app" / "build" / "intermediates" / "cmake",
        project_root / "VmEngine" / "app" / ".cxx",
        project_root / "VmEngine" / "app" / "build" / "intermediates" / "cxx",
        project_root / "VmEngine" / "app" / "build" / "intermediates" / "cmake",
    ]
    removed_count = 0
    for cache_dir in cache_dirs:
        if remove_dir_if_exists(cache_dir, timeout_seconds=timeout_seconds):
            removed_count += 1
    print(f"[INFO] native cache cleanup finished, removed_dirs={removed_count}")


def stop_gradle_daemons(project_dirs, env: dict):
    for project_dir in project_dirs:
        runCmd(
            ["cmd", "/c", "gradlew.bat", "--stop"],
            cwd=str(project_dir),
            env=env,
            check=False,
        )
    # 给 Windows 文件句柄一点释放时间，降低后续清理失败概率。
    time.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(
        description="Run installDebug + startActivity protect regression."
    )
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).parent.parent),
        help="Path to VmpProject root",
    )
    parser.add_argument(
        "--package",
        default="com.example.demo",
        help="Android package name",
    )
    parser.add_argument(
        "--activity",
        default=".MainActivity",
        help="Launch activity name",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=3.0,
        help="Wait after startActivity before collecting logcat",
    )
    parser.add_argument(
        "--gradle-task",
        default="installDebug",
        help="Gradle install task",
    )
    parser.add_argument(
        "--vmp-enabled",
        default="true",
        choices=("true", "false"),
        help="Pass -PvmpEnabled value to Gradle",
    )
    parser.add_argument(
        "--rerun-tasks",
        action="store_true",
        help="Append --rerun-tasks to Gradle command",
    )
    parser.add_argument(
        "--skip-native-clean",
        action="store_true",
        help="Skip auto cleanup of demo/vmengine native caches before build",
    )
    parser.add_argument(
        "--native-clean-timeout",
        type=float,
        default=30.0,
        help="Max seconds to wait while cleaning one native cache directory",
    )
    args = parser.parse_args()

    root = Path(os.path.abspath(args.project_root))
    vmengine_dir = root / "VmEngine"
    demo_dir = root / "demo"
    if not vmengine_dir.exists() or not demo_dir.exists():
        raise RuntimeError(f"invalid project root: {root}")

    adb = locateAdb(root, [Path("demo/local.properties"), Path("VmEngine/local.properties")])
    java_home = locateJavaHome()

    env = os.environ.copy()
    env["JAVA_HOME"] = java_home

    stop_gradle_daemons([vmengine_dir, demo_dir], env)

    if args.skip_native_clean:
        print("[INFO] skip native cache cleanup by --skip-native-clean")
    else:
        clean_native_caches(root, timeout_seconds=args.native_clean_timeout)

    # 当 VmEngine 侧启用 vmp 管线时，先确保 demo origin so 已生成。
    if args.vmp_enabled == "true":
        prepare_demo_origin_cmd = [
            "cmd",
            "/c",
            "gradlew.bat",
            "externalNativeBuildDebug",
        ]
        if args.rerun_tasks:
            prepare_demo_origin_cmd.append("--rerun-tasks")
        runCmd(prepare_demo_origin_cmd, cwd=str(demo_dir), env=env)

    build_vmengine_cmd = [
        "cmd",
        "/c",
        "gradlew.bat",
        "assembleDebug",
        f"-PvmpEnabled={args.vmp_enabled}",
    ]
    if args.rerun_tasks:
        build_vmengine_cmd.append("--rerun-tasks")
    runCmd(build_vmengine_cmd, cwd=str(vmengine_dir), env=env)

    demo_gradle_cmd = [
        "cmd",
        "/c",
        "gradlew.bat",
        args.gradle_task,
    ]
    if args.rerun_tasks:
        demo_gradle_cmd.append("--rerun-tasks")
    runCmd(demo_gradle_cmd, cwd=str(demo_dir), env=env)

    component = f"{args.package}/{args.activity}"
    runCmd([adb, "logcat", "-c"])
    runCmd([adb, "shell", "am", "force-stop", args.package], check=False)
    runCmd([adb, "shell", "am", "start", "-W", "-n", component])
    time.sleep(args.sleep_seconds)
    log_proc = runCmd([adb, "logcat", "-d", "-t", "2500"], check=False)
    log_text = log_proc.stdout or ""

    print("\n=== Filtered Log Lines ===")
    for line in extract_relevant_log_lines(log_text):
        print(line)

    expected_markers = [
        "VMP_DEMO: fun_add(",
        "VMP_DEMO: fun_global_mutable_state(",
        "VMP_DEMO: demo protect results",
    ]
    fail_markers = [
        "vm_init route4 init failed",
        "vm_init failed",
        "JNI_ERR",
        "Fatal signal",
        "FATAL EXCEPTION",
        "UnsatisfiedLinkError",
    ]

    missing = [marker for marker in expected_markers if marker not in log_text]
    found_fail = [marker for marker in fail_markers if marker in log_text]

    print("\n=== Regression Result ===")
    if missing:
        print("Missing expected markers:")
        for marker in missing:
            print(f"  - {marker}")
    if found_fail:
        print("Detected failure markers:")
        for marker in found_fail:
            print(f"  - {marker}")

    if missing or found_fail:
        return 1

    print("PASS: all expected startup regression markers found.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
