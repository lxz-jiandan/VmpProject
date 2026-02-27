#!/usr/bin/env python3
"""Install + startactivity regression for demo protect route."""

import argparse
import os
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
