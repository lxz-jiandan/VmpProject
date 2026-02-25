#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - Demo 自动验证脚本：安装 demo、启动 Activity、抓取 VMP 标记。
# - 加固链路位置：功能烟雾测试。
# - 输入：demo 工程与可选 protected so。
# - 输出：VMP_DEMO_CHECK PASS/FAIL。
import argparse
import os
import sys
import time
from pathlib import Path

from _common.env_utils import locateAdb, locateJavaHome, removeDirRetry, runCmd


def buildDemoInstallCmd(build_stamp: int, protected_so: str):
    cmd = [
        "cmd",
        "/c",
        "gradlew.bat",
        "--no-daemon",
        f"-PvmpDemoBuildStamp={build_stamp}",
        "installDebug",
    ]
    if protected_so:
        cmd.append(f"-PprotectedDemoSo={protected_so}")
    return cmd


def cleanupStaleBuildDirs(demo_dir: Path, keep_stamp: int):
    app_dir = demo_dir / "app"
    keep_name = f"build-vmp-{keep_stamp}"
    for child in app_dir.iterdir():
        if not child.is_dir() or not child.name.startswith("build-vmp-"):
            continue
        if child.name == keep_name:
            continue
        if not removeDirRetry(child, retries=4, base_delay_seconds=0.2):
            print(f"[WARN] failed to cleanup stale demo build dir: {child}")

def main():
    # Demo 验证流程：
    # 1) installDebug（可选替换 protected so）；
    # 2) 启动 MainActivity 触发 onCreate JNI；
    # 3) 读取 logcat 中 VMP_DEMO_CHECK 标记并判定。
    parser = argparse.ArgumentParser(
        description="Build/install demo app and verify VMP JNI smoke check in onCreate.")
    parser.add_argument("--project-root", default=str(Path(__file__).parent.parent))
    parser.add_argument("--package", default="com.example.demo")
    parser.add_argument("--activity", default=".MainActivity")
    parser.add_argument("--sleep-seconds", type=float, default=3.0)
    parser.add_argument(
        "--protected-so",
        default="",
        help="Optional absolute/relative path for -PprotectedDemoSo",
    )
    args = parser.parse_args()

    root = Path(os.path.abspath(args.project_root))
    demo_dir = root / "demo"
    if not demo_dir.exists():
        raise RuntimeError(f"demo dir not found: {demo_dir}")

    adb = locateAdb(root, [Path("demo/local.properties"), Path("VmEngine/local.properties")])
    env = os.environ.copy()
    env["JAVA_HOME"] = locateJavaHome()

    gradle_protected_so = ""
    if args.protected_so:
        protected_so = Path(args.protected_so)
        if not protected_so.is_absolute():
            protected_so = (root / protected_so).resolve()
        gradle_protected_so = str(protected_so)

    build_stamp = int(time.time() * 1000)
    cleanupStaleBuildDirs(demo_dir, build_stamp)
    gradle_cmd = buildDemoInstallCmd(build_stamp, gradle_protected_so)
    install_proc = runCmd(gradle_cmd, cwd=str(demo_dir), env=env, check=False)
    install_log = (install_proc.stdout or "") + (install_proc.stderr or "")
    if install_proc.returncode != 0 and "Unable to delete directory" in install_log:
        print("[WARN] demo install hit locked output dir, retrying once with fresh build stamp")
        retry_cmd = buildDemoInstallCmd(build_stamp + 1, gradle_protected_so) + ["--rerun-tasks"]
        install_proc = runCmd(retry_cmd, cwd=str(demo_dir), env=env, check=False)

    if install_proc.returncode != 0:
        merged_output = (install_proc.stdout or "") + (install_proc.stderr or "")
        if "INSTALL_FAILED_USER_RESTRICTED" in merged_output:
            raise RuntimeError("install blocked by device policy: INSTALL_FAILED_USER_RESTRICTED")
        raise RuntimeError("demo installDebug failed")

    component = f"{args.package}/{args.activity}"
    runCmd([adb, "logcat", "-c"])
    runCmd([adb, "shell", "am", "force-stop", args.package], check=False)
    runCmd([adb, "shell", "am", "start", "-W", "-n", component])
    time.sleep(args.sleep_seconds)
    log_proc = runCmd([adb, "logcat", "-d", "-t", "2500"], check=False)
    log_text = log_proc.stdout or ""

    print("\n=== Filtered Demo Lines ===")
    for line in log_text.splitlines():
        if any(k in line for k in ("VMP_DEMO", "FATAL EXCEPTION", "Fatal signal", "UnsatisfiedLinkError")):
            print(line)

    pass_marker = "VMP_DEMO_CHECK PASS:"
    fail_markers = [
        "VMP_DEMO_CHECK FAIL:",
        "FATAL EXCEPTION",
        "Fatal signal",
        "UnsatisfiedLinkError",
    ]

    print("\n=== Demo Verify Result ===")
    has_pass = pass_marker in log_text
    found_fail = [m for m in fail_markers if m in log_text]
    if not has_pass:
        print(f"Missing marker: {pass_marker}")
    if found_fail:
        print("Detected fail markers:")
        for marker in found_fail:
            print(f"  - {marker}")
    if not has_pass or found_fail:
        return 1

    print("PASS: demo onCreate JNI smoke check succeeded.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
