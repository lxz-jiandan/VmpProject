#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - Demo 自动验证脚本：安装 demo、启动 Activity、抓取 VMP 标记。
# - 加固链路位置：功能烟雾测试。
# - 输入：demo 工程与可选 protected so。
# - 输出：VMP_DEMO_CHECK PASS/FAIL。
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def run_cmd(cmd, cwd=None, env=None, check=True):
    # 和 run_regression.py 保持一致的命令执行语义，便于统一排障。
    print(f"$ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd,
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


def parse_local_properties(path: Path):
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("sdk.dir="):
            continue
        raw = line[len("sdk.dir="):]
        return raw.replace("\\\\", "\\").replace("\\:", ":")
    return None


def locate_adb(project_root: Path):
    demo_local = parse_local_properties(project_root / "demo" / "local.properties")
    vmengine_local = parse_local_properties(project_root / "VmEngine" / "local.properties")
    sdk_dir = demo_local or vmengine_local or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if not sdk_dir:
        raise RuntimeError("failed to locate Android SDK (local.properties / ANDROID_SDK_ROOT)")
    adb = Path(sdk_dir) / "platform-tools" / "adb.exe"
    if not adb.exists():
        adb = Path(sdk_dir) / "platform-tools" / "adb"
    if not adb.exists():
        raise RuntimeError(f"adb not found under SDK: {sdk_dir}")
    return str(adb)


def locate_java_home():
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

    adb = locate_adb(root)
    env = os.environ.copy()
    env["JAVA_HOME"] = locate_java_home()

    gradle_cmd = ["cmd", "/c", "gradlew.bat", "installDebug"]
    if args.protected_so:
        protected_so = Path(args.protected_so)
        if not protected_so.is_absolute():
            protected_so = (root / protected_so).resolve()
        gradle_cmd.append(f"-PprotectedDemoSo={protected_so}")

    install_proc = run_cmd(gradle_cmd, cwd=str(demo_dir), env=env, check=False)
    if install_proc.returncode != 0:
        if "INSTALL_FAILED_USER_RESTRICTED" in (install_proc.stdout + install_proc.stderr):
            raise RuntimeError("install blocked by device policy: INSTALL_FAILED_USER_RESTRICTED")
        raise RuntimeError("demo installDebug failed")

    component = f"{args.package}/{args.activity}"
    run_cmd([adb, "logcat", "-c"])
    run_cmd([adb, "shell", "am", "force-stop", args.package], check=False)
    run_cmd([adb, "shell", "am", "start", "-W", "-n", component])
    time.sleep(args.sleep_seconds)
    log_proc = run_cmd([adb, "logcat", "-d", "-t", "2500"], check=False)
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
