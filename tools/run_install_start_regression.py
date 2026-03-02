#!/usr/bin/env python3
"""Install + startactivity regression for demo protect route."""
# [VMP_FLOW_NOTE] 文件级流程注释
# - 该脚本负责“安装 + 启动 + 日志判定”的端到端回归闭环。
# - 目标是给本地和 CI 提供同一套可复现的启动验收逻辑。
#
# 维护说明（回归判定约束）：
# 1) 成功判据依赖 expected_markers，新增业务场景时需同步更新。
# 2) 失败判据依赖 fail_markers，需覆盖崩溃、链接失败、初始化失败。
# 3) logcat 清理动作必须保留，否则历史日志会污染判定。
# 4) force-stop + start -W 是保证冷启动路径一致性的关键步骤。
# 5) native cache 清理默认开启，避免误用旧产物导致假通过。
# 6) 目录删除超时逻辑不可取消，用于吸收 Windows 文件句柄抖动。
# 7) vmp_enabled=true 时先构建 demo origin so，顺序不可颠倒。
# 8) 所有命令执行应通过 runCmd，保持日志和异常行为一致。
# 9) 非零退出码语义用于 CI 门禁，不应弱化或静默吞错。
# 10) 日志过滤关键字应保持“少而准”，避免输出过噪影响定位。
#
# 维护建议（排障导向）：
# 1) 若回归频繁出现假失败，先检查 marker 设计是否覆盖真实成功路径。
# 2) 若 installDebug 失败，优先检查签名/设备状态，再检查脚本逻辑。
# 3) 若启动成功但 marker 缺失，优先检查 sleep_seconds 是否过短。
# 4) 日志关键字新增时应避免过泛匹配，防止噪声误导判断。
# 5) 若引入新构建变体，请显式增加参数而非复用旧参数语义。
# 6) 该脚本应保持“串行且可读”的执行顺序，避免并行引入时序不确定。
# 7) 错误输出应保留原始异常文本，便于 CI 平台聚合分析。
# 8) 任何对成功/失败判据的修改都需要同步更新团队回归基线。
# 9) 建议把新增判据先灰度到本地，再启用到 CI 门禁。
# 10) 当路径解析逻辑变更时，需验证 Windows 和 UNC 两类路径场景。
# 11) 若设备性能差异明显，建议通过参数化 sleep_seconds 做环境适配。
# 12) 保持脚本输出稳定字段，便于自动化平台做日志规则匹配。
# 13) 该脚本应保持“单入口、单退出码语义”，避免多分支返回口径不一致。

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from _common.env_utils import locateAdb, locateJavaHome, runCmd


def extract_relevant_log_lines(log_text: str):
    """提取回归判定相关的关键日志行。"""
    # 该过滤函数用于把大体量 logcat 缩小到可读范围。
    # 保留关键关键词，便于快速判断“初始化失败/链接失败/崩溃”。
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
    """递归删除目录子项（目录优先深度删除）。"""
    # 先删子目录再删父目录，避免目录非空导致 rmdir 失败。
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
    """删除目录并在超时内循环重试。"""
    # 该函数用于处理 Windows 下短时文件占用造成的删目录不稳定。
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
    """清理 demo/VmEngine 的 native 中间缓存目录。"""
    # 仅清理中间产物，不触碰源码目录。
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
    """停止 Gradle 守护进程，释放可能占用的文件句柄。"""
    # 不强制 check=True，避免守护进程不存在时中断主流程。
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
    """执行 install+startActivity 回归主流程。"""
    # 该主流程目标是输出“可用于 CI 判定”的稳定退出码。
    # 参数设计尽量覆盖本地调试和 CI 两种运行方式。
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

    # 1) 解析工程根目录并校验关键模块目录存在性。
    root = Path(os.path.abspath(args.project_root))
    vmengine_dir = root / "VmEngine"
    demo_dir = root / "demo"
    # 工程目录缺失属于前置条件失败，直接终止。
    if not vmengine_dir.exists() or not demo_dir.exists():
        raise RuntimeError(f"invalid project root: {root}")

    # 2) 定位 Android SDK/adb 与 Java 运行环境。
    adb = locateAdb(root, [Path("demo/local.properties"), Path("VmEngine/local.properties")])
    java_home = locateJavaHome()

    # 复制环境变量后覆写 JAVA_HOME，避免污染调用进程。
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home

    # 3) 清理前先停止守护进程，降低缓存目录占用导致的失败概率。
    stop_gradle_daemons([vmengine_dir, demo_dir], env)

    # 4) 统一清理 native 缓存，保证使用本轮最新产物。
    if args.skip_native_clean:
        print("[INFO] skip native cache cleanup by --skip-native-clean")
    else:
        clean_native_caches(root, timeout_seconds=args.native_clean_timeout)

    # 5) 当 VmEngine 侧启用 VMP 管线时，先构建 demo origin so。
    if args.vmp_enabled == "true":
        prepare_demo_origin_cmd = [
            "cmd",
            "/c",
            "gradlew.bat",
            "externalNativeBuildDebug",
        ]
        if args.rerun_tasks:
            prepare_demo_origin_cmd.append("--rerun-tasks")
        # 先产出 origin so，确保后续 VMP 管线输入可用。
        runCmd(prepare_demo_origin_cmd, cwd=str(demo_dir), env=env)

    # 6) 构建 VmEngine（assembleDebug），可通过属性控制是否启用 VMP。
    build_vmengine_cmd = [
        "cmd",
        "/c",
        "gradlew.bat",
        "assembleDebug",
        f"-PvmpEnabled={args.vmp_enabled}",
    ]
    if args.rerun_tasks:
        build_vmengine_cmd.append("--rerun-tasks")
    # 先构建 VmEngine，再安装 demo，保持依赖顺序明确。
    runCmd(build_vmengine_cmd, cwd=str(vmengine_dir), env=env)

    # 7) 安装 demo（默认 installDebug）。
    demo_gradle_cmd = [
        "cmd",
        "/c",
        "gradlew.bat",
        args.gradle_task,
    ]
    if args.rerun_tasks:
        demo_gradle_cmd.append("--rerun-tasks")
    runCmd(demo_gradle_cmd, cwd=str(demo_dir), env=env)

    # 8) 启动 Activity 并抓取最近日志用于判定。
    component = f"{args.package}/{args.activity}"
    # 清理旧日志，避免历史记录影响本轮判定。
    runCmd([adb, "logcat", "-c"])
    runCmd([adb, "shell", "am", "force-stop", args.package], check=False)
    runCmd([adb, "shell", "am", "start", "-W", "-n", component])
    # 留出冷启动与初始化日志落地时间。
    time.sleep(args.sleep_seconds)
    log_proc = runCmd([adb, "logcat", "-d", "-t", "2500"], check=False)
    log_text = log_proc.stdout or ""

    # 先输出过滤日志，再输出最终判定，便于人工复核。
    print("\n=== Filtered Log Lines ===")
    for line in extract_relevant_log_lines(log_text):
        print(line)

    # 9) 定义成功/失败 marker。
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

    # 10) 计算缺失的成功 marker 与命中的失败 marker。
    missing = [marker for marker in expected_markers if marker not in log_text]
    found_fail = [marker for marker in fail_markers if marker in log_text]

    print("\n=== Regression Result ===")
    # 11) 输出判定结果与明细，便于定位是“未跑到”还是“跑到但崩溃”。
    # 缺少成功 marker 通常代表流程未完整跑通。
    if missing:
        print("Missing expected markers:")
        for marker in missing:
            print(f"  - {marker}")
    # 命中失败 marker 代表显式失败（崩溃/链接失败等）。
    if found_fail:
        print("Detected failure markers:")
        for marker in found_fail:
            print(f"  - {marker}")

    # 12) 任一失败条件触发时返回非 0，便于 CI 识别失败。
    if missing or found_fail:
        return 1

    # 13) 全部 marker 满足则判定通过。
    print("PASS: all expected startup regression markers found.")
    return 0


if __name__ == "__main__":
    # 顶层入口：统一异常转退出码 1，并保留错误信息。
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
