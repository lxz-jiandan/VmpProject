#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 端到端自动回归脚本：导出、patch、安装、启动、判定。
# - 加固链路位置：工程自动化测试入口。
# - 输入：项目路径、函数清单、patch 参数。
# - 输出：启动回归 PASS/FAIL 结论。
import argparse
# 操作系统相关能力：环境变量、路径处理等。
import os
# 文件复制/删除/which 工具探测。
import shutil
# 二进制结构体解包（ELF 头解析使用）。
import struct
# stdout/stderr 输出与退出码控制。
import sys
# 启动后等待日志稳定。
import time
# 面向对象路径处理（跨平台分隔符兼容）。
from pathlib import Path

from _common.env_utils import locateAdb, locateJavaHome, runCmd


DEFAULT_FUNCTIONS = [
    # 默认导出/回归函数集：覆盖基础算术、分支、C++对象、全局状态等场景。
    "fun_for",
    "fun_add",
    "fun_for_add",
    "fun_if_sub",
    "fun_countdown_muladd",
    "fun_loop_call_mix",
    "fun_call_chain",
    "fun_branch_call",
    "fun_cpp_make_string",
    "fun_cpp_string_len",
    "fun_cpp_vector_sum",
    "fun_cpp_virtual_mix",
    "fun_global_data_mix",
    "fun_static_local_table",
    "fun_global_struct_acc",
    "fun_class_static_member",
    "fun_multi_branch_path",
    "fun_switch_dispatch",
    "fun_bitmask_branch",
    "fun_global_table_rw",
    "fun_global_mutable_state",
]
def locateVmProtectExe(project_root: Path):
    # 候选路径按优先顺序：Windows exe -> 非 exe 可执行名。
    candidates = [
        project_root / "VmProtect" / "cmake-build-debug" / "VmProtect.exe",
        project_root / "VmProtect" / "cmake-build-debug" / "VmProtect",
    ]
    # 逐个检查候选路径是否存在。
    for candidate in candidates:
        if candidate.exists():
            # 返回字符串路径，便于直接拼命令。
            return str(candidate)
    # 全部不存在时抛出明确错误提示。
    raise RuntimeError("VmProtect executable not found (build VmProtect first)")


def locateTool(name: str, candidates):
    # 优先使用给定候选路径（固定版本工具优先）。
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    # 候选失败后回退到 PATH 查找。
    found = shutil.which(name)
    if found:
        return found
    # 仍未找到则抛错，阻止后续空路径执行。
    raise RuntimeError(f"tool not found: {name}")


def locateGccPair():
    # 固定候选：优先 CLion 自带 MinGW，再尝试其它已知安装位置。
    candidate_pairs = [
        (
            r"C:\Program Files\JetBrains\CLion 2022.2.5\bin\mingw\bin\gcc.exe",
            r"C:\Program Files\JetBrains\CLion 2022.2.5\bin\mingw\bin\g++.exe",
        ),
        (
            r"D:\Clion2022\bin\mingw\bin\gcc.exe",
            r"D:\Clion2022\bin\mingw\bin\g++.exe",
        ),
    ]
    # 候选路径中只要 gcc/g++ 成对存在就返回。
    for gcc, gpp in candidate_pairs:
        if Path(gcc).exists() and Path(gpp).exists():
            return gcc, gpp

    # 未命中固定路径时，从 PATH 里查找 gcc/g++。
    gcc = shutil.which("gcc")
    gpp = shutil.which("g++")
    if gcc and gpp:
        return gcc, gpp
    # 全部失败返回 (None, None)，由上层决定是否继续。
    return None, None


def toCmakePath(value: str):
    # CMake 在 Windows 上也接受 '/'，统一转换减少转义噪音。
    return value.replace("\\", "/")


def extractRelevantLogLines(log_text: str):
    # 仅保留回归判定相关关键词，降低日志噪声。
    keys = (
        "route_",
        "vm_init",
        "Fatal signal",
        "FATAL EXCEPTION",
        "UnsatisfiedLinkError",
        "JNI_ERR",
    )
    # 承接过滤后的日志行。
    lines = []
    # 逐行扫描 logcat 全量文本。
    for line in log_text.splitlines():
        # 命中任意关键词即保留。
        if any(key in line for key in keys):
            lines.append(line)
    # 返回过滤结果用于展示。
    return lines


def runVmProtectExport(project_root: Path, env: dict, functions):
    # 离线导出阶段：
    # - 编译 VmProtect；
    # - 运行 VmProtect 生成 txt/bin/expand so；
    # - 把产物同步到 VmEngine assets。
    # VmProtect 源目录。
    vmprotect_dir = project_root / "VmProtect"
    # VmEngine assets 目录（导出产物最终拷贝目标）。
    vmengine_assets_dir = project_root / "VmEngine" / "app" / "src" / "main" / "assets"
    # VmProtect CMake 构建目录。
    build_dir = vmprotect_dir / "cmake-build-debug"
    # CMake target 名称。
    target_name = "VmProtect"
    # 平台相关可执行文件名（Windows 带 .exe）。
    exe_name = f"{target_name}.exe" if os.name == "nt" else target_name

    # 定位 CMake 可执行程序。
    cmake_exe = locateTool(
        "cmake",
        [
            r"C:\Program Files\JetBrains\CLion 2022.2.5\bin\cmake\win\bin\cmake.exe",
            r"D:\Clion2022\bin\cmake\win\bin\cmake.exe",
        ],
    )
    # 定位 Ninja 可执行程序。
    ninja_exe = locateTool(
        "ninja",
        [
            r"C:\Program Files\JetBrains\CLion 2022.2.5\bin\ninja\win\ninja.exe",
            r"D:\Clion2022\bin\ninja\win\ninja.exe",
        ],
    )
    # 定位 gcc/g++（可能返回 None）。
    gcc_exe, gpp_exe = locateGccPair()

    # 打印工具定位结果。
    print(f"[INFO] cmake: {cmake_exe}")
    print(f"[INFO] ninja: {ninja_exe}")
    # 如果找到 gcc/g++，则把 MinGW bin 追加到 PATH，保证 CMake/Ninja 找到编译器依赖。
    if gcc_exe and gpp_exe:
        print(f"[INFO] gcc: {gcc_exe}")
        print(f"[INFO] g++: {gpp_exe}")
        # MinGW bin 目录。
        mingw_bin = str(Path(gcc_exe).parent)
        # 拷贝 env，避免污染调用方传入对象。
        env = env.copy()
        # PATH 前置 MinGW，优先使用期望版本工具链。
        env["PATH"] = mingw_bin + os.pathsep + env.get("PATH", "")

    # 确保构建目录存在。
    build_dir.mkdir(parents=True, exist_ok=True)
    # CMake 缓存文件路径。
    cache = build_dir / "CMakeCache.txt"
    # CMake 中间目录路径。
    cmake_files = build_dir / "CMakeFiles"
    # 删除旧缓存，保证配置参数（编译器、生成器）可被强制刷新。
    if cache.exists():
        cache.unlink()
    # 删除旧中间目录，避免增量配置残留。
    if cmake_files.exists():
        shutil.rmtree(cmake_files)

    # 组装 CMake configure 命令。
    configure_cmd = [
        cmake_exe,
        "-G",
        "Ninja",
        "-S",
        toCmakePath(str(vmprotect_dir)),
        "-B",
        toCmakePath(str(build_dir)),
        "-DCMAKE_BUILD_TYPE=Debug",
        f"-DCMAKE_MAKE_PROGRAM={toCmakePath(ninja_exe)}",
    ]
    # 有明确 gcc/g++ 时，显式指定编译器避免被系统默认值覆盖。
    if gcc_exe and gpp_exe:
        configure_cmd.append(f"-DCMAKE_C_COMPILER={toCmakePath(gcc_exe)}")
        configure_cmd.append(f"-DCMAKE_CXX_COMPILER={toCmakePath(gpp_exe)}")

    # 执行 configure。
    runCmd(configure_cmd, cwd=str(vmprotect_dir), env=env)
    # 执行 build（并行 12 线程）。
    runCmd(
        [
            cmake_exe,
            "--build",
            str(build_dir),
            "--target",
            target_name,
            "-j",
            "12",
        ],
        cwd=str(vmprotect_dir),
        env=env,
    )

    # 计算期望输出可执行文件路径。
    target_exe = build_dir / exe_name
    # 不存在则立即失败，避免后续调用空路径。
    if not target_exe.exists():
        raise RuntimeError(f"missing executable: {target_exe}")
    # 组装 VmProtect 导出命令（基础参数）。
    export_cmd = [
        str(target_exe),
        "--input-so",
        str(vmprotect_dir / "libdemo.so"),
    ]
    # 追加函数白名单参数：--function <name>。
    for function_name in functions:
        export_cmd.extend(["--function", function_name])
    # 执行离线导出。
    runCmd(export_cmd, cwd=str(build_dir), env=env)

    # assets 目录不存在时给出警告并返回（允许仅做导出不拷贝）。
    if not vmengine_assets_dir.exists():
        print(f"[WARN] asset dir not found: {vmengine_assets_dir}")
        return

    # 必需的公共导出产物。
    required_common = [
        "libdemo_expand.so",
        "branch_addr_list.txt",
    ]
    # 校验并复制公共产物。
    for filename in required_common:
        src = build_dir / filename
        if not src.exists():
            raise RuntimeError(f"missing exported file: {src}")
        shutil.copy2(src, vmengine_assets_dir / filename)

    # 对每个函数分别校验并复制 txt/bin 产物。
    for func_name in functions:
        for suffix in (".txt", ".bin"):
            filename = func_name + suffix
            src = build_dir / filename
            if not src.exists():
                raise RuntimeError(f"missing exported file: {src}")
            shutil.copy2(src, vmengine_assets_dir / filename)

    # 输出导出与拷贝成功提示。
    print(
        "[OK] exported libdemo_expand.so + branch_addr_list.txt + "
        f"function txt/bin to {vmengine_assets_dir}"
    )


def findVmEngineSoOutputs(vmengine_dir: Path):
    # CXX 构建产物根目录（按 ABI 输出在子目录）。
    pattern = vmengine_dir / "app" / "build" / "intermediates" / "cxx" / "Debug"
    # 搜索所有 arm64-v8a 的 libvmengine.so 路径。
    outputs = list(pattern.glob("*/obj/arm64-v8a/libvmengine.so"))
    # 返回排序后的稳定列表，保证处理顺序一致。
    return sorted(outputs)


def findVmEngineCmakeSoOutput(vmengine_dir: Path):
    # CMake 另一条中间产物路径（兼容历史目录结构）。
    return (
        vmengine_dir
        / "app"
        / "build"
        / "intermediates"
        / "cmake"
        / "debug"
        / "obj"
        / "arm64-v8a"
        / "libvmengine.so"
    )


def removeExistingVmEngineOutputs(vmengine_dir: Path):
    # 记录实际删除的旧产物，便于调用方排查。
    removed = []
    # 合并两类候选路径：cxx/debug + cmake/debug。
    for path in [*findVmEngineSoOutputs(vmengine_dir), findVmEngineCmakeSoOutput(vmengine_dir)]:
        # 不存在则跳过。
        if not path.exists():
            continue
        # 删除旧 so，强制后续步骤使用新构建产物。
        path.unlink()
        # 记录删除结果。
        removed.append(path)
        # 打印删除日志。
        print(f"[INFO] removed stale native output: {path}")
    # 返回删除列表（可能为空）。
    return removed


def validateAndroidElfLayout(path: Path):
    # 读入完整 so 二进制内容。
    data = path.read_bytes()
    # ELF64 最小头部长度校验。
    if len(data) < 0x40:
        raise RuntimeError(f"{path} is too small to be ELF64")
    # ELF 魔数校验。
    if data[0:4] != b"\x7fELF":
        raise RuntimeError(f"{path} is not an ELF file")
    # EI_CLASS 校验：2 表示 ELF64。
    if data[4] != 2:
        raise RuntimeError(f"{path} is not ELF64")

    # 读取 program/section 头相关字段。
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]

    # program header 范围校验：off + size 不得越界。
    if e_phnum > 0:
        ph_size = e_phentsize * e_phnum
        if e_phentsize == 0 or e_phoff + ph_size > len(data):
            raise RuntimeError(
                f"{path} has invalid program header table: off={e_phoff} size={ph_size} file={len(data)}"
            )
    # section header 范围与对齐校验。
    if e_shnum > 0:
        sh_size = e_shentsize * e_shnum
        if e_shentsize == 0 or e_shoff + sh_size > len(data):
            raise RuntimeError(
                f"{path} has invalid section header table range: off={e_shoff} size={sh_size} file={len(data)}"
            )
        # Android/ELF64 场景中 section header 常规应 8 字节对齐。
        if (e_shoff % 8) != 0:
            raise RuntimeError(
                f"{path} has non-8-byte-aligned section header table: e_shoff={e_shoff}"
            )

    # 打印结构检查通过信息。
    print(f"[INFO] ELF layout OK: {path.name} e_shoff={e_shoff} e_shnum={e_shnum} file_size={len(data)}")


def patchVmEngineSymbolsPatchbay(
    project_root: Path,
    vmengine_dir: Path,
    env: dict,
    donor_so: Path,
    impl_symbol: str,
    only_fun_java: bool,
):
    # route4 L2 接管前置：
    # 1) 先强制重编 native，拿到“干净” libvmengine.so；
    # 2) 用 patch 工具把 donor 导出注入到 vmengine，产出独立 libvmengine_patch.so；
    # 3) 临时把 patch 结果部署到 libvmengine.so 供 installDebug 打包；
    # 4) 回归后再恢复原始 libvmengine.so，避免污染后续构建输入。
    if not donor_so.exists():
        raise RuntimeError(f"donor so not found: {donor_so}")

    # 先删除旧产物，避免 patch 到陈旧文件。
    removeExistingVmEngineOutputs(vmengine_dir)

    # 强制重建 native so，确保 patch 输入是最新编译结果。
    runCmd(
        ["cmd", "/c", "gradlew.bat", "externalNativeBuildDebug", "--rerun-tasks"],
        cwd=str(vmengine_dir),
        env=env,
    )

    # 定位 patch 工具（VmProtect.exe）。
    patch_tool = locateVmProtectExe(project_root)

    # 收集本次构建产出的所有目标 so。
    targets = findVmEngineSoOutputs(vmengine_dir)
    # 没有目标 so 直接失败，避免静默跳过。
    if not targets:
        raise RuntimeError("no vmengine so outputs found under app/build/intermediates/cxx/Debug")

    # 记录“临时部署”信息：[(target_so, backup_so, patched_so), ...]。
    # main() 会在 installDebug 后恢复 target_so。
    staged_for_install = []

    # 逐个目标 so 执行 patch，确保多构建变体都一致处理。
    for target_so in targets:
        # patch 前做一次 ELF 结构校验，防止输入文件已损坏。
        validateAndroidElfLayout(target_so)
        # 固定 patch 输出文件名：libvmengine_patch.so（与原始 so 分离）。
        patched_so = target_so.with_name("libvmengine_patch.so")
        # 备份原始 so，供 installDebug 后恢复。
        backup_so = target_so.with_name("libvmengine_origin.so")
        # 清理上次遗留文件，避免旧产物混入本次流程。
        if patched_so.exists():
            patched_so.unlink()
        if backup_so.exists():
            backup_so.unlink()
        # 组装 patchbay 命令：
        # input=target_so, donor=donor_so, output=patched_so, impl=impl_symbol。
        cmd = [
            patch_tool,
            "export_alias_from_patchbay",
            str(target_so),
            str(donor_so),
            str(patched_so),
            impl_symbol,
            "--allow-validate-fail",
        ]
        # 默认仅 patch fun_* / Java_*，可选关闭限制。
        if only_fun_java:
            cmd.append("--only-fun-java")

        # 执行 patch 命令。
        cmd_str = " ".join([
            patch_tool,
            "export_alias_from_patchbay",
            str(target_so),
            str(donor_so),
            str(patched_so),
            impl_symbol,
            "--allow-validate-fail",
        ])
        print("cmd_str:" + cmd_str)
        runCmd(cmd, cwd=str(project_root), env=env)
        # 校验独立 patch 产物，确保输出完整可用。
        validateAndroidElfLayout(patched_so)

        # 临时部署给 installDebug：先备份原始 so，再覆盖目标路径。
        shutil.copy2(str(target_so), str(backup_so))
        shutil.copy2(str(patched_so), str(target_so))
        validateAndroidElfLayout(target_so)
        staged_for_install.append((target_so, backup_so, patched_so))
        print(f"[OK] generated patched vmengine so: {patched_so}")

    # 返回临时部署信息，供主流程在 install 后恢复原始 so。
    return staged_for_install


def restoreVmEngineOutputs(staged_for_install):
    # installDebug 结束后恢复原始 so，避免把 patch 结果留在构建输出目录。
    for target_so, backup_so, patched_so in staged_for_install:
        if not backup_so.exists():
            raise RuntimeError(f"backup so missing, cannot restore: {backup_so}")
        shutil.copy2(str(backup_so), str(target_so))
        backup_so.unlink()
        print(f"[INFO] restored original vmengine so: {target_so}")
        print(f"[INFO] kept patched artifact: {patched_so}")


def main():
    # 脚本主流程：
    # A. VmProtect 导出；
    # B. (可选) patch vmengine 导出；
    # C. 安装 VmEngine；
    # D. startActivity + logcat 判定。
    # 创建命令行参数解析器。
    parser = argparse.ArgumentParser(description="Run VmProtect + VmEngine startup regression.")
    # 项目根目录参数，默认取脚本上一级目录。
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).parent.parent),
        help="Path to VmpProject root",
    )
    # App 包名。
    parser.add_argument("--package", default="com.example.vmengine")
    # 启动 Activity。
    parser.add_argument("--activity", default=".MainActivity")
    # 启动后等待秒数（等待 vm_init/route 日志稳定输出）。
    parser.add_argument("--sleep-seconds", type=float, default=3.0)
    # 是否启用 vmengine 导出 patch 流程。
    parser.add_argument(
        "--patch-vmengine-symbols",
        action="store_true",
        help="Patch libvmengine.so with export_alias_from_patchbay before installDebug",
    )
    # donor so 路径参数。
    parser.add_argument(
        "--patch-donor-so",
        default="VmProtect/libdemo.so",
        help="Donor .so path (relative to project root or absolute)",
    )
    # patch 实现符号名参数。
    parser.add_argument(
        "--patch-impl-symbol",
        default="vm_takeover_slot_0000",
        help="Implementation symbol/prefix used by export_alias_from_patchbay",
    )
    # 是否 patch donor 的全部导出。
    parser.add_argument(
        "--patch-all-exports",
        action="store_true",
        help="Patch all donor exports (default only patches fun_* and Java_*)",
    )
    # 函数导出清单参数。
    parser.add_argument(
        "--functions",
        nargs="+",
        default=DEFAULT_FUNCTIONS,
        help="Functions to export from VmProtect",
    )
    # 解析参数。
    args = parser.parse_args()

    # 归一化项目根目录为绝对路径。
    root = Path(os.path.abspath(args.project_root))
    # 关键子目录路径。
    vmprotect_dir = root / "VmProtect"
    vmengine_dir = root / "VmEngine"
    # 根目录有效性校验。
    if not vmprotect_dir.exists() or not vmengine_dir.exists():
        raise RuntimeError(f"invalid project root: {root}")

    # 定位 adb。
    adb = locateAdb(root, [Path("VmEngine/local.properties")])
    # 定位 Java 运行时。
    java_home = locateJavaHome()
    # 复制环境变量用于子进程。
    env = os.environ.copy()
    # 强制使用定位到的 JAVA_HOME。
    env["JAVA_HOME"] = java_home

    # 1) Build/export from VmProtect.
    runVmProtectExport(root, env, args.functions)

    # 2) Optionally patch vmengine symbol exports before install.
    if args.patch_vmengine_symbols:
        # donor 路径对象化。
        donor = Path(args.patch_donor_so)
        # 相对路径时按 project_root 解析。
        if not donor.is_absolute():
            donor = root / donor
        # 执行 patch 流程。
        staged_for_install = patchVmEngineSymbolsPatchbay(
            project_root=root,
            vmengine_dir=vmengine_dir,
            env=env,
            donor_so=donor,
            impl_symbol=args.patch_impl_symbol,
            only_fun_java=not args.patch_all_exports,
        )
        try:
            # Skip native rebuild so patched output is not overwritten.
            # 关键点：跳过 externalNativeBuildDebug，防止 Gradle 重新编译覆盖临时部署结果。
            runCmd(
                ["cmd", "/c", "gradlew.bat", "installDebug", "-x", "externalNativeBuildDebug"],
                cwd=str(vmengine_dir),
                env=env,
            )
        finally:
            # 无论 install 成功/失败，都恢复原始 libvmengine.so。
            restoreVmEngineOutputs(staged_for_install)
    else:
        # 2) Install VmEngine debug apk.
        # 不做 patch 时按默认安装流程（包含必要 native task 依赖）。
        runCmd(["cmd", "/c", "gradlew.bat", "installDebug"], cwd=str(vmengine_dir), env=env)

    # 3) Start activity and collect logs.
    # 组装启动组件名：<package>/<activity>。
    component = f"{args.package}/{args.activity}"
    # 清空 logcat 缓冲，避免旧日志干扰本次判定。
    runCmd([adb, "logcat", "-c"])
    # 先强停应用，保证冷启动路径一致。
    runCmd([adb, "shell", "am", "force-stop", args.package], check=False)
    # 启动目标 Activity，并等待启动完成返回。
    runCmd([adb, "shell", "am", "start", "-W", "-n", component])
    # 等待指定时间，让 JNI/route 日志完整落地。
    time.sleep(args.sleep_seconds)
    # 拉取最近 2500 行日志。
    log_proc = runCmd([adb, "logcat", "-d", "-t", "2500"], check=False)
    # 防御性处理：stdout 为空时用空串。
    log_text = log_proc.stdout or ""

    # 打印过滤后的关键日志，便于人工快速检查。
    print("\n=== Filtered Log Lines ===")
    for line in extractRelevantLogLines(log_text):
        print(line)

    # route4-only 启动健康判定：两条成功 marker 缺一不可。
    # 当前版本已移除 reference 解析依赖，不再要求 reference marker。
    expected_markers = [
        # route4 L1 必须真正执行（state=0），不能是 skip。
        "route_embedded_expand_so result=1 state=0",
        # route4 L2 takeover 校验通过。
        "route_symbol_takeover result=1",
    ]
    # route4 L1 的失败表现：当前只保留“显式失败”一种形态。
    # 说明：kSkipNoPayload 等兼容状态已移除，故不再检查 state=1/state=2。
    embedded_fail_markers = [
        # L1 直接失败。
        "route_embedded_expand_so result=0",
    ]
    # 通用崩溃/链接失败 marker。
    fail_markers = [
        # vm_init 路径错误文案。
        "vm_init route4 init failed",
        "vm_init failed",
        # route4 L2 takeover 显式失败文案。
        "route_symbol_takeover result=0",
        "JNI_ERR",
        "Fatal signal",
        "FATAL EXCEPTION",
        "UnsatisfiedLinkError",
    ]

    # 收集缺失的必需成功 marker。
    missing = [marker for marker in expected_markers if marker not in log_text]
    # 收集通用失败 marker。
    found_fail = [marker for marker in fail_markers if marker in log_text]
    # 追加 route4 L1 专属失败 marker。
    found_fail.extend([marker for marker in embedded_fail_markers if marker in log_text])

    print("\n=== Regression Result ===")
    # 输出缺失项，帮助快速定位“没跑到”还是“跑了但失败”。
    if missing:
        print("Missing expected markers:")
        for marker in missing:
            print(f"  - {marker}")
    # 输出失败项，帮助快速定位崩溃或链路断点。
    if found_fail:
        print("Detected failure markers:")
        for marker in found_fail:
            print(f"  - {marker}")

    # 仅在确认 state=0 时输出 active 提示。
    if "route_embedded_expand_so result=1 state=0" in log_text:
        print("route_embedded_expand_so: active (state=0).")

    # 只要有缺失或失败 marker，就返回非 0 让 CI/调用方感知失败。
    if missing or found_fail:
        return 1

    # 全部判定通过。
    print("PASS: all expected startup regression markers found.")
    return 0


if __name__ == "__main__":
    try:
        # 正常入口：main 返回码作为进程退出码。
        raise SystemExit(main())
    except Exception as exc:
        # 兜底异常输出，确保 CI 能看到明确错误信息。
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
