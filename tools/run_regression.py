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
# 外部命令调用（目录删除回退到 rmdir）。
import subprocess
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
    "fun_div_mod_chain",
    "fun_shift_mix",
    "fun_do_while_path",
    "fun_nested_continue_break",
    "fun_indirect_call_mix",
    "fun_unsigned_compare_fold",
    "fun_local_array_walk",
    "fun_switch_fallthrough",
    "fun_short_circuit_logic",
    "fun_select_mix",
    "fun_global_data_mix",
    "fun_static_local_table",
    "fun_global_struct_acc",
    "fun_class_static_member",
    "fun_multi_branch_path",
    "fun_switch_dispatch",
    "fun_bitmask_branch",
    "fun_global_table_rw",
    "fun_global_mutable_state",
    "fun_flag_merge_cbz",
    "fun_ptr_stride_sum",
    "fun_fn_table_dispatch",
    "fun_clamp_window",
    "fun_ret_i64_mix",
    "fun_ret_u64_mix",
    "fun_ret_bool_gate",
    "fun_ret_i16_pack",
    "fun_switch_loop_acc",
    "fun_struct_alias_walk",
    "fun_unsigned_edge_paths",
    "fun_reverse_ptr_mix",
    "fun_guarded_chain_mix",
    "fun_ret_i64_steps",
    "fun_ret_u64_acc",
    "fun_ret_bool_mix2",
    "fun_ret_u16_blend",
    "fun_ret_i8_wave",
    "fun_ext_insn_mix",
    "fun_bfm_nonwrap",
    "fun_bfm_wrap",
    "fun_csinc_path",
    "fun_madd_msub_div",
    "fun_orn_bic_extr",
    "fun_mem_half_signed",
    "fun_atomic_u8_order",
    "fun_atomic_u16_order",
    "fun_atomic_u64_order",
    "fun_ret_cstr_pick",
    "fun_ret_std_string_mix",
    "fun_ret_vector_mix",
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
        "VMP_DEMO",
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


def deleteChildrenRecursive(path: Path):
    # 深度优先删除子项：先删子内容，再删子目录。
    for child in list(path.iterdir()):
        if child.is_dir():
            deleteChildrenRecursive(child)
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


def removeDirIfExists(path: Path, timeoutSeconds: float):
    # 若目录存在则递归删除，直到目录为空后再删目录本身。
    if not path.exists():
        return False
    if not path.is_dir():
        return False
    deadline = time.time() + max(timeoutSeconds, 0.0)
    while True:
        try:
            deleteChildrenRecursive(path)
        except OSError:
            pass
        try:
            path.rmdir()
        except OSError:
            # Windows 上目录残留时回退到原生命令，提升清理稳定性。
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
                f"[WARN] stale native cache remains after timeout={timeoutSeconds:.1f}s: "
                f"{path} remaining_entries={remaining}"
            )
            return False
        time.sleep(0.3)


def cleanNativeCaches(project_root: Path, timeoutSeconds: float):
    # 两个 Android 工程的 native 缓存目录集合。
    cache_dirs = [
        project_root / "demo" / "app" / ".cxx",
        project_root / "demo" / "app" / "build" / "intermediates" / "cxx",
        project_root / "demo" / "app" / "build" / "intermediates" / "cmake",
        project_root / "VmEngine" / "app" / ".cxx",
        project_root / "VmEngine" / "app" / "build" / "intermediates" / "cxx",
        project_root / "VmEngine" / "app" / "build" / "intermediates" / "cmake",
        project_root / "VmEngine" / "app" / "build" / "intermediates" / "tmp_vmprotect_route",
    ]
    removed_count = 0
    for cache_dir in cache_dirs:
        if removeDirIfExists(cache_dir, timeoutSeconds=timeoutSeconds):
            removed_count += 1
    print(f"[INFO] native cache cleanup finished, removed_dirs={removed_count}")


def stopGradleDaemons(project_dirs, env: dict):
    # 清理前先停掉守护进程，减少 Windows 文件占用导致的删除失败。
    for project_dir in project_dirs:
        runCmd(
            ["cmd", "/c", "gradlew.bat", "--stop"],
            cwd=str(project_dir),
            env=env,
            check=False,
        )
    # 给 Windows 文件句柄一点释放时间，降低后续清理失败概率。
    time.sleep(1.0)


def findDemoOriginSoOutputs(demo_dir: Path):
    # Demo CXX 产物根目录（按 ABI 输出在子目录）。
    pattern = demo_dir / "app" / "build" / "intermediates" / "cxx" / "Debug"
    # 搜索所有 arm64-v8a 的 libdemo.so 路径。
    outputs = list(pattern.glob("*/obj/arm64-v8a/libdemo.so"))
    # 返回排序后的稳定列表，保证处理顺序一致。
    return sorted(outputs)


def findDemoOriginCmakeSoOutput(demo_dir: Path):
    # CMake 另一条中间产物路径（兼容历史目录结构）。
    return (
        demo_dir
        / "app"
        / "build"
        / "intermediates"
        / "cmake"
        / "debug"
        / "obj"
        / "arm64-v8a"
        / "libdemo.so"
    )


def buildDemoOriginSo(demo_dir: Path, env: dict):
    # 构建 demo native，产出 origin so 中间文件（libdemo.so）。
    runCmd(
        ["cmd", "/c", "gradlew.bat", "externalNativeBuildDebug", "--rerun-tasks"],
        cwd=str(demo_dir),
        env=env,
    )

    # 汇总候选输出路径并取最新文件。
    candidates = [*findDemoOriginSoOutputs(demo_dir)]
    cmake_fallback = findDemoOriginCmakeSoOutput(demo_dir)
    if cmake_fallback.exists():
        candidates.append(cmake_fallback)

    if not candidates:
        raise RuntimeError(
            "demo origin so not found under demo/app/build/intermediates "
            "(expected libdemo.so)"
        )
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    origin_so = candidates[0]

    # 对产物做 ELF 结构校验，提前发现损坏文件。
    validateAndroidElfLayout(origin_so)
    print(f"[INFO] demo origin so: {origin_so}")
    return origin_so


def runVmProtectExport(project_root: Path, env: dict, functions, input_so: Path):
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
    # 输入 so 必须存在。
    if not input_so.exists():
        raise RuntimeError(f"VmProtect input so not found: {input_so}")
    # 组装 VmProtect 导出命令（基础参数）。
    export_cmd = [
        str(target_exe),
        "--mode",
        "export",
        "--input-so",
        str(input_so),
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
        sh_table_size = e_shentsize * e_shnum
        if e_shentsize == 0 or e_shoff + sh_table_size > len(data):
            raise RuntimeError(
                f"{path} has invalid section header table range: off={e_shoff} size={sh_table_size} file={len(data)}"
            )
        # Android/ELF64 场景中 section header 常规应 8 字节对齐。
        if (e_shoff % 8) != 0:
            raise RuntimeError(
                f"{path} has non-8-byte-aligned section header table: e_shoff={e_shoff}"
            )

        # 逐节校验文件范围，并检测“文件占位型 section”重叠。
        # 注意：SHT_NOBITS 不占用文件字节，跳过重叠判断。
        kShtNoBits = 8
        sectionRanges = []
        for sectionIndex in range(e_shnum):
            sh_off = e_shoff + sectionIndex * e_shentsize
            # Elf64_Shdr: <IIQQQQIIQQ
            (_, sh_type, _, _, sh_offset, sh_size, _, _, _, _) = struct.unpack_from(
                "<IIQQQQIIQQ", data, sh_off
            )
            if sh_size == 0 or sh_type == kShtNoBits:
                continue
            if sh_offset > len(data) or sh_size > (len(data) - sh_offset):
                raise RuntimeError(
                    f"{path} has out-of-range section data: index={sectionIndex} off={sh_offset} size={sh_size} file={len(data)}"
                )
            sectionRanges.append((sh_offset, sh_offset + sh_size, sectionIndex))

        sectionRanges.sort(key=lambda item: (item[0], item[1]))
        for rangeIndex in range(len(sectionRanges) - 1):
            left = sectionRanges[rangeIndex]
            right = sectionRanges[rangeIndex + 1]
            if right[0] < left[1]:
                raise RuntimeError(
                    f"{path} has overlapping file-backed sections: left={left[2]}({left[0]}..{left[1]}) right={right[2]}({right[0]}..{right[1]})"
                )

    # 打印结构检查通过信息。
    print(f"[INFO] ELF layout OK: {path.name} e_shoff={e_shoff} e_shnum={e_shnum} file_size={len(data)}")


def patchVmEngineSymbolsWithVmProtectRoute(
    project_root: Path,
    vmengine_dir: Path,
    env: dict,
    origin_so: Path,
    functions,
):
    # route4 L2 接管前置（走 VmProtect 主流程）：
    # 1) 先强制重编 native，拿到“干净” libvmengine.so；
    # 2) 用 VmProtect 主流程对 vmengine 执行 embed+patch，产出独立 libvmengine_patch.so；
    # 3) 临时把 patch 结果部署到 libvmengine.so 供 installDebug 打包；
    # 4) 回归后再恢复原始 libvmengine.so，避免污染后续构建输入。
    if not origin_so.exists():
        raise RuntimeError(f"origin so not found: {origin_so}")

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

    # VmProtect 主流程临时输出目录（保存 expanded/report 等中间文件）。
    route_out_dir = vmengine_dir / "app" / "build" / "intermediates" / "tmp_vmprotect_route"
    if route_out_dir.exists():
        shutil.rmtree(route_out_dir)
    route_out_dir.mkdir(parents=True, exist_ok=True)

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
        # 组装 VmProtect 主流程命令：
        # input=origin_so, vmengine=target_so, output=patched_so。
        cmd = [
            patch_tool,
            "--mode",
            "protect",
            "--input-so",
            str(origin_so),
            "--output-dir",
            str(route_out_dir),
            "--vmengine-so",
            str(target_so),
            "--output-so",
            str(patched_so),
            "--patch-origin-so",
            str(origin_so),
        ]
        # 加固路线必须显式传入函数集合。
        for function_name in functions:
            cmd.extend(["--function", function_name])

        # 执行主流程命令。
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
    # C. 安装 demo；
    # D. startActivity + logcat 判定。
    # 创建命令行参数解析器。
    parser = argparse.ArgumentParser(description="Run VmProtect + demo startup regression.")
    # 项目根目录参数，默认取脚本上一级目录。
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).parent.parent),
        help="Path to VmpProject root",
    )
    # App 包名。
    parser.add_argument("--package", default="com.example.demo")
    # 启动 Activity。
    parser.add_argument("--activity", default=".MainActivity")
    # 启动后等待秒数（等待 vm_init/route 日志稳定输出）。
    parser.add_argument("--sleep-seconds", type=float, default=3.0)
    # 是否启用 vmengine 导出 patch 流程。
    parser.add_argument(
        "--patch-vmengine-symbols",
        action="store_true",
        help="Patch libvmengine.so with VmProtect main route before installDebug",
    )
    # origin so 路径参数。
    parser.add_argument(
        "--patch-origin-so",
        default="",
        help="Origin .so path for patch stage; default uses demo libdemo.so",
    )
    # demo origin so（VmProtect input-so）路径参数。
    parser.add_argument(
        "--demo-origin-so",
        default="",
        help="Demo origin .so path for VmProtect input; default auto-build and detect libdemo.so",
    )
    # 函数导出清单参数。
    parser.add_argument(
        "--functions",
        nargs="+",
        default=DEFAULT_FUNCTIONS,
        help="Functions to export from VmProtect",
    )
    # 是否跳过 native 缓存清理（默认会清理，保证使用最新 so）。
    parser.add_argument(
        "--skip-native-clean",
        action="store_true",
        help="Skip auto cleanup of demo/vmengine native caches before build",
    )
    # 每个缓存目录最大清理等待时间（秒）。
    parser.add_argument(
        "--native-clean-timeout",
        type=float,
        default=30.0,
        help="Max seconds to wait while cleaning one native cache directory",
    )
    # 解析参数。
    args = parser.parse_args()

    # 归一化项目根目录为绝对路径。
    root = Path(os.path.abspath(args.project_root))
    # 关键子目录路径。
    vmprotect_dir = root / "VmProtect"
    vmengine_dir = root / "VmEngine"
    demo_dir = root / "demo"
    # 根目录有效性校验。
    if not vmprotect_dir.exists() or not vmengine_dir.exists() or not demo_dir.exists():
        raise RuntimeError(f"invalid project root: {root}")

    # 定位 adb。
    adb = locateAdb(root, [Path("demo/local.properties"), Path("VmEngine/local.properties")])
    # 定位 Java 运行时。
    java_home = locateJavaHome()
    # 复制环境变量用于子进程。
    env = os.environ.copy()
    # 强制使用定位到的 JAVA_HOME。
    env["JAVA_HOME"] = java_home

    # 清理前先停止 Gradle daemon，尽量释放 native 中间目录句柄。
    stopGradleDaemons([vmengine_dir, demo_dir], env)

    # 默认清理 native 缓存，避免旧 so 被复用导致回归误判。
    if args.skip_native_clean:
        print("[INFO] skip native cache cleanup by --skip-native-clean")
    else:
        cleanNativeCaches(root, timeoutSeconds=args.native_clean_timeout)

    # 1) 先确定本轮 origin so（默认来自 demo 中间产物）。
    demo_origin_so = None
    if args.demo_origin_so.strip():
        demo_origin_so = Path(args.demo_origin_so)
        if not demo_origin_so.is_absolute():
            demo_origin_so = root / demo_origin_so
        if not demo_origin_so.exists():
            raise RuntimeError(f"demo origin so not found: {demo_origin_so}")
        validateAndroidElfLayout(demo_origin_so)
    else:
        demo_origin_so = buildDemoOriginSo(demo_dir=demo_dir, env=env)

    # 2) Build/export from VmProtect（input-so 使用 demo origin so）。
    runVmProtectExport(root, env, args.functions, demo_origin_so)

    # 3) Optionally patch vmengine symbol exports before install.
    if args.patch_vmengine_symbols:
        # patch origin 路径对象化：未指定则默认沿用 demo origin so。
        if args.patch_origin_so.strip():
            origin = Path(args.patch_origin_so)
            if not origin.is_absolute():
                origin = root / origin
        else:
            origin = demo_origin_so
        # 执行 patch 流程。
        staged_for_install = patchVmEngineSymbolsWithVmProtectRoute(
            project_root=root,
            vmengine_dir=vmengine_dir,
            env=env,
            origin_so=origin,
            functions=args.functions,
        )
        try:
            # Skip native rebuild so patched output is not overwritten.
            # 关键点：安装 demo 时保持 vmengine patch 输出不被覆盖。
            runCmd(
                ["cmd", "/c", "gradlew.bat", "installDebug"],
                cwd=str(demo_dir),
                env=env,
            )
        finally:
            # 无论 install 成功/失败，都恢复原始 libvmengine.so。
            restoreVmEngineOutputs(staged_for_install)
    else:
        # 2) Install demo debug apk.
        # 不做 patch 时按默认安装流程（包含必要 native task 依赖）。
        runCmd(["cmd", "/c", "gradlew.bat", "installDebug"], cwd=str(demo_dir), env=env)

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

    # demo UI 启动健康判定：需要看到 bridge 输出的 fun_* 调用结果。
    expected_markers = [
        "VMP_DEMO: fun_add(",
        "VMP_DEMO: fun_global_mutable_state(",
        "VMP_DEMO: demo protect results",
    ]
    # 通用崩溃/链接失败 marker。
    fail_markers = [
        # vm_init 路径错误文案。
        "vm_init route4 init failed",
        "vm_init failed",
        "JNI_ERR",
        "Fatal signal",
        "FATAL EXCEPTION",
        "UnsatisfiedLinkError",
    ]

    # 收集缺失的必需成功 marker。
    missing = [marker for marker in expected_markers if marker not in log_text]
    # 收集通用失败 marker。
    found_fail = [marker for marker in fail_markers if marker in log_text]

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

