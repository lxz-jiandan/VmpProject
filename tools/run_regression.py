#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 端到端自动回归脚本：导出、patch、安装、启动、判定。
# - 加固链路位置：工程自动化测试入口。
# - 输入：项目路径、函数清单、patch 参数。
# - 输出：启动回归 PASS/FAIL 结论。
import argparse
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path


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


def run_cmd(cmd, cwd=None, env=None, check=True):
    # 统一子进程执行入口：
    # 1) 打印命令，便于 CI/本地回放；
    # 2) 透传 stdout/stderr；
    # 3) 在 check=True 时把非 0 退出码升级为异常。
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


def locate_patch_tool_exe(project_root: Path):
    candidates = [
        project_root / "VmProtect" / "cmake-build-debug" / "VmProtectPatchbay.exe",
        project_root / "VmProtect" / "cmake-build-debug" / "VmProtectPatchbay",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise RuntimeError("patch tool executable not found (build VmProtectPatchbay first)")


def locate_tool(name: str, candidates):
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    found = shutil.which(name)
    if found:
        return found
    raise RuntimeError(f"tool not found: {name}")


def locate_gcc_pair():
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
    for gcc, gpp in candidate_pairs:
        if Path(gcc).exists() and Path(gpp).exists():
            return gcc, gpp

    gcc = shutil.which("gcc")
    gpp = shutil.which("g++")
    if gcc and gpp:
        return gcc, gpp
    return None, None


def to_cmake_path(value: str):
    return value.replace("\\", "/")


def parse_local_properties(path: Path):
    sdk_dir = None
    if not path.exists():
        return sdk_dir
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("sdk.dir="):
            continue
        raw = stripped[len("sdk.dir="):]
        raw = raw.replace("\\\\", "\\").replace("\\:", ":")
        sdk_dir = raw
        break
    return sdk_dir


def locate_adb(project_root: Path):
    sdk_dir = parse_local_properties(project_root / "VmEngine" / "local.properties")
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


def extract_relevant_log_lines(log_text: str):
    keys = (
        "route_",
        "JNI_OnLoad",
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


def run_vmprotect_export(project_root: Path, env: dict, functions):
    # 对应旧 build_run.bat 的“离线导出阶段”：
    # - 编译 VmProtect；
    # - 运行 VmProtect 生成 txt/bin/expand so；
    # - 把产物同步到 VmEngine assets。
    vmprotect_dir = project_root / "VmProtect"
    vmengine_assets_dir = project_root / "VmEngine" / "app" / "src" / "main" / "assets"
    build_dir = vmprotect_dir / "cmake-build-debug"
    target_name = "VmProtect"
    exe_name = f"{target_name}.exe" if os.name == "nt" else target_name

    cmake_exe = locate_tool(
        "cmake",
        [
            r"C:\Program Files\JetBrains\CLion 2022.2.5\bin\cmake\win\bin\cmake.exe",
            r"D:\Clion2022\bin\cmake\win\bin\cmake.exe",
        ],
    )
    ninja_exe = locate_tool(
        "ninja",
        [
            r"C:\Program Files\JetBrains\CLion 2022.2.5\bin\ninja\win\ninja.exe",
            r"D:\Clion2022\bin\ninja\win\ninja.exe",
        ],
    )
    gcc_exe, gpp_exe = locate_gcc_pair()

    print(f"[INFO] cmake: {cmake_exe}")
    print(f"[INFO] ninja: {ninja_exe}")
    if gcc_exe and gpp_exe:
        print(f"[INFO] gcc: {gcc_exe}")
        print(f"[INFO] g++: {gpp_exe}")
        mingw_bin = str(Path(gcc_exe).parent)
        env = env.copy()
        env["PATH"] = mingw_bin + os.pathsep + env.get("PATH", "")

    build_dir.mkdir(parents=True, exist_ok=True)
    cache = build_dir / "CMakeCache.txt"
    cmake_files = build_dir / "CMakeFiles"
    if cache.exists():
        cache.unlink()
    if cmake_files.exists():
        shutil.rmtree(cmake_files)

    configure_cmd = [
        cmake_exe,
        "-G",
        "Ninja",
        "-S",
        to_cmake_path(str(vmprotect_dir)),
        "-B",
        to_cmake_path(str(build_dir)),
        "-DCMAKE_BUILD_TYPE=Debug",
        f"-DCMAKE_MAKE_PROGRAM={to_cmake_path(ninja_exe)}",
    ]
    if gcc_exe and gpp_exe:
        configure_cmd.append(f"-DCMAKE_C_COMPILER={to_cmake_path(gcc_exe)}")
        configure_cmd.append(f"-DCMAKE_CXX_COMPILER={to_cmake_path(gpp_exe)}")

    run_cmd(configure_cmd, cwd=str(vmprotect_dir), env=env)
    run_cmd(
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

    target_exe = build_dir / exe_name
    if not target_exe.exists():
        raise RuntimeError(f"missing executable: {target_exe}")
    run_cmd([str(target_exe), *functions], cwd=str(build_dir), env=env)

    if not vmengine_assets_dir.exists():
        print(f"[WARN] asset dir not found: {vmengine_assets_dir}")
        return

    required_common = [
        "libdemo_expand.so",
        "branch_addr_list.txt",
    ]
    for filename in required_common:
        src = build_dir / filename
        if not src.exists():
            raise RuntimeError(f"missing exported file: {src}")
        shutil.copy2(src, vmengine_assets_dir / filename)

    for func_name in functions:
        for suffix in (".txt", ".bin"):
            filename = func_name + suffix
            src = build_dir / filename
            if not src.exists():
                raise RuntimeError(f"missing exported file: {src}")
            shutil.copy2(src, vmengine_assets_dir / filename)

    print(
        "[OK] exported libdemo_expand.so + branch_addr_list.txt + "
        f"function txt/bin to {vmengine_assets_dir}"
    )


def find_vmengine_so_outputs(vmengine_dir: Path):
    pattern = vmengine_dir / "app" / "build" / "intermediates" / "cxx" / "Debug"
    outputs = list(pattern.glob("*/obj/arm64-v8a/libvmengine.so"))
    return sorted(outputs)


def find_vmengine_cmake_so_output(vmengine_dir: Path):
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


def remove_existing_vmengine_outputs(vmengine_dir: Path):
    removed = []
    for path in [*find_vmengine_so_outputs(vmengine_dir), find_vmengine_cmake_so_output(vmengine_dir)]:
        if not path.exists():
            continue
        path.unlink()
        removed.append(path)
        print(f"[INFO] removed stale native output: {path}")
    return removed


def validate_android_elf_layout(path: Path):
    data = path.read_bytes()
    if len(data) < 0x40:
        raise RuntimeError(f"{path} is too small to be ELF64")
    if data[0:4] != b"\x7fELF":
        raise RuntimeError(f"{path} is not an ELF file")
    if data[4] != 2:
        raise RuntimeError(f"{path} is not ELF64")

    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]

    if e_phnum > 0:
        ph_size = e_phentsize * e_phnum
        if e_phentsize == 0 or e_phoff + ph_size > len(data):
            raise RuntimeError(
                f"{path} has invalid program header table: off={e_phoff} size={ph_size} file={len(data)}"
            )
    if e_shnum > 0:
        sh_size = e_shentsize * e_shnum
        if e_shentsize == 0 or e_shoff + sh_size > len(data):
            raise RuntimeError(
                f"{path} has invalid section header table range: off={e_shoff} size={sh_size} file={len(data)}"
            )
        if (e_shoff % 8) != 0:
            raise RuntimeError(
                f"{path} has non-8-byte-aligned section header table: e_shoff={e_shoff}"
            )

    print(f"[INFO] ELF layout OK: {path.name} e_shoff={e_shoff} e_shnum={e_shnum} file_size={len(data)}")


def patch_vmengine_symbols_patchbay(
    project_root: Path,
    vmengine_dir: Path,
    env: dict,
    donor_so: Path,
    impl_symbol: str,
    only_fun_java: bool,
):
    # route4 L2 接管前置：
    # 1) 先强制重编 native，拿到“干净” libvmengine.so；
    # 2) 用 patch 工具把 donor 导出注入到 vmengine；
    # 3) 回写 patched so，供 installDebug 打包。
    if not donor_so.exists():
        raise RuntimeError(f"donor so not found: {donor_so}")

    remove_existing_vmengine_outputs(vmengine_dir)

    # Force native rebuild so we always patch a fresh baseline .so, not a previously patched one.
    run_cmd(
        ["cmd", "/c", "gradlew.bat", "externalNativeBuildDebug", "--rerun-tasks"],
        cwd=str(vmengine_dir),
        env=env,
    )

    patch_tool = locate_patch_tool_exe(project_root)
    targets = find_vmengine_so_outputs(vmengine_dir)
    if not targets:
        raise RuntimeError("no vmengine so outputs found under app/build/intermediates/cxx/Debug")

    for target_so in targets:
        validate_android_elf_layout(target_so)
        patched_so = target_so.with_suffix(".patched.so")
        cmd = [
            patch_tool,
            "export_alias_from_patchbay",
            str(target_so),
            str(donor_so),
            str(patched_so),
            impl_symbol,
            "--allow-validate-fail",
        ]
        if only_fun_java:
            cmd.append("--only-fun-java")
        run_cmd(cmd, cwd=str(project_root), env=env)
        shutil.move(str(patched_so), str(target_so))
        validate_android_elf_layout(target_so)
        print(f"[OK] patched vmengine so: {target_so}")


def main():
    # 脚本主流程：
    # A. VmProtect 导出；
    # B. (可选) patch vmengine 导出；
    # C. 安装 VmEngine；
    # D. startActivity + logcat 判定。
    parser = argparse.ArgumentParser(description="Run VmProtect + VmEngine startup regression.")
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).parent.parent),
        help="Path to VmpProject root",
    )
    parser.add_argument("--package", default="com.example.vmengine")
    parser.add_argument("--activity", default=".MainActivity")
    parser.add_argument("--sleep-seconds", type=float, default=3.0)
    parser.add_argument(
        "--patch-vmengine-symbols",
        action="store_true",
        help="Patch libvmengine.so with export_alias_from_patchbay before installDebug",
    )
    parser.add_argument(
        "--patch-donor-so",
        default="VmProtect/libdemo.so",
        help="Donor .so path (relative to project root or absolute)",
    )
    parser.add_argument(
        "--patch-impl-symbol",
        default="z_takeover_dispatch_by_id",
        help="Implementation symbol used by export_alias_from_patchbay",
    )
    parser.add_argument(
        "--patch-all-exports",
        action="store_true",
        help="Patch all donor exports (default only patches fun_* and Java_*)",
    )
    parser.add_argument(
        "--functions",
        nargs="+",
        default=DEFAULT_FUNCTIONS,
        help="Functions to export from VmProtect",
    )
    args = parser.parse_args()

    root = Path(os.path.abspath(args.project_root))
    vmprotect_dir = root / "VmProtect"
    vmengine_dir = root / "VmEngine"
    if not vmprotect_dir.exists() or not vmengine_dir.exists():
        raise RuntimeError(f"invalid project root: {root}")

    adb = locate_adb(root)
    java_home = locate_java_home()
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home

    # 1) Build/export from VmProtect (build_run.bat logic implemented in Python).
    run_vmprotect_export(root, env, args.functions)

    # 2) Optionally patch vmengine symbol exports before install.
    if args.patch_vmengine_symbols:
        donor = Path(args.patch_donor_so)
        if not donor.is_absolute():
            donor = root / donor
        patch_vmengine_symbols_patchbay(
            project_root=root,
            vmengine_dir=vmengine_dir,
            env=env,
            donor_so=donor,
            impl_symbol=args.patch_impl_symbol,
            only_fun_java=not args.patch_all_exports,
        )

        # Skip native rebuild so patched output is not overwritten.
        run_cmd(
            ["cmd", "/c", "gradlew.bat", "installDebug", "-x", "externalNativeBuildDebug"],
            cwd=str(vmengine_dir),
            env=env,
        )
    else:
        # 2) Install VmEngine debug apk.
        run_cmd(["cmd", "/c", "gradlew.bat", "installDebug"], cwd=str(vmengine_dir), env=env)

    # 3) Start activity and collect logs.
    component = f"{args.package}/{args.activity}"
    run_cmd([adb, "logcat", "-c"])
    run_cmd([adb, "shell", "am", "force-stop", args.package], check=False)
    run_cmd([adb, "shell", "am", "start", "-W", "-n", component])
    time.sleep(args.sleep_seconds)
    log_proc = run_cmd([adb, "logcat", "-d", "-t", "2500"], check=False)
    log_text = log_proc.stdout or ""

    print("\n=== Filtered Log Lines ===")
    for line in extract_relevant_log_lines(log_text):
        print(line)

    expected_markers = [
        # 这些标记共同定义了“启动链路健康”。
        "route_unencoded_text result=1",
        "route_native_vs_vm result=1",
        "route_encoded_asset_bin result=1",
        "route_encoded_expand_so result=1",
        "route_symbol_takeover result=1",
    ]
    embedded_ok_prefix = "route_embedded_expand_so result=1"
    embedded_state_0 = "route_embedded_expand_so result=1 state=0"
    embedded_state_1 = "route_embedded_expand_so result=1 state=1"
    embedded_fail_markers = [
        "route_embedded_expand_so result=0",
        "route_embedded_expand_so result=1 state=2",
    ]
    fail_markers = [
        "JNI_OnLoad route regression failed",
        "JNI_ERR",
        "Fatal signal",
        "FATAL EXCEPTION",
        "UnsatisfiedLinkError",
    ]

    missing = [marker for marker in expected_markers if marker not in log_text]
    if embedded_ok_prefix not in log_text:
        missing.append(embedded_ok_prefix)
    found_fail = [marker for marker in fail_markers if marker in log_text]
    found_fail.extend([marker for marker in embedded_fail_markers if marker in log_text])

    print("\n=== Regression Result ===")
    if missing:
        print("Missing expected markers:")
        for marker in missing:
            print(f"  - {marker}")
    if found_fail:
        print("Detected failure markers:")
        for marker in found_fail:
            print(f"  - {marker}")

    if embedded_state_0 in log_text:
        print("route_embedded_expand_so: active (state=0).")
    elif embedded_state_1 in log_text:
        print("route_embedded_expand_so: skipped (state=1, payload not embedded).")

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
