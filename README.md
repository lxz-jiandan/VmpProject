# VmpProject

面向 `arm64-v8a` so 的 VMP 加固实验工程。当前仓库由多个子项目协同组成，核心目标是把目标 so 的函数翻译为 VM 可执行形态，并通过导出接管把调用转发到 VM 执行路径。

## 1. 当前状态（2026-02）

- 已将 `VmProtect` 从“固定 demo 流程”改为 `CLI + policy` 配置模式。
- 已建立 Python 端到端回归脚本（替代手工串行执行 `build_run.bat + gradle + startActivity + logcat`）。
- 已落地 Route4 方案基础能力：
- `L1`：把 `libdemo_expand.so` 追加到 `libvmengine.so` 尾部（embed）。
- `L2`：基于 PatchBay 的符号注入与导出接管（由 `VmProtectPatchbay` 执行后处理）。
- `L2.5`：基于清单自动生成导出桩汇编与符号映射头（`tools/gen_takeover_stubs.py`）。
- demo 工程支持把受保护 `libvmengine.so` 重命名注入为 `libdemo.so`，并在 `onCreate` 主动 JNI 验证返回值。

## 2. 仓库结构

- `VmProtect`
- 离线分析与翻译导出工具（`VmProtect.exe`）。
- PatchBay 后处理工具（`VmProtectPatchbay.exe`）。
- 输入目标 so，输出 `*.txt/*.bin`、`branch_addr_list.txt`、`libdemo_expand.so`、覆盖率看板等。
- `VmEngine`
- Android App + Native VM 引擎。
- 运行时加载/调度 VM payload，执行 Route 回归，支持符号接管。
- `demo`
- 最小验证 App。
- 构建时注入受保护 `libdemo.so` 与参考 `libdemo_ref.so`，JNI 对照校验行为一致性。
- `tools`
- Python 自动化脚本、生成器与符号清单。

## 3. 环境要求

- OS：Windows（当前脚本路径与调用方式以 Windows 为主）。
- Python：`python` 可直接调用（建议 3.10+）。
- Android SDK：可用 `adb`，且 `VmEngine/local.properties` 或 `demo/local.properties` 配置了 `sdk.dir`。
- JDK：`JAVA_HOME` 可用，或本机安装 Android Studio（脚本可自动探测 `jbr`）。
- CMake/Ninja：可在 PATH 中找到，或安装 CLion/Android Studio 自带版本。
- NDK：由 Android Gradle 工程使用（`compileSdk 34`，`abiFilters arm64-v8a`）。

## 4. 快速开始（推荐）

在仓库根目录执行：

```powershell
python tools/run_regression.py --project-root .
```

该命令会自动完成：

- 构建并运行 `VmProtect`，导出函数产物到 `VmEngine/app/src/main/assets`。
- 安装 `VmEngine` debug 包。
- 启动 `com.example.vmengine/.MainActivity`。
- 抓取 logcat 并按关键标记判定 PASS/FAIL。

## 5. 常用流程

### 5.1 仅跑 demo JNI 冒烟验证

```powershell
python tools/run_demo_vmp_verify.py --project-root .
```

可选传入受保护 so 路径（覆盖默认自动发现）：

```powershell
python tools/run_demo_vmp_verify.py --project-root . --protected-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine.so
```

### 5.2 使用 PatchBay 进行符号注入后再回归

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

可选参数：

- `--patch-donor-so`：donor so 路径（默认 `VmProtect/libdemo.so`）。
- `--patch-impl-symbol`：注入导出统一指向的实现符号（默认 `z_takeover_dispatch_by_id`）。
- `--patch-all-exports`：默认只补 `fun_*` 与 `Java_*`，加此开关可补全所有 donor 导出。

### 5.3 单独运行 VmProtect CLI

`VmProtect` 支持位置参数与显式参数：

```powershell
VmProtect\cmake-build-debug\VmProtect.exe fun_add fun_for
VmProtect\cmake-build-debug\VmProtect.exe --policy VmProtect/vmprotect.policy.example
VmProtect\cmake-build-debug\VmProtect.exe --help
```

Policy 示例文件：`VmProtect/vmprotect.policy.example`。

### 5.4 保留历史批处理入口

旧流程脚本仍在：

```powershell
VmProtect\build_run.bat
```

说明：当前推荐优先使用 Python 脚本（`tools/run_regression.py`），逻辑更完整且输出更直观。

### 5.5 Gradle 直连 VmProtect.exe（Stage3）

`VmEngine/app/build.gradle` 已新增 Debug 任务 `runVmProtectPipelineDebug`：

- 在 `externalNativeBuildDebug` 之后直接调用 `VmProtect.exe`；
- 同一次调用内完成：
- 函数导出产物生成（`txt/bin/branch_addr_list/libdemo_expand.so`）；
- `libdemo_expand.so` embed 到 `libvmengine.so`；
- 通过 PatchBay 补全导出（默认使用 `VmProtectPatchbay.exe`，仅 `fun_*` / `Java_*`）。

开启方式：

```powershell
cd VmEngine
gradlew.bat installDebug -PvmpEnabled=true
```

常用可选参数：

- `-PvmpToolExe=<path>`：`VmProtect.exe` 路径（默认 `VmProtect/cmake-build-debug/VmProtect.exe`）。
- `-PvmpAutoBuildTool=true`：自动构建 `VmProtect.exe` + `VmProtectPatchbay.exe`（默认关闭）。
- `-PvmpInputSo=<path>`：输入 so（默认 `VmProtect/libdemo.so`）。
- `-PvmpPatchDonorSo=<path>`：patch donor so（默认 `VmProtect/libdemo.so`）。
- `-PvmpPatchToolExe=<path>`：外部 patch 工具路径（可选；不传则默认使用 `VmProtectPatchbay.exe`）。
- `-PvmpPatchImplSymbol=<name>`：导出统一指向实现符号（默认 `z_takeover_dispatch_by_id`）。
- `-PvmpPatchAllExports=true`：补齐 donor 全部导出（默认仅 `fun_*` / `Java_*`）。
- `-PvmpFunctions=fun_add,fun_for,...`：覆盖默认函数清单。
- `-PvmpPolicy=<path>`：传入 policy 文件。

## 6. Route4 相关说明

### 6.1 Route4 L1（尾部 payload embed）

- CMake 选项：`VMENGINE_ROUTE4_EMBED_PAYLOAD=ON`（默认开启）。
- 构建 `VmEngine` 时，`tools/embed_expand_into_vmengine.py` 会在 `POST_BUILD` 把 `assets/libdemo_expand.so` 附加到 `libvmengine.so`。
- `VmEngine/app/build.gradle` 已配置 `keepDebugSymbols`，避免打包阶段 strip 破坏尾部 payload。

### 6.2 Route4 L2（PatchBay 符号注入）

- `VmEngine` 在 `.vmp_patchbay` 段预留 dynsym/dynstr/hash/versym 空间。
- `VmProtectPatchbay export_alias_from_patchbay`（或外部兼容 patch 工具）把 donor 导出映射为目标 so 导出，并统一指向接管实现符号。
- 该方式目标是减少对 text/data 布局扰动，简化后处理 patch。

### 6.3 Route4 L2.5（导出桩生成）

- 清单：`tools/takeover_symbols.json`
- 生成器：`tools/gen_takeover_stubs.py`
- 产物：
- `VmEngine/app/src/main/cpp/generated/zTakeoverStubs.generated.S`
- `VmEngine/app/src/main/cpp/generated/zTakeoverSymbols.generated.h`
- `VmEngine/app/src/main/cpp/CMakeLists.txt` 会在配置阶段自动调用生成器。

## 7. 回归判定标记

`tools/run_regression.py` 主要检查以下 marker：

- `route_unencoded_text result=1`
- `route_native_vs_vm result=1`
- `route_encoded_asset_bin result=1`
- `route_encoded_expand_so result=1`
- `route_symbol_takeover result=1`
- `route_embedded_expand_so result=1 state=0|1`

失败关键字包括：

- `JNI_ERR`
- `Fatal signal`
- `FATAL EXCEPTION`
- `UnsatisfiedLinkError`

demo 冒烟脚本（`tools/run_demo_vmp_verify.py`）检查 `VMP_DEMO_CHECK PASS:`。

## 8. 关键产物

### 8.1 VmProtect 输出（默认在 `VmProtect/cmake-build-debug`）

- `<fun>.txt`
- `<fun>.bin`
- `branch_addr_list.txt`
- `libdemo_expand.so`
- `coverage_report.md`

### 8.2 VmEngine 关键输入目录

- `VmEngine/app/src/main/assets`

### 8.3 demo 注入目录（构建时自动生成）

- `demo/app/build/generated/vmpJniLibs/main/arm64-v8a/libdemo.so`
- `demo/app/build/generated/vmpJniLibs/main/arm64-v8a/libdemo_ref.so`

## 9. 故障排查

- 安装失败 `INSTALL_FAILED_USER_RESTRICTED`
- 设备侧仍限制安装，需在开发者选项放开 USB 安装/调试安装策略。
- 脚本报 `adb not found`
- 检查 `local.properties` 中 `sdk.dir` 或设置 `ANDROID_SDK_ROOT`。
- `patch tool executable not found`
- 默认使用 `VmProtect/cmake-build-debug/VmProtectPatchbay.exe`，可传 `-PvmpPatchToolExe=<path>` 覆盖。
- `protected vmengine so not found`
- 先构建 `VmEngine` native，或在 demo 构建时传 `-PprotectedDemoSo=<path>`。

## 10. 参考文档

- 脚本细节：`tools/README.md`
- 策略模板：`VmProtect/vmprotect.policy.example`
- Route4 生成清单：`tools/takeover_symbols.json`
