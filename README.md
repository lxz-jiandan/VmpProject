﻿# VmProject

VmProject 是一个面向 Android ARM64 `so` 的离线加固与运行时接管工程。
当前主路线是 `route4`，由两个核心子系统组成：

- `VmProtect`：离线工具，负责函数分析、导出 VM payload、嵌入 `VmEngine`、可选符号接管补丁。
- `VmEngine`：运行时引擎内核，负责从自身读取嵌入 payload、装载 expand so、执行 VM 指令并对外接管调用。

本文按当前仓库实现编写，目标是让新同学快速理解：

- 工程到底做了什么。
- 模块如何分层。
- 保护链路如何从输入 so 走到设备运行。
- 当前实现中的三个核心难点如何落地。

## 一、项目全局视角

### 1.1 route4 端到端流程

1. `VmProtect` 读取 origin so（例如 `demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so`），解析目标函数。
2. 生成函数编码产物（`*.txt` / `*.bin`）和 `libdemo_expand.so`。
3. 将 `libdemo_expand.so` 追加嵌入到 `vmengine so` 尾部。
4. 可选执行 patchbay：把 origin 导出名追加到 `vmengine` 的 dynsym，并把这些导出绑定到 key 路由跳板。
5. `demo/app` 打包阶段把受保护 `vmengine so` 覆盖为 `libdemo.so`，运行时由 `libbridge.so` 链接期依赖加载。
6. App 启动后，`VmEngine` 自动 `vm_init()`：
   - 从自身尾部读取嵌入 payload；
   - 直接从内存装载 expand so；
   - 预热函数缓存与共享分支地址；
   - 注册 `soId -> soName` 路由；
   - 对外提供 `vm_takeover_dispatch_by_key(...)`。
7. `bridge JNI -> fun_*` 调用时，先命中跳板，再进入 `dispatch_by_key`，最终由 VM 执行对应函数，结果回传 Java 展示。

### 1.2 仓库顶层目录

- `VmProtect`：离线工具（Windows CMake 可执行程序）。
- `VmEngine`：native VM 运行时与加固构建管线（无 Java UI 入口）。
- `demo`：设备侧展示与回归工程（`libdemo.so + libbridge.so`，界面展示 `expected/actual/status` 列和汇总）。
- `shared`：共享协议与通用头文件。
- `tools`：回归与构建辅助脚本（核心是 `tools/run_regression.py`）。

## 二、VmProtect（离线系统）

### 2.1 职责边界

`VmProtect` 负责离线阶段的完整流水线：

1. 解析输入 ELF，定位目标函数。
2. 做覆盖率分析与翻译可行性检查。
3. 导出函数 payload（txt/bin）并打包 `libdemo_expand.so`。
4. 把 expand so 嵌入 `vmengine so`。
5. 可选做符号接管注入，输出最终 `--output-so`。

入口文件是 `VmProtect/app/zMain.cpp`。

### 2.2 架构分层（当前实现）

#### L0 基础层

路径：`VmProtect/modules/base/core`

职责：无业务语义的通用能力。

核心组件：

- `zFile.*`：文件读写、目录创建、路径存在性。
- `zLog.*`：日志输出。
- `zBytes.*`：字节区间与写入辅助。
- `zCodec.*` / `zBitCodec.*`：编解码工具。
- `zChecksum.*` / `zHash.*`：校验与 hash。
- `zEmbeddedPayloadTail.*`：payload footer 协议处理。

#### L1 格式与解析层

路径：

- `VmProtect/modules/elfkit/core`
- `VmProtect/modules/elfkit/api`
- `VmProtect/modules/elfkit/patchbayModel`

职责：

- ELF 读取、函数视图、反汇编翻译准备。
- 函数编码产物组织与 expand so 打包。
- patch 场景下的 ELF 模型、布局与校验。

#### L2 领域能力层

路径：

- `VmProtect/modules/patchbay/format`
- `VmProtect/modules/patchbay/domain`
- `VmProtect/modules/patchbay/app`

职责：

- origin 导出收集。
- 命名规则和冲突校验。
- alias 构建（dynsym/dynstr/versym）。
- GNU/SysV hash 重建。
- patch 落盘（ELF 重建单路径）。

#### L3 流程编排层

路径：`VmProtect/modules/pipeline/core`

职责：

- CLI 参数解析。
- 配置合并与合法性校验。
- 覆盖率分析与报告。
- 导出产物构建。
- embed + patch 编排。

#### L4 应用入口层

路径：`VmProtect/app/zMain.cpp`

职责：

- 主命令入口。
- patchbay 子命令分流。

### 2.3 CLI 与模式约束

`VmProtect/modules/pipeline/core/zPipelineCli.cpp` 当前由 `--mode` 显式控制路线：

- `--mode coverage`：仅覆盖率。
- `--mode export`：覆盖率 + 导出。
- `--mode protect`：覆盖率 + 导出 + vmengine embed/patch。

`--mode protect` 下，核心参数必须显式传入：

- `--input-so`
- `--vmengine-so`
- `--output-so`
- `--function`（至少一个）

可选 patch 参数：

- `--patch-origin-so`：提供 origin 导出集合，用于符号接管注入。

### 2.4 流程细节

#### 覆盖率阶段

实现：`VmProtect/modules/pipeline/core/zPipelineCoverage.cpp`

当前已拆分为两个职责：

- `runCoverageAnalyzeFlow(...)`：统计指令支持率 + 准备翻译状态。
- `runCoverageReportFlow(...)`：仅写 `coverage_report.md`。

这样可以保证“分析逻辑”与“报告落盘”解耦。

#### 导出阶段

实现：`VmProtect/modules/pipeline/core/zPipelineExport.cpp`

关键动作：

1. 校验目标函数可翻译。
2. 归并共享分支地址表。
3. 逐函数生成 `<name>.txt` 和 `<name>.bin`。
4. 使用 `zSoBinBundleWriter::writeExpandedSo(...)` 生成 `libdemo_expand.so`。

`libdemo_expand.so` 结构可以简单理解为：

- 原始输入 so 主体不改；
- 在文件尾部追加 bundle 区（payload 索引和数据）。

#### protect 阶段（embed + 可选 patch）

实现：`VmProtect/modules/pipeline/core/zPipelinePatch.cpp`

- embed：把 `libdemo_expand.so` 追加到 `vmengine so` 尾部并写 footer。
- patch（当传 `--patch-origin-so`）：调用领域 API `runPatchbayExportAliasFromOrigin(...)` 完成符号接管注入。

### 2.5 核心难点一：符号注入原理（当前 key 路由）

这一段是离线加固最关键的协议实现，对应目录 `VmProtect/modules/patchbay/domain`。

#### 难点本质

我们要把 origin 导出名“嫁接”到 vmengine 上，但运行时不能靠固定槽位，也不能依赖硬编码条目数量。
因此当前方案是：

- 每个 alias 导出只携带业务路由键：`symbolKey + soId`。
- 由统一 `vm_takeover_dispatch_by_key` 在运行时完成最终分发。

#### 具体落地步骤

1. `zPatchbayOrigin.cpp`
   - 收集 origin 动态导出。
   - 稳定排序，保证构建结果可复现。
   - 生成 `AliasPair`：
     - `exportName = origin 导出名`
     - `exportKey = origin.st_value`
     - `soId = 1`（当前单模块默认值）

2. `zPatchbayAliasTables.cpp`
   - 追加 alias 到 dynsym/dynstr/versym。
   - alias 先占位 `st_value=0`。
   - 记录 `pendingTakeoverBindings`：`symbolIndex -> {symbolKey, soId}`。
   - 解析 `vm_takeover_dispatch_by_key` 地址供后续跳板注入。

3. `zPatchbayPatchApply.cpp`
   - 为每个 pending binding 生成 ARM64 跳板：
     - `x2 = symbolKey`
     - `x3 = soId`
     - `x16 = dispatchAddr`
     - `br x16`
   - 回填 alias dynsym 的 `st_value` 指向跳板地址。
   - 重建 dynsym/dynstr/versym/gnu hash（以及可选 sysv hash）。
   - 更新 `.dynamic` 指针并同步 section 视图。
   - 对 RELRO 执行收口：把可写 PT_LOAD 的 `p_memsz` 至少扩到 `relro_end`。

#### 为什么这样更稳

- 不依赖固定 128 槽位。
- 不依赖历史中间跳板符号。
- 为后续多 so 扩展预留了 `soId` 维度。
- 跳板统一、接口面更窄，运行时协议更清晰。

## 三、VmEngine（运行时内核）

### 3.1 职责边界

`VmEngine` 负责把离线产物真正执行起来（`VmEngine/app` 当前不承担 Java UI）：

1. so 加载时自动触发初始化。
2. 从自身尾部读取 embedded payload。
3. 从内存装载 expand so。
4. 预热函数缓存和共享分支地址。
5. 建立 key 路由接管入口。

### 3.2 运行时分层（CMake 视角）

文件：`VmEngine/app/src/main/cpp/CMakeLists.txt`

- `vm_l0_foundation`：`zLog`、`zAssetManager`、`zLinker`、`zFileBytes`。
- `vm_l1_format`：`zFunction`、`zFunctionData`、`zSoBinBundle`、`zEmbeddedPayload`、`zPatchBay`。
- `vm_l2_domain`：`zVmEngine`、`zVmOpcodes`、`zTypeManager`、`zSymbolTakeover`。
- `vm_l3_pipeline`：`zPipelineConfig`、`zVmInitCore`、`zVmInitLifecycle`。

最终合并为 `libvmengine.so`。

### 3.3 初始化生命周期

实现：`VmEngine/app/src/main/cpp/zVmInitLifecycle.cpp`

状态机：

- `0` 未初始化
- `1` 初始化中
- `2` 初始化成功
- `3` 初始化失败

`vm_library_ctor` 会在 so 加载后自动调用 `vm_init()`。

### 3.4 route4 初始化核心

实现：`VmEngine/app/src/main/cpp/zVmInitCore.cpp`

`runVmInitCore(JNIEnv* env)` 当前顺序：

1. 清空旧缓存与接管状态。
2. `route_embedded_expand_so`：
   - 定位当前 vmengine so；
   - 从尾部读取 payload；
   - `LoadLibraryFromMemory(...)` 装载 expand so；
   - 预热函数缓存与共享分支地址。
3. `route_symbol_takeover`：
   - 注册默认模块 `soId=1 -> libdemo_expand_embedded.so`。

成功日志关键 marker：

- `route_embedded_expand_so result=1 state=0`
- `route_symbol_takeover result=1`

### 3.5 key 路由接管闭环

实现：`VmEngine/app/src/main/cpp/zSymbolTakeover.cpp`

- `zSymbolTakeoverRegisterModule(soId, soName)`：注册模块路由。
- `vm_takeover_dispatch_by_key(a,b,symbolKey,soId)`：统一接管入口。

分发逻辑：

1. 若 vm 未初始化，先惰性 `vm_init()`。
2. 用 `soId` 查 `soName`。
3. 调 `zVmEngine::execute(..., soName, symbolKey, params)`。

注意：当前 `symbolKey` 约定使用 origin `st_value`，因此可直接作为 `funAddr` 命中 VM 函数缓存。

### 3.6 核心难点二：VmEngine 对 `BL` 指令的处理

相关文件：

- 离线侧：`VmProtect/modules/pipeline/core/zPipelineExport.cpp`
- 运行时：`VmEngine/app/src/main/cpp/zVmEngine.cpp`
- opcode：`VmEngine/app/src/main/cpp/zVmOpcodes.cpp`

#### 难点本质

`BL` 既要保留 ARM64 ABI（参数寄存器、返回寄存器、x8 隐式参数），又要跨“离线地址 -> 运行时地址”完成稳定重定位。

#### 当前实现

1. 离线阶段
   - 把每个函数中的 `BL` 目标 remap 成 `branchId`。
   - 全局共享地址表写入 `libdemo_expand.so`。

2. 初始化阶段
   - 将共享地址表绑定到对应 `soName`。
   - 执行前按已加载模块 `base` 修正为进程绝对地址。

3. 执行阶段（`op_bl`）
   - 读取 `branchId`，查 `ctx->branch_addr_list[branchId]`。
   - 用 `call_native_with_x8(...)` 显式桥接 `x0..x7 + x8` 后 `blr` 调用。
   - 返回值写回 `x0`。

#### 风险控制

- `branchId` 越界或地址表缺失时立即停机并报错，避免跳转到非法地址。

### 3.7 核心难点三：VmEngine 自定义 Linker 实现

实现：`VmEngine/app/src/main/cpp/zLinker.cpp`

#### 难点本质

这个 linker 决定 route4 在设备上的加载稳定性。它既要支持离线 patch 后的 ELF，又要支持内存直装场景。

#### 当前加载主流程

`LoadLibrary(...)` / `LoadLibraryFromMemory(...)` 最终都收敛到 `LoadPreparedElf(...)`，阶段顺序是：

1. `ReadElf`
2. `ReserveAddressSpace`
3. `LoadSegments`
4. `FindPhdr`
5. `UpdateSoinfo`
6. `PrelinkImage`
7. `ProtectSegments`
8. `LinkImage`

#### 动态段与符号解析

`ParseDynamic(...)` 解析并缓存：

- `DT_SYMTAB` / `DT_STRTAB`
- `DT_GNU_HASH` / `DT_HASH`
- `DT_RELA` / `DT_JMPREL`
- `DT_INIT` / `DT_INIT_ARRAY`
- `DT_NEEDED`

符号查找顺序：

1. 本 so（GNU hash 优先，再 SysV hash）
2. `DT_NEEDED` 库（`RTLD_NOLOAD + dlsym`）
3. `RTLD_DEFAULT`

#### 重定位支持（AArch64）

`ProcessRelaRelocation(...)` 重点支持：

- `R_AARCH64_ABS64`
- `R_AARCH64_GLOB_DAT`
- `R_AARCH64_JUMP_SLOT`
- `R_AARCH64_RELATIVE`
- `R_AARCH64_IRELATIVE`

## 四、构建与回归

### 4.1 构建 VmProtect

```powershell
cmake -S VmProtect -B VmProtect/cmake-build-debug -G Ninja
cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12
```

帮助命令：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe --help
```

### 4.2 构建 VmEngine Native

```powershell
cd VmEngine
./gradlew.bat externalNativeBuildDebug --rerun-tasks
```

### 4.3 构建 demo origin so（input-so 来源）

```powershell
cd demo
./gradlew.bat externalNativeBuildDebug --rerun-tasks
```

默认 input-so 取 `demo` 的中间产物：

- `demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so`

### 4.4 常用命令

仅导出：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --mode export `
  --input-so demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so `
  --function fun_add `
  --function fun_for
```

完整 protect：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --mode protect `
  --input-so demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so `
  --vmengine-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine.so `
  --output-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine_patch.so `
  --patch-origin-so demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so `
  --function fun_add `
  --function fun_for
```

### 4.5 设备回归命令

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

或快速安装启动回归：

```powershell
python tools/run_install_start_regression.py --project-root . --rerun-tasks
```

通过判据：

- `VMP_DEMO: demo protect results`
- `VMP_DEMO: fun_add(`
- `VMP_DEMO: fun_global_mutable_state(`

## 五、常见排障路径

1. `route_embedded_expand_so` 失败
   - 重点看 `VmEngine/app/src/main/cpp/zEmbeddedPayload.cpp` 与 `zVmInitCore.cpp`。
   - 检查 footer 解析、payload 读取、内存装载。

2. `route_symbol_takeover` 失败
   - 重点看 `VmEngine/app/src/main/cpp/zSymbolTakeover.cpp` 与 `zVmInitCore.cpp`。
   - 检查 `soId -> soName` 注册是否成功，`dispatch_by_key` 是否可达。

3. `op_bl invalid branch target`
   - 重点看 `VmProtect/modules/pipeline/core/zPipelineExport.cpp` 导出的共享地址表。
   - 重点看 `VmEngine/app/src/main/cpp/zVmEngine.cpp` 的 base 地址修正。

4. patch 后 ELF 校验失败
   - 重点看 `VmProtect/modules/patchbay/domain/zPatchbayPatchApply.cpp`。
   - 检查 dyn 表重建、`DT_*` 回写、PT_LOAD/RELRO 收口是否一致。

## 六、面向后续扩展的约束

当前 key 路由已具备多 so 扩展基础：

- 跳板协议天然携带 `soId + symbolKey`。
- 运行时分发表是 `soId -> soName`。

后续若支持多 origin so，建议保持以下原则：

1. 在离线 pipeline 统一分配稳定 `soId`。
2. 在初始化阶段批量注册所有 `soId -> soName`。
3. 保持 `dispatch_by_key` 入口不变，避免破坏现有调用协议。
