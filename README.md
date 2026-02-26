# VmProject

VmProject 是一个面向 Android ARM64 `so` 的“离线加固 + 运行时接管”工程。  
当前主路线是 `route4`，由两个核心子系统组成：

1. `VmProtect`：离线工具，负责分析函数、导出 VM payload、把 payload 嵌入 `VmEngine`，并完成导出符号接管补丁。
2. `VmEngine`：运行时引擎，负责读取嵌入 payload、恢复接管映射、执行 VM 指令并转发外部调用。

本文按当前仓库代码现状编写，目标是让新同学快速建立完整认知：  
工程做什么、模块如何分层、核心流程如何跑通、难点在哪里、怎么构建和回归。

## 1. 端到端总览

`route4` 的主链路如下：

1. 对原始 donor so（例如 `VmProtect/libdemo.so`）做函数分析与导出。
2. 生成函数编码产物（`*.txt` / `*.bin`）与 `libdemo_expand.so`。
3. 将 `libdemo_expand.so` 以尾部 payload 形式嵌入 `VmEngine` 的 `libvmengine.so`。
4. 对嵌入后的 `vmengine so` 执行 patchbay：新增 donor 导出名，映射到 `vm_takeover_entry_xxxx` 跳板。
5. App 启动后，`VmEngine` 自动 `vm_init()`：
   - 从自身尾部提取 `libdemo_expand.so`；
   - 用自定义 linker 装载；
   - 预热函数缓存；
   - 从 patched dynsym 恢复 `entryId -> funAddr`；
   - 建立 `vm_takeover_dispatch_by_id` 分发能力。
6. 外部调用 donor 导出名时，进入接管分发，最终由 VM 执行对应函数。

## 2. 仓库目录（顶层）

- `VmProtect`：离线工具（Windows CMake 可执行程序）。
- `VmEngine`：Android App + native VM 运行时。
- `demo`：设备侧验证 App（对照 `libdemo.so` 与 `libdemo_ref.so`）。
- `shared`：跨端共享协议（当前核心是 patchbay 协议头）。
- `tools`：回归和构建辅助脚本（核心是 `run_regression.py`、`embed_expand_into_vmengine.py`）。

---

## 第一大块：VmProtect（离线系统）

## 1. 职责边界

`VmProtect` 的职责不是单点 patch，而是完整离线流水线：

1. 读取输入 ELF，解析函数符号。
2. 做覆盖率和翻译可行性分析，输出 `coverage_report.md`。
3. 导出函数产物（文本/编码 bin）并打包为 `libdemo_expand.so`。
4. 把 `libdemo_expand.so` embed 到 `vmengine so` 尾部。
5. 需要时执行 patchbay，完成 donor 导出名接管注入，输出最终 `--output-so`。

入口是 `VmProtect/app/zMain.cpp`。  
如果首参数是 patchbay 子命令，会直接分流到 patchbay 入口；否则走主 pipeline。

## 2. 架构分层与目录

### 2.1 L0 基础层（无业务语义）

路径：`VmProtect/modules/base/core`

主要文件：

- `zFile.*`：文件读写、存在性、目录创建。
- `zLog.*`：日志。
- `zBytes.*`：字节区间校验、写入辅助。
- `zCodec.*`、`zBitCodec.*`：编解码工具。
- `zChecksum.*`、`zHash.*`：校验与 hash 工具。
- `zEmbeddedPayloadTail.*`：嵌入 payload footer 协议（离线侧）。

### 2.2 L1 格式与解析层

路径：

- `VmProtect/modules/elfkit/core`
- `VmProtect/modules/elfkit/api`
- `VmProtect/modules/elfkit/patchbayModel`

职责：

- ELF 读取与函数视图（`zElf.*`、`zFunction.*`）。
- 函数翻译中间产物和导出打包（`zFunctionData.*`、`zSoBinBundle.*`）。
- patch 场景 ELF 模型、布局与校验（`zPatchElf*` 系列）。

### 2.3 L2 领域能力层

路径：

- `VmProtect/modules/patchbay/foundation`
- `VmProtect/modules/patchbay/format`
- `VmProtect/modules/patchbay/domain`
- `VmProtect/modules/patchbay/app`

职责：

- donor 导出采集、命名规则校验、冲突检测。
- alias 表构建（dynsym/dynstr/versym 追加）。
- GNU/SysV hash 重建。
- patch 落盘（优先重构路径，失败回退 `.vmp_patchbay` 原位路径）。
- patchbay 子命令入口。

### 2.4 L3 流程编排层

路径：`VmProtect/modules/pipeline/core`

职责：

- CLI 解析（`zPipelineCli.cpp`）。
- 配置合并与合法性校验（`zPipelineRun.cpp`）。
- 覆盖率分析与报告（`zPipelineCoverage.cpp`）。
- 导出产物（`zPipelineExport.cpp`）。
- embed + patch 编排（`zPipelinePatch.cpp`）。

### 2.5 L4 应用入口层

路径：`VmProtect/app/zMain.cpp`

职责：

- 主命令入口。
- patchbay 子命令分流。

## 3. 主流程（对应源码）

### 3.1 CLI 解析与必填约束

CLI 实现在 `VmProtect/modules/pipeline/core/zPipelineCli.cpp`，主参数包括：

- `--input-so`
- `--output-dir`
- `--expanded-so`
- `--shared-branch-file`
- `--coverage-report`
- `--function`（可重复）
- `--coverage-only`
- `--analyze-all`
- `--vmengine-so`
- `--output-so`
- `--patch-donor-so`
- `--patch-impl-symbol`
- `--patch-all-exports`
- `--patch-allow-validate-fail`

“加固路线”触发条件定义在 `VmProtect/modules/pipeline/core/zPipelineRun.cpp`：  
只要出现以下任一参数，就进入加固路线：

- `--vmengine-so`
- `--output-so`
- `--patch-donor-so`

加固路线下必须显式传入：

1. `--input-so`
2. `--vmengine-so`
3. `--output-so`
4. `--function`（至少一个，且必须显式传，不允许回落默认函数集）

### 3.2 覆盖率分析

实现：`VmProtect/modules/pipeline/core/zPipelineCoverage.cpp`

拆分为两个阶段：

1. `runCoverageAnalyzeFlow(...)`
   - 指令支持统计（capstone）。
   - 函数翻译状态收集（`prepareTranslation`）。
2. `runCoverageReportFlow(...)`
   - 只负责写 `coverage_report.md`。

这保证了“分析逻辑”和“报告写出逻辑”职责分离。

### 3.3 导出产物

实现：`VmProtect/modules/pipeline/core/zPipelineExport.cpp`

核心动作：

1. 收集目标函数。
2. 校验每个函数翻译可行性。
3. 汇总共享分支地址。
4. 对每个函数输出：
   - `<function>.txt`
   - `<function>.bin`
5. 用 `zSoBinBundleWriter::writeExpandedSo(...)` 生成 `libdemo_expand.so`。

### 3.4 embed 与 patch 编排

实现：`VmProtect/modules/pipeline/core/zPipelinePatch.cpp`

1. embed 阶段：
   - 把 `libdemo_expand.so` 追加到 `vmengine so` 尾部；
   - 写入 footer（`magic/version/size/crc`）。
2. patch 阶段（可选）：
   - 当指定 `--patch-donor-so` 时，调用 donor 领域 API：
     `runPatchbayExportAliasFromDonor(...)`；
   - 不经过 shell 命令，直接 API 调用。

## 4. 难点一：符号注入原理（VmProtect 侧）

这部分对应 `VmProtect/modules/patchbay/domain`，是离线侧最关键的协议逻辑。

### 4.1 donor 导出转 alias 对

在 `zPatchbayDonor.cpp` 中：

1. 收集 donor 动态导出。
2. 稳定排序后分配 entry（保证不同机器顺序稳定）。
3. 构建 `AliasPair`：
   - `exportName = donor 导出名`
   - `implName = vm_takeover_entry_xxxx`（entry 模式）或显式实现符号
   - `exportKey = donor.st_value`

这里明确约定：`exportKey` 最终写入新导出符号的 `st_size` 字段。

### 4.2 dyn 表构建与待回填绑定

在 `zPatchbayAliasTables.cpp` 中：

1. 追加/复用 entry 符号（`vm_takeover_entry_xxxx`）。
2. 追加 alias 导出符号。
3. entry 模式下先把 `st_value` 置为 0（占位）。
4. 记录 `pendingTakeoverBindings`：
   - 哪个 dynsym 索引需要回填；
   - 回填到哪个 `entryId`。
5. alias 符号 `st_size` 写入 `exportKey`（即 donor `st_value`）。

### 4.3 跳板注入与 dynsym 回填

在 `zPatchbayPatchApply.cpp` 中：

1. 根据 `pendingTakeoverBindings` 生成 ARM64 跳板 blob。
2. 每个 entry 的跳板写入 `w2=entryId` 后跳到 `vm_takeover_dispatch_by_id`。
3. 回填 dynsym `st_value = 对应跳板地址`。
4. 重建 `gnu hash/sysv hash/versym`。
5. 改写 `.dynamic` 的 `DT_SYMTAB/DT_STRTAB/DT_GNU_HASH/DT_HASH/DT_VERSYM` 指针。

### 4.4 两种落盘路径

`applyPatchbayAliasPayload(...)` 先尝试重构路径，再回退 patchbay 原位路径：

1. 重构路径：直接在文件尾追加新 dyn 表区域并更新 PT_LOAD 覆盖。
2. 回退路径：若存在 `.vmp_patchbay`，在预留区原位改写。

当前主路线优先重构路径，容量不受 `.vmp_patchbay` 固定区限制。

---

## 第二大块：VmEngine（运行时系统）

## 1. 职责边界

`VmEngine` 负责把离线产物真正执行起来：

1. 在 so 加载时自动触发 `vm_init()`。
2. 从自身尾部读取 embedded payload。
3. 直接从内存加载 embedded `libdemo_expand.so`（不再先落盘）。
4. 预热函数缓存和共享分支地址表。
5. 从 patched dynsym 恢复 `entryId -> funAddr`。
6. 对外提供统一接管分发 `vm_takeover_dispatch_by_id(...)`。

## 2. 运行时分层（CMake 视角）

`VmEngine/app/src/main/cpp/CMakeLists.txt` 按对象层组织：

- `vm_l0_foundation`：日志、资产、linker、文件字节读写。
- `vm_l1_format`：函数模型、bundle、embedded payload、takeover dynsym 解析、patchbay 协议镜像。
- `vm_l2_domain`：VM 执行器、opcode、类型系统、接管状态。
- `vm_l3_pipeline`：初始化配置与 route4 编排。

最终合并成 `libvmengine.so`，并通过 `vmengine.exports.map` 限制只导出 `vm_*`。

## 3. 初始化生命周期

实现：`VmEngine/app/src/main/cpp/zVmInitLifecycle.cpp`

状态机：

1. `0` 未初始化
2. `1` 初始化中
3. `2` 初始化成功
4. `3` 初始化失败

`vm_library_ctor` 会在 so 加载后自动调用 `vm_init()`。  
并发策略是“原子状态 + 互斥串行化 + JNI 线程 attach/detach”。

## 4. route4 初始化核心

实现：`VmEngine/app/src/main/cpp/zVmInitCore.cpp`

`runVmInitCore(JNIEnv* env)` 的主顺序：

1. 清理旧状态（缓存、共享分支表、takeover 映射）。
2. 执行 `route_embedded_expand_so`：
   - 定位当前 vmengine so 路径；
   - 从尾部读取 payload；
   - 通过 `zLinker` 的内存加载入口直接装载；
   - 预热函数缓存与共享分支表。
3. 执行 `route_symbol_takeover`：
   - 从 patched vmengine dynsym 恢复条目；
   - 调 `zSymbolTakeoverInit(...)` 建立全局映射。

成功日志关键 marker：

- `route_embedded_expand_so result=1 state=0`
- `route_symbol_takeover result=1`

## 5. takeover 恢复与分发闭环

### 5.1 dynsym 恢复

实现：`VmEngine/app/src/main/cpp/zElfTakeoverDynsym.cpp`

当前策略是“dynamic table 优先，section table 兜底”：

1. 优先从 `PT_DYNAMIC` + `DT_*` 构建 dynsym 视图（兼容 strip 场景）。
2. dynamic 失败时才回退 section 解析。
3. 两遍扫描：
   - 第一遍：解析 `vm_takeover_entry_xxxx`，建立 `st_value -> entryId`。
   - 第二遍：扫描普通导出符号，用 `st_value` 反查 `entryId`，从 `st_size` 读取 `funAddr`。

输出结构是 `zTakeoverSymbolEntry { entryId, funAddr }`。

### 5.2 接管状态提交与 dispatch

实现：`VmEngine/app/src/main/cpp/zSymbolTakeover.cpp`

1. `zSymbolTakeoverInit(...)` 校验并提交 `entryId -> funAddr` 映射。
2. `vm_takeover_dispatch_by_id(a,b,symbol_id)`：
   - 若未初始化，先惰性 `vm_init()`；
   - `symbol_id` 作为 `entryId` 查表；
   - 调 `zVmEngine::execute(...)` 执行真实 VM 函数。

---

## 6. 难点二：VmEngine 对 `BL` 指令的处理

这一点对应离线导出与运行时执行的跨阶段一致性。

### 6.1 离线阶段

在 `VmProtect/modules/pipeline/core/zPipelineExport.cpp` 中：

1. 每个函数执行 `remapBlToSharedBranchAddrs(...)`。
2. 本地 branch 索引统一 remap 到共享索引。
3. 共享地址表写入 `libdemo_expand.so` bundle。

### 6.2 运行时装载阶段

在 `VmEngine/app/src/main/cpp/zVmInitCore.cpp` 和 `zVmEngine.cpp` 中：

1. 读取 bundle 得到共享分支地址表。
2. `engine.setSharedBranchAddrs(soName, ...)` 写入映射。
3. 执行前按目标 so `base` 修正地址，形成进程内绝对调用地址。

### 6.3 执行阶段

在 `VmEngine/app/src/main/cpp/zVmOpcodes.cpp` 中：

1. `op_bl` 读取 `branchId`。
2. 从 `ctx->branch_addr_list[branchId]` 拿目标地址。
3. 通过 `call_native_with_x8(...)` 执行 `blr` 调用，保留 x0..x7/x8 ABI 语义。
4. 返回值回写到 x0。

如果 `branchId` 越界或地址表为空，会立即报错并停机，避免错误跳转。

---

## 7. 难点三：VmEngine 自定义 Linker 设计

实现：`VmEngine/app/src/main/cpp/zLinker.cpp`

`zLinker::LoadLibrary(...)` 串联完整加载流程：

1. `OpenElf`
2. `ReadElf`
3. `ReserveAddressSpace`
4. `LoadSegments`
5. `FindPhdr`
6. `UpdateSoinfo`
7. `PrelinkImage`（解析 `DT_*`）
8. `ProtectSegments`
9. `LinkImage`（重定位 + init）

### 7.1 动态段解析

`ParseDynamic(...)` 解析并缓存：

- `DT_SYMTAB/DT_STRTAB`
- `DT_GNU_HASH/DT_HASH`
- `DT_RELA/DT_JMPREL`
- `DT_INIT/DT_INIT_ARRAY`
- `DT_NEEDED`

### 7.2 符号解析顺序

`FindSymbolAddress(...)` 顺序如下：

1. 当前 so（GNU hash 优先，再 SysV hash）
2. `DT_NEEDED` 依赖库（`RTLD_NOLOAD + dlsym`）
3. `RTLD_DEFAULT` 全局兜底

### 7.3 当前重定位支持范围（AArch64）

`ProcessRelaRelocation(...)` 重点支持：

- `R_AARCH64_ABS64`
- `R_AARCH64_GLOB_DAT`
- `R_AARCH64_JUMP_SLOT`
- `R_AARCH64_RELATIVE`
- `R_AARCH64_IRELATIVE`

这个 linker 直接决定了 route4 是否能在设备上稳定加载并执行。

---

## 构建与运行

## 1. 构建 VmProtect

在项目根目录执行：

```powershell
cmake -S VmProtect -B VmProtect/cmake-build-debug -G Ninja
cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12
```

查看帮助：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe --help
```

## 2. 常用离线命令

### 2.1 仅导出（不做 vmengine 加固）

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --input-so VmProtect/libdemo.so `
  --function fun_add `
  --function fun_for
```

### 2.2 完整加固路线（embed + patch）

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --input-so VmProtect/libdemo.so `
  --vmengine-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine.so `
  --output-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine_patch.so `
  --patch-donor-so VmProtect/libdemo.so `
  --patch-impl-symbol vm_takeover_entry_0000 `
  --function fun_add `
  --function fun_for
```

说明：

1. `--vmengine-so` 是“待嵌入/待补丁的 vmengine so 输入路径”。
2. `--output-so` 是“最终输出路径”，必须显式给出。
3. 加固路线必须显式 `--function`，不会回落默认函数列表。
4. `--patch-allow-validate-fail` 默认关闭（严格模式）。

## 3. 设备回归

推荐命令：

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

脚本会执行：

1. 构建并运行 VmProtect 导出。
2. patch vmengine 符号导出（主路线参数自动组装）。
3. 安装 `VmEngine` debug 包并启动。
4. 检查启动日志 marker。

通过判据（必须同时命中）：

1. `route_embedded_expand_so result=1 state=0`
2. `route_symbol_takeover result=1`

---

## Demo 说明

`demo` 是设备侧验收工程：

1. 会把受保护库注入为 `libdemo.so`。
2. 同时打包 donor 参考库为 `libdemo_ref.so`。
3. JNI 桥 `demo/app/src/main/cpp/zVmpBridge.cpp` 对多个 `fun_*` 做对照验证。
4. 输出 `PASS/FAIL` 文本并写入 logcat（`VMP_DEMO_CHECK`）。

---

## 常见排障入口

1. `route_embedded_expand_so` 失败  
排查 `VmEngine/app/src/main/cpp/zEmbeddedPayload.cpp` 与 `zVmInitCore.cpp`，重点看 footer 解析和 CRC。

2. `route_symbol_takeover` 失败  
排查 `VmEngine/app/src/main/cpp/zElfTakeoverDynsym.cpp` 与 `zSymbolTakeover.cpp`，重点看 dynsym 两遍扫描是否拿到 `entryId` 和 `st_size` key。

3. 调用期 `op_bl invalid branch target`  
排查 `VmProtect/modules/pipeline/core/zPipelineExport.cpp` 的共享地址导出，以及 `VmEngine/app/src/main/cpp/zVmEngine.cpp` 地址修正逻辑。

4. patch 产物校验失败  
排查 `VmProtect/modules/patchbay/domain/zPatchbayPatchApply.cpp`，重点看重构路径的 PT_LOAD 覆盖和 `DT_*` 回写。

---

## 关键文件索引（便于快速跳转）

- VmProtect 主入口：`VmProtect/app/zMain.cpp`
- CLI：`VmProtect/modules/pipeline/core/zPipelineCli.cpp`
- 配置校验：`VmProtect/modules/pipeline/core/zPipelineRun.cpp`
- 覆盖率：`VmProtect/modules/pipeline/core/zPipelineCoverage.cpp`
- 导出：`VmProtect/modules/pipeline/core/zPipelineExport.cpp`
- embed/patch 编排：`VmProtect/modules/pipeline/core/zPipelinePatch.cpp`
- donor API：`VmProtect/modules/patchbay/domain/zPatchbayDonor.cpp`
- alias 构建：`VmProtect/modules/patchbay/domain/zPatchbayAliasTables.cpp`
- patch 落盘：`VmProtect/modules/patchbay/domain/zPatchbayPatchApply.cpp`
- VmEngine 初始化：`VmEngine/app/src/main/cpp/zVmInitCore.cpp`
- 生命周期：`VmEngine/app/src/main/cpp/zVmInitLifecycle.cpp`
- dynsym 恢复：`VmEngine/app/src/main/cpp/zElfTakeoverDynsym.cpp`
- takeover 分发：`VmEngine/app/src/main/cpp/zSymbolTakeover.cpp`
- VM 执行：`VmEngine/app/src/main/cpp/zVmEngine.cpp`
- opcode（含 `OP_BL`）：`VmEngine/app/src/main/cpp/zVmOpcodes.cpp`
- 自定义 linker：`VmEngine/app/src/main/cpp/zLinker.cpp`
- 共享协议：`shared/patchbay/zPatchbayProtocol.h`
- 回归脚本：`tools/run_regression.py`
