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

## 四、elfkit 指令解析与翻译（并入主文档）

本节给出 `VmProtect/modules/elfkit` 的核心实现说明，重点是 ARM64 到 VMProtect 指令的解析与翻译逻辑。

### 4.1 模块分层

`elfkit` 分为三层目录：

1. `VmProtect/modules/elfkit/api`：对外门面与稳定接口。
2. `VmProtect/modules/elfkit/core`：ELF 解析、函数建模、指令翻译、导出编码。
3. `VmProtect/modules/elfkit/patchbayModel`：Patch ELF 模型、布局重建和一致性校验。

### 4.2 翻译入口调用链

函数级翻译从 `zFunction::ensureUnencodedReady()` 触发，主链路如下：

1. `zInstAsm::buildUnencodedBytecode(code, size, baseAddr)`。
2. `zInstAsm::openWithDetail()` 打开 Capstone 并启用 `CS_OPT_DETAIL`。
3. `zInstAsm::disasm()` 产出 `cs_insn` 序列。
4. `buildUnencodedByCapstone(...)` 逐条指令翻译并组装 `zInstAsmUnencodedBytecode`。

对应关键文件：

1. `VmProtect/modules/elfkit/core/zFunction.cpp`
2. `VmProtect/modules/elfkit/core/zInstAsm.h`
3. `VmProtect/modules/elfkit/core/zInstAsmCore.cpp`
4. `VmProtect/modules/elfkit/core/zInstAsmTranslate.cpp`

### 4.3 指令分派机制

每条 ARM64 指令翻译按“三段式”执行：

1. 域分类：`zInst::classifyArm64Domain()` -> `Arith/Logic/Memory/Branch`。
2. 域分发：`dispatchArm64*Case(...)` 按 instruction id 做精确翻译。
3. 严格失败：未命中已支持的 `instruction id + operand 结构` 时立即失败并记录详细错误。

如仍无法建模，部分系统/SIMD/FP 指令按策略降级为 `OP_NOP`，保证流程可继续并可诊断。

### 4.3.1 指令解析架构总览（难点拆解）

`elfkit` 的指令解析不是单点函数，而是一条分层流水线。建议按下面 8 层理解：

1. **输入层（函数边界确定）**
   - 入口：`zFunction::ensureUnencodedReady()`。
   - 作用：确认函数机器码区间、基础地址、缓存状态。
   - 难点：函数边界一旦错误，后续 Capstone 解析与分支表都会整体偏移。

2. **反汇编层（Capstone 抽象）**
   - 入口：`zInstAsm::openWithDetail()` + `zInstAsm::disasm()`。
   - 作用：把 bytes 转为 `cs_insn` 序列，拿到 `id/mnemonic/op_str/operands`。
   - 难点：不同 Capstone 版本对同一指令可能给出不同 id 或 operand 形态。

3. **操作数结构层（detail-only）**
   - 入口：`cs_detail.aarch64.operands[]`。
   - 作用：所有寄存器/立即数/内存寻址信息都只从 Capstone detail 结构读取。
   - 难点：必须覆盖同一指令在不同 alias/宽度/shift 形态下的 operand 组合。

4. **语义分域层（粗粒度分类）**
   - 入口：`zInst::classifyArm64Domain()`。
   - 作用：把指令先分到 `Arith/Logic/Memory/Branch` 四大域。
   - 难点：某些 alias 指令语义跨域，分类与真实翻译路径可能不一致。

5. **域内分发层（精确 case）**
   - 入口：`dispatchArm64*Case(...)`。
   - 作用：按 instruction id 做“主路径翻译”，输出 VM opcode words。
   - 难点：需要覆盖同一语义的多种 operand 组合、shift 变体和寄存器宽度差异。

6. **语义别名归一层（ID 驱动）**
   - 入口：`dispatchArm64*Case(...)` 内部各 `ARM64_INS_* / ARM64_INS_ALIAS_*` 分支。
   - 作用：把同义 alias 收敛到统一 VM 指令序列，避免字符串匹配分支。
   - 难点：别名共享语义但 operand 细节可能不同，需要在同一 case 中收口。

7. **链接装配层（控制流与地址映射）**
   - 输出结构：`zInstAsmUnencodedBytecode`。
   - 关键动作：
     - 生成 `preludeWords`；
     - 建立 `instByAddress`；
     - 构建 `addr->pc`、`branchWords`、`branchLookup*`。
   - 难点：`preludeWords` 与真实 ARM 地址必须解耦，否则 PC/分支映射会错位。

8. **失败策略层（Fail-Fast）**
   - 规则：出现不可翻译指令或分支目标未解析时立即失败。
   - 关键字段：`translationOk=false` + `translationError`。
   - 难点：既要保证严格失败不静默，又要让错误信息足够细以支持快速定位。

### 4.3.2 架构定位图（排障顺序）

建议按以下顺序定位翻译问题：

1. 先看 `translationError` 是否指向“unsupported instruction”还是“unresolved branch target”。
2. 若是 unsupported：
   - 检查 `classifyArm64Domain()` 分域是否正确。
   - 检查对应 `dispatchArm64*Case` 是否覆盖该 operand 形态。
3. 若是 unresolved branch：
   - 检查该目标地址是否进入 `instByAddress`。
   - 检查 `preludeWords` 引入后 `addr->pc` 偏移是否正确。
4. 若表现为运行结果异常但不报错：
   - 优先核查 `TYPE_TAG_*` 与 `BIN_*` 的组合是否匹配寄存器宽度和符号位语义。

### 4.4 操作数解析规则（严格模式）

当前解析策略为 **detail-only**，不再依赖 `op_str` 文本兜底。规则如下：

1. 立即数只读取 `ops[i].imm`，不从字符串截取 `#imm`。
2. 寄存器只读取 `ops[i].reg`，并通过 `arm64CapstoneToArchIndex()` 统一映射。
3. 分支目标优先读取 `ops[i].imm` 或寄存器操作数；无法确定时直接失败。
4. 对 `shift/extend/mem.disp` 统一走 `cs_arm64_op` 字段，避免字符串歧义。
5. 任一关键信息缺失时立即失败，错误消息中带地址、instruction id、operand 摘要。

这套策略保证“能翻译就结构化翻译，不能翻译就明确失败”，避免字符串关键字误判。

### 4.5 VM 指令编码模型

翻译结果是 VM opcode words 序列，而不是“一条 ARM 对应一条 VM 指令”。

1. 主操作码：`OP_*`（如 `OP_BINARY`、`OP_LOAD_IMM`、`OP_BRANCH`）。
2. 子操作码：`BIN_*`（如 `BIN_ADD`、`BIN_SUB`、`BIN_SHL`）。
3. 类型标签：`TYPE_TAG_*`（决定宽度与有符号语义）。

核心枚举集中在 `VmProtect/modules/elfkit/core/zInstDispatch.h`。

### 4.6 Prelude 与 PC 映射策略

当前实现将 VM 前缀指令与真实 ARM 地址完全解耦：

1. 前缀写入 `preludeWords`（如 `OP_ALLOC_RETURN` / `OP_ALLOC_VSP`）。
2. `preludeWords` 不进入 `instByAddress`，避免伪地址污染。
3. 地址到 PC 的映射从 `preludeWords.size()` 起算。
4. 导出文本/bin 中保留前缀可视化（bin 以伪地址行表达）。

这避免了旧方案使用 `instByAddress[0/1]` 占位带来的地址冲突问题。

### 4.7 分支目标 Fail-Fast 机制

本地分支在写入 `branchWords` 前执行严格校验：

1. 若目标 ARM 地址找不到映射 PC，立即翻译失败。
2. 禁止“写 0 继续”的静默退化。
3. 错误文本携带分支下标与目标地址，便于回归追踪。

### 4.8 关键中间结构

`zInstAsmUnencodedBytecode` 是翻译层与导出层的共享契约，关键字段包括：

1. `preludeWords`
2. `instByAddress`
3. `asmByAddress`
4. `branchWords / branchLookupWords / branchLookupAddrs / branchAddrWords`
5. `translationOk / translationError`

最终编码由 `zFunctionData` 承载并通过 `validate/serializeEncoded/deserializeEncoded` 保证一致性。

### 4.9 回归建议

涉及 `elfkit/core` 翻译逻辑变更时，至少执行：

```bash
cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12
python tools/run_regression.py --project-root . --patch-vmengine-symbols
python tools/run_install_start_regression.py --project-root . --rerun-tasks
```

重点关注：

1. `translationError` 日志。
2. `unresolved local branch target` 是否出现。
3. 设备侧汇总是否保持 `PASS`。

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
