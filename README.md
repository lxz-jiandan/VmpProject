# VmProject

VmProject 是一个面向 Android ARM64 `so` 的“离线加固 + 运行时接管”工程。  
当前仓库的核心由两部分组成：

1. `VmProtect`：离线处理工具，负责函数分析、导出 payload、embed、patchbay。
2. `VmEngine`：运行时引擎，负责加载 payload、恢复接管映射并解释执行。

配套目录：

- `tools`：回归与构建辅助脚本（核心：`run_regression.py`、`embed_expand_into_vmengine.py`、`gen_takeover_stubs.py`）
- `demo`：演示与端到端验证

本文基于当前代码现状（含最近重构）编写，重点是让新同学能快速理解：

1. 工程做什么
2. 两个子系统如何协作
3. 核心模块与协议是什么
4. 如何构建、回归、排查问题

---

## 快速总览

端到端主路线是 `route4`：

```text
input so + function list
   -> VmProtect analyze/report/export
   -> libdemo_expand.so
   -> embed into libvmengine.so
   -> (optional) patchbay export alias
   -> patched vmengine so
   -> app load vmengine
   -> vm_init
   -> read embedded payload
   -> preload function cache
   -> recover entryId -> funAddr
   -> vm_takeover_entry_xxxx -> vm_takeover_dispatch_by_id -> VM execute
```

---

## 第一大块：VmProtect（离线系统）

## 1.1 当前职责边界

`VmProtect` 不只是“改导出表”，而是完整离线流水线：

1. 读取输入 ELF。
2. 收集目标函数并做覆盖率/翻译状态分析。
3. 导出函数编码产物并打包 `libdemo_expand.so`。
4. 把 payload embed 到 `vmengine so` 尾部。
5. 需要时执行 patchbay，对导出符号做接管映射补丁。

入口文件：`VmProtect/app/zMain.cpp`

---

## 1.2 架构层级（按当前目录）

### L0 基础能力层

路径：`VmProtect/modules/base/core`

当前基础模块已经统一，不再存在旧的 `modules/foundation`：

- 文件读写：`zFile.h` / `zFile.cpp`
  - 命名空间：`vmp::base::file`
- 日志：`zLog.h` / `zLog.cpp`
- 编码与字节工具：`zCodec/zBitCodec/zBytes/zChecksum/zHash`

特点：

- 无业务语义，可复用；
- 文件能力统一走 `base::file`；
- 已移除历史薄封装（如 `zIo`、`zIoUtils`、`zPatchbayIo`）。

### L1 格式与解析层

路径：

- `VmProtect/modules/elfkit/core`
- `VmProtect/modules/elfkit/api`
- `VmProtect/modules/elfkit/patchbayModel`

职责：

- ELF 读取与函数视图；
- 函数翻译中间模型；
- patch 视角下的 ELF 模型与校验器。

### L2 领域能力层

路径：

- `VmProtect/modules/patchbay/foundation`
- `VmProtect/modules/patchbay/format`
- `VmProtect/modules/patchbay/domain`
- `VmProtect/modules/patchbay/app`

职责：

- alias 构建；
- GNU/SYSV hash 重建；
- patchbay 落盘与 `.dynamic` 指针更新；
- patchbay 子命令入口编排。

### L3 流程编排层

路径：`VmProtect/modules/pipeline/core`

职责：

- CLI 解析；
- 配置合并与校验；
- 覆盖率分析与报告；
- 导出产物；
- embed + patch 编排。

### L4 应用入口层

路径：`VmProtect/app/zMain.cpp`

职责：

- 主 CLI 入口；
- patchbay 子命令分流。

---

## 1.3 主流程细节（源码映射）

### 步骤 1：CLI 解析

文件：`VmProtect/modules/pipeline/core/zPipelineCli.cpp`

支持主参数：

- `--input-so`
- `--output-dir`
- `--expanded-so`
- `--shared-branch-file`
- `--vmengine-so`
- `--output-so`
- `--patch-donor-so`
- `--patch-impl-symbol`
- `--patch-all-exports`
- `--patch-no-allow-validate-fail`
- `--coverage-report`
- `--function`（可重复）
- `--coverage-only`
- `--analyze-all`

### 步骤 2：配置合并与合法性校验

文件：

- `VmProtect/modules/pipeline/core/zPipelineTypes.h`
- `VmProtect/modules/pipeline/core/zPipelineRun.cpp`

关键规则：

1. 若进入“加固路线”（`--vmengine-so/--output-so/--patch-donor-so` 任一出现），则必须显式传：
   - `--input-so`
   - `--vmengine-so`
   - `--output-so`
   - `--function`
2. `--function` 未显式传时，仅在非加固路线下才使用默认函数集（定义于 `zPipelineTypes.cpp`）。

### 步骤 3：覆盖率与翻译状态

文件：`VmProtect/modules/pipeline/core/zPipelineCoverage.cpp`

产出：

- `coverage_report.md`（默认名）

内容包含：

- 指令支持/不支持统计；
- 函数级翻译状态；
- 错误信息聚合。

### 步骤 4：导出 payload

文件：`VmProtect/modules/pipeline/core/zPipelineExport.cpp`

动作：

1. 导出 `<function>.txt` 与 `<function>.bin`
2. 汇总共享分支地址列表
3. 调 `zSoBinBundleWriter::writeExpandedSo(...)` 生成 `libdemo_expand.so`

bundle 写入实现：`VmProtect/modules/elfkit/core/zSoBinBundle.cpp`

### 步骤 5：embed + patch

文件：`VmProtect/modules/pipeline/core/zPipelinePatch.cpp`

动作：

1. embed：将 `libdemo_expand.so` 追加到 `vmengine so` 尾部，写入 footer（`magic/version/size/crc`）。
2. patch（可选）：
   - 当提供 `--patch-donor-so` 时，直接调用 patchbay donor 领域 API
     （`zPatchbayDonor.cpp`，CLI 与 pipeline 共享同一实现）
   - 中间会先生成 `*.embed.tmp.so`，再产出最终 `--output-so`。

---

## 1.4 PatchBay 设计要点（离线）

### 子命令入口

文件：`VmProtect/modules/patchbay/app/zMain.cpp`

当前保留的子命令：

- `export_alias_from_patchbay`

### 关键规则

1. donor 与 vmengine 导出重名会直接失败。
2. 默认仅处理 `fun_*` 与 `Java_*`（除非显式 `--patch-all-exports`）。
3. `vm_takeover_entry_xxxx` entry 模式支持批量映射。
4. `exportKey` 用 donor 符号 `st_value` 承载，写入新增导出的 `st_size` 字段。

### 主实现文件

- donor 领域 API：`VmProtect/modules/patchbay/domain/zPatchbayDonor.cpp`
- alias 构建：`VmProtect/modules/patchbay/domain/zPatchbayAliasTables.cpp`
- hash 重建：`VmProtect/modules/patchbay/format/zPatchbayHash.cpp`
- 主流程：`VmProtect/modules/patchbay/domain/zPatchbayExport.cpp`
- 落盘与 dynamic 更新：`VmProtect/modules/patchbay/domain/zPatchbayPatchApply.cpp`

### 协议结构

离线协议头定义：`VmProtect/modules/patchbay/domain/zPatchbayTypes.h`  
运行时镜像定义：`VmEngine/app/src/main/cpp/zPatchBay.h`

硬约束：

- 结构大小必须一致（`sizeof(...) == 148`）
- 布局字段必须一致（magic/version/offset/capacity/used/crc 等）

---

## 1.5 当前产物与文件

离线阶段常见产物：

- `coverage_report.md`
- `branch_addr_list.txt`
- `<function>.txt`
- `<function>.bin`
- `libdemo_expand.so`
- `<output-so>.embed.tmp.so`
- `libvmengine_patch.so`（或你指定的 `--output-so`）

---

## 第二大块：VmEngine（运行时系统，详细）

这一部分是新人理解成本最高的区域，也是影响“加固是否真正生效”的关键。

## 2.1 构建时行为（CMake）

文件：`VmEngine/app/src/main/cpp/CMakeLists.txt`

### 分层编译（对象层）

- L0 `vm_l0_foundation`
- L1 `vm_l1_format`
- L2 `vm_l2_domain`
- L3 `vm_l3_pipeline`

### 构建时自动动作

1. 若 `VMENGINE_ROUTE4_EMBED_PAYLOAD=ON`（默认开）：
   - post-build 调用 `tools/embed_expand_into_vmengine.py`
   - 把 `assets/libdemo_expand.so` embed 到 `libvmengine.so` 尾部

### 导出可见性

- map 文件：`VmEngine/app/src/main/cpp/vmengine.exports.map`
- 规则：仅导出 `vm_*`，其他默认隐藏

---

## 2.2 初始化生命周期与状态机

文件：`VmEngine/app/src/main/cpp/zVmInitLifecycle.cpp`

关键导出：

- `vm_init()`
- `vm_get_init_state()`

构造器触发：

- `vm_library_ctor` 在 so 加载后自动调用 `vm_init()`

状态机：

- `0`：未初始化
- `1`：初始化中
- `2`：初始化成功
- `3`：初始化失败

并发策略：

1. 原子状态 + 快速路径（ready/failed）
2. 互斥锁串行化初始化
3. 动态获取 `JNIEnv`，必要时 attach/detach 当前线程

---

## 2.3 Route4 核心初始化链路

文件：`VmEngine/app/src/main/cpp/zVmInitCore.cpp`

函数：`runVmInitCore(JNIEnv* env)`

执行顺序：

1. 清理旧状态：
   - `engine.clearCache()`
   - `engine.clearSharedBranchAddrs(...)`
   - `zSymbolTakeoverClear()`
2. 执行 `route_embedded_expand_so`：
   - 读取宿主 vmengine 尾部 payload
   - 落盘 `libdemo_expand_embedded.so`
   - 加载并预热函数缓存
3. 恢复 takeover 映射：
   - 从 patched vmengine dynsym 恢复 `entryId -> funAddr`
   - 初始化符号接管表
4. 任一关键环节失败，初始化失败

---

## 2.4 embedded payload 读取机制

文件：`VmEngine/app/src/main/cpp/zEmbeddedPayload.cpp`

读取流程：

1. 读取 host so 全字节
2. 从文件尾反向解析 footer
3. 校验 `magic/version/payloadSize/payloadCrc32`
4. 提取 payload 返回

状态返回：

- `kOk`
- `kNotFound`（没有嵌入）
- `kInvalid`（格式或校验错误）

离线写入点对应：

- `VmProtect/modules/pipeline/core/zPipelinePatch.cpp`

---

## 2.5 payload 预热与函数缓存

### bundle 读取

文件：`VmEngine/app/src/main/cpp/zSoBinBundle.cpp`

解析出：

- `zSoBinEntry` 列表（`fun_addr + encoded_data`）
- 共享分支地址列表

### 预热逻辑

在 `zVmInitCore.cpp` 的 `preloadExpandedSoBundle(...)` 中：

1. `engine.setSharedBranchAddrs(...)`
2. 每条 payload 构建 `zFunction`
3. `loadEncodedData(...)`
4. `setFunctionAddress(...)`
5. `engine.cacheFunction(...)`

---

## 2.6 takeover 恢复与分发

### dynsym 恢复（关键）

文件：`VmEngine/app/src/main/cpp/zElfTakeoverDynsym.cpp`

两遍扫描：

1. 找 `vm_takeover_entry_XXXX`，建立 `st_value -> entryId`
2. 扫普通导出符号，用同 `st_value` 反查 `entryId`，从 `st_size` 取 key（当前语义为 `funAddr`）

输出：`std::vector<zTakeoverSymbolEntry>`
当前结构字段：`entryId`、`funAddr`

### 接管状态机

文件：`VmEngine/app/src/main/cpp/zSymbolTakeover.cpp`

`zSymbolTakeoverInit(...)`：

1. 校验条目合法性（非空、entryId 不重复、地址有效）
2. 校验目标 so 已被 linker 感知
3. 提交全局映射 `entryId -> funAddr`

### 分发入口

统一入口：

- `vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id)`

策略：

1. 若 `vm_init` 未 ready，先惰性初始化
2. `symbol_id` 作为 `entryId` 查映射
3. 调 `zVmEngine::execute(...)` 执行对应函数

---

## 2.7 VM 执行引擎（zVmEngine）

文件：

- 声明：`VmEngine/app/src/main/cpp/zVmEngine.h`
- 实现：`VmEngine/app/src/main/cpp/zVmEngine.cpp`

核心能力：

1. 缓存管理（`funAddr -> zFunction*`）
2. 链接器桥接（`zLinker`）
3. 共享分支地址表管理
4. 双形态执行入口：
   - 按 `soName + funAddr + params`
   - 按底层 `VMContext` 字段

执行路径摘要：

1. 命中缓存函数
2. 分配寄存器管理器并写入参数
3. 合成 `VMContext`
4. `dispatch()` 循环执行 opcode
5. 返回 `ret_value`

并发控制：

- cache：`shared_timed_mutex`
- linker：`mutex`
- shared branch map：`mutex`

---

## 2.8 PatchBay 运行时预留区

文件：

- `VmEngine/app/src/main/cpp/zPatchBay.h`
- `VmEngine/app/src/main/cpp/zPatchBay.cpp`

设计目标：

1. 在编译期放置 `.vmp_patchbay` 预留区
2. 离线补丁时尽量原位写入，避免重排整 ELF
3. 通过 header 记录各区偏移/容量/used/crc

当前 entry 策略：

- 编译期不再预置固定 entry 桩（旧的 128 槽方案已移除）
- 离线 patch 阶段按需重构 dynsym，并为任意 entryId 动态合成跳板

---

## 构建与回归

## 3.1 构建 VmProtect

```powershell
cmake -S VmProtect -B VmProtect/cmake-build-debug -G Ninja
cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12
```

查看帮助：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe --help
```

## 3.2 常见离线命令

### 仅分析与导出（不做 vmengine 加固）

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --input-so VmProtect/libdemo.so `
  --function fun_add `
  --function fun_for
```

### 完整加固路线（embed + patch）

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --input-so VmProtect/libdemo.so `
  --vmengine-so VmEngine/app/build/intermediates/cxx/Debug/2z4j1d3z/obj/arm64-v8a/libvmengine.so `
  --output-so VmEngine/app/build/intermediates/cxx/Debug/2z4j1d3z/obj/arm64-v8a/libvmengine_patch.so `
  --patch-donor-so VmProtect/libdemo.so `
  --patch-impl-symbol vm_takeover_entry_0000 `
  --function fun_add `
  --function fun_for
```

## 3.3 设备回归

回归：

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

构建辅助脚本（由构建系统直接调用）：

- `tools/embed_expand_into_vmengine.py`
