# VmProject

VmProject 是一个面向 Android ARM64 so 的“离线加固 + 运行时接管”工程，核心由三部分组成：

- `VmProtect`：离线工具，负责函数翻译、导出、打包、注入与符号接管补丁。
- `VmEngine`：运行时引擎，负责加载导出的 payload、建立接管映射并执行 VM 逻辑。
- `tools` / `demo`：自动化回归与演示工程，用于验证端到端链路。

这份文档面向新同学，重点回答四个问题：

- 这个项目在做什么
- 原理是什么
- 设计思路是什么
- 代码架构分几层、每层干什么

## 1. 项目在做什么

一句话：把原始 so 中指定函数转成 VM 可执行的编码数据，并在运行时通过导出符号接管把调用导向 VM 执行路径。

在当前工程里，主要路线是 `route4`：

- 离线阶段把函数导出为编码 payload（`libdemo_expand.so`）。
- 把 payload 嵌入到 `vmengine so` 尾部（embed）。
- 可选地对导出符号做 patch（patchbay），把 donor 中的导出名映射到 `vm_takeover_slot_xxxx`。
- 运行时在 `vmengine` 初始化时加载嵌入 payload，恢复 slot 映射并接管调用。

## 2. 端到端原理

## 2.1 离线阶段（VmProtect）

入口在 `VmProtect/app/zMain.cpp`，主流程是：

1. 解析 CLI 参数，构建配置。
2. 读取输入 so，收集目标函数。
3. 生成覆盖率与翻译可达性报告（Capstone + 翻译状态）。
4. 导出函数文本和编码二进制，生成 `libdemo_expand.so`。
5. 若指定 `--vmengine-so/--output-so`，执行加固路线：
   - embed：把 `libdemo_expand.so` 附加到 vmengine so 尾部（带 footer+CRC）。
   - patchbay（可选）：更新 `.dynsym/.dynstr/.gnu.hash/.gnu.version/.dynamic` 指针与数据，导出 alias 接管。

关键点：

- 函数翻译核心在 `VmProtect/modules/elfkit/core/zFunction.cpp`。
- 覆盖率统计在 `VmProtect/modules/pipeline/core/zPipelineCoverage.cpp`。
- payload 打包在 `VmProtect/modules/elfkit/core/zSoBinBundle.cpp`。
- embed 在 `VmProtect/modules/pipeline/core/zPipelinePatch.cpp`。
- patchbay 主流程在 `VmProtect/modules/patchbay/domain/zPatchbayExport.cpp`。

## 2.2 运行时阶段（VmEngine）

`VmEngine` 在库构造阶段进入初始化（`vm_library_ctor`），核心流程在 `VmEngine/app/src/main/cpp/zVmInitCore.cpp`：

1. 从当前 `libvmengine.so` 尾部读取嵌入 payload（`zEmbeddedPayload`）。
2. 把 payload 落盘成 `libdemo_expand_embedded.so` 并加载。
3. 预加载函数编码数据到 VM 缓存。
4. 从 patched vmengine 的 `dynsym/dynstr` 恢复 `slot_id -> fun_addr` 映射（`zElfTakeoverDynsym`）。
5. 初始化接管表，后续所有 slot 跳板统一进入 `vm_takeover_dispatch_by_id`（`zSymbolTakeover`）。

结果是：外部调用被 patch 后的导出符号，会通过 `vm_takeover_slot_xxxx` 跳板转进 VM 分发逻辑执行。

## 3. 设计思路

## 3.1 分层拆解，保持职责单一

工程把“基础能力、格式解析、领域逻辑、流程编排、入口”拆开，避免一个模块同时做 IO、ELF 解析、业务决策、CLI 控制。

## 3.2 对 ELF 做“低破坏”修改

patchbay 采用预留区（`.vmp_patchbay`）写入新表，优先避免大规模重排整个 ELF，从而降低链接/装载风险。

## 3.3 核心参数显式化

在加固路线中，关键参数必须显式传入：

- `--input-so`
- `--vmengine-so`
- `--output-so`
- `--function`（可重复）

这样可以减少“默认值误触发”的不确定性。

## 3.4 可观测、可回归

工程内置覆盖率报告、流程日志和设备端回归脚本，保障每次重构后能快速确认链路可用。

## 4. 架构层级（按当前实现映射）

## L0 基础能力层

目录：

- `VmProtect/modules/base/core`
- `VmProtect/modules/foundation/core`

职责：

- 字节/校验/编码/哈希/文件 IO（`zBytes/zChecksum/zCodec/zHash/zIo`）。
- 日志与基础工具（`zLog/zIoUtils`）。

特点：

- 不带业务语义，可复用到其他项目。

## L1 格式与解析层

目录：

- `VmProtect/modules/elfkit/core`
- `VmProtect/modules/elfkit/patchbayModel`
- `VmProtect/modules/elfkit/api`

职责：

- ELF 文件读取、函数视图、翻译模型、bundle 读写。
- patch 视角下的 ELF 模型、校验器、section/program 抽象。
- 对上暴露窄接口（`zElfKit`、`zPatchbayApi`、`zElfReadFacade`）。

## L2 领域能力层

目录：

- `VmProtect/modules/patchbay/foundation`
- `VmProtect/modules/patchbay/format`
- `VmProtect/modules/patchbay/domain`

职责：

- alias 表构建。
- gnu/sysv hash 重建。
- patchbay payload 写回、dynamic 指针更新、布局校验、CRC 更新。

## L3 流程编排层

目录：

- `VmProtect/modules/pipeline/core`

职责：

- 参数解析与配置合并（`zPipelineCli/zPipelineRun`）。
- 覆盖率阶段（analyze + report）。
- 导出阶段（export）。
- 注入与 patch 阶段（patch）。

核心编排可理解为：

- `analyze -> report -> export -> embed -> patch -> verify`

## L4 应用入口层

目录：

- `VmProtect/app/zMain.cpp`
- `tools/`
- `demo/`

职责：

- CLI 主入口、patchbay 子命令分流。
- 回归脚本与交付门禁。
- Android demo 验证接管效果。

## 5. VmEngine 侧分层（运行时）

`VmEngine/app/src/main/cpp/CMakeLists.txt` 里同样按层组织：

- `L0 foundation`：日志、文件、链接器基础能力
- `L1 format`：payload/函数/patchbay 元数据解析
- `L2 domain`：VM 执行、opcode、类型系统、符号接管
- `L3 pipeline`：route4 初始化、生命周期、JNI 入口

这是离线工具与运行时在“分层思想”上的对齐点。

## 6. 新人上手：先跑通最短路径

## 6.1 构建 VmProtect

```powershell
cmake -S VmProtect -B VmProtect/cmake-build-debug -G Ninja
cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12
```

查看参数：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe --help
```

## 6.2 仅跑导出+覆盖率（不做 vmengine 加固）

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --input-so VmProtect/libdemo.so `
  --function fun_add `
  --function fun_for
```

## 6.3 跑完整加固路线（embed + patch）

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --input-so VmProtect/libdemo.so `
  --vmengine-so VmEngine/app/build/intermediates/cxx/Debug/2z4j1d3z/obj/arm64-v8a/libvmengine.so `
  --output-so VmEngine/app/build/intermediates/cxx/Debug/2z4j1d3z/obj/arm64-v8a/libvmengine_patch.so `
  --patch-donor-so VmProtect/libdemo.so `
  --patch-impl-symbol vm_takeover_slot_0000 `
  --function fun_add `
  --function fun_for
```

## 6.4 跑设备回归

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

交付门禁：

```powershell
python tools/run_delivery_check.py --project-root .
```

## 7. 关键产物说明

- `coverage_report.md`：翻译覆盖率与失败原因。
- `branch_addr_list.txt`：共享分支地址列表。
- `*.txt` / `*.bin`：函数级中间产物。
- `libdemo_expand.so`：离线导出的 payload so。
- `*.embed.tmp.so`：embed 阶段临时产物。
- `libvmengine_patch.so`：最终可部署的 patch 后 vmengine。

## 8. 你最需要先理解的三个文件

- `VmProtect/app/zMain.cpp`
  这是离线主入口，先看总流程。
- `VmProtect/modules/pipeline/core/zPipelinePatch.cpp`
  这是从导出到 embed/patch 的关键衔接层。
- `VmEngine/app/src/main/cpp/zVmInitCore.cpp`
  这是运行时从嵌入 payload 到 takeover 生效的核心入口。

## 9. 常见认知误区

- 误区 1：`VmProtect` 只是“改导出表”
  实际上它先做函数翻译与 payload 打包，再做注入与可选 patch。

- 误区 2：patch 后一定要重排整份 ELF
  当前方案尽量利用 `.vmp_patchbay` 预留区做低破坏更新。

- 误区 3：运行时只是 `dlopen` 一个 so
  运行时还包含 payload 读取、缓存预热、slot 映射恢复和 dispatch 执行链。

## 10. 后续扩展建议

如果你准备继续扩展项目，建议优先按下面顺序阅读和改动：

1. 先改 `pipeline` 编排层，不直接改底层格式层。
2. 需要新增 ELF 能力时，优先加到 `elfkit`，通过 API 层对外暴露。
3. 需要改接管策略时，优先在 `patchbay/domain` 与 `VmEngine/zSymbolTakeover` 对齐设计。
4. 每次改动后都跑 `tools/run_regression.py`，避免“能编译但链路不通”。

