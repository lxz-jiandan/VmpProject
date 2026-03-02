# VmProject

VmProject 是一个面向 Android ARM64 `so` 的离线加固与运行时接管工程。  
当前以 `route4` 作为主路线，核心目标如下：

- 离线阶段把目标函数翻译为 VM 可执行载荷（payload）；
- 运行时由 `VmEngine` 接管目标导出并完成分发执行；
- 在不修改业务调用方代码的前提下，实现可控、可回归、可扩展的保护链路。

术语约定：

- `so`：ELF 动态库文件；
- `payload`：离线翻译后的函数执行载荷；
- `patch`：离线阶段执行的符号与布局补丁。

---

## 一、项目概述

从端到端链路看，项目完成了三项核心能力建设：

1. **把 origin `so` 的目标函数变成 VM `payload`**
2. **把 `payload` 嵌入并绑定到运行时引擎**
3. **把原始导出调用稳定接管到 VM 执行路径**

对业务侧而言，调用方式保持原有导出符号形式；对系统侧而言，实际执行路径已切换到 VM。

---

## 二、总体架构（离线与运行时）

### 2.1 离线侧（VmProtect）

离线阶段负责受保护产物生产，核心动作包括：

- 解析 ELF，定位目标函数；
- 做可翻译性分析（覆盖率/指令支持）；
- 导出 `payload`（函数编码 + 分支地址信息）；
- 执行 `embed` 与 `patch`，输出最终受保护 `so`。

设计要点：

- 路线由 `--mode` 显式控制（`coverage/export/embed/protect`）；
- `protect` 路线是完整链路（导出 + 嵌入 + 接管补丁）。

### 2.2 运行时（VmEngine）

运行时负责离线产物落地执行，核心动作包括：

- `so` 加载时自动初始化；
- 从宿主 `so` 尾部读取嵌入 `payload`；
- 内存方式装载 expand `so`，并预热函数缓存；
- 对外提供统一接管入口，按 `key` 路由分发到 VM 执行。

设计要点：

- 接管入口统一；
- 初始化有生命周期状态机；
- 失败路径可快速诊断（快速失败，Fail-Fast）。

---

## 三、模块职责划分

### 3.1 `VmProtect`（离线系统）

定位：加固产物生产线。  
职责：分析、导出、嵌入、补丁编排。  
关注点：构建可复现、参数可控、失败可定位。

### 3.2 `VmEngine`（运行时内核）

定位：执行与接管内核。  
职责：初始化、`payload` 装载、路由分发、VM 执行。  
关注点：加载稳定性、调用语义一致性、运行时性能与可靠性。

### 3.3 `demo`（验证工程）

定位：链路验证与行为对照。  
职责：触发真实调用路径、展示 expected/actual、输出回归标记。  
关注点：快速发现回归，不做核心逻辑承载。

### 3.4 `tools`（自动化脚本）

定位：工程化入口。  
职责：构建串联、安装启动、日志判定、回归闭环。  
关注点：一键复现、稳定清理、可追踪输出。

### 3.5 `shared`（共享协议）

定位：跨模块协议约束。  
职责：定义离线侧与运行时共享的数据/布局约定。  
关注点：双端一致性，避免协议漂移。

---

## 四、核心原理与设计说明

### 4.1 接管思路：符号名不变，执行路径可控

项目保持业务调用方式不变，在离线 `patch` 后将导出符号统一汇聚到接管入口。  
该设计的主要效果：

- 外部调用面保持稳定；
- 内部执行策略可演进；
- 后续扩展多模块时路由模型不需要推倒重来。

### 4.2 路由模型：`symbolKey + soId`

接管分发采用 `key` 路由模型，而非固定槽位模型。  
该设计的主要效果：

- 避免“槽位数量/顺序”带来的脆弱耦合；
- 保持构建结果稳定；
- 为多 `so` 扩展预留天然维度。

### 4.3 指令翻译思路（elfkit）

翻译策略采用“结构化翻译 + 严格失败”：

- 以结构化反汇编信息为准；
- 语义按域分类后再分发翻译；
- 不能可靠翻译时立即失败并给出定位信息。

该设计的主要效果：

- 行为边界清晰；
- 问题更容易复现和回归；
- 避免静默降级导致的隐蔽错误。

### 4.4 `BL` 处理思路：离线抽象，运行时重定位

`BL` 是离线与运行时耦合最强的环节之一。当前采用：

- 离线阶段把目标调用抽象成稳定索引/映射信息；
- 运行时按实际加载地址完成最终定位与调用桥接。

该设计同时满足以下目标：

- 调用语义不丢（ABI 维持）；
- 地址环境变化可适配（重定位可控）。

### 4.5 装载思路：嵌入 `payload` + 自定义链接器（linker）

运行时既需要读取嵌入 `payload`，也需要在设备侧稳定完成装载与解析。  
当前设计重点包括：

- 路径统一（初始化流程固定）；
- 状态明确（生命周期可观测）；
- 异常可诊断（日志与错误路径完整）。

---

## 五、关键难点与应对方式

### 难点 1：在不改业务调用面的前提下完成执行接管

解决方式：统一接管入口 + `key` 路由协议。  
结果：导出名可保持，执行逻辑可替换。

### 难点 2：离线地址与运行时地址不一致

解决方式：离线产物提供可重定位信息，运行时按加载基址修正。  
结果：跨环境调用稳定，不依赖固定地址。

### 难点 3：链路较长，问题容易跨模块传播

解决方式：快速失败（Fail-Fast） + 回归脚本 + 标记化日志。  
结果：问题能在“离线/运行时/打包”层快速归位。

### 难点 4：扩展性要求与当前实现兼容

解决方式：路由协议保留 `soId` 维度，入口保持单一。  
结果：未来扩展不需要重构主调用协议。

---

## 六、构建与回归流程

### 6.1 基础构建

构建 `VmProtect`：

```powershell
cmake -S VmProtect -B VmProtect/cmake-build-debug -G Ninja
cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12
```

构建 `demo` origin `so`：

```powershell
cd demo
./gradlew.bat externalNativeBuildDebug --rerun-tasks
```

构建 `VmEngine` native：

```powershell
cd VmEngine
./gradlew.bat externalNativeBuildDebug --rerun-tasks
```

### 6.2 离线命令示例

仅导出：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --mode export `
  --input-so demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so `
  --function fun_add `
  --function fun_for
```

完整保护：

```powershell
VmProtect/cmake-build-debug/VmProtect.exe `
  --mode protect `
  --input-so demo/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libdemo.so `
  --vmengine-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine.so `
  --output-so VmEngine/app/build/intermediates/cxx/Debug/<hash>/obj/arm64-v8a/libvmengine_patch.so `
  --function fun_add `
  --function fun_for
```

### 6.3 回归入口

完整回归：

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

安装与启动回归（快速路径）：

```powershell
python tools/run_install_start_regression.py --project-root . --rerun-tasks
```

---

## 七、排障方法（按链路分层）

排障建议先判断问题所属层级：

1. **离线导出层**：函数不可翻译、产物缺失、`patch` 失败
2. **打包集成层**：产物未被正确覆盖/拷贝
3. **运行时初始化层**：`payload` 读取/装载失败
4. **执行分发层**：路由不命中、调用结果异常

排障原则：

- 先看回归脚本结论与关键日志标记（marker）；
- 再按层收窄范围，避免跨层假设；
- 优先处理最早出现的失败点。

---

## 八、设计边界与扩展方向

当前设计边界：

- 以 `route4` 为主链路；
- 核心协议围绕 `symbolKey + soId`；
- 运行时入口保持统一。

在保持兼容性的前提下，可按以下方向扩展：

1. 多 origin `so` 的统一编排；
2. 更细粒度的函数选择与策略分级；
3. 更完善的性能画像与稳定性基线。

---

## 九、阅读路径建议

首次阅读该项目时，建议按以下顺序：

1. 本 README（先建立整体认知）
2. `VmProtect` 主流程与模式（理解离线生产线）
3. `VmEngine` 初始化与接管链路（理解运行时执行）
4. `tools` 回归脚本（理解工程验证闭环）

阅读目标是先建立稳定的系统级认知，再进入实现细节。
