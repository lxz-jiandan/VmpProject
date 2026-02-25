# VmpProject：教学 + 原理版 README

这份文档不是“命令清单”，而是按教学顺序解释：

1. 这套方案在解决什么问题。
2. 为什么这样设计（原理）。
3. 如何验证“方案真的成立”（不是只看能跑）。

---

## 1. 问题定义

目标：把目标 `so` 中的函数迁移到 VM 执行路径，同时尽量保持外部行为不变。

工程当前采用三段式：

1. 离线翻译导出（`VmProtect.exe`）。
2. payload 嵌入宿主 `so`（embed）。
3. 导出接管（patchbay），把导出符号指向接管实现。

---

## 2. 工程组成

- `VmProtect/`
  - 离线工具，产出 `VmProtect.exe`。
  - 同时内置 patchbay 子命令（`export_alias_from_patchbay` 等）。
- `VmEngine/`
  - Android 运行时，负责加载与执行 VM 数据。
- `tools/`
  - 自动化脚本（构建、回归、安装、logcat 判定）。
- `demo/`
  - 最小验证工程。

---

## 3. 核心原理（重点）

### 3.1 原理 A：函数语义先“数据化”，再“执行化”

不是在运行时直接改原始函数机器码，而是离线先把函数转成可被 VM 消费的数据：

- `fun_xxx.txt`：未编码文本表示，便于排查和教学对照。
- `fun_xxx.bin`：编码后的运行时载荷。
- `branch_addr_list.txt`：多函数共享的分支地址表。

本质上是“先做可重建的数据模型，再做执行”。

---

### 3.2 原理 B：同一语义，多种载体，逐层验证

同一批函数有三种主要承载方式：

1. `assets/*.txt`（未编码文本）
2. `assets/*.bin`（编码二进制）
3. `libdemo_expand.so`（容器承载编码数据）

运行时仅保留 route4（内嵌 payload + 导出接管）单路线校验，历史 route1/2/3 代码已从主工程移除。

---

### 3.3 原理 C：等价性验证不是“是否崩溃”，而是“结果一致”

`VmEngine` 当前仅保留 route4 启动链路：

- `route4_reference_from_assets`
- `route_embedded_expand_so`
- `route_symbol_takeover`

关键思想：

- route4 启动时先从 `assets/*.txt` 提取函数地址并加载固定期望值，作为 takeover 对照基线。
- route4 L1/L2 必须同时通过，才能认定当前加固链路健康。
- 主链路保持单路径，降低分叉逻辑与维护成本。

---

### 3.4 原理 D：embed 采用“尾部附加 + footer”而不是改写主体布局

Route4 L1 不是重排整个 ELF，而是把 `libdemo_expand.so` 作为 payload 追加到 `libvmengine.so` 末尾，并写入 footer 元数据：

- magic/version
- payload_size
- payload_crc32

优点：

- 对原有段布局扰动小。
- 可做完整性校验（CRC）。
- 可支持“已有 payload 时替换”。

---

### 3.5 原理 E：patchbay 采用“预留区改写”，降低全局 ELF 重排风险

Route4 L2 的关键不是“随意改 ELF”，而是提前在目标 so 预留 `.vmp_patchbay` 区域，再在该区域内更新：

- `dynsym`
- `dynstr`
- `gnu hash / sysv hash`
- `versym`

并把新增导出映射到统一实现符号（默认 `z_takeover_dispatch_by_id`）。

这比“后处理全文件重构”风险更可控，尤其在 Android linker 兼容性上更稳。

---

### 3.6 原理 F：当前已统一单工具模型，减少分叉复杂度

当前工程已经收敛为：

- Stage3 固定通过 `VmProtect.exe` 内置 patchbay 执行。
- 不再走外部 patch 工具覆盖链路。

这样做的目的：

- 降低配置分叉和环境差异。
- 回归路径更确定，问题定位更直接。

---

## 4. 你应掌握的“输入/输出契约”

### 4.1 VmProtect 主流程输入

- 必须提供输入 so：
  - `--input-so <path>`

### 4.2 VmProtect 主流程输出（典型）

- `fun_*.txt`
- `fun_*.bin`
- `branch_addr_list.txt`
- `libdemo_expand.so`
- `coverage_report.md`

### 4.3 Stage3 patchbay 子命令（核心）

常用命令：

```powershell
VmProtect.exe export_alias_from_patchbay <input_elf> <donor_elf> <output_elf> <impl_symbol> [--allow-validate-fail] [--only-fun-java]
```

---

## 5. 快速上手（先跑通）

在仓库根目录：

```powershell
python tools/run_regression.py --project-root .
```

如果要把导出接管路径也包含在回归中：

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
```

如果要做“可交付一键门禁检查”（回归 + demo 冒烟串行）：

```powershell
python tools/run_delivery_check.py --project-root .
```

---

## 6. 教学实验（建议顺序）

### 实验 1：只跑离线导出

```powershell
VmProtect\cmake-build-debug\VmProtect.exe --input-so VmProtect/libdemo.so --function fun_add --function fun_for
```

观察：

1. 是否生成 `fun_add.txt/bin`、`fun_for.txt/bin`。
2. `coverage_report.md` 的覆盖统计是否合理。

### 实验 2：跑 Android 全链路

```powershell
cd VmEngine
gradlew.bat installDebug -PvmpEnabled=true
```

教学目的：理解 Stage1~Stage3 如何在 Gradle 内串联。

---

## 7. 回归判定（不要只看安装成功）

`tools/run_regression.py` 重点检查以下 marker（route4-only）：

- `route4_reference_from_assets result=1`
- `route_embedded_expand_so result=1 state=0`
- `route_symbol_takeover result=1`

只要这些关键结果不成立，就不能算“方案成立”。

---

## 8. 常见问题与原理定位

1. `input so is empty (use --input-so)`
   - 含义：主流程没有输入契约，不会再用隐式默认路径兜底。
   - 处理：补 `--input-so`。

2. `input so not found: ...`
   - 含义：路径存在性检查失败。
   - 处理：改为绝对路径或确认相对路径基准目录。

3. `VmProtect executable not found (build VmProtect first)`
   - 含义：回归脚本找不到工具二进制。
   - 处理：先构建 `VmProtect`，或修正工具路径。

4. `route_symbol_takeover` 不一致
   - 含义：导出接管后的符号行为与基线不一致。
   - 排查优先级：
     1. donor 导出是否符合预期。
     2. impl symbol 是否正确（默认 `z_takeover_dispatch_by_id`）。
     3. patchbay 是否实际追加了目标导出。

---

## 9. 关键代码入口（按原理查）

- `VmProtect/app/main.cpp`
  - CLI 契约、embed、patchbay 调用。
- `VmProtect/modules/patchbay/app/main.cpp`
  - patchbay 子命令实现入口。
- `VmEngine/app/src/main/cpp/zVmInitCore.cpp`
  - route4 初始化主流程（embedded expand + symbol takeover）。
- `VmEngine/app/src/main/cpp/zVmInitLifecycle.cpp`
  - 运行时生命周期入口与 `vm_init` 状态机。
- `VmEngine/app/src/main/cpp/zPatchBay.h`
  - `.vmp_patchbay` 预留区结构定义说明。
- `VmEngine/app/build.gradle`
  - Stage1~Stage3 的 Gradle 串联逻辑。
- `tools/run_regression.py`
  - 端到端自动回归入口。

---

## 10. 一句话总结这套方案

先把函数语义离线“数据化”，再通过可控的 embed 与导出接管把执行路径切换到 VM，并以 route4 启动回归确保主链路可重复、可验证。
