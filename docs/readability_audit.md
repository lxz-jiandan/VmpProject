# 可阅读性评估（2026-02-25）

本文聚焦三个维度：

1. 架构可读性（目录与依赖方向是否一眼能懂）
2. 代码可读性（单文件复杂度、职责边界、命名一致性）
3. 维护可读性（文档、回归入口、交付判定）

## 1. 当前结论

当前项目“可读性”已明显优于重构前，但还没有到“优秀项目的上限”。

- 已达到：
  - 模块边界基本清晰（`modules/base`、`modules/foundation`、`modules/elfkit`、`modules/patchbay`、`modules/pipeline`）。
  - 交付链路可追踪（`tools/run_delivery_check.py` 一键门禁）。
  - patchbay 的 ELF 解析入口已收敛到 `elfkit/patchbay_api.h`。
  - `zElf` 已按职责拆分为 `zElf.cpp` / `zElfLayout.cpp` / `zElfSymbols.cpp`。
  - `zElfValidator` 已按职责拆分为 `Base/Segment/Symbol/Dynamic` 四个实现单元。
  - `zFunction` 已拆分出 `Facade/Asm/Dump` 单元，主文件体积明显下降。
- 仍需优化：
  - 核心大文件仍集中在 `zFunction.cpp`、`tools/run_regression.py`、`patchbay_patch_apply.cpp`。
  - 少数接口命名还保留历史风格（`z*` + 现代 API 混用）。
  - 关键流程文档有了，但“读代码前 5 分钟上手图”仍可加强。

## 2. 现状数据（按行数）

以下统计排除了第三方 SDK 头文件后的主要热点：

- `VmProtect/modules/elfkit/core/zFunction.cpp`：1057 行
- `tools/run_regression.py`：595 行
- `VmProtect/modules/patchbay/domain/patchbay_patch_apply.cpp`：477 行
- `VmProtect/modules/elfkit/core/zElfLayout.cpp`：465 行
- `VmProtect/modules/elfkit/core/zFunctionDump.cpp`：379 行
- `VmProtect/modules/elfkit/patchbay_model/elf_model.cpp`：331 行
- `VmProtect/modules/elfkit/patchbay_model/elf_validator_segment.cpp`：319 行
- `VmProtect/modules/elfkit/patchbay_model/elf_layout.cpp`：281 行
- `VmProtect/modules/elfkit/patchbay_model/elf_validator_dynamic.cpp`：229 行

这组数据说明：复杂度已从单文件 `zElf.cpp`、`zElfValidator.cpp`、`zFunction.cpp` 持续分散到更清晰的职责单元；其中 `patchbay_model/PatchElf.cpp` 已完成大幅瘦身（49 行），`zFunction` 的导出路径也已迁出到 `zFunctionDump.cpp`，下一步应优先继续处理 `zFunction.cpp` 的翻译规则聚合与 `tools/run_regression.py` 的脚本拆分。

## 3. 优化优先级建议

### P0（建议立即做）

- 将 `zFunction.cpp` 按职责拆成：
  - 指令翻译规则（按语义分组）
  - branch 重映射
  - 错误建模/诊断输出
- `zFunction` 已拆分 `Asm/Facade/Dump`；下一步建议继续把翻译规则按指令族拆分独立单元。
- `zElfValidator` 已拆分；下一步把 `zElfValidatorSegment.cpp` 再细分为“段结构规则”和“段重叠规则”两块。
- `patchbay_patch_apply.cpp` 已抽取 `region/layout/DT` helper；下一步建议继续把 `SHDR` 更新与 `CRC` 回填分离为独立 helper，降低主流程认知跳转。

### P1（建议本阶段完成）

- 统一命名风格：
  - 对外稳定接口用 `elfkit::*` 语义名；
  - `z*` 保留为内部实现细节，不再向业务层扩散。
  - 新增文件/模块优先使用简单词汇命名（如 `Base/Segment/Symbol/Dynamic`），避免过长复合词。
- 在 `README.md` 增加“5 分钟架构图 + 调用链图（L0-L4）”。
- 在 `tools/` 增加“脚本输入输出契约表”（参数、默认值、失败码）。

### P2（持续演进）

- 引入“文件复杂度红线”规则（例如单文件 > 800 行需拆分评审）。
- 逐步补齐每个模块 README 的“责任边界 + 禁止依赖方向”。
- 为高风险流程（patch apply）补充更细粒度单元测试夹具。

## 4. 总体判断

当前项目已具备交付可读性，但距离“优秀项目”的标准仍有一段可量化差距。

重点不是再做目录搬迁，而是继续降低大文件复杂度和认知跳转成本。
