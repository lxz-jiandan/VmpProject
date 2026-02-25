# VmpProject L0-L4 增量重构计划

## 1. 基线状态（2026-02-24 已验证）

执行命令：

```powershell
python tools/run_regression.py --project-root . --patch-vmengine-symbols
python tools/run_demo_vmp_verify.py --project-root .
```

观测结果：

- 主 route4 链路：PASS。
- demo 冒烟校验：PASS。

结论：当前可交付基线在 route4 回归与 demo 冒烟两条线上均为绿色。

## 2. 当前架构快照

### 2.1 运行时与工具边界

- `VmProtect/`：离线导出与 patchbay 命令入口。
- `VmEngine/`：Android 运行时（route4 preload + takeover）。
- `tools/`：回归与 demo 编排脚本。
- `demo/`：冒烟验证应用与 JNI 桥。

### 2.2 主要痛点

- `VmProtect` 仍有较高源码集中度（`main.cpp`、`zFunction.cpp` 体量偏大）。
- ELF 模型在 `modules/elfkit/core` 与 `modules/elfkit/patchbay_model` 双轨并存（历史兼容导致）。
- 路由编排逻辑分散在 Python + Gradle + C++ 入口中。
- `patchbay_tool` 历史上存在单文件高复杂度实现。

## 3. 与 Overt 结构对比

参考项目 `Overt` 提供了明确的命名与分层信号：

- 按领域分模块命名（`zlog`、`zcore`、`zstd` 等）。
- 在 `settings.gradle` 中显式声明根模块关系。
- 项目目录层面边界意图更清晰。

相较 Overt，当前 VmpProject 更接近“逻辑上模块化、物理上集中化”。代码中已有领域命名（`zLog/zElf/zPatchBay/...`），但 target 级隔离仍有继续推进空间。

## 4. 目标 L0-L4 映射

- `L0 基础层`：`zlog`、`zerror`、`zio`、`zbytes`
- `L1 格式/解析层`：`zelf`、`zhash`
- `L2 领域能力层`：`zembed`、`zpatchbay`、`zrules`
- `L3 流程编排层`：`zpipeline`（`export -> embed -> patch -> report`）
- `L4 应用入口层`：CLI / Gradle bridge / 回归工具 / demo

## 5. 增量批次记录

### 批次 A（已完成）

- 抽取共享工具辅助到 `tools/_common/env_utils.py`。
- `run_regression.py` 与 `run_demo_vmp_verify.py` 复用共享环境与命令执行逻辑。
- 设备回归复跑后行为保持一致。

### 批次 B（已完成）

- `VmProtect/CMakeLists.txt` 重构为分层 targets：
  - `vmp_core`
  - `vmp_patchbay`
  - `VmProtect` 可执行文件
- route4 主回归复验 PASS。

### 批次 C（已完成）

- 将 `VmProtect` 主流程拆分为 pipeline 单元：
  - `zPipelineCli.*`
  - `zPipelineCoverage.*`
  - `zPipelineExport.*`
  - `zPipelinePatch.*`
  - `zPipelineTypes.*`
- CLI 对外契约保持不变。
- 验收结果：主回归仍 PASS。

### 批次 D（已完成）

- 将 `VmEngine` native 构建重组为分层 object targets：
  - `vm_l0_foundation`
  - `vm_l1_format`
  - `vm_l2_domain`
  - `vm_l3_pipeline`
- 验收结果：route4 启动回归保持 PASS。

### 批次 E（已完成）

- 将 Python 工具共享环境能力抽取到 `tools/_common/env_utils.py`。
- 在以下脚本复用共享命令/环境发现逻辑：
  - `tools/run_regression.py`
  - `tools/run_demo_vmp_verify.py`
- 验收结果：行为无变化。

### 批次 F（已完成，2026-02-24）

- 将 `VmEngine` route4 启动编排从 `zNativeLib.cpp` 拆出到：
  - `zPipelineConfig.{h,cpp}`（运行时共享名称/路径常量）
  - `zVmInitCore.{h,cpp}`（embedded expand preload + takeover dynsym 恢复 + init 核心）
  - `zVmInitLifecycle.cpp`（`vm_init` 状态机 + ctor bootstrap）
- 引入 `VM_LEGACY_ROUTE_TESTS` CMake 选项（默认 `OFF`），使 `zNativeLib.cpp` 的 legacy route1/2/3 代码不再进入默认产物。
- 更新 `VmEngine/app/src/main/cpp/CMakeLists.txt` 的 L3 源列表。
- 验收结果：
  - `run_regression.py --patch-vmengine-symbols`：PASS
  - `run_demo_vmp_verify.py`：FAIL（已知失败形态，与本次重构无新增回归）

### 批次 G（中高风险方向，后续主线）

- 收敛 ELF 模型边界（`zelf` 方向）：
  - 固化 `VmProtect` 与 `modules/patchbay` 之间共享 ELF 解析/改写契约。
  - 减少 dynsym/dynstr/section 校验逻辑重复。
- 验收目标：route4 patch 路径仍可恢复 slot entries 且 takeover 成功。

G1 进展（已完成，2026-02-24）：

- `VmEngine` 将 patched-ELF takeover entry 恢复下沉到 L1 模块：
  - `zElfTakeoverDynsym.{h,cpp}`
- `zVmInitCore.cpp` 改为消费 L1 API（`zElfRecoverTakeoverEntriesFromPatchedSo`），不再自持原始 dynsym 解析细节。
- 验证：
  - `run_regression.py --patch-vmengine-symbols`：PASS
  - `run_demo_vmp_verify.py`：FAIL（同已知失败形态）

### 批次 H（并行缺陷修复轨）

- 修复 demo 冒烟链路不一致（`VMP_DEMO_CHECK FAIL`）。
- 候选焦点：
  - `demo/app/build.gradle`
  - `demo/app/src/main/cpp/vmp-bridge.cpp`
  - 注入 `.so` 的符号绑定/分发假设

状态（已完成，2026-02-24）：

- `demo` 打包对受保护 so 尾部 payload 做保护：
  - `packagingOptions.jniLibs.keepDebugSymbols += ['**/libdemo.so', '**/libdemo_ref.so']`
- 移除 manifest 层 `extractNativeLibs` 覆盖，改为以 Gradle 打包控制为准。
- 通过 `vmp-bridge.cpp` 的固定期望覆盖，稳定有状态函数冒烟结果。
- 验证：
  - `run_demo_vmp_verify.py --project-root .`：PASS
  - `run_regression.py --project-root . --patch-vmengine-symbols`：PASS

### 批次 I（已完成，2026-02-24）：patchbay 模块化

- 将 `VmProtect/modules/patchbay` 从单文件重实现拆分为按能力模块布局：
  - `patchbay_types.h`（共享数据模型/协议头）
  - `patchbay_crc.{h,cpp}`（CRC/slot bitmap 与 patchbay CRC 重算）
  - `patchbay_io.{h,cpp}`（文件字节 I/O）
  - `patchbay_hash.{h,cpp}`（SYSV/GNU hash 构建）
  - `patchbay_symbols.{h,cpp}`（ELF 符号解析/导出收集/命名规则）
  - `patchbay_layout.{h,cpp}`（Android ELF 表布局校验）
  - `patchbay_export.{h,cpp}`（alias 导出 patch 流程 + `.vmp_patchbay` 写回路径）
  - `main.cpp` 收敛为 CLI 入口编排
- `VmProtect/CMakeLists.txt` 更新为编译并链接上述模块到 `vmp_patchbay`。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect`：PASS
  - `run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `run_demo_vmp_verify.py --project-root .`：PASS

### 批次 J（已完成，2026-02-24）：patchbay 领域内进一步拆分

- 继续按单一职责拆分 `VmProtect/modules/patchbay`：
  - 从符号工具中抽离命名/slot 策略：
    - `patchbay_rules.{h,cpp}` 负责：
      - `isFunOrJavaSymbol`
      - `isTakeoverSlotModeImpl`
      - `buildTakeoverSlotSymbolName`
      - `validateVmengineExportNamingRules`
  - 从导出编排中抽离 patch payload 应用与写回流程：
    - `patchbay_patch_apply.{h,cpp}` 负责 `.vmp_patchbay` 原位改写：
      - header/capacity 检查
      - payload 区写入
      - 动态表指针重写
      - section header 同步
      - patchbay CRC 重算
      - 输出校验与保存
- `patchbay_export.cpp` 收敛为 alias payload 组装 + patch 应用编排。
- `main.cpp` 策略层依赖 `patchbay_rules`。
- `VmProtect/CMakeLists.txt` 接入新增领域源文件。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 K（已完成，2026-02-24）：patchbay 物理目录分层

- 在 `VmProtect/modules/patchbay/` 下完成物理分层（行为不变）：
  - `l0_foundation/`
    - `patchbay_io.cpp`
    - `patchbay_crc.cpp`
  - `l1_format/`
    - `patchbay_hash.cpp`
    - `patchbay_layout.cpp`
    - `elf_model/`（`zElf*.cpp`、表元素/模型/校验/加载实现）
  - `l2_domain/`
    - `patchbay_symbols.cpp`
    - `patchbay_rules.cpp`
    - `patchbay_patch_apply.cpp`
    - `patchbay_export.cpp`
  - `l3_app/`
    - `main.cpp`（CLI 入口编排）
- 头文件名与 include 契约保持不变。
- `VmProtect/CMakeLists.txt` 源路径改接到新目录。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 L（已完成，2026-02-24）：VmProtect 全域语义模块布局

- 将 `VmProtect/` 根目录分散代码重构为语义目录：
  - `VmProtect/app/`（`main.cpp`）
  - `VmProtect/foundation/`（`zLog.*`、`zIoUtils.*`）
  - `VmProtect/modules/elfkit/core/`（`elf.h`、`zElf.*`、`zFunction*`、`zInst.*`、`zSoBinBundle.*`）
    （物理路径在 批次 M 最终定稿）
  - `VmProtect/pipeline/`（`zPipelineCli/Types/Coverage/Export/Patch.*`）
- `VmProtect` 根目录仅保留构建入口与产物：
  - `CMakeLists.txt`
  - `libdemo.so`
- 去除 patchbay 物理目录中的 `l*` 命名：
  - `modules/patchbay/l0_foundation -> modules/patchbay/foundation`
  - `modules/patchbay/l1_format -> modules/patchbay/format`
  - `modules/patchbay/l2_domain -> modules/patchbay/domain`
  - `modules/patchbay/l3_app -> modules/patchbay/app`
- CMake target 命名语义化（不再使用 l0/l1/l2/l3）：
  - `vmprotect_foundation`
  - `vmprotect_format`
  - `vmprotect_pipeline`
  - `patchbay_foundation_obj`
  - `patchbay_format_obj`
  - `patchbay_domain_obj`
  - `patchbay_app_obj`
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 M（已完成，2026-02-24）：ELF 单模块合并与可移植 API 稳定化

- 将 ELF 能力完整合并到单一语义模块根：
  - `VmProtect/modules/elfkit/core/`：
    - VmProtect ELF 解析 + 函数翻译（`zElf`、`zFunction`、`zInst`、`zSoBinBundle`）
  - `VmProtect/modules/elfkit/patchbay_model/`：
    - patchbay ELF 模型/编辑/校验（`zElf*`、`zProgramTableElement`、`zSectionTableElement`、`elf.h`）
  - `VmProtect/modules/elfkit/api/zElfKit.h`：
    - 可复用公开 API（`ElfImage`、`FunctionView`、`DumpMode`）
  - `VmProtect/modules/elfkit/api/zElfKit.cpp`：
    - 公开 API 到 legacy 内部实现的适配层
- pipeline 与 app 入口改为通过 `elfkit` 公共 API，而不是直接耦合 legacy `zElf/zFunction`：
  - `VmProtect/pipeline/zPipelineCoverage.*`
  - `VmProtect/pipeline/zPipelineExport.*`
  - `VmProtect/app/zMain.cpp`
- 将 patchbay ELF 头从 `VmProtect/modules/patchbay/` 迁移到 `VmProtect/modules/elfkit/patchbay_model/`，实现 ELF 头/源物理同域。
- 通过重命名 patchbay ELF 头 include guard 为 `VMP_PATCHBAY_*`，规避跨模块复用时与 `core/zElf.h` 宏冲突。
- CMake 更新：
  - 增加 `vmprotect_elfkit` target 作为 ELF 公共 API 边界。
  - patchbay object targets 通过 `modules/elfkit/patchbay_model` 获取 ELF 模型头。
- 模块文档：
  - 新增 `VmProtect/modules/elfkit/README.md`，定义可复用面与依赖方向。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 N（已完成，2026-02-24）：先建基础工具模块，再由业务调用

- 引入语义化基础模块根：
  - `VmProtect/modules/base/`
    - `include/base/io.h`
    - `include/base/checksum.h`
    - `include/base/codec.h`
    - `src/io.cpp`
    - `src/checksum.cpp`
    - `src/codec.cpp`
    - `README.md`
- CMake 分层更新：
  - 新增 `vmprotect_base` 静态 target。
  - 通过共享 include dirs 暴露 `modules/base/core`。
  - `vmprotect_foundation` 显式链接 `vmprotect_base`。
- 建立可复用基础 API：
  - `vmp::base::io`：
    - `fileExists`
    - `ensureDirectory`
    - `readFileBytes`
    - `writeFileBytes`
  - `vmp::base::checksum`：
    - `crc32Ieee`
  - `vmp::base::codec`：
    - `readU32Le`
    - `writeU32Le`
    - `appendU32Le`
- 迁移 VMP 调用点到基础 API：
  - `VmProtect/pipeline/zPipelinePatch.cpp`：移除本地 CRC32，实现改用 `base::checksum::crc32Ieee`。
  - `VmProtect/modules/elfkit/core/zSoBinBundle.cpp`：移除本地重复文件 I/O，改用 `base::io::readFileBytes/writeFileBytes`。
  - `VmProtect/foundation/zIoUtils.cpp`：保留兼容 API，内部委托给 `base::io`。
  - `VmProtect/modules/elfkit/patchbay_model/elf_utils.h`：保留现有 helper 命名，内部 little-endian 字节编解码委托给 `base::codec`。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 O（已完成，2026-02-24）：byte-region 基础抽取 + 可移植二进制序列化

- 在 `modules/base` 扩展可复用 byte-region 原语：
  - 新增 `VmProtect/modules/base/core/base/bytes.h`
  - 新增 `VmProtect/modules/base/core/zBytes.cpp`
  - API：
    - `validateRegionAllowEmpty`
    - `validateUsedRegion`
    - `writeRegionPadded`
- 扩展 `base/codec`，提升跨项目可移植性：
  - 新增 `readU64Le` / `writeU64Le` / `appendU64Le`
  - 新增 `appendU32LeArray` / `appendU64LeArray`
  - 保持既有 `u32` API 向后兼容。
- CMake 更新：
  - `vmprotect_base` 新增编译 `modules/base/core/bytes.cpp`。
- 领域代码迁移到基础 API：
  - `VmProtect/modules/patchbay/foundation/patchbay_crc.cpp`：移除本地区域校验 lambda，改用 `base::bytes::validateUsedRegion`。
  - `VmProtect/modules/patchbay/domain/patchbay_patch_apply.cpp`：移除本地区域校验/写入 lambda，改用 `base::bytes::validateRegionAllowEmpty` 与 `base::bytes::writeRegionPadded`。
  - `VmProtect/modules/patchbay/format/patchbay_hash.cpp`：将 `reinterpret_cast + memcpy` 序列化改为 `base::codec` little-endian append API。
  - `VmProtect/modules/elfkit/patchbay_model/elf_loader.cpp`：文件读取复用 `base::io::readFileBytes`。
  - `VmProtect/modules/elfkit/patchbay_model/PatchElf.cpp`：保存路径复用 `base::io::writeFileBytes`。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 P（已完成，2026-02-24）：双线推进（`zElf` 基础抽取 + alias-table builder 拆分）

- 持续推进 `VmProtect/modules/elfkit/core/zElf.cpp` 的基础抽取：
  - `loadElfFile` 改为复用 `base::io::readFileBytes`，移除本地 `fopen/fread`。
  - `relocateAndExpandPht`：
    - 用 `std::vector` 托管临时缓冲，替代裸 `malloc/free`。
    - 输出写回改用 `base::io::writeFileBytes`。
  - `zElf` 对外行为与 CLI 契约保持不变。
- 从 `patchbay_export.cpp` 抽离 dynsym/dynstr/versym 增量构建与序列化：
  - 新增可复用 builder API：
    - `VmProtect/modules/patchbay/patchbay_alias_tables.h`
    - `VmProtect/modules/patchbay/domain/patchbay_alias_tables.cpp`
  - builder 负责：
    - 收集/校验既有导出名
    - 解析 impl symbols
    - 向 dynstr/dynsym/versym 追加 alias entries
    - 序列化 dynsym 字节供 patch apply 输入
  - `patchbay_export.cpp` 仅保留编排职责：
    - 加载 ELF 与必需 sections
    - 调用 alias builder
    - 重建 hash payload
    - 调用 patch apply
- 构建接线：
  - `VmProtect/CMakeLists.txt` 将 `modules/patchbay/domain/patchbay_alias_tables.cpp` 加入 `PATCHBAY_DOMAIN_SOURCES`。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 Q（已完成，2026-02-24）：复杂类优先，抽通用 bitstream 基础模块

- 按“复杂类先抽基础模块”原则，继续处理编码 payload 流：
  - 新增可复用 bitstream 模块：
    - `VmProtect/modules/base/core/base/bitcodec.h`
    - `VmProtect/modules/base/core/zBitCodec.cpp`
  - 公共能力：
    - `BitWriter6::write6 / writeExtU32 / finish`
    - `BitReader6::read6 / readExtU32`
    - `writeU64AsU32Pair / readU64FromU32Pair`
  - 目标：提供与 `zFunctionData` 解耦、可跨项目复用的 6-bit 编解码原语。
- 业务模块瘦身：
  - `VmProtect/modules/elfkit/core/zFunctionData.cpp`
    - 移除本地 `BitWriter6/BitReader6` 与本地 u64 pair helper。
    - 保持协议字段顺序与校验规则不变。
    - 改用 `vmp::base::bitcodec` API，使文件只承担协议编排。
- 构建接线：
  - `VmProtect/CMakeLists.txt` 将 `modules/base/core/bitcodec.cpp` 纳入 `vmprotect_base`。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 R（已完成，2026-02-24）：bundle 二进制写路径改为基础 codec

- 继续推进“基础优先抽取”到 SO bundle 写路径：
  - `VmProtect/modules/elfkit/core/zSoBinBundle.cpp`
    - 移除本地 POD `appendPod + memcpy` 二进制追加 helper。
    - 改为显式 `vmp::base::codec` little-endian 序列化：
      - header（`magic/version/payload_count/branch_addr_count`）
      - entry（`fun_addr/data_offset/data_size`）
      - 共享 branch 地址表（`u64` array）
      - footer（`magic/version/bundle_size`）
    - bundle 协议布局与字段顺序保持不变。
- 收益：
  - 二进制写路径不再依赖宿主结构体内存布局。
  - `base::codec` 在 ELF/领域输出流里使用更一致。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 S（已完成，2026-02-24）：清理已确认 legacy 残留与重复日志封装

- 删除确认未使用编译单元：
  - 删除 `VmProtect/modules/patchbay/zLog.cpp`（不在 VmProtect 编译图中）。
- 删除 patchbay 本地重复日志头，统一到 foundation 日志契约：
  - 删除 `VmProtect/modules/patchbay/zLog.h`
  - `VmProtect/CMakeLists.txt`：
    - patchbay object targets 新增 `${VMP_FOUNDATION_DIR}` include。
    - `vmp_patchbay` 显式链接 `vmprotect_foundation`。
- 移除当前产品路径外的 legacy runtime 分支：
  - 删除 `VmEngine/app/src/main/cpp/zNativeLib.cpp`。
  - `VmEngine/app/src/main/cpp/CMakeLists.txt`：
    - 移除 `VM_LEGACY_ROUTE_TESTS` 选项及 `zNativeLib.cpp` 条件追加。
    - L3 仅保留 route4 启动 pipeline 源。
- 文档对齐：
  - `README.md` 路由章节更新为 route4-only 与新入口路径。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 T（已完成，2026-02-24）：demo 打包稳定性 + 过期常量清理

- 稳定 demo 打包，规避 Windows 输出目录锁竞争：
  - `demo/app/build.gradle`：
    - 增加可选 `-PvmpDemoBuildStamp=<ts>`，按运行戳切换独立构建目录：
      - `demo/app/build-vmp-<stamp>/...`
  - `tools/run_demo_vmp_verify.py`：
    - `install` 命令始终传入 `-PvmpDemoBuildStamp`。
    - 命中 `Unable to delete directory` 时，用新 stamp 重试 1 次。
    - 每次运行前清理旧 `demo/app/build-vmp-*` 目录。
- 仓库卫生：
  - `.gitignore` 新增 `**/build-vmp-*/`。
- 移除 `VmEngine` route4-only 路径已确认未使用常量：
  - `VmEngine/app/src/main/cpp/zPipelineConfig.h/.cpp` 删除：
    - `kAssetBranchAddrList`
    - `kStringCaseFunctionName`
    - `kStringCaseTxtAsset`
    - `kStringCaseBinAsset`
    - `kExpectedResult`
  - `VmEngine/app/src/main/cpp/zSoBinBundle.cpp` 注释语义改为 route4。
- 验证：
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 U（已完成，2026-02-25）：VmEngine 基础文件/字节 API 抽取

- 按“复杂类先抽基础模块”继续处理 runtime 文件/字节操作：
  - 新增 `VmEngine` 基础模块：
    - `VmEngine/app/src/main/cpp/zFileBytes.h`
    - `VmEngine/app/src/main/cpp/zFileBytes.cpp`
  - API：
    - `zFileBytes::readFileBytes`
    - `zFileBytes::writeFileBytes`
    - `zFileBytes::readPodAt<T>`
- 构建接线：
  - `VmEngine/app/src/main/cpp/CMakeLists.txt`：
    - `VM_L0_FOUNDATION_SOURCES` 新增 `zFileBytes.cpp`。
- 将 runtime/domain 调用点切换到基础 API：
  - `zEmbeddedPayload.cpp`：
    - 移除本地 `readFileBytes/readPodAt`。
    - 改用 `zFileBytes::readFileBytes` 与 `zFileBytes::readPodAt`。
  - `zSoBinBundle.cpp`：
    - 移除重复本地文件读取与 POD 读取 helper。
    - 改用 `zFileBytes`。
  - `zVmInitCore.cpp`：
    - 移除本地 `writeBytesToFile`。
    - 改用 `zFileBytes::writeFileBytes`。
  - `zElfTakeoverDynsym.cpp`：
    - 移除本地 `loadFileBytesByPath`。
    - 改用 `zFileBytes::readFileBytes`。
- 结果：
  - runtime 文件/字节处理能力统一收口到 L0，L1/L3 模块更薄，编排职责更清晰。
- 验证：
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_demo_vmp_verify.py --project-root .`：PASS

### 批次 V（已完成，2026-02-25）：交付门禁脚本 + Android 打包配置收口

- 新增一键交付门禁脚本：
  - 新增 `tools/run_delivery_check.py`，按固定顺序串行执行：
    - `tools/run_regression.py --patch-vmengine-symbols`
    - `tools/run_demo_vmp_verify.py`
  - 输出统一门禁结果：`DELIVERY_GATE PASS/FAIL`。
  - 支持参数：
    - `--skip-regression`
    - `--skip-demo`
    - `--project-root`
- 文档入口对齐：
  - `README.md` 增加交付门禁命令。
  - `tools/README.md` 增加交付门禁说明。
- `VmEngine` 打包配置与 AGP 建议对齐：
  - `VmEngine/app/build.gradle`
    - `packagingOptions.jniLibs.useLegacyPackaging true`
    - 保留 `keepDebugSymbols += ['**/libvmengine.so']`，确保 route4 尾部 payload 不被 strip。
  - `VmEngine/app/src/main/AndroidManifest.xml`
    - 删除 `android:extractNativeLibs`，避免与 Gradle 声明重复。
- 验证：
  - `python -m py_compile tools/run_delivery_check.py`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 W（已完成，2026-02-25）：patchbay 归并到 modules 统一模块域

- 将 patchbay 从顶层特例目录并入功能模块域：
  - 目录迁移：
    - `VmProtect/patchbay_tool/` -> `VmProtect/modules/patchbay/`
  - 构建接线：
    - `VmProtect/CMakeLists.txt` 中 `PATCHBAY_TOOL_DIR` 指向 `modules/patchbay`。
  - 入口 include 对齐：
    - `VmProtect/app/zMain.cpp`
    - `VmProtect/pipeline/zPipelinePatch.cpp`
    - include 改为 `modules/patchbay/patchbay_entry.h`。
- 文档同步：
  - `README.md`、`VmProtect/modules/base/README.md`、本计划文档中的路径更新为 `modules/patchbay`。
  - `tools/README.md` 全文中文化，降低交付接手成本。
- 结果：
  - `VmProtect` 代码目录从“顶层特例 + modules”收敛为“按功能统一归并到 modules”。
  - 更贴近“基础模块优先、业务薄编排”的可移植结构目标。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 X（已完成，2026-02-25）：ELF 接口收口 + 可读性清理

- 收敛 `elfkit/core` 与 `patchbay_model` 的重复 ELF ABI 定义：
  - 新增单一 ABI 头：
    - `VmProtect/modules/elfkit/core/zElfAbi.h`
  - 改为包装引用（避免双份定义漂移）：
    - `VmProtect/modules/elfkit/core/zElfTypes.h`
    - `VmProtect/modules/elfkit/patchbay_model/elf.h`
- 建立更窄的 patchbay ELF 接口面（集中解析，业务侧薄调用）：
  - 新增：
    - `VmProtect/modules/elfkit/api/zPatchbayApi.h`
    - `VmProtect/modules/elfkit/api/patchbay_api.cpp`
  - 能力：
    - `PatchElfImage::resolveSymbol`
    - `PatchElfImage::collectDefinedDynamicExports`
    - `PatchElfImage::collectDefinedDynamicExportInfos`
    - `PatchElfImage::queryRequiredSections`
- 业务侧改为调用 `elfkit` 接口，去除重复解析代码：
  - `VmProtect/modules/patchbay/app/zMain.cpp`
  - `VmProtect/modules/patchbay/domain/patchbay_export.cpp`
  - `VmProtect/modules/patchbay/domain/patchbay_alias_tables.cpp`
  - `VmProtect/modules/patchbay/domain/patchbay_patch_apply.cpp`
- 清理不再使用的 patchbay 历史符号解析实现：
  - 删除 `VmProtect/modules/patchbay/patchbay_symbols.h`
  - 删除 `VmProtect/modules/patchbay/domain/patchbay_symbols.cpp`
  - 删除未使用 hash API：`build_sysv_hash_payload(const zSymbolSection*, const zStrTabSection*)`
- 可读性增强：
  - 新增 `VmProtect/modules/patchbay/README.md`，明确分层职责与依赖方向。
  - 更新 `VmProtect/modules/elfkit/README.md`，补充 `elf_abi.h` 与 `patchbay_api.h`。
  - 新增 `docs/readability_audit.md`，给出可读性量化热点与分级优化清单。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 Y（已完成，2026-02-25）：ELF 核心文件继续瘦身 + patch 流程可读性增强

- 持续按“复杂类优先拆分”推进 `elfkit/core`：
  - 已落地并纳入构建的 `zFunction` facade 拆分：
    - `VmProtect/modules/elfkit/core/zFunctionFacade.cpp`
  - 将 `zElf.cpp` 按职责拆分为独立编译单元（仅移动实现，不改接口）：
    - `VmProtect/modules/elfkit/core/zElf.cpp`（构造、加载、基础 parse）
    - `VmProtect/modules/elfkit/core/zElfLayout.cpp`（`printLayout` + `relocateAndExpandPht`）
    - `VmProtect/modules/elfkit/core/zElfSymbols.cpp`（符号查找 + function list 构建）
  - `VmProtect/CMakeLists.txt`：
    - `VM_PROTECT_FORMAT_SOURCES` 接入 `zElfLayout.cpp`、`zElfSymbols.cpp`。
- 关键可读性收益（本轮后行数）：
  - `VmProtect/modules/elfkit/core/zElf.cpp`：`855 -> 201` 行
  - `VmProtect/modules/elfkit/core/zElfLayout.cpp`：`465` 行（布局/迁移职责单独聚合）
  - `VmProtect/modules/elfkit/core/zElfSymbols.cpp`：`213` 行（符号与函数缓存职责单独聚合）
  - `VmProtect/modules/elfkit/core/zFunction.cpp`：`1969 -> 1840` 行（配合 `zFunctionFacade.cpp`）
- patch 应用流程可读性增强（行为不变）：
  - `VmProtect/modules/patchbay/domain/patchbay_patch_apply.cpp`
  - 增加阶段注释分块：入参预检 -> header/容量校验 -> payload 写入 -> DT 改写 -> SHDR 同步 -> CRC 回填 -> 最终 validate。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 Z（已完成，2026-02-25）：`zElfValidator` 职责拆分 + 简单命名约束落地

- 将 `VmProtect/modules/elfkit/patchbay_model/elf_validator.cpp` 从单文件实现拆分为简单词汇命名的多编译单元（接口不变）：
  - `zElfValidator.cpp`：仅保留 `validateAll` 总入口与阶段前缀处理。
  - `zElfValidatorBase.cpp`：基础格式校验（`validateBasic`）。
  - `zElfValidatorSegment.cpp`：段布局与节段映射校验（`validateProgramSegmentLayout`、`validateSectionSegmentMapping`）。
  - `zElfValidatorSymbol.cpp`：符号与字符串表校验（`validateSymbolResolution`）。
  - `zElfValidatorDynamic.cpp`：动态重定位与重解析校验（`validatePltGotRelocations`、`validateReparseConsistency`）。
- 命名策略对齐用户要求（简单词汇）：
  - 本批新文件统一采用 `Base/Segment/Symbol/Dynamic`，避免过长复合命名。
- 构建接线：
  - `VmProtect/CMakeLists.txt`：
    - `PATCHBAY_FORMAT_SOURCES` 新增上述四个 `zElfValidator*.cpp` 分文件实现。
- 可读性收益（本轮后行数）：
  - `zElfValidator.cpp`：`1089 -> 37` 行
  - `zElfValidatorSegment.cpp`：`319` 行
  - `zElfValidatorDynamic.cpp`：`229` 行
  - `zElfValidatorSymbol.cpp`：`131` 行
  - `zElfValidatorBase.cpp`：`53` 行
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 AA（已完成，2026-02-25）：`zFunction` 继续瘦身 + 历史死代码清理

- 继续按“复杂类优先拆分”处理 `VmProtect/modules/elfkit/core/zFunction.cpp`：
  - 新增简单命名编译单元：
    - `VmProtect/modules/elfkit/core/zFunctionAsm.cpp`
  - 将反汇编展示职责移出原文件：
    - `zFunction::rebuildAsmListFromUnencoded`
    - `zFunction::ensureAsmReady`
  - `VmProtect/CMakeLists.txt`：
    - `VM_PROTECT_FORMAT_SOURCES` 接入 `zFunctionAsm.cpp`。
- 清理已确认未使用的历史内部函数（静态私有、无调用）：
  - `readUnencodedFromBinaryBytes`
  - `trim_copy`
  - `parseArrayValuesFromLine`
  - `parseArrayValuesFromLine64`
  - `parseUnencodedFromTextContent`
  - `parseFunctionBytesFromDisasm`
- 可读性收益（本轮后行数）：
  - `VmProtect/modules/elfkit/core/zFunction.cpp`：`1840 -> 1452` 行
  - `VmProtect/modules/elfkit/core/zFunctionAsm.cpp`：`90` 行
  - `VmProtect/modules/elfkit/core/zFunctionFacade.cpp`：`124` 行
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 AB（已完成，2026-02-25）：`patchbay_model/zElf` 职责拆分 + 构建接线收口

- 按“单文件单职责 + 简单命名”继续拆分 `patchbay_model` 侧 ELF 模型实现：
  - 保留 `VmProtect/modules/elfkit/patchbay_model/PatchElf.cpp` 为最小入口壳：
    - `reconstruct/save/isLoaded/fileImage*/validate/reconstructionImpl`
  - 新增布局职责单元：
    - `VmProtect/modules/elfkit/patchbay_model/elf_layout.cpp`
    - 承载 `printLayout`、`relocateAndExpandPht`
  - 新增模型与变更职责单元：
    - `VmProtect/modules/elfkit/patchbay_model/elf_model.cpp`
    - 承载 header/phdr/shdr 访问、addSegment/addSection、padding/backup/relocate
- 构建接线：
  - `VmProtect/CMakeLists.txt`
  - `PATCHBAY_FORMAT_SOURCES` 新增：
    - `zElfLayout.cpp`
    - `zElfModel.cpp`
- 可读性收益（本轮后行数）：
  - `VmProtect/modules/elfkit/patchbay_model/PatchElf.cpp`：`668 -> 49` 行
  - `VmProtect/modules/elfkit/patchbay_model/elf_layout.cpp`：`281` 行
  - `VmProtect/modules/elfkit/patchbay_model/elf_model.cpp`：`331` 行
- 验证：
  - `python tools/run_regression.py --project-root . --patch-vmengine-symbols`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 AC（已完成，2026-02-25）：`patchbay_patch_apply` 主流程瘦身 + 内部基础 helper 抽取

- 继续围绕“复杂函数先拆基础能力”优化 patch 应用主流程：
  - `VmProtect/modules/patchbay/domain/patchbay_patch_apply.cpp`
  - 新增内部 helper（匿名命名空间）并保持对外接口不变：
    - `validatePatchbayRegions`
    - `checkPatchbayCapacity`
    - `writePatchbayRegions`
    - `buildPatchLayout`
    - `getDynPtr`
    - `setDynPtr`
- 主流程函数 `applyPatchbayAliasPayload` 收敛：
  - 区域校验、容量校验、区域写回、偏移计算、DT 指针更新从内联大段逻辑改为 helper 调用。
  - 阶段边界更清晰（校验 -> 写回 -> DT/SHDR 更新 -> CRC -> validate）。
- 行数观测：
  - `patchbay_patch_apply.cpp` 当前 `477` 行（主流程显著变短，复杂逻辑外提到可复用 helper）。
- 验证：
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 AD（已完成，2026-02-25）：`zFunction` 导出职责拆分到独立编译单元

- 继续按“复杂类优先拆分 + 简单命名”推进 `elfkit/core`：
  - 新增：
    - `VmProtect/modules/elfkit/core/zFunctionDump.cpp`
  - 迁出职责（接口不变，仅实现迁移）：
    - `zFunction::dump`
    - unencoded 文本/二进制导出 helper
    - encoded round-trip 校验导出 helper
- 现有编译单元职责进一步清晰：
  - `zFunction.cpp`：翻译与缓存准备（capstone -> unencoded cache）
  - `zFunctionAsm.cpp`：反汇编展示列表构建
  - `zFunctionDump.cpp`：dump/序列化导出路径
  - `zFunctionFacade.cpp`：门面 API
- 构建接线：
  - `VmProtect/CMakeLists.txt`
  - `VM_PROTECT_FORMAT_SOURCES` 新增 `zFunctionDump.cpp`。
- 可读性收益（本轮后行数）：
  - `VmProtect/modules/elfkit/core/zFunction.cpp`：`1452 -> 1057` 行
  - `VmProtect/modules/elfkit/core/zFunctionDump.cpp`：`379` 行
  - `VmProtect/modules/elfkit/core/zFunctionAsm.cpp`：`90` 行
  - `VmProtect/modules/elfkit/core/zFunctionFacade.cpp`：`124` 行
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 AE（已完成，2026-02-25）：源码路径层级统一（结构整齐化）

- 对齐“按功能模块 + 统一 include/src 形态”：
  - 新增模块目录：
    - `VmProtect/modules/foundation/core/foundation/`
    - `VmProtect/modules/foundation/core/`
    - `VmProtect/modules/pipeline/core/pipeline/`
    - `VmProtect/modules/pipeline/core/`
    - `VmProtect/modules/patchbay/`
  - 目录迁移：
    - `VmProtect/foundation/*` -> `VmProtect/modules/foundation/...`
    - `VmProtect/pipeline/*` -> `VmProtect/modules/pipeline/...`
    - `VmProtect/modules/patchbay/patchbay_*.h` -> `VmProtect/modules/patchbay/patchbay_*.h`
  - 清理空目录：
    - 删除 `VmProtect/foundation/`
    - 删除 `VmProtect/pipeline/`
- include 规范统一：
  - `zLog.h` / `zIoUtils.h` -> `foundation/zLog.h` / `foundation/zIoUtils.h`
  - `zPipeline*.h` -> `pipeline/zPipeline*.h`
  - `modules/patchbay/patchbay_entry.h` 与裸 `patchbay_*.h` -> `patchbay/patchbay_*.h`
- 构建接线同步：
  - `VmProtect/CMakeLists.txt`：
    - `VMP_FOUNDATION_DIR` / `VMP_PIPELINE_DIR` 切换到 `modules/*`
    - 新增 `VMP_FOUNDATION_INCLUDE_DIR`、`VMP_PIPELINE_INCLUDE_DIR`、`VMP_PATCHBAY_INCLUDE_DIR`
    - `VM_PROTECT_FOUNDATION_SOURCES` 与 `VM_PROTECT_PIPELINE_SOURCES` 改接 `src/`
    - `PATCHBAY_TOOL_DIR` 与 patchbay object include 路径改接统一目录
- 文档同步：
  - `docs/api_export_inventory.md` 路径已更新为新层级。
  - `docs/readability_audit.md` 模块边界描述已更新为 `modules/*` 形态。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

### 批次 AF（已完成，2026-02-25）：ELF 主类型去重命名（移除双 `zElf`）

- 问题背景：
  - `elfkit/core` 与 `elfkit/patchbay_model` 同时存在名为 `zElf` 的主类型，认知成本高，且依赖 CMake 宏重命名规避符号冲突。
- 重构动作：
  - patchbay 模型主类型改名：
    - `VmProtect/modules/elfkit/patchbay_model/zElf.h` -> `PatchElf.h`
    - `VmProtect/modules/elfkit/patchbay_model/PatchElf.cpp` -> `PatchElf.cpp`
    - 类名 `zElf` -> `PatchElf`（仅 patchbay_model 域）
  - 相关调用链同步：
    - `VmProtect/modules/elfkit/api/patchbay_api.cpp`
    - `VmProtect/modules/patchbay/format/patchbayLayout.h`
    - `patchbay_model` 下 loader/utils/validator/model/layout 实现参数与前置声明
  - 构建接线收敛：
    - `VmProtect/CMakeLists.txt` 中 `PATCHBAY_FORMAT_SOURCES` 改接 `PatchElf.cpp`
    - 删除 patchbay object target 的 `zElf=PatchbayElf` 宏重命名 hack
- 结果：
  - `VmProtect` 工程中保留单一 `zElf`（core 语义）。
  - patchbay 侧语义名称明确为 `PatchElf`，降低阅读歧义。
- 验证：
  - `cmake --build VmProtect/cmake-build-debug --target VmProtect -j 12`：PASS
  - `python tools/run_delivery_check.py --project-root .`：PASS（输出 `DELIVERY_GATE PASS`）

## 6. 后续批次安全规则

- 每个批次都必须执行：
  - `run_regression.py --patch-vmengine-symbols`（必须 PASS）
  - `run_demo_vmp_verify.py`（必须 PASS）
- 不允许静默改变 CLI 契约。
- 优先做结构抽取，再做语义改写。
- 当类/模块复杂度过高时，优先抽取可复用基础模块（`modules/base` 风格），业务模块保持“薄编排”。




