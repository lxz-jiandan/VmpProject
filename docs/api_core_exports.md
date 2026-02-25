# 核心导出 API 设计稿（可编辑）

说明：
- 本文件只放“核心导出面”草案，不是全量声明。
- `导出级别` 含义：
  - `核心导出`：建议保留为跨模块/跨项目稳定接口。
  - `可内部化`：当前可见，但后续可下沉到模块内部实现，不对外承诺稳定性。
- 你可以直接修改函数名、分层、参数、返回值和导出级别；我将按你修改后的版本重构代码。

## L0 基础层（base / foundation）

### `bool vmp::base::io::fileExists(const std::string& path)`
- 作用：判断文件是否存在。
- 入参：`path`，文件路径。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::base::io::ensureDirectory(const std::string& path)`
- 作用：确保目录存在（不存在则创建）。
- 入参：`path`，目录路径。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::base::io::readFileBytes(const char* path, std::vector<uint8_t>* out)`
- 作用：读取文件全部字节。
- 入参：`path` 文件路径；`out` 输出缓冲。
- 出参：返回 `true/false`，成功时写入 `out`。
- 导出级别：核心导出。

### `bool vmp::base::io::writeFileBytes(const std::string& path, const std::vector<uint8_t>& data)`
- 作用：写入字节到文件。
- 入参：`path` 文件路径；`data` 待写入字节。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::base::codec::readU32Le(const std::vector<uint8_t>& bytes, size_t offset, uint32_t* out)`
- 作用：按小端从缓冲读取 `u32`。
- 入参：`bytes`、`offset`、`out`。
- 出参：返回 `true/false`，成功时写入 `out`。
- 导出级别：核心导出。

### `bool vmp::base::codec::readU64Le(const std::vector<uint8_t>& bytes, size_t offset, uint64_t* out)`
- 作用：按小端从缓冲读取 `u64`。
- 入参：`bytes`、`offset`、`out`。
- 出参：返回 `true/false`，成功时写入 `out`。
- 导出级别：核心导出。

### `bool vmp::base::codec::writeU32Le(std::vector<uint8_t>* bytes, size_t offset, uint32_t value)`
- 作用：按小端向缓冲写入 `u32`。
- 入参：`bytes`、`offset`、`value`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::base::codec::writeU64Le(std::vector<uint8_t>* bytes, size_t offset, uint64_t value)`
- 作用：按小端向缓冲写入 `u64`。
- 入参：`bytes`、`offset`、`value`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `void vmp::base::codec::appendU32Le(std::vector<uint8_t>* out, uint32_t value)`
- 作用：在缓冲尾部追加 `u32`。
- 入参：`out`、`value`。
- 出参：无（原地修改 `out`）。
- 导出级别：可内部化。

### `void vmp::base::codec::appendU64Le(std::vector<uint8_t>* out, uint64_t value)`
- 作用：在缓冲尾部追加 `u64`。
- 入参：`out`、`value`。
- 出参：无（原地修改 `out`）。
- 导出级别：可内部化。

### `uint32_t vmp::base::hash::elfSysvHash(const char* name)`
- 作用：计算 ELF SYSV hash。
- 入参：`name` 符号名。
- 出参：返回 hash 值。
- 导出级别：核心导出。

### `uint32_t vmp::base::hash::elfGnuHash(const char* name)`
- 作用：计算 ELF GNU hash。
- 入参：`name` 符号名。
- 出参：返回 hash 值。
- 导出级别：核心导出。

### `uint32_t vmp::base::hash::chooseBucketCount(uint32_t nchain)`
- 作用：根据符号数估算 hash bucket 数。
- 入参：`nchain` 符号数量。
- 出参：返回 bucket 数。
- 导出级别：可内部化。

## L1 ELF 能力层（elfkit）

### `vmp::elfkit::ElfImage::ElfImage(const char* elf_path)`
- 作用：加载并持有 ELF 镜像。
- 入参：`elf_path` ELF 文件路径。
- 出参：构造对象实例。
- 导出级别：核心导出。

### `bool vmp::elfkit::ElfImage::loaded() const`
- 作用：判断 ELF 是否加载成功。
- 入参：无。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `vmp::elfkit::FunctionView vmp::elfkit::ElfImage::findFunction(const std::string& symbol_name)`
- 作用：按符号名查找函数。
- 入参：`symbol_name` 函数符号名。
- 出参：返回 `FunctionView`。
- 导出级别：核心导出。

### `std::vector<vmp::elfkit::FunctionView> vmp::elfkit::ElfImage::listFunctions()`
- 作用：枚举函数列表。
- 入参：无。
- 出参：返回函数视图数组。
- 导出级别：核心导出。

### `bool vmp::elfkit::FunctionView::valid() const`
- 作用：判断函数视图是否有效。
- 入参：无。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `const std::string& vmp::elfkit::FunctionView::name() const`
- 作用：获取函数名。
- 入参：无。
- 出参：返回函数名引用。
- 导出级别：核心导出。

### `uint64_t vmp::elfkit::FunctionView::offset() const`
- 作用：获取函数地址（偏移）。
- 入参：无。
- 出参：返回地址值。
- 导出级别：核心导出。

### `size_t vmp::elfkit::FunctionView::size() const`
- 作用：获取函数机器码长度。
- 入参：无。
- 出参：返回字节长度。
- 导出级别：核心导出。

### `const uint8_t* vmp::elfkit::FunctionView::data() const`
- 作用：获取函数原始字节指针。
- 入参：无。
- 出参：返回只读指针。
- 导出级别：核心导出。

### `bool vmp::elfkit::FunctionView::prepareTranslation(std::string* error) const`
- 作用：预翻译函数为 VM 中间表示。
- 入参：`error` 可选错误输出。
- 出参：返回 `true/false`，失败时可写 `error`。
- 导出级别：核心导出。

### `bool vmp::elfkit::FunctionView::dump(const char* file_path, DumpMode mode) const`
- 作用：导出函数（文本 / 未编码二进制 / 编码二进制）。
- 入参：`file_path` 输出路径；`mode` 导出模式。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `const std::vector<uint64_t>& vmp::elfkit::FunctionView::sharedBranchAddrs() const`
- 作用：读取共享分支地址表。
- 入参：无。
- 出参：返回地址数组引用。
- 导出级别：核心导出。

### `bool vmp::elfkit::FunctionView::remapBlToSharedBranchAddrs(const std::vector<uint64_t>& shared_branch_addrs) const`
- 作用：将 `BL` 目标重映射到共享地址表。
- 入参：`shared_branch_addrs` 共享地址数组。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `vmp::elfkit::PatchElfImage::PatchElfImage(const char* elf_path)`
- 作用：加载 patch 侧 ELF 镜像。
- 入参：`elf_path` ELF 路径。
- 出参：构造对象实例。
- 导出级别：核心导出。

### `bool vmp::elfkit::PatchElfImage::loaded() const`
- 作用：判断 patch 镜像是否可用。
- 入参：无。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::elfkit::PatchElfImage::validate(std::string* error) const`
- 作用：校验 ELF 结构有效性。
- 入参：`error` 可选错误输出。
- 出参：返回 `true/false`，失败时可写 `error`。
- 导出级别：核心导出。

### `bool vmp::elfkit::PatchElfImage::resolveSymbol(const char* symbol_name, PatchSymbolInfo* out_info) const`
- 作用：解析符号地址与属性。
- 入参：`symbol_name`；`out_info` 输出结构。
- 出参：返回 `true/false`，成功时写 `out_info`。
- 导出级别：核心导出。

### `bool vmp::elfkit::PatchElfImage::collectDefinedDynamicExports(std::vector<std::string>* out_exports, std::string* error) const`
- 作用：收集动态导出符号名。
- 入参：`out_exports` 输出列表；`error` 可选错误输出。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::elfkit::PatchElfImage::collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* out_exports, std::string* error) const`
- 作用：收集动态导出符号名和地址。
- 入参：`out_exports` 输出列表；`error` 可选错误输出。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool vmp::elfkit::PatchElfImage::queryRequiredSections(PatchRequiredSections* out, std::string* error) const`
- 作用：查询 patch 流程所需节和索引信息。
- 入参：`out` 输出结构；`error` 可选错误输出。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

## L2 patchbay 领域层

### `bool vmprotectIsPatchbayCommand(const char* cmd)`
- 作用：判断子命令是否由 patchbay 处理。
- 入参：`cmd` 子命令。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `int vmprotectPatchbayEntry(int argc, char* argv[])`
- 作用：patchbay CLI 入口。
- 入参：`argc`、`argv`。
- 出参：返回状态码（`0` 成功，非 `0` 失败）。
- 导出级别：核心导出。

### `bool exportAliasSymbolsPatchbay(const char* input_path, const char* output_path, const std::vector<AliasPair>& alias_pairs, bool allow_validate_fail, std::string* error)`
- 作用：执行 alias 导出 patch。
- 入参：输入 so、输出 so、alias 列表、校验容错开关、错误输出。
- 出参：返回 `true/false`，失败时可写 `error`。
- 导出级别：核心导出。

### `bool buildPatchbayAliasTables(const vmp::elfkit::PatchElfImage& elf, const vmp::elfkit::PatchRequiredSections& required, const std::vector<AliasPair>& alias_pairs, AliasTableBuildResult* out, std::string* error)`
- 作用：构建新的 dynsym/dynstr/hash 载荷。
- 入参：`elf`、`required`、`alias_pairs`、`out`、`error`。
- 出参：返回 `true/false`，成功时写 `out`。
- 导出级别：可内部化。

### `bool applyPatchbayAliasPayload(const vmp::elfkit::PatchRequiredSections& required, const char* input_path, const char* output_path, const std::vector<uint8_t>& new_dynsym_bytes, const std::vector<uint8_t>& new_dynstr, const std::vector<uint8_t>& new_versym, const std::vector<uint8_t>& new_gnu_hash, const std::vector<uint8_t>& new_sysv_hash, uint32_t slot_used_hint, bool allow_validate_fail, bool* handled, std::string* error)`
- 作用：将新表写回 ELF，并同步 dynamic / section / CRC。
- 入参：所需节信息、输入输出路径、多个新表字节、槽位提示、容错开关、处理标志、错误输出。
- 出参：返回 `true/false`，并写 `handled` / `error`。
- 导出级别：可内部化。

### `bool validateVmengineExportNamingRules(const std::vector<std::string>& input_exports, std::string* error)`
- 作用：校验导出命名规则。
- 入参：`input_exports`、`error`。
- 出参：返回 `true/false`。
- 导出级别：可内部化。

## L3 流程编排层（pipeline）

### `bool parseCommandLine(int argc, char* argv[], CliOverrides& cli, std::string& error)`
- 作用：解析 CLI 参数并填充覆盖配置。
- 入参：`argc`、`argv`、`cli`、`error`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `void printUsage()`
- 作用：打印命令帮助。
- 入参：无。
- 出参：无。
- 导出级别：核心导出。

### `bool collectFunctions(elfkit::ElfImage& elf, const std::vector<std::string>& function_names, std::vector<elfkit::FunctionView>& functions)`
- 作用：从 ELF 中收集目标函数视图。
- 入参：`elf`、目标函数名列表、输出函数列表。
- 出参：返回 `true/false`，成功时写 `functions`。
- 导出级别：核心导出。

### `bool exportProtectedPackage(const VmProtectConfig& config, const std::vector<std::string>& function_names, const std::vector<elfkit::FunctionView>& functions)`
- 作用：导出保护产物（expand so、branch 列表、函数导出文件等）。
- 入参：`config`、函数名列表、函数视图列表。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool embedExpandedSoIntoHost(const std::string& host_so, const std::string& payload_so, const std::string& final_so)`
- 作用：把 expand so 嵌入宿主 so。
- 入参：`host_so`、`payload_so`、`final_so`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool runPatchbayExportFromDonor(const std::string& input_so, const std::string& output_so, const std::string& donor_so, const std::string& impl_symbol, bool patch_all_exports, bool allow_validate_fail)`
- 作用：以 donor 导出为基准修补目标 so。
- 入参：输入输出 so、donor so、实现符号、全量导出开关、校验容错开关。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool buildCoverageBoard(const std::vector<std::string>& function_names, const std::vector<elfkit::FunctionView>& functions, CoverageBoard& board)`
- 作用：构建覆盖率统计板。
- 入参：函数名列表、函数视图列表、输出板对象。
- 出参：返回 `true/false`，成功时写 `board`。
- 导出级别：核心导出。

### `bool writeCoverageReport(const std::string& report_path, const CoverageBoard& board)`
- 作用：写覆盖率报告文件。
- 入参：`report_path`、`board`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `std::string joinOutputPath(const VmProtectConfig& config, const std::string& file_name)`
- 作用：组合输出路径。
- 入参：`config`、`file_name`。
- 出参：返回组合后的路径字符串。
- 导出级别：可内部化。

### `void deduplicateKeepOrder(std::vector<std::string>& values)`
- 作用：去重并保持原顺序。
- 入参：`values`。
- 出参：无（原地修改）。
- 导出级别：可内部化。

## L4 Runtime（VmEngine）

### `bool runVmInitCore(JNIEnv* env)`
- 作用：route4 启动初始化（payload 预热 + takeover 初始化）。
- 入参：`env`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool zFileBytes::readFileBytes(const std::string& path, std::vector<uint8_t>& out)`
- 作用：读取文件字节。
- 入参：`path`、`out`。
- 出参：返回 `true/false`，成功时写 `out`。
- 导出级别：核心导出。

### `bool zFileBytes::writeFileBytes(const std::string& path, const std::vector<uint8_t>& data)`
- 作用：写入文件字节。
- 入参：`path`、`data`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `bool zEmbeddedPayload::readEmbeddedPayloadFromHostSo(const std::string& host_so_path, std::vector<uint8_t>& out_payload, zEmbeddedPayloadReadStatus* out_status)`
- 作用：从宿主 so 读取内嵌 payload。
- 入参：`host_so_path`、`out_payload`、`out_status`。
- 出参：返回 `true/false`，并写 `out_payload` / `out_status`。
- 导出级别：核心导出。

### `bool zSoBinBundleReader::readFromExpandedSo(const std::string& so_path, std::vector<zSoBinEntry>& out_entries, std::vector<uint64_t>& out_shared_branch_addrs)`
- 作用：读取 expand so 尾部 bundle。
- 入参：`so_path`、`out_entries`、`out_shared_branch_addrs`。
- 出参：返回 `true/false`，成功时写两个输出容器。
- 导出级别：核心导出。

### `bool zSymbolTakeoverInit(const char* primary_so_name, const zTakeoverSymbolEntry* entries, size_t entry_count)`
- 作用：初始化符号接管映射。
- 入参：`primary_so_name`、`entries`、`entry_count`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `void zSymbolTakeoverClear()`
- 作用：清理接管状态。
- 入参：无。
- 出参：无。
- 导出级别：核心导出。

### `extern "C" int vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id)`
- 作用：汇编桩统一分发入口。
- 入参：`a`、`b`、`symbol_id`。
- 出参：返回业务结果值。
- 导出级别：核心导出。

### `static zVmEngine& zVmEngine::getInstance()`
- 作用：获取 VM 引擎单例。
- 入参：无。
- 出参：返回引擎引用。
- 导出级别：核心导出。

### `uint64_t zVmEngine::execute(void* retBuffer, const char* soName, uint64_t funAddr, const zParams& params)`
- 作用：按 `so + funAddr` 执行函数。
- 入参：`retBuffer`、`soName`、`funAddr`、`params`。
- 出参：返回执行结果。
- 导出级别：核心导出。

### `bool zVmEngine::LoadLibrary(const char* path)`
- 作用：加载目标 so。
- 入参：`path`。
- 出参：返回 `true/false`。
- 导出级别：核心导出。

### `soinfo* zVmEngine::GetSoinfo(const char* name)`
- 作用：查询已加载 so 的 `soinfo`。
- 入参：`name`。
- 出参：返回 `soinfo*`。
- 导出级别：可内部化。

### `bool zVmEngine::cacheFunction(std::unique_ptr<zFunction> function)`
- 作用：向引擎缓存注册函数对象。
- 入参：`function`。
- 出参：返回 `true/false`。
- 导出级别：可内部化。

### `void zVmEngine::setSharedBranchAddrs(const char* soName, std::vector<uint64_t> branchAddrs)`
- 作用：设置模块级共享分支地址表。
- 入参：`soName`、`branchAddrs`。
- 出参：无。
- 导出级别：可内部化。

### `void zVmEngine::clearSharedBranchAddrs(const char* soName)`
- 作用：清理模块级共享分支地址表。
- 入参：`soName`。
- 出参：无。
- 导出级别：可内部化。

### `void zVmEngine::clearCache()`
- 作用：清理函数缓存。
- 入参：无。
- 出参：无。
- 导出级别：可内部化。

---

附注：
- 全量可见声明仍保留在 `docs/api_export_inventory.md`（供补查）。
- 建议优先改本文件；后续重构将以本文件作为契约。

