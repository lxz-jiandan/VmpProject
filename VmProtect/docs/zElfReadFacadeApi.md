# zElfReadFacade API 说明

## 1. 目标

`zElfReadFacade` 是 patchbay 域的只读 ELF 访问入口。  
设计目标是给 app/domain 提供稳定、窄、可迁移的查询接口，避免业务层直接依赖底层 `PatchElfImage` 与 section 模型细节。

文件位置：`VmProtect/modules/elfkit/api/zElfReadFacade.h`

## 2. 对象生命周期

### 2.1 构造

#### `zElfReadFacade(const char* elfPath)`

作用：按路径加载 ELF 并建立只读查询上下文。  
入参：
- `elfPath`：ELF 文件路径（`const char*`，不能为空字符串）。
出参：无。  
返回：构造函数本身无返回值，调用方通过 `loaded()` 判断是否加载成功。

## 3. 核心查询接口

### 3.1 `bool loaded() const`

作用：判断 ELF 是否加载成功。  
入参：无。  
出参：无。  
返回：
- `true`：加载成功。
- `false`：加载失败或对象不可用。

### 3.2 `bool validate(std::string* error = nullptr) const`

作用：执行 ELF 结构校验。  
入参：
- `error`：可选错误输出字符串指针。
出参：
- `error`：失败时写入错误描述。
返回：
- `true`：校验通过。
- `false`：校验失败。

### 3.3 `bool resolveSymbol(const char* symbolName, PatchSymbolInfo* outInfo) const`

作用：解析指定符号信息（地址、大小、类型、节索引）。  
入参：
- `symbolName`：目标符号名。
- `outInfo`：输出对象指针。
出参：
- `outInfo->value`：符号地址。
- `outInfo->size`：符号大小。
- `outInfo->shndx`：节索引。
- `outInfo->type`：符号类型。
- `outInfo->found`：是否找到。
返回：
- `true`：找到并成功填充。
- `false`：未找到或输入非法。

### 3.4 `bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* outExports, std::string* error) const`

作用：收集已定义动态导出（导出名 + value）。  
入参：
- `outExports`：输出数组指针。
- `error`：可选错误输出字符串指针。
出参：
- `outExports`：导出列表，每项包含 `name`、`value`。
- `error`：失败时写入错误描述。
返回：
- `true`：收集成功。
- `false`：收集失败。

### 3.5 `bool queryRequiredSections(PatchRequiredSections* out, std::string* error) const`

作用：提取 patchbay 所需关键节快照（不暴露底层 section 类对象）。  
入参：
- `out`：输出快照结构指针。
- `error`：可选错误输出字符串指针。
出参：
- `out->dynsym`：`.dynsym` 索引和符号表快照。
- `out->dynstr`：`.dynstr` 索引和字节快照。
- `out->versym` + `out->versymBytes`：`.gnu.version` 视图与字节快照。
- `out->gnuHash`：`.gnu.hash` 视图。
- `out->hash` + `out->hasHash`：`.hash` 视图与存在标记。
- `out->dynamic`：`.dynamic` 索引、offset、entries 快照。
- `out->patchbay` + `out->hasPatchbay`：`.vmp_patchbay` 视图与存在标记。
- `error`：失败时写入错误描述。
返回：
- `true`：关键节快照提取成功。
- `false`：关键节缺失或类型不匹配。

## 4. PatchRequiredSections 字段语义

### 4.1 `PatchSectionView`

作用：节最小稳定视图。  
字段：
- `index`：节索引（不存在时为 `-1`）。
- `offset`：文件偏移。
- `size`：节大小。
- `addr`：虚拟地址。

### 4.2 `PatchDynsymView`

作用：`.dynsym` 快照。  
字段：
- `index`：`.dynsym` 节索引。
- `symbols`：完整符号条目数组。

### 4.3 `PatchDynstrView`

作用：`.dynstr` 快照。  
字段：
- `index`：`.dynstr` 节索引。
- `bytes`：原始字节数组。

### 4.4 `PatchDynamicView`

作用：`.dynamic` 快照。  
字段：
- `index`：`.dynamic` 节索引。
- `offset`：`.dynamic` 文件偏移。
- `entries`：`Elf64_Dyn` 条目数组。

## 5. 使用建议

1. patchbay app/domain 只使用 `zElfReadFacade`，不要直接依赖 `PatchElfImage`。  
2. 对 `.hash` 和 `.vmp_patchbay` 一律先判断 `hasHash` / `hasPatchbay`。  
3. 对符号解析失败使用 `PatchSymbolInfo::found` 和返回值双重判断，避免空指针分支泄漏。  
