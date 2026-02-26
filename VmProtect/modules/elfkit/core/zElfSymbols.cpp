/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - zElf 符号查询与函数列表构建实现。
 * - 加固链路位置：离线函数提取与查找。
 * - 输入：符号名 / ELF 符号表。
 * - 输出：符号偏移、符号信息、zFunction 缓存。
 */
#include "zElf.h"
// 日志输出：用于记录符号匹配过程与失败原因。
#include "zLog.h"
// 字符串比较。
#include <cstring>
// move 语义。
#include <utility>
// 动态字节缓存。
#include <vector>

// 通过动态符号表查找符号偏移（文件视图）。
// 返回值含义：符号虚拟地址相对首个 PT_LOAD 的偏移。
Elf64_Addr zElf::getSymbolOffsetByDynamic(const char *symbolName) {
    // 打印动态表关键状态，便于定位“为何找不到符号”。
    LOGD("find_symbol_by_dynamic dynamic_symbol_table_offset 0x%llx", (unsigned long long)dynamic_symbol_table_offset);
    // 打印动态符号数量。
    LOGD("find_symbol_by_dynamic dynamic_symbol_table_num %llu", (unsigned long long)dynamic_symbol_table_num);
    // 打印动态字符串表偏移。
    LOGD("find_symbol_by_dynamic dynamic_string_table_offset 0x%llx", (unsigned long long)dynamic_string_table_offset);

    // 动态符号表或动态字符串表缺失时，当前路径不可用。
    if (!dynamic_symbol_table || !dynamic_string_table) {
        LOGD("Dynamic symbol table or string table not available");
        return 0;
    }

    // 从动态符号表首元素开始线性扫描。
    Elf64_Sym* dynamic_symbol = dynamic_symbol_table;
    // 按动态符号表数量逐项扫描。
    for (uint64_t symbolIndex = 0; symbolIndex < dynamic_symbol_table_num; symbolIndex++) {
        // 做 st_name 边界保护，避免 dynstr 越界访问。
        if (dynamic_symbol->st_name >= 0 && dynamic_symbol->st_name <= dynamic_string_table_size) {
            // 由 st_name 索引拿到符号名称。
            const char *name = dynamic_string_table + dynamic_symbol->st_name;
            // 匹配目标符号名。
            if (strcmp(name, symbolName) == 0) {
                // 输出命中的符号信息。
                LOGD("find_dynamic_symbol [%llu] %s offset: 0x%llx value: 0x%llx",
                     (unsigned long long)symbolIndex, name,
                     (unsigned long long)dynamic_symbol->st_name,
                     (unsigned long long)dynamic_symbol->st_value);
                // 在文件视图下，返回“符号 VA - 首个 LOAD 段 VA”。
                return dynamic_symbol->st_value - load_segment_virtual_offset;
            }
        }

        // 前进到下一条动态符号。
        dynamic_symbol++;
    }
    // 未命中返回 0。
    return 0;
}

// 通过节符号表查找符号偏移（动态表失败后的回退路径）。
Elf64_Addr zElf::getSymbolOffsetBySection(const char *symbolName) {
    // 节符号表或字符串表缺失则无法继续。
    if (!symbol_table || !string_table) {
        LOGD("Symbol table or string table not available");
        return 0;
    }

    // 从节符号表首元素开始扫描。
    Elf64_Sym *symbol = symbol_table;
    // 遍历全部节符号项。
    for (uint64_t sectionSymbolIndex = 0; sectionSymbolIndex < section_symbol_num; sectionSymbolIndex++) {
        // 由 st_name 拿到符号名。
        const char *name = string_table + symbol->st_name;
        // 命中同名符号。
        if (strcmp(name, symbolName) == 0) {
            // 打印命中信息。
            LOGD("getSymbolOffsetBySection [%llu] %s value: 0x%llx",
                 (unsigned long long)sectionSymbolIndex, name,
                 (unsigned long long)symbol->st_value);
            // 文件视图下返回“符号值 - 物理地址基准”。
            return symbol->st_value - physical_address;
        }
        // 前进到下一条节符号。
        symbol++;
    }

    // 未命中返回 0。
    return 0;
}

// 统一符号偏移查找：优先 dynamic，失败再回退 section。
Elf64_Addr zElf::getSymbolOffset(const char *symbolName) {
    // 初始化偏移结果。
    Elf64_Addr symbolOffset = 0;
    // 先走动态符号路径。
    symbolOffset = getSymbolOffsetByDynamic(symbolName);
    // 动态表失败时再走节符号路径。
    if (symbolOffset == 0) {
        symbolOffset = getSymbolOffsetBySection(symbolName);
    }
    // 返回最终偏移。
    return symbolOffset;
}

// 获取符号在当前 FILE_VIEW 缓冲中的地址。
char* zElf::getSymbolFileAddress(const char *symbolName) {
    // 未加载 ELF 文件时无法计算地址。
    if (elf_file_ptr == nullptr) {
        LOGE("getSymbolFileAddress elf_file_ptr == nullptr");
        return nullptr;
    }

    // 查找符号偏移。
    Elf64_Addr symbolOffset = getSymbolOffset(symbolName);

    // 偏移为 0 视为查找失败。
    if (symbolOffset == 0) {
        LOGE("getSymbolFileAddress %s failed", symbolName);
        return nullptr;
    }
    // 返回文件缓冲中的实际字节地址。
    return elf_file_ptr + symbolOffset;
}

// 查找完整符号表项（含 st_size），用于构建 zFunctionData。
Elf64_Sym* zElf::getSymbolInfo(const char *symbolName) {
    // 先查动态符号表（导出符号优先）。
    if (dynamic_symbol_table && dynamic_string_table) {
        // 指向动态符号表首项。
        Elf64_Sym* dynamic_symbol = dynamic_symbol_table;
        // 逐项扫描动态符号。
        for (uint64_t symbolIndex = 0; symbolIndex < dynamic_symbol_table_num; symbolIndex++) {
            // 先做 st_name 边界保护。
            if (dynamic_symbol->st_name >= 0 && dynamic_symbol->st_name <= dynamic_string_table_size) {
                // 取出当前符号名。
                const char *name = dynamic_string_table + dynamic_symbol->st_name;
                // 名称命中即返回完整符号项。
                if (strcmp(name, symbolName) == 0) {
                    LOGD("getSymbolInfo: found in dynamic table [%llu] %s size: 0x%llx",
                         (unsigned long long)symbolIndex, name, (unsigned long long)dynamic_symbol->st_size);
                    return dynamic_symbol;
                }
            }
            // 前进到下一条动态符号。
            dynamic_symbol++;
        }
    }

    // 动态表未命中时，再查节符号表。
    if (symbol_table && string_table) {
        // 指向节符号表首项。
        Elf64_Sym *symbol = symbol_table;
        // 遍历全部节符号项。
        for (uint64_t sectionSymbolIndex = 0; sectionSymbolIndex < section_symbol_num; sectionSymbolIndex++) {
            // 取当前节符号名。
            const char *name = string_table + symbol->st_name;
            // 名称命中则返回完整符号项。
            if (strcmp(name, symbolName) == 0) {
                LOGD("getSymbolInfo: found in section table [%llu] %s size: 0x%llx",
                     (unsigned long long)sectionSymbolIndex, name, (unsigned long long)symbol->st_size);
                return symbol;
            }
            // 前进到下一条节符号。
            symbol++;
        }
    }

    // 两张表都未命中。
    return nullptr;
}

// 从符号信息构建一个 zFunction，并加入 function_list_。
bool zElf::addFunctionFromSymbol(const char* symbolName, Elf64_Xword symbolSize) {
    // 空名称直接过滤，避免污染缓存。
    if (!symbolName || symbolName[0] == '\0') {
        return false;
    }

    // 已存在同名函数则跳过，防止重复插入。
    if (getCachedFunction(symbolName) != nullptr) {
        return false;
    }

    // 先解析符号偏移。
    Elf64_Addr symbolOffset = getSymbolOffset(symbolName);
    // 偏移无效时失败。
    if (symbolOffset == 0) {
        return false;
    }

    // 再取到符号在文件中的字节地址。
    char* symbolFileAddress = getSymbolFileAddress(symbolName);
    // 地址无效时失败。
    if (!symbolFileAddress) {
        return false;
    }

    // 以符号 size 为准；若 size 为 0，回退固定窗口便于回归诊断。
    size_t symbolBytesSize = symbolSize > 0 ? static_cast<size_t>(symbolSize) : 256;
    // 分配函数字节缓存。
    std::vector<uint8_t> symbolBytes(symbolBytesSize);
    // 从 ELF 文件缓冲复制函数机器码。
    memcpy(symbolBytes.data(), symbolFileAddress, symbolBytesSize);

    // 组装 zFunctionData。
    zFunctionData data;
    // 写入函数名。
    data.function_name = symbolName;
    // 写入函数偏移。
    data.function_offset = symbolOffset;
    // 写入函数字节（move 转移所有权）。
    data.function_bytes = std::move(symbolBytes);
    // 构造并压入 zFunction。
    function_list_.emplace_back(data);
    return true;
}

// 在线性缓存中查找函数对象。
zFunction* zElf::getCachedFunction(const char* functionName) {
    // 空名直接失败。
    if (!functionName || functionName[0] == '\0') {
        return nullptr;
    }

    // 遍历函数缓存。
    for (auto& function : function_list_) {
        // 命中同名函数。
        if (function.getName() == functionName) {
            return &function;
        }
    }
    // 未命中返回空。
    return nullptr;
}

// 从 ELF 符号表重建函数列表。
bool zElf::buildFunctionList() {
    // 每次重建先清空旧缓存，避免残留状态。
    function_list_.clear();

    // ELF 文件未加载时无法构建。
    if (!elf_file_ptr) {
        return false;
    }

    // 先扫动态符号表（优先导出符号）。
    if (dynamic_symbol_table && dynamic_string_table) {
        // 遍历动态符号项。
        for (uint64_t symbolIndex = 0; symbolIndex < dynamic_symbol_table_num; symbolIndex++) {
            // 读取当前符号项。
            Elf64_Sym* symbol = &dynamic_symbol_table[symbolIndex];
            // 只保留函数符号。
            if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC) {
                continue;
            }
            // 过滤非法 st_name 索引。
            if (symbol->st_name >= dynamic_string_table_size) {
                continue;
            }
            // 取符号名。
            const char* symbolName = dynamic_string_table + symbol->st_name;
            // 尝试加入函数缓存（内部自带去重）。
            addFunctionFromSymbol(symbolName, symbol->st_size);
        }
    }

    // 再扫节符号表（补充非导出函数）。
    if (symbol_table && string_table) {
        // 遍历节符号项。
        for (uint64_t sectionSymbolIndex = 0; sectionSymbolIndex < section_symbol_num; sectionSymbolIndex++) {
            // 读取当前节符号。
            Elf64_Sym* symbol = &symbol_table[sectionSymbolIndex];
            // 只保留函数符号。
            if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC) {
                continue;
            }
            // 取节符号名。
            const char* symbolName = string_table + symbol->st_name;
            // 尝试加入函数缓存（内部自带去重）。
            addFunctionFromSymbol(symbolName, symbol->st_size);
        }
    }

    // 打印构建结果。
    LOGI("buildFunctionList complete, function_count=%zu", function_list_.size());
    // 兼容历史语义：空列表返回 false。
    return !function_list_.empty();
}

// 获取指定函数对象；若缓存未命中则尝试现场补建。
zFunction* zElf::getFunction(const char* functionName) {
    // 空名直接失败。
    if (!functionName || functionName[0] == '\0') {
        return nullptr;
    }

    // 先查缓存，避免重复查表和拷贝。
    zFunction* function = getCachedFunction(functionName);
    // 命中缓存直接返回。
    if (function) {
        return function;
    }

    // 缓存未命中时先找符号信息。
    Elf64_Sym* symbol = getSymbolInfo(functionName);
    // 符号不存在则失败。
    if (!symbol) {
        return nullptr;
    }

    // 尝试补建函数对象。
    if (!addFunctionFromSymbol(functionName, symbol->st_size)) {
        return nullptr;
    }
    // 补建后再次按名称返回缓存对象。
    return getCachedFunction(functionName);
}

// 返回函数列表只读引用。
const std::vector<zFunction>& zElf::getFunctionList() const {
    return function_list_;
}

