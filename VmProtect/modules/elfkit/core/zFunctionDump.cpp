/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - zFunction dump 导出实现（文本/未编码二进制/编码二进制）。
 * - 加固链路位置：离线导出与调试回归。
 * - 输入：zFunction 的未编码缓存。
 * - 输出：可读文本或二进制导出文件。
 */
#include "zFunction.h"

// 引入字节编解码工具。
#include "zCodec.h"
// 引入文件读写工具。
#include "zFile.h"
// 引入日志接口。
#include "zLog.h"

// 引入 PRI* 宏。
#include <cinttypes>
// 引入 snprintf。
#include <cstdio>
// 引入 strlen。
#include <cstring>
// 引入文件流。
#include <fstream>
// 引入 unique_ptr。
#include <memory>
// 引入动态数组容器。
#include <vector>

// 匿名命名空间：仅当前编译单元可见。
namespace {

// 未编码中间表示结构。
struct zUnencodedBytecode {
    // 虚拟寄存器数量。
    uint32_t registerCount = 0;
    // 寄存器 ID 列表。
    std::vector<uint32_t> regList;
    // 类型数量。
    uint32_t typeCount = 0;
    // 类型标签列表。
    std::vector<uint32_t> typeTags;
    // 初始化值数量。
    uint32_t initValueCount = 0;
    // 指令映射：地址 -> opcode words。
    std::map<uint64_t, std::vector<uint32_t>> instByAddress;
    // 汇编文本映射：地址 -> "mnemonic op"。
    std::map<uint64_t, std::string> asmByAddress;
    // 扁平指令总 word 数。
    uint32_t instCount = 0;
    // 本地分支数量。
    uint32_t branchCount = 0;
    // 本地分支表（branch_id -> pc）。
    std::vector<uint32_t> branchWords;
    // 外部调用地址表（branch_addr_list）。
    std::vector<uint64_t> branchAddrWords;
};

// 未编码二进制文件头。
struct zUnencodedBinHeader {
    // 魔数。
    uint32_t magic = 0;
    // 版本。
    uint32_t version = 0;
    // register_count。
    uint32_t registerCount = 0;
    // regList 条目数。
    uint32_t regCount = 0;
    // type_count。
    uint32_t typeCount = 0;
    // init_value_count。
    uint32_t initValueCount = 0;
    // 指令行数量（instByAddress 项数）。
    uint32_t instLineCount = 0;
    // inst_count。
    uint32_t instCount = 0;
    // branch_count。
    uint32_t branchCount = 0;
    // branch_addr 数量。
    uint32_t branchAddrCount = 0;
};

// 未编码 bin 魔数：'ZUBF'（仅项目内部约定）。
static constexpr uint32_t Z_UNENCODED_BIN_MAGIC = 0x4642555A;
// 未编码 bin 版本号。
static constexpr uint32_t Z_UNENCODED_BIN_VERSION = 2;

// opcode 数字到可读名称映射。
static const char* getOpcodeName(uint32_t op) {
    switch (op) {
        case 0: return "OP_END";
        case 1: return "OP_BINARY";
        case 2: return "OP_TYPE_CONVERT";
        case 3: return "OP_LOAD_CONST";
        case 4: return "OP_STORE_CONST";
        case 5: return "OP_GET_ELEMENT";
        case 6: return "OP_ALLOC_RETURN";
        case 7: return "OP_STORE";
        case 8: return "OP_LOAD_CONST64";
        case 9: return "OP_NOP";
        case 10: return "OP_COPY";
        case 11: return "OP_GET_FIELD";
        case 12: return "OP_CMP";
        case 13: return "OP_SET_FIELD";
        case 14: return "OP_RESTORE_REG";
        case 15: return "OP_CALL";
        case 16: return "OP_RETURN";
        case 17: return "OP_BRANCH";
        case 18: return "OP_BRANCH_IF";
        case 19: return "OP_ALLOC_MEMORY";
        case 20: return "OP_MOV";
        case 21: return "OP_LOAD_IMM";
        case 22: return "OP_DYNAMIC_CAST";
        case 23: return "OP_UNARY";
        case 24: return "OP_PHI";
        case 25: return "OP_SELECT";
        case 26: return "OP_MEMCPY";
        case 27: return "OP_MEMSET";
        case 28: return "OP_STRLEN";
        case 29: return "OP_FETCH_NEXT";
        case 30: return "OP_CALL_INDIRECT";
        case 31: return "OP_SWITCH";
        case 32: return "OP_GET_PTR";
        case 33: return "OP_BITCAST";
        case 34: return "OP_SIGN_EXTEND";
        case 35: return "OP_ZERO_EXTEND";
        case 36: return "OP_TRUNCATE";
        case 37: return "OP_FLOAT_EXTEND";
        case 38: return "OP_FLOAT_TRUNCATE";
        case 39: return "OP_INT_TO_FLOAT";
        case 40: return "OP_ARRAY_ELEM";
        case 41: return "OP_FLOAT_TO_INT";
        case 42: return "OP_READ";
        case 43: return "OP_WRITE";
        case 44: return "OP_LEA";
        case 45: return "OP_ATOMIC_ADD";
        case 46: return "OP_ATOMIC_SUB";
        case 47: return "OP_ATOMIC_XCHG";
        case 48: return "OP_ATOMIC_CAS";
        case 49: return "OP_FENCE";
        case 50: return "OP_UNREACHABLE";
        case 51: return "OP_ALLOC_VSP";
        case 52: return "OP_BINARY_IMM";
        case 53: return "OP_BRANCH_IF_CC";
        case 54: return "OP_SET_RETURN_PC";
        case 55: return "OP_BL";
        case 56: return "OP_ADRP";
        default: return "OP_UNKNOWN";
    }
}

// 安全字符串格式化工具。
template<typename ... Args>
static std::string strFormat(const std::string& format, Args ... args) {
    // 第一次 snprintf 获取目标长度。
    int size_buf = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    // 长度异常直接返回空串。
    if (size_buf <= 0) return std::string();
    // 分配缓冲区。
    std::unique_ptr<char[]> buf(new(std::nothrow) char[size_buf]);
    // 分配失败返回空串。
    if (!buf) return std::string();
    // 第二次 snprintf 写入实际内容。
    std::snprintf(buf.get(), static_cast<size_t>(size_buf), format.c_str(), args...);
    // 构造结果字符串（去掉末尾 '\0'）。
    return std::string(buf.get(), buf.get() + size_buf - 1);
}

// 把 opcode 数组格式化成单行文本。
static std::string formatOpcodeList(const std::vector<uint32_t>& opcodeList, bool trailingComma = true) {
    // 输出前缀缩进。
    std::string result = "        ";
    // 顺序输出每个 word。
    for (size_t wordIndex = 0; wordIndex < opcodeList.size(); ++wordIndex) {
        // 第二个元素开始补空格。
        if (wordIndex > 0) result += " ";
        // 写数字。
        result += std::to_string(opcodeList[wordIndex]);
        // 非最后一个补逗号。
        if (wordIndex + 1 < opcodeList.size()) result += ",";
    }
    // 兼容历史格式：行尾可选补逗号。
    if (trailingComma && !opcodeList.empty()) result += ",";
    return result;
}

// 构造行尾注释（opcode 名 + 可选 asm 文本）。
static std::string formatComment(const char* opName, const char* asmText, size_t opNameWidth = 20) {
    // 注释前缀。
    std::string result = "// ";
    // 写 opcode 名称。
    result += opName;

    // 有 asm 文本时再拼接“对齐后的 asm”。
    if (asmText && asmText[0] != '\0') {
        // 当前 opcode 名长度。
        size_t opNameLen = std::strlen(opName);
        // 补齐到固定宽度，便于垂直对齐阅读。
        if (opNameLen < opNameWidth) {
            result.append(opNameWidth - opNameLen, ' ');
        }
        // 追加 asm 文本。
        result += asmText;
    }
    return result;
}

// 格式化一条 inst 行（左侧数字 + 右侧注释）。
static std::string formatInstructionLine(
    const std::vector<uint32_t>& opcodeList,
    const char* opName,
    const char* asmText,
    size_t commentColumn = 50,
    size_t opNameWidth = 20
) {
    // 先生成左侧 opcode 字段。
    std::string line = formatOpcodeList(opcodeList, true);
    // 当前行长。
    size_t currentLen = line.length();
    // 补齐到注释列起始。
    if (currentLen < commentColumn) {
        line.append(commentColumn - currentLen, ' ');
    } else {
        // 已超过注释列时至少补两个空格。
        line += "  ";
    }
    // 拼接注释部分。
    line += formatComment(opName, asmText, opNameWidth);
    return line;
}

// 按地址顺序把 map 中的 opcode 行扁平化。
static std::vector<uint32_t> flattenInstByAddress(const std::map<uint64_t, std::vector<uint32_t>>& instByAddress) {
    // 扁平结果。
    std::vector<uint32_t> flat;
    // 顺序遍历地址 map。
    for (const auto& instEntry : instByAddress) {
        // 依次追加该地址对应的全部 words。
        for (uint32_t word : instEntry.second) {
            flat.push_back(word);
        }
    }
    return flat;
}

// 选择一个函数地址用于文本导出 fun_addr 字段。
static uint64_t inferFunctionAddress(const zUnencodedBytecode& unencoded) {
    // 优先返回“同时存在 asm 文本”的第一条指令地址。
    for (const auto& instEntry : unencoded.instByAddress) {
        const auto asmTextIt = unencoded.asmByAddress.find(instEntry.first);
        if (asmTextIt != unencoded.asmByAddress.end() && !asmTextIt->second.empty()) {
            return instEntry.first;
        }
    }
    // 其次回退到 asm map 的首元素地址。
    if (!unencoded.asmByAddress.empty()) {
        return unencoded.asmByAddress.begin()->first;
    }
    // 都没有则返回 0。
    return 0;
}

// 把未编码结构转成 zFunctionData（用于编码导出）。
static bool buildEncodedDataFromUnencoded(const zUnencodedBytecode& unencoded, zFunctionData& out, std::string* error) {
    // 先重置输出对象。
    out = zFunctionData{};
    // marker 固定为 0（当前协议版本约定）。
    out.marker = 0;
    // 写 register_count。
    out.register_count = unencoded.registerCount;
    // 当前导出路径不使用 first_inst。
    out.first_inst_count = 0;
    // 写 type_count。
    out.type_count = unencoded.typeCount;
    // 写 type_tags。
    out.type_tags = unencoded.typeTags;
    // 写 init_value_count。
    out.init_value_count = unencoded.initValueCount;
    // 当前导出器不支持 init_value_count 非 0。
    if (out.init_value_count != 0) {
        if (error) {
            *error = "init_value_count != 0 is not supported by current exporter";
        }
        return false;
    }
    // 扁平化 inst words。
    out.inst_words = flattenInstByAddress(unencoded.instByAddress);
    // 写 inst_count。
    out.inst_count = static_cast<uint32_t>(out.inst_words.size());
    // 写 branch_count。
    out.branch_count = unencoded.branchCount;
    // 写 branch_words。
    out.branch_words = unencoded.branchWords;
    // 写 branch_addrs。
    out.branch_addrs = unencoded.branchAddrWords;
    // 写 function_offset。
    out.function_offset = inferFunctionAddress(unencoded);
    // 最后做结构校验。
    return out.validate(error);
}

// 把未编码结构序列化为二进制 bytes。
static bool serializeUnencodedToBinaryBytes(const zUnencodedBytecode& unencoded,
                                            std::vector<uint8_t>* out) {
    // 输出指针不能为空。
    if (out == nullptr) {
        return false;
    }
    // 清空旧输出。
    out->clear();

    // 填充文件头。
    zUnencodedBinHeader header;
    header.magic = Z_UNENCODED_BIN_MAGIC;
    header.version = Z_UNENCODED_BIN_VERSION;
    header.registerCount = unencoded.registerCount;
    header.regCount = static_cast<uint32_t>(unencoded.regList.size());
    header.typeCount = unencoded.typeCount;
    header.initValueCount = unencoded.initValueCount;
    header.instLineCount = static_cast<uint32_t>(unencoded.instByAddress.size());
    header.instCount = unencoded.instCount;
    header.branchCount = unencoded.branchCount;
    header.branchAddrCount = static_cast<uint32_t>(unencoded.branchAddrWords.size());

    // 预估容量，减少 realloc。
    size_t reserve_size = sizeof(uint32_t) * 10 +
                          unencoded.regList.size() * sizeof(uint32_t) +
                          unencoded.typeTags.size() * sizeof(uint32_t) +
                          unencoded.branchWords.size() * sizeof(uint32_t) +
                          unencoded.branchAddrWords.size() * sizeof(uint64_t);
    // 把每条 inst 行的地址/长度/内容/asm 文本长度一起计入。
    for (const auto& instEntry : unencoded.instByAddress) {
        reserve_size += sizeof(uint64_t);
        reserve_size += sizeof(uint32_t);
        reserve_size += instEntry.second.size() * sizeof(uint32_t);
        const auto asmTextIt = unencoded.asmByAddress.find(instEntry.first);
        const size_t asm_len = (asmTextIt != unencoded.asmByAddress.end())
                               ? asmTextIt->second.size()
                               : 0;
        reserve_size += sizeof(uint32_t) + asm_len;
    }
    // 预分配。
    out->reserve(reserve_size);

    // 逐字段写文件头。
    vmp::base::codec::appendU32Le(out, header.magic);
    vmp::base::codec::appendU32Le(out, header.version);
    vmp::base::codec::appendU32Le(out, header.registerCount);
    vmp::base::codec::appendU32Le(out, header.regCount);
    vmp::base::codec::appendU32Le(out, header.typeCount);
    vmp::base::codec::appendU32Le(out, header.initValueCount);
    vmp::base::codec::appendU32Le(out, header.instLineCount);
    vmp::base::codec::appendU32Le(out, header.instCount);
    vmp::base::codec::appendU32Le(out, header.branchCount);
    vmp::base::codec::appendU32Le(out, header.branchAddrCount);

    // 写 reg/type/branch/branch_addr 基础数组。
    vmp::base::codec::appendU32LeArray(out, unencoded.regList.data(), unencoded.regList.size());
    vmp::base::codec::appendU32LeArray(out, unencoded.typeTags.data(), unencoded.typeTags.size());
    vmp::base::codec::appendU32LeArray(out, unencoded.branchWords.data(), unencoded.branchWords.size());
    vmp::base::codec::appendU64LeArray(out, unencoded.branchAddrWords.data(), unencoded.branchAddrWords.size());

    // 顺序写每条 inst 行。
    for (const auto& instEntry : unencoded.instByAddress) {
        // 写地址。
        vmp::base::codec::appendU64Le(out, instEntry.first);
        // 写本行 word 数。
        vmp::base::codec::appendU32Le(out, static_cast<uint32_t>(instEntry.second.size()));
        // 写本行 words。
        vmp::base::codec::appendU32LeArray(out, instEntry.second.data(), instEntry.second.size());
        // 取可选 asm 文本。
        const auto asmTextIt = unencoded.asmByAddress.find(instEntry.first);
        const std::string asm_text =
                (asmTextIt != unencoded.asmByAddress.end()) ? asmTextIt->second : std::string();
        // 写长度前缀字符串。
        vmp::base::codec::appendStringU32Le(out, asm_text);
    }

    return true;
}

// 把未编码结构写成历史文本格式。
static bool writeUnencodedToStream(std::ostream& out, const zUnencodedBytecode& unencoded) {
    // 写寄存器列表。
    out << "static const uint32_t reg_id_list[] = { ";
    for (size_t regIndex = 0; regIndex < unencoded.regList.size(); ++regIndex) {
        if (regIndex > 0) out << ", ";
        out << unencoded.regList[regIndex];
    }
    out << " };\n";
    out << "static const uint32_t reg_id_count = sizeof(reg_id_list)/sizeof(uint32_t);\n";

    // 写类型列表。
    out << "static const uint32_t type_id_count = " << unencoded.typeCount << ";\n";
    out << "static const uint32_t type_id_list[] = { ";
    for (size_t typeIndex = 0; typeIndex < unencoded.typeTags.size(); ++typeIndex) {
        if (typeIndex > 0) out << ", ";
        out << unencoded.typeTags[typeIndex];
    }
    out << " };\n";

    // 写本地分支表。
    out << "static const uint32_t branch_id_count = " << unencoded.branchCount << ";\n";
    if (unencoded.branchCount > 0) {
        out << "uint32_t branch_id_list[] = { ";
        for (size_t branchWordIndex = 0; branchWordIndex < unencoded.branchWords.size(); ++branchWordIndex) {
            if (branchWordIndex > 0) out << ", ";
            out << unencoded.branchWords[branchWordIndex];
        }
        out << " };\n";
    } else {
        out << "uint32_t branch_id_list[1] = {};\n";
    }

    // 写外部调用地址表。
    out << "static const uint64_t branch_addr_count = " << unencoded.branchAddrWords.size() << ";\n";
    if (!unencoded.branchAddrWords.empty()) {
        out << "uint64_t branch_addr_list[] = { ";
        for (size_t branchAddrIndex = 0;
             branchAddrIndex < unencoded.branchAddrWords.size();
             ++branchAddrIndex) {
            if (branchAddrIndex > 0) out << ", ";
            out << strFormat("0x%" PRIx64, unencoded.branchAddrWords[branchAddrIndex]);
        }
        out << " };\n";
    } else {
        out << "uint64_t branch_addr_list[1] = {};\n";
    }

    // 写 inst_count 与 fun_addr。
    out << "static const uint32_t inst_id_count = " << unencoded.instCount << ";\n";
    out << "static const uint64_t fun_addr = "
        << strFormat("0x%" PRIx64, inferFunctionAddress(unencoded)) << ";\n";
    out << "uint32_t inst_id_list[] = {\n";

    // 配置注释对齐参数。
    const size_t comment_column = 54;
    const size_t op_name_width = 20;
    // 顺序写每条 inst 行。
    for (const auto& instEntry : unencoded.instByAddress) {
        // 本行 opcode 列表。
        const auto& opcode_list = instEntry.second;
        // 解析 opcode 名称。
        const char* op_name = opcode_list.empty() ? "OP_UNKNOWN" : getOpcodeName(opcode_list[0]);

        // 查找同地址 asm 文本。
        const auto asmTextIt = unencoded.asmByAddress.find(instEntry.first);
        const char* asm_str =
                (asmTextIt != unencoded.asmByAddress.end()) ? asmTextIt->second.c_str() : "";
        // 拼接“地址 + asm”用于注释展示。
        std::string asm_with_addr = (asm_str[0] != '\0')
            ? strFormat("0x%" PRIx64 ": %s", instEntry.first, asm_str)
            : std::string();
        // 选择最终显示文本。
        const char* asm_display = (asm_str[0] != '\0') ? asm_with_addr.c_str() : asm_str;

        // 格式化单行输出。
        std::string line = formatInstructionLine(opcode_list, op_name, asm_display, comment_column, op_name_width);
        out << line << "\n";
    }

    // 结束 inst 数组。
    out << "};\n";
    return static_cast<bool>(out);
}

// 结束匿名命名空间。
} // namespace

// 导出入口：按 mode 输出文本/未编码 bin/编码 bin。
bool zFunction::dump(const char* filePath, DumpMode mode) const {
    // 路径合法性校验。
    if (!filePath || filePath[0] == '\0') return false;

    // 构造“从缓存快照到未编码结构”的转换器。
    auto buildCachedUnencoded = [this]() {
        zUnencodedBytecode unencoded;
        unencoded.registerCount = register_count_cache_;
        unencoded.regList = register_ids_cache_;
        unencoded.typeCount = type_count_cache_;
        unencoded.typeTags = type_tags_cache_;
        unencoded.initValueCount = init_value_count_cache_;
        unencoded.instByAddress = inst_words_by_addr_cache_;
        unencoded.asmByAddress = asm_text_by_addr_cache_;
        unencoded.instCount = inst_count_cache_;
        unencoded.branchCount = branch_count_cache_;
        unencoded.branchWords = branch_words_cache_;
        unencoded.branchAddrWords = branch_addrs_cache_;
        return unencoded;
    };

    // 模式一：未编码二进制导出。
    if (mode == DumpMode::UNENCODED_BIN) {
        // 先确保未编码缓存可用。
        ensureUnencodedReady();
        // 翻译失败直接返回。
        if (!unencoded_translate_ok_) {
            LOGE("dump failed for %s: %s",
                 function_name.c_str(),
                 unencoded_translate_error_.c_str());
            return false;
        }
        // 构建未编码结构快照。
        zUnencodedBytecode unencoded = buildCachedUnencoded();
        // 序列化到 bytes。
        std::vector<uint8_t> unencoded_bytes;
        if (!serializeUnencodedToBinaryBytes(unencoded, &unencoded_bytes)) {
            return false;
        }
        // 落盘。
        return vmp::base::file::writeFileBytes(filePath, unencoded_bytes);
    }

    // 其它模式同样需要未编码缓存。
    ensureUnencodedReady();
    // 翻译失败直接返回。
    if (!unencoded_translate_ok_) {
        LOGE("dump failed for %s: %s",
             function_name.c_str(),
             unencoded_translate_error_.c_str());
        return false;
    }
    // 构建未编码结构快照。
    zUnencodedBytecode unencoded = buildCachedUnencoded();

    // 模式二：编码二进制导出。
    if (mode == DumpMode::ENCODED) {
        // 先把未编码结构转成 zFunctionData。
        zFunctionData source_data;
        std::string error;
        if (!buildEncodedDataFromUnencoded(unencoded, source_data, &error)) {
            LOGE("dump encoded failed: build source data error: %s", error.c_str());
            return false;
        }

        // 执行编码序列化。
        std::vector<uint8_t> encoded;
        if (!source_data.serializeEncoded(encoded, &error)) {
            LOGE("dump encoded failed: serialize error: %s", error.c_str());
            return false;
        }

        // 立刻做一次反序列化校验（round-trip）。
        zFunctionData decoded_data;
        if (!zFunctionData::deserializeEncoded(encoded.data(), encoded.size(), decoded_data, &error)) {
            LOGE("dump encoded failed: deserialize error: %s", error.c_str());
            return false;
        }
        // 比较编码相关字段是否一致。
        if (!source_data.encodedEquals(decoded_data, &error)) {
            LOGE("dump encoded failed: round-trip mismatch: %s", error.c_str());
            return false;
        }

        // 落盘编码结果。
        return vmp::base::file::writeFileBytes(filePath, encoded);
    }

    // 模式三：未编码文本导出。
    std::ofstream out(filePath);
    // 文件打开失败返回 false。
    if (!out) return false;
    // 写文本内容。
    return writeUnencodedToStream(out, unencoded);
}

