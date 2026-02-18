#include "zFunction.h"
#include "zVmEngine.h"
#include "zLog.h"
#include "zTypeManager.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <istream>
#include <sstream>

// 去除字符串两端空白字符，返回裁剪后的副本。
std::string zFunction::trimCopy(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        begin++;
    }

    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        end--;
    }

    return value.substr(begin, end - begin);
}

// 解析单行 32 位数组定义，支持十进制与十六进制字面量。
bool zFunction::parseArrayValues32(const std::string& line, std::vector<uint32_t>& values) {
    size_t l = line.find('{');
    size_t r = line.find('}');
    if (l == std::string::npos || r == std::string::npos || r <= l) return false;

    std::string body = line.substr(l + 1, r - l - 1);
    std::stringstream ss(body);
    std::string token;
    values.clear();
    while (std::getline(ss, token, ',')) {
        std::string trimmed = trimCopy(token);
        if (trimmed.empty()) continue;
        unsigned long long value = std::strtoull(trimmed.c_str(), nullptr, 0);
        values.push_back(static_cast<uint32_t>(value));
    }
    return true;
}

// 解析单行 64 位数组定义，支持十进制与十六进制字面量。
bool zFunction::parseArrayValues64(const std::string& line, std::vector<uint64_t>& values) {
    size_t l = line.find('{');
    size_t r = line.find('}');
    if (l == std::string::npos || r == std::string::npos || r <= l) return false;

    std::string body = line.substr(l + 1, r - l - 1);
    std::stringstream ss(body);
    std::string token;
    values.clear();
    while (std::getline(ss, token, ',')) {
        std::string trimmed = trimCopy(token);
        if (trimmed.empty()) continue;
        unsigned long long value = std::strtoull(trimmed.c_str(), nullptr, 0);
        values.push_back(static_cast<uint64_t>(value));
    }
    return true;
}

// 解析 "name = value;" 形式的 uint32 标量。
bool zFunction::parseScalarUint32(const std::string& line, uint32_t& value) {
    size_t eq = line.find('=');
    size_t sc = line.find(';', eq);
    if (eq == std::string::npos || sc == std::string::npos || sc <= eq) return false;

    std::string number = trimCopy(line.substr(eq + 1, sc - eq - 1));
    if (number.empty()) return false;
    value = static_cast<uint32_t>(std::strtoul(number.c_str(), nullptr, 0));
    return true;
}

// 解析 "name = value;" 形式的 uint64 标量。
bool zFunction::parseScalarUint64(const std::string& line, uint64_t& value) {
    size_t eq = line.find('=');
    size_t sc = line.find(';', eq);
    if (eq == std::string::npos || sc == std::string::npos || sc <= eq) return false;

    std::string number = trimCopy(line.substr(eq + 1, sc - eq - 1));
    if (number.empty()) return false;
    value = static_cast<uint64_t>(std::strtoull(number.c_str(), nullptr, 0));
    return true;
}

// 从内存文本解析未编码函数数据。
bool zFunction::loadUnencodedText(const char* text, size_t len) {
    if (text == nullptr || len == 0) return false;
    std::string content(text, len);
    std::istringstream in(content);
    return parseFromStream(in);
}

namespace {
// 清理运行态解码缓存，确保下一次 loadEncodedData 从干净状态开始。
void resetDecodedRuntimeState(zFunction& function) {
    delete[] function.register_list;
    function.register_list = nullptr;
    delete[] function.inst_list;
    function.inst_list = nullptr;
    delete[] function.branch_words_ptr;
    function.branch_words_ptr = nullptr;
    function.releaseTypeResources();
    function.function_sig_type = nullptr;
    function.register_count = 0;
    function.inst_count = 0;
    function.branch_count = 0;
    function.ext_list = nullptr;
}
} // namespace


// 从输入流执行完整解析流程。
bool zFunction::parseFromStream(std::istream& in) {
    fun_addr_ = 0;
    register_ids_.clear();
    type_tags_.clear();
    branch_words_.clear();
    branch_addrs_.clear();
    inst_words_.clear();
    inst_lines_.clear();

    bool in_inst_list = false;
    uint32_t reg_id_count = 0;
    uint32_t type_id_count = 0;
    uint32_t branch_id_count = 0;
    uint32_t inst_id_count = 0;

    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = trimCopy(line);
        if (trimmed.empty()) continue;

        if (!in_inst_list) {
            if (trimmed.find("static const uint64_t fun_addr") != std::string::npos) {
                uint64_t funAddr = 0;
                if (!parseScalarUint64(trimmed, funAddr)) return false;
                fun_addr_ = funAddr;
                continue;
            }
            if (trimmed.find("static const uint32_t fun_addr") != std::string::npos) {
                uint32_t funAddr = 0;
                if (!parseScalarUint32(trimmed, funAddr)) return false;
                fun_addr_ = static_cast<uint64_t>(funAddr);
                continue;
            }
            if (trimmed.find("static const uint32_t reg_id_list[]") != std::string::npos) {
                if (!parseArrayValues32(trimmed, register_ids_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t reg_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, reg_id_count)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t type_id_list[]") != std::string::npos) {
                if (!parseArrayValues32(trimmed, type_tags_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t type_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, type_id_count)) return false;
                continue;
            }
            if (trimmed.find("uint32_t branch_id_list") != std::string::npos && trimmed.find('{') != std::string::npos) {
                if (!parseArrayValues32(trimmed, branch_words_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t branch_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, branch_id_count)) return false;
                continue;
            }
            if (trimmed.find("uint64_t branch_addr_list") != std::string::npos && trimmed.find('{') != std::string::npos) {
                if (!parseArrayValues64(trimmed, branch_addrs_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t inst_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, inst_id_count)) return false;
                continue;
            }
            if (trimmed.find("uint32_t inst_id_list[]") != std::string::npos) {
                in_inst_list = true;
                continue;
            }
        } else {
            if (trimmed == "};") {
                in_inst_list = false;
                continue;
            }

            size_t comment_pos = trimmed.find("//");
            std::string value_part = (comment_pos == std::string::npos) ? trimmed : trimmed.substr(0, comment_pos);
            value_part = trimCopy(value_part);
            if (!value_part.empty() && value_part.back() == ',') {
                value_part.pop_back();
                value_part = trimCopy(value_part);
            }

            if (value_part.empty()) continue;

            std::vector<uint32_t> words;
            std::stringstream ss(value_part);
            std::string token;
            while (std::getline(ss, token, ',')) {
                std::string token_trimmed = trimCopy(token);
                if (token_trimmed.empty()) continue;
                unsigned long long value = std::strtoull(token_trimmed.c_str(), nullptr, 0);
                words.push_back(static_cast<uint32_t>(value));
                inst_words_.push_back(static_cast<uint32_t>(value));
            }

            if (!words.empty()) {
                inst_lines_.push_back(std::move(words));
            }
        }
    }

    if (register_ids_.empty() || type_tags_.empty() || inst_words_.empty()) {
        return false;
    }

    // 允许无分支函数：branch_id_count 为 0 时，branch_id_list 允许为空。
    if (branch_id_count > 0 && branch_words_.empty()) {
        return false;
    }

    if (reg_id_count != 0 && reg_id_count != static_cast<uint32_t>(register_ids_.size())) return false;
    if (type_id_count != 0 && type_id_count != static_cast<uint32_t>(type_tags_.size())) return false;
    if (branch_id_count != static_cast<uint32_t>(branch_words_.size())) return false;
    if (inst_id_count != 0 && inst_id_count != static_cast<uint32_t>(inst_words_.size())) return false;

    // 将文本解析结果同步到 zFunctionData 字段，统一后续执行入口。
    marker = 0;
    register_count = static_cast<uint32_t>(register_ids_.size());
    first_inst_count = 0;
    first_inst_opcodes.clear();
    external_init_words.clear();
    type_count = static_cast<uint32_t>(type_tags_.size());
    type_tags = type_tags_;
    init_value_count = 0;
    init_value_words.clear();
    inst_count = static_cast<uint32_t>(inst_words_.size());
    inst_words = inst_words_;
    branch_count = static_cast<uint32_t>(branch_words_.size());
    branch_words = branch_words_;
    zFunctionData::branch_addrs = branch_addrs_;
    function_offset = fun_addr_;

    return true;
}

bool zFunction::loadEncodedData(const uint8_t* data, uint64_t len, uint64_t* externalInitArray) {
    if (data == nullptr || len == 0) {
        return false;
    }

    resetDecodedRuntimeState(*this);

    // 1) 先反序列化 encoded 载荷到中间对象。
    zFunctionData decoded_data;
    std::string decode_error;
    if (!zFunctionData::deserializeEncoded(data, static_cast<size_t>(len), decoded_data, &decode_error)) {
        LOGE("deserializeEncoded failed: %s", decode_error.c_str());
        return false;
    }
    static_cast<zFunctionData&>(*this) = decoded_data;
    branch_addrs_ = zFunctionData::branch_addrs;

    // 2) 准备寄存器初值缓存。
    std::unique_ptr<VMRegSlot[]> tempRegisters;
    if (register_count > 0) {
        tempRegisters = std::make_unique<VMRegSlot[]>(register_count);
        std::memset(tempRegisters.get(), 0, sizeof(VMRegSlot) * register_count);
    }

    // 3) 映射外部传入初值（若有）。
    if (first_inst_count > 0 && externalInitArray && tempRegisters && external_init_words.size() == static_cast<size_t>(first_inst_count) * 2ull) {
        for (uint32_t i = 0; i < first_inst_count; i++) {
            const uint32_t targetReg = external_init_words[static_cast<size_t>(i) * 2ull];
            const uint32_t extIdx = external_init_words[static_cast<size_t>(i) * 2ull + 1ull];
            if (targetReg < register_count) {
                tempRegisters[targetReg].value = externalInitArray[extIdx];
                tempRegisters[targetReg].ownership = 0;
            }
        }
    }

    // 4) 构建本函数独立类型池与 type_list。
    std::unique_ptr<zTypeManager> typePool = std::make_unique<zTypeManager>();
    zType** typeList = nullptr;
    if (type_count > 0) {
        typeList = new zType*[type_count]();
        for (uint32_t i = 0; i < type_count; i++) {
            typeList[i] = typePool->createFromCode(type_tags[i]);
        }
    }

    // 5) 执行“初始化值指令段”，补齐寄存器初值。
    if (init_value_count > 0 && tempRegisters && typeList && first_inst_opcodes.size() >= init_value_count) {
        size_t cursor = 0;
        for (uint32_t i = 0; i < init_value_count; i++) {
            if (cursor >= init_value_words.size()) {
                break;
            }
            const uint32_t regIdx = init_value_words[cursor++];
            const uint32_t opcode = first_inst_opcodes[i];
            if (regIdx >= register_count) {
                if (opcode == 1u) {
                    if (cursor + 1 <= init_value_words.size()) cursor += 2;
                } else if (cursor < init_value_words.size()) {
                    cursor += 1;
                }
                continue;
            }

            switch (opcode) {
                case 1u: {
                    if (cursor + 1 >= init_value_words.size()) break;
                    const uint32_t low = init_value_words[cursor++];
                    const uint32_t high = init_value_words[cursor++];
                    tempRegisters[regIdx].value = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);
                    tempRegisters[regIdx].ownership = 0;
                    break;
                }
                case 2u: {
                    if (cursor >= init_value_words.size()) break;
                    const uint32_t typeIdx = init_value_words[cursor++];
                    if (typeIdx < type_count && typeList[typeIdx]) {
                        tempRegisters[regIdx].value = reinterpret_cast<uint64_t>(typeList[typeIdx]);
                    }
                    tempRegisters[regIdx].ownership = 0;
                    break;
                }
                case 0u:
                default: {
                    if (cursor >= init_value_words.size()) break;
                    tempRegisters[regIdx].value = init_value_words[cursor++];
                    tempRegisters[regIdx].ownership = 0;
                    break;
                }
            }
        }
    }

    // 6) 恢复函数地址（fun_addr）。
    setFunctionAddress(function_offset);

    // 7) 从 type_list 推导 function_sig_type（当前按首元素做兼容处理）。
    FunctionStructType* functionList = nullptr;
    if (type_count > 0 && typeList && typeList[0]) {
        if (typeList[0]->kind == TYPE_KIND_STRUCT) {
            functionList = reinterpret_cast<FunctionStructType*>(typeList[0]);
        }
    }

    function_sig_type = functionList;

    // 8) 固化运行态数组：register/inst/branch/type。
    if (register_count > 0 && tempRegisters) {
        register_list = new VMRegSlot[register_count];
        std::memcpy(register_list, tempRegisters.get(), sizeof(VMRegSlot) * register_count);
    }

    std::unique_ptr<uint32_t[]> instList;
    if (inst_count > 0) {
        instList = std::make_unique<uint32_t[]>(inst_count);
        std::memcpy(instList.get(), inst_words.data(), sizeof(uint32_t) * inst_count);
    }
    std::unique_ptr<uint32_t[]> branchList;
    if (branch_count > 0) {
        branchList = std::make_unique<uint32_t[]>(branch_count);
        std::memcpy(branchList.get(), branch_words.data(), sizeof(uint32_t) * branch_count);
    }

    inst_list = instList.release();
    branch_words_ptr = branchList.release();
    type_list = typeList;
    setTypePool(std::move(typePool));
    ext_list = !branch_addrs_.empty() ? branch_addrs_.data() : externalInitArray;

    return true;
}

// 判断当前是否没有解析到任何指令数据。
bool zFunction::empty() const {
    if (inst_count > 0 && inst_list != nullptr) {
        return false;
    }
    return inst_words_.empty();
}

// 返回寄存器 ID 列表长度。
uint32_t zFunction::registerIdCount() const {
    return static_cast<uint32_t>(register_ids_.size());
}

// 返回类型 ID 列表长度。
uint32_t zFunction::typeTagCount() const {
    if (!type_tags_.empty()) {
        return static_cast<uint32_t>(type_tags_.size());
    }
    return type_count;
}

// 返回分支 ID 列表长度。
uint32_t zFunction::branchWordCount() const {
    if (!branch_words_.empty()) {
        return static_cast<uint32_t>(branch_words_.size());
    }
    return branch_count;
}

// 返回指令 ID 列表长度。
uint32_t zFunction::instWordCount() const {
    if (!inst_words_.empty()) {
        return static_cast<uint32_t>(inst_words_.size());
    }
    return inst_count;
}

// 只读访问寄存器 ID 列表。
const std::vector<uint32_t>& zFunction::registerIds() const {
    return register_ids_;
}

// 只读访问类型 ID 列表。
const std::vector<uint32_t>& zFunction::typeTags() const {
    if (!type_tags_.empty()) {
        return type_tags_;
    }
    return zFunctionData::type_tags;
}

// 只读访问分支 ID 列表。
const std::vector<uint32_t>& zFunction::branchWords() const {
    if (!branch_words_.empty()) {
        return branch_words_;
    }
    return zFunctionData::branch_words;
}

// 只读访问指令 ID 列表。
const std::vector<uint32_t>& zFunction::instWords() const {
    if (!inst_words_.empty()) {
        return inst_words_;
    }
    return zFunctionData::inst_words;
}

// 只读访问分支地址列表。
const std::vector<uint64_t>& zFunction::branchAddrs() const {
    return branch_addrs_;
}

uint64_t zFunction::functionAddress() const {
    return fun_addr_;
}

void zFunction::setFunctionAddress(uint64_t functionAddress) {
    fun_addr_ = functionAddress;
}

void zFunction::setTypePool(std::unique_ptr<zTypeManager> pool) {
    type_pool_ = std::move(pool);
}

void zFunction::releaseTypeResources() {
    if (type_list != nullptr) {
        if (type_pool_) {
            type_pool_->freeTypeList(type_list, type_count);
        } else {
            delete[] type_list;
        }
        type_list = nullptr;
    }
    type_count = 0;
    type_pool_.reset();
}

