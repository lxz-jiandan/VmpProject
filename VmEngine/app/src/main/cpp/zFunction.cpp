/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 运行时侧函数对象实现，负责载入编码数据并提供执行所需视图。
 * - 加固链路位置：VmEngine 执行前准备。
 * - 输入：离线导出的编码 payload。
 * - 输出：可缓存并执行的函数对象。
 */
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
    // begin 指向首个非空白字符。
    size_t begin = 0;
    // 跳过前导空白。
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        begin++;
    }

    // end 从末尾回退到最后一个非空白字符后一个位置。
    size_t end = value.size();
    // 跳过尾部空白。
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        end--;
    }

    // 返回裁剪后的字符串副本。
    return value.substr(begin, end - begin);
}

// 解析单行 32 位数组定义，支持十进制与十六进制字面量。
bool zFunction::parseArrayValues32(const std::string& line, std::vector<uint32_t>& values) {
    // 提取大括号区间。
    size_t l = line.find('{');
    size_t r = line.find('}');
    // 大括号非法时失败。
    if (l == std::string::npos || r == std::string::npos || r <= l) return false;

    // 取出大括号内部内容。
    std::string body = line.substr(l + 1, r - l - 1);
    // 按逗号分割。
    std::stringstream ss(body);
    std::string token;
    // 清空输出数组，避免保留旧值。
    values.clear();
    while (std::getline(ss, token, ',')) {
        // 去除每个元素前后空白。
        std::string trimmed = trimCopy(token);
        if (trimmed.empty()) continue;
        // 支持十进制和 0x 十六进制。
        unsigned long long value = std::strtoull(trimmed.c_str(), nullptr, 0);
        values.push_back(static_cast<uint32_t>(value));
    }
    return true;
}

// 解析单行 64 位数组定义，支持十进制与十六进制字面量。
bool zFunction::parseArrayValues64(const std::string& line, std::vector<uint64_t>& values) {
    // 提取大括号区间。
    size_t l = line.find('{');
    size_t r = line.find('}');
    // 大括号非法时失败。
    if (l == std::string::npos || r == std::string::npos || r <= l) return false;

    // 取出大括号内部内容。
    std::string body = line.substr(l + 1, r - l - 1);
    // 按逗号分割。
    std::stringstream ss(body);
    std::string token;
    // 清空输出数组，避免保留旧值。
    values.clear();
    while (std::getline(ss, token, ',')) {
        // 去除每个元素前后空白。
        std::string trimmed = trimCopy(token);
        if (trimmed.empty()) continue;
        // 支持十进制和 0x 十六进制。
        unsigned long long value = std::strtoull(trimmed.c_str(), nullptr, 0);
        values.push_back(static_cast<uint64_t>(value));
    }
    return true;
}

// 解析 "name = value;" 形式的 uint32 标量。
bool zFunction::parseScalarUint32(const std::string& line, uint32_t& value) {
    // 定位 '=' 与 ';'。
    size_t eq = line.find('=');
    size_t sc = line.find(';', eq);
    if (eq == std::string::npos || sc == std::string::npos || sc <= eq) return false;

    // 提取标量数字区间。
    std::string number = trimCopy(line.substr(eq + 1, sc - eq - 1));
    if (number.empty()) return false;
    // 支持十进制和十六进制。
    value = static_cast<uint32_t>(std::strtoul(number.c_str(), nullptr, 0));
    return true;
}

// 解析 "name = value;" 形式的 uint64 标量。
bool zFunction::parseScalarUint64(const std::string& line, uint64_t& value) {
    // 定位 '=' 与 ';'。
    size_t eq = line.find('=');
    size_t sc = line.find(';', eq);
    if (eq == std::string::npos || sc == std::string::npos || sc <= eq) return false;

    // 提取标量数字区间。
    std::string number = trimCopy(line.substr(eq + 1, sc - eq - 1));
    if (number.empty()) return false;
    // 支持十进制和十六进制。
    value = static_cast<uint64_t>(std::strtoull(number.c_str(), nullptr, 0));
    return true;
}

// 从内存文本解析未编码函数数据。
bool zFunction::loadUnencodedText(const char* text, size_t len) {
    // 输入为空时失败。
    if (text == nullptr || len == 0) return false;
    // 拷贝到 string 以便用 istringstream 统一处理。
    std::string content(text, len);
    // 构造输入流。
    std::istringstream in(content);
    // 复用统一解析流程。
    return parseFromStream(in);
}

namespace {
// 清理运行态解码缓存，确保下一次 loadEncodedData 从干净状态开始。
void resetDecodedRuntimeState(zFunction& function) {
    // 释放寄存器数组。
    delete[] function.register_list;
    function.register_list = nullptr;
    // 释放指令数组。
    delete[] function.inst_list;
    function.inst_list = nullptr;
    // 释放分支数组。
    delete[] function.branch_words_ptr;
    function.branch_words_ptr = nullptr;
    // 释放类型相关资源。
    function.releaseTypeResources();
    // 函数签名指针失效。
    function.function_sig_type = nullptr;
    // 重置计数字段，防止旧值污染。
    function.register_count = 0;
    function.inst_count = 0;
    function.branch_count = 0;
    // 清空外部分支地址指针。
    function.ext_list = nullptr;
}
} // namespace


// 从输入流执行完整解析流程。
bool zFunction::parseFromStream(std::istream& in) {
    // 先清理旧运行态资源。
    resetDecodedRuntimeState(*this);
    // 清空函数地址缓存。
    fun_addr_ = 0;
    // 清空文本解析缓存。
    register_ids_.clear();
    type_tags_.clear();
    branch_words_.clear();
    branch_addrs_.clear();
    inst_words_.clear();
    inst_lines_.clear();

    bool in_inst_list = false;
    // 记录文本中的计数字段，用于后续一致性校验。
    uint32_t reg_id_count = 0;
    uint32_t type_id_count = 0;
    uint32_t branch_id_count = 0;
    uint32_t inst_id_count = 0;

    std::string line;
    // 逐行读取文本。
    while (std::getline(in, line)) {
        // 行首尾裁剪后再做关键字匹配。
        std::string trimmed = trimCopy(line);
        if (trimmed.empty()) continue;

        // 第一阶段：读取头部标量/数组定义。
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
                // 进入 inst 列表读取模式。
                in_inst_list = true;
                continue;
            }
        } else {
            // inst 列表结束标记。
            if (trimmed == "};") {
                in_inst_list = false;
                continue;
            }

            // 去掉行尾注释，保留纯数值段。
            size_t comment_pos = trimmed.find("//");
            std::string value_part = (comment_pos == std::string::npos) ? trimmed : trimmed.substr(0, comment_pos);
            value_part = trimCopy(value_part);
            // 行尾逗号去除，便于统一分割。
            if (!value_part.empty() && value_part.back() == ',') {
                value_part.pop_back();
                value_part = trimCopy(value_part);
            }

            if (value_part.empty()) continue;

            std::vector<uint32_t> words;
            std::stringstream ss(value_part);
            std::string token;
            // 每行可包含多个 uint32，按逗号展开。
            while (std::getline(ss, token, ',')) {
                std::string token_trimmed = trimCopy(token);
                if (token_trimmed.empty()) continue;
                unsigned long long value = std::strtoull(token_trimmed.c_str(), nullptr, 0);
                // 行级缓存（用于回写格式）。
                words.push_back(static_cast<uint32_t>(value));
                // 扁平缓存（用于执行）。
                inst_words_.push_back(static_cast<uint32_t>(value));
            }

            // 非空行写入逐行缓存。
            if (!words.empty()) {
                inst_lines_.push_back(std::move(words));
            }
        }
    }

    // 关键字段至少要有寄存器/类型/指令。
    if (register_ids_.empty() || type_tags_.empty() || inst_words_.empty()) {
        return false;
    }

    // 允许无分支函数：branch_id_count 为 0 时，branch_id_list 允许为空。
    if (branch_id_count > 0 && branch_words_.empty()) {
        return false;
    }

    // 与文本计数字段交叉校验。
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
    branch_lookup_words.clear();
    branch_lookup_addrs.clear();
    zFunctionData::branch_addrs = branch_addrs_;
    function_offset = fun_addr_;

    // 直接构建运行态数组，保证文本/编码两条加载路径走同一执行入口。
    if (register_count > 0) {
        // 分配寄存器数组并清零。
        register_list = new VMRegSlot[register_count];
        std::memset(register_list, 0, sizeof(VMRegSlot) * register_count);
    }

    // 每个函数独立类型池，避免跨函数共享状态。
    std::unique_ptr<zTypeManager> typePool = std::make_unique<zTypeManager>();
    zType** typeList = nullptr;
    if (type_count > 0) {
        // 分配类型表指针数组。
        typeList = new zType*[type_count]();
        for (uint32_t i = 0; i < type_count; i++) {
            // 由类型码构造类型对象。
            typeList[i] = typePool->createFromCode(type_tags[i]);
        }
    }

    // 首类型是函数签名结构时，缓存到 function_sig_type。
    if (type_count > 0 && typeList && typeList[0] && typeList[0]->kind == TYPE_KIND_STRUCT) {
        function_sig_type = reinterpret_cast<FunctionStructType*>(typeList[0]);
    } else {
        function_sig_type = nullptr;
    }

    // 固化 inst_list。
    if (inst_count > 0) {
        inst_list = new uint32_t[inst_count];
        std::memcpy(inst_list, inst_words.data(), sizeof(uint32_t) * inst_count);
    }
    // 固化 branch_words_ptr。
    if (branch_count > 0) {
        branch_words_ptr = new uint32_t[branch_count];
        std::memcpy(branch_words_ptr, branch_words.data(), sizeof(uint32_t) * branch_count);
    }
    // 绑定运行时类型表。
    type_list = typeList;
    // 转移类型池所有权，供后续释放。
    setTypePool(std::move(typePool));
    // ext_list 指向分支地址缓存（为空则置空）。
    ext_list = !branch_addrs_.empty() ? branch_addrs_.data() : nullptr;

    return true;
}

bool zFunction::loadEncodedData(const uint8_t* data, uint64_t len, uint64_t* externalInitArray) {
    // 编码输入为空时直接失败。
    if (data == nullptr || len == 0) {
        return false;
    }

    // 先清理旧运行态。
    resetDecodedRuntimeState(*this);

    // 1) 先反序列化 encoded 载荷到中间对象。
    zFunctionData decoded_data;
    std::string decode_error;
    if (!zFunctionData::deserializeEncoded(data, static_cast<size_t>(len), decoded_data, &decode_error)) {
        LOGE("deserializeEncoded failed: %s", decode_error.c_str());
        return false;
    }
    // 覆盖当前对象的编码字段。
    static_cast<zFunctionData&>(*this) = decoded_data;
    // 同步 branch 地址缓存。
    branch_addrs_ = zFunctionData::branch_addrs;

    // 2) 准备寄存器初值缓存。
    std::unique_ptr<VMRegSlot[]> tempRegisters;
    if (register_count > 0) {
        // 分配并清零寄存器临时数组。
        tempRegisters = std::make_unique<VMRegSlot[]>(register_count);
        std::memset(tempRegisters.get(), 0, sizeof(VMRegSlot) * register_count);
    }

    // 3) 映射外部传入初值（若有）。
    if (first_inst_count > 0 && externalInitArray && tempRegisters && external_init_words.size() == static_cast<size_t>(first_inst_count) * 2ull) {
        for (uint32_t i = 0; i < first_inst_count; i++) {
            // 每组映射：targetReg = externalInitArray[extIdx]。
            const uint32_t targetReg = external_init_words[static_cast<size_t>(i) * 2ull];
            const uint32_t extIdx = external_init_words[static_cast<size_t>(i) * 2ull + 1ull];
            if (targetReg < register_count) {
                // 写入外部初值。
                tempRegisters[targetReg].value = externalInitArray[extIdx];
                // 外部值不归 VM 释放。
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
            // 按类型码构造运行时类型对象。
            typeList[i] = typePool->createFromCode(type_tags[i]);
        }
    }

    // 5) 执行“初始化值指令段”，补齐寄存器初值。
    if (init_value_count > 0 && tempRegisters && typeList && first_inst_opcodes.size() >= init_value_count) {
        // init_value_words 读取游标。
        size_t cursor = 0;
        for (uint32_t i = 0; i < init_value_count; i++) {
            // 越界保护。
            if (cursor >= init_value_words.size()) {
                break;
            }
            // 目标寄存器下标。
            const uint32_t regIdx = init_value_words[cursor++];
            // 当前初始化 opcode。
            const uint32_t opcode = first_inst_opcodes[i];
            if (regIdx >= register_count) {
                // 无效寄存器下标时，按 opcode 消耗对应参数后跳过。
                if (opcode == 1u) {
                    if (cursor + 1 <= init_value_words.size()) cursor += 2;
                } else if (cursor < init_value_words.size()) {
                    cursor += 1;
                }
                continue;
            }

            switch (opcode) {
                case 1u: {
                    // opcode=1：读取 low32/high32 组合 64bit。
                    if (cursor + 1 >= init_value_words.size()) break;
                    const uint32_t low = init_value_words[cursor++];
                    const uint32_t high = init_value_words[cursor++];
                    tempRegisters[regIdx].value = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);
                    // 纯数值不参与释放。
                    tempRegisters[regIdx].ownership = 0;
                    break;
                }
                case 2u: {
                    // opcode=2：值解释为 type 索引，写入类型对象地址。
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
                    // 默认：读取单个 32bit 值写入寄存器。
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

    // 7) 从 type_list 按约定推导 function_sig_type（首元素为函数签名结构体类型）。
    FunctionStructType* functionList = nullptr;
    if (type_count > 0 && typeList && typeList[0]) {
        // 约定：type_list[0] 若为 STRUCT 则可视为函数签名类型。
        if (typeList[0]->kind == TYPE_KIND_STRUCT) {
            functionList = reinterpret_cast<FunctionStructType*>(typeList[0]);
        }
    }

    function_sig_type = functionList;

    // 8) 固化运行态数组：register/inst/branch/type。
    if (register_count > 0 && tempRegisters) {
        // 把临时寄存器初值固化为运行态寄存器数组。
        register_list = new VMRegSlot[register_count];
        std::memcpy(register_list, tempRegisters.get(), sizeof(VMRegSlot) * register_count);
    }

    // 先用 unique_ptr 承接，避免中途异常泄漏。
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

    // 转移所有权到成员字段。
    inst_list = instList.release();
    branch_words_ptr = branchList.release();
    type_list = typeList;
    setTypePool(std::move(typePool));
    // 优先使用解析出的 branch_addrs_，回退 externalInitArray 兼容旧逻辑。
    ext_list = !branch_addrs_.empty() ? branch_addrs_.data() : externalInitArray;

    return true;
}

// 判断当前是否没有解析到任何指令数据。
bool zFunction::empty() const {
    // 只要运行态有有效 inst_list 与 inst_count，就不算空。
    if (inst_count > 0 && inst_list != nullptr) {
        return false;
    }
    // 否则按解析缓存 inst_words_ 是否为空判断。
    return inst_words_.empty();
}

// 只读访问分支地址列表。
const std::vector<uint64_t>& zFunction::branchAddrs() const {
    return branch_addrs_;
}

uint64_t zFunction::functionAddress() const {
    // 返回 fun_addr 缓存值。
    return fun_addr_;
}

void zFunction::setFunctionAddress(uint64_t functionAddress) {
    // 覆盖 fun_addr 缓存值。
    fun_addr_ = functionAddress;
}

void zFunction::setTypePool(std::unique_ptr<zTypeManager> pool) {
    // 交接类型池所有权。
    type_pool_ = std::move(pool);
}

void zFunction::releaseTypeResources() {
    // type_list 非空时先释放其元素。
    if (type_list != nullptr) {
        if (type_pool_) {
            // 有类型池时由类型池统一释放，保持创建/销毁路径一致。
            type_pool_->freeTypeList(type_list, type_count);
        } else {
            // 无类型池时退化为仅释放指针数组（元素生命周期由外部兜底）。
            delete[] type_list;
        }
        type_list = nullptr;
    }
    // 重置类型计数与类型池。
    type_count = 0;
    type_pool_.reset();
}

