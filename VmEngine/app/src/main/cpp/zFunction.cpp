#include "zFunction.h"
#include "zTypeManager.h"

#include <algorithm>
#include <cctype>
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

// 从内存文本解析 function_unencoded 数据。
bool zFunction::loadUnencodedText(const char* text, size_t len) {
    if (text == nullptr || len == 0) return false;
    std::string content(text, len);
    std::istringstream in(content);
    return parseFromStream(in);
}

// 从输入流执行完整解析流程。
bool zFunction::parseFromStream(std::istream& in) {
    fun_addr_ = 0;
    reg_id_list_.clear();
    type_id_list_.clear();
    branch_id_list_.clear();
    branch_addr_from_file_.clear();
    inst_id_list_.clear();
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
            if (trimmed.find("static const uint32_t fun_addr") != std::string::npos) {
                uint32_t funAddr = 0;
                if (!parseScalarUint32(trimmed, funAddr)) return false;
                fun_addr_ = static_cast<uint64_t>(funAddr);
                continue;
            }
            if (trimmed.find("static const uint32_t reg_id_list[]") != std::string::npos) {
                if (!parseArrayValues32(trimmed, reg_id_list_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t reg_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, reg_id_count)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t type_id_list[]") != std::string::npos) {
                if (!parseArrayValues32(trimmed, type_id_list_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t type_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, type_id_count)) return false;
                continue;
            }
            if (trimmed.find("uint32_t branch_id_list") != std::string::npos && trimmed.find('{') != std::string::npos) {
                if (!parseArrayValues32(trimmed, branch_id_list_)) return false;
                continue;
            }
            if (trimmed.find("static const uint32_t branch_id_count") != std::string::npos) {
                if (!parseScalarUint32(trimmed, branch_id_count)) return false;
                continue;
            }
            if (trimmed.find("uint64_t branch_addr_list") != std::string::npos && trimmed.find('{') != std::string::npos) {
                if (!parseArrayValues64(trimmed, branch_addr_from_file_)) return false;
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
                inst_id_list_.push_back(static_cast<uint32_t>(value));
            }

            if (!words.empty()) {
                inst_lines_.push_back(std::move(words));
            }
        }
    }

    if (reg_id_list_.empty() || type_id_list_.empty() || inst_id_list_.empty()) {
        return false;
    }

    // 允许无分支函数：branch_id_count 为 0 时，branch_id_list 允许为空。
    if (branch_id_count > 0 && branch_id_list_.empty()) {
        return false;
    }

    if (reg_id_count != 0 && reg_id_count != static_cast<uint32_t>(reg_id_list_.size())) return false;
    if (type_id_count != 0 && type_id_count != static_cast<uint32_t>(type_id_list_.size())) return false;
    if (branch_id_count != static_cast<uint32_t>(branch_id_list_.size())) return false;
    if (inst_id_count != 0 && inst_id_count != static_cast<uint32_t>(inst_id_list_.size())) return false;

    return true;
}

// 判断当前是否没有解析到任何指令数据。
bool zFunction::empty() const {
    return inst_id_list_.empty();
}

// 返回寄存器 ID 列表长度。
uint32_t zFunction::regIdCount() const {
    return static_cast<uint32_t>(reg_id_list_.size());
}

// 返回类型 ID 列表长度。
uint32_t zFunction::typeIdCount() const {
    return static_cast<uint32_t>(type_id_list_.size());
}

// 返回分支 ID 列表长度。
uint32_t zFunction::branchIdCount() const {
    return static_cast<uint32_t>(branch_id_list_.size());
}

// 返回指令 ID 列表长度。
uint32_t zFunction::instIdCount() const {
    return static_cast<uint32_t>(inst_id_list_.size());
}

// 只读访问寄存器 ID 列表。
const std::vector<uint32_t>& zFunction::regIdList() const {
    return reg_id_list_;
}

// 只读访问类型 ID 列表。
const std::vector<uint32_t>& zFunction::typeIdList() const {
    return type_id_list_;
}

// 只读访问分支 ID 列表。
const std::vector<uint32_t>& zFunction::branchIdList() const {
    return branch_id_list_;
}

// 只读访问指令 ID 列表。
const std::vector<uint32_t>& zFunction::instIdList() const {
    return inst_id_list_;
}

// 只读访问指令 ID 列表。
const std::vector<uint64_t>& zFunction::branchAddrList() const {
    return branch_addr_from_file_;
}

uint64_t zFunction::funAddr() const {
    return fun_addr_;
}

void zFunction::setFunAddr(uint64_t funAddr) {
    fun_addr_ = funAddr;
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

