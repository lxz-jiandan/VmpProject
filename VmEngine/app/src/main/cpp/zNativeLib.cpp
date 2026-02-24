/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - vm_init 回归总控：去除 JNI_OnLoad 后的统一初始化入口。
 * - 加固链路位置：运行时入口编排层。
 * - 输入：assets + expand so + 内嵌 payload + 符号清单。
 * - 输出：各路线初始化结果与 VM 初始化状态。
 */
#include <jni.h>  // JNIEnv / JavaVM / JNI_GetCreatedJavaVMs。

#include <atomic>         // g_vm_init_state。
#include <cerrno>         // errno / strerror。
#include <cctype>         // std::isspace。
#include <cstdint>        // uint64_t / uintptr_t。
#include <cstdio>         // FILE / fread / fclose。
#include <cstdlib>        // std::strtoull。
#include <cstring>        // std::strerror。
#include <dlfcn.h>        // dladdr。
#include <elf.h>          // Elf64_Ehdr/Elf64_Shdr/Elf64_Sym。
#include <fcntl.h>        // open。
#include <mutex>          // vm_init 互斥保护。
#include <memory>         // std::unique_ptr / std::make_unique。
#include <new>            // placement new。
#include <sstream>        // std::stringstream。
#include <string>         // std::string。
#include <type_traits>    // std::aligned_storage。
#include <unordered_map>  // 名称/地址索引。
#include <unordered_set>  // 差分用例过滤集合。
#include <unistd.h>       // write / close。
#include <vector>         // 动态数组容器。

#include "zAssestManager.h"  // assets 读写与解包。
#include "zEmbeddedPayload.h"  // route4 嵌入 payload 读取。
#include "zFunction.h"       // zFunction 装载与地址绑定。
#include "zLog.h"            // LOGI/LOGE。
#include "zSoBinBundle.h"    // expand so 容器读取。
#include "zSymbolTakeover.h" // route4 L2 导出符号接管。
#include "zVmEngine.h"       // VM 执行入口。

// 保存解包后的 base so 绝对路径，供 zLinker 执行与后续日志定位复用。
static std::string g_libdemo_so_path;
// 保存解包后的 expand so 绝对路径，供 expand 容器读取流程复用。
static std::string g_libdemo_expand_so_path;
// 保存 route4 从 vmengine.so 内嵌 payload 落盘后的 expand so 路径。
static std::string g_libdemo_expand_embedded_so_path;

// 资产名：基础 so（文本/编码 bin 路线都基于它执行）。
constexpr const char* kAssetBaseSo = "libdemo.so";
// 资产名：expand so（编码容器路线使用）。
constexpr const char* kAssetExpandSo = "libdemo_expand.so";
// route4 运行时落盘的 expand so 文件名。
constexpr const char* kEmbeddedExpandSoName = "libdemo_expand_embedded.so";
// 资产名：所有函数共享的一份 branch 地址列表。
constexpr const char* kAssetBranchAddrList = "branch_addr_list.txt";
// 字符串返回值用例函数名，用于覆盖对象返回（sret）路径。
constexpr const char* kStringCaseFunctionName = "fun_cpp_make_string";
// 字符串用例的文本资产。
constexpr const char* kStringCaseTxtAsset = "fun_cpp_make_string.txt";
// 字符串用例的编码资产。
constexpr const char* kStringCaseBinAsset = "fun_cpp_make_string.bin";
// 基础算术用例的固定期望值，防止“三路一致但整体错误”。
constexpr uint64_t kExpectedResult = 30;

enum zVmInitState : int {
    // 尚未执行初始化。
    kVmInitStateUninitialized = 0,
    // 初始化进行中（用于并发线程可见状态）。
    kVmInitStateInitializing = 1,
    // 初始化已完成，可进入 VM 调度路径。
    kVmInitStateReady = 2,
    // 初始化失败，后续调用应走兜底或直接失败。
    kVmInitStateFailed = 3,
};

// vmengine 全局初始化状态：由 vm_init 写入，导出跳板读取。
static std::atomic<int> g_vm_init_state{kVmInitStateUninitialized};

// vm_init 串行锁：保证任意时刻只有一个线程执行初始化流程。
static std::mutex g_vm_init_mutex;

namespace {

struct FunctionCaseConfig {
    // 回归函数名（也是日志标识）。
    const char* function_name;
    // 未编码路线读取的文本文件名。
    const char* txt_asset;
    // 编码路线读取的 bin 文件名。
    const char* bin_asset;
};

struct FunctionExpectedConfig {
    // 函数名（必须与导出/资产中的函数名完全一致）。
    const char* function_name;
    // 固定输入 (2,4) 下的期望返回值（route4-only 对照基线）。
    uint64_t expected_result;
};

struct FunctionCaseResult {
    // 以未编码路线为基准记录地址和期望结果，后两条路线做一致性比对。
    // 函数名。
    std::string function_name;
    // 基准路线解析得到的函数地址。
    uint64_t fun_addr = 0;
    // 基准路线执行结果（字符串用例不使用该字段）。
    uint64_t expected_result = 0;
};

enum class EmbeddedExpandRouteStatus {
    // route4 L1 成功执行并校验通过。
    kPass = 0,
    // 读取/装载/执行任一步失败。
    kFail = 1,
};

const FunctionCaseConfig kFunctionCases[] = {
    // 固定顺序用于三条路线逐项对齐；带全局写入副作用的用例放在列表末尾。
    {"fun_for", "fun_for.txt", "fun_for.bin"},  // 基础 for 循环。
    {"fun_add", "fun_add.txt", "fun_add.bin"},  // 基础整数加法。
    {"fun_for_add", "fun_for_add.txt", "fun_for_add.bin"},  // 固定值守门用例。
    {"fun_if_sub", "fun_if_sub.txt", "fun_if_sub.bin"},  // if 分支 + 减法路径。
    {"fun_countdown_muladd", "fun_countdown_muladd.txt", "fun_countdown_muladd.bin"},  // 递减循环 + 乘加。
    {"fun_loop_call_mix", "fun_loop_call_mix.txt", "fun_loop_call_mix.bin"},  // 循环中调用子函数。
    {"fun_call_chain", "fun_call_chain.txt", "fun_call_chain.bin"},  // 多层调用链。
    {"fun_branch_call", "fun_branch_call.txt", "fun_branch_call.bin"},  // 分支后调用路径。
    {"fun_cpp_string_len", "fun_cpp_string_len.txt", "fun_cpp_string_len.bin"},  // C++ string 长度读取。
    {"fun_cpp_vector_sum", "fun_cpp_vector_sum.txt", "fun_cpp_vector_sum.bin"},  // C++ vector 求和。
    {"fun_cpp_virtual_mix", "fun_cpp_virtual_mix.txt", "fun_cpp_virtual_mix.bin"},  // 虚函数分派混合路径。
    {"fun_global_data_mix", "fun_global_data_mix.txt", "fun_global_data_mix.bin"},  // 全局数据读写混合。
    {"fun_static_local_table", "fun_static_local_table.txt", "fun_static_local_table.bin"},  // 静态局部表访问。
    {"fun_global_struct_acc", "fun_global_struct_acc.txt", "fun_global_struct_acc.bin"},  // 全局结构体字段累计。
    {"fun_class_static_member", "fun_class_static_member.txt", "fun_class_static_member.bin"},  // 类静态成员读写。
    {"fun_multi_branch_path", "fun_multi_branch_path.txt", "fun_multi_branch_path.bin"},  // 多分支路径覆盖。
    {"fun_switch_dispatch", "fun_switch_dispatch.txt", "fun_switch_dispatch.bin"},  // switch 派发路径。
    {"fun_bitmask_branch", "fun_bitmask_branch.txt", "fun_bitmask_branch.bin"},  // 位运算 + 分支。
    {"fun_global_table_rw", "fun_global_table_rw.txt", "fun_global_table_rw.bin"},  // 全局表读写。
    {"fun_global_mutable_state", "fun_global_mutable_state.txt", "fun_global_mutable_state.bin"},  // 全局可变状态。
};

// route4-only 回归基线：不执行 route1/2/3，直接用固定输入的期望结果做一致性校验。
const FunctionExpectedConfig kFunctionExpectedResults[] = {
    // 基础循环函数。
    {"fun_for", 30},
    // 基础加法函数。
    {"fun_add", 6},
    // 守门用例，结果应与 kExpectedResult 一致。
    {"fun_for_add", kExpectedResult},
    // if/else 分支函数。
    {"fun_if_sub", 2},
    // 递减循环 + 乘加函数。
    {"fun_countdown_muladd", 10},
    // 循环调用混合函数。
    {"fun_loop_call_mix", 18},
    // 调用链函数。
    {"fun_call_chain", 38},
    // 分支调用函数。
    {"fun_branch_call", 24},
    // C++ string 长度函数。
    {"fun_cpp_string_len", 4},
    // C++ vector 求和函数。
    {"fun_cpp_vector_sum", 12},
    // 虚函数分派混合函数。
    {"fun_cpp_virtual_mix", 6},
    // 全局数据混合读写函数。
    {"fun_global_data_mix", 31},
    // 静态局部表读写函数。
    {"fun_static_local_table", 10},
    // 全局结构体字段累计函数。
    {"fun_global_struct_acc", 22},
    // 类静态成员读写函数。
    {"fun_class_static_member", 20},
    // 多分支路径函数。
    {"fun_multi_branch_path", 8},
    // switch 派发函数。
    {"fun_switch_dispatch", 10},
    // 位运算分支函数（按 uint64 存储 -2 的补码值）。
    {"fun_bitmask_branch", 4294967294ULL},
    // 全局表读写函数。
    {"fun_global_table_rw", 74},
    // 全局可变状态函数。
    {"fun_global_mutable_state", 45},
};

bool findExpectedResultByFunctionName(const char* function_name, uint64_t& out_expected_result) {
    // 调用方必须传有效函数名；空指针或空串直接失败。
    if (function_name == nullptr || function_name[0] == '\0') {
        return false;
    }
    // 线性扫描小规模常量表，逻辑直观且足够快。
    for (const FunctionExpectedConfig& item : kFunctionExpectedResults) {
        // 名称完全匹配才可认为找到。
        if (std::strcmp(item.function_name, function_name) == 0) {
            // 回写期望值给调用方。
            out_expected_result = item.expected_result;
            // 找到即返回，避免额外遍历。
            return true;
        }
    }
    // 没有任何命中则返回 false，由上层记录缺失并中断启动。
    return false;
}

bool parseTakeoverSlotId(const char* symbol_name, uint32_t* out_slot_id) {
    // 解析格式：vm_takeover_slot_0000。
    if (out_slot_id == nullptr || symbol_name == nullptr) {
        return false;
    }
    static constexpr const char* kPrefix = "vm_takeover_slot_";
    static constexpr size_t kPrefixLen = 17;
    if (std::strncmp(symbol_name, kPrefix, kPrefixLen) != 0) {
        return false;
    }
    const char* digits = symbol_name + kPrefixLen;
    if (digits[0] == '\0') {
        return false;
    }
    for (const char* p = digits; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    const unsigned long slot = std::strtoul(digits, nullptr, 10);
    if (slot > 0xFFFFFFFFUL) {
        return false;
    }
    *out_slot_id = static_cast<uint32_t>(slot);
    return true;
}

bool loadFileBytesByPath(const std::string& path, std::vector<uint8_t>& out_bytes) {
    // 统一二进制加载工具：读取整个 ELF 文件到内存。
    out_bytes.clear();
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        return false;
    }
    if (std::fseek(fp, 0, SEEK_END) != 0) {
        std::fclose(fp);
        return false;
    }
    const long size = std::ftell(fp);
    if (size < 0) {
        std::fclose(fp);
        return false;
    }
    if (std::fseek(fp, 0, SEEK_SET) != 0) {
        std::fclose(fp);
        return false;
    }
    out_bytes.resize(static_cast<size_t>(size));
    const size_t nread = out_bytes.empty() ? 0 : std::fread(out_bytes.data(), 1, out_bytes.size(), fp);
    std::fclose(fp);
    return out_bytes.empty() || nread == out_bytes.size();
}

bool buildTakeoverEntriesFromPatchedVmengineElf(
    const std::string& vmengine_path,
    std::vector<zTakeoverSymbolEntry>& out_entries
) {
    // 目标：从 patched libvmengine.so 的 .dynsym 恢复 slot_id -> key(fun_addr)。
    out_entries.clear();
    std::vector<uint8_t> file_bytes;
    if (!loadFileBytesByPath(vmengine_path, file_bytes)) {
        LOGE("[route_symbol_takeover] load vmengine file failed: %s", vmengine_path.c_str());
        return false;
    }
    if (file_bytes.size() < sizeof(Elf64_Ehdr)) {
        LOGE("[route_symbol_takeover] vmengine file too small: %s", vmengine_path.c_str());
        return false;
    }

    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(file_bytes.data());
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        LOGE("[route_symbol_takeover] invalid elf header: %s", vmengine_path.c_str());
        return false;
    }
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0) {
        LOGE("[route_symbol_takeover] invalid section table: %s", vmengine_path.c_str());
        return false;
    }
    if (ehdr->e_shoff > file_bytes.size() ||
        static_cast<size_t>(ehdr->e_shoff) + static_cast<size_t>(ehdr->e_shnum) * sizeof(Elf64_Shdr) > file_bytes.size()) {
        LOGE("[route_symbol_takeover] section table out of range: %s", vmengine_path.c_str());
        return false;
    }

    const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(file_bytes.data() + ehdr->e_shoff);
    const Elf64_Shdr* dynsym_sh = nullptr;
    const Elf64_Shdr* dynstr_sh = nullptr;
    // 先定位 .dynsym，再依据 sh_link 拿到 .dynstr。
    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym_sh = &shdrs[i];
            if (shdrs[i].sh_link < ehdr->e_shnum) {
                dynstr_sh = &shdrs[shdrs[i].sh_link];
            }
            break;
        }
    }
    if (dynsym_sh == nullptr || dynstr_sh == nullptr || dynstr_sh->sh_type != SHT_STRTAB) {
        LOGE("[route_symbol_takeover] dynsym/dynstr missing: %s", vmengine_path.c_str());
        return false;
    }
    if (dynsym_sh->sh_entsize != sizeof(Elf64_Sym) || dynsym_sh->sh_size < sizeof(Elf64_Sym)) {
        LOGE("[route_symbol_takeover] invalid dynsym layout: %s", vmengine_path.c_str());
        return false;
    }
    if (dynsym_sh->sh_offset > file_bytes.size() ||
        dynsym_sh->sh_size > file_bytes.size() - dynsym_sh->sh_offset ||
        dynstr_sh->sh_offset > file_bytes.size() ||
        dynstr_sh->sh_size > file_bytes.size() - dynstr_sh->sh_offset) {
        LOGE("[route_symbol_takeover] dynsym/dynstr out of range: %s", vmengine_path.c_str());
        return false;
    }

    const auto* dynsyms = reinterpret_cast<const Elf64_Sym*>(file_bytes.data() + dynsym_sh->sh_offset);
    const size_t dynsym_count = static_cast<size_t>(dynsym_sh->sh_size / sizeof(Elf64_Sym));
    const char* dynstr = reinterpret_cast<const char*>(file_bytes.data() + dynstr_sh->sh_offset);
    const size_t dynstr_size = static_cast<size_t>(dynstr_sh->sh_size);

    // slot 符号值 -> slot_id。
    std::unordered_map<uint64_t, uint32_t> slot_id_by_value;
    // slot_id -> key(fun_addr)。
    std::unordered_map<uint32_t, uint64_t> key_by_slot_id;

    // 第一遍：建立 slot 符号地址索引。
    for (size_t i = 1; i < dynsym_count; ++i) {
        const Elf64_Sym& sym = dynsyms[i];
        if (sym.st_name >= dynstr_size) {
            continue;
        }
        const char* name = dynstr + sym.st_name;
        if (name[0] == '\0') {
            continue;
        }
        uint32_t slot_id = 0;
        if (!parseTakeoverSlotId(name, &slot_id)) {
            continue;
        }
        slot_id_by_value[static_cast<uint64_t>(sym.st_value)] = slot_id;
    }

    if (slot_id_by_value.empty()) {
        LOGE("[route_symbol_takeover] no takeover slots found in dynsym: %s", vmengine_path.c_str());
        return false;
    }

    // 第二遍：收集 donor alias（st_value 指向 slot，st_size 存 key）。
    for (size_t i = 1; i < dynsym_count; ++i) {
        const Elf64_Sym& sym = dynsyms[i];
        if (sym.st_name >= dynstr_size || sym.st_shndx == SHN_UNDEF) {
            continue;
        }
        const char* name = dynstr + sym.st_name;
        if (name[0] == '\0') {
            continue;
        }
        uint32_t self_slot_id = 0;
        if (parseTakeoverSlotId(name, &self_slot_id)) {
            // 跳过 slot 符号自身。
            continue;
        }
        const auto slot_it = slot_id_by_value.find(static_cast<uint64_t>(sym.st_value));
        if (slot_it == slot_id_by_value.end()) {
            continue;
        }
        const uint32_t slot_id = slot_it->second;
        const uint64_t key = static_cast<uint64_t>(sym.st_size);
        if (key == 0) {
            continue;
        }
        auto existed = key_by_slot_id.find(slot_id);
        if (existed != key_by_slot_id.end() && existed->second != key) {
            LOGE("[route_symbol_takeover] conflicting key for slot=%u: old=0x%llx new=0x%llx",
                 slot_id,
                 static_cast<unsigned long long>(existed->second),
                 static_cast<unsigned long long>(key));
            return false;
        }
        key_by_slot_id[slot_id] = key;
    }

    // route4-only：patched vmengine 必须能恢复出至少一条 slot->key 映射。
    if (key_by_slot_id.empty()) {
        LOGE("[route_symbol_takeover] no takeover key entries found in dynsym: %s", vmengine_path.c_str());
        return false;
    }

    out_entries.reserve(key_by_slot_id.size());
    for (const auto& item : key_by_slot_id) {
        out_entries.push_back(zTakeoverSymbolEntry{item.first, item.second});
    }
    LOGI("[route_symbol_takeover] recovered slot entries from dynsym: slot_count=%llu",
         static_cast<unsigned long long>(out_entries.size()));
    return true;
}

// 统一空白裁剪工具：
// 输入保持只读，返回一个新字符串，不修改原值。
std::string trimCopy(const std::string& value) {
    // 只做前后空白裁剪，不改中间内容。
    // begin 指向首个非空白字符。
    size_t begin = 0;
    // 跳过前导空白。
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }

    // end 从末尾开始回退，定位最后一个非空白字符的后一位。
    size_t end = value.size();
    // 跳过尾随空白。
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    // 返回裁剪后的新字符串。
    return value.substr(begin, end - begin);
}

// 解析 `branch_addr_list.txt`：
// 支持两种信息：
// 1) 可选 `branch_addr_count = N;`
// 2) 必选 `branch_addr_list = {...};`
// 返回 true 表示解析成功且（若有 count）数量一致。
bool parseSharedBranchAddrListText(const std::vector<uint8_t>& text_data, std::vector<uint64_t>& out_branch_addrs) {
    // 每次解析前先清空输出，避免残留旧数据。
    out_branch_addrs.clear();
    // 输入为空直接失败。
    if (text_data.empty()) {
        return false;
    }

    // 把字节数组转换为文本，后续统一用字符串查找/切片解析。
    const std::string text(reinterpret_cast<const char*>(text_data.data()), text_data.size());

    // 兼容 "branch_addr_count = N;" 可选字段，存在时做数量一致性校验。
    // 标记是否解析到了 count 字段。
    bool has_expected_count = false;
    // 解析出的期望数量。
    uint64_t expected_count = 0;
    // 定位 count 字段名。
    size_t count_pos = text.find("branch_addr_count");
    // 找到字段才继续解析等号和分号。
    if (count_pos != std::string::npos) {
        // 定位 '='。
        size_t eq = text.find('=', count_pos);
        // 定位 ';'。
        size_t sc = text.find(';', eq);
        // 仅当边界合法时再切片。
        if (eq != std::string::npos && sc != std::string::npos && sc > eq) {
            // 取出等号与分号之间的内容并裁剪空白。
            std::string count_str = trimCopy(text.substr(eq + 1, sc - eq - 1));
            // 非空才做数字解析。
            if (!count_str.empty()) {
                // strtoull 支持十进制和 0x 前缀十六进制。
                expected_count = std::strtoull(count_str.c_str(), nullptr, 0);
                // 标记 count 生效，后面将启用一致性校验。
                has_expected_count = true;
            }
        }
    }

    // 定位 branch 列表字段名。
    size_t list_pos = text.find("branch_addr_list");
    // 未找到列表字段则失败。
    if (list_pos == std::string::npos) {
        return false;
    }
    // 定位列表左花括号。
    size_t l = text.find('{', list_pos);
    // 定位列表右花括号。
    size_t r = text.find('}', l == std::string::npos ? list_pos : l + 1);
    // 括号不完整或区间非法则失败。
    if (l == std::string::npos || r == std::string::npos || r <= l) {
        return false;
    }

    // 取出花括号内部内容。
    std::string body = text.substr(l + 1, r - l - 1);
    // 构建字符串流，按逗号分割 token。
    std::stringstream ss(body);
    // 承接每个 token。
    std::string token;
    // 按十进制/十六进制自动解析，允许逗号后带空白。
    while (std::getline(ss, token, ',')) {
        // 去除 token 前后空白。
        std::string trimmed = trimCopy(token);
        // 空 token 跳过。
        if (trimmed.empty()) {
            continue;
        }
        // 解析地址值。
        uint64_t addr = std::strtoull(trimmed.c_str(), nullptr, 0);
        // 写入输出数组。
        out_branch_addrs.push_back(addr);
    }

    // 如果存在 count 字段，则校验数量一致。
    if (has_expected_count && expected_count != out_branch_addrs.size()) {
        LOGE("parseSharedBranchAddrListText count mismatch: expected=%llu actual=%llu",
             static_cast<unsigned long long>(expected_count),
             static_cast<unsigned long long>(out_branch_addrs.size()));
        return false;
    }
    // 解析成功。
    return true;
}

// 从 assets 读取共享 branch 地址表并解析到向量。
// 失败会打印明确错误来源（读取失败 / 文本格式失败）。
bool loadSharedBranchAddrsFromAsset(JNIEnv* env, const char* asset_name, std::vector<uint64_t>& out_branch_addrs) {
    // branch_addr_list 是所有函数共享的一份索引表，先完整读取再一次性下发给 VM。
    // 承接 asset 原始文本字节。
    std::vector<uint8_t> text_data;
    // 从 assets 中读取文件。
    if (!zAssetManager::loadAssetDataByFileName(env, asset_name, text_data)) {
        LOGE("loadSharedBranchAddrsFromAsset failed to read asset: %s", asset_name);
        return false;
    }
    // 解析文本中的 branch 列表。
    if (!parseSharedBranchAddrListText(text_data, out_branch_addrs)) {
        LOGE("loadSharedBranchAddrsFromAsset failed to parse asset: %s", asset_name);
        return false;
    }
    // 成功返回。
    return true;
}

// 构造默认执行参数：
// 当前所有回归函数统一用 (2,4)，后续若需函数级参数可在此扩展。
zParams buildDefaultParams(const char* function_name) {
    // 本函数当前不区分函数名，保留参数是为了后续可按函数定制入参。
    (void)function_name;
    // 三条路线统一使用同一组参数，验证编码链路一致性。
    return zParams(std::vector<uint64_t>{2, 4});
}

// 生成字符串用例期望值：
// 与 demo::fun_cpp_make_string 的语义保持一致：A{a}:{b}。
std::string buildExpectedStringCaseResult(const zParams& params) {
    // 与 demo 中 fun_cpp_make_string 的语义保持一致：A{a}:{b}
    // 读取第一个参数，不存在则按 0。
    const int a = (params.values.size() > 0) ? static_cast<int>(params.values[0]) : 0;
    // 读取第二个参数，不存在则按 0。
    const int b = (params.values.size() > 1) ? static_cast<int>(params.values[1]) : 0;
    // 拼接期望字符串。
    return std::string("A") + std::to_string(a) + ":" + std::to_string(b);
}

} // namespace

// 准备单条路线所需的 so：
// 1) 从 assets 解包到文件系统；
// 2) 交给自定义 linker 加载。
bool prepareRouteLibrary(JNIEnv* env, zVmEngine& engine, const char* asset_so_name, std::string& out_path) {
    // 每条路线都从 asset 解包出独立 so，再交给自定义 linker 装载。
    // 先把 so 从 assets 解压到应用可访问路径。
    if (!zAssetManager::extractAssetToFile(env, asset_so_name, out_path)) {
        LOGE("extract asset failed: %s", asset_so_name);
        return false;
    }
    // 再交给 VM 的自定义 linker 进行加载和重定位。
    if (!engine.LoadLibrary(out_path.c_str())) {
        LOGE("custom linker load failed: %s", out_path.c_str());
        return false;
    }
    // 准备成功。
    return true;
}

// 执行 uint64 返回值用例：
// - 输入：函数地址 + 路线标记 + so 名称；
// - 输出：可选回写到 out_result；
// - 判定：仅保证调用成功，结果正确性由外层比对。
bool executeCase(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const char* function_name,
    uint64_t fun_addr,
    uint64_t* out_result
) {
    // 函数地址必须有效。
    if (fun_addr == 0) {
        LOGE("[%s][%s] invalid fun_addr=0", route_tag, function_name);
        return false;
    }
    // so 名称必须有效。
    if (so_name == nullptr || so_name[0] == '\0') {
        LOGE("[%s][%s] invalid so_name", route_tag, function_name);
        return false;
    }

    // 构造统一入参。
    zParams params = buildDefaultParams(function_name);
    // 默认结果缓冲。
    uint64_t result = 0;
    // execute 返回主返回寄存器值；同时 retBuffer 允许 VM 在需要时写回对象/聚合返回。
    result = engine.execute(&result, so_name, fun_addr, params);
    // 记录执行日志。
    LOGI("[%s][%s] execute by fun_addr=0x%llx result=%llu",
         route_tag,
         function_name,
         static_cast<unsigned long long>(fun_addr),
         static_cast<unsigned long long>(result));
    // 如果调用方提供输出指针，则回传结果。
    if (out_result != nullptr) {
        *out_result = result;
    }
    // 执行成功。
    return true;
}

// 执行字符串返回值用例（sret 路径）：
// - 通过 placement-new 提供对象存储；
// - execute 后读取对象值并显式析构；
// - 与期望字符串比对。
bool executeStringCase(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const char* function_name,
    uint64_t fun_addr
) {
    // 字符串用例也先做基础参数校验。
    if (fun_addr == 0) {
        LOGE("[%s][%s] invalid fun_addr=0", route_tag, function_name);
        return false;
    }
    // so 名称必须非空。
    if (so_name == nullptr || so_name[0] == '\0') {
        LOGE("[%s][%s] invalid so_name", route_tag, function_name);
        return false;
    }

    // 构造统一入参。
    zParams params = buildDefaultParams(function_name);
    // 为 std::string 预留一块对齐后的栈内存，避免额外堆分配。
    using StringStorage = typename std::aligned_storage<sizeof(std::string), alignof(std::string)>::type;
    // 原位存储区清零初始化。
    StringStorage storage{};
    // 先原位构造一份对象，VM 可直接把返回对象写入该地址，随后统一走显式析构。
    std::string* out = new (&storage) std::string();
    // 记录输出对象地址，方便日志排查。
    const uint64_t out_ptr = reinterpret_cast<uint64_t>(out);
    // 执行函数：ret 为寄存器返回值，out 承接对象内容。
    const uint64_t ret = engine.execute(out, so_name, fun_addr, params);
    // 基于入参构造期望字符串。
    const std::string expected = buildExpectedStringCaseResult(params);

    // 拷贝出实际字符串值，随后手动析构 placement-new 对象。
    const std::string actual = *out;
    // 手动析构，匹配上面的 placement new。
    out->~basic_string();
    // 打印详细日志，包含 ret/out 指针和值。
    LOGI("[%s][%s] execute by fun_addr=0x%llx ret_ptr=0x%llx out_ptr=0x%llx value=%s",
         route_tag,
         function_name,
         static_cast<unsigned long long>(fun_addr),
         static_cast<unsigned long long>(ret),
         static_cast<unsigned long long>(out_ptr),
         actual.c_str());

    // 结果不一致即判失败。
    if (actual != expected) {
        LOGE("[%s][%s] string mismatch: actual=%s expected=%s",
             route_tag,
             function_name,
             actual.c_str(),
             expected.c_str());
        return false;
    }
    // 字符串回归成功。
    return true;
}

bool resolveCurrentLibraryPath(void* symbol, std::string& out_path) {
    out_path.clear();
    if (symbol == nullptr) {
        return false;
    }

    Dl_info info{};
    if (dladdr(symbol, &info) == 0 || info.dli_fname == nullptr || info.dli_fname[0] == '\0') {
        return false;
    }
    out_path = info.dli_fname;
    return true;
}

bool writeBytesToFile(const std::string& path, const std::vector<uint8_t>& data) {
    if (path.empty()) {
        return false;
    }

    int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        LOGE("writeBytesToFile open failed: %s errno=%d", path.c_str(), errno);
        return false;
    }

    const uint8_t* ptr = data.empty() ? nullptr : data.data();
    size_t remain = data.size();
    while (remain > 0) {
        ssize_t wrote = write(fd, ptr, remain);
        if (wrote <= 0) {
            LOGE("writeBytesToFile write failed: %s errno=%d", path.c_str(), errno);
            close(fd);
            return false;
        }
        ptr += wrote;
        remain -= static_cast<size_t>(wrote);
    }

    close(fd);
    return true;
}

// route4-only 仍需要函数名 -> 地址映射（供 takeover 初始化），
// 但不再执行 route1。这里仅读取 txt 头并提取 functionAddress。
bool buildReferenceCasesFromAssets(JNIEnv* env, std::vector<FunctionCaseResult>& out_cases) {
    // 每次重建前先清空输出，避免复用旧数据造成错配。
    out_cases.clear();
    // 逐个普通数值函数构建 reference 条目。
    for (const FunctionCaseConfig& config : kFunctionCases) {
        // 承接单个 txt 资产内容。
        std::vector<uint8_t> text_data;
        // 从 assets 加载当前函数 txt。
        if (!zAssetManager::loadAssetDataByFileName(env, config.txt_asset, text_data)) {
            LOGE("[route4_reference] loadAssetDataByFileName failed: %s", config.txt_asset);
            return false;
        }
        // 创建临时 zFunction，仅用于解析地址，不进入 VM 缓存。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 解析未编码文本格式，提取函数结构信息。
        if (!function->loadUnencodedText(reinterpret_cast<const char*>(text_data.data()), text_data.size())) {
            LOGE("[route4_reference] loadUnencodedText failed: %s", config.txt_asset);
            return false;
        }
        // 从解析结果读取函数地址（相对 so 的 fun_addr）。
        const uint64_t fun_addr = function->functionAddress();
        // 地址为 0 说明资产内容无效或解析异常。
        if (fun_addr == 0) {
            LOGE("[route4_reference] invalid fun_addr=0 for %s", config.function_name);
            return false;
        }
        // 承接该函数固定输入下的期望返回值。
        uint64_t expected_result = 0;
        // 通过函数名在常量表中查期望值。
        if (!findExpectedResultByFunctionName(config.function_name, expected_result)) {
            LOGE("[route4_reference] expected result missing for %s", config.function_name);
            return false;
        }
        // 写入 reference：函数名 + 地址 + 期望值。
        out_cases.push_back(FunctionCaseResult{std::string(config.function_name), fun_addr, expected_result});
    }

    // 字符串函数单独处理：takeover 初始化需要它的地址，但不使用 expected_result 数值比较。
    std::vector<uint8_t> string_case_txt_data;
    // 加载字符串用例 txt 资产。
    if (!zAssetManager::loadAssetDataByFileName(env, kStringCaseTxtAsset, string_case_txt_data)) {
        LOGE("[route4_reference] loadAssetDataByFileName failed: %s", kStringCaseTxtAsset);
        return false;
    }
    // 创建字符串函数解析对象。
    std::unique_ptr<zFunction> string_case_function = std::make_unique<zFunction>();
    // 解析字符串函数文本，提取 fun_addr。
    if (!string_case_function->loadUnencodedText(reinterpret_cast<const char*>(string_case_txt_data.data()),
                                                 string_case_txt_data.size())) {
        LOGE("[route4_reference] loadUnencodedText failed: %s", kStringCaseTxtAsset);
        return false;
    }
    // 提取字符串函数地址。
    const uint64_t string_case_fun_addr = string_case_function->functionAddress();
    // 地址非法则终止，避免后续 takeover 绑定空地址。
    if (string_case_fun_addr == 0) {
        LOGE("[route4_reference] invalid fun_addr=0 for %s", kStringCaseFunctionName);
        return false;
    }
    // expected_result 对字符串路径无语义，固定为 0 作为占位。
    out_cases.push_back(FunctionCaseResult{std::string(kStringCaseFunctionName), string_case_fun_addr, 0});
    // 所有 reference 均准备完成。
    return true;
}

// 直接执行 so 内原生函数，并与 VM 基准结果做差分校验。
bool test_nativeVsVm(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    // env 当前不直接使用，保留参数与其它路线签名一致。
    (void)env;
    if (reference_cases.empty()) {
        LOGE("[route_native_vs_vm] reference_cases is empty");
        return false;
    }

    soinfo* so_info = engine.GetSoinfo(kAssetBaseSo);
    if (so_info == nullptr || so_info->base == 0) {
        LOGE("[route_native_vs_vm] soinfo unavailable for %s", kAssetBaseSo);
        return false;
    }

    std::unordered_map<std::string, FunctionCaseResult> case_map;
    for (const FunctionCaseResult& item : reference_cases) {
        case_map[item.function_name] = item;
    }

    using NativeBinaryFn = uint64_t (*)(uint64_t, uint64_t);
    const std::unordered_set<std::string> stateful_cases = {
        "fun_global_data_mix",
        "fun_static_local_table",
        "fun_global_struct_acc",
        "fun_class_static_member",
        "fun_global_table_rw",
        "fun_global_mutable_state",
    };
    for (const FunctionCaseConfig& config : kFunctionCases) {
        const std::string case_name = config.function_name == nullptr ? std::string() : std::string(config.function_name);
        if (stateful_cases.find(case_name) != stateful_cases.end()) {
            LOGI("[route_native_vs_vm][%s] skip stateful case", case_name.c_str());
            continue;
        }
        auto it = case_map.find(case_name);
        if (it == case_map.end()) {
            LOGE("[route_native_vs_vm] missing reference case: %s", case_name.c_str());
            return false;
        }

        const zParams params = buildDefaultParams(case_name.c_str());
        const uint64_t arg0 = (params.values.size() > 0) ? params.values[0] : 0;
        const uint64_t arg1 = (params.values.size() > 1) ? params.values[1] : 0;
        const uintptr_t fn_addr = static_cast<uintptr_t>(so_info->base + it->second.fun_addr);
        NativeBinaryFn native_fn = reinterpret_cast<NativeBinaryFn>(fn_addr);

        const uint64_t native_result = native_fn(arg0, arg1);
        LOGI("[route_native_vs_vm][%s] native= %llu vm_baseline=%llu fun_addr=0x%llx",
             case_name.c_str(),
             static_cast<unsigned long long>(native_result),
             static_cast<unsigned long long>(it->second.expected_result),
             static_cast<unsigned long long>(it->second.fun_addr));
        if (native_result != it->second.expected_result) {
            LOGE("[route_native_vs_vm][%s] mismatch native=%llu vm=%llu",
                 case_name.c_str(),
                 static_cast<unsigned long long>(native_result),
                 static_cast<unsigned long long>(it->second.expected_result));
            return false;
        }
    }

    auto string_case_it = case_map.find(kStringCaseFunctionName);
    if (string_case_it == case_map.end()) {
        LOGE("[route_native_vs_vm] missing reference case: %s", kStringCaseFunctionName);
        return false;
    }
    using NativeStringFn = std::string (*)(int, int);
    const zParams string_params = buildDefaultParams(kStringCaseFunctionName);
    const int a = (string_params.values.size() > 0) ? static_cast<int>(string_params.values[0]) : 0;
    const int b = (string_params.values.size() > 1) ? static_cast<int>(string_params.values[1]) : 0;
    const uintptr_t string_fn_addr = static_cast<uintptr_t>(so_info->base + string_case_it->second.fun_addr);
    NativeStringFn native_string_fn = reinterpret_cast<NativeStringFn>(string_fn_addr);
    const std::string native_string = native_string_fn(a, b);
    const std::string expected_string = buildExpectedStringCaseResult(string_params);

    LOGI("[route_native_vs_vm][%s] native=%s expected=%s fun_addr=0x%llx",
         kStringCaseFunctionName,
         native_string.c_str(),
         expected_string.c_str(),
         static_cast<unsigned long long>(string_case_it->second.fun_addr));
    if (native_string != expected_string) {
        LOGE("[route_native_vs_vm][%s] mismatch native=%s expected=%s",
             kStringCaseFunctionName,
             native_string.c_str(),
             expected_string.c_str());
        return false;
    }
    return true;
}

// 路线1：加载未编码文本（fun_xxx.txt）并执行。
// 该路线产出 reference_cases，作为其它路线的对齐基准。
bool test_loadUnencodedText(JNIEnv* env, zVmEngine& engine, std::vector<FunctionCaseResult>& out_cases) {
    // 每轮先清空输出基准列表。
    out_cases.clear();
    // 路线1：文本反汇编结果直接进 VM，作为后续两条编码路线的基准。
    if (!prepareRouteLibrary(env, engine, kAssetBaseSo, g_libdemo_so_path)) {
        LOGE("[route_unencoded_text] prepareRouteLibrary failed");
        return false;
    }

    // 读取共享 branch 地址表。
    std::vector<uint64_t> shared_branch_addrs;
    if (!loadSharedBranchAddrsFromAsset(env, kAssetBranchAddrList, shared_branch_addrs)) {
        LOGE("[route_unencoded_text] loadSharedBranchAddrsFromAsset failed: %s", kAssetBranchAddrList);
        return false;
    }
    // 基准路线按 libdemo.so 维度注册共享 branch 地址。
    engine.setSharedBranchAddrs(kAssetBaseSo, std::move(shared_branch_addrs));

    // 遍历所有 uint64 返回值用例。
    for (const FunctionCaseConfig& config : kFunctionCases) {
        // 承接文本资产数据。
        std::vector<uint8_t> text_data;
        // 读取单函数文本文件。
        if (!zAssetManager::loadAssetDataByFileName(env, config.txt_asset, text_data)) {
            LOGE("[route_unencoded_text] loadAssetDataByFileName failed: %s", config.txt_asset);
            return false;
        }

        // 创建函数对象。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 按文本格式解析函数。
        if (!function->loadUnencodedText(reinterpret_cast<const char*>(text_data.data()), text_data.size())) {
            LOGE("[route_unencoded_text] loadUnencodedText failed: %s", config.txt_asset);
            return false;
        }

        // 解析得到函数地址。
        const uint64_t fun_addr = function->functionAddress();
        // 地址无效则失败。
        if (fun_addr == 0) {
            LOGE("[route_unencoded_text] invalid fun_addr=0 for %s", config.function_name);
            return false;
        }

        // 缓存到 VM，供 execute 按地址调度。
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_unencoded_text] cacheFunction failed: %s fun_addr=0x%llx",
                 config.function_name,
                 static_cast<unsigned long long>(fun_addr));
            return false;
        }

        // 初始化基准结果项。
        FunctionCaseResult result_case;
        // 填入函数名。
        result_case.function_name = config.function_name;
        // 填入函数地址。
        result_case.fun_addr = fun_addr;
        // 记录基准输出，后两条路线按同 fun_addr + 同入参做逐项对比。
        if (!executeCase(
                engine,
                kAssetBaseSo,
                "route_unencoded_text",
                config.function_name,
                fun_addr,
                &result_case.expected_result)) {
            return false;
        }

        // 保留关键入口固定预期值校验，避免“跨路线一致但全错”的情况。
        // 当前用 fun_for_add 作为固定值守门用例。
        if (result_case.function_name == "fun_for_add" && result_case.expected_result != kExpectedResult) {
            LOGE("[route_unencoded_text][%s] unexpected result=%llu expected=%llu",
                 config.function_name,
                 static_cast<unsigned long long>(result_case.expected_result),
                 static_cast<unsigned long long>(kExpectedResult));
            return false;
        }
        // 保存基准结果，供后续两条路线比对。
        out_cases.push_back(result_case);
    }

    // 下面单独处理 string 返回值用例（不走 uint64 比对）。
    std::vector<uint8_t> string_case_txt_data;
    // 读取字符串文本资产。
    if (!zAssetManager::loadAssetDataByFileName(env, kStringCaseTxtAsset, string_case_txt_data)) {
        LOGE("[route_unencoded_text] loadAssetDataByFileName failed: %s", kStringCaseTxtAsset);
        return false;
    }
    // 创建字符串函数对象。
    std::unique_ptr<zFunction> string_case_function = std::make_unique<zFunction>();
    // 解析字符串函数文本。
    if (!string_case_function->loadUnencodedText(reinterpret_cast<const char*>(string_case_txt_data.data()),
                                                 string_case_txt_data.size())) {
        LOGE("[route_unencoded_text] loadUnencodedText failed: %s", kStringCaseTxtAsset);
        return false;
    }
    // 读取字符串函数地址。
    const uint64_t string_case_fun_addr = string_case_function->functionAddress();
    // 地址非法则失败。
    if (string_case_fun_addr == 0) {
        LOGE("[route_unencoded_text] invalid fun_addr=0 for %s", kStringCaseFunctionName);
        return false;
    }
    // 缓存字符串函数到 VM。
    if (!engine.cacheFunction(std::move(string_case_function))) {
        LOGE("[route_unencoded_text] cacheFunction failed: %s fun_addr=0x%llx",
             kStringCaseFunctionName,
             static_cast<unsigned long long>(string_case_fun_addr));
        return false;
    }
    // 执行并校验字符串内容。
    if (!executeStringCase(
            engine,
            kAssetBaseSo,
            "route_unencoded_text",
            kStringCaseFunctionName,
            string_case_fun_addr)) {
        return false;
    }
    // string 用例不做 uint64 比对，仅保留地址用于后续两条路线复测。
    out_cases.push_back(FunctionCaseResult{std::string(kStringCaseFunctionName), string_case_fun_addr, 0});
    // 路线1成功。
    return true;
}

// 路线2：加载 assets 中的编码 bin（fun_xxx.bin）并执行。
// 以路线1的 `fun_addr + expected_result` 做逐项对齐校验。
bool test_loadEncodedAssetBin(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    // 必须先有基准结果，编码路线才能做对齐比对。
    if (reference_cases.empty()) {
        LOGE("[route_encoded_asset_bin] reference_cases is empty");
        return false;
    }

    // 按函数名回填基准数据，确保每个编码用例都能对齐到同一 fun_addr。
    std::unordered_map<std::string, FunctionCaseResult> case_map;
    // 构建 name -> baseline 的快速索引。
    for (const FunctionCaseResult& item : reference_cases) {
        case_map[item.function_name] = item;
    }

    // 准备 base so。
    if (!prepareRouteLibrary(env, engine, kAssetBaseSo, g_libdemo_so_path)) {
        LOGE("[route_encoded_asset_bin] prepareRouteLibrary failed");
        return false;
    }

    // 读取共享 branch 表。
    std::vector<uint64_t> shared_branch_addrs;
    if (!loadSharedBranchAddrsFromAsset(env, kAssetBranchAddrList, shared_branch_addrs)) {
        LOGE("[route_encoded_asset_bin] loadSharedBranchAddrsFromAsset failed: %s", kAssetBranchAddrList);
        return false;
    }
    // 编码 bin 仍复用 libdemo.so 的共享 branch 表。
    engine.setSharedBranchAddrs(kAssetBaseSo, std::move(shared_branch_addrs));

    // 遍历所有 uint64 返回值用例，读取 bin 并执行回归。
    for (const FunctionCaseConfig& config : kFunctionCases) {
        // 查找对应基准项。
        auto it = case_map.find(config.function_name);
        // 缺失基准直接失败，避免“盲跑”。
        if (it == case_map.end()) {
            LOGE("[route_encoded_asset_bin] missing reference case: %s", config.function_name);
            return false;
        }

        // 承接编码数据。
        std::vector<uint8_t> encoded_data;
        // 读取单函数 bin。
        if (!zAssetManager::loadAssetDataByFileName(env, config.bin_asset, encoded_data)) {
            LOGE("[route_encoded_asset_bin] loadAssetDataByFileName failed: %s", config.bin_asset);
            return false;
        }

        // 创建函数对象。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 加载编码格式。
        if (!function->loadEncodedData(encoded_data.data(), encoded_data.size())) {
            LOGE("[route_encoded_asset_bin] loadEncodedData failed: %s", config.bin_asset);
            return false;
        }

        // 统一按未编码路线 fun_addr 做回归。
        function->setFunctionAddress(it->second.fun_addr);
        // 缓存到 VM。
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[route_encoded_asset_bin] cacheFunction failed: %s fun_addr=0x%llx",
                 config.function_name,
                 static_cast<unsigned long long>(it->second.fun_addr));
            return false;
        }

        // 执行并获取结果。
        uint64_t result = 0;
        if (!executeCase(
                engine,
                kAssetBaseSo,
                "route_encoded_asset_bin",
                config.function_name,
                it->second.fun_addr,
                &result)) {
            return false;
        }
        // 与基准结果逐项比对。
        if (result != it->second.expected_result) {
            LOGE("[route_encoded_asset_bin][%s] unexpected result=%llu expected=%llu",
                 config.function_name,
                 static_cast<unsigned long long>(result),
                 static_cast<unsigned long long>(it->second.expected_result));
            return false;
        }
    }

    // 单独回归 string 返回值用例。
    auto string_case_it = case_map.find(kStringCaseFunctionName);
    // 缺基准则失败。
    if (string_case_it == case_map.end()) {
        LOGE("[route_encoded_asset_bin] missing reference case: %s", kStringCaseFunctionName);
        return false;
    }
    // 承接字符串函数编码数据。
    std::vector<uint8_t> string_case_bin_data;
    // 读取字符串函数 bin。
    if (!zAssetManager::loadAssetDataByFileName(env, kStringCaseBinAsset, string_case_bin_data)) {
        LOGE("[route_encoded_asset_bin] loadAssetDataByFileName failed: %s", kStringCaseBinAsset);
        return false;
    }
    // 创建字符串函数对象。
    std::unique_ptr<zFunction> string_case_function = std::make_unique<zFunction>();
    // 解析字符串函数编码数据。
    if (!string_case_function->loadEncodedData(string_case_bin_data.data(), string_case_bin_data.size())) {
        LOGE("[route_encoded_asset_bin] loadEncodedData failed: %s", kStringCaseBinAsset);
        return false;
    }
    // 绑定基准地址，确保三路线地址一致。
    string_case_function->setFunctionAddress(string_case_it->second.fun_addr);
    // 写入 VM 缓存。
    if (!engine.cacheFunction(std::move(string_case_function))) {
        LOGE("[route_encoded_asset_bin] cacheFunction failed: %s fun_addr=0x%llx",
             kStringCaseFunctionName,
             static_cast<unsigned long long>(string_case_it->second.fun_addr));
        return false;
    }
    // 执行字符串比对。
    if (!executeStringCase(
            engine,
            kAssetBaseSo,
            "route_encoded_asset_bin",
            kStringCaseFunctionName,
            string_case_it->second.fun_addr)) {
        return false;
    }
    // 路线2成功。
    return true;
}

bool runExpandedSoRoute(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const std::string& expand_so_path,
    const std::vector<FunctionCaseResult>& reference_cases
) {
    // 承接容器解出的函数条目。
    std::vector<zSoBinEntry> entries;
    // 承接容器中的共享 branch 列表。
    std::vector<uint64_t> shared_branch_addrs;
    // 从 expanded so 尾部容器解包：拿到每个函数编码体 + 共享 branch 表。
    if (!zSoBinBundleReader::readFromExpandedSo(expand_so_path, entries, shared_branch_addrs)) {
        LOGE("[%s] readFromExpandedSo failed: %s", route_tag, expand_so_path.c_str());
        return false;
    }
    // 容器内无函数 payload 直接视为无效产物。
    if (entries.empty()) {
        LOGE("[%s] readFromExpandedSo returned empty payload list", route_tag);
        return false;
    }
    // 该路线使用当前 so_name 维度保存共享 branch 表。
    // 注意：不同 so_name 维度隔离缓存，避免相互污染。
    engine.setSharedBranchAddrs(so_name, std::move(shared_branch_addrs));

    // 记录已成功加载的 fun_addr，便于后续完整性校验。
    std::unordered_map<uint64_t, std::string> loaded_fun_map;
    // 逐条把编码函数载入 VM 缓存。
    for (const zSoBinEntry& entry : entries) {
        // 为当前 entry 创建 zFunction 对象。
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        // 反序列化编码函数体。
        if (!function->loadEncodedData(entry.encoded_data.data(), entry.encoded_data.size())) {
            LOGE("[%s] loadEncodedData failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        // 绑定容器提供的 fun_addr。
        function->setFunctionAddress(entry.fun_addr);
        // 写入 VM 缓存供 execute 路径调度。
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[%s] cacheFunction failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        // 标记该地址已加载，后面会检查 reference 覆盖完整性。
        loaded_fun_map[entry.fun_addr] = "loaded";
    }

    // 按 reference 列表逐项执行数值函数并比对结果。
    for (const FunctionCaseResult& item : reference_cases) {
        // 字符串用例单独处理，这里先跳过。
        if (item.function_name == kStringCaseFunctionName) {
            continue;
        }
        // 若 reference 中某函数未出现在容器中，直接判失败。
        if (loaded_fun_map.find(item.fun_addr) == loaded_fun_map.end()) {
            LOGE("[%s] missing function in expanded so: %s fun_addr=0x%llx",
                 route_tag,
                 item.function_name.c_str(),
                 static_cast<unsigned long long>(item.fun_addr));
            return false;
        }

        // 执行函数并回收返回值。
        uint64_t result = 0;
        if (!executeCase(
                engine,
                so_name,
                route_tag,
                item.function_name.c_str(),
                item.fun_addr,
                &result)) {
            return false;
        }
        // 与 reference 期望值比对，确保语义一致。
        if (result != item.expected_result) {
            LOGE("[%s][%s] unexpected result=%llu expected=%llu",
                 route_tag,
                 item.function_name.c_str(),
                 static_cast<unsigned long long>(result),
                 static_cast<unsigned long long>(item.expected_result));
            return false;
        }
    }

    // 查找字符串用例地址。
    uint64_t string_case_fun_addr = 0;
    for (const FunctionCaseResult& item : reference_cases) {
        if (item.function_name == kStringCaseFunctionName) {
            string_case_fun_addr = item.fun_addr;
            break;
        }
    }
    // reference 缺字符串用例时，说明基线构建不完整。
    if (string_case_fun_addr == 0) {
        LOGE("[%s] missing reference case: %s", route_tag, kStringCaseFunctionName);
        return false;
    }
    // 容器必须包含字符串函数地址。
    if (loaded_fun_map.find(string_case_fun_addr) == loaded_fun_map.end()) {
        LOGE("[%s] missing function in expanded so: %s fun_addr=0x%llx",
             route_tag,
             kStringCaseFunctionName,
             static_cast<unsigned long long>(string_case_fun_addr));
        return false;
    }
    // 执行字符串路径（对象返回）并校验内容。
    if (!executeStringCase(
            engine,
            so_name,
            route_tag,
            kStringCaseFunctionName,
            string_case_fun_addr)) {
        return false;
    }
    // 当前容器路线完整通过。
    return true;
}

bool preloadExpandedSoBundle(
    zVmEngine& engine,
    const char* so_name,
    const char* route_tag,
    const std::string& expand_so_path
) {
    // 该函数仅负责“容器解包 + VM 缓存预热”，不执行 reference 对照。
    std::vector<zSoBinEntry> entries;
    std::vector<uint64_t> shared_branch_addrs;
    if (!zSoBinBundleReader::readFromExpandedSo(expand_so_path, entries, shared_branch_addrs)) {
        LOGE("[%s] preload readFromExpandedSo failed: %s", route_tag, expand_so_path.c_str());
        return false;
    }
    if (entries.empty()) {
        LOGE("[%s] preload failed: empty payload list", route_tag);
        return false;
    }

    // 注册该 so 对应的共享 branch 表，供 executeState 计算真实分支地址。
    engine.setSharedBranchAddrs(so_name, std::move(shared_branch_addrs));

    // 逐条把编码函数写入 VM 缓存，key=fun_addr。
    for (const zSoBinEntry& entry : entries) {
        std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
        if (!function->loadEncodedData(entry.encoded_data.data(), entry.encoded_data.size())) {
            LOGE("[%s] preload loadEncodedData failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
        function->setFunctionAddress(entry.fun_addr);
        if (!engine.cacheFunction(std::move(function))) {
            LOGE("[%s] preload cacheFunction failed: fun_addr=0x%llx",
                 route_tag,
                 static_cast<unsigned long long>(entry.fun_addr));
            return false;
        }
    }
    LOGI("[%s] preload success: cached_entries=%llu",
         route_tag,
         static_cast<unsigned long long>(entries.size()));
    return true;
}

// 路线3：从 `libdemo_expand.so` 尾部容器读取编码数据并执行。
// 同样以路线1基准做逐项对齐，覆盖“容器读取 + 执行”整条链路。
bool test_loadEncodedExpandedSo(JNIEnv* env, zVmEngine& engine, const std::vector<FunctionCaseResult>& reference_cases) {
    if (reference_cases.empty()) {
        LOGE("[route_encoded_expand_so] reference_cases is empty");
        return false;
    }
    if (!prepareRouteLibrary(env, engine, kAssetExpandSo, g_libdemo_expand_so_path)) {
        LOGE("[route_encoded_expand_so] prepareRouteLibrary failed");
        return false;
    }
    return runExpandedSoRoute(
        engine,
        kAssetExpandSo,
        "route_encoded_expand_so",
        g_libdemo_expand_so_path,
        reference_cases
    );
}

// 路线4（L1）：从当前 `libvmengine.so` 末尾读取内嵌的 `libdemo_expand.so`，落盘后执行。
EmbeddedExpandRouteStatus test_loadEmbeddedExpandedSo(
    JNIEnv* env,
    zVmEngine& engine
) {

    // 定位当前 libvmengine.so 实际路径（运行时加载路径）。
    std::string vmengine_path;
    if (!resolveCurrentLibraryPath(reinterpret_cast<void*>(&test_loadEmbeddedExpandedSo), vmengine_path)) {
        LOGE("[route_embedded_expand_so] resolveCurrentLibraryPath failed");
        return EmbeddedExpandRouteStatus::kFail;
    }

    // 承接从宿主 so 尾部读取到的内嵌 payload。
    std::vector<uint8_t> embedded_payload;
    // 读取状态：用于区分 not found / invalid / ok。
    zEmbeddedPayloadReadStatus read_status = zEmbeddedPayloadReadStatus::kInvalid;
    // 从 vmengine.so 尾部读取 route4 payload。
    if (!zEmbeddedPayload::readEmbeddedPayloadFromHostSo(vmengine_path, embedded_payload, &read_status)) {
        LOGE("[route_embedded_expand_so] readEmbeddedPayloadFromHostSo failed: %s", vmengine_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    // route4-only：未找到 payload 直接失败，不再保留 skip 兼容态。
    if (read_status == zEmbeddedPayloadReadStatus::kNotFound) {
        LOGE("[route_embedded_expand_so] embedded payload not found in %s", vmengine_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    // 读到了 footer 但 payload 为空同样算失败。
    if (embedded_payload.empty()) {
        LOGE("[route_embedded_expand_so] embedded payload is empty");
        return EmbeddedExpandRouteStatus::kFail;
    }

    // 获取应用 files 目录，用于落盘临时 so。
    std::string files_dir;
    if (!zAssetManager::getCurrentFilesDirPath(env, files_dir)) {
        LOGE("[route_embedded_expand_so] getCurrentFilesDirPath failed");
        return EmbeddedExpandRouteStatus::kFail;
    }
    // 规范化目录分隔符，确保后续拼接路径正确。
    if (!files_dir.empty() && files_dir.back() != '/') {
        files_dir.push_back('/');
    }
    // 形成落盘路径：<files>/libdemo_expand_embedded.so。
    g_libdemo_expand_embedded_so_path = files_dir + kEmbeddedExpandSoName;

    // 把内嵌 payload 写成独立 so 文件。
    if (!writeBytesToFile(g_libdemo_expand_embedded_so_path, embedded_payload)) {
        LOGE("[route_embedded_expand_so] write payload failed: %s", g_libdemo_expand_embedded_so_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }
    // 让 VM 自定义 linker 装载新落盘的 so。
    if (!engine.LoadLibrary(g_libdemo_expand_embedded_so_path.c_str())) {
        LOGE("[route_embedded_expand_so] custom linker load failed: %s", g_libdemo_expand_embedded_so_path.c_str());
        return EmbeddedExpandRouteStatus::kFail;
    }

    // route4-only 核心路径只做容器预热，不再执行 reference 对照检查。
    if (!preloadExpandedSoBundle(
            engine,
            kEmbeddedExpandSoName,
            "route_embedded_expand_so",
            g_libdemo_expand_embedded_so_path)) {
        return EmbeddedExpandRouteStatus::kFail;
    }
    // route4 L1 全流程成功。
    return EmbeddedExpandRouteStatus::kPass;
}

bool initSymbolTakeover(
    const std::string& vmengine_path
) {
    // 从 patched vmengine dynsym 恢复 slot_id -> key(fun_addr)。
    std::vector<zTakeoverSymbolEntry> entries;
    if (!buildTakeoverEntriesFromPatchedVmengineElf(vmengine_path, entries)) {
        return false;
    }

    // 提交初始化：发布符号映射并绑定主执行 so。
    return zSymbolTakeoverInit(kEmbeddedExpandSoName, entries.data(), entries.size());
}

bool acquireCurrentJniEnv(JavaVM** out_vm, JNIEnv** out_env, bool* out_attached) {
    // 调用方必须传入输出指针。
    if (out_vm == nullptr || out_env == nullptr || out_attached == nullptr) {
        return false;
    }
    *out_vm = nullptr;
    *out_env = nullptr;
    *out_attached = false;

    // 运行时解析 JNI_GetCreatedJavaVMs，避免对该符号的静态链接依赖。
    using GetCreatedJavaVMsFn = jint (*)(JavaVM**, jsize, jsize*);
    GetCreatedJavaVMsFn get_created_java_vms = reinterpret_cast<GetCreatedJavaVMsFn>(
        dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    if (get_created_java_vms == nullptr) {
        const char* candidates[] = {"libart.so", "libnativehelper.so"};
        for (const char* soname : candidates) {
            void* handle = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
            if (handle == nullptr) {
                continue;
            }
            get_created_java_vms = reinterpret_cast<GetCreatedJavaVMsFn>(
                dlsym(handle, "JNI_GetCreatedJavaVMs"));
            if (get_created_java_vms != nullptr) {
                break;
            }
        }
    }
    if (get_created_java_vms == nullptr) {
        LOGE("vm_init failed: JNI_GetCreatedJavaVMs symbol not found");
        return false;
    }

    // 枚举当前进程已创建的 JavaVM。
    JavaVM* vms[1] = {nullptr};
    jsize vm_count = 0;
    if (get_created_java_vms(vms, 1, &vm_count) != JNI_OK || vm_count <= 0 || vms[0] == nullptr) {
        LOGE("vm_init failed: JNI_GetCreatedJavaVMs returned no vm");
        return false;
    }
    JavaVM* vm = vms[0];
    JNIEnv* env = nullptr;
    const jint env_result = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (env_result == JNI_OK && env != nullptr) {
        *out_vm = vm;
        *out_env = env;
        *out_attached = false;
        return true;
    }
    // 当前线程未附着 JVM 时，主动附着后再执行初始化。
    if (env_result == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || env == nullptr) {
            LOGE("vm_init failed: AttachCurrentThread failed");
            return false;
        }
        *out_vm = vm;
        *out_env = env;
        *out_attached = true;
        return true;
    }
    LOGE("vm_init failed: GetEnv failed result=%d", static_cast<int>(env_result));
    return false;
}

bool runVmInitCore(JNIEnv* env) {
    // vm_init 走统一初始化链路，失败直接返回 false。
    if (env == nullptr) {
        LOGE("vm_init failed: env is null");
        return false;
    }

    // 获取 VM 单例。
    zVmEngine& engine = zVmEngine::getInstance();
    // 每次进程加载都从干净状态开始，避免上次缓存污染回归结果。
    // 清空函数缓存：移除上次进程内缓存的 zFunction 对象。
    engine.clearCache();
    // 清空 base so 的共享 branch 缓存：route1/2 历史缓存防御性清理。
    engine.clearSharedBranchAddrs(kAssetBaseSo);
    // 清空 expand so 的共享 branch 缓存：防止同进程重复加载旧 branch 表。
    engine.clearSharedBranchAddrs(kAssetExpandSo);
    // 清空 route4 内嵌 expand so 的共享 branch 缓存：保证本次从嵌入数据重新建立。
    engine.clearSharedBranchAddrs(kEmbeddedExpandSoName);
    // 清空符号接管状态：重置 symbol_id -> fun_addr 映射与活动 so 选择。
    zSymbolTakeoverClear();

    // 路线4（L1）：libvmengine.so 尾部内嵌 expand so（route4-only 要求必须可用）。
    // 该函数内部会执行：读取嵌入 payload -> 落盘 -> LoadLibrary -> 预热 VM 缓存。
    const EmbeddedExpandRouteStatus embedded_status = test_loadEmbeddedExpandedSo(env, engine);
    // route4-only 下只有 kPass 视为成功。
    const bool ok_embedded_expand = (embedded_status == EmbeddedExpandRouteStatus::kPass);
    // 输出 L1 结果与状态码（0 pass / 1 fail）。
    LOGI("route_embedded_expand_so result=%d state=%d",
         ok_embedded_expand ? 1 : 0,
         static_cast<int>(embedded_status));

    // 路线4（L2）：slot 跳板统一转发到 VM 执行器。
    // takeover 初始化通过 patched vmengine dynsym 恢复 slot_id->key，再按 key 执行 VM。
    std::string vmengine_path_for_takeover;
    const bool ok_vmengine_path = resolveCurrentLibraryPath(reinterpret_cast<void*>(&runVmInitCore),
                                                            vmengine_path_for_takeover);
    if (!ok_vmengine_path) {
        LOGE("vm_init route4 init failed: resolve vmengine path for takeover");
    }
    const bool ok_takeover_init = ok_embedded_expand &&
                                  ok_vmengine_path &&
                                  initSymbolTakeover(vmengine_path_for_takeover);
    // 输出 L2 对照结果。
    LOGI("route_symbol_takeover result=%d", ok_takeover_init ? 1 : 0);

    // route4 初始化任一路径失败都返回 false。
    if (!(ok_embedded_expand && ok_takeover_init)) {
        LOGE("vm_init route4 init failed: embedded_expand=%d embedded_state=%d symbol_takeover=%d takeover_init=%d",
             ok_embedded_expand ? 1 : 0,
             static_cast<int>(embedded_status),
             ok_takeover_init ? 1 : 0,
             ok_takeover_init ? 1 : 0);
        return false;
    }
    return true;
}

extern "C" __attribute__((visibility("default"))) int vm_init() {
    // 快路径：ready 直接返回。
    const int state = g_vm_init_state.load(std::memory_order_acquire);
    if (state == kVmInitStateReady) {
        return 1;
    }
    if (state == kVmInitStateFailed) {
        return 0;
    }

    // 慢路径：串行执行初始化。
    std::lock_guard<std::mutex> lock(g_vm_init_mutex);
    const int locked_state = g_vm_init_state.load(std::memory_order_acquire);
    if (locked_state == kVmInitStateReady) {
        return 1;
    }
    if (locked_state == kVmInitStateFailed) {
        return 0;
    }
    g_vm_init_state.store(kVmInitStateInitializing, std::memory_order_release);

    JavaVM* vm = nullptr;
    JNIEnv* env = nullptr;
    bool attached = false;
    if (!acquireCurrentJniEnv(&vm, &env, &attached)) {
        g_vm_init_state.store(kVmInitStateFailed, std::memory_order_release);
        return 0;
    }

    const bool ok = runVmInitCore(env);
    if (attached && vm != nullptr) {
        vm->DetachCurrentThread();
    }
    g_vm_init_state.store(ok ? kVmInitStateReady : kVmInitStateFailed, std::memory_order_release);
    return ok ? 1 : 0;
}

extern "C" __attribute__((visibility("default"))) int vm_get_init_state() {
    return g_vm_init_state.load(std::memory_order_acquire);
}

// 去掉 JNI_OnLoad 后，用构造函数在库加载阶段执行一次 vm_init。
__attribute__((constructor)) static void vm_library_ctor() {
    const int ok = vm_init();
    LOGI("vm_library_ctor vm_init=%d state=%d", ok, vm_get_init_state());
}
