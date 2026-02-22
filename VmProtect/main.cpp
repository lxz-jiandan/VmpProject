/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VmProtect CLI 主入口，负责策略解析、覆盖率看板与导出物生成。
 * - 加固链路位置：第 1 阶段（离线分析与产物构建）。
 * - 输入：原始 arm64 so + 函数清单/策略配置。
 * - 输出：函数 txt/bin、branch_addr_list.txt、libdemo_expand.so。
 */
#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <capstone/arm64.h>
#include <capstone/capstone.h>

#include "zElf.h"
#include "zFunction.h"
#include "zLog.h"
#include "zSoBinBundle.h"
#include "patchbay_tool/patchbay_entry.h"

namespace fs = std::filesystem;

namespace {

struct VmProtectPolicy {
    // 待分析/导出的原始 so。
    std::string input_so = "libdemo.so";
    // 所有导出产物输出目录。
    std::string output_dir = ".";
    // 尾部拼包后的 so 文件名。
    std::string expanded_so = "libdemo_expand.so";
    // 全函数共享 branch 表文件名。
    std::string shared_branch_file = "branch_addr_list.txt";
    // 翻译覆盖率看板文件名。
    std::string coverage_report = "coverage_report.md";
    // 目标函数清单。
    std::vector<std::string> functions;
    // 是否显式指定了函数（用于区分默认清单与外部注入）。
    bool has_explicit_functions = false;
    // 是否分析 ELF 内全部函数（而非函数白名单）。
    bool analyze_all_functions = false;
    // 是否仅出覆盖率报告，不导出 payload。
    bool coverage_only = false;
    // 需要被写回 route4 嵌入 payload 的宿主 so（通常是 libvmengine.so）。
    std::string host_so;
    // 产出的最终 so 路径。为空时默认覆盖 host_so。
    std::string final_so;
    // donor so（用于 patchbay 导出补全）。
    std::string patch_donor_so;
    // patchbay 导出统一指向的实现符号。
    std::string patch_impl_symbol = "z_takeover_dispatch_by_id";
    // 外部 patch 工具可执行文件路径（可选，不传则用内置 patchbay 子命令）。
    std::string patch_tool_exe;
    // true: donor 所有导出都补齐；false: 仅补 fun_* 与 Java_*。
    bool patch_all_exports = false;
    // patchbay 失败时是否放宽 validate。
    bool patch_allow_validate_fail = true;
};

struct CliOverrides {
    // 命令行 help 开关。
    bool show_help = false;
    // policy 文件路径（可选）。
    std::string policy_file;
    std::string input_so;
    std::string output_dir;
    std::string expanded_so;
    std::string shared_branch_file;
    std::string coverage_report;
    std::vector<std::string> functions;
    bool coverage_only_set = false;
    bool coverage_only = false;
    bool analyze_all_set = false;
    bool analyze_all = false;
    std::string host_so;
    std::string final_so;
    std::string patch_donor_so;
    std::string patch_impl_symbol;
    std::string patch_tool_exe;
    bool patch_all_exports_set = false;
    bool patch_all_exports = false;
    bool patch_allow_validate_fail_set = false;
    bool patch_allow_validate_fail = true;
};

struct FunctionCoverageRow {
    // 单函数覆盖率条目。
    std::string function_name;
    uint64_t total_instructions = 0;
    uint64_t supported_instructions = 0;
    uint64_t unsupported_instructions = 0;
    bool translate_ok = false;
    std::string translate_error;
};

struct CoverageBoard {
    // 全局覆盖率看板（汇总 + 按函数 + 指令分布）。
    uint64_t total_instructions = 0;
    uint64_t supported_instructions = 0;
    uint64_t unsupported_instructions = 0;
    std::map<std::string, uint64_t> supported_histogram;
    std::map<std::string, uint64_t> unsupported_histogram;
    std::vector<FunctionCoverageRow> function_rows;
};

const std::vector<std::string> kDefaultFunctions = {
    // 默认函数清单：保证回归包含算术、分支、对象、全局状态等典型路径。
    "fun_for",
    "fun_add",
    "fun_for_add",
    "fun_if_sub",
    "fun_countdown_muladd",
    "fun_loop_call_mix",
    "fun_call_chain",
    "fun_branch_call",
    "fun_cpp_make_string",
    "fun_cpp_string_len",
    "fun_cpp_vector_sum",
    "fun_cpp_virtual_mix",
    "fun_global_data_mix",
    "fun_static_local_table",
    "fun_global_struct_acc",
    "fun_class_static_member",
    "fun_multi_branch_path",
    "fun_switch_dispatch",
    "fun_bitmask_branch",
    "fun_global_table_rw",
    "fun_global_mutable_state",
};

std::string trimCopy(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() &&
           std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool fileExists(const std::string& path) {
    std::error_code ec;
    return !path.empty() && fs::exists(path, ec) && fs::is_regular_file(path, ec);
}

bool ensureDirectory(const std::string& path) {
    std::error_code ec;
    if (path.empty()) {
        return false;
    }
    if (fs::exists(path, ec)) {
        return fs::is_directory(path, ec);
    }
    return fs::create_directories(path, ec);
}

std::string resolvePath(const fs::path& base_dir, const std::string& value) {
    fs::path p(value);
    if (p.is_absolute()) {
        return p.lexically_normal().string();
    }
    return (base_dir / p).lexically_normal().string();
}

bool parseBoolValue(const std::string& raw, bool& out) {
    const std::string value = lowerCopy(trimCopy(raw));
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        out = true;
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        out = false;
        return true;
    }
    return false;
}

std::vector<std::string> parseFunctionList(const std::string& value) {
    std::vector<std::string> out;
    std::string token;
    for (char ch : value) {
        if (ch == ',' || std::isspace(static_cast<unsigned char>(ch)) != 0) {
            std::string trimmed = trimCopy(token);
            if (!trimmed.empty()) {
                out.push_back(trimmed);
            }
            token.clear();
            continue;
        }
        token.push_back(ch);
    }
    std::string trimmed = trimCopy(token);
    if (!trimmed.empty()) {
        out.push_back(trimmed);
    }
    return out;
}

void deduplicateKeepOrder(std::vector<std::string>& values) {
    std::unordered_set<std::string> seen;
    std::vector<std::string> dedup;
    dedup.reserve(values.size());
    for (const std::string& value : values) {
        if (seen.insert(value).second) {
            dedup.push_back(value);
        }
    }
    values.swap(dedup);
}

bool loadFunctionsFromFile(const std::string& path, std::vector<std::string>& out) {
    std::ifstream in(path);
    if (!in) {
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }
        out.push_back(trimmed);
    }
    return true;
}

bool loadPolicyFile(const std::string& policy_path, VmProtectPolicy& policy) {
    // 解析策略文件：
    // - 支持 key=value / key:value；
    // - 支持 functions 与 functions_file；
    // - 所有相对路径按 policy 文件目录解析。
    std::ifstream in(policy_path);
    if (!in) {
        LOGE("failed to open policy file: %s", policy_path.c_str());
        return false;
    }

    const fs::path base_dir = fs::path(policy_path).parent_path();
    std::string line;
    size_t line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        const size_t eq = trimmed.find('=');
        const size_t colon = trimmed.find(':');
        size_t sep = std::string::npos;
        if (eq != std::string::npos && colon != std::string::npos) {
            sep = std::min(eq, colon);
        } else if (eq != std::string::npos) {
            sep = eq;
        } else if (colon != std::string::npos) {
            sep = colon;
        }

        if (sep == std::string::npos || sep == 0 || sep + 1 >= trimmed.size()) {
            LOGE("invalid policy line %zu: %s", line_no, trimmed.c_str());
            return false;
        }

        const std::string key = lowerCopy(trimCopy(trimmed.substr(0, sep)));
        const std::string value = trimCopy(trimmed.substr(sep + 1));

        if (key == "input_so") {
            policy.input_so = resolvePath(base_dir, value);
        } else if (key == "output_dir") {
            policy.output_dir = resolvePath(base_dir, value);
        } else if (key == "expanded_so") {
            policy.expanded_so = value;
        } else if (key == "host_so") {
            policy.host_so = resolvePath(base_dir, value);
        } else if (key == "final_so") {
            policy.final_so = resolvePath(base_dir, value);
        } else if (key == "patch_donor_so") {
            policy.patch_donor_so = resolvePath(base_dir, value);
        } else if (key == "patch_impl_symbol") {
            policy.patch_impl_symbol = value;
        } else if (key == "patch_tool_exe") {
            policy.patch_tool_exe = resolvePath(base_dir, value);
        } else if (key == "shared_branch_file") {
            policy.shared_branch_file = value;
        } else if (key == "coverage_report") {
            policy.coverage_report = value;
        } else if (key == "coverage_only") {
            bool parsed = false;
            if (!parseBoolValue(value, parsed)) {
                LOGE("invalid bool for coverage_only at line %zu", line_no);
                return false;
            }
            policy.coverage_only = parsed;
        } else if (key == "analyze_all_functions") {
            bool parsed = false;
            if (!parseBoolValue(value, parsed)) {
                LOGE("invalid bool for analyze_all_functions at line %zu", line_no);
                return false;
            }
            policy.analyze_all_functions = parsed;
        } else if (key == "patch_all_exports") {
            bool parsed = false;
            if (!parseBoolValue(value, parsed)) {
                LOGE("invalid bool for patch_all_exports at line %zu", line_no);
                return false;
            }
            policy.patch_all_exports = parsed;
        } else if (key == "patch_allow_validate_fail") {
            bool parsed = false;
            if (!parseBoolValue(value, parsed)) {
                LOGE("invalid bool for patch_allow_validate_fail at line %zu", line_no);
                return false;
            }
            policy.patch_allow_validate_fail = parsed;
        } else if (key == "functions") {
            std::vector<std::string> list = parseFunctionList(value);
            policy.functions.insert(policy.functions.end(), list.begin(), list.end());
            policy.has_explicit_functions = true;
        } else if (key == "function") {
            if (!value.empty()) {
                policy.functions.push_back(value);
                policy.has_explicit_functions = true;
            }
        } else if (key == "functions_file") {
            std::vector<std::string> loaded;
            const std::string function_file = resolvePath(base_dir, value);
            if (!loadFunctionsFromFile(function_file, loaded)) {
                LOGE("failed to load functions_file: %s", function_file.c_str());
                return false;
            }
            policy.functions.insert(policy.functions.end(), loaded.begin(), loaded.end());
            policy.has_explicit_functions = true;
        } else {
            LOGE("unknown policy key at line %zu: %s", line_no, key.c_str());
            return false;
        }
    }

    deduplicateKeepOrder(policy.functions);
    return true;
}

bool parseCommandLine(int argc, char* argv[], CliOverrides& cli, std::string& error) {
    // 兼容历史调用方式：
    // 1) 新参数模式：--function xxx；
    // 2) 旧位置参数模式：直接写函数名。
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] ? argv[i] : "";
        if (arg.empty()) {
            continue;
        }
        if (arg == "-h" || arg == "--help") {
            cli.show_help = true;
            continue;
        }
        if (arg == "--policy" && i + 1 < argc) {
            cli.policy_file = argv[++i];
            continue;
        }
        if (arg == "--input-so" && i + 1 < argc) {
            cli.input_so = argv[++i];
            continue;
        }
        if (arg == "--output-dir" && i + 1 < argc) {
            cli.output_dir = argv[++i];
            continue;
        }
        if (arg == "--expanded-so" && i + 1 < argc) {
            cli.expanded_so = argv[++i];
            continue;
        }
        if (arg == "--shared-branch-file" && i + 1 < argc) {
            cli.shared_branch_file = argv[++i];
            continue;
        }
        if (arg == "--host-so" && i + 1 < argc) {
            cli.host_so = argv[++i];
            continue;
        }
        if (arg == "--final-so" && i + 1 < argc) {
            cli.final_so = argv[++i];
            continue;
        }
        if (arg == "--patch-donor-so" && i + 1 < argc) {
            cli.patch_donor_so = argv[++i];
            continue;
        }
        if (arg == "--patch-impl-symbol" && i + 1 < argc) {
            cli.patch_impl_symbol = argv[++i];
            continue;
        }
        if (arg == "--patch-tool-exe" && i + 1 < argc) {
            cli.patch_tool_exe = argv[++i];
            continue;
        }
        if (arg == "--coverage-report" && i + 1 < argc) {
            cli.coverage_report = argv[++i];
            continue;
        }
        if (arg == "--function" && i + 1 < argc) {
            cli.functions.emplace_back(argv[++i]);
            continue;
        }
        if (arg == "--patch-all-exports") {
            cli.patch_all_exports_set = true;
            cli.patch_all_exports = true;
            continue;
        }
        if (arg == "--patch-no-allow-validate-fail") {
            cli.patch_allow_validate_fail_set = true;
            cli.patch_allow_validate_fail = false;
            continue;
        }
        if (arg == "--patch-allow-validate-fail") {
            cli.patch_allow_validate_fail_set = true;
            cli.patch_allow_validate_fail = true;
            continue;
        }
        if (arg == "--coverage-only") {
            cli.coverage_only_set = true;
            cli.coverage_only = true;
            continue;
        }
        if (arg == "--analyze-all") {
            cli.analyze_all_set = true;
            cli.analyze_all = true;
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            error = "unknown option: " + arg;
            return false;
        }
        // Backward compatibility: positional args are function names.
        cli.functions.push_back(arg);
    }
    return true;
}

void printUsage() {
    std::cout
        << "Usage:\n"
        << "  VmProtect.exe [options] [function ...]\n\n"
        << "Options:\n"
        << "  --policy <file>              Load policy file\n"
        << "  --input-so <file>            Input arm64 so path\n"
        << "  --output-dir <dir>           Output directory for txt/bin/report\n"
        << "  --expanded-so <file>         Expanded so output file name\n"
        << "  --host-so <file>             Host so for embed/patch output (e.g. libvmengine.so)\n"
        << "  --final-so <file>            Final protected so path (default overwrite host-so)\n"
        << "  --patch-donor-so <file>      Donor so for patchbay export fill\n"
        << "  --patch-impl-symbol <name>   Impl symbol used by export_alias_from_patchbay\n"
        << "  --patch-tool-exe <file>      External patch tool executable path (optional)\n"
        << "  --patch-all-exports          Patch all donor exports (default: only fun_* and Java_*)\n"
        << "  --patch-no-allow-validate-fail Disable --allow-validate-fail during patch\n"
        << "  --shared-branch-file <file>  Shared branch list output file name\n"
        << "  --coverage-report <file>     Coverage report output file name\n"
        << "  --function <name>            Protected function (repeatable)\n"
        << "  --coverage-only              Only generate coverage board\n"
        << "  --analyze-all                Analyze all extracted functions\n"
        << "  -h, --help                   Show this help\n";
}

std::string resolveInputSoFallback(const std::string& configured) {
    if (fileExists(configured)) {
        return configured;
    }
    fs::path configured_path(configured);
    if (!configured_path.is_absolute()) {
        const fs::path parent_candidate = fs::path("..") / configured_path;
        if (fileExists(parent_candidate.lexically_normal().string())) {
            return parent_candidate.lexically_normal().string();
        }
    }
    return configured;
}

std::string joinOutputPath(const VmProtectPolicy& policy, const std::string& file_name) {
    fs::path p(file_name);
    if (p.is_absolute()) {
        return p.lexically_normal().string();
    }
    return (fs::path(policy.output_dir) / p).lexically_normal().string();
}

// Read file bytes into memory for payload packing.
bool readFileBytes(const char* path, std::vector<uint8_t>& out) {
    out.clear();
    if (!path || path[0] == '\0') {
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(out.size()));
    }
    return static_cast<bool>(in);
}

bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    const fs::path out_path(path);
    if (out_path.has_parent_path()) {
        fs::create_directories(out_path.parent_path(), ec);
        if (ec) {
            return false;
        }
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    return static_cast<bool>(out);
}

uint32_t crc32Ieee(const uint8_t* data, size_t size) {
    static uint32_t table[256];
    static bool table_inited = false;
    if (!table_inited) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1u)) : (c >> 1u);
            }
            table[i] = c;
        }
        table_inited = true;
    }

    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        c = table[(c ^ data[i]) & 0xFFu] ^ (c >> 8u);
    }
    return c ^ 0xFFFFFFFFu;
}

#pragma pack(push, 1)
struct EmbeddedPayloadFooter {
    uint32_t magic;
    uint32_t version;
    uint64_t payload_size;
    uint32_t payload_crc32;
    uint32_t reserved;
};
#pragma pack(pop)

constexpr uint32_t kEmbeddedPayloadMagic = 0x34454D56U; // 'VME4'
constexpr uint32_t kEmbeddedPayloadVersion = 1U;

bool parseExistingEmbeddedPayload(const std::vector<uint8_t>& host_bytes,
                                  size_t* out_base_size,
                                  size_t* out_old_payload_size) {
    if (out_base_size == nullptr || out_old_payload_size == nullptr) {
        return false;
    }
    *out_base_size = host_bytes.size();
    *out_old_payload_size = 0;
    if (host_bytes.size() < sizeof(EmbeddedPayloadFooter)) {
        return true;
    }

    EmbeddedPayloadFooter footer{};
    const size_t footer_off = host_bytes.size() - sizeof(EmbeddedPayloadFooter);
    std::memcpy(&footer, host_bytes.data() + footer_off, sizeof(EmbeddedPayloadFooter));
    if (footer.magic != kEmbeddedPayloadMagic || footer.version != kEmbeddedPayloadVersion) {
        return true;
    }
    if (footer.payload_size == 0 ||
        footer.payload_size > host_bytes.size() - sizeof(EmbeddedPayloadFooter)) {
        LOGE("embedded footer invalid payload_size=%llu",
             static_cast<unsigned long long>(footer.payload_size));
        return false;
    }

    const size_t payload_begin = host_bytes.size() -
                                 sizeof(EmbeddedPayloadFooter) -
                                 static_cast<size_t>(footer.payload_size);
    const uint32_t actual_crc =
        crc32Ieee(host_bytes.data() + payload_begin, static_cast<size_t>(footer.payload_size));
    if (actual_crc != footer.payload_crc32) {
        LOGE("embedded footer crc mismatch expected=0x%x actual=0x%x",
             footer.payload_crc32,
             actual_crc);
        return false;
    }

    *out_base_size = payload_begin;
    *out_old_payload_size = static_cast<size_t>(footer.payload_size);
    return true;
}

bool embedExpandedSoIntoHost(const std::string& host_so,
                             const std::string& payload_so,
                             const std::string& final_so) {
    if (!fileExists(host_so)) {
        LOGE("host so not found: %s", host_so.c_str());
        return false;
    }
    if (!fileExists(payload_so)) {
        LOGE("payload so not found: %s", payload_so.c_str());
        return false;
    }
    if (final_so.empty()) {
        LOGE("final so path is empty");
        return false;
    }

    std::vector<uint8_t> host_bytes;
    if (!readFileBytes(host_so.c_str(), host_bytes)) {
        LOGE("failed to read host so: %s", host_so.c_str());
        return false;
    }
    std::vector<uint8_t> payload_bytes;
    if (!readFileBytes(payload_so.c_str(), payload_bytes) || payload_bytes.empty()) {
        LOGE("failed to read payload so: %s", payload_so.c_str());
        return false;
    }

    size_t base_size = host_bytes.size();
    size_t old_payload_size = 0;
    if (!parseExistingEmbeddedPayload(host_bytes, &base_size, &old_payload_size)) {
        LOGE("failed to parse existing embedded payload in host so: %s", host_so.c_str());
        return false;
    }

    std::vector<uint8_t> out;
    out.reserve(base_size + payload_bytes.size() + sizeof(EmbeddedPayloadFooter));
    out.insert(out.end(), host_bytes.begin(), host_bytes.begin() + static_cast<std::ptrdiff_t>(base_size));
    out.insert(out.end(), payload_bytes.begin(), payload_bytes.end());

    EmbeddedPayloadFooter footer{};
    footer.magic = kEmbeddedPayloadMagic;
    footer.version = kEmbeddedPayloadVersion;
    footer.payload_size = static_cast<uint64_t>(payload_bytes.size());
    footer.payload_crc32 = crc32Ieee(payload_bytes.data(), payload_bytes.size());
    footer.reserved = 0;
    const uint8_t* footer_bytes = reinterpret_cast<const uint8_t*>(&footer);
    out.insert(out.end(), footer_bytes, footer_bytes + sizeof(EmbeddedPayloadFooter));

    if (!writeFileBytes(final_so, out)) {
        LOGE("failed to write final so: %s", final_so.c_str());
        return false;
    }

    if (old_payload_size > 0) {
        LOGI("embed host so: replaced existing payload old=%llu new=%llu output=%s",
             static_cast<unsigned long long>(old_payload_size),
             static_cast<unsigned long long>(payload_bytes.size()),
             final_so.c_str());
    } else {
        LOGI("embed host so: appended payload=%llu output=%s",
             static_cast<unsigned long long>(payload_bytes.size()),
             final_so.c_str());
    }
    return true;
}

std::string quoteCommandArg(const std::string& arg) {
    if (arg.find_first_of(" \t\"") == std::string::npos) {
        return arg;
    }
    std::string out = "\"";
    for (char ch : arg) {
        if (ch == '"') {
            out += "\\\"";
        } else {
            out.push_back(ch);
        }
    }
    out.push_back('"');
    return out;
}

int runCommandLine(const std::vector<std::string>& args) {
    if (args.empty()) {
        return -1;
    }
    std::ostringstream cmd;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) {
            cmd << ' ';
        }
        cmd << quoteCommandArg(args[i]);
    }
    const std::string line = cmd.str();
    LOGI("run command: %s", line.c_str());
    return std::system(line.c_str());
}

int runPatchbayCommandInProcess(const std::vector<std::string>& args) {
    if (args.empty()) {
        return -1;
    }
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const std::string& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    return vmprotect_patchbay_entry(static_cast<int>(argv.size()), argv.data());
}

bool moveOrReplaceFile(const std::string& from, const std::string& to) {
    if (from.empty() || to.empty()) {
        return false;
    }
    std::error_code ec;
    fs::remove(to, ec);
    ec.clear();
    fs::rename(from, to, ec);
    if (!ec) {
        return true;
    }
    ec.clear();
    fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        return false;
    }
    ec.clear();
    fs::remove(from, ec);
    return true;
}

bool runPatchbayExportFromDonor(const std::string& patch_tool_exe,
                                const std::string& self_exe,
                                const std::string& input_so,
                                const std::string& donor_so,
                                const std::string& impl_symbol,
                                bool patch_all_exports,
                                bool allow_validate_fail) {
    if (!fileExists(input_so)) {
        LOGE("patch input so not found: %s", input_so.c_str());
        return false;
    }
    if (!fileExists(donor_so)) {
        LOGE("patch donor so not found: %s", donor_so.c_str());
        return false;
    }
    if (impl_symbol.empty()) {
        LOGE("patch impl symbol is empty");
        return false;
    }

    const std::string patched_tmp = input_so + ".patchbay.tmp.so";
    const std::string tool_exe = patch_tool_exe.empty() ? self_exe : patch_tool_exe;
    if (tool_exe.empty()) {
        LOGE("patch tool executable is empty");
        return false;
    }
    if (!patch_tool_exe.empty() && !fileExists(tool_exe)) {
        LOGE("patch tool executable not found: %s", tool_exe.c_str());
        return false;
    }

    std::vector<std::string> cmd = {
        tool_exe,
        "export_alias_from_patchbay",
        input_so,
        donor_so,
        patched_tmp,
        impl_symbol,
    };
    if (allow_validate_fail) {
        cmd.emplace_back("--allow-validate-fail");
    }
    if (!patch_all_exports) {
        cmd.emplace_back("--only-fun-java");
    }

    const int rc = patch_tool_exe.empty()
        ? runPatchbayCommandInProcess(cmd)
        : runCommandLine(cmd);
    if (rc != 0) {
        LOGE("patch tool command failed rc=%d", rc);
        return false;
    }
    if (!fileExists(patched_tmp)) {
        LOGE("patch output not found: %s", patched_tmp.c_str());
        return false;
    }
    if (!moveOrReplaceFile(patched_tmp, input_so)) {
        LOGE("failed to replace patched so: %s", input_so.c_str());
        return false;
    }

    LOGI("patchbay export completed: tool=%s input=%s donor=%s impl=%s patch_all_exports=%d",
         tool_exe.c_str(),
         input_so.c_str(),
         donor_so.c_str(),
         impl_symbol.c_str(),
         patch_all_exports ? 1 : 0);
    return true;
}

bool writeSharedBranchAddrList(const char* file_path,
                               const std::vector<uint64_t>& branch_addrs) {
    if (file_path == nullptr || file_path[0] == '\0') {
        return false;
    }
    std::ofstream out(file_path, std::ios::trunc);
    if (!out) {
        return false;
    }
    out << "static const uint64_t branch_addr_count = " << branch_addrs.size() << ";\n";
    if (branch_addrs.empty()) {
        out << "uint64_t branch_addr_list[1] = {};\n";
        return static_cast<bool>(out);
    }
    out << "uint64_t branch_addr_list[] = { ";
    for (size_t i = 0; i < branch_addrs.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << "0x" << std::hex << branch_addrs[i] << std::dec;
    }
    out << " };\n";
    return static_cast<bool>(out);
}

void appendUniqueBranchAddrs(const std::vector<uint64_t>& local_addrs,
                             std::unordered_set<uint64_t>& seen_addrs,
                             std::vector<uint64_t>& out_shared) {
    for (uint64_t addr : local_addrs) {
        if (seen_addrs.insert(addr).second) {
            out_shared.push_back(addr);
        }
    }
}

std::unordered_set<unsigned int> buildSupportedInsnIdSet() {
    std::unordered_set<unsigned int> ids = {
        ARM64_INS_ADD,
        ARM64_INS_ADRP,
        ARM64_INS_ALIAS_LSL,
        ARM64_INS_AND,
        ARM64_INS_ANDS,
        ARM64_INS_B,
        ARM64_INS_BL,
        ARM64_INS_BLR,
        ARM64_INS_BR,
        ARM64_INS_CSEL,
        ARM64_INS_LDP,
        ARM64_INS_LDR,
        ARM64_INS_LDRB,
        ARM64_INS_LDUR,
        ARM64_INS_LDURB,
        ARM64_INS_LSL,
        ARM64_INS_LSLR,
        ARM64_INS_MOV,
        ARM64_INS_MOVK,
        ARM64_INS_MOVN,
        ARM64_INS_MOVZ,
        ARM64_INS_MRS,
        ARM64_INS_MUL,
        ARM64_INS_ORR,
        ARM64_INS_RET,
        ARM64_INS_STP,
        ARM64_INS_STR,
        ARM64_INS_STRB,
        ARM64_INS_STUR,
        ARM64_INS_SUB,
        ARM64_INS_SUBS,
        ARM64_INS_TBNZ,
        ARM64_INS_TBZ,
    };
#ifdef ARM64_INS_LDRSW
    ids.insert(ARM64_INS_LDRSW);
#endif
#ifdef ARM64_INS_LDURSW
    ids.insert(ARM64_INS_LDURSW);
#endif
    return ids;
}

bool isSupportedByFallbackMnemonic(const char* mnemonic) {
    if (mnemonic == nullptr) {
        return false;
    }
    return std::strcmp(mnemonic, "mov") == 0 ||
           std::strcmp(mnemonic, "mul") == 0 ||
           std::strcmp(mnemonic, "and") == 0 ||
           std::strcmp(mnemonic, "ldrsw") == 0 ||
           std::strcmp(mnemonic, "ldursw") == 0 ||
           std::strcmp(mnemonic, "csel") == 0 ||
           std::strcmp(mnemonic, "lsl") == 0;
}

bool isInstructionSupported(const std::unordered_set<unsigned int>& supported_ids,
                            unsigned int insn_id,
                            const char* mnemonic) {
    if (supported_ids.find(insn_id) != supported_ids.end()) {
        return true;
    }
    return isSupportedByFallbackMnemonic(mnemonic);
}

std::string buildInstructionLabel(csh handle, unsigned int insn_id, const char* mnemonic) {
    const char* cap_name = cs_insn_name(handle, insn_id);
    std::string name;
    if (cap_name != nullptr && cap_name[0] != '\0') {
        name = cap_name;
    } else if (mnemonic != nullptr && mnemonic[0] != '\0') {
        name = mnemonic;
    } else {
        name = "unknown";
    }
    std::ostringstream oss;
    oss << name << "(" << insn_id << ")";
    return oss.str();
}

std::string markdownSafe(std::string value) {
    for (char& ch : value) {
        if (ch == '|') {
            ch = '/';
        }
    }
    return value;
}

void analyzeCoverageForFunction(csh handle,
                                const std::unordered_set<unsigned int>& supported_ids,
                                zFunction* function,
                                FunctionCoverageRow& row,
                                CoverageBoard& board) {
    row.translate_ok = function->prepareTranslation(&row.translate_error);
    row.translate_error = markdownSafe(row.translate_error);

    if (function->data() == nullptr || function->size() == 0) {
        return;
    }

    cs_insn* insn = nullptr;
    const size_t count = cs_disasm(handle,
                                   function->data(),
                                   function->size(),
                                   function->offset(),
                                   0,
                                   &insn);
    for (size_t i = 0; i < count; ++i) {
        const bool supported = isInstructionSupported(supported_ids, insn[i].id, insn[i].mnemonic);
        const std::string label = buildInstructionLabel(handle, insn[i].id, insn[i].mnemonic);
        ++row.total_instructions;
        ++board.total_instructions;
        if (supported) {
            ++row.supported_instructions;
            ++board.supported_instructions;
            ++board.supported_histogram[label];
        } else {
            ++row.unsupported_instructions;
            ++board.unsupported_instructions;
            ++board.unsupported_histogram[label];
        }
    }
    if (insn != nullptr) {
        cs_free(insn, count);
    }
}

bool writeCoverageReport(const std::string& report_path, const CoverageBoard& board) {
    std::ofstream out(report_path, std::ios::trunc);
    if (!out) {
        return false;
    }

    out << "# ARM64 Translation Coverage Board\n\n";
    out << "| Metric | Value |\n";
    out << "| --- | ---: |\n";
    out << "| Total instructions | " << board.total_instructions << " |\n";
    out << "| Supported instructions | " << board.supported_instructions << " |\n";
    out << "| Unsupported instructions | " << board.unsupported_instructions << " |\n\n";

    out << "## Per Function\n\n";
    out << "| Function | Total | Supported | Unsupported | Translation OK | Translation Error |\n";
    out << "| --- | ---: | ---: | ---: | --- | --- |\n";
    for (const FunctionCoverageRow& row : board.function_rows) {
        out << "| " << row.function_name
            << " | " << row.total_instructions
            << " | " << row.supported_instructions
            << " | " << row.unsupported_instructions
            << " | " << (row.translate_ok ? "yes" : "no")
            << " | " << (row.translate_error.empty() ? "-" : row.translate_error)
            << " |\n";
    }
    out << "\n";

    auto dumpHistogram = [&out](const std::string& title,
                                const std::map<std::string, uint64_t>& hist) {
        out << "## " << title << "\n\n";
        out << "| Instruction | Count |\n";
        out << "| --- | ---: |\n";
        std::vector<std::pair<std::string, uint64_t>> sorted(hist.begin(), hist.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& lhs, const auto& rhs) {
                      if (lhs.second != rhs.second) {
                          return lhs.second > rhs.second;
                      }
                      return lhs.first < rhs.first;
                  });
        for (const auto& item : sorted) {
            out << "| " << markdownSafe(item.first) << " | " << item.second << " |\n";
        }
        out << "\n";
    };

    dumpHistogram("Unsupported Instructions", board.unsupported_histogram);
    dumpHistogram("Supported Instructions", board.supported_histogram);

    return static_cast<bool>(out);
}

bool collectFunctions(zElf& elf,
                      const std::vector<std::string>& function_names,
                      std::vector<zFunction*>& functions) {
    // 根据函数名从 ELF 中取出函数对象，后续覆盖率统计与导出都依赖该列表。
    functions.clear();
    functions.reserve(function_names.size());
    for (const std::string& function_name : function_names) {
        zFunction* function = elf.getfunction(function_name.c_str());
        if (function == nullptr) {
            LOGE("failed to resolve function: %s", function_name.c_str());
            return false;
        }
        LOGI("resolved function %s at 0x%llx",
             function->name().c_str(),
             static_cast<unsigned long long>(function->offset()));
        functions.push_back(function);
    }
    return true;
}

bool exportProtectedPackage(const VmProtectPolicy& policy,
                            const std::vector<std::string>& function_names,
                            const std::vector<zFunction*>& functions) {
    // 导出阶段（加固产物生成）：
    // A. prepareTranslation 预校验，确保函数可翻译；
    // B. 汇总共享 branch 地址；
    // C. 导出 txt/bin；
    // D. 拼包写入 expanded so。
    for (size_t i = 0; i < functions.size(); ++i) {
        std::string error;
        if (!functions[i]->prepareTranslation(&error)) {
            LOGE("translation failed for %s: %s",
                 function_names[i].c_str(),
                 error.c_str());
            return false;
        }
    }

    std::vector<uint64_t> shared_branch_addrs;
    std::unordered_set<uint64_t> seen_addrs;
    for (zFunction* function : functions) {
        appendUniqueBranchAddrs(function->sharedBranchAddrs(), seen_addrs, shared_branch_addrs);
    }

    const std::string shared_branch_file = joinOutputPath(policy, policy.shared_branch_file);
    if (!writeSharedBranchAddrList(shared_branch_file.c_str(), shared_branch_addrs)) {
        LOGE("failed to write shared branch list: %s", shared_branch_file.c_str());
        return false;
    }

    std::vector<zSoBinPayload> payloads;
    payloads.reserve(functions.size());

    for (size_t i = 0; i < functions.size(); ++i) {
        zFunction* function = functions[i];
        const std::string& function_name = function_names[i];

        if (!function->remapBlToSharedBranchAddrs(shared_branch_addrs)) {
            LOGE("failed to remap OP_BL for %s", function_name.c_str());
            return false;
        }

        const std::string txt_path = joinOutputPath(policy, function_name + ".txt");
        const std::string bin_path = joinOutputPath(policy, function_name + ".bin");
        if (!function->dump(txt_path.c_str(), zFunction::DumpMode::UNENCODED)) {
            LOGE("failed to dump unencoded txt: %s", txt_path.c_str());
            return false;
        }
        if (!function->dump(bin_path.c_str(), zFunction::DumpMode::ENCODED)) {
            LOGE("failed to dump encoded bin: %s", bin_path.c_str());
            return false;
        }

        zSoBinPayload payload;
        payload.fun_addr = static_cast<uint64_t>(function->offset());
        if (!readFileBytes(bin_path.c_str(), payload.encoded_bytes) ||
            payload.encoded_bytes.empty()) {
            LOGE("failed to read encoded payload: %s", bin_path.c_str());
            return false;
        }
        payloads.push_back(std::move(payload));
    }

    const std::string expanded_so_path = joinOutputPath(policy, policy.expanded_so);
    if (!zSoBinBundleWriter::writeExpandedSo(
            policy.input_so.c_str(),
            expanded_so_path.c_str(),
            payloads,
            shared_branch_addrs)) {
        LOGE("failed to build expanded so: %s", expanded_so_path.c_str());
        return false;
    }

    LOGI("export completed: payload_count=%u shared_branch_addr_count=%u",
         static_cast<unsigned int>(payloads.size()),
         static_cast<unsigned int>(shared_branch_addrs.size()));
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc >= 2 && vmprotect_is_patchbay_command(argv[1])) {
        return vmprotect_patchbay_entry(argc, argv);
    }

    // main 总流程：
    // 1) 合并 policy + CLI；
    // 2) 解析目标函数；
    // 3) 生成翻译覆盖率看板；
    // 4) (可选) 导出加固产物。
    CliOverrides cli;
    std::string cli_error;
    if (!parseCommandLine(argc, argv, cli, cli_error)) {
        std::cerr << cli_error << "\n";
        printUsage();
        return 1;
    }
    if (cli.show_help) {
        printUsage();
        return 0;
    }

    VmProtectPolicy policy;
    policy.functions = kDefaultFunctions;
    deduplicateKeepOrder(policy.functions);

    if (!cli.policy_file.empty()) {
        if (!loadPolicyFile(cli.policy_file, policy)) {
            return 1;
        }
        if (!policy.has_explicit_functions) {
            policy.functions = kDefaultFunctions;
        }
    }

    if (!cli.input_so.empty()) {
        policy.input_so = cli.input_so;
    }
    if (!cli.output_dir.empty()) {
        policy.output_dir = cli.output_dir;
    }
    if (!cli.expanded_so.empty()) {
        policy.expanded_so = cli.expanded_so;
    }
    if (!cli.shared_branch_file.empty()) {
        policy.shared_branch_file = cli.shared_branch_file;
    }
    if (!cli.host_so.empty()) {
        policy.host_so = cli.host_so;
    }
    if (!cli.final_so.empty()) {
        policy.final_so = cli.final_so;
    }
    if (!cli.patch_donor_so.empty()) {
        policy.patch_donor_so = cli.patch_donor_so;
    }
    if (!cli.patch_impl_symbol.empty()) {
        policy.patch_impl_symbol = cli.patch_impl_symbol;
    }
    if (!cli.patch_tool_exe.empty()) {
        policy.patch_tool_exe = cli.patch_tool_exe;
    }
    if (cli.patch_all_exports_set) {
        policy.patch_all_exports = cli.patch_all_exports;
    }
    if (cli.patch_allow_validate_fail_set) {
        policy.patch_allow_validate_fail = cli.patch_allow_validate_fail;
    }
    if (!cli.coverage_report.empty()) {
        policy.coverage_report = cli.coverage_report;
    }
    if (!cli.functions.empty()) {
        policy.functions = cli.functions;
        policy.has_explicit_functions = true;
    }
    if (cli.coverage_only_set) {
        policy.coverage_only = cli.coverage_only;
    }
    if (cli.analyze_all_set) {
        policy.analyze_all_functions = cli.analyze_all;
    }

    deduplicateKeepOrder(policy.functions);
    policy.input_so = resolveInputSoFallback(policy.input_so);

    if (!fileExists(policy.input_so)) {
        LOGE("input so not found: %s", policy.input_so.c_str());
        return 1;
    }
    if (!policy.host_so.empty() && !fileExists(policy.host_so)) {
        LOGE("host so not found: %s", policy.host_so.c_str());
        return 1;
    }
    if ((!policy.patch_donor_so.empty() || !policy.patch_tool_exe.empty()) && policy.host_so.empty()) {
        LOGE("patch options require host_so (--host-so)");
        return 1;
    }
    if (!policy.patch_donor_so.empty() && !fileExists(policy.patch_donor_so)) {
        LOGE("patch donor so not found: %s", policy.patch_donor_so.c_str());
        return 1;
    }
    if (!ensureDirectory(policy.output_dir)) {
        LOGE("failed to create output dir: %s", policy.output_dir.c_str());
        return 1;
    }

    zElf elf(policy.input_so.c_str());

    std::vector<std::string> function_names;
    if (policy.analyze_all_functions) {
        const std::vector<zFunction>& list = elf.getFunctionList();
        function_names.reserve(list.size());
        for (const zFunction& function : list) {
            if (!function.name().empty()) {
                function_names.push_back(function.name());
            }
        }
    } else {
        function_names = policy.functions;
    }
    deduplicateKeepOrder(function_names);
    if (function_names.empty()) {
        LOGE("function list is empty");
        return 1;
    }

    std::vector<zFunction*> functions;
    if (!collectFunctions(elf, function_names, functions)) {
        return 1;
    }

    CoverageBoard board;
    {
        // 覆盖率统计使用 capstone 反汇编原始函数，并结合支持指令集合做统计。
        csh handle = 0;
        if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
            LOGE("coverage failed: capstone cs_open failed");
            return 1;
        }
        const std::unordered_set<unsigned int> supported_ids = buildSupportedInsnIdSet();
        board.function_rows.reserve(functions.size());
        for (size_t i = 0; i < functions.size(); ++i) {
            FunctionCoverageRow row;
            row.function_name = function_names[i];
            analyzeCoverageForFunction(handle, supported_ids, functions[i], row, board);
            board.function_rows.push_back(std::move(row));
        }
        cs_close(&handle);
    }

    const std::string coverage_report_path = joinOutputPath(policy, policy.coverage_report);
    if (!writeCoverageReport(coverage_report_path, board)) {
        LOGE("failed to write coverage report: %s", coverage_report_path.c_str());
        return 1;
    }
    LOGI("coverage report written: %s", coverage_report_path.c_str());

    if (policy.coverage_only) {
        // 仅看板模式：用于“翻译覆盖看板”快速迭代。
        LOGI("coverage-only mode enabled, export skipped");
        return 0;
    }

    if (!exportProtectedPackage(policy, function_names, functions)) {
        return 1;
    }

    if (!policy.host_so.empty()) {
        const std::string expanded_so_path = joinOutputPath(policy, policy.expanded_so);
        const std::string final_so_path =
            policy.final_so.empty() ? policy.host_so : policy.final_so;
        if (!embedExpandedSoIntoHost(policy.host_so, expanded_so_path, final_so_path)) {
            return 1;
        }
        if (!policy.patch_donor_so.empty() || !policy.patch_tool_exe.empty()) {
            if (policy.patch_donor_so.empty()) {
                LOGE("patch requires patch_donor_so");
                return 1;
            }
            if (!runPatchbayExportFromDonor(policy.patch_tool_exe,
                                            argv[0] ? argv[0] : "",
                                            final_so_path,
                                            policy.patch_donor_so,
                                            policy.patch_impl_symbol,
                                            policy.patch_all_exports,
                                            policy.patch_allow_validate_fail)) {
                return 1;
            }
        }
    }

    return 0;
}
