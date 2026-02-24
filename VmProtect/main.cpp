/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VmProtect CLI 主入口，负责配置解析、覆盖率看板与导出物生成。
 * - 加固链路位置：第 1 阶段（离线分析与产物构建）。
 * - 输入：原始 arm64 so + 函数清单/CLI 配置。
 * - 输出：函数 txt/bin、branch_addr_list.txt、libdemo_expand.so。
 */
#include <algorithm>
#include <cinttypes>
#include <cstring>
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

struct VmProtectConfig {
    // 待分析/导出的原始 so。
    std::string input_so;
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
    // 是否分析 ELF 内全部函数（而非函数白名单）。
    bool analyze_all_functions = false;
    // 是否仅出覆盖率报告，不导出 payload。
    bool coverage_only = false;
    // route4 宿主 so 输入（通常是 libvmengine.so）。
    std::string host_so;
    // 产出的最终 so 路径。
    // 为空时：
    // - 仅 embed：默认覆盖 host_so；
    // - embed + patch：默认输出 host 同目录下的 libvmengine_patch.so。
    std::string final_so;
    // donor so（用于 patchbay 导出补全）。
    std::string patch_donor_so;
    // patchbay 导出默认走“通用槽位模式”（按 donor 导出顺序映射到 vm_takeover_slot_xxxx）。
    std::string patch_impl_symbol = "vm_takeover_slot_0000";
    // true: donor 所有导出都补齐；false: 仅补 fun_* 与 Java_*。
    bool patch_all_exports = false;
    // patchbay 失败时是否放宽 validate。
    bool patch_allow_validate_fail = true;
};

struct CliOverrides {
    // 命令行 help 开关。
    bool show_help = false;
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

bool fileExists(const std::string& path) {
    // error_code 版本避免 filesystem 抛异常，便于统一返回 false。
    std::error_code ec;
    // 条件顺序：
    // 1) 路径非空；
    // 2) 路径存在；
    // 3) 路径是常规文件（非目录）。
    return !path.empty() && fs::exists(path, ec) && fs::is_regular_file(path, ec);
}

bool ensureDirectory(const std::string& path) {
    // 使用 error_code 版本减少异常路径复杂度。
    std::error_code ec;
    // 空路径视为非法目录。
    if (path.empty()) {
        return false;
    }
    // 已存在时仅当它是目录才算成功。
    if (fs::exists(path, ec)) {
        return fs::is_directory(path, ec);
    }
    // 不存在时递归创建目录。
    return fs::create_directories(path, ec);
}

void deduplicateKeepOrder(std::vector<std::string>& values) {
    // seen 用于 O(1) 去重判断。
    std::unordered_set<std::string> seen;
    // dedup 保存“首次出现顺序”。
    std::vector<std::string> dedup;
    // 预留容量减少扩容开销。
    dedup.reserve(values.size());
    // 顺序遍历原列表。
    for (const std::string& value : values) {
        // insert(...).second 为 true 代表首次出现。
        if (seen.insert(value).second) {
            dedup.push_back(value);
        }
    }
    // 原地替换为去重结果。
    values.swap(dedup);
}

bool parseCommandLine(int argc, char* argv[], CliOverrides& cli, std::string& error) {
    // 统一 CLI：函数名必须通过 --function 显式传入，避免位置参数歧义。
    // 从 argv[1] 开始，argv[0] 是程序名。
    for (int i = 1; i < argc; ++i) {
        // 防御性转换：空指针转空串。
        const std::string arg = argv[i] ? argv[i] : "";
        // 空参数跳过。
        if (arg.empty()) {
            continue;
        }
        // 帮助参数：只设置标志位，不立即退出（交给 main 统一处理）。
        if (arg == "-h" || arg == "--help") {
            cli.show_help = true;
            continue;
        }
        // 下面这组参数都要求“带一个值”，因此都检查 i+1 < argc。
        if (arg == "--input-so" && i + 1 < argc) {
            // 消费下一个参数作为 input_so。
            cli.input_so = argv[++i];
            continue;
        }
        if (arg == "--output-dir" && i + 1 < argc) {
            // 消费下一个参数作为输出目录。
            cli.output_dir = argv[++i];
            continue;
        }
        if (arg == "--expanded-so" && i + 1 < argc) {
            // 消费下一个参数作为 expanded so 文件名。
            cli.expanded_so = argv[++i];
            continue;
        }
        if (arg == "--shared-branch-file" && i + 1 < argc) {
            // 消费下一个参数作为共享 branch 文件名。
            cli.shared_branch_file = argv[++i];
            continue;
        }
        if (arg == "--host-so" && i + 1 < argc) {
            // 消费下一个参数作为宿主 so。
            cli.host_so = argv[++i];
            continue;
        }
        if (arg == "--final-so" && i + 1 < argc) {
            // 消费下一个参数作为最终输出 so。
            cli.final_so = argv[++i];
            continue;
        }
        if (arg == "--patch-donor-so" && i + 1 < argc) {
            // 消费下一个参数作为 donor so。
            cli.patch_donor_so = argv[++i];
            continue;
        }
        if (arg == "--patch-impl-symbol" && i + 1 < argc) {
            // 消费下一个参数作为 patch 实现符号名。
            cli.patch_impl_symbol = argv[++i];
            continue;
        }
        if (arg == "--coverage-report" && i + 1 < argc) {
            // 消费下一个参数作为覆盖率报告文件名。
            cli.coverage_report = argv[++i];
            continue;
        }
        if (arg == "--function" && i + 1 < argc) {
            // 可重复参数：每出现一次追加一个目标函数。
            cli.functions.emplace_back(argv[++i]);
            continue;
        }
        // 下面是无值布尔开关，出现即置位。
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
        // 以 '-' 开头但未命中任何已知参数：判定为未知选项。
        if (!arg.empty() && arg[0] == '-') {
            error = "unknown option: " + arg;
            return false;
        }
        // 非 '-' 开头参数不再允许位置参数，统一要求 --function 显式传入。
        error = "unexpected positional argument: " + arg + " (use --function <name>)";
        return false;
    }
    // 全量扫描成功。
    return true;
}

void printUsage() {
    // CLI 帮助文本统一在这里维护，避免参数说明分散在各处。
    std::cout
        << "Usage:\n"
        << "  VmProtect.exe [options]\n\n"
        << "Options:\n"
        << "  --input-so <file>            Input arm64 so path (required)\n"
        << "  --output-dir <dir>           Output directory for txt/bin/report\n"
        << "  --expanded-so <file>         Expanded so output file name\n"
        << "  --host-so <file>             Host so for embed/patch output (e.g. libvmengine.so)\n"
        << "  --final-so <file>            Final protected so path "
           "(default: host-so; with patch -> libvmengine_patch.so)\n"
        << "  --patch-donor-so <file>      Donor so for patchbay export fill\n"
        << "  --patch-impl-symbol <name>   Impl symbol used by export_alias_from_patchbay\n"
        << "  --patch-all-exports          Patch all donor exports (default: only fun_* and Java_*)\n"
        << "  --patch-no-allow-validate-fail Disable --allow-validate-fail during patch\n"
        << "  --shared-branch-file <file>  Shared branch list output file name\n"
        << "  --coverage-report <file>     Coverage report output file name\n"
        << "  --function <name>            Protected function (repeatable)\n"
        << "  --coverage-only              Only generate coverage board\n"
        << "  --analyze-all                Analyze all extracted functions\n"
        << "  -h, --help                   Show this help\n";
}

std::string joinOutputPath(const VmProtectConfig& config, const std::string& file_name) {
    // 绝对路径原样使用；相对路径拼到 output_dir 下，保持产物集中。
    fs::path p(file_name);
    if (p.is_absolute()) {
        return p.lexically_normal().string();
    }
    return (fs::path(config.output_dir) / p).lexically_normal().string();
}

// Read file bytes into memory for payload packing.
bool readFileBytes(const char* path, std::vector<uint8_t>& out) {
    out.clear();
    // 入参必须是非空 C 字符串。
    if (!path || path[0] == '\0') {
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    // tellg 失败会返回负值。
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
    // 输出路径为空视为调用方错误。
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    const fs::path out_path(path);
    if (out_path.has_parent_path()) {
        // 先确保父目录存在，再打开文件。
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
    // 运行时懒构建 CRC32 查表，避免每次重复初始化。
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
    // 固定魔数，用于识别“尾部附加 payload”格式。
    uint32_t magic;
    // 结构版本，支持未来协议升级。
    uint32_t version;
    // payload 字节长度。
    uint64_t payload_size;
    // payload 的 CRC32 校验值。
    uint32_t payload_crc32;
    // 预留位，当前写 0。
    uint32_t reserved;
};
#pragma pack(pop)

constexpr uint32_t kEmbeddedPayloadMagic = 0x34454D56U; // 'VME4'
constexpr uint32_t kEmbeddedPayloadVersion = 1U;

bool parseExistingEmbeddedPayload(const std::vector<uint8_t>& host_bytes,
                                  size_t* out_base_size,
                                  size_t* out_old_payload_size) {
    // 返回值语义：
    // - true: 解析成功（包括“没有旧 payload”这种正常情况）；
    // - false: 识别到 footer 但结构不合法或校验失败。
    if (out_base_size == nullptr || out_old_payload_size == nullptr) {
        return false;
    }
    *out_base_size = host_bytes.size();
    *out_old_payload_size = 0;
    if (host_bytes.size() < sizeof(EmbeddedPayloadFooter)) {
        // 文件比 footer 还短，不可能含旧 payload，按“无旧 payload”处理。
        return true;
    }

    EmbeddedPayloadFooter footer{};
    const size_t footer_off = host_bytes.size() - sizeof(EmbeddedPayloadFooter);
    std::memcpy(&footer, host_bytes.data() + footer_off, sizeof(EmbeddedPayloadFooter));
    if (footer.magic != kEmbeddedPayloadMagic || footer.version != kEmbeddedPayloadVersion) {
        // 不是我们的尾部格式，按“无旧 payload”处理。
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
    // 校验旧 payload CRC，防止把损坏文件继续当作基线。
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
    // route4 嵌入流程：
    // 1) 读取 host/payload；
    // 2) 若 host 已含旧 payload 则剥离；
    // 3) 追加新 payload + footer；
    // 4) 写出 final_so。
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
    // base_size 指“宿主原始主体”长度（不含旧 payload）。
    if (!parseExistingEmbeddedPayload(host_bytes, &base_size, &old_payload_size)) {
        LOGE("failed to parse existing embedded payload in host so: %s", host_so.c_str());
        return false;
    }

    std::vector<uint8_t> out;
    // 预留最终容量，减少多次扩容拷贝。
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

int runPatchbayCommandInProcess(const std::vector<std::string>& args) {
    // 通过进程内入口调用 patchbay，避免额外拉起子进程。
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

std::string buildPatchSoDefaultPath(const std::string& host_so_path) {
    // 把 libvmengine.so 映射为 libvmengine_patch.so；
    // 其它文件名统一追加 "_patch.so" 后缀，避免覆盖原文件。
    fs::path host_path(host_so_path);
    fs::path parent = host_path.parent_path();
    const std::string stem = host_path.stem().string();
    const std::string ext = host_path.extension().string();
    std::string patch_name;
    if (!stem.empty() && ext == ".so") {
        patch_name = stem + "_patch.so";
    } else if (!host_path.filename().string().empty()) {
        patch_name = host_path.filename().string() + "_patch.so";
    } else {
        patch_name = "libvmengine_patch.so";
    }
    return (parent / patch_name).lexically_normal().string();
}

bool runPatchbayExportFromDonor(const std::string& input_so,
                                const std::string& output_so,
                                const std::string& donor_so,
                                const std::string& impl_symbol,
                                bool patch_all_exports,
                                bool allow_validate_fail) {
    // patchbay 主路径：
    // input_so + donor_so -> output_so（独立产物，不覆盖 input_so）。
    if (!fileExists(input_so)) {
        LOGE("patch input so not found: %s", input_so.c_str());
        return false;
    }
    if (output_so.empty()) {
        LOGE("patch output so is empty");
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

    std::vector<std::string> cmd = {
        "VmProtect.exe",
        "export_alias_from_patchbay",
        input_so,
        donor_so,
        output_so,
        impl_symbol,
    };
    if (allow_validate_fail) {
        // 兼容历史样本：允许校验放宽，优先保证流程可继续。
        cmd.emplace_back("--allow-validate-fail");
    }
    if (!patch_all_exports) {
        cmd.emplace_back("--only-fun-java");
    }

    const int rc = runPatchbayCommandInProcess(cmd);
    if (rc != 0) {
        LOGE("patchbay command failed rc=%d", rc);
        return false;
    }
    if (!fileExists(output_so)) {
        LOGE("patch output not found: %s", output_so.c_str());
        return false;
    }

    LOGI("patchbay export completed: tool=embedded input=%s output=%s donor=%s impl=%s patch_all_exports=%d",
         input_so.c_str(),
         output_so.c_str(),
         donor_so.c_str(),
         impl_symbol.c_str(),
         patch_all_exports ? 1 : 0);
    return true;
}

bool writeSharedBranchAddrList(const char* file_path,
                               const std::vector<uint64_t>& branch_addrs) {
    // 生成 C 风格静态数组，供 VmEngine 侧直接 include/编译。
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
    // 汇总多个函数的 BL 目标地址并去重，保留首次出现顺序。
    for (uint64_t addr : local_addrs) {
        if (seen_addrs.insert(addr).second) {
            out_shared.push_back(addr);
        }
    }
}

std::unordered_set<unsigned int> buildSupportedInsnIdSet() {
    // 覆盖率看板“已支持指令”白名单。
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
    // 某些 Capstone 版本指令 ID 会漂移，提供 mnemonic 级兜底判定。
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
    // 优先 ID 精确匹配，失败再走 mnemonic 兜底。
    if (supported_ids.find(insn_id) != supported_ids.end()) {
        return true;
    }
    return isSupportedByFallbackMnemonic(mnemonic);
}

std::string buildInstructionLabel(csh handle, unsigned int insn_id, const char* mnemonic) {
    // 统一标签格式：name(id)，便于 Markdown 统计汇总。
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
    // Markdown 表格中 '|' 会破坏列结构，这里统一替换为 '/'。
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
    // 单函数覆盖率流程：
    // 1) 先做翻译预校验；
    // 2) 反汇编统计支持/不支持指令数；
    // 3) 回填 row 与全局 board。
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
    // 输出 Markdown 报告，便于 CI 与人工阅读双用。
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
        // 频次优先降序，频次相同按名称升序，保证输出稳定。
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
        zFunction* function = elf.getFunction(function_name.c_str());
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

bool exportProtectedPackage(const VmProtectConfig& config,
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

    const std::string shared_branch_file = joinOutputPath(config, config.shared_branch_file);
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

        const std::string txt_path = joinOutputPath(config, function_name + ".txt");
        const std::string bin_path = joinOutputPath(config, function_name + ".bin");
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

    const std::string expanded_so_path = joinOutputPath(config, config.expanded_so);
    if (!zSoBinBundleWriter::writeExpandedSo(
            config.input_so.c_str(),
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
    // 兼容 patchbay 子命令入口：若命中则直接转发，不走 VmProtect 主流程。
    if (argc >= 2 && vmprotect_is_patchbay_command(argv[1])) {
        return vmprotect_patchbay_entry(argc, argv);
    }

    // main 总流程：
    // 1) 合并 CLI；
    // 2) 解析目标函数；
    // 3) 生成翻译覆盖率看板；
    // 4) (可选) 导出加固产物。
    CliOverrides cli;
    std::string cli_error;
    // 解析 CLI，失败时打印错误与 usage。
    if (!parseCommandLine(argc, argv, cli, cli_error)) {
        std::cerr << cli_error << "\n";
        printUsage();
        return 1;
    }
    // 命中 help 直接输出 usage 并正常退出。
    if (cli.show_help) {
        printUsage();
        return 0;
    }

    // 构建默认配置：先填默认函数，再由 CLI 覆盖。
    VmProtectConfig config;
    config.functions = kDefaultFunctions;
    // 默认列表先去重，确保后续行为稳定。
    deduplicateKeepOrder(config.functions);

    // 逐项应用 CLI 覆盖。
    if (!cli.input_so.empty()) {
        config.input_so = cli.input_so;
    }
    if (!cli.output_dir.empty()) {
        config.output_dir = cli.output_dir;
    }
    if (!cli.expanded_so.empty()) {
        config.expanded_so = cli.expanded_so;
    }
    if (!cli.shared_branch_file.empty()) {
        config.shared_branch_file = cli.shared_branch_file;
    }
    if (!cli.host_so.empty()) {
        config.host_so = cli.host_so;
    }
    if (!cli.final_so.empty()) {
        config.final_so = cli.final_so;
    }
    if (!cli.patch_donor_so.empty()) {
        config.patch_donor_so = cli.patch_donor_so;
    }
    if (!cli.patch_impl_symbol.empty()) {
        config.patch_impl_symbol = cli.patch_impl_symbol;
    }
    if (cli.patch_all_exports_set) {
        config.patch_all_exports = cli.patch_all_exports;
    }
    if (cli.patch_allow_validate_fail_set) {
        config.patch_allow_validate_fail = cli.patch_allow_validate_fail;
    }
    if (!cli.coverage_report.empty()) {
        config.coverage_report = cli.coverage_report;
    }
    if (!cli.functions.empty()) {
        config.functions = cli.functions;
    }
    if (cli.coverage_only_set) {
        config.coverage_only = cli.coverage_only;
    }
    if (cli.analyze_all_set) {
        config.analyze_all_functions = cli.analyze_all;
    }

    // 最终函数列表再去重一次（含 CLI 重复项）。
    deduplicateKeepOrder(config.functions);
    // 输入 so 是硬性必需参数。
    if (config.input_so.empty()) {
        LOGE("input so is empty (use --input-so)");
        return 1;
    }
    // 校验 input so 文件存在。
    if (!fileExists(config.input_so)) {
        LOGE("input so not found: %s", config.input_so.c_str());
        return 1;
    }
    // host_so 提供时必须存在。
    if (!config.host_so.empty() && !fileExists(config.host_so)) {
        LOGE("host so not found: %s", config.host_so.c_str());
        return 1;
    }
    // 开启 patch 功能必须同时提供 host_so。
    if (!config.patch_donor_so.empty() && config.host_so.empty()) {
        LOGE("patch options require host_so (--host-so)");
        return 1;
    }
    // donor_so 提供时必须存在。
    if (!config.patch_donor_so.empty() && !fileExists(config.patch_donor_so)) {
        LOGE("patch donor so not found: %s", config.patch_donor_so.c_str());
        return 1;
    }
    // 确保输出目录可用（存在或可创建）。
    if (!ensureDirectory(config.output_dir)) {
        LOGE("failed to create output dir: %s", config.output_dir.c_str());
        return 1;
    }

    // 加载输入 ELF，后续解析函数信息。
    zElf elf(config.input_so.c_str());

    // 解析目标函数名列表。
    std::vector<std::string> function_names;
    // --analyze-all 时从 ELF 提取所有具名函数。
    if (config.analyze_all_functions) {
        const std::vector<zFunction>& list = elf.getFunctionList();
        function_names.reserve(list.size());
        for (const zFunction& function : list) {
            // 过滤空函数名。
            if (!function.name().empty()) {
                function_names.push_back(function.name());
            }
        }
    } else {
        // 默认路径：使用配置中的函数白名单。
        function_names = config.functions;
    }
    // 去重并保持顺序稳定。
    deduplicateKeepOrder(function_names);
    // 最终目标函数不能为空。
    if (function_names.empty()) {
        LOGE("function list is empty");
        return 1;
    }

    // 把函数名解析成 zFunction* 指针集合。
    std::vector<zFunction*> functions;
    if (!collectFunctions(elf, function_names, functions)) {
        return 1;
    }

    // 覆盖率看板对象。
    CoverageBoard board;
    {
        // 覆盖率统计使用 capstone 反汇编原始函数，并结合支持指令集合做统计。
        csh handle = 0;
        // 打开 capstone AArch64 反汇编句柄。
        if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
            LOGE("coverage failed: capstone cs_open failed");
            return 1;
        }
        // 构建“已支持指令 ID”集合。
        const std::unordered_set<unsigned int> supported_ids = buildSupportedInsnIdSet();
        // 预留函数行容量。
        board.function_rows.reserve(functions.size());
        // 逐函数做覆盖率统计并写入 board。
        for (size_t i = 0; i < functions.size(); ++i) {
            FunctionCoverageRow row;
            row.function_name = function_names[i];
            analyzeCoverageForFunction(handle, supported_ids, functions[i], row, board);
            board.function_rows.push_back(std::move(row));
        }
        // 关闭 capstone 句柄。
        cs_close(&handle);
    }

    // 计算 coverage 报告输出路径。
    const std::string coverage_report_path = joinOutputPath(config, config.coverage_report);
    // 写覆盖率报告文件。
    if (!writeCoverageReport(coverage_report_path, board)) {
        LOGE("failed to write coverage report: %s", coverage_report_path.c_str());
        return 1;
    }
    // 输出覆盖率报告路径日志。
    LOGI("coverage report written: %s", coverage_report_path.c_str());

    // 看板模式只产出覆盖率报告，不做导出。
    if (config.coverage_only) {
        // 仅看板模式：用于“翻译覆盖看板”快速迭代。
        LOGI("coverage-only mode enabled, export skipped");
        return 0;
    }

    // 执行离线导出：txt/bin + shared branch + expanded so。
    if (!exportProtectedPackage(config, function_names, functions)) {
        return 1;
    }

    // 若提供 host_so，则继续执行 embed + patch 链路。
    if (!config.host_so.empty()) {
        // 计算 expanded so 完整路径。
        const std::string expanded_so_path = joinOutputPath(config, config.expanded_so);
        // embed-only：默认仍覆盖 host；embed+patch：默认写独立 libvmengine_patch.so。
        if (config.patch_donor_so.empty()) {
            const std::string final_so_path =
                config.final_so.empty() ? config.host_so : config.final_so;
            if (!embedExpandedSoIntoHost(config.host_so, expanded_so_path, final_so_path)) {
                return 1;
            }
        } else {
            // patch 输入先落到临时 embed 产物，随后输出独立 patch so。
            const std::string final_so_path =
                config.final_so.empty() ? buildPatchSoDefaultPath(config.host_so) : config.final_so;
            const std::string embed_tmp_so_path = final_so_path + ".embed.tmp.so";
            if (!embedExpandedSoIntoHost(config.host_so, expanded_so_path, embed_tmp_so_path)) {
                return 1;
            }
            if (!runPatchbayExportFromDonor(embed_tmp_so_path,
                                            final_so_path,
                                            config.patch_donor_so,
                                            config.patch_impl_symbol,
                                            config.patch_all_exports,
                                            config.patch_allow_validate_fail)) {
                return 1;
            }
            // 清理 embed 临时文件，保留最终 patch so。
            std::error_code ec;
            fs::remove(embed_tmp_so_path, ec);
            if (ec) {
                LOGW("remove embed tmp so failed: %s", embed_tmp_so_path.c_str());
            }
        }
    }

    // 全流程成功。
    return 0;
}
