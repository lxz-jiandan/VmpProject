// 引入 CLI 相关接口声明。
#include "zPipelineCli.h"

// 引入路径拼接工具。
#include <filesystem>
// 引入控制台输出。
#include <iostream>
// 引入哈希集合用于去重。
#include <unordered_set>

// 文件系统命名空间别名。
namespace fs = std::filesystem;

// 进入 pipeline 命名空间。
namespace vmp {

// 对字符串列表去重并保持原始顺序。
void deduplicateKeepOrder(std::vector<std::string>& values) {
    // 记录已出现元素。
    std::unordered_set<std::string> seen;
    // 存放去重后的结果。
    std::vector<std::string> dedup;
    // 预留容量，减少扩容开销。
    dedup.reserve(values.size());
    // 按原顺序遍历输入。
    for (const std::string& value : values) {
        // 仅首次出现时写入结果。
        if (seen.insert(value).second) {
            dedup.push_back(value);
        }
    }
    // 用去重结果替换原数组。
    values.swap(dedup);
}

// 解析命令行参数并填充覆盖项。
bool parseCommandLine(int argc, char* argv[], CliOverrides& cli, std::string& error) {
    // 从 argv[1] 开始遍历（跳过程序名）。
    for (int argIndex = 1; argIndex < argc; ++argIndex) {
        // 读取当前参数，空指针时回退空字符串。
        const std::string arg = argv[argIndex] ? argv[argIndex] : "";
        // 跳过空参数。
        if (arg.empty()) {
            continue;
        }
        // 帮助参数：标记后继续扫描其他参数。
        if (arg == "-h" || arg == "--help") {
            cli.showHelp = true;
            continue;
        }
        // 输入 so 路径参数。
        if (arg == "--input-so" && argIndex + 1 < argc) {
            cli.inputSo = argv[++argIndex];
            continue;
        }
        // 输出目录参数。
        if (arg == "--output-dir" && argIndex + 1 < argc) {
            cli.outputDir = argv[++argIndex];
            continue;
        }
        // expand so 文件名参数。
        if (arg == "--expanded-so" && argIndex + 1 < argc) {
            cli.expandedSo = argv[++argIndex];
            continue;
        }
        // 共享 branch 地址文件参数。
        if (arg == "--shared-branch-file" && argIndex + 1 < argc) {
            cli.sharedBranchFile = argv[++argIndex];
            continue;
        }
        // vmengine so 参数。
        if (arg == "--vmengine-so" && argIndex + 1 < argc) {
            cli.vmengineSo = argv[++argIndex];
            continue;
        }
        // 输出 so 参数。
        if (arg == "--output-so" && argIndex + 1 < argc) {
            cli.outputSo = argv[++argIndex];
            continue;
        }
        // patch donor so 参数。
        if (arg == "--patch-donor-so" && argIndex + 1 < argc) {
            cli.patchDonorSo = argv[++argIndex];
            continue;
        }
        // patch impl symbol 参数。
        if (arg == "--patch-impl-symbol" && argIndex + 1 < argc) {
            cli.patchImplSymbol = argv[++argIndex];
            continue;
        }
        // 覆盖率报告路径参数。
        if (arg == "--coverage-report" && argIndex + 1 < argc) {
            cli.coverageReport = argv[++argIndex];
            continue;
        }
        // 受保护函数参数（可重复）。
        if (arg == "--function" && argIndex + 1 < argc) {
            cli.functions.emplace_back(argv[++argIndex]);
            continue;
        }
        // 是否 patch donor 全量导出。
        if (arg == "--patch-all-exports") {
            cli.patchAllExportsSet = true;
            cli.patchAllExports = true;
            continue;
        }
        // 是否关闭 allow-validate-fail。
        if (arg == "--patch-no-allow-validate-fail") {
            cli.patchAllowValidateFailSet = true;
            cli.patchAllowValidateFail = false;
            continue;
        }
        // 仅覆盖率模式。
        if (arg == "--coverage-only") {
            cli.coverageOnlySet = true;
            cli.coverageOnly = true;
            continue;
        }
        // 分析全部函数模式。
        if (arg == "--analyze-all") {
            cli.analyzeAllSet = true;
            cli.analyzeAll = true;
            continue;
        }
        // 任何未知选项都立即报错。
        if (!arg.empty() && arg[0] == '-') {
            error = "unknown option: " + arg;
            return false;
        }
        // 禁止位置参数，要求显式使用 --function。
        error = "unexpected positional argument: " + arg + " (use --function <name>)";
        return false;
    }
    // 全部参数解析成功。
    return true;
}

// 打印命令行帮助文本。
void printUsage() {
    std::cout
        // 标题区。
        << "Usage:\n"
        // 主命令模板。
        << "  VmProtect.exe [options]\n\n"
        // 选项说明标题。
        << "Options:\n"
        // 输入 so。
        << "  --input-so <file>            Input arm64 so path (required)\n"
        // 输出目录。
        << "  --output-dir <dir>           Output directory for txt/bin/report\n"
        // expand so。
        << "  --expanded-so <file>         Expanded so output file name\n"
        // vmengine so。
        << "  --vmengine-so <file>         Vmengine so path (required in hardening route)\n"
        // 输出 so。
        << "  --output-so <file>           Protected output so path (required in hardening route)\n"
        // donor so。
        << "  --patch-donor-so <file>      Donor so for patchbay export fill\n"
        // impl symbol。
        << "  --patch-impl-symbol <name>   Impl symbol used by export_alias_from_patchbay\n"
        // 全量导出开关。
        << "  --patch-all-exports          Patch all donor exports (default: only fun_* and Java_*)\n"
        // validate fail 开关。
        << "  --patch-no-allow-validate-fail Disable --allow-validate-fail during patch\n"
        // branch 地址文件。
        << "  --shared-branch-file <file>  Shared branch list output file name\n"
        // 覆盖率报告。
        << "  --coverage-report <file>     Coverage report output file name\n"
        // 函数参数。
        << "  --function <name>            Protected function symbol (repeatable, required in hardening route)\n"
        // 覆盖率模式。
        << "  --coverage-only              Only generate coverage board\n"
        // 全函数分析模式。
        << "  --analyze-all                Analyze all extracted functions\n"
        // 加固模式说明。
        << "\n"
        << "Hardening route:\n"
        << "  Triggered when any of --vmengine-so/--output-so/--patch-donor-so is set.\n"
        << "  In this mode, --input-so/--vmengine-so/--output-so/--function are required.\n"
        << "\n"
        // 帮助参数。
        << "  -h, --help                   Show this help\n";
}

// 拼接输出路径：fileName 可为绝对路径或相对路径。
std::string joinOutputPath(const VmProtectConfig& config, const std::string& fileName) {
    // 先构造 path 对象。
    fs::path p(fileName);
    // 绝对路径直接返回标准化结果。
    if (p.is_absolute()) {
        return p.lexically_normal().string();
    }
    // 相对路径挂到 outputDir 下再标准化。
    return (fs::path(config.outputDir) / p).lexically_normal().string();
}

// 结束命名空间。
}  // namespace vmp
