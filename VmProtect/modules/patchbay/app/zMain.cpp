/**
 * @file zMain.cpp
 * @brief patchbay 子命令入口编排层。
 *
 * 当前仅保留生产链路需要的命令：
 * - export_alias_from_patchbay
 */

#include "zPatchbayEntry.h"
// 引入 patch ELF 访问 API。
#include "zPatchbayApi.h"
// 引入 patchbay 导出主流程。
#include "zPatchbayExport.h"
// 引入命名规则与槽位命名规则。
#include "zPatchbayRules.h"
// 引入 alias/payload 类型定义。
#include "zPatchbayTypes.h"
// 引入日志接口。
#include "zLog.h"

// 引入 printf。
#include <cstdio>
// 引入 strcmp。
#include <cstring>
// 引入字符串类型。
#include <string>
// 引入哈希集合。
#include <unordered_set>
// 引入 move 语义。
#include <utility>
// 引入数组容器。
#include <vector>

// 打印命令行帮助。
static void printUsage(const char* exeName) {
    // 空程序名时使用默认可执行名。
    const char* name = exeName ? exeName : "VmProtect.exe";
    std::printf("Usage:\n");
    std::printf(
        "  %s export_alias_from_patchbay <inputElf> <donorElf> <outputElf> <implSymbol> [--allow-validate-fail] [--only-fun-java]\n",
        name);
}

// 判断某子命令是否由 patchbay 处理。
bool vmprotectIsPatchbayCommand(const char* rawCmd) {
    // 空命令不是 patchbay 子命令。
    if (rawCmd == nullptr || rawCmd[0] == '\0') {
        return false;
    }
    // 转成 std::string 方便比较。
    const std::string cmd(rawCmd);
    // 当前仅支持 export_alias_from_patchbay。
    return cmd == "export_alias_from_patchbay";
}

// patchbay 内嵌入口实现。
int vmprotectPatchbayEntry(int argc, char* argv[]) {
    // 至少要有程序名和子命令。
    if (argc < 2) {
        const char* exeName = (argc > 0 && argv && argv[0]) ? argv[0] : "VmProtect.exe";
        printUsage(exeName);
        return 1;
    }

    // 读取子命令。
    const std::string cmd(argv[1]);

    // 处理 export_alias_from_patchbay。
    if (cmd == "export_alias_from_patchbay") {
        // 语法：
        // export_alias_from_patchbay <input> <donor> <output> <impl> [opts]
        if (argc < 6) {
            printUsage(argv[0]);
            return 1;
        }

        // 是否允许 validate 失败继续。
        bool allowValidateFail = false;
        // 是否只处理 fun_* 和 Java_*。
        bool onlyFunJava = false;

        // 解析可选参数。
        for (int i = 6; i < argc; ++i) {
            if (std::strcmp(argv[i], "--allow-validate-fail") == 0) {
                allowValidateFail = true;
                continue;
            }
            if (std::strcmp(argv[i], "--only-fun-java") == 0) {
                onlyFunJava = true;
                continue;
            }
            LOGE("invalid option: %s", argv[i]);
            return 2;
        }

        // 加载 donor ELF。
        vmp::elfkit::PatchElfImage donor(argv[3]);
        if (!donor.loaded()) {
            LOGE("failed to load donor ELF: %s", argv[3]);
            return 2;
        }

        // 收集 donor 的动态导出信息。
        std::vector<vmp::elfkit::PatchDynamicExportInfo> donorExports;
        std::string collectError;
        if (!donor.collectDefinedDynamicExportInfos(&donorExports, &collectError)) {
            LOGE("collect donor exports failed: %s",
                 collectError.empty() ? "(unknown)" : collectError.c_str());
            return 2;
        }

        // only_fun_java 模式下只保留 fun_* 和 Java_* 导出。
        if (onlyFunJava) {
            std::vector<vmp::elfkit::PatchDynamicExportInfo> filtered;
            filtered.reserve(donorExports.size());
            for (const vmp::elfkit::PatchDynamicExportInfo& info : donorExports) {
                if (isFunOrJavaSymbol(info.name)) {
                    filtered.push_back(info);
                }
            }
            donorExports.swap(filtered);
        }

        // donor 至少要有一个可用导出。
        if (donorExports.empty()) {
            LOGE("donor has no defined dynamic exports: %s", argv[3]);
            return 2;
        }

        // 加载 input ELF。
        vmp::elfkit::PatchElfImage inputElf(argv[2]);
        if (!inputElf.loaded()) {
            LOGE("failed to load input ELF: %s", argv[2]);
            return 2;
        }

        // 收集 input 已有导出名。
        std::vector<std::string> inputExports;
        if (!inputElf.collectDefinedDynamicExports(&inputExports, &collectError)) {
            LOGE("collect input exports failed: %s",
                 collectError.empty() ? "(unknown)" : collectError.c_str());
            return 2;
        }

        // 校验 vmengine 导出命名规则，不合法直接终止。
        if (!validateVmengineExportNamingRules(inputExports, &collectError)) {
            LOGE("invalid vmengine export naming: %s",
                 collectError.empty() ? "(unknown)" : collectError.c_str());
            return 3;
        }

        // 把 input 导出放进 set，提升查重效率。
        std::unordered_set<std::string> inputExportSet;
        inputExportSet.reserve(inputExports.size());
        for (const std::string& name : inputExports) {
            inputExportSet.insert(name);
        }

        // 严格模式：donor 与 vmengine 导出重名时直接失败。
        std::vector<std::string> duplicateExports;
        duplicateExports.reserve(donorExports.size());
        for (const vmp::elfkit::PatchDynamicExportInfo& exportInfo : donorExports) {
            if (inputExportSet.find(exportInfo.name) != inputExportSet.end()) {
                duplicateExports.push_back(exportInfo.name);
            }
        }
        if (!duplicateExports.empty()) {
            LOGE("export conflict detected between donor and vmengine: count=%zu",
                 duplicateExports.size());
            constexpr size_t kDetailLimit = 16;
            for (size_t i = 0; i < duplicateExports.size() && i < kDetailLimit; ++i) {
                LOGE("conflict export[%zu]: %s", i, duplicateExports[i].c_str());
            }
            if (duplicateExports.size() > kDetailLimit) {
                LOGE("... and %zu more conflict exports",
                     duplicateExports.size() - kDetailLimit);
            }
            return 3;
        }

        // 构建 alias 列表：donor 每个导出都映射到 impl 或 takeover slot。
        std::vector<AliasPair> pairs;
        pairs.reserve(donorExports.size());
        const bool useSlotMode = isTakeoverSlotModeImpl(argv[5]);
        for (size_t i = 0; i < donorExports.size(); ++i) {
            AliasPair pair;
            pair.exportName = donorExports[i].name;
            pair.implName =
                useSlotMode ? buildTakeoverSlotSymbolName(static_cast<uint32_t>(i))
                            : std::string(argv[5]);
            // key 字段承载 donor st_value（route4 key 语义）。
            pair.exportKey = donorExports[i].value;
            pairs.push_back(std::move(pair));
        }

        // 槽位模式输出额外日志。
        if (useSlotMode) {
            LOGI("export_alias_from_patchbay slot mode enabled: slot_prefix=%s slot_needed=%zu",
                 argv[5],
                 pairs.size());
        }

        // 输出开始日志。
        LOGI("export_alias_from_patchbay start: donorExports=%zu inputExports=%zu toAppend=%zu impl=%s onlyFunJava=%d",
             donorExports.size(),
             inputExports.size(),
             pairs.size(),
             argv[5],
             onlyFunJava ? 1 : 0);

        // 执行 patchbay 导出 patch。
        std::string patchError;
        if (!exportAliasSymbolsPatchbay(argv[2],
                                        argv[4],
                                        pairs,
                                        allowValidateFail,
                                        &patchError)) {
            LOGE("export_alias_from_patchbay failed: %s",
                 patchError.empty() ? "(unknown)" : patchError.c_str());
            return 3;
        }

        // 输出成功日志。
        LOGI("export_alias_from_patchbay success: %s + %s -> %s (impl=%s)",
             argv[2],
             argv[3],
             argv[4],
             argv[5]);
        return 0;
    }

    // 未知命令：打印帮助并返回参数错误。
    printUsage(argv[0]);
    return 1;
}

