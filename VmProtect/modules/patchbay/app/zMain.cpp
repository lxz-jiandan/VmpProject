/**
 * @file zMain.cpp
 * @brief patchbay 子命令入口编排层。
 *
 * 当前仅保留生产链路需要的命令：
 * - export_alias_from_patchbay
 */

#include "zPatchbayEntry.h"
// 引入 origin API（领域层）。
#include "zPatchbayOrigin.h"
// 引入日志接口。
#include "zLog.h"

// 引入 printf。
#include <cstdio>
// 引入 strcmp。
#include <cstring>
// 引入字符串类型。
#include <string>

// 打印命令行帮助。
static void printUsage(const char* exeName) {
    // 空程序名时使用默认可执行名。
    const char* name = exeName ? exeName : "VmProtect.exe";
    std::printf("Usage:\n");
    std::printf(
        "  %s export_alias_from_patchbay <inputElf> <originElf> <outputElf> <implSymbol> [--allow-validate-fail] [--only-fun-java]\n",
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
        // export_alias_from_patchbay <input> <origin> <output> <impl> [opts]
        if (argc < 6) {
            printUsage(argv[0]);
            return 1;
        }

        // 是否允许 validate 失败继续。
        bool allowValidateFail = false;
        // 是否只处理 fun_* 和 Java_*。
        bool onlyFunJava = false;

        // 解析可选参数。
        for (int argIndex = 6; argIndex < argc; ++argIndex) {
            if (std::strcmp(argv[argIndex], "--allow-validate-fail") == 0) {
                allowValidateFail = true;
                continue;
            }
            if (std::strcmp(argv[argIndex], "--only-fun-java") == 0) {
                onlyFunJava = true;
                continue;
            }
            LOGE("invalid option: %s", argv[argIndex]);
            return 2;
        }

        // 组装 origin API 请求对象。
        zPatchbayOriginRequest request;
        request.inputSoPath = argv[2];
        request.originSoPath = argv[3];
        request.outputSoPath = argv[4];
        request.implSymbol = argv[5];
        request.onlyFunJava = onlyFunJava;
        request.allowValidateFail = allowValidateFail;

        // 执行 origin 领域流程。
        zPatchbayOriginResult runResult;
        if (!runPatchbayExportAliasFromOrigin(request, &runResult)) {
            LOGE("export_alias_from_patchbay failed: status=%d rc=%d error=%s",
                 static_cast<int>(runResult.status),
                 runResult.exitCode,
                 runResult.error.empty() ? "(unknown)" : runResult.error.c_str());
            return runResult.exitCode;
        }

        // entry 模式输出额外摘要日志。
        if (runResult.entryMode) {
            LOGI("export_alias_from_patchbay entry mode enabled: entry_prefix=%s entry_needed=%zu",
                 argv[5],
                 runResult.appendCount);
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

