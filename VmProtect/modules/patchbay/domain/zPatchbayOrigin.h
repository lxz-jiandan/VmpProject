#ifndef VMPROTECT_PATCHBAY_ORIGIN_H
#define VMPROTECT_PATCHBAY_ORIGIN_H

// 引入字符串类型。
#include <string>

// patchbay origin 导出流程的输入参数。
struct zPatchbayOriginRequest {
    // 输入 vmengine so（通常是 embed 后的临时 so）。
    std::string inputSoPath;
    // origin so（提供导出符号集合与 st_value key）。
    std::string originSoPath;
    // 输出 so（应用 alias patch 后的最终产物）。
    std::string outputSoPath;
    // 实现符号（常见为 vm_takeover_entry_0000）。
    std::string implSymbol;
    // 是否只处理 fun_* 与 Java_* 导出。
    bool onlyFunJava = false;
    // 是否允许 validate 失败继续输出。
    bool allowValidateFail = false;
};

// origin 流程状态码（用于结构化错误定位）。
enum class zPatchbayOriginStatus {
    // 成功完成。
    ok = 0,
    // 参数缺失或不合法。
    invalidInput,
    // ELF 加载失败或输入文件不存在。
    loadFailed,
    // 动态导出收集失败（含 origin 空导出）。
    collectFailed,
    // vmengine 命名规则校验失败。
    namingRuleFailed,
    // origin 与 input 导出冲突。
    exportConflict,
    // patchbay 落盘失败。
    patchApplyFailed,
    // 执行成功但输出文件未落地。
    outputMissing,
};

// origin 流程执行结果。
struct zPatchbayOriginResult {
    // 执行状态。
    zPatchbayOriginStatus status = zPatchbayOriginStatus::ok;
    // 兼容 CLI 的退出码语义（0/1/2/3）。
    int exitCode = 0;
    // 详细错误文本（成功时可为空）。
    std::string error;
    // origin 原始导出数量。
    size_t originExportCount = 0;
    // input 原始导出数量。
    size_t inputExportCount = 0;
    // 实际追加 alias 数量。
    size_t appendCount = 0;
    // 是否启用槽位模式。
    bool entryMode = false;
};

// 运行 origin 导出 patch 流程（领域 API）。
// 返回值：
// - true：流程执行成功。
// - false：流程执行失败，详见 outResult。
bool runPatchbayExportAliasFromOrigin(const zPatchbayOriginRequest& request,
                                     zPatchbayOriginResult* outResult);

#endif // VMPROTECT_PATCHBAY_ORIGIN_H

