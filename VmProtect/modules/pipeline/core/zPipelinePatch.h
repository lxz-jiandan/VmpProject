// 防止头文件重复包含。
#pragma once

// 引入字符串类型。
#include <string>

// 进入 pipeline 命名空间。
namespace vmp {

// 基于 host so 路径生成默认 patch so 路径。
std::string buildPatchSoDefaultPath(const std::string& hostSoPath);
// 将 expand so 作为 payload 嵌入 host so，输出 final so。
bool embedExpandedSoIntoHost(const std::string& hostSo,
                             const std::string& payloadSo,
                             const std::string& finalSo);
// 调用 patchbay 流程：从 donor 导出并写入目标 so。
bool runPatchbayExportFromDonor(const std::string& inputSo,
                                const std::string& outputSo,
                                const std::string& donorSo,
                                const std::string& implSymbol,
                                bool patchAllExports,
                                bool allowValidateFail);

// 结束命名空间。
}  // namespace vmp


