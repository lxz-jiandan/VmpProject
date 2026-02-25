#include "zPipelineConfig.h"

// 运行时基线 so 路径（通常来自 assets 解包后的真实路径）。
std::string g_libdemo_so_path;
// 运行时 expand so 路径（外部导出版本）。
std::string g_libdemo_expand_so_path;
// 运行时 embedded expand so 路径（从 vmengine 内嵌 payload 释放得到）。
std::string g_libdemo_expand_embedded_so_path;

// 资产目录中的原始 demo so 文件名。
const char* const kAssetBaseSo = "libdemo.so";
// 资产目录中的 expand so 文件名。
const char* const kAssetExpandSo = "libdemo_expand.so";
// 嵌入式 expand so 的落盘文件名。
const char* const kEmbeddedExpandSoName = "libdemo_expand_embedded.so";
