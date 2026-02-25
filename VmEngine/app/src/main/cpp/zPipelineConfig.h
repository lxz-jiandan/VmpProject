#pragma once

#include <string>

// 解包后的 base so 绝对路径。
extern std::string g_libdemo_so_path;
// 解包后的 expand so 绝对路径。
extern std::string g_libdemo_expand_so_path;
// route4 从 vmengine.so 内嵌 payload 落盘后的 expand so 路径。
extern std::string g_libdemo_expand_embedded_so_path;

// 资产名：基础 so（文本/编码 bin 路线都基于它执行）。
extern const char* const kAssetBaseSo;
// 资产名：expand so（编码容器路线使用）。
extern const char* const kAssetExpandSo;
// route4 运行时落盘的 expand so 文件名。
extern const char* const kEmbeddedExpandSoName;
