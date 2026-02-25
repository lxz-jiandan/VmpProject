#ifndef VMPROTECT_PATCHBAY_CRC_H
#define VMPROTECT_PATCHBAY_CRC_H

// 引入 patchbay 协议头定义。
#include "zPatchbayTypes.h"

// 引入基础整型定义。
#include <cstdint>
// 引入错误信息字符串。
#include <string>
// 引入字节数组容器。
#include <vector>

// 根据槽位数量构建低位 bitmask。
// 入参：
// - count: 需要置 1 的低位数量。
// 出参：
// - 返回 uint64 位图值。
uint64_t bitmaskForCountU32(uint32_t count);

// 计算 patchbay 段的 CRC32。
// 计算范围：
// - header（其中 crc32 字段按 0 参与计算）；
// - 各子区域的“已使用字节段”。
// 入参：
// - fileBytes: 完整 ELF 文件字节。
// - patchbayOffset: patchbay 段在文件中的起始偏移。
// - header: 已解析 patchbay 头。
// - outCrc: CRC 输出指针。
// - error: 可选错误描述输出。
// 返回：
// - true: 计算成功。
// - false: 边界非法或参数错误。
bool computePatchbayCrcFromFile(const std::vector<uint8_t>& fileBytes,
                                uint64_t patchbayOffset,
                                const PatchBayHeader& header,
                                uint32_t* outCrc,
                                std::string* error);

#endif // VMPROTECT_PATCHBAY_CRC_H

