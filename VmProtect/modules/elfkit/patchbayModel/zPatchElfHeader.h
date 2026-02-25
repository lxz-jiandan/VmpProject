#ifndef VMP_PATCHBAY_ELF_HEADER_H
#define VMP_PATCHBAY_ELF_HEADER_H

// ELF 基础类型与常量（Elf64_Ehdr / EI_* / EM_*）。
#include "zPatchElfTypes.h"

// size_t。
#include <cstddef>
// uint8_t。
#include <cstdint>

/**
 * @brief ELF Header 的轻量模型。
 *
 * 用途：
 * - 保存一个原始的 `Elf64_Ehdr` 结构；
 * - 提供“从字节解析”与“目标格式识别”两个基础能力；
 * - 作为 PatchElf 加载链路的第一层输入门禁。
 */
class zElfHeader {
public:
    // 原始 ELF64 头；默认零初始化，避免未定义字段。
    Elf64_Ehdr raw{};

    /**
     * @brief 从字节流解析 ELF Header。
     * @param data 字节流首地址，必须非空。
     * @param size 字节流长度，必须 >= sizeof(Elf64_Ehdr)。
     * @return true 表示复制成功；false 表示输入不足或无效。
     */
    bool fromRaw(const uint8_t* data, size_t size);

    /**
     * @brief 判定是否为 ELF64 + 小端 + AArch64。
     * @return true 表示格式满足当前项目支持范围。
     */
    bool isElf64AArch64() const;
};

#endif // VMP_PATCHBAY_ELF_HEADER_H
