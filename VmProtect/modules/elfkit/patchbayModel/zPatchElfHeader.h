/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfHeader.h
 * - 主要职责：ELF Header 处理：负责 ELF 头字段读取、校验与重建策略。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
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
