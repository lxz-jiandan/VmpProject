/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfValidator.h
 * - 主要职责：Patch ELF 校验总入口：聚合各类校验器并生成一致性校验结果。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#ifndef VMP_PATCHBAY_ELF_VALIDATOR_H
#define VMP_PATCHBAY_ELF_VALIDATOR_H

#include <string>

class PatchElf;

/**
 * @brief ELF 完整性校验器。
 *
 * 将校验拆分为多个阶段：基础格式、段布局、节映射、符号与重定位、
 * 以及“重解析一致性”检查，便于定位问题根因。
 */
class zElfValidator {
public:
    /** @brief 校验 ELF 头、表项大小、基础边界关系。 */
    static bool validateBasic(const PatchElf& elf, std::string* error);

    /** @brief 校验 Program Header 布局、对齐与映射约束。 */
    static bool validateProgramSegmentLayout(const PatchElf& elf, std::string* error);

    /** @brief 校验 Section 与 Segment 的覆盖/映射关系。 */
    static bool validateSectionSegmentMapping(const PatchElf& elf, std::string* error);

    /** @brief 校验符号表与字符串表、索引、地址有效性。 */
    static bool validateSymbolResolution(const PatchElf& elf, std::string* error);

    /** @brief 校验 PLT/GOT/重定位相关动态标签与数据结构。 */
    static bool validatePltGotRelocations(const PatchElf& elf, std::string* error);

    /** @brief 通过重新解析当前字节镜像，校验模型与原始字节一致性。 */
    static bool validateReparseConsistency(const PatchElf& elf, std::string* error);

    /** @brief 按顺序执行全部校验阶段。 */
    static bool validateAll(const PatchElf& elf, std::string* error);
};

#endif // VMP_PATCHBAY_ELF_VALIDATOR_H
