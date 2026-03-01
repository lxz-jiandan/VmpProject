/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfValidator.cpp
 * - 主要职责：Patch ELF 校验总入口：聚合各类校验器并生成一致性校验结果。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
// 校验流程编排实现：把多个校验阶段串成统一入口。
#include "zPatchElfValidator.h"

// 字符串拼接。
#include <string>

namespace {

// 给错误信息加上阶段前缀，方便快速定位失败位置。
void addErrorStage(std::string* error, const char* stage) {
    // 没有错误输出指针或阶段标签时直接返回。
    if (!error || !stage) {
        return;
    }
    // 下游没提供具体错误时，补一条通用失败信息。
    if (error->empty()) {
        *error = std::string(stage) + " validation failed";
        return;
    }
    // 下游已有错误细节时，前置阶段标签。
    *error = std::string(stage) + ": " + *error;
}

} // namespace

// 全量校验入口：按固定阶段顺序执行并附加阶段前缀。
bool zElfValidator::validateAll(const PatchElf& elf, std::string* error) {
    // 阶段顺序固定：先基础结构，再段布局，再动态重定位关系，最后重解析一致性。
    if (!validateBasic(elf, error)) {
        // 基础阶段失败。
        addErrorStage(error, "[BASIC]");
        return false;
    }
    // 段布局阶段。
    if (!validateProgramSegmentLayout(elf, error)) {
        addErrorStage(error, "[SEGMENT]");
        return false;
    }
    // 动态重定位/PLT/GOT 阶段。
    // 当前主链路聚焦动态重定位与可加载性；section/symbol 细粒度校验按需单独调用。
    if (!validatePltGotRelocations(elf, error)) {
        addErrorStage(error, "[PLT_GOT]");
        return false;
    }
    // 重解析一致性阶段。
    if (!validateReparseConsistency(elf, error)) {
        addErrorStage(error, "[REPARSE]");
        return false;
    }
    // 全部阶段通过。
    return true;
}
