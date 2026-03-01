/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElfLoader.h
 * - 主要职责：Patch ELF 加载层：把输入文件解析为可编辑模型并维护地址映射关系。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：稳定的接口声明、类型约束和调用契约。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#ifndef VMP_PATCHBAY_ELF_LOADER_H
#define VMP_PATCHBAY_ELF_LOADER_H

// PatchElf 前向声明：头文件只暴露接口，不引入完整定义。
class PatchElf;

namespace zElfLoader {

/**
 * @brief 加载并完整解析 ELF 文件。
 *
 * 说明：
 * - 这是命名空间级别的便捷入口；
 * - 内部会调用 PatchElf::loadElfFile 完成模型构建；
 * - 不抛异常，统一用 bool 返回结果。
 *
 * @param elf 目标 PatchElf 对象（输出）。
 * @param elfPath ELF 路径。
 * @return true 表示加载与解析成功。
 */
bool loadFileAndParse(PatchElf* elf, const char* elfPath);

} // namespace zElfLoader

#endif // VMP_PATCHBAY_ELF_LOADER_H
