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
