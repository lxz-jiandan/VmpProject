#ifndef OVERT_ZELF_LOADER_H
#define OVERT_ZELF_LOADER_H

class zElf;

namespace zElfLoader {
/**
 * @brief 加载并完整解析 ELF 文件。
 * @param elf 目标 zElf 对象（输出）。
 * @param elf_path ELF 路径。
 * @return true 表示加载与解析成功。
 */
bool loadFileAndParse(zElf* elf, const char* elf_path);
}

#endif // OVERT_ZELF_LOADER_H
