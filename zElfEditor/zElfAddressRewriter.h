#ifndef OVERT_ZELF_ADDRESS_REWRITER_H
#define OVERT_ZELF_ADDRESS_REWRITER_H

#include "elf.h"

#include <functional>
#include <string>

class zElf;

/**
 * @brief 地址重写器：在段/节地址整体平移后，修复 ELF 内部引用。
 *
 * 典型场景：注入、重构导致虚拟地址区间发生迁移。
 * 该类负责按回调规则重写 `.dynamic`、重定位表、打包重定位流等地址字段。
 */
class zElfAddressRewriter {
public:
    /**
     * @brief 重写常规地址引用（动态表、重定位槽等）。
     * @param elf 目标 ELF 对象。
     * @param relocate_old_vaddr 旧地址 -> 新地址的映射回调。
     * @param error [输出] 错误信息。
     * @return true 表示重写成功。
     */
    static bool rewriteAfterAddressShift(
            zElf* elf,
            const std::function<Elf64_Addr(Elf64_Addr)>& relocate_old_vaddr,
            std::string* error);

    /**
     * @brief 重写打包重定位（如 Android APS2 / DT_RELR）中的地址。
     * @param elf 目标 ELF 对象。
     * @param relocate_old_vaddr 旧地址 -> 新地址的映射回调。
     * @param error [输出] 错误信息。
     * @return true 表示重写成功。
     */
    static bool rewritePackedRelocationsAfterShift(
            zElf* elf,
            const std::function<Elf64_Addr(Elf64_Addr)>& relocate_old_vaddr,
            std::string* error);

private:
    /**
     * @brief 优先通过 PT_LOAD 映射读取 64 位值，失败时回退节视图。
     */
    static bool readU64MappedSegmentFirst(const zElf* elf, Elf64_Addr addr, uint64_t* out_value);

    /**
     * @brief 优先通过 PT_LOAD 映射写入 64 位值，失败时回退节视图。
     */
    static bool writeU64MappedSegmentFirst(zElf* elf, Elf64_Addr addr, uint64_t value);

    /**
     * @brief 将动态条目写入 PT_DYNAMIC 段。
     */
    static bool writeDynamicEntriesToPhdr(zElf* elf,
                                          const std::vector<Elf64_Dyn>& entries,
                                          Elf64_Off off,
                                          Elf64_Xword size,
                                          std::string* error);
};

#endif // OVERT_ZELF_ADDRESS_REWRITER_H
