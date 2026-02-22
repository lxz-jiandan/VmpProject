#include "zElfProgramHeaderTable.h"

// 从原始 phdr 数组构建模型对象序列。
void zElfProgramHeaderTable::fromRaw(const Elf64_Phdr* raw, size_t count) {
    elements.clear();
    elements.reserve(count);
    for (size_t idx = 0; idx < count; ++idx) {
        elements.push_back(zProgramTableElement::fromPhdr(raw[idx]));
    }
}

// 将模型对象回写为原始 phdr 数组。
std::vector<Elf64_Phdr> zElfProgramHeaderTable::toRaw() const {
    std::vector<Elf64_Phdr> out;
    out.reserve(elements.size());
    for (const auto& element : elements) {
        out.push_back(element.toPhdr());
    }
    return out;
}

// 查找首个指定类型段（找不到返回 -1）。
int zElfProgramHeaderTable::findFirstByType(Elf64_Word type) const {
    for (size_t idx = 0; idx < elements.size(); ++idx) {
        if (elements[idx].type == type) {
            return (int)idx;
        }
    }
    return -1;
}

// 收集全部指定类型段索引。
std::vector<int> zElfProgramHeaderTable::findAllByType(Elf64_Word type) const {
    std::vector<int> out;
    for (size_t idx = 0; idx < elements.size(); ++idx) {
        if (elements[idx].type == type) {
            out.push_back((int)idx);
        }
    }
    return out;
}
