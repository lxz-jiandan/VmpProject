#include "zElfProgramHeaderTable.h"

// 从原始 phdr 数组构建模型对象序列。
void zElfProgramHeaderTable::fromRaw(const Elf64_Phdr* raw, size_t count) {
    elements.clear();
    elements.reserve(count);
    for (size_t idx = 0; idx < count; ++idx) {
        // 逐条转换为内部可读写模型，便于后续重构修改。
        elements.push_back(zProgramTableElement::fromPhdr(raw[idx]));
    }
}

// 将模型对象回写为原始 phdr 数组。
std::vector<Elf64_Phdr> zElfProgramHeaderTable::toRaw() const {
    std::vector<Elf64_Phdr> out;
    out.reserve(elements.size());
    for (const auto& element : elements) {
        // 序列化回标准 phdr 结构，供写回文件镜像。
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
    // 未找到目标类型。
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
    // 允许返回空数组，表示当前表不存在该类型段。
    return out;
}
