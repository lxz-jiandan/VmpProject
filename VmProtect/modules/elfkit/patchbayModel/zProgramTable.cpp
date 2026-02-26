#include "zProgramTable.h"

// 从原始 phdr 数组构建模型对象序列。
void zElfProgramHeaderTable::fromRaw(const Elf64_Phdr* raw, size_t count) {
    // 清空旧模型。
    elements.clear();
    // 预留容量减少扩容次数。
    elements.reserve(count);
    // 逐条转换。
    for (size_t programHeaderIndex = 0; programHeaderIndex < count; ++programHeaderIndex) {
        // 逐条转换为内部可读写模型，便于后续重构修改。
        elements.push_back(zProgramTableElement::fromPhdr(raw[programHeaderIndex]));
    }
}

// 将模型对象回写为原始 phdr 数组。
std::vector<Elf64_Phdr> zElfProgramHeaderTable::toRaw() const {
    // 输出缓冲。
    std::vector<Elf64_Phdr> out;
    // 预留容量。
    out.reserve(elements.size());
    // 顺序序列化每个段。
    for (const auto& element : elements) {
        // 序列化回标准 phdr 结构，供写回文件镜像。
        out.push_back(element.toPhdr());
    }
    return out;
}

// 查找首个指定类型段（找不到返回 -1）。
int zElfProgramHeaderTable::getFirstByType(Elf64_Word type) const {
    // 线性扫描。
    for (size_t programHeaderIndex = 0;
         programHeaderIndex < elements.size();
         ++programHeaderIndex) {
        if (elements[programHeaderIndex].type == type) {
            return (int)programHeaderIndex;
        }
    }
    // 未找到目标类型。
    return -1;
}

// 收集全部指定类型段索引。
std::vector<int> zElfProgramHeaderTable::getAllByType(Elf64_Word type) const {
    // 结果数组。
    std::vector<int> out;
    // 顺序扫描。
    for (size_t programHeaderIndex = 0;
         programHeaderIndex < elements.size();
         ++programHeaderIndex) {
        if (elements[programHeaderIndex].type == type) {
            out.push_back((int)programHeaderIndex);
        }
    }
    // 允许返回空数组，表示当前表不存在该类型段。
    return out;
}

