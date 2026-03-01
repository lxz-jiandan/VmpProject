/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zProgramTable.cpp
 * - 主要职责：Program Header 表模型：管理段项集合及其查找、增删、重排逻辑。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
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

