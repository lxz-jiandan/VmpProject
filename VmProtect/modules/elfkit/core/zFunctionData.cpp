/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 函数字节与指令序列的底层数据容器实现。
 * - 加固链路位置：翻译数据底座。
 * - 输入：函数机器码、偏移与大小。
 * - 输出：供翻译器与导出器复用的数据视图。
 */
#include "zFunctionData.h"

#include "zBitCodec.h"

#include <sstream>  // 组装可读错误消息。

namespace {

// 统一错误写入入口，便于上层输出详细失败原因。
static bool failWith(std::string* error, const std::string& message) {
    // 调用方传入 error 指针时写入详细错误原因。
    if (error) {
        *error = message;
    }
    // 统一返回 false，方便在表达式中直接 return failWith(...);。
    return false;
}

static uint32_t expectedInitWordCount(const zFunctionData& data) {
    // 根据 init_value_count 与首段 opcode 估算 init_value_words 理论长度。
    uint32_t expected = 0;
    for (uint32_t initIndex = 0; initIndex < data.init_value_count; initIndex++) {
        const uint32_t opcode = data.first_inst_opcodes[initIndex];
        // 每条初始化至少包含目标寄存器下标 + 1 个值。
        expected += 1;
        // opcode=1 需要额外一个 high32（组成 64bit 值）。
        expected += (opcode == 1u) ? 2u : 1u;
    }
    return expected;
}

static bool appendMismatch(std::string* error, const char* field, const std::string& lhs, const std::string& rhs) {
    // 统一 mismatch 文本格式，便于测试脚本按前缀筛选。
    std::ostringstream oss;
    oss << "encodedEquals mismatch: " << field << " lhs=" << lhs << " rhs=" << rhs;
    return failWith(error, oss.str());
}

}  // namespace

bool zFunctionData::validate(std::string* error) const {
    // 先校验所有 count 字段与容器长度的一致性。
    // marker 在协议里占固定 6bit，超界会导致编码溢出。
    if (marker > 63u) {
        return failWith(error, "marker must fit into 6 bits");
    }
    // first_inst_count 必须与 first_inst_opcodes 一一对应。
    if (first_inst_count != static_cast<uint32_t>(first_inst_opcodes.size())) {
        return failWith(error, "first_inst_count does not match first_inst_opcodes.size()");
    }
    // 外部初始化映射按 [reg, index] 成对存储。
    if (!external_init_words.empty() && external_init_words.size() != static_cast<size_t>(first_inst_count) * 2ull) {
        return failWith(error, "external_init_words.size() must be 2 * first_inst_count");
    }
    // type_count 与 type_tags 长度必须一致。
    if (type_count != static_cast<uint32_t>(type_tags.size())) {
        return failWith(error, "type_count does not match type_tags.size()");
    }
    // inst_count 与 inst_words 长度必须一致。
    if (inst_count != static_cast<uint32_t>(inst_words.size())) {
        return failWith(error, "inst_count does not match inst_words.size()");
    }
    // branch_count 与 branch_words 长度必须一致。
    if (branch_count != static_cast<uint32_t>(branch_words.size())) {
        return failWith(error, "branch_count does not match branch_words.size()");
    }
    // 间接跳转查找表需要地址/pc 一一对应。
    if (branch_lookup_words.size() != branch_lookup_addrs.size()) {
        return failWith(error, "branch_lookup_words.size() does not match branch_lookup_addrs.size()");
    }
    // 初始化条目数不能超过 first_inst_count。
    if (init_value_count > first_inst_count) {
        return failWith(error, "init_value_count cannot exceed first_inst_count");
    }
    // 无初始化条目时，init_value_words 必须为空。
    if (init_value_count == 0u) {
        if (!init_value_words.empty()) {
            return failWith(error, "init_value_words must be empty when init_value_count == 0");
        }
        // 无初始化数据时，其它约束已满足，可提前成功返回。
        return true;
    }
    // 有初始化条目时，opcode 列表长度必须覆盖 init_value_count。
    if (first_inst_opcodes.size() < init_value_count) {
        return failWith(error, "first_inst_opcodes is shorter than init_value_count");
    }
    // init_value_words 长度必须匹配 opcode 推导结果。
    if (init_value_words.size() != expectedInitWordCount(*this)) {
        return failWith(error, "init_value_words has unexpected size for init opcode layout");
    }
    // 所有约束满足。
    return true;
}

bool zFunctionData::serializeEncoded(std::vector<uint8_t>& out, std::string* error) const {
    // 先过一遍结构校验，避免写出非法流。
    if (!validate(error)) {
        return false;
    }

    // 按协议固定顺序写入，顺序必须与 deserializeEncoded 完全一致。
    vmp::base::bitcodec::BitWriter6 writer;
    // 写 marker（固定 6bit）。
    writer.write6(marker);
    // 写 register_count。
    writer.writeExtU32(register_count);
    // 写 first_inst_count。
    writer.writeExtU32(first_inst_count);
    // 写 first_inst_opcodes。
    for (uint32_t value : first_inst_opcodes) {
        writer.writeExtU32(value);
    }
    // 写 external_init_words（可为空）。
    for (uint32_t value : external_init_words) {
        writer.writeExtU32(value);
    }
    // 写 type_count。
    writer.writeExtU32(type_count);
    // 写 type_tags。
    for (uint32_t value : type_tags) {
        writer.writeExtU32(value);
    }
    // 写 init_value_count。
    writer.writeExtU32(init_value_count);
    // 写 init_value_words。
    for (uint32_t value : init_value_words) {
        writer.writeExtU32(value);
    }
    // 写 inst_count。
    writer.writeExtU32(inst_count);
    // 写 inst_words。
    for (uint32_t value : inst_words) {
        writer.writeExtU32(value);
    }
    // 写 branch_count。
    writer.writeExtU32(branch_count);
    // 写 branch_words。
    for (uint32_t value : branch_words) {
        writer.writeExtU32(value);
    }
    // 写 branch_lookup_words 数量。
    writer.writeExtU32(static_cast<uint32_t>(branch_lookup_words.size()));
    // 写 branch_lookup_words 内容。
    for (uint32_t value : branch_lookup_words) {
        writer.writeExtU32(value);
    }
    // 写 branch_lookup_addrs 数量（与 branch_lookup_words 数量保持一致）。
    writer.writeExtU32(static_cast<uint32_t>(branch_lookup_addrs.size()));
    // 写 branch_lookup_addrs 内容。
    for (uint64_t value : branch_lookup_addrs) {
        vmp::base::bitcodec::writeU64AsU32Pair(&writer, value);
    }
    // 写 branch_addrs 数量。
    writer.writeExtU32(static_cast<uint32_t>(branch_addrs.size()));
    // 写 branch_addrs 内容。
    for (uint64_t value : branch_addrs) {
        vmp::base::bitcodec::writeU64AsU32Pair(&writer, value);
    }
    // 最后写 function_offset。
    vmp::base::bitcodec::writeU64AsU32Pair(&writer, function_offset);

    // 输出最终编码字节流。
    out = writer.finish();
    // 编码完成。
    return true;
}

bool zFunctionData::deserializeEncoded(const uint8_t* data, size_t len, zFunctionData& out, std::string* error) {
    // 输入为空直接拒绝。
    if (data == nullptr || len == 0) {
        return failWith(error, "input buffer is empty");
    }

    // 每次反序列化都重置输出对象，避免残留旧数据。
    out = zFunctionData{};
    // 构造位读取器，后续按协议顺序流式读取。
    vmp::base::bitcodec::BitReader6 reader(data, len);

    // 读取 marker（固定 6bit）。
    uint32_t value = 0;
    if (!reader.read6(&value)) {
        return failWith(error, "failed to read marker");
    }
    out.marker = value;

    // 读取 register_count。
    if (!reader.readExtU32(&out.register_count)) {
        return failWith(error, "failed to read register_count");
    }
    // 读取 first_inst_count。
    if (!reader.readExtU32(&out.first_inst_count)) {
        return failWith(error, "failed to read first_inst_count");
    }

    // 按 first_inst_count 读取 opcode 列表。
    out.first_inst_opcodes.resize(out.first_inst_count);
    for (uint32_t firstInstIndex = 0; firstInstIndex < out.first_inst_count; firstInstIndex++) {
        if (!reader.readExtU32(&out.first_inst_opcodes[firstInstIndex])) {
            return failWith(error, "failed to read first_inst_opcodes");
        }
    }

    // external_init_words 按 2 * first_inst_count 读取。
    if (out.first_inst_count > 0) {
        out.external_init_words.resize(static_cast<size_t>(out.first_inst_count) * 2ull);
        for (uint32_t externalInitWordIndex = 0; externalInitWordIndex < out.first_inst_count * 2u; externalInitWordIndex++) {
            if (!reader.readExtU32(&out.external_init_words[externalInitWordIndex])) {
                return failWith(error, "failed to read external_init_words");
            }
        }
    }

    if (!reader.readExtU32(&out.type_count)) {
        return failWith(error, "failed to read type_count");
    }
    // 读取 type_tags。
    out.type_tags.resize(out.type_count);
    for (uint32_t typeIndex = 0; typeIndex < out.type_count; typeIndex++) {
        if (!reader.readExtU32(&out.type_tags[typeIndex])) {
            return failWith(error, "failed to read type_tags");
        }
    }

    // 读取 init_value_count。
    if (!reader.readExtU32(&out.init_value_count)) {
        return failWith(error, "failed to read init_value_count");
    }
    // 基本边界约束。
    if (out.init_value_count > out.first_inst_count) {
        return failWith(error, "init_value_count exceeds first_inst_count");
    }
    // 根据 init_value_count 逐条还原 init_value_words。
    out.init_value_words.clear();
    out.init_value_words.reserve(static_cast<size_t>(out.init_value_count) * 3ull);
    for (uint32_t initIndex = 0; initIndex < out.init_value_count; initIndex++) {
        // 每条先读目标寄存器索引。
        uint32_t regIndex = 0;
        if (!reader.readExtU32(&regIndex)) {
            return failWith(error, "failed to read init reg index");
        }
        out.init_value_words.push_back(regIndex);

        // 再读低 32bit 或普通值。
        uint32_t word = 0;
        if (!reader.readExtU32(&word)) {
            return failWith(error, "failed to read init value");
        }
        out.init_value_words.push_back(word);

        // opcode=1 时还要读取高 32bit。
        if (out.first_inst_opcodes[initIndex] == 1u) {
            if (!reader.readExtU32(&word)) {
                return failWith(error, "failed to read init high value");
            }
            out.init_value_words.push_back(word);
        }
    }

    if (!reader.readExtU32(&out.inst_count)) {
        return failWith(error, "failed to read inst_count");
    }
    // 读取 inst_words。
    out.inst_words.resize(out.inst_count);
    for (uint32_t instIndex = 0; instIndex < out.inst_count; instIndex++) {
        if (!reader.readExtU32(&out.inst_words[instIndex])) {
            return failWith(error, "failed to read inst_words");
        }
    }

    if (!reader.readExtU32(&out.branch_count)) {
        return failWith(error, "failed to read branch_count");
    }
    // 读取 branch_words。
    out.branch_words.resize(out.branch_count);
    for (uint32_t branchIndex = 0; branchIndex < out.branch_count; branchIndex++) {
        if (!reader.readExtU32(&out.branch_words[branchIndex])) {
            return failWith(error, "failed to read branch_words");
        }
    }

    // 读取 branch_lookup_words 数量。
    uint32_t branchLookupCount = 0;
    if (!reader.readExtU32(&branchLookupCount)) {
        return failWith(error, "failed to read branch_lookup_count");
    }
    // 读取 branch_lookup_words 列表。
    out.branch_lookup_words.resize(branchLookupCount);
    for (uint32_t branchLookupIndex = 0; branchLookupIndex < branchLookupCount; branchLookupIndex++) {
        if (!reader.readExtU32(&out.branch_lookup_words[branchLookupIndex])) {
            return failWith(error, "failed to read branch_lookup_words");
        }
    }
    // 读取 branch_lookup_addrs 数量。
    uint32_t branchLookupAddrCount = 0;
    if (!reader.readExtU32(&branchLookupAddrCount)) {
        return failWith(error, "failed to read branch_lookup_addr_count");
    }
    if (branchLookupAddrCount != branchLookupCount) {
        return failWith(error, "branch_lookup_addr_count does not match branch_lookup_count");
    }
    // 读取 branch_lookup_addrs 列表。
    out.branch_lookup_addrs.resize(branchLookupAddrCount);
    for (uint32_t branchLookupAddrIndex = 0; branchLookupAddrIndex < branchLookupAddrCount; branchLookupAddrIndex++) {
        if (!vmp::base::bitcodec::readU64FromU32Pair(&reader, &out.branch_lookup_addrs[branchLookupAddrIndex])) {
            return failWith(error, "failed to read branch_lookup_addrs");
        }
    }

    // 读取 branch_addrs 数量。
    uint32_t branchAddrCount = 0;
    if (!reader.readExtU32(&branchAddrCount)) {
        return failWith(error, "failed to read branch_addr_count");
    }
    // 读取 branch_addrs 列表。
    out.branch_addrs.resize(branchAddrCount);
    for (uint32_t branchAddrIndex = 0; branchAddrIndex < branchAddrCount; branchAddrIndex++) {
        if (!vmp::base::bitcodec::readU64FromU32Pair(&reader, &out.branch_addrs[branchAddrIndex])) {
            return failWith(error, "failed to read branch_addrs");
        }
    }
    // 最后读取 function_offset。
    if (!vmp::base::bitcodec::readU64FromU32Pair(&reader, &out.function_offset)) {
        return failWith(error, "failed to read function_offset");
    }

    // 反序列化完成后再做一次完整一致性校验。
    return out.validate(error);
}

bool zFunctionData::encodedEquals(const zFunctionData& other, std::string* error) const {
    // 字段逐项比对，优先返回第一处差异，便于定位问题。
    if (marker != other.marker) {
        // marker 不一致通常意味着编码头或协议版本差异。
        return appendMismatch(error, "marker", std::to_string(marker), std::to_string(other.marker));
    }
    if (register_count != other.register_count) {
        // 寄存器槽数量不同会直接影响执行语义。
        return appendMismatch(error, "register_count", std::to_string(register_count), std::to_string(other.register_count));
    }
    if (first_inst_count != other.first_inst_count) {
        return appendMismatch(error, "first_inst_count", std::to_string(first_inst_count), std::to_string(other.first_inst_count));
    }
    if (first_inst_opcodes != other.first_inst_opcodes) {
        // 初始化 opcode 序列不同，直接失败。
        return failWith(error, "encodedEquals mismatch: first_inst_opcodes");
    }
    if (external_init_words != other.external_init_words) {
        // 外部初始化映射不同，直接失败。
        return failWith(error, "encodedEquals mismatch: external_init_words");
    }
    if (type_count != other.type_count) {
        return appendMismatch(error, "type_count", std::to_string(type_count), std::to_string(other.type_count));
    }
    if (type_tags != other.type_tags) {
        // 类型标签表不同会导致运行时解释类型不一致。
        return failWith(error, "encodedEquals mismatch: type_tags");
    }
    if (init_value_count != other.init_value_count) {
        return appendMismatch(error, "init_value_count", std::to_string(init_value_count), std::to_string(other.init_value_count));
    }
    if (init_value_words != other.init_value_words) {
        // 初始化值流不同，直接失败。
        return failWith(error, "encodedEquals mismatch: init_value_words");
    }
    if (inst_count != other.inst_count) {
        return appendMismatch(error, "inst_count", std::to_string(inst_count), std::to_string(other.inst_count));
    }
    if (inst_words != other.inst_words) {
        // 指令流不同，直接失败。
        return failWith(error, "encodedEquals mismatch: inst_words");
    }
    if (branch_count != other.branch_count) {
        return appendMismatch(error, "branch_count", std::to_string(branch_count), std::to_string(other.branch_count));
    }
    if (branch_words != other.branch_words) {
        // 本地分支目标不同，直接失败。
        return failWith(error, "encodedEquals mismatch: branch_words");
    }
    if (branch_lookup_words != other.branch_lookup_words) {
        // 间接跳转本地目标 pc 表不同，直接失败。
        return failWith(error, "encodedEquals mismatch: branch_lookup_words");
    }
    if (branch_lookup_addrs != other.branch_lookup_addrs) {
        // 间接跳转本地目标地址表不同，直接失败。
        return failWith(error, "encodedEquals mismatch: branch_lookup_addrs");
    }
    if (branch_addrs != other.branch_addrs) {
        // 全局调用地址表不同，直接失败。
        return failWith(error, "encodedEquals mismatch: branch_addrs");
    }
    if (function_offset != other.function_offset) {
        return appendMismatch(error, "function_offset", std::to_string(function_offset), std::to_string(other.function_offset));
    }
    // 全部字段一致。
    return true;
}


