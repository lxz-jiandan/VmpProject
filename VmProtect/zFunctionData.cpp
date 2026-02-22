/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 函数字节与指令序列的底层数据容器实现。
 * - 加固链路位置：翻译数据底座。
 * - 输入：函数机器码、偏移与大小。
 * - 输出：供翻译器与导出器复用的数据视图。
 */
#include "zFunctionData.h"

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

class BitWriter6 {
public:
    // 写入固定 6bit 值（低位优先拼接到 bit_buf_）。
    void write6bits(uint32_t value) {
        // 仅保留低 6 bit。
        value &= 0x3Fu;
        // 把 6 bit 追加到临时 bit 缓冲。
        bit_buf_ |= (value << bit_count_);
        // bit 缓冲有效位数增加 6。
        bit_count_ += 6;
        // 每累计到 8bit 就吐出一个字节。
        while (bit_count_ >= 8) {
            out_.push_back(static_cast<uint8_t>(bit_buf_ & 0xFFu));
            bit_buf_ >>= 8;
            bit_count_ -= 8;
        }
    }

    // 写入 6bit 扩展整数：每 5bit 一组，高位用 continuation bit 标记。
    void write6bitExt(uint32_t value) {
        // 小值（<32）可以单组直接编码，无 continuation。
        if (value < 32u) {
            write6bits(value);
            return;
        }
        // 大值按 5bit 分组，每组带 continuation 标记位 0x20。
        while (value >= 32u) {
            write6bits(0x20u | (value & 0x1Fu));
            value >>= 5;
        }
        // 最后一组（最高位）不带 continuation 标记。
        write6bits(value & 0x1Fu);
    }

    // 刷新剩余 bit，返回完整字节流。
    std::vector<uint8_t> finish() {
        // 末尾不足 8bit 的残留需要补成一个字节输出。
        if (bit_count_ > 0) {
            out_.push_back(static_cast<uint8_t>(bit_buf_ & 0xFFu));
        }
        // 重置内部状态，避免误复用造成串流污染。
        bit_buf_ = 0;
        bit_count_ = 0;
        // 以 move 返回结果，避免额外拷贝。
        return std::move(out_);
    }

private:
    std::vector<uint8_t> out_;
    uint32_t bit_buf_ = 0;
    int bit_count_ = 0;
};

class BitReader6 {
public:
    // 绑定输入字节流与长度。
    BitReader6(const uint8_t* data, size_t len) : data_(data), len_(len) {
        // 构造后从 bit_pos_=0 开始顺序读取。
    }

    // 读取固定 6bit 值，与 BitWriter6::write6bits 对应。
    bool read6bits(uint32_t& out) {
        // 总可读取 bit 数。
        const uint64_t total_bits = static_cast<uint64_t>(len_) * 8ull;
        // 剩余位数不足 6 时读取失败。
        if (bit_pos_ + 6ull > total_bits) {
            return false;
        }
        // 汇总当前 6bit 值。
        uint32_t value = 0;
        for (uint32_t i = 0; i < 6; i++) {
            // 逐 bit 计算全局位位置。
            const uint64_t pos = bit_pos_ + i;
            // 映射到对应字节。
            const uint8_t byte = data_[static_cast<size_t>(pos / 8ull)];
            // 提取该字节内对应 bit。
            const uint32_t bit = (byte >> static_cast<uint32_t>(pos % 8ull)) & 0x1u;
            // 按低位优先重组到 value。
            value |= (bit << i);
        }
        // 消费 6bit。
        bit_pos_ += 6ull;
        // 输出结果。
        out = value;
        return true;
    }

    // 读取 6bit 扩展整数，与 BitWriter6::write6bitExt 对应。
    bool read6bitExt(uint32_t& out) {
        // 先读第一组。
        uint32_t chunk = 0;
        if (!read6bits(chunk)) {
            return false;
        }

        // 当前累计值先放入低 5bit。
        uint32_t value = chunk & 0x1Fu;
        // 下一组写入偏移。
        uint32_t shift = 5;
        // 保护计数，避免恶意数据导致无限循环。
        uint32_t guard = 0;
        // continuation 标记存在时继续读后续分组。
        while (chunk & 0x20u) {
            if (++guard > 7) {
                return false;
            }
            if (!read6bits(chunk)) {
                return false;
            }
            // 追加后续 5bit 数据。
            value |= ((chunk & 0x1Fu) << shift);
            shift += 5;
        }

        // 输出最终还原值。
        out = value;
        return true;
    }

private:
    // 输入数据起始地址。
    const uint8_t* data_ = nullptr;
    // 输入字节总长度。
    size_t len_ = 0;
    // 当前读取到的 bit 偏移（相对 data_ 起点）。
    uint64_t bit_pos_ = 0;
};

static uint32_t expectedInitWordCount(const zFunctionData& data) {
    // 根据 init_value_count 与首段 opcode 估算 init_value_words 理论长度。
    uint32_t expected = 0;
    for (uint32_t i = 0; i < data.init_value_count; i++) {
        const uint32_t opcode = data.first_inst_opcodes[i];
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

static void writeU64AsU32Pair(BitWriter6& writer, uint64_t value) {
    // 统一按 low32/high32 写入，保持跨平台稳定编码。
    // 低 32bit。
    const uint32_t low = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    // 高 32bit。
    const uint32_t high = static_cast<uint32_t>((value >> 32u) & 0xFFFFFFFFull);
    // 顺序写入 low/high。
    writer.write6bitExt(low);
    writer.write6bitExt(high);
}

static bool readU64FromU32Pair(BitReader6& reader, uint64_t& value) {
    // 先读 low/high 两段 32bit。
    uint32_t low = 0;
    uint32_t high = 0;
    if (!reader.read6bitExt(low)) {
        return false;
    }
    if (!reader.read6bitExt(high)) {
        return false;
    }
    // 还原为完整 64bit 值。
    value = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32u);
    return true;
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
    BitWriter6 writer;
    // 写 marker（固定 6bit）。
    writer.write6bits(marker);
    // 写 register_count。
    writer.write6bitExt(register_count);
    // 写 first_inst_count。
    writer.write6bitExt(first_inst_count);
    // 写 first_inst_opcodes。
    for (uint32_t value : first_inst_opcodes) {
        writer.write6bitExt(value);
    }
    // 写 external_init_words（可为空）。
    for (uint32_t value : external_init_words) {
        writer.write6bitExt(value);
    }
    // 写 type_count。
    writer.write6bitExt(type_count);
    // 写 type_tags。
    for (uint32_t value : type_tags) {
        writer.write6bitExt(value);
    }
    // 写 init_value_count。
    writer.write6bitExt(init_value_count);
    // 写 init_value_words。
    for (uint32_t value : init_value_words) {
        writer.write6bitExt(value);
    }
    // 写 inst_count。
    writer.write6bitExt(inst_count);
    // 写 inst_words。
    for (uint32_t value : inst_words) {
        writer.write6bitExt(value);
    }
    // 写 branch_count。
    writer.write6bitExt(branch_count);
    // 写 branch_words。
    for (uint32_t value : branch_words) {
        writer.write6bitExt(value);
    }
    // 写 branch_addrs 数量。
    writer.write6bitExt(static_cast<uint32_t>(branch_addrs.size()));
    // 写 branch_addrs 内容。
    for (uint64_t value : branch_addrs) {
        writeU64AsU32Pair(writer, value);
    }
    // 最后写 function_offset。
    writeU64AsU32Pair(writer, function_offset);

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
    BitReader6 reader(data, len);

    // 读取 marker（固定 6bit）。
    uint32_t value = 0;
    if (!reader.read6bits(value)) {
        return failWith(error, "failed to read marker");
    }
    out.marker = value;

    // 读取 register_count。
    if (!reader.read6bitExt(out.register_count)) {
        return failWith(error, "failed to read register_count");
    }
    // 读取 first_inst_count。
    if (!reader.read6bitExt(out.first_inst_count)) {
        return failWith(error, "failed to read first_inst_count");
    }

    // 按 first_inst_count 读取 opcode 列表。
    out.first_inst_opcodes.resize(out.first_inst_count);
    for (uint32_t i = 0; i < out.first_inst_count; i++) {
        if (!reader.read6bitExt(out.first_inst_opcodes[i])) {
            return failWith(error, "failed to read first_inst_opcodes");
        }
    }

    // external_init_words 按 2 * first_inst_count 读取。
    if (out.first_inst_count > 0) {
        out.external_init_words.resize(static_cast<size_t>(out.first_inst_count) * 2ull);
        for (uint32_t i = 0; i < out.first_inst_count * 2u; i++) {
            if (!reader.read6bitExt(out.external_init_words[i])) {
                return failWith(error, "failed to read external_init_words");
            }
        }
    }

    if (!reader.read6bitExt(out.type_count)) {
        return failWith(error, "failed to read type_count");
    }
    // 读取 type_tags。
    out.type_tags.resize(out.type_count);
    for (uint32_t i = 0; i < out.type_count; i++) {
        if (!reader.read6bitExt(out.type_tags[i])) {
            return failWith(error, "failed to read type_tags");
        }
    }

    // 读取 init_value_count。
    if (!reader.read6bitExt(out.init_value_count)) {
        return failWith(error, "failed to read init_value_count");
    }
    // 基本边界约束。
    if (out.init_value_count > out.first_inst_count) {
        return failWith(error, "init_value_count exceeds first_inst_count");
    }
    // 根据 init_value_count 逐条还原 init_value_words。
    out.init_value_words.clear();
    out.init_value_words.reserve(static_cast<size_t>(out.init_value_count) * 3ull);
    for (uint32_t i = 0; i < out.init_value_count; i++) {
        // 每条先读目标寄存器索引。
        uint32_t reg_idx = 0;
        if (!reader.read6bitExt(reg_idx)) {
            return failWith(error, "failed to read init reg idx");
        }
        out.init_value_words.push_back(reg_idx);

        // 再读低 32bit 或普通值。
        uint32_t word = 0;
        if (!reader.read6bitExt(word)) {
            return failWith(error, "failed to read init value");
        }
        out.init_value_words.push_back(word);

        // opcode=1 时还要读取高 32bit。
        if (out.first_inst_opcodes[i] == 1u) {
            if (!reader.read6bitExt(word)) {
                return failWith(error, "failed to read init high value");
            }
            out.init_value_words.push_back(word);
        }
    }

    if (!reader.read6bitExt(out.inst_count)) {
        return failWith(error, "failed to read inst_count");
    }
    // 读取 inst_words。
    out.inst_words.resize(out.inst_count);
    for (uint32_t i = 0; i < out.inst_count; i++) {
        if (!reader.read6bitExt(out.inst_words[i])) {
            return failWith(error, "failed to read inst_words");
        }
    }

    if (!reader.read6bitExt(out.branch_count)) {
        return failWith(error, "failed to read branch_count");
    }
    // 读取 branch_words。
    out.branch_words.resize(out.branch_count);
    for (uint32_t i = 0; i < out.branch_count; i++) {
        if (!reader.read6bitExt(out.branch_words[i])) {
            return failWith(error, "failed to read branch_words");
        }
    }

    // 读取 branch_addrs 数量。
    uint32_t branch_addr_count = 0;
    if (!reader.read6bitExt(branch_addr_count)) {
        return failWith(error, "failed to read branch_addr_count");
    }
    // 读取 branch_addrs 列表。
    out.branch_addrs.resize(branch_addr_count);
    for (uint32_t i = 0; i < branch_addr_count; i++) {
        if (!readU64FromU32Pair(reader, out.branch_addrs[i])) {
            return failWith(error, "failed to read branch_addrs");
        }
    }
    // 最后读取 function_offset。
    if (!readU64FromU32Pair(reader, out.function_offset)) {
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
