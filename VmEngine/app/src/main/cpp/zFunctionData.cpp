#include "zFunctionData.h"

#include <sstream>

namespace {

// 统一错误写入入口，便于上层输出详细失败原因。
static bool failWith(std::string* error, const std::string& message) {
    if (error) {
        *error = message;
    }
    return false;
}

class BitWriter6 {
public:
    // 写入固定 6bit 值（低位优先拼接到 bit_buf_）。
    void write6bits(uint32_t value) {
        value &= 0x3Fu;
        bit_buf_ |= (value << bit_count_);
        bit_count_ += 6;
        while (bit_count_ >= 8) {
            out_.push_back(static_cast<uint8_t>(bit_buf_ & 0xFFu));
            bit_buf_ >>= 8;
            bit_count_ -= 8;
        }
    }

    // 写入 6bit 扩展整数：每 5bit 一组，高位用 continuation bit 标记。
    void write6bitExt(uint32_t value) {
        if (value < 32u) {
            write6bits(value);
            return;
        }
        while (value >= 32u) {
            write6bits(0x20u | (value & 0x1Fu));
            value >>= 5;
        }
        write6bits(value & 0x1Fu);
    }

    // 刷新剩余 bit，返回完整字节流。
    std::vector<uint8_t> finish() {
        if (bit_count_ > 0) {
            out_.push_back(static_cast<uint8_t>(bit_buf_ & 0xFFu));
        }
        bit_buf_ = 0;
        bit_count_ = 0;
        return std::move(out_);
    }

private:
    std::vector<uint8_t> out_;
    uint32_t bit_buf_ = 0;
    int bit_count_ = 0;
};

class BitReader6 {
public:
    BitReader6(const uint8_t* data, size_t len) : data_(data), len_(len) {}

    // 读取固定 6bit 值，与 BitWriter6::write6bits 对应。
    bool read6bits(uint32_t& out) {
        const uint64_t total_bits = static_cast<uint64_t>(len_) * 8ull;
        if (bit_pos_ + 6ull > total_bits) {
            return false;
        }
        uint32_t value = 0;
        for (uint32_t i = 0; i < 6; i++) {
            const uint64_t pos = bit_pos_ + i;
            const uint8_t byte = data_[static_cast<size_t>(pos / 8ull)];
            const uint32_t bit = (byte >> static_cast<uint32_t>(pos % 8ull)) & 0x1u;
            value |= (bit << i);
        }
        bit_pos_ += 6ull;
        out = value;
        return true;
    }

    // 读取 6bit 扩展整数，与 BitWriter6::write6bitExt 对应。
    bool read6bitExt(uint32_t& out) {
        uint32_t chunk = 0;
        if (!read6bits(chunk)) {
            return false;
        }

        uint32_t value = chunk & 0x1Fu;
        uint32_t shift = 5;
        uint32_t guard = 0;
        while (chunk & 0x20u) {
            if (++guard > 7) {
                return false;
            }
            if (!read6bits(chunk)) {
                return false;
            }
            value |= ((chunk & 0x1Fu) << shift);
            shift += 5;
        }

        out = value;
        return true;
    }

private:
    const uint8_t* data_ = nullptr;
    size_t len_ = 0;
    uint64_t bit_pos_ = 0;
};

static uint32_t expectedInitWordCount(const zFunctionData& data) {
    uint32_t expected = 0;
    for (uint32_t i = 0; i < data.init_value_count; i++) {
        const uint32_t opcode = data.first_inst_opcodes[i];
        // 每条初始化至少包含目标寄存器下标 + 1 个值。
        expected += 1;
        expected += (opcode == 1u) ? 2u : 1u;
    }
    return expected;
}

static bool appendMismatch(std::string* error, const char* field, const std::string& lhs, const std::string& rhs) {
    std::ostringstream oss;
    oss << "encodedEquals mismatch: " << field << " lhs=" << lhs << " rhs=" << rhs;
    return failWith(error, oss.str());
}

static void writeU64AsU32Pair(BitWriter6& writer, uint64_t value) {
    // 统一按 low32/high32 写入，保持跨平台稳定编码。
    const uint32_t low = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    const uint32_t high = static_cast<uint32_t>((value >> 32u) & 0xFFFFFFFFull);
    writer.write6bitExt(low);
    writer.write6bitExt(high);
}

static bool readU64FromU32Pair(BitReader6& reader, uint64_t& value) {
    uint32_t low = 0;
    uint32_t high = 0;
    if (!reader.read6bitExt(low)) {
        return false;
    }
    if (!reader.read6bitExt(high)) {
        return false;
    }
    value = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32u);
    return true;
}

}  // namespace

bool zFunctionData::validate(std::string* error) const {
    // 先校验所有 count 字段与容器长度的一致性。
    if (marker > 63u) {
        return failWith(error, "marker must fit into 6 bits");
    }
    if (first_inst_count != static_cast<uint32_t>(first_inst_opcodes.size())) {
        return failWith(error, "first_inst_count does not match first_inst_opcodes.size()");
    }
    if (!external_init_words.empty() && external_init_words.size() != static_cast<size_t>(first_inst_count) * 2ull) {
        return failWith(error, "external_init_words.size() must be 2 * first_inst_count");
    }
    if (type_count != static_cast<uint32_t>(type_tags.size())) {
        return failWith(error, "type_count does not match type_tags.size()");
    }
    if (inst_count != static_cast<uint32_t>(inst_words.size())) {
        return failWith(error, "inst_count does not match inst_words.size()");
    }
    if (branch_count != static_cast<uint32_t>(branch_words.size())) {
        return failWith(error, "branch_count does not match branch_words.size()");
    }
    if (init_value_count > first_inst_count) {
        return failWith(error, "init_value_count cannot exceed first_inst_count");
    }
    if (init_value_count == 0u) {
        if (!init_value_words.empty()) {
            return failWith(error, "init_value_words must be empty when init_value_count == 0");
        }
        return true;
    }
    if (first_inst_opcodes.size() < init_value_count) {
        return failWith(error, "first_inst_opcodes is shorter than init_value_count");
    }
    if (init_value_words.size() != expectedInitWordCount(*this)) {
        return failWith(error, "init_value_words has unexpected size for init opcode layout");
    }
    return true;
}

bool zFunctionData::serializeEncoded(std::vector<uint8_t>& out, std::string* error) const {
    if (!validate(error)) {
        return false;
    }

    // 按协议固定顺序写入，顺序必须与 deserializeEncoded 完全一致。
    BitWriter6 writer;
    writer.write6bits(marker);
    writer.write6bitExt(register_count);
    writer.write6bitExt(first_inst_count);
    for (uint32_t value : first_inst_opcodes) {
        writer.write6bitExt(value);
    }
    for (uint32_t value : external_init_words) {
        writer.write6bitExt(value);
    }
    writer.write6bitExt(type_count);
    for (uint32_t value : type_tags) {
        writer.write6bitExt(value);
    }
    writer.write6bitExt(init_value_count);
    for (uint32_t value : init_value_words) {
        writer.write6bitExt(value);
    }
    writer.write6bitExt(inst_count);
    for (uint32_t value : inst_words) {
        writer.write6bitExt(value);
    }
    writer.write6bitExt(branch_count);
    for (uint32_t value : branch_words) {
        writer.write6bitExt(value);
    }
    writer.write6bitExt(static_cast<uint32_t>(branch_addrs.size()));
    for (uint64_t value : branch_addrs) {
        writeU64AsU32Pair(writer, value);
    }
    writeU64AsU32Pair(writer, function_offset);

    out = writer.finish();
    return true;
}

bool zFunctionData::deserializeEncoded(const uint8_t* data, size_t len, zFunctionData& out, std::string* error) {
    if (data == nullptr || len == 0) {
        return failWith(error, "input buffer is empty");
    }

    // 每次反序列化都重置输出对象，避免残留旧数据。
    out = zFunctionData{};
    BitReader6 reader(data, len);

    uint32_t value = 0;
    if (!reader.read6bits(value)) {
        return failWith(error, "failed to read marker");
    }
    out.marker = value;

    if (!reader.read6bitExt(out.register_count)) {
        return failWith(error, "failed to read register_count");
    }
    if (!reader.read6bitExt(out.first_inst_count)) {
        return failWith(error, "failed to read first_inst_count");
    }

    out.first_inst_opcodes.resize(out.first_inst_count);
    for (uint32_t i = 0; i < out.first_inst_count; i++) {
        if (!reader.read6bitExt(out.first_inst_opcodes[i])) {
            return failWith(error, "failed to read first_inst_opcodes");
        }
    }

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
    out.type_tags.resize(out.type_count);
    for (uint32_t i = 0; i < out.type_count; i++) {
        if (!reader.read6bitExt(out.type_tags[i])) {
            return failWith(error, "failed to read type_tags");
        }
    }

    if (!reader.read6bitExt(out.init_value_count)) {
        return failWith(error, "failed to read init_value_count");
    }
    if (out.init_value_count > out.first_inst_count) {
        return failWith(error, "init_value_count exceeds first_inst_count");
    }
    out.init_value_words.clear();
    out.init_value_words.reserve(static_cast<size_t>(out.init_value_count) * 3ull);
    for (uint32_t i = 0; i < out.init_value_count; i++) {
        uint32_t reg_idx = 0;
        if (!reader.read6bitExt(reg_idx)) {
            return failWith(error, "failed to read init reg idx");
        }
        out.init_value_words.push_back(reg_idx);

        uint32_t word = 0;
        if (!reader.read6bitExt(word)) {
            return failWith(error, "failed to read init value");
        }
        out.init_value_words.push_back(word);

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
    out.inst_words.resize(out.inst_count);
    for (uint32_t i = 0; i < out.inst_count; i++) {
        if (!reader.read6bitExt(out.inst_words[i])) {
            return failWith(error, "failed to read inst_words");
        }
    }

    if (!reader.read6bitExt(out.branch_count)) {
        return failWith(error, "failed to read branch_count");
    }
    out.branch_words.resize(out.branch_count);
    for (uint32_t i = 0; i < out.branch_count; i++) {
        if (!reader.read6bitExt(out.branch_words[i])) {
            return failWith(error, "failed to read branch_words");
        }
    }

    uint32_t branch_addr_count = 0;
    if (!reader.read6bitExt(branch_addr_count)) {
        return failWith(error, "failed to read branch_addr_count");
    }
    out.branch_addrs.resize(branch_addr_count);
    for (uint32_t i = 0; i < branch_addr_count; i++) {
        if (!readU64FromU32Pair(reader, out.branch_addrs[i])) {
            return failWith(error, "failed to read branch_addrs");
        }
    }
    if (!readU64FromU32Pair(reader, out.function_offset)) {
        return failWith(error, "failed to read function_offset");
    }

    return out.validate(error);
}

bool zFunctionData::encodedEquals(const zFunctionData& other, std::string* error) const {
    // 字段逐项比对，优先返回第一处差异，便于定位问题。
    if (marker != other.marker) {
        return appendMismatch(error, "marker", std::to_string(marker), std::to_string(other.marker));
    }
    if (register_count != other.register_count) {
        return appendMismatch(error, "register_count", std::to_string(register_count), std::to_string(other.register_count));
    }
    if (first_inst_count != other.first_inst_count) {
        return appendMismatch(error, "first_inst_count", std::to_string(first_inst_count), std::to_string(other.first_inst_count));
    }
    if (first_inst_opcodes != other.first_inst_opcodes) {
        return failWith(error, "encodedEquals mismatch: first_inst_opcodes");
    }
    if (external_init_words != other.external_init_words) {
        return failWith(error, "encodedEquals mismatch: external_init_words");
    }
    if (type_count != other.type_count) {
        return appendMismatch(error, "type_count", std::to_string(type_count), std::to_string(other.type_count));
    }
    if (type_tags != other.type_tags) {
        return failWith(error, "encodedEquals mismatch: type_tags");
    }
    if (init_value_count != other.init_value_count) {
        return appendMismatch(error, "init_value_count", std::to_string(init_value_count), std::to_string(other.init_value_count));
    }
    if (init_value_words != other.init_value_words) {
        return failWith(error, "encodedEquals mismatch: init_value_words");
    }
    if (inst_count != other.inst_count) {
        return appendMismatch(error, "inst_count", std::to_string(inst_count), std::to_string(other.inst_count));
    }
    if (inst_words != other.inst_words) {
        return failWith(error, "encodedEquals mismatch: inst_words");
    }
    if (branch_count != other.branch_count) {
        return appendMismatch(error, "branch_count", std::to_string(branch_count), std::to_string(other.branch_count));
    }
    if (branch_words != other.branch_words) {
        return failWith(error, "encodedEquals mismatch: branch_words");
    }
    if (branch_addrs != other.branch_addrs) {
        return failWith(error, "encodedEquals mismatch: branch_addrs");
    }
    if (function_offset != other.function_offset) {
        return appendMismatch(error, "function_offset", std::to_string(function_offset), std::to_string(other.function_offset));
    }
    return true;
}
