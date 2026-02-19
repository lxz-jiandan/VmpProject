#ifndef Z_FUNCTION_H
#define Z_FUNCTION_H

#include "zFunctionData.h"

#include <cstddef>
#include <cstdint>
#include <istream>
#include <memory>
#include <string>
#include <vector>

struct VMRegSlot;
class zType;
class FunctionStructType;
class zTypeManager;

class zFunction : public zFunctionData {
public:
    // VM 运行态字段：直接由 zFunction 持有。
    FunctionStructType* function_sig_type = nullptr;
    VMRegSlot* register_list = nullptr;
    uint32_t* inst_list = nullptr;
    uint32_t* branch_words_ptr = nullptr;
    zType** type_list = nullptr;
    uint64_t* ext_list = nullptr;

    // 从内存文本中加载程序数据（用于 Android assets 读取后直接解析）。
    bool loadUnencodedText(const char* text, size_t len);

    // 从编码字节流加载程序数据（寄存器初值、类型表、指令流、分支表）。
    // externalInitArray 可为空；为空时会跳过“外部初值映射”阶段。
    bool loadEncodedData(const uint8_t* data, uint64_t len, uint64_t* externalInitArray = nullptr);

    // 判断当前对象是否还没有可执行指令数据。
    bool empty() const;

    // 以只读引用方式返回解析后的分支地址列表。
    const std::vector<uint64_t>& branchAddrs() const;
    uint64_t functionAddress() const;
    void setFunctionAddress(uint64_t functionAddress);

    void setTypePool(std::unique_ptr<zTypeManager> pool);
    void releaseTypeResources();

private:
    // 去除字符串两端空白字符，返回裁剪后的副本。
    static std::string trimCopy(const std::string& value);

    // 解析 "{1,2,3}" 形式的 32 位数组定义行。
    static bool parseArrayValues32(const std::string& line, std::vector<uint32_t>& values);

    // 解析 "{0x1,0x2,...}" 形式的 64 位数组定义行。
    static bool parseArrayValues64(const std::string& line, std::vector<uint64_t>& values);

    // 解析“变量 = 数值;”形式的标量定义行。
    static bool parseScalarUint32(const std::string& line, uint32_t& value);
    static bool parseScalarUint64(const std::string& line, uint64_t& value);

    // 从输入流执行完整解析流程（供文件加载与内存加载复用）。
    bool parseFromStream(std::istream& in);

private:
    std::unique_ptr<zTypeManager> type_pool_;
    std::vector<uint32_t> register_ids_;
    std::vector<uint32_t> type_tags_;
    std::vector<uint32_t> branch_words_;
    std::vector<uint64_t> branch_addrs_;
    std::vector<uint32_t> inst_words_;
    std::vector<std::vector<uint32_t>> inst_lines_;
    uint64_t fun_addr_ = 0;
};

#endif // Z_FUNCTION_H

