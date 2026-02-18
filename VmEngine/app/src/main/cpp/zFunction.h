#ifndef Z_FUNCTION_H
#define Z_FUNCTION_H

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

class zFunction {
public:
    // VM 运行态字段：直接由 zFunction 持有。
    FunctionStructType* function_list = nullptr;
    uint32_t register_count = 0;
    uint32_t type_count = 0;
    uint32_t inst_count = 0;
    uint32_t branch_count = 0;
    VMRegSlot* register_list = nullptr;
    uint32_t* inst_list = nullptr;
    uint32_t* param_list = nullptr;
    zType** type_list = nullptr;
    uint64_t* ext_list = nullptr;

    // 从内存文本中加载程序数据（用于 Android assets 读取后直接解析）。
    bool loadUnencodedText(const char* text, size_t len);

    // 判断当前对象是否还没有可执行指令数据。
    bool empty() const;

    // 获取寄存器、类型、分支、指令四类 ID 列表的元素数量。
    uint32_t regIdCount() const;
    uint32_t typeIdCount() const;
    uint32_t branchIdCount() const;
    uint32_t instIdCount() const;

    // 以只读引用方式返回解析后的各类 ID 列表，避免额外拷贝。
    const std::vector<uint32_t>& regIdList() const;
    const std::vector<uint32_t>& typeIdList() const;
    const std::vector<uint32_t>& branchIdList() const;
    const std::vector<uint32_t>& instIdList() const;
    const std::vector<uint64_t>& branchAddrList() const;
    uint64_t funAddr() const;
    void setFunAddr(uint64_t funAddr);
    void setTypePool(std::unique_ptr<zTypeManager> pool);
    void releaseTypeResources();

private:
    // 去除字符串两端空白字符，返回裁剪后的副本。
    static std::string trimCopy(const std::string& value);

    // 解析 "{1,2,3}" 形式的 32 位数组定义行。
    static bool parseArrayValues32(const std::string& line, std::vector<uint32_t>& values);

    // 解析 "{0x1,0x2,...}" 形式的 64 位数组定义行。
    static bool parseArrayValues64(const std::string& line, std::vector<uint64_t>& values);

    // 解析 "xxx = number;" 形式的标量定义行。
    static bool parseScalarUint32(const std::string& line, uint32_t& value);

    // 从输入流执行完整解析流程（供文件加载与内存加载复用）。
    bool parseFromStream(std::istream& in);

private:
    std::unique_ptr<zTypeManager> type_pool_;
    std::vector<uint32_t> reg_id_list_;
    std::vector<uint32_t> type_id_list_;
    std::vector<uint32_t> branch_id_list_;
    std::vector<uint64_t> branch_addr_from_file_;
    std::vector<uint32_t> inst_id_list_;
    std::vector<std::vector<uint32_t>> inst_lines_;
    uint64_t fun_addr_ = 0;
};

#endif // Z_FUNCTION_H
