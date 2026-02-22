/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 运行时函数对象声明。
 * - 加固链路位置：执行对象模型层。
 * - 输入：编码字节。
 * - 输出：执行元数据（寄存器/类型/指令/分支）。
 */
#ifndef Z_FUNCTION_H
#define Z_FUNCTION_H

#include "zFunctionData.h"  // 编码字段与序列化能力。

#include <cstddef>  // size_t。
#include <cstdint>  // 固定宽度整数类型。
#include <istream>  // std::istream。
#include <memory>   // std::unique_ptr。
#include <string>   // std::string。
#include <vector>   // std::vector。

struct VMRegSlot;         // VM 寄存器槽结构（在 zVmEngine.h 定义）。
class zType;              // 类型系统基类。
class FunctionStructType; // 函数签名结构类型。
class zTypeManager;       // 类型池管理器。

class zFunction : public zFunctionData {
public:
    // VM 运行态字段：直接由 zFunction 持有。
    // 函数签名类型（约定来自 type_list[0]）。
    FunctionStructType* function_sig_type = nullptr;
    // 运行时寄存器数组。
    VMRegSlot* register_list = nullptr;
    // 扁平化指令流。
    uint32_t* inst_list = nullptr;
    // 分支 ID -> PC 映射数组。
    uint32_t* branch_words_ptr = nullptr;
    // 运行时类型表。
    zType** type_list = nullptr;
    // 分支地址表指针（通常指向 branch_addrs_ 内存）。
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
    // 返回当前函数地址标识（fun_addr）。
    uint64_t functionAddress() const;
    // 设置当前函数地址标识（fun_addr）。
    void setFunctionAddress(uint64_t functionAddress);

    // 注入类型池所有权（用于释放 type_list）。
    void setTypePool(std::unique_ptr<zTypeManager> pool);
    // 释放 type_list 与类型池资源。
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
    // 类型池对象，负责 type_list 元素生命周期。
    std::unique_ptr<zTypeManager> type_pool_;
    // 文本导出中的寄存器 ID 列表缓存。
    std::vector<uint32_t> register_ids_;
    // 文本导出中的类型标签列表缓存。
    std::vector<uint32_t> type_tags_;
    // 文本导出中的分支 word 列表缓存。
    std::vector<uint32_t> branch_words_;
    // 文本导出中的分支地址列表缓存。
    std::vector<uint64_t> branch_addrs_;
    // 文本导出中的扁平指令流缓存。
    std::vector<uint32_t> inst_words_;
    // 文本导出中的逐行指令缓存（调试/回写用）。
    std::vector<std::vector<uint32_t>> inst_lines_;
    // 函数地址缓存。
    uint64_t fun_addr_ = 0;
};

#endif // Z_FUNCTION_H

