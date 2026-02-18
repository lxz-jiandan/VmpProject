#ifndef Z_VM_ENGINE_H
#define Z_VM_ENGINE_H

#include "zByteCodeReader.h"
#include "zFunction.h"
#include "zTypeManager.h"
#include "zLinker.h"
#include <atomic>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>


// ============================================================================
// 寄存器槽：24 字节
// ============================================================================
struct VMRegSlot {
    uint64_t value;          // 偏移 0：值或指针
    uint64_t reserved;       // 偏移 8：保留
    uint8_t  ownership;      // 偏移 16：1=需 VM free 槽内指针，0=否
    uint8_t  padding[7];     // 偏移 17：对齐填充
};

static_assert(sizeof(VMRegSlot) == 24, "VMRegSlot must be 24 bytes");

// ============================================================================
// 寄存器管理器
// ============================================================================
struct RegManager {
    uint32_t count;           // 寄存器个数
    uint32_t _pad;
    VMRegSlot slots[];        // 24 * count 字节（柔性数组）
};

// ============================================================================
// VaStruct（可变参数结构，用于参数填充）
// ============================================================================
struct VaStruct {
    void*     __stack;       // 栈参数指针
    void*     __gr_top;      // 通用寄存器顶部
    void*     __vr_top;      // 向量寄存器顶部
    int32_t   __gr_offs;     // 通用寄存器偏移
    int32_t   __vr_offs;     // 向量寄存器偏移
};

// 轻量参数容器：按寄存器顺序写入 x0..xN/w0..wN。
struct zParams {
    std::vector<uint64_t> values;

    zParams() = default;
    explicit zParams(std::vector<uint64_t> inValues) : values(std::move(inValues)) {}
    zParams(std::initializer_list<uint64_t> initValues) : values(initValues) {}
};

// ============================================================================
// VM 执行上下文（用于 opcode 处理函数）
// ============================================================================
// 标志位掩码（与 ARM64 NZCV 对应，低 4 bit：N,Z,C,V）
#define VM_FLAG_N  1u
#define VM_FLAG_Z  2u
#define VM_FLAG_C  4u
#define VM_FLAG_V  8u

struct VMContext {
    void*        ret_buffer;       // 返回值缓冲区
    uint32_t     register_count;   // 寄存器数量
    VMRegSlot*   registers;        // 寄存器数组
    uint32_t     type_count;       // 类型数量
    zType** types;            // 类型数组
    uint32_t     inst_count;       // 指令数量
    uint32_t*    instructions;     // 指令数组
    uint32_t     branch_count;     // 分支表项数
    uint32_t*    branch_id_list;         // 分支表 branch_list[branchId]=targetPc
    uint64_t*    branch_addr_list;         //

    uint32_t     pc;               // 程序计数器
    uint32_t     branch_id;        // 当前分支 ID
    uint32_t     saved_branch_id;  // 保存的分支 ID
    uint64_t     ret_value;        // 返回值
    bool         running;          // 是否继续运行
    uint8_t      nzcv;             // 标志寄存器：N=bit0, Z=bit1, C=bit2, V=bit3（与 ARM64 一致）
};


// ============================================================================
// 寄存器管理器辅助函数
// ============================================================================
// 为指定寄存器数量分配连续寄存器管理块（含柔性数组区）。
RegManager* allocRegManager(uint32_t count);
// 释放寄存器管理块，并回收 ownership=1 槽位指向的堆内存。
void freeRegManager(RegManager* mgr);
// 获取指定下标寄存器槽地址。
VMRegSlot* getRegSlot(VMRegSlot* base, uint32_t index);

// ============================================================================
// 解码辅助函数
// ============================================================================

// 设置寄存器初值（对应 set_registers_inial_value）
// 根据临时 opcode 数组从字节码中读取初始值并写入寄存器表。
void setRegistersInitialValue(
    zByteCodeReader& reader,
    uint32_t initCount,
    uint32_t* tempOpcodeArray,
    zType** typeList,
    VMRegSlot* registerList
);

// 从 VaStruct 填充参数到寄存器
// 按 ABI 规则从可变参数结构提取实参并写入目标寄存器区。
void fillParametersFromVa(
    VMRegSlot* registerList,
    FunctionStructType* functionList,
    VaStruct* va
);

// ============================================================================
// 虚拟机主类
// ============================================================================
class zVmEngine {
public:
    // 获取全局唯一 VM 引擎实例（线程安全的静态局部变量）。
    static zVmEngine& getInstance();

    // 执行已解码程序：输入寄存器/类型/指令/分支等运行时数据并返回执行结果。
    uint64_t execute(
        void* retBuffer,
        uint32_t registerCount,
        VMRegSlot* registers,
        uint32_t typeCount,
        zType** types,
        uint32_t instCount,
        uint32_t* instructions,
        uint32_t branchCount,
        uint32_t* branches,
        uint64_t* ext_list
    );

    // 通过 fun_addr 执行缓存中的函数，参数由 zParams 写入寄存器。
    uint64_t execute(
        void* retBuffer,
        uint64_t funAddr,
        const zParams& params
    );

    // 解码并执行字节码
    // 若命中缓存则直接执行，否则先解码 bytecode 再执行。
    uint64_t decodeAndExecute(
        void* retBuffer,
        const uint8_t* bytecode,
        uint64_t bytecodeSize,
        uint64_t* externalInitArray,
        void* vaArgs
    );

    // 将解析后的函数缓存到引擎（key = fun_addr）。
    bool cacheFunction(std::unique_ptr<zFunction> function);

    // 使用 zLinker 加载 so。
    bool LoadLibrary(const char* path);
    // 查询已加载 so 的 soinfo。
    soinfo* GetSoinfo(const char* name);
    // 查询已加载 so 的符号地址。
    void* GetSymbol(const char* name);

    // 清除缓存
    // 释放缓存中的 VmState 与其附属资源。
    void clearCache();

    // 获取统计信息
    // 返回当前缓存命中/未命中和指令执行统计。
    struct Stats {
        uint64_t cacheHits;
        uint64_t cacheMisses;
        uint64_t instructionsExecuted;
    };
    // 获取统计信息快照（线程安全）。
    Stats getStats() const;

private:
    // 单例：禁止外部构造/析构与拷贝移动。
    zVmEngine();
    ~zVmEngine();
    zVmEngine(const zVmEngine&) = delete;
    zVmEngine& operator=(const zVmEngine&) = delete;
    zVmEngine(zVmEngine&&) = delete;
    zVmEngine& operator=(zVmEngine&&) = delete;

    // fun_addr -> decoded function
    std::unordered_map<uint64_t, zFunction*> cache_;
    std::unique_ptr<zLinker> linker_;
    mutable std::shared_timed_mutex cache_mutex_;
    mutable std::mutex linker_mutex_;
    std::atomic<uint64_t> cache_hits_{0};
    std::atomic<uint64_t> cache_misses_{0};
    std::atomic<uint64_t> instructions_executed_{0};

    // 解码字节码
    // 将字节码解码为可执行的 zFunction 结构。
    zFunction* decode(
        const uint8_t* bytecode,
        uint64_t bytecodeSize,
        uint64_t* externalInitArray
    );

    // 执行
    // 使用指定寄存器区执行已解码状态，并写入返回缓冲。
    uint64_t executeState(
        zFunction* function,
        VMRegSlot* registers,
        void* retBuffer
    );

    // 释放单个函数对象及其附属资源。
    void destroyFunction(zFunction* function);

    // 取当前 pc 的 opcode 并分发到处理函数。
    void dispatch(VMContext* ctx);
};


#endif // Z_VM_ENGINE_H
