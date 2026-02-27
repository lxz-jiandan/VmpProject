/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 引擎公开接口声明。
 * - 加固链路位置：执行核心接口层。
 * - 输入：执行请求。
 * - 输出：结果与缓存控制能力。
 */
#ifndef Z_VM_ENGINE_H
#define Z_VM_ENGINE_H

#include "zFunction.h"
#include "zTypeManager.h"
#include "zLinker.h"
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>


// ============================================================================
// 寄存器槽：24 字节
// ============================================================================
struct VMRegSlot {
    uint64_t value;          // 偏移 0：值或指针
    uint64_t reserved;       // 偏移 8：ownership=1 时可存放可释放的 base 指针
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
    zType**      types;            // 类型数组
    uint32_t     inst_count;       // 指令数量
    uint32_t*    instructions;     // 指令数组
    uint32_t     branch_count;     // 分支表项数
    uint32_t*    branch_id_list;   // 分支表：branch_id -> 目标 pc
    uint32_t     branch_addr_count;// 外部调用地址表项数（供 OP_BL 使用）
    uint64_t*    branch_addr_list; // 分支表：branch_id -> 目标原生地址（可选）
    uint32_t     branch_lookup_count; // 间接跳转查找表项数（供 OP_BRANCH_REG 使用）
    uint32_t*    branch_lookup_words; // 查找表：lookup_id -> 目标 pc
    uint64_t*    branch_lookup_addrs; // 查找表：lookup_id -> 目标 ARM 地址

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
        uint32_t branchAddrCount,
        uint64_t* ext_list,
        uint32_t branchLookupCount,
        uint32_t* branchLookupWords,
        uint64_t* branchLookupAddrs
    );

    // 通过 soName + fun_addr 执行缓存中的函数，参数由 zParams 写入寄存器。
    uint64_t execute(
        void* retBuffer,
        const char* soName,
        uint64_t funAddr,
        const zParams& params
    );

    // 将解析后的函数缓存到引擎（key = fun_addr）。
    bool cacheFunction(std::unique_ptr<zFunction> function);

    // 使用 zLinker 加载 so。
    bool LoadLibrary(const char* path);
    // 使用 zLinker 从内存字节直接加载 so。
    bool LoadLibraryFromMemory(const char* soName, const uint8_t* soBytes, size_t soSize);
    // 查询已加载 so 的 soinfo。
    soinfo* GetSoinfo(const char* name);
    // 设置模块级共享 branch_addr_list（覆盖函数内同名数据）。
    void setSharedBranchAddrs(const char* soName, std::vector<uint64_t> branchAddrs);
    // 清理模块级共享 branch_addr_list。
    void clearSharedBranchAddrs(const char* soName);

    // 清除缓存并释放函数对象及其附属资源。
    void clearCache();

private:
    // 单例：禁止外部构造/析构与拷贝移动。
    zVmEngine();
    ~zVmEngine();
    zVmEngine(const zVmEngine&) = delete;
    zVmEngine& operator=(const zVmEngine&) = delete;
    zVmEngine(zVmEngine&&) = delete;
    zVmEngine& operator=(zVmEngine&&) = delete;

    // 函数地址 -> 已解码函数对象（缓存命中后可直接执行）。
    std::unordered_map<uint64_t, zFunction*> cache_;
    std::unique_ptr<zLinker> linker_;
    mutable std::shared_timed_mutex cache_mutex_;
    mutable std::mutex linker_mutex_;
    mutable std::mutex shared_branch_mutex_;
    std::unordered_map<std::string, std::vector<uint64_t>> shared_branch_addrs_map_;

    // 使用指定寄存器区执行已解码状态，并写入返回缓冲。
    uint64_t executeState(
        zFunction* function,
        VMRegSlot* registers,
        void* retBuffer,
        const char* soName
    );

    // 释放单个函数对象及其附属资源。
    void destroyFunction(zFunction* function);

    // 取当前 pc 的 opcode 并分发到处理函数。
    void dispatch(VMContext* ctx);
};


#endif // Z_VM_ENGINE_H
