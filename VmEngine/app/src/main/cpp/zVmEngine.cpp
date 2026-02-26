/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 执行引擎实现：缓存函数、装配运行态、调度 opcode、返回结果。
 * - 加固链路位置：运行时执行核心。
 * - 输入：函数地址 + so 上下文 + 调用参数。
 * - 输出：执行结果（uint64_t / 写回 ret_buffer）。
 */
#include "zVmEngine.h"

// opcode 分发表与处理函数。
#include "zVmOpcodes.h"
// 日志。
#include "zLog.h"
// memset / memcpy。
#include <cstring>
// calloc / free。
#include <cstdlib>

// 追踪开关（默认关闭）。
#ifndef VM_TRACE
#define VM_TRACE 0
#endif

// trace 打开时输出详细执行日志。
#if VM_TRACE
#define VM_TRACE_LOGD(...) LOGD(__VA_ARGS__)
#else
// trace 关闭时编译成空操作。
#define VM_TRACE_LOGD(...) ((void)0)
#endif

// ============================================================================
// 寄存器管理器辅助函数
// ============================================================================

// 分配寄存器管理器（头部 + 柔性数组一次性分配）。
RegManager* allocRegManager(uint32_t count) {
    // 每个寄存器槽固定 24 字节。
    size_t size = sizeof(RegManager) + 24 * count;
    // 零初始化分配，确保未写字段默认值为 0。
    RegManager* mgr = static_cast<RegManager*>(calloc(1, size));
    // 记录槽位数量。
    mgr->count = count;
    return mgr;
}

// 释放寄存器管理器并回收 ownership=1 的寄存器指针。
void freeRegManager(RegManager* mgr) {
    // 空指针直接返回。
    if (mgr) {
        // 遍历全部寄存器槽。
        for (uint32_t i = 0; i < mgr->count; i++) {
            // 仅处理 ownership=1 的需要回收槽位。
            if (mgr->slots[i].ownership == 1) {
                // 优先使用 reserved 作为可释放基址；否则回退到 value。
                const uint64_t freePtr = (mgr->slots[i].reserved != 0)
                                         ? mgr->slots[i].reserved
                                         : mgr->slots[i].value;
                // 非空指针才执行 free。
                if (freePtr != 0) {
                    free(reinterpret_cast<void*>(freePtr));
                }
            }
        }
        // 释放管理器整体内存块。
        free(mgr);
    }
}

// ============================================================================
// 虚拟机主类实现
// ============================================================================

// 获取单例实例。
zVmEngine& zVmEngine::getInstance() {
    // 线程安全的局部静态对象。
    static zVmEngine instance;
    return instance;
}

// 构造函数：初始化 opcode 表与缓存容量。
zVmEngine::zVmEngine() {
    // 初始化 opcode 跳转表。
    vm::initOpcodeTable();
    // 预留缓存容量，降低扩容开销。
    cache_.reserve(256);
}

// 析构函数：释放缓存中的函数对象。
zVmEngine::~zVmEngine() {
    clearCache();
}

// 销毁单个函数对象及其附带动态资源。
void zVmEngine::destroyFunction(zFunction* function) {
    // 空对象直接返回。
    if (function == nullptr) {
        return;
    }
    // 释放寄存器初值数组。
    delete[] function->register_list;
    function->register_list = nullptr;
    // 释放指令数组。
    delete[] function->inst_list;
    function->inst_list = nullptr;
    // 释放 branch_id 列表。
    delete[] function->branch_words_ptr;
    function->branch_words_ptr = nullptr;
    // 释放类型系统相关资源。
    function->releaseTypeResources();
    // 释放对象本体。
    delete function;
}

// 把函数对象缓存到引擎中（key = fun_addr）。
bool zVmEngine::cacheFunction(std::unique_ptr<zFunction> function) {
    // 空对象或空内容直接拒绝。
    if (!function || function->empty()) {
        return false;
    }

    // 读取函数地址键。
    const uint64_t key = function->functionAddress();
    // key=0 视为非法。
    if (key == 0) {
        return false;
    }

    // 写缓存需要独占锁。
    std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
    // 若存在同 key 旧函数，先释放旧对象。
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        destroyFunction(it->second);
    }

    // 接管 unique_ptr 所有权并写入缓存。
    cache_[key] = function.release();
    return true;
}

// 加载 so（通过 zLinker）。
bool zVmEngine::LoadLibrary(const char* path) {
    // 链接器内部状态修改需串行化。
    std::lock_guard<std::mutex> lock(linker_mutex_);
    // 延迟初始化 linker。
    if (!linker_) {
        linker_ = std::make_unique<zLinker>();
    }
    // 委托给 linker 加载。
    return linker_->LoadLibrary(path);
}

// 从内存字节加载 so（不依赖落盘路径）。
bool zVmEngine::LoadLibraryFromMemory(const char* soName, const uint8_t* soBytes, size_t soSize) {
    // 链接器内部状态修改需串行化。
    std::lock_guard<std::mutex> lock(linker_mutex_);
    // 延迟初始化 linker。
    if (!linker_) {
        linker_ = std::make_unique<zLinker>();
    }
    // 委托给 linker 的内存加载入口。
    return linker_->LoadLibraryFromMemory(soName, soBytes, soSize);
}

// 查询 soinfo。
soinfo* zVmEngine::GetSoinfo(const char* name) {
    // 统一通过 linker 查询，避免外层持有裸引用。
    std::lock_guard<std::mutex> lock(linker_mutex_);
    // linker 尚未初始化时返回空。
    if (!linker_) {
        return nullptr;
    }
    // 返回查询结果。
    return linker_->GetSoinfo(name);
}

// 设置模块级共享 branch 地址列表。
void zVmEngine::setSharedBranchAddrs(const char* soName, std::vector<uint64_t> branchAddrs) {
    // so 名不能为空。
    if (soName == nullptr || soName[0] == '\0') {
        return;
    }
    // 写入共享映射需要加锁。
    std::lock_guard<std::mutex> lock(shared_branch_mutex_);
    // 覆盖或新增。
    shared_branch_addrs_map_[soName] = std::move(branchAddrs);
}

// 清理单个模块的共享 branch 地址列表。
void zVmEngine::clearSharedBranchAddrs(const char* soName) {
    // so 名不能为空。
    if (soName == nullptr || soName[0] == '\0') {
        return;
    }
    // 删除映射项。
    std::lock_guard<std::mutex> lock(shared_branch_mutex_);
    shared_branch_addrs_map_.erase(soName);
}

// 清空函数缓存。
void zVmEngine::clearCache() {
    // 清缓存需独占锁。
    std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
    // 逐个释放函数对象。
    for (auto& pair : cache_) {
        destroyFunction(pair.second);
    }
    // 清空哈希表。
    cache_.clear();
}

// 执行已缓存函数的“运行态版本”。
uint64_t zVmEngine::executeState(
    zFunction* function,
    VMRegSlot* registers,
    void* retBuffer,
    const char* soName
) {
    // 函数对象不能为空。
    if (function == nullptr) {
        return 0;
    }
    // so 名不能为空。
    if (soName == nullptr || soName[0] == '\0') {
        LOGE("executeState failed: invalid soName");
        return 0;
    }

    // 默认使用函数自带 ext_list（branch_addr_list）。
    uint64_t* branchAddrPtr = function->ext_list;
    // 临时可写分支地址列表（用于叠加 base）。
    std::vector<uint64_t> branchAddrsList;
    {
        // 读取共享分支映射。
        std::lock_guard<std::mutex> lock(shared_branch_mutex_);
        auto it = shared_branch_addrs_map_.find(soName);
        if (it != shared_branch_addrs_map_.end()) {
            branchAddrsList = it->second;
        }
    }
    // 共享映射缺失时回退函数私有列表。
    if (branchAddrsList.empty()) {
        branchAddrsList = function->branchAddrs();
    }
    // 若存在分支地址列表，需要把相对地址加上模块基址。
    if (!branchAddrsList.empty()) {
        // 查询目标 so 的 soinfo。
        soinfo* soInfo = GetSoinfo(soName);
        if (soInfo == nullptr) {
            LOGE("executeState failed: soinfo not found for %s", soName);
            return 0;
        }
        // 同步设置 VM 全局模块基址（供某些 opcode 使用）。
        vm::setVmModuleBase(soInfo->base);
        // 把每个相对地址转换为进程内绝对地址。
        for (uint64_t& addr : branchAddrsList) {
            addr += soInfo->base;
        }
        // 指向本地临时数组。
        branchAddrPtr = branchAddrsList.data();
    }

    // 进入核心执行入口（低层上下文版本）。
    return execute(
        retBuffer,
        function->register_count,
        registers,
        function->type_count,
        function->type_list,
        function->inst_count,
        function->inst_list,
        function->branch_count,
        function->branch_words_ptr,
        // 使用共享列表时按其长度传入；否则沿用函数 branch_count。
        branchAddrsList.empty() ? function->branch_count : static_cast<uint32_t>(branchAddrsList.size()),
        branchAddrPtr
    );
}

// 执行入口（按 soName + funAddr 查缓存并执行）。
uint64_t zVmEngine::execute(
    void* retBuffer,
    const char* soName,
    uint64_t funAddr,
    const zParams& params
) {
    // so 名不能为空。
    if (soName == nullptr || soName[0] == '\0') {
        LOGE("execute by fun_addr failed: soName is empty, fun_addr=0x%llx",
             static_cast<unsigned long long>(funAddr));
        return 0;
    }

    // 读缓存使用共享锁。
    std::shared_lock<std::shared_timed_mutex> lock(cache_mutex_);
    // 定位函数对象。
    auto it = cache_.find(funAddr);
    if (it == cache_.end() || it->second == nullptr) {
        LOGE("execute by fun_addr failed: not found, fun_addr=0x%llx", static_cast<unsigned long long>(funAddr));
        return 0;
    }

    // 取出目标函数。
    zFunction* function = it->second;

    // 基本运行态完整性检查。
    if (function->register_count == 0 ||
        function->inst_count == 0 ||
        function->register_list == nullptr ||
        function->inst_list == nullptr ||
        function->type_list == nullptr) {
        LOGE("execute by fun_addr failed: runtime state incomplete, fun_addr=0x%llx",
             static_cast<unsigned long long>(funAddr));
        return 0;
    }

    // 分配寄存器管理器并复制函数默认寄存器快照。
    RegManager* regMgr = allocRegManager(function->register_count);
    VMRegSlot* registers = regMgr->slots;
    // 显式清零，确保未覆盖字段处于已知状态。
    memset(registers, 0, 24 * function->register_count);
    // 复制函数预设寄存器。
    memcpy(registers, function->register_list, 24 * function->register_count);

    // 计算实际可写入参数数量（取 min(params, register_count)）。
    const uint32_t paramSize = static_cast<uint32_t>(params.values.size());
    const uint32_t paramCount = (paramSize < function->register_count) ? paramSize : function->register_count;
    if (paramCount > 0) {
        // 逐个写入 x0..xN。
        for (uint32_t i = 0; i < paramCount; ++i) {
            registers[i].value = params.values[i];
            // 参数来源于调用方，不由 VM 释放。
            registers[i].ownership = 0;
        }
    }
    // 约定把调用方 retBuffer 写入 x8，供 sret 场景使用。
    if (retBuffer != nullptr && function->register_count > 8) {
        registers[8].value = reinterpret_cast<uint64_t>(retBuffer);
        registers[8].ownership = 0;
    }

    // 执行并拿到结果。
    const uint64_t result = executeState(function, registers, retBuffer, soName);
    // 释放寄存器管理器。
    freeRegManager(regMgr);
    return result;
}

// 执行入口（底层上下文版本）。
uint64_t zVmEngine::execute(
    void* retBuffer,
    uint32_t registerCount,
    VMRegSlot* registers,
    uint32_t typeCount,
    zType** types,
    uint32_t instCount,
    uint32_t* instructions,
    uint32_t branchCount,
    uint32_t* branch_id_list,
    uint32_t branchAddrCount,
    uint64_t* branch_addr_list
) {
    // 无指令流直接返回 0。
    if (instCount == 0 || instructions == nullptr) return 0;

    // 协议约束：首条必须是 OP_ALLOC_RETURN。
    if (instructions[0] != OP_ALLOC_RETURN) {
        return 0;
    }

    // 组装 VM 上下文。
    VMContext ctx{};
    ctx.ret_buffer = retBuffer;
    ctx.register_count = registerCount;
    ctx.registers = registers;
    ctx.type_count = typeCount;
    ctx.types = types;
    ctx.inst_count = instCount;
    ctx.instructions = instructions;
    ctx.branch_count = branchCount;
    ctx.branch_id_list = branch_id_list;
    ctx.branch_addr_count = branchAddrCount;
    ctx.branch_addr_list = branch_addr_list;
    // 初始 pc=0。
    ctx.pc = 0;
    // 分支状态初始值。
    ctx.branch_id = 0;
    ctx.saved_branch_id = 0;
    // 返回值初始为 0。
    ctx.ret_value = 0;
    // 标记运行态开始。
    ctx.running = true;
    // NZCV 初始清零。
    ctx.nzcv = 0;

    // 主解释循环：running 且 pc 未越界。
    while (ctx.running && ctx.pc < ctx.inst_count) {
        dispatch(&ctx);
    }

    // 返回最终 ret_value。
    return ctx.ret_value;
}

// 单步分发：执行当前 pc 对应 opcode。
void zVmEngine::dispatch(VMContext* ctx) {
    // 空上下文直接返回。
    if (ctx == nullptr) {
        return;
    }

    // pc 越界时停止运行。
    if (ctx->pc >= ctx->inst_count) {
        VM_TRACE_LOGD("pc=%u >= inst_count=%u, stop", ctx->pc, ctx->inst_count);
        ctx->running = false;
        return;
    }

    // 读取当前 opcode。
    uint32_t opcode = ctx->instructions[ctx->pc];
    // 记录执行前 pc 便于 trace。
    uint32_t pc_before = ctx->pc;

    // 命中分发表则调用对应处理函数。
    if (opcode < OP_MAX && vm::g_opcode_table[opcode]) {
        vm::g_opcode_table[opcode](ctx);
    } else {
        // 未知 opcode 走统一陷阱处理。
        vm::op_unknown(ctx);
    }

    // trace：输出 pc 变化与 opcode 名称。
    VM_TRACE_LOGD("pc %u -> %u  %s", pc_before, ctx->pc, vm::getOpcodeName(opcode));
}
