/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 执行引擎实现，负责缓存函数、分发 opcode、执行结果返回。
 * - 加固链路位置：运行时执行核心。
 * - 输入：函数对象 + 参数 + so 上下文。
 * - 输出：函数执行结果。
 */
#include "zVmEngine.h"
#include "zVmOpcodes.h"
#include "zLog.h"
#include <cstring>
#include <cstdlib>

#ifndef VM_TRACE
#define VM_TRACE 0
#endif

#if VM_TRACE
#define VM_TRACE_LOGD(...) LOGD(__VA_ARGS__)
#else
#define VM_TRACE_LOGD(...) ((void)0)
#endif

// ============================================================================
// 寄存器管理器辅助函数
// ============================================================================

RegManager* allocRegManager(uint32_t count) {
    // 按“头部 + 柔性数组”一次性分配，减少碎片和多次分配开销。
    size_t size = sizeof(RegManager) + 24 * count;
    RegManager* mgr = static_cast<RegManager*>(calloc(1, size));
    mgr->count = count;
    return mgr;
}

// 释放寄存器管理器，并回收 ownership 标记需要释放的寄存器指针值。
void freeRegManager(RegManager* mgr) {
    if (mgr) {
        // 释放 ownership=1 的槽
        for (uint32_t i = 0; i < mgr->count; i++) {
            if (mgr->slots[i].ownership == 1) {
                const uint64_t freePtr = (mgr->slots[i].reserved != 0)
                                         ? mgr->slots[i].reserved
                                         : mgr->slots[i].value;
                if (freePtr != 0) {
                    free(reinterpret_cast<void*>(freePtr));
                }
            }
        }
        free(mgr);
    }
}


// ============================================================================
// 虚拟机主类实现
// ============================================================================

zVmEngine& zVmEngine::getInstance() {
    static zVmEngine instance;
    return instance;
}

// 构造引擎：初始化 opcode 分发表，并预留函数缓存容量。
zVmEngine::zVmEngine() {
    // 初始化 opcode 跳转表
    vm::initOpcodeTable();
    cache_.reserve(256);

}

// 析构引擎并清理缓存状态。
zVmEngine::~zVmEngine() {
    clearCache();
}

void zVmEngine::destroyFunction(zFunction* function) {
    if (function == nullptr) {
        return;
    }
    delete[] function->register_list;
    function->register_list = nullptr;
    delete[] function->inst_list;
    function->inst_list = nullptr;
    delete[] function->branch_words_ptr;
    function->branch_words_ptr = nullptr;
    function->releaseTypeResources();
    delete function;
}

bool zVmEngine::cacheFunction(std::unique_ptr<zFunction> function) {
    if (!function || function->empty()) {
        return false;
    }

    const uint64_t key = function->functionAddress();
    if (key == 0) {
        return false;
    }

    // 同 fun_addr 的旧版本直接替换，避免缓存中出现重复定义。
    std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        destroyFunction(it->second);
    }

    cache_[key] = function.release();
    return true;
}

bool zVmEngine::LoadLibrary(const char* path) {
    // 链接器实例延迟初始化；调用方可重复加载不同 so。
    std::lock_guard<std::mutex> lock(linker_mutex_);
    if (!linker_) {
        linker_ = std::make_unique<zLinker>();
    }
    return linker_->LoadLibrary(path);
}

soinfo* zVmEngine::GetSoinfo(const char* name) {
    // 统一经由 linker 查询，避免外层直接持有 linker 生命周期。
    std::lock_guard<std::mutex> lock(linker_mutex_);
    if (!linker_) {
        return nullptr;
    }
    return linker_->GetSoinfo(name);
}

void zVmEngine::setSharedBranchAddrs(const char* soName, std::vector<uint64_t> branchAddrs) {
    // 以 so 名为 key 保存共享 branch_addr_list（全局 ID 语义）。
    if (soName == nullptr || soName[0] == '\0') {
        return;
    }
    std::lock_guard<std::mutex> lock(shared_branch_mutex_);
    shared_branch_addrs_map_[soName] = std::move(branchAddrs);
}

void zVmEngine::clearSharedBranchAddrs(const char* soName) {
    // 清理单个 so 的共享 branch_addr_list 映射。
    if (soName == nullptr || soName[0] == '\0') {
        return;
    }
    std::lock_guard<std::mutex> lock(shared_branch_mutex_);
    shared_branch_addrs_map_.erase(soName);
}

// 清空缓存：释放所有 zFunction 及其动态字段。
void zVmEngine::clearCache() {
    std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
    for (auto& pair : cache_) {
        destroyFunction(pair.second);
    }
    cache_.clear();
}

// 执行缓存函数：补齐 branch 地址与模块基址后转交解释器主循环。
uint64_t zVmEngine::executeState(
    zFunction* function,
    VMRegSlot* registers,
    void* retBuffer,
    const char* soName
) {
    if (function == nullptr) {
        return 0;
    }
    if (soName == nullptr || soName[0] == '\0') {
        LOGE("executeState failed: invalid soName");
        return 0;
    }

    uint64_t* branchAddrPtr = function->ext_list;
    std::vector<uint64_t> branchAddrsList;
    {
        std::lock_guard<std::mutex> lock(shared_branch_mutex_);
        auto it = shared_branch_addrs_map_.find(soName);
        if (it != shared_branch_addrs_map_.end()) {
            branchAddrsList = it->second;
        }
    }
    // 优先使用 setSharedBranchAddrs 写入的共享列表；缺失时回退函数私有列表。
    if (branchAddrsList.empty()) {
        branchAddrsList = function->branchAddrs();
    }
    if (!branchAddrsList.empty()) {
        soinfo* soInfo = GetSoinfo(soName);
        if (soInfo == nullptr) {
            LOGE("executeState failed: soinfo not found for %s", soName);
            return 0;
        }
        vm::setVmModuleBase(soInfo->base);
        for (uint64_t& addr : branchAddrsList) {
            addr += soInfo->base;
        }
        branchAddrPtr = branchAddrsList.data();
    }

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
        branchAddrsList.empty() ? function->branch_count : static_cast<uint32_t>(branchAddrsList.size()),
        branchAddrPtr
    );
}

uint64_t zVmEngine::execute(
    void* retBuffer,
    const char* soName,
    uint64_t funAddr,
    const zParams& params
) {
    // 外部调用入口：按 so + fun_addr 在缓存中定位函数并执行。
    if (soName == nullptr || soName[0] == '\0') {
        LOGE("execute by fun_addr failed: soName is empty, fun_addr=0x%llx",
             static_cast<unsigned long long>(funAddr));
        return 0;
    }

    // 先在缓存中定位目标函数。
    std::shared_lock<std::shared_timed_mutex> lock(cache_mutex_);
    auto it = cache_.find(funAddr);
    if (it == cache_.end() || it->second == nullptr) {
        LOGE("execute by fun_addr failed: not found, fun_addr=0x%llx", static_cast<unsigned long long>(funAddr));
        return 0;
    }

    zFunction* function = it->second;

    if (function->register_count == 0 ||
        function->inst_count == 0 ||
        function->register_list == nullptr ||
        function->inst_list == nullptr ||
        function->type_list == nullptr) {
        LOGE("execute by fun_addr failed: runtime state incomplete, fun_addr=0x%llx",
             static_cast<unsigned long long>(funAddr));
        return 0;
    }

    // 执行前复制寄存器初值并覆写前 N 个实参。
    RegManager* regMgr = allocRegManager(function->register_count);
    VMRegSlot* registers = regMgr->slots;
    memset(registers, 0, 24 * function->register_count);
    memcpy(registers, function->register_list, 24 * function->register_count);

    const uint32_t paramSize = static_cast<uint32_t>(params.values.size());
    const uint32_t paramCount = (paramSize < function->register_count) ? paramSize : function->register_count;
    if (paramCount > 0) {
        for (uint32_t i = 0; i < paramCount; ++i) {
            registers[i].value = params.values[i];
            registers[i].ownership = 0;
        }
    }
    // 统一把调用方返回缓冲写入 x8：sret 函数可直接使用，普通函数会忽略该值。
    if (retBuffer != nullptr && function->register_count > 8) {
        registers[8].value = reinterpret_cast<uint64_t>(retBuffer);
        registers[8].ownership = 0;
    }

    const uint64_t result = executeState(function, registers, retBuffer, soName);
    freeRegManager(regMgr);
    return result;
}

// 执行已准备好的运行时上下文，驱动解释循环直到结束。
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
    if (instCount == 0 || instructions == nullptr) return 0;

    // 解释器约定：首条必须是 OP_ALLOC_RETURN，用于初始化返回语义。
    if (instructions[0] != OP_ALLOC_RETURN) {
        return 0;
    }

    VMContext ctx{};
    // 组装解释器上下文，随后循环 dispatch 直到结束。
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
    ctx.pc = 0;
    ctx.branch_id = 0;
    ctx.saved_branch_id = 0;
    ctx.ret_value = 0;
    ctx.running = true;
    ctx.nzcv = 0;

    while (ctx.running && ctx.pc < ctx.inst_count) {
        dispatch(&ctx);
    }

    return ctx.ret_value;
}

// 分发当前 pc 对应的 opcode 到具体处理函数。
void zVmEngine::dispatch(VMContext* ctx) {
    if (ctx == nullptr) {
        return;
    }

    if (ctx->pc >= ctx->inst_count) {
        VM_TRACE_LOGD("pc=%u >= inst_count=%u, stop", ctx->pc, ctx->inst_count);
        ctx->running = false;
        return;
    }

    uint32_t opcode = ctx->instructions[ctx->pc];
    uint32_t pc_before = ctx->pc;

    // opcode 命中分发表则执行对应处理函数，否则进入未知指令陷阱。
    if (opcode < OP_MAX && vm::g_opcode_table[opcode]) {
        vm::g_opcode_table[opcode](ctx);
    } else {
        vm::op_unknown(ctx);
    }

    VM_TRACE_LOGD("pc %u -> %u  %s", pc_before, ctx->pc, vm::getOpcodeName(opcode));
}
