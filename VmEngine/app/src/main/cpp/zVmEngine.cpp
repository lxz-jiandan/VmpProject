#include "zVmEngine.h"
#include "zVmOpcodes.h"
#include "zLog.h"
#include <cstring>
#include <cstdlib>


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
            if (mgr->slots[i].ownership == 1 && mgr->slots[i].value) {
                free(reinterpret_cast<void*>(mgr->slots[i].value));
            }
        }
        free(mgr);
    }
}

// 获取寄存器数组中指定索引槽位地址。
VMRegSlot* getRegSlot(VMRegSlot* base, uint32_t index) {
    return &base[index];
}

// ============================================================================
// 设置寄存器初值（对应 set_registers_inial_value）
// ============================================================================
// 根据初始化 opcode 描述，从字节码读取寄存器初值并写入寄存器数组。
void setRegistersInitialValue(
    zByteCodeReader& reader,
    uint32_t initCount,
    uint32_t* tempOpcodeArray,
    zType** typeList,
    VMRegSlot* registerList
) {
    // 根据 IDA 反编译代码，这个函数从字节码读取寄存器初值
    // 每次读取寄存器索引和对应的值/类型信息
    for (uint32_t i = 0; i < initCount; i++) {
        uint32_t regIdx = reader.read6bitExt();
        uint32_t opcode = tempOpcodeArray[i];
        
        // 根据 opcode 确定如何设置初值
        switch (opcode) {
            case 0: {
                // 读取立即数值
                uint32_t value = reader.read6bitExt();
                registerList[regIdx].value = value;
                registerList[regIdx].ownership = 0;
                break;
            }
            case 1: {
                // 64位立即数
                uint32_t low = reader.read6bitExt();
                uint32_t high = reader.read6bitExt();
                registerList[regIdx].value = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);
                registerList[regIdx].ownership = 0;
                break;
            }
            case 2: {
                // 类型索引引用
                uint32_t typeIdx = reader.read6bitExt();
                if (typeIdx < 1000 && typeList && typeList[typeIdx]) {
                    registerList[regIdx].value = reinterpret_cast<uint64_t>(typeList[typeIdx]);
                }
                registerList[regIdx].ownership = 0;
                break;
            }
            default: {
                // 默认：读取一个值
                uint32_t value = reader.read6bitExt();
                registerList[regIdx].value = value;
                registerList[regIdx].ownership = 0;
                break;
            }
        }
    }
}

// ============================================================================
// 从 VaStruct 填充参数到寄存器
// ============================================================================
// 从 VaStruct 中按类型读取实参，顺序填充到寄存器区域。
void fillParametersFromVa(
    VMRegSlot* registerList,
    FunctionStructType* functionList,
    VaStruct* va
) {
    if (!functionList || functionList->param_count == 0 || !va) {
        return;
    }
    
    VMRegSlot* regPtr = registerList;
    
    for (uint32_t paramIdx = 0; paramIdx < functionList->param_count; paramIdx++) {
        zType* paramType = functionList->param_list[paramIdx];
        if (!paramType) continue;
        
        uint32_t typeKind = paramType->getKind();
        void* valuePtr = nullptr;
        uint64_t value = 0;
        
        switch (typeKind) {
            case TYPE_KIND_FLOAT32:
            case TYPE_KIND_FLOAT64: {
                // 浮点参数：从 vr 区域或栈获取
                if (va->__vr_offs < 0) {
                    int32_t newOffs = va->__vr_offs + 16;
                    if (newOffs <= 0) {
                        valuePtr = reinterpret_cast<char*>(va->__vr_top) + va->__vr_offs;
                        va->__vr_offs = newOffs;
                    } else {
                        valuePtr = va->__stack;
                        va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                    }
                } else {
                    valuePtr = va->__stack;
                    va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                }
                if (valuePtr) {
                    if (typeKind == TYPE_KIND_FLOAT32) {
                        float fval = *reinterpret_cast<float*>(valuePtr);
                        memcpy(&value, &fval, sizeof(float));
                    } else {
                        value = *reinterpret_cast<uint64_t*>(valuePtr);
                    }
                }
                regPtr->value = value;
                regPtr->ownership = 0;
                break;
            }
            
            case TYPE_KIND_INT8_SIGNED:
            case TYPE_KIND_INT8_UNSIGNED:
            case TYPE_KIND_INT16_SIGNED:
            case TYPE_KIND_INT16_UNSIGNED:
            case TYPE_KIND_INT32_SIGNED:
            case TYPE_KIND_INT32_UNSIGNED:
            case TYPE_KIND_INT64_SIGNED:
            case TYPE_KIND_INT64_UNSIGNED:
            case TYPE_KIND_POINTER: {
                // 整数/指针参数：从 gr 区域或栈获取
                if (va->__gr_offs < 0) {
                    int32_t newOffs = va->__gr_offs + 8;
                    if (newOffs <= 0) {
                        valuePtr = reinterpret_cast<char*>(va->__gr_top) + va->__gr_offs;
                        va->__gr_offs = newOffs;
                    } else {
                        valuePtr = va->__stack;
                        va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                    }
                } else {
                    valuePtr = va->__stack;
                    va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                }
                
                if (valuePtr) {
                    uint32_t size = paramType->getSize();
                    switch (size) {
                        case 1: value = *reinterpret_cast<int8_t*>(valuePtr); break;
                        case 2: value = *reinterpret_cast<int16_t*>(valuePtr); break;
                        case 4: value = *reinterpret_cast<int32_t*>(valuePtr); break;
                        default: value = *reinterpret_cast<uint64_t*>(valuePtr); break;
                    }
                }
                regPtr->value = value;
                regPtr->ownership = 0;
                break;
            }
            
            case TYPE_KIND_PTR_TYPE: {
                // 指针类型参数
                if (va->__gr_offs < 0) {
                    int32_t newOffs = va->__gr_offs + 8;
                    if (newOffs <= 0) {
                        valuePtr = reinterpret_cast<char*>(va->__gr_top) + va->__gr_offs;
                        va->__gr_offs = newOffs;
                    } else {
                        valuePtr = va->__stack;
                        va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                    }
                } else {
                    valuePtr = va->__stack;
                    va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                }
                
                if (valuePtr) {
                    value = *reinterpret_cast<uint64_t*>(valuePtr);
                }
                regPtr->value = value;
                regPtr->ownership = 0;
                break;
            }
            
            default:
                // 其他类型按 8 字节处理
                valuePtr = va->__stack;
                va->__stack = reinterpret_cast<char*>(va->__stack) + 8;
                if (valuePtr) {
                    value = *reinterpret_cast<uint64_t*>(valuePtr);
                }
                regPtr->value = value;
                regPtr->ownership = 0;
                break;
        }
        
        regPtr++;
    }
}

// ============================================================================
// 虚拟机主类实现
// ============================================================================

zVmEngine& zVmEngine::getInstance() {
    static zVmEngine instance;
    return instance;
}

// 构造引擎并初始化执行上下文与 opcode 分发表。
zVmEngine::zVmEngine() {
    // 初始化 opcode 跳转表
    initOpcodeTable();
    cache_.reserve(256);

}

// 析构引擎并清理缓存状态。
zVmEngine::~zVmEngine() {
    clearCache();
}

zVmEngine::Stats zVmEngine::getStats() const {
    return Stats{
        cache_hits_.load(std::memory_order_relaxed),
        cache_misses_.load(std::memory_order_relaxed),
        instructions_executed_.load(std::memory_order_relaxed)
    };
}

void zVmEngine::destroyFunction(zFunction* function) {
    if (function == nullptr) {
        return;
    }
    delete[] function->register_list;
    function->register_list = nullptr;
    delete[] function->inst_list;
    function->inst_list = nullptr;
    delete[] function->param_list;
    function->param_list = nullptr;
    function->releaseTypeResources();
    delete function;
}

bool zVmEngine::cacheFunction(std::unique_ptr<zFunction> function) {
    if (!function || function->empty()) {
        return false;
    }

    const uint64_t key = function->funAddr();
    if (key == 0) {
        return false;
    }

    std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        destroyFunction(it->second);
    }

    cache_[key] = function.release();
    return true;
}

bool zVmEngine::LoadLibrary(const char* path) {
    std::lock_guard<std::mutex> lock(linker_mutex_);
    if (!linker_) {
        linker_ = std::make_unique<zLinker>();
    }
    return linker_->LoadLibrary(path);
}

soinfo* zVmEngine::GetSoinfo(const char* name) {
    std::lock_guard<std::mutex> lock(linker_mutex_);
    if (!linker_) {
        return nullptr;
    }
    return linker_->GetSoinfo(name);
}

void* zVmEngine::GetSymbol(const char* name) {
    std::lock_guard<std::mutex> lock(linker_mutex_);
    if (!linker_) {
        return nullptr;
    }
    return linker_->GetSymbol(name);
}

// 清空缓存：释放所有 VmState 及其附属动态内存。
void zVmEngine::clearCache() {
    std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
    for (auto& pair : cache_) {
        destroyFunction(pair.second);
    }
    cache_.clear();
}

// 字节码执行入口：先查缓存，未命中则解码，再基于独立寄存器副本执行。
uint64_t zVmEngine::decodeAndExecute(
    void* retBuffer,
    const uint8_t* bytecode,
    uint64_t bytecodeSize,
    uint64_t* externalInitArray,
    void* vaArgs
) {
    zFunction* function = nullptr;
    const uint64_t fallbackFunAddr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(bytecode));
    uint64_t cacheKey = fallbackFunAddr;

    {
        std::shared_lock<std::shared_timed_mutex> lock(cache_mutex_);
        auto it = cache_.find(cacheKey);
        if (it != cache_.end() && it->second != nullptr) {
            function = it->second;
            cache_hits_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if (function == nullptr) {
        cache_misses_.fetch_add(1, std::memory_order_relaxed);

        zFunction* decoded = decode(bytecode, bytecodeSize, externalInitArray);
        if (!decoded) {
            return 0;
        }

        if (decoded->funAddr() == 0) {
            decoded->setFunAddr(fallbackFunAddr);
        }
        cacheKey = decoded->funAddr();

        std::unique_lock<std::shared_timed_mutex> lock(cache_mutex_);
        auto it = cache_.find(cacheKey);
        if (it != cache_.end() && it->second != nullptr) {
            function = it->second;
            destroyFunction(decoded);
        } else {
            function = decoded;
            cache_[cacheKey] = decoded;
        }
    }

    std::shared_lock<std::shared_timed_mutex> lock(cache_mutex_);
    auto it = cache_.find(cacheKey);
    if (it == cache_.end() || it->second == nullptr) {
        return 0;
    }
    function = it->second;

    if (function->register_count == 0 ||
        function->inst_count == 0 ||
        function->register_list == nullptr ||
        function->inst_list == nullptr ||
        function->type_list == nullptr) {
        LOGE("decodeAndExecute failed: cached function is incomplete, fun_addr=0x%llx",
             static_cast<unsigned long long>(cacheKey));
        return 0;
    }

    // 分配新的寄存器区
    RegManager* regMgr = allocRegManager(function->register_count);
    VMRegSlot* registers = regMgr->slots;

    // 清零寄存器
    memset(registers, 0, 24 * function->register_count);

    // 拷贝缓存的寄存器初值
    memcpy(registers, function->register_list, 24 * function->register_count);

    // 如果有参数需要填充
    if (function->function_list && function->function_list->param_count > 0 && vaArgs) {
        fillParametersFromVa(registers, function->function_list, reinterpret_cast<VaStruct*>(vaArgs));
    }

    // 执行
    uint64_t result = executeState(function, registers, retBuffer);

    // 清理
    freeRegManager(regMgr);

    return result;
}

// 将压缩字节码解码成 zFunction（寄存器初值、类型表、指令流、分支表）。
zFunction* zVmEngine::decode(
    const uint8_t* bytecode,
    uint64_t bytecodeSize,
    uint64_t* externalInitArray
) {
    zByteCodeReader reader;
    reader.init(bytecode, bytecodeSize);

    // 步骤1：消费前 6 bit（解码起始标志）
    reader.read6bits();

    // 步骤2：读 register_count
    uint32_t registerCount = reader.read6bitExt();

    // 步骤3：分配 RegManager 并清零
    VMRegSlot* tempRegisters = new VMRegSlot[registerCount]();
    memset(tempRegisters, 0, 24 * registerCount);

    // 步骤4：读 first_inst_count（初值区指令条数）
    uint32_t firstInstCount = reader.read6bitExt();

    // 步骤5-6：分配并填充 temp_opcode_array
    uint32_t* tempOpcodeArray = nullptr;
    if (firstInstCount > 0) {
        tempOpcodeArray = new uint32_t[firstInstCount];
        for (uint32_t i = 0; i < firstInstCount; i++) {
            tempOpcodeArray[i] = reader.read6bitExt();
        }
    }

    // 步骤7：寄存器初值对
    // 按照规范：先读目标寄存器下标，然后循环读取外部数组下标
    if (firstInstCount > 0 && externalInitArray) {
        uint32_t targetReg = reader.read6bitExt();
        for (uint32_t i = 0; i < firstInstCount; i++) {
            uint32_t extIdx = reader.read6bitExt();
            if (targetReg < registerCount) {
                tempRegisters[targetReg].value = externalInitArray[extIdx];
                tempRegisters[targetReg].ownership = 0;
            }
            // 读取下一个目标寄存器下标（除了最后一次）
            if (i + 1 < firstInstCount) {
                targetReg = reader.read6bitExt();
            }
        }
    }

    // 步骤8：读 type_count
    uint32_t typeCount = reader.read6bitExt();

    // 步骤9：为当前函数创建独立 type pool 并解码 type_list
    std::unique_ptr<zTypeManager> typePool = std::make_unique<zTypeManager>();
    zType** typeList = typePool->decodeTypeList(reader, typeCount);

    // 步骤10：set_registers_initial_value
    uint32_t initValueCount = reader.read6bitExt();
    if (initValueCount > 0 && tempOpcodeArray) {
        setRegistersInitialValue(reader, initValueCount, tempOpcodeArray, typeList, tempRegisters);
    }

    // 释放 temp_opcode_array
    delete[] tempOpcodeArray;

    // 步骤11-12：读 inst_count 并填充 inst_list
    uint32_t instCount = reader.read6bitExt();
    uint32_t* instList = nullptr;
    if (instCount > 0) {
        instList = new uint32_t[instCount];
        for (uint32_t i = 0; i < instCount; i++) {
            instList[i] = reader.read6bitExt();
        }
    }

    // 步骤13-14：读 branch_count 并填充 branch_list
    uint32_t branchCount = reader.read6bitExt();
    uint32_t* branchList = nullptr;
    if (branchCount > 0) {
        branchList = new uint32_t[branchCount];
        for (uint32_t i = 0; i < branchCount; i++) {
            branchList[i] = reader.read6bitExt();
        }
    }

    // 步骤15：构建 zFunction
    zFunction* function = new zFunction();
    function->setFunAddr(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(bytecode)));
    
    // 从 type_list 获取 function_list（根据 IDA 代码，function_list 来自某个类型槽）
    // 这里简化处理：如果第一个类型是 FunctionStructType，则使用它
    FunctionStructType* functionList = nullptr;
    if (typeCount > 0 && typeList && typeList[0]) {
        if (typeList[0]->kind == TYPE_KIND_STRUCT) {
            functionList = reinterpret_cast<FunctionStructType*>(typeList[0]);
        }
    }
    
    function->function_list = functionList;
    function->register_count = registerCount;
    function->type_count = typeCount;
    function->inst_count = instCount;
    function->branch_count = branchCount;
    
    // 复制寄存器初值
    function->register_list = new VMRegSlot[registerCount];
    memcpy(function->register_list, tempRegisters, 24 * registerCount);
    
    function->inst_list = instList;
    function->param_list = branchList;  // branch_list 同时作为 param_list
    function->type_list = typeList;
    function->setTypePool(std::move(typePool));

    // 清理临时寄存器
    delete[] tempRegisters;

    return function;
}

// 执行已解码状态对象，包装为 execute(...) 参数调用。
uint64_t zVmEngine::executeState(
    zFunction* function,
    VMRegSlot* registers,
    void* retBuffer
) {
    if (function == nullptr) {
        return 0;
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
        function->param_list,
        function->ext_list
    );
}

uint64_t zVmEngine::execute(
    void* retBuffer,
    uint64_t funAddr,
    const zParams& params
) {
    std::shared_lock<std::shared_timed_mutex> lock(cache_mutex_);
    auto it = cache_.find(funAddr);
    if (it == cache_.end() || it->second == nullptr) {
        LOGE("execute by fun_addr failed: not found, fun_addr=0x%llx", static_cast<unsigned long long>(funAddr));
        return 0;
    }

    zFunction* function = it->second;

    // 优先走已解码态（decodeAndExecute 生成的缓存）。
    if (function->register_count > 0 &&
        function->inst_count > 0 &&
        function->register_list != nullptr &&
        function->inst_list != nullptr &&
        function->type_list != nullptr) {
        RegManager* regMgr = allocRegManager(function->register_count);
        VMRegSlot* registers = regMgr->slots;
        memset(registers, 0, 24 * function->register_count);
        memcpy(registers, function->register_list, 24 * function->register_count);

        if (!params.values.empty()) {
            const uint32_t paramSize = static_cast<uint32_t>(params.values.size());
            const uint32_t paramCount = (paramSize < function->register_count) ? paramSize : function->register_count;
            for (uint32_t i = 0; i < paramCount; ++i) {
                registers[i].value = params.values[i];
                registers[i].ownership = 0;
            }
        }

        const uint64_t result = executeState(function, registers, retBuffer);
        freeRegManager(regMgr);
        return result;
    }

    // 兼容文本函数（zFunction::loadUnencodedText 产生的缓存）。
    const uint32_t registerCount = function->regIdCount();
    const uint32_t typeCount = function->typeIdCount();
    const uint32_t branchCount = function->branchIdCount();
    const uint32_t instCount = function->instIdCount();
    if (registerCount == 0 || typeCount == 0 || instCount == 0) {
        LOGE("execute by fun_addr failed: invalid function data, fun_addr=0x%llx", static_cast<unsigned long long>(funAddr));
        return 0;
    }

    std::vector<VMRegSlot> registerList(registerCount);
    for (uint32_t i = 0; i < registerCount; ++i) {
        registerList[i] = VMRegSlot{};
        registerList[i].value = 0;
        registerList[i].ownership = 0;
    }
    if (!params.values.empty()) {
        const uint32_t paramSize = static_cast<uint32_t>(params.values.size());
        const uint32_t paramCount = (paramSize < registerCount) ? paramSize : registerCount;
        for (uint32_t i = 0; i < paramCount; ++i) {
            registerList[i].value = params.values[i];
            registerList[i].ownership = 0;
        }
    }

    zTypeManager localTypeManager;
    std::vector<zType*> typeList(typeCount, nullptr);
    const std::vector<uint32_t>& typeIdList = function->typeIdList();
    for (uint32_t i = 0; i < typeCount; ++i) {
        typeList[i] = localTypeManager.createFromCode(typeIdList[i]);
    }

    std::vector<uint32_t> instList = function->instIdList();
    std::vector<uint32_t> branchIdList = function->branchIdList();
    std::vector<uint64_t> branchAddrList = function->branchAddrList();

    soinfo* soInfo = GetSoinfo("libdemo.so");
    if (soInfo != nullptr) {
        setVmModuleBase(soInfo->base);
        for (size_t i = 0; i < branchAddrList.size(); ++i) {
            branchAddrList[i] += soInfo->base;
        }
    }

    return execute(
        retBuffer,
        registerCount,
        registerList.data(),
        typeCount,
        typeList.data(),
        instCount,
        instList.data(),
        branchCount,
        branchIdList.data(),
        branchAddrList.data()
    );
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
    uint64_t* branch_addr_list
) {
    if (instCount == 0 || instructions == nullptr) return 0;

    if (instructions[0] != OP_ALLOC_RETURN) {
        return 0;
    }

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
    ctx.branch_addr_list = branch_addr_list;
    ctx.pc = 0;
    ctx.branch_id = 0;
    ctx.saved_branch_id = 0;
    ctx.ret_value = 0;
    ctx.running = true;
    ctx.nzcv = 0;

    while (ctx.running && ctx.pc < ctx.inst_count) {
        dispatch(&ctx);
        instructions_executed_.fetch_add(1, std::memory_order_relaxed);
    }

    return ctx.ret_value;
}

// 分发当前 pc 对应的 opcode 到具体处理函数。
void zVmEngine::dispatch(VMContext* ctx) {
    if (ctx == nullptr) {
        return;
    }

    if (ctx->pc >= ctx->inst_count) {
        LOGD("pc=%u >= inst_count=%u, stop", ctx->pc, ctx->inst_count);
        ctx->running = false;
        return;
    }

    uint32_t opcode = ctx->instructions[ctx->pc];
    uint32_t pc_before = ctx->pc;

    if (opcode < OP_MAX && g_opcode_table[opcode]) {
        g_opcode_table[opcode](ctx);
    } else {
        op_unknown(ctx);
    }

    LOGD("pc %u -> %u  %s", pc_before, ctx->pc, getOpcodeName(opcode));
}




