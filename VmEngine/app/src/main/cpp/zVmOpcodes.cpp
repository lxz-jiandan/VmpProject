#include "zVmOpcodes.h"
#include "zLog.h"
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <cinttypes>
#include <iostream>
#include <atomic>

#ifndef VM_TRACE
#define VM_TRACE 0
#endif

#if VM_TRACE
#define VM_TRACE_LOGD(...) LOGD(__VA_ARGS__)
#else
#define VM_TRACE_LOGD(...) ((void)0)
#endif

#ifndef VM_DEBUG_HOOK
#define VM_DEBUG_HOOK 0
#endif

// GCC/Clang 原子操作封装：统一提供 32/64 位原子原语，供 VM 指令实现复用。
// 32 位原子加：返回加之前的旧值。
inline uint32_t atomic_fetch_add(uint32_t* ptr, uint32_t val) {
    return __sync_fetch_and_add(ptr, val);
}
// 64 位原子加：返回加之前的旧值。
inline uint64_t atomic_fetch_add(uint64_t* ptr, uint64_t val) {
    return __sync_fetch_and_add(ptr, val);
}
// 32 位原子减：返回减之前的旧值。
inline uint32_t atomic_fetch_sub(uint32_t* ptr, uint32_t val) {
    return __sync_fetch_and_sub(ptr, val);
}
// 64 位原子减：返回减之前的旧值。
inline uint64_t atomic_fetch_sub(uint64_t* ptr, uint64_t val) {
    return __sync_fetch_and_sub(ptr, val);
}
// 32 位原子交换：写入新值并返回旧值。
inline uint32_t atomic_exchange(uint32_t* ptr, uint32_t val) {
    return __sync_lock_test_and_set(ptr, val);
}
// 64 位原子交换：写入新值并返回旧值。
inline uint64_t atomic_exchange(uint64_t* ptr, uint64_t val) {
    return __sync_lock_test_and_set(ptr, val);
}
// 32 位原子比较交换：若 *ptr == expected 则写入 desired，返回交换前值。
inline uint32_t atomic_compare_exchange(uint32_t* ptr, uint32_t expected, uint32_t desired) {
    return __sync_val_compare_and_swap(ptr, expected, desired);
}
// 64 位原子比较交换：若 *ptr == expected 则写入 desired，返回交换前值。
inline uint64_t atomic_compare_exchange(uint64_t* ptr, uint64_t expected, uint64_t desired) {
    return __sync_val_compare_and_swap(ptr, expected, desired);
}
// 全栅栏：保证该线程内存访问顺序在屏障两侧不会重排。
inline void atomic_fence() {
    __sync_synchronize();
}


// ============================================================================
// 全局 Opcode 跳转表
// ============================================================================
OpcodeHandler g_opcode_table[OP_MAX] = {nullptr};
static uint64_t g_vm_module_base = 0;

void setVmModuleBase(uint64_t base) {
    g_vm_module_base = base;
}

// 初始化全局 opcode 跳转表，建立 opcode 到处理函数的映射关系。
void initOpcodeTable() {
    // 建立 opcode 到处理函数的静态分发表，避免运行时大量 switch 判断。
    // 初始化为未知处理函数
    for (int i = 0; i < OP_MAX; i++) {
        g_opcode_table[i] = op_unknown;
    }

    // 注册已实现的 opcode 处理函数
    g_opcode_table[OP_END]            = op_end;
    g_opcode_table[OP_BINARY]         = op_binary;
    g_opcode_table[OP_TYPE_CONVERT]   = op_type_convert;
    g_opcode_table[OP_LOAD_CONST]     = op_load_const;
    g_opcode_table[OP_STORE_CONST]    = op_store_const;
    g_opcode_table[OP_GET_ELEMENT]    = op_get_element;
    g_opcode_table[OP_ALLOC_RETURN]  = op_alloc_return;
    g_opcode_table[OP_ALLOC_VSP]     = op_alloc_vsp;
    g_opcode_table[OP_BINARY_IMM]    = op_binary_imm;
    g_opcode_table[OP_STORE]         = op_store;
    g_opcode_table[OP_LOAD_CONST64]   = op_load_const64;
    g_opcode_table[OP_NOP]            = op_nop;
    g_opcode_table[OP_COPY]           = op_copy;
    g_opcode_table[OP_GET_FIELD]      = op_get_field;
    g_opcode_table[OP_CMP]            = op_cmp;
    g_opcode_table[OP_SET_FIELD]      = op_set_field;
    g_opcode_table[OP_RESTORE_REG]    = op_restore_reg;
    g_opcode_table[OP_CALL]           = op_call;
    g_opcode_table[OP_RETURN]         = op_return;
    g_opcode_table[OP_BRANCH]         = op_branch;
    g_opcode_table[OP_BRANCH_IF]      = op_branch_if;
    g_opcode_table[OP_ALLOC_MEMORY]   = op_alloc_memory;
    g_opcode_table[OP_MOV]            = op_mov;
    g_opcode_table[OP_LOAD_IMM]       = op_load_imm;
    g_opcode_table[OP_DYNAMIC_CAST]   = op_dynamic_cast;
    g_opcode_table[OP_UNARY]          = op_unary;
    g_opcode_table[OP_PHI]            = op_phi;
    g_opcode_table[OP_SELECT]         = op_select;
    g_opcode_table[OP_MEMCPY]         = op_memcpy;
    g_opcode_table[OP_MEMSET]         = op_memset;
    g_opcode_table[OP_STRLEN]         = op_strlen;
    g_opcode_table[OP_FETCH_NEXT]     = op_fetch_next;
    g_opcode_table[OP_CALL_INDIRECT]  = op_call_indirect;
    g_opcode_table[OP_SWITCH]         = op_switch;
    g_opcode_table[OP_GET_PTR]        = op_get_ptr;
    g_opcode_table[OP_BITCAST]        = op_bitcast;
    g_opcode_table[OP_SIGN_EXTEND]    = op_sign_extend;
    g_opcode_table[OP_ZERO_EXTEND]    = op_zero_extend;
    g_opcode_table[OP_TRUNCATE]       = op_truncate;
    g_opcode_table[OP_FLOAT_EXTEND]   = op_float_extend;
    g_opcode_table[OP_FLOAT_TRUNCATE] = op_float_truncate;
    g_opcode_table[OP_INT_TO_FLOAT]   = op_int_to_float;
    g_opcode_table[OP_ARRAY_ELEM]     = op_array_elem;
    g_opcode_table[OP_FLOAT_TO_INT]   = op_float_to_int;
    g_opcode_table[OP_READ]           = op_read;
    g_opcode_table[OP_WRITE]          = op_write;
    g_opcode_table[OP_LEA]            = op_lea;
    g_opcode_table[OP_ATOMIC_ADD]     = op_atomic_add;
    g_opcode_table[OP_ATOMIC_SUB]     = op_atomic_sub;
    g_opcode_table[OP_ATOMIC_XCHG]    = op_atomic_xchg;
    g_opcode_table[OP_ATOMIC_CAS]     = op_atomic_cas;
    g_opcode_table[OP_FENCE]          = op_fence;
    g_opcode_table[OP_UNREACHABLE]    = op_unreachable;
    g_opcode_table[OP_BRANCH_IF_CC]   = op_branch_if_cc;
    g_opcode_table[OP_SET_RETURN_PC]  = op_set_return_pc;
    g_opcode_table[OP_BL]             = op_bl;
    g_opcode_table[OP_ADRP]           = op_adrp;
}

// subOp 高位标记：0x40 表示本条运算需要更新 VM 标志寄存器（对应 ARM64 SUBS/ADDS）。
#define BIN_UPDATE_FLAGS  0x40u

// ============================================================================
// 辅助宏
// ============================================================================
static inline void vmTrapBounds(VMContext* ctx, const char* kind, uint32_t index, uint32_t limit) {
    if (ctx == nullptr) {
        return;
    }
    LOGE("[VM_BOUNDS] %s out of range: idx=%u limit=%u pc=%u inst_count=%u",
         kind,
         index,
         limit,
         ctx->pc,
         ctx->inst_count);
    ctx->running = false;
    ctx->pc = ctx->inst_count;
}

static inline uint32_t vmGetInstChecked(VMContext* ctx, uint32_t offset) {
    if (ctx == nullptr || !ctx->running) {
        return 0;
    }
    if (ctx->instructions == nullptr) {
        LOGE("[VM_BOUNDS] instruction buffer is null, pc=%u", ctx->pc);
        ctx->running = false;
        ctx->pc = ctx->inst_count;
        return 0;
    }

    const uint64_t instIndex = static_cast<uint64_t>(ctx->pc) + static_cast<uint64_t>(offset);
    if (instIndex >= ctx->inst_count) {
        vmTrapBounds(ctx, "inst", static_cast<uint32_t>(instIndex), ctx->inst_count);
        return 0;
    }
    return ctx->instructions[instIndex];
}

static inline VMRegSlot& vmGetRegChecked(VMContext* ctx, uint32_t idx) {
    static VMRegSlot invalidSlot{};
    if (ctx == nullptr || !ctx->running) {
        return invalidSlot;
    }
    if (ctx->registers == nullptr) {
        LOGE("[VM_BOUNDS] register buffer is null, pc=%u", ctx->pc);
        ctx->running = false;
        ctx->pc = ctx->inst_count;
        return invalidSlot;
    }
    if (idx >= ctx->register_count) {
        vmTrapBounds(ctx, "reg", idx, ctx->register_count);
        return invalidSlot;
    }
    return ctx->registers[idx];
}

#define GET_INST(offset) vmGetInstChecked(ctx, static_cast<uint32_t>(offset))
#define GET_REG(idx) vmGetRegChecked(ctx, static_cast<uint32_t>(idx))
#define GET_TYPE(idx) (((idx) < ctx->type_count && ctx->types != nullptr) ? ctx->types[(idx)] : nullptr)

// 调试辅助：读取 x0 的当前值，便于关键路径打点。
static inline uint64_t log_x0_deref(VMContext* ctx) {
    if (!ctx || ctx->register_count == 0) return 0;
    return GET_REG(0).value;
}

// 将 opcode 数值转换为可读字符串，便于日志和调试输出。
const char* getOpcodeName(uint32_t opcode) {
    switch (opcode) {
        case OP_END: return "OP_END";
        case OP_BINARY: return "OP_BINARY";
        case OP_TYPE_CONVERT: return "OP_TYPE_CONVERT";
        case OP_LOAD_CONST: return "OP_LOAD_CONST";
        case OP_STORE_CONST: return "OP_STORE_CONST";
        case OP_GET_ELEMENT: return "OP_GET_ELEMENT";
        case OP_ALLOC_RETURN: return "OP_ALLOC_RETURN";
        case OP_STORE: return "OP_STORE";
        case OP_LOAD_CONST64: return "OP_LOAD_CONST64";
        case OP_NOP: return "OP_NOP";
        case OP_COPY: return "OP_COPY";
        case OP_GET_FIELD: return "OP_GET_FIELD";
        case OP_CMP: return "OP_CMP";
        case OP_SET_FIELD: return "OP_SET_FIELD";
        case OP_RESTORE_REG: return "OP_RESTORE_REG";
        case OP_CALL: return "OP_CALL";
        case OP_RETURN: return "OP_RETURN";
        case OP_BRANCH: return "OP_BRANCH";
        case OP_BRANCH_IF: return "OP_BRANCH_IF";
        case OP_ALLOC_MEMORY: return "OP_ALLOC_MEMORY";
        case OP_MOV: return "OP_MOV";
        case OP_LOAD_IMM: return "OP_LOAD_IMM";
        case OP_DYNAMIC_CAST: return "OP_DYNAMIC_CAST";
        case OP_UNARY: return "OP_UNARY";
        case OP_PHI: return "OP_PHI";
        case OP_SELECT: return "OP_SELECT";
        case OP_MEMCPY: return "OP_MEMCPY";
        case OP_MEMSET: return "OP_MEMSET";
        case OP_STRLEN: return "OP_STRLEN";
        case OP_FETCH_NEXT: return "OP_FETCH_NEXT";
        case OP_CALL_INDIRECT: return "OP_CALL_INDIRECT";
        case OP_SWITCH: return "OP_SWITCH";
        case OP_GET_PTR: return "OP_GET_PTR";
        case OP_BITCAST: return "OP_BITCAST";
        case OP_SIGN_EXTEND: return "OP_SIGN_EXTEND";
        case OP_ZERO_EXTEND: return "OP_ZERO_EXTEND";
        case OP_TRUNCATE: return "OP_TRUNCATE";
        case OP_FLOAT_EXTEND: return "OP_FLOAT_EXTEND";
        case OP_FLOAT_TRUNCATE: return "OP_FLOAT_TRUNCATE";
        case OP_INT_TO_FLOAT: return "OP_INT_TO_FLOAT";
        case OP_ARRAY_ELEM: return "OP_ARRAY_ELEM";
        case OP_FLOAT_TO_INT: return "OP_FLOAT_TO_INT";
        case OP_READ: return "OP_READ";
        case OP_WRITE: return "OP_WRITE";
        case OP_LEA: return "OP_LEA";
        case OP_ATOMIC_ADD: return "OP_ATOMIC_ADD";
        case OP_ATOMIC_SUB: return "OP_ATOMIC_SUB";
        case OP_ATOMIC_XCHG: return "OP_ATOMIC_XCHG";
        case OP_ATOMIC_CAS: return "OP_ATOMIC_CAS";
        case OP_FENCE: return "OP_FENCE";
        case OP_UNREACHABLE: return "OP_UNREACHABLE";
        case OP_ALLOC_VSP: return "OP_ALLOC_VSP";
        case OP_BINARY_IMM: return "OP_BINARY_IMM";
        case OP_BRANCH_IF_CC: return "OP_BRANCH_IF_CC";
        case OP_SET_RETURN_PC: return "OP_SET_RETURN_PC";
        case OP_BL: return "OP_BL";
        case OP_ADRP: return "OP_ADRP";
        default: return "OP_???";
    }
}

// ============================================================================
// 辅助函数实现
// ============================================================================

// 执行二元运算：根据类型信息选择整数或浮点路径。
uint64_t execBinaryOp(uint32_t op, uint64_t lhs, uint64_t rhs, zType* type) {
    if (type && type->is_float) {
        double l, r, result;
        if (type->size == 4) {
            float fl, fr;
            memcpy(&fl, &lhs, 4);
            memcpy(&fr, &rhs, 4);
            l = fl; r = fr;
        } else {
            memcpy(&l, &lhs, 8);
            memcpy(&r, &rhs, 8);
        }

        switch (op) {
            case BIN_ADD:  result = l + r; break;
            case BIN_SUB:  result = l - r; break;
            case BIN_MUL:  result = l * r; break;
            case BIN_DIV:  result = l / r; break;
            case BIN_FMOD: result = fmod(l, r); break;
            default: result = 0; break;
        }

        uint64_t ret = 0;
        if (type->size == 4) {
            float f = static_cast<float>(result);
            memcpy(&ret, &f, 4);
        } else {
            memcpy(&ret, &result, 8);
        }
        return ret;
    }

    // 整数运算
    int64_t sl = static_cast<int64_t>(lhs);
    int64_t sr = static_cast<int64_t>(rhs);
    bool isSigned = type ? type->is_signed : false;

    switch (op) {
        case BIN_XOR:  return lhs ^ rhs;
        case BIN_SUB:  return lhs - rhs;
        case BIN_ASR:  return static_cast<uint64_t>(sl >> (rhs & 63));
        case BIN_DIV:
        case BIN_IDIV:
            if (rhs == 0) return 0;
            return isSigned ? static_cast<uint64_t>(sl / sr) : lhs / rhs;
        case BIN_ADD:  return lhs + rhs;
        case BIN_OR:   return lhs | rhs;
        case BIN_MOD:
        case BIN_FMOD:
            if (rhs == 0) return 0;
            return isSigned ? static_cast<uint64_t>(sl % sr) : lhs % rhs;
        case BIN_MUL:  return lhs * rhs;
        case BIN_LSR:  return lhs >> (rhs & 63);
        case BIN_SHL:  return lhs << (rhs & 63);
        case BIN_AND:  return lhs & rhs;
        default: return 0;
    }
}

// 执行一元运算：支持整数位运算与浮点数学运算。
uint64_t execUnaryOp(uint32_t op, uint64_t src, zType* type) {
    if (type && type->is_float) {
        double val;
        if (type->size == 4) {
            float f;
            memcpy(&f, &src, 4);
            val = f;
        } else {
            memcpy(&val, &src, 8);
        }

        double result;
        switch (op) {
            case UNARY_NEG:   result = -val; break;
            case UNARY_ABS:   result = fabs(val); break;
            case UNARY_SQRT:  result = sqrt(val); break;
            case UNARY_CEIL:  result = ceil(val); break;
            case UNARY_FLOOR: result = floor(val); break;
            case UNARY_ROUND: result = round(val); break;
            default: result = val; break;
        }

        uint64_t ret = 0;
        if (type->size == 4) {
            float f = static_cast<float>(result);
            memcpy(&ret, &f, 4);
        } else {
            memcpy(&ret, &result, 8);
        }
        return ret;
    }

    int64_t s = static_cast<int64_t>(src);
    switch (op) {
        case UNARY_NEG:  return static_cast<uint64_t>(-s);
        case UNARY_NOT:  return ~src;
        case UNARY_LNOT: return src ? 0 : 1;
        case UNARY_ABS:  return static_cast<uint64_t>(s < 0 ? -s : s);
        default: return src;
    }
}

// 执行比较运算并返回布尔结果（0/1）。
uint64_t execCompareOp(uint32_t op, uint64_t lhs, uint64_t rhs, zType* type) {
    if (type && type->is_float) {
        double l, r;
        if (type->size == 4) {
            float fl, fr;
            memcpy(&fl, &lhs, 4);
            memcpy(&fr, &rhs, 4);
            l = fl; r = fr;
        } else {
            memcpy(&l, &lhs, 8);
            memcpy(&r, &rhs, 8);
        }

        switch (op) {
            case CMP_FEQ:   return l == r ? 1 : 0;
            case CMP_FLE_N: return l <= r ? 0 : 1;
            case CMP_FLT_N: return l < r ? 0 : 1;
            case CMP_FLT:   return l < r ? 1 : 0;
            case CMP_FGT_N: return l > r ? 0 : 1;
            case CMP_FNE:   return l == r ? 0 : 1;
            default: break;
        }
    }

    int64_t sl = static_cast<int64_t>(lhs);
    int64_t sr = static_cast<int64_t>(rhs);

    switch (op) {
        case CMP_EQ:  return lhs == rhs ? 1 : 0;
        case CMP_NE:  return lhs != rhs ? 1 : 0;
        case CMP_GT:  return sl > sr ? 1 : 0;
        case CMP_GE:  return sl >= sr ? 1 : 0;
        case CMP_LT:  return sl < sr ? 1 : 0;
        case CMP_LE:  return sl <= sr ? 1 : 0;
        case CMP_UGT: return lhs > rhs ? 1 : 0;
        case CMP_UGE: return lhs >= rhs ? 1 : 0;
        case CMP_ULT: return lhs < rhs ? 1 : 0;
        case CMP_ULE: return lhs <= rhs ? 1 : 0;
        default: return 0;
    }
}

// 执行类型转换：按转换操作码在整数/浮点语义间转换。
uint64_t execTypeConvert(uint32_t op, uint64_t src, zType* srcType, zType* dstType) {
    switch (op) {
        case CONV_COPY:
        case CONV_COPY2:
        case CONV_COPY3:
        case CONV_COPY4:
            return src;

        case CONV_SEXT: {
            // 符号扩展：基于源类型的位宽来确定符号位
            if (!srcType) return src;
            uint32_t bits = srcType->bit_width;
            if (bits == 0) bits = srcType->size * 8;
            int64_t val = static_cast<int64_t>(src);
            if (bits < 64) {
                int64_t mask = (1LL << bits) - 1;
                val &= mask;
                // 检查符号位并扩展
                if (val & (1LL << (bits - 1))) {
                    val |= ~mask;
                }
            }
            return static_cast<uint64_t>(val);
        }

        case CONV_F2D: {
            float f;
            memcpy(&f, &src, 4);
            double d = f;
            uint64_t ret;
            memcpy(&ret, &d, 8);
            return ret;
        }

        case CONV_F2U: {
            float f;
            memcpy(&f, &src, 4);
            return static_cast<uint64_t>(f);
        }

        case CONV_F2I: {
            float f;
            memcpy(&f, &src, 4);
            return static_cast<uint64_t>(static_cast<int64_t>(f));
        }

        case CONV_S2F: {
            int64_t i = static_cast<int64_t>(src);
            if (dstType && dstType->size == 4) {
                float f = static_cast<float>(i);
                uint64_t ret = 0;
                memcpy(&ret, &f, 4);
                return ret;
            } else {
                double d = static_cast<double>(i);
                uint64_t ret;
                memcpy(&ret, &d, 8);
                return ret;
            }
        }

        case CONV_TRUNC: {
            if (!dstType) return src;
            uint32_t bits = dstType->bit_width;
            if (bits < 64) {
                return src & ((1ULL << bits) - 1);
            }
            return src;
        }

        case CONV_U2F: {
            if (dstType && dstType->size == 4) {
                float f = static_cast<float>(src);
                uint64_t ret = 0;
                memcpy(&ret, &f, 4);
                return ret;
            } else {
                double d = static_cast<double>(src);
                uint64_t ret;
                memcpy(&ret, &d, 8);
                return ret;
            }
        }

        case CONV_D2F: {
            double d;
            memcpy(&d, &src, 8);
            float f = static_cast<float>(d);
            uint64_t ret = 0;
            memcpy(&ret, &f, 4);
            return ret;
        }

        default:
            return src;
    }
}

// 根据 IDA 反编译的 vm_copy_value_1 (0x13ffc8)
// 如果 type_kind == 14 (ARRAY_ELEM)，使用 memcpy
// 否则根据类型大小 (1/2/4/8 字节) 拷贝值
// 复制寄存器槽值；当类型需要时处理内存拷贝与 ownership 标记。
void copyValue(VMRegSlot* src, zType* type, VMRegSlot* dst) {
    if (!type) {
        dst->value = src->value;
        return;
    }
    
    uint32_t typeKind = type->getKind();
    
    // 特殊处理：type_kind == 14 (ARRAY_ELEM) 使用 memcpy
    if (typeKind == TYPE_KIND_ARRAY_ELEM) {
        void* srcPtr = reinterpret_cast<void*>(src->value);
        void* dstPtr = reinterpret_cast<void*>(dst->value);
        if (srcPtr && dstPtr) {
            uint32_t size = type->getSize();
            memcpy(dstPtr, srcPtr, size);
        }
        return;
    }
    
    // 根据类型大小拷贝
    uint32_t size = type->getSize();
    switch (size) {
        case 1: dst->value = static_cast<uint8_t>(src->value); break;
        case 2: dst->value = static_cast<uint16_t>(src->value); break;
        case 4: dst->value = static_cast<uint32_t>(src->value); break;
        case 8:
        default: 
            dst->value = src->value; 
            break;
    }
}

// 根据 IDA 反编译的 vm_read_value_1 (0x13ff24)
// 如果 type_kind == 14 (ARRAY_ELEM)，存储指针本身（不解引用）
// 并设置 ownership = 0 (偏移 16)
// 否则根据类型大小读取 1/2/4/8 字节
// 按类型宽度从地址读取值并写入目标槽位。
void readValue(VMRegSlot* addrSlot, zType* type, VMRegSlot* dst) {
    void* addr = reinterpret_cast<void*>(addrSlot->value);
    if (!addr) {
        dst->value = 0;
        return;
    }
    if (!type) {
        dst->value = *static_cast<uint64_t*>(addr);
        return;
    }
    
    uint32_t typeKind = type->getKind();
    
    // 特殊处理：type_kind == 14 (ARRAY_ELEM)
    // 存储指针本身，不解引用
    if (typeKind == TYPE_KIND_ARRAY_ELEM) {
        dst->value = reinterpret_cast<uint64_t>(addr);
        dst->ownership = 0;
        return;
    }
    
    // 根据类型大小读取
    uint32_t size = type->getSize();
    switch (size) {
        case 1: 
            // 有符号扩展
            dst->value = static_cast<uint64_t>(static_cast<int8_t>(*static_cast<uint8_t*>(addr))); 
            break;
        case 2: 
            // 有符号扩展
            dst->value = static_cast<uint64_t>(static_cast<int16_t>(*static_cast<uint16_t*>(addr))); 
            break;
        case 4:
            if (type->is_float) {
                float f = *static_cast<float*>(addr);
                dst->value = 0;
                memcpy(&dst->value, &f, 4);
            } else {
                // 有符号扩展
                dst->value = static_cast<uint64_t>(static_cast<int32_t>(*static_cast<uint32_t*>(addr)));
            }
            break;
        case 8:
        default:
            dst->value = *static_cast<uint64_t*>(addr);
            break;
    }
}

// 根据 IDA 反编译的 vm_write_value (类似 vm_copy_value_1 的逻辑)
// 按类型宽度将槽位值写入目标地址。
void writeValue(VMRegSlot* addrSlot, zType* type, VMRegSlot* valueSlot) {
    void* addr = reinterpret_cast<void*>(addrSlot->value);
    if (!addr) return;

    if (!type) {
        *static_cast<uint64_t*>(addr) = valueSlot->value;
        return;
    }
    
    uint32_t typeKind = type->getKind();
    
    // 特殊处理：type_kind == 14 (ARRAY_ELEM) 使用 memcpy
    if (typeKind == TYPE_KIND_ARRAY_ELEM) {
        void* srcPtr = reinterpret_cast<void*>(valueSlot->value);
        if (srcPtr) {
            uint32_t size = type->getSize();
            memcpy(addr, srcPtr, size);
        }
        return;
    }
    
    uint64_t value = valueSlot->value;
    uint32_t size = type->getSize();
    switch (size) {
        case 1: *static_cast<uint8_t*>(addr) = static_cast<uint8_t>(value); break;
        case 2: *static_cast<uint16_t*>(addr) = static_cast<uint16_t>(value); break;
        case 4: *static_cast<uint32_t*>(addr) = static_cast<uint32_t>(value); break;
        case 8:
        default: 
            *static_cast<uint64_t*>(addr) = value; 
            break;
    }
}

// ============================================================================
// NZCV 标志更新与条件判断（与 ARM64 一致）
// ============================================================================
// 根据减法结果更新 VM 的 NZCV 标志位。
static void setFlagsFromSub(VMContext* ctx, uint64_t lhs, uint64_t rhs, uint64_t result, bool is64) {
    if (is64) {
        int64_t sl = static_cast<int64_t>(lhs);
        int64_t sr = static_cast<int64_t>(rhs);
        int64_t res = static_cast<int64_t>(result);
        ctx->nzcv = 0;
        if (res < 0) ctx->nzcv |= VM_FLAG_N;
        if (result == 0) ctx->nzcv |= VM_FLAG_Z;
        if (lhs >= rhs) ctx->nzcv |= VM_FLAG_C;  // 无符号无借位
        if (((sl ^ sr) & (sl ^ res)) < 0) ctx->nzcv |= VM_FLAG_V;  // 有符号溢出
    } else {
        uint32_t l = static_cast<uint32_t>(lhs);
        uint32_t r = static_cast<uint32_t>(rhs);
        uint32_t res = static_cast<uint32_t>(result);
        int32_t sl = static_cast<int32_t>(l);
        int32_t sr = static_cast<int32_t>(r);
        int32_t sres = static_cast<int32_t>(res);
        ctx->nzcv = 0;
        if (sres < 0) ctx->nzcv |= VM_FLAG_N;
        if (res == 0) ctx->nzcv |= VM_FLAG_Z;
        if (l >= r) ctx->nzcv |= VM_FLAG_C;
        if (((sl ^ sr) & (sl ^ sres)) < 0) ctx->nzcv |= VM_FLAG_V;
    }
}

// 根据加法结果更新 VM 的 NZCV 标志位。
static void setFlagsFromAdd(VMContext* ctx, uint64_t lhs, uint64_t rhs, uint64_t result, bool is64) {
    if (is64) {
        int64_t sl = static_cast<int64_t>(lhs);
        int64_t sr = static_cast<int64_t>(rhs);
        int64_t res = static_cast<int64_t>(result);
        ctx->nzcv = 0;
        if (res < 0) ctx->nzcv |= VM_FLAG_N;
        if (result == 0) ctx->nzcv |= VM_FLAG_Z;
        if (result < lhs) ctx->nzcv |= VM_FLAG_C;  // 无符号进位
        if (((sl ^ res) & (sr ^ res)) < 0) ctx->nzcv |= VM_FLAG_V;  // 有符号溢出
    } else {
        uint32_t l = static_cast<uint32_t>(lhs);
        uint32_t r = static_cast<uint32_t>(rhs);
        uint32_t res = static_cast<uint32_t>(result);
        int32_t sl = static_cast<int32_t>(l);
        int32_t sr = static_cast<int32_t>(r);
        int32_t sres = static_cast<int32_t>(res);
        ctx->nzcv = 0;
        if (sres < 0) ctx->nzcv |= VM_FLAG_N;
        if (res == 0) ctx->nzcv |= VM_FLAG_Z;
        if (res < l) ctx->nzcv |= VM_FLAG_C;
        if (((sl ^ sres) & (sr ^ sres)) < 0) ctx->nzcv |= VM_FLAG_V;
    }
}

// 仅根据结果值更新 N/Z 标志位（不改动 C/V）。
static void setFlagsFromResultNZ(VMContext* ctx, uint64_t result, zType* type) {
    uint32_t size = type && type->size ? type->size : 8;
    ctx->nzcv = 0;
    if (size == 4) {
        int32_t s = static_cast<int32_t>(static_cast<uint32_t>(result));
        if (s < 0) ctx->nzcv |= VM_FLAG_N;
    } else {
        if (static_cast<int64_t>(result) < 0) ctx->nzcv |= VM_FLAG_N;
    }
    if (result == 0) ctx->nzcv |= VM_FLAG_Z;
}

// 根据当前 nzcv 与条件码 cc（AArch64 编码 0..15）判断条件是否成立
// 按 AArch64 条件码语义，用 nzcv 判定条件是否成立。
static bool evaluateCondition(uint8_t nzcv, uint32_t cc) {
    bool N = (nzcv & VM_FLAG_N) != 0;
    bool Z = (nzcv & VM_FLAG_Z) != 0;
    bool C = (nzcv & VM_FLAG_C) != 0;
    bool V = (nzcv & VM_FLAG_V) != 0;
    switch (cc) {
        case 0x0: return Z;                    // EQ
        case 0x1: return !Z;                   // NE
        case 0x2: return C;                    // HS
        case 0x3: return !C;                   // LO
        case 0x4: return N;                    // MI
        case 0x5: return !N;                   // PL
        case 0x6: return V;                    // VS
        case 0x7: return !V;                   // VC
        case 0x8: return C && !Z;              // HI
        case 0x9: return !C || Z;              // LS
        case 0xa: return N == V;               // GE
        case 0xb: return N != V;               // LT
        case 0xc: return !Z && (N == V);       // GT
        case 0xd: return Z || (N != V);        // LE
        case 0xe: return true;                 // AL
        case 0xf: return false;                 // NV
        default: return false;
    }
}

// ============================================================================
// Opcode 处理函数实现
// ============================================================================

// OP_END：停止解释循环。
void op_end(VMContext* ctx) {
    ctx->running = false;
}

// OP_BINARY：执行寄存器-寄存器二元运算，可选更新 NZCV。
void op_binary(VMContext* ctx) {
    // 布局: [0]=opcode, [1]=subOp, [2]=typeIdx, [3]=lhsReg, [4]=rhsReg, [5]=dstReg；语义 dstReg = type.op(lhsReg, rhsReg)
    uint32_t subOp = GET_INST(1);   // 二元算子：BIN_SUB/BIN_ADD/...；高 bit 0x40 表示更新标志
    uint32_t typeIdx = GET_INST(2);
    uint32_t lhsReg = GET_INST(3);
    uint32_t rhsReg = GET_INST(4);
    uint32_t dstReg = GET_INST(5);

    zType* type = GET_TYPE(typeIdx);
    uint32_t actualOp = subOp & 0x3Fu;
    uint64_t lhs = GET_REG(lhsReg).value;
    uint64_t rhs = GET_REG(rhsReg).value;
    uint64_t result = execBinaryOp(actualOp, lhs, rhs, type);
    GET_REG(dstReg).value = result;

    if (subOp & BIN_UPDATE_FLAGS) {
        bool is64 = (type && type->size == 8);
        if (actualOp == BIN_SUB)
            setFlagsFromSub(ctx, lhs, rhs, result, is64);
        else if (actualOp == BIN_ADD)
            setFlagsFromAdd(ctx, lhs, rhs, result, is64);
        else
            setFlagsFromResultNZ(ctx, result, type);
    }
    ctx->pc += 6;
}

// OP_BINARY_IMM：执行寄存器与立即数二元运算，可选更新 NZCV。
void op_binary_imm(VMContext* ctx) {
    // 布局: [0]=opcode(52), [1]=subOp, [2]=typeIdx, [3]=lhsReg, [4]=imm, [5]=dstReg；subOp 的 0x40 标记表示更新 NZCV
    uint32_t subOp = GET_INST(1);
    uint32_t typeIdx = GET_INST(2);
    uint32_t lhsReg = GET_INST(3);
    uint32_t imm = GET_INST(4);
    uint32_t dstReg = GET_INST(5);

    zType* type = GET_TYPE(typeIdx);
    uint32_t actualOp = subOp & 0x3Fu;
    uint64_t lhs = GET_REG(lhsReg).value;
    uint64_t rhs = static_cast<uint64_t>(imm);
    uint64_t result = execBinaryOp(actualOp, lhs, rhs, type);
    GET_REG(dstReg).value = result;

    if (subOp & BIN_UPDATE_FLAGS) {
        bool is64 = (type && type->size == 8);
        if (actualOp == BIN_SUB)
            setFlagsFromSub(ctx, lhs, rhs, result, is64);
        else if (actualOp == BIN_ADD)
            setFlagsFromAdd(ctx, lhs, rhs, result, is64);
        else
            setFlagsFromResultNZ(ctx, result, type);
        VM_TRACE_LOGD("[OP_BINARY_IMM] updateFlags subOp=0x%x result=%" PRIu64 " -> nzcv=0x%x *x0=%" PRIu64,
                      (unsigned)subOp,
                      (unsigned long long)result,
                      (unsigned)ctx->nzcv,
                      (unsigned long long)log_x0_deref(ctx));
    }
    ctx->pc += 6;
}

// OP_TYPE_CONVERT：按 src/dst 类型执行转换并写入目标寄存器。
void op_type_convert(VMContext* ctx) {
    // 参数槽位：[pc+1]=sub_op, [pc+2]=dst_type, [pc+3]=src_type, [pc+4]=src_reg, [pc+5]=dst_reg
    uint32_t subOp = GET_INST(1);
    uint32_t dstTypeIdx = GET_INST(2);
    uint32_t srcTypeIdx = GET_INST(3);
    uint32_t srcReg = GET_INST(4);
    uint32_t dstReg = GET_INST(5);

    zType* srcType = GET_TYPE(srcTypeIdx);
    zType* dstType = GET_TYPE(dstTypeIdx);
    uint64_t src = GET_REG(srcReg).value;
    uint64_t result = execTypeConvert(subOp, src, srcType, dstType);
    GET_REG(dstReg).value = result;
    GET_REG(dstReg).ownership = 0;

    ctx->pc += 6;
}

// OP_LOAD_CONST：加载 32 位立即数到寄存器。
void op_load_const(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_reg, [pc+2]=value
    uint32_t dstReg = GET_INST(1);
    uint32_t value = GET_INST(2);
    GET_REG(dstReg).value = value;
    ctx->pc += 3;
}

// OP_STORE_CONST：将立即数按类型写入目标地址。
void op_store_const(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=addr_reg, [pc+3]=value
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t value = GET_INST(3);

    zType* type = GET_TYPE(typeIdx);
    void* addr = reinterpret_cast<void*>(GET_REG(addrReg).value);
    if (addr && type) {
        switch (type->size) {
            case 1: *static_cast<uint8_t*>(addr) = value; break;
            case 2: *static_cast<uint16_t*>(addr) = value; break;
            case 4: *static_cast<uint32_t*>(addr) = value; break;
            default: *static_cast<uint64_t*>(addr) = value; break;
        }
    }
    ctx->pc += 4;
}

// OP_GET_ELEMENT：按索引与元素大小计算元素地址/访问位置。
void op_get_element(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=base_reg, [pc+3]=index_reg, [pc+4]=dst_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t baseReg = GET_INST(2);
    uint32_t indexReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    uint64_t base = GET_REG(baseReg).value;
    uint64_t index = GET_REG(indexReg).value;
    uint32_t elemSize = type ? type->size : 8;

    GET_REG(dstReg).value = base + index * elemSize;
    ctx->pc += 5;
}

// OP_ALLOC_RETURN：初始化返回缓冲相关寄存器语义。
void op_alloc_return(VMContext* ctx) {
    // 布局: [opcode][result_type][size_type][size_reg][dst_reg]
    uint32_t dstReg = GET_INST(4);
    // 避免每次执行都分配临时堆内存；优先复用调用方传入的返回缓冲。
    ctx->ret_value = (ctx->ret_buffer != nullptr)
                     ? reinterpret_cast<uint64_t>(ctx->ret_buffer)
                     : 0;
    VM_TRACE_LOGD("[OP_ALLOC_RETURN] dstReg=%u ret_value=0x%llx *x0=0x%llx",
                  (unsigned)dstReg,
                  (unsigned long long)ctx->ret_value,
                  (unsigned long long)log_x0_deref(ctx));
    ctx->pc += 5;
}

// OP_ALLOC_VSP：为虚拟栈分配空间并更新 SP/VSP 相关寄存器。
void op_alloc_vsp(VMContext* ctx) {
    // 布局同 OP_ALLOC_RETURN: [0]=opcode(51), [1]=resultTypeIdx, [2]=sizeTypeIdx, [3]=sizeReg, [4]=dstReg
    // 动态申请一块堆内存作为虚拟栈；将 块起始地址+大小 写入 dstReg（VSP），并标记 ownership=1；大小暂时固定 1024
    uint32_t fpReg = GET_INST(4);
    uint32_t spReg = GET_INST(5);
    size_t kVspSize = 1024;

    void* block = malloc(kVspSize);
    if (!block) {
        ctx->pc += 6;
        return;
    }
    const uint64_t blockBase = reinterpret_cast<uint64_t>(block);
    const uint64_t vspValue = blockBase + kVspSize;

    VMRegSlot& fpSlot = GET_REG(fpReg);
    fpSlot.value = vspValue;
    fpSlot.reserved = blockBase;
    fpSlot.ownership = 1;

    if (spReg != fpReg) {
        VMRegSlot& spSlot = GET_REG(spReg);
        spSlot.value = vspValue;
        spSlot.reserved = 0;
        spSlot.ownership = 0;
    }

    VM_TRACE_LOGD("[OP_ALLOC_VSP] fpReg=%u spReg=%u vsp=0x%llx base=0x%llx *x0=0x%llx",
                  (unsigned)fpReg,
                  (unsigned)spReg,
                  (unsigned long long)vspValue,
                  (unsigned long long)blockBase,
                  (unsigned long long)log_x0_deref(ctx));
    ctx->pc += 6;
}

// OP_STORE：把源寄存器值写入目标地址。
void op_store(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=addr_reg, [pc+3]=value_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t valueReg = GET_INST(3);

    zType* type = GET_TYPE(typeIdx);
    writeValue(&GET_REG(addrReg), type, &GET_REG(valueReg));

    ctx->pc += 4;
}

// OP_LOAD_CONST64：加载 64 位立即数到寄存器。
void op_load_const64(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_reg, [pc+2]=low32, [pc+3]=high32
    uint32_t dstReg = GET_INST(1);
    uint64_t low = GET_INST(2);
    uint64_t high = GET_INST(3);
    GET_REG(dstReg).value = low | (high << 32);
    ctx->pc += 4;
}

// OP_NOP：不做任何计算，仅推进程序计数器。
void op_nop(VMContext* ctx) {
    ctx->pc += 1;
}

// OP_COPY：根据类型语义复制源寄存器到目标寄存器。
void op_copy(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=src_reg, [pc+3]=dst_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t srcReg = GET_INST(2);
    uint32_t dstReg = GET_INST(3);

    zType* type = GET_TYPE(typeIdx);
    copyValue(&GET_REG(srcReg), type, &GET_REG(dstReg));

    ctx->pc += 4;
}

// OP_GET_FIELD：按偏移从基址读取字段值。
void op_get_field(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=base_reg, [pc+3]=offset, [pc+4]=dst_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t baseReg = GET_INST(2);
    int32_t offset = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    uint64_t base = GET_REG(baseReg).value;
    if (base == 0) {
        GET_REG(dstReg).value = 0;
        GET_REG(dstReg).ownership = 0;
        ctx->pc += 5;
        return;
    }
    void* fieldAddr = reinterpret_cast<void*>(base + offset);

    if (fieldAddr && type) {
        switch (type->size) {
            case 1: GET_REG(dstReg).value = *static_cast<uint8_t*>(fieldAddr); break;
            case 2: GET_REG(dstReg).value = *static_cast<uint16_t*>(fieldAddr); break;
            case 4: GET_REG(dstReg).value = *static_cast<uint32_t*>(fieldAddr); break;
            default: GET_REG(dstReg).value = *static_cast<uint64_t*>(fieldAddr); break;
        }
    }

    ctx->pc += 5;
}

// OP_CMP：执行比较并写结果，必要时更新条件标志位。
void op_cmp(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=lhs_reg, [pc+3]=rhs_reg, [pc+4]=result_reg, [pc+5]=cmp_op；同时按 lhs-rhs 更新 NZCV
    uint32_t typeIdx = GET_INST(1);
    uint32_t lhsReg = GET_INST(2);
    uint32_t rhsReg = GET_INST(3);
    uint32_t resultReg = GET_INST(4);
    uint32_t cmpOp = GET_INST(5);

    zType* type = GET_TYPE(typeIdx);
    uint64_t lhs = GET_REG(lhsReg).value;
    uint64_t rhs = GET_REG(rhsReg).value;
    uint64_t result = execCompareOp(cmpOp, lhs, rhs, type);
    GET_REG(resultReg).value = result;

    if (type && !type->is_float) {
        uint32_t size = type->size;
        bool is64 = (size == 8);
        uint64_t diff = lhs - rhs;
        if (!is64) diff &= 0xFFFFFFFFu;
        setFlagsFromSub(ctx, lhs, rhs, diff, is64);
        VM_TRACE_LOGD("[OP_CMP] lhs=%" PRIu64 " rhs=%" PRIu64 " -> nzcv=0x%x *x0=%" PRIu64,
                      (unsigned long long)lhs,
                      (unsigned long long)rhs,
                      (unsigned)ctx->nzcv,
                      (unsigned long long)log_x0_deref(ctx));
    }
    ctx->pc += 6;
}

// OP_SET_FIELD：按偏移向基址写入字段值。
void op_set_field(VMContext* ctx) {

    // 参数槽位：[pc+1]=type_idx, [pc+2]=base_reg, [pc+3]=offset, [pc+4]=value_reg（value_reg>=register_count 表示 str wzr/xzr，存 0）
    uint32_t typeIdx = GET_INST(1);
    uint32_t baseReg = GET_INST(2);
    int32_t offset = GET_INST(3);
    uint32_t valueReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    uint64_t base = GET_REG(baseReg).value;
    if (base == 0) {
        ctx->pc += 5;
        return;
    }
    uint64_t value = (valueReg < ctx->register_count) ? GET_REG(valueReg).value : 0;
    void* fieldAddr = reinterpret_cast<void*>(base + offset);

    VM_TRACE_LOGD("[OP_SET_FIELD] baseReg=%u offset=0x%x valueReg=%u value=0x%llx *x0=0x%llx",
                  (unsigned)baseReg,
                  (unsigned)offset,
                  (unsigned)valueReg,
                  (unsigned long long)value,
                  (unsigned long long)log_x0_deref(ctx));

    if (fieldAddr && type) {
        switch (type->size) {
            case 1: *static_cast<uint8_t*>(fieldAddr) = static_cast<uint8_t>(value); break;
            case 2: *static_cast<uint16_t*>(fieldAddr) = static_cast<uint16_t>(value); break;
            case 4: *static_cast<uint32_t*>(fieldAddr) = static_cast<uint32_t>(value); break;
            default: *static_cast<uint64_t*>(fieldAddr) = value; break;
        }
    }

    ctx->pc += 5;
}

// OP_RESTORE_REG：从保存区恢复寄存器值。
void op_restore_reg(VMContext* ctx) {
    // 布局: [opcode][dst_slot][reserved][pair_count][pairs...]
    // 参数槽位：[pc+0]=opcode=14, [pc+1]=dst_slot, [pc+2]=reserved, [pc+3]=pair_count
    // 参数槽位：[pc+4..pc+3+2*pair_count]=(reg_slot, branch_id) 对
    // pc 步进 = 4 + 2*pair_count
    
    uint32_t dstSlot = GET_INST(1);
    uint32_t pairCount = GET_INST(3);

    bool matched = false;
    for (uint32_t i = 0; i < pairCount; i++) {
        uint32_t regIdx = GET_INST(4 + i * 2);
        uint32_t branchId = GET_INST(4 + i * 2 + 1);
        if (branchId == ctx->saved_branch_id) {
            GET_REG(dstSlot).value = GET_REG(regIdx).value;
            matched = true;
            break;
        }
    }
    
    if (!matched) {
        // 分支 ID 不匹配，可能是默认分支
        // 不一定是错误，继续执行
    }

    ctx->pc += 4 + pairCount * 2;
}

// OP_CALL：执行直接调用并按约定处理返回值与现场。
void op_call(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=param_count, [pc+3]=type_mask, [pc+4]=result_reg,
    // 参数槽位：[pc+5]=func_ptr_reg, [pc+6..]=param_regs
    uint32_t paramCount = GET_INST(2);
    uint32_t typeMask = GET_INST(3);
    uint32_t resultReg = GET_INST(4);
    uint32_t funcPtrReg = GET_INST(5);

    uint64_t funcPtr = GET_REG(funcPtrReg).value;

    if (funcPtr == 0) {
        if (typeMask & 0x1) {
            GET_REG(resultReg).value = 0;
        }
        ctx->pc += 6 + paramCount;
        return;
    }

    // VM 内调用（BL）：funcPtr 为 branchId 时，跳转到 branch_id_list[branchId]；LR 已由前一条 OP_LOAD_IMM 填好
    if (ctx->branch_id_list && funcPtr < ctx->branch_count) {
        uint32_t targetPc = ctx->branch_id_list[static_cast<uint32_t>(funcPtr)];
        if (targetPc < ctx->inst_count) {
            ctx->pc = targetPc;
            return;
        }
    }

    // 准备参数（原生 FFI）
    uint64_t args[16] = {0};
    for (uint32_t i = 0; i < paramCount && i < 16; i++) {
        uint32_t paramReg = GET_INST(6 + i);
        args[i] = GET_REG(paramReg).value;
    }

    // 调用函数（简化 FFI）
    typedef uint64_t (*FuncPtr0)();
    typedef uint64_t (*FuncPtr1)(uint64_t);
    typedef uint64_t (*FuncPtr2)(uint64_t, uint64_t);
    typedef uint64_t (*FuncPtr3)(uint64_t, uint64_t, uint64_t);
    typedef uint64_t (*FuncPtr4)(uint64_t, uint64_t, uint64_t, uint64_t);
    typedef uint64_t (*FuncPtr5)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    typedef uint64_t (*FuncPtr6)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

    uint64_t callResult = 0;
    switch (paramCount) {
        case 0: callResult = reinterpret_cast<FuncPtr0>(funcPtr)(); break;
        case 1: callResult = reinterpret_cast<FuncPtr1>(funcPtr)(args[0]); break;
        case 2: callResult = reinterpret_cast<FuncPtr2>(funcPtr)(args[0], args[1]); break;
        case 3: callResult = reinterpret_cast<FuncPtr3>(funcPtr)(args[0], args[1], args[2]); break;
        case 4: callResult = reinterpret_cast<FuncPtr4>(funcPtr)(args[0], args[1], args[2], args[3]); break;
        case 5: callResult = reinterpret_cast<FuncPtr5>(funcPtr)(args[0], args[1], args[2], args[3], args[4]); break;
        default: callResult = reinterpret_cast<FuncPtr6>(funcPtr)(args[0], args[1], args[2], args[3], args[4], args[5]); break;
    }

    if (typeMask & 0x1) {
        GET_REG(resultReg).value = callResult;
        GET_REG(resultReg).ownership = 0;
    }

    ctx->pc += 6 + paramCount;
}

// OP_RETURN：设置返回值并终止当前执行流。
void op_return(VMContext* ctx) {
    // 参数槽位：[pc+1]=has_value, [pc+2]=value_reg（可选）
    uint32_t hasValue = GET_INST(1);
    if (hasValue) {
        uint32_t valueReg = GET_INST(2);
        ctx->ret_value = GET_REG(valueReg).value;
        VM_TRACE_LOGD("[OP_RETURN] valueReg=%u ret_value=%" PRIu64 " *x0=%" PRIu64,
                      (unsigned)valueReg,
                      (unsigned long long)ctx->ret_value,
                      (unsigned long long)log_x0_deref(ctx));
        // 返回值由 ret_value 统一承载，不再把 8 字节标量强制写回 ret_buffer，
        // 以免覆盖对象返回（如 std::string）的构造结果。
        GET_REG(valueReg).ownership = 0;
    }
    ctx->running = false;
}

// OP_BRANCH：无条件跳转到分支表目标。
void op_branch(VMContext* ctx) {
    // 参数槽位：[pc+1]=branchId；targetPc = ctx->branch_id_list[branchId]
    uint32_t branchId = GET_INST(1);
    uint32_t target = 0;
    if (ctx->branch_id_list && branchId < ctx->branch_count)
        target = ctx->branch_id_list[branchId];
    VM_TRACE_LOGD("[OP_BRANCH] branchId=%u branch_count=%u targetPc=%u inst_count=%u *x0=%" PRIu64,
                  (unsigned)branchId,
                  (unsigned)ctx->branch_count,
                  (unsigned)target,
                  (unsigned)ctx->inst_count,
                  (unsigned long long)log_x0_deref(ctx));
    if (target < ctx->inst_count) {
        ctx->pc = target;
    } else {
        ctx->running = false;
    }
}

// OP_BRANCH_IF：按条件寄存器值决定是否跳转。
void op_branch_if(VMContext* ctx) {
    // 参数槽位：[pc+1]=cond_reg, [pc+2]=true_target, [pc+3]=false_target；
    // true_target/false_target 均按 branch_id_list 下标解析。
    uint32_t condReg = GET_INST(1);
    uint32_t trueTarget = GET_INST(2);
    uint32_t falseTarget = GET_INST(3);

    uint64_t cond = GET_REG(condReg).value;
    uint32_t idx = cond ? trueTarget : falseTarget;
    if (ctx->branch_id_list == nullptr || idx >= ctx->branch_count) {
        LOGE("op_branch_if invalid branch index: idx=%u branch_count=%u", idx, ctx->branch_count);
        ctx->running = false;
        return;
    }
    uint32_t target = ctx->branch_id_list[idx];

    if (target < ctx->inst_count) {
        ctx->pc = target;
    } else {
        LOGE("op_branch_if target out of range: target=%u inst_count=%u", target, ctx->inst_count);
        ctx->running = false;
    }
}

// OP_BRANCH_IF_CC：按 NZCV+条件码判定是否跳转。
void op_branch_if_cc(VMContext* ctx) {
    // [0]=opcode, [1]=cc, [2]=branchId；若 nzcv 满足 cc 则 pc = branch_list[branchId]，否则 pc += 3（fall-through）
    uint32_t cc = GET_INST(1);
    uint32_t branchId = GET_INST(2);
    uint32_t fallthroughPc = ctx->pc + 3;
    bool taken = evaluateCondition(ctx->nzcv, cc);
    uint32_t targetPc = (ctx->branch_id_list && branchId < ctx->branch_count) ? ctx->branch_id_list[branchId] : fallthroughPc;

    VM_TRACE_LOGD("[OP_BRANCH_IF_CC] cc=%u branchId=%u nzcv=0x%x taken=%d targetPc=%u fallthrough=%u *x0=%" PRIu64,
                  (unsigned)cc,
                  (unsigned)branchId,
                  (unsigned)ctx->nzcv,
                  (int)taken,
                  (unsigned)targetPc,
                  (unsigned)fallthroughPc,
                  (unsigned long long)log_x0_deref(ctx));

    if (taken) {
        if (targetPc < ctx->inst_count)
            ctx->pc = targetPc;
        else
            ctx->pc = fallthroughPc;
    } else {
        ctx->pc = fallthroughPc;
    }
}

// OP_SET_RETURN_PC：写入当前 PC 相对返回地址。
void op_set_return_pc(VMContext* ctx) {
    // [0]=opcode, [1]=dstReg, [2]=offset；运行时设置 dstReg = 当前 pc + offset（用于 BL 的 LR）
    uint32_t dstReg = GET_INST(1);
    uint32_t offset = GET_INST(2);
    if (dstReg < ctx->register_count)
        GET_REG(dstReg).value = ctx->pc + offset;
    ctx->pc += 3;
}

// 以 AArch64 ABI 调用原生地址：显式传入 x0..x7 和 x8（用于 sret 等隐藏参数）。
static uint64_t call_native_with_x8(uint64_t target_addr, const uint64_t args[8], uint64_t x8_value) {
#if defined(__aarch64__)
    register uint64_t x0 asm("x0") = args[0];
    register uint64_t x1 asm("x1") = args[1];
    register uint64_t x2 asm("x2") = args[2];
    register uint64_t x3 asm("x3") = args[3];
    register uint64_t x4 asm("x4") = args[4];
    register uint64_t x5 asm("x5") = args[5];
    register uint64_t x6 asm("x6") = args[6];
    register uint64_t x7 asm("x7") = args[7];
    register uint64_t x8 asm("x8") = x8_value;
    register uint64_t x16 asm("x16") = target_addr;
    asm volatile(
        "blr x16"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4),
          "+r"(x5), "+r"(x6), "+r"(x7), "+r"(x8), "+r"(x16)
        :
        : "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "x30", "memory", "cc");
    return x0;
#else
    using BlrFunc8 = uint64_t (*)(
        uint64_t, uint64_t, uint64_t, uint64_t,
        uint64_t, uint64_t, uint64_t, uint64_t
    );
    auto fn = reinterpret_cast<BlrFunc8>(target_addr);
    return fn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
#endif
}

// OP_BL：带链接跳转，保存返回位点并跳转到目标。
void op_bl(VMContext* ctx) {
    // [0]=OP_BL, [1]=branchId；语义由你实现：通常设 LR=返回地址、跳转到 branch_id_list[branchId]
#if VM_DEBUG_HOOK
    if (ctx->pc == 136) {
        static const char* str = "zLog";
        static const char* str2 = "fun_for_add ret: %d";
        GET_REG(0).value = 6;
        GET_REG(1).value = reinterpret_cast<uint64_t>(str);
        GET_REG(2).value = reinterpret_cast<uint64_t>(str2);
    }
#endif

    uint32_t branchId = GET_INST(1);
    if (!ctx->running) {
        return;
    }
    VM_TRACE_LOGD("[OP_BL] branchId=%u", (unsigned)branchId);

    if (ctx->branch_addr_list == nullptr || branchId >= ctx->branch_addr_count) {
        LOGE("op_bl invalid branch target: branchId=%u branch_addr_count=%u", branchId, ctx->branch_addr_count);
        ctx->running = false;
        return;
    }

    uint64_t new_sp = 0;
    if (ctx->register_count > 31) {
        new_sp = GET_REG(31).value & 0xffffffffff;
    }
    uint64_t new_addr = ctx->branch_addr_list[branchId];

    VM_TRACE_LOGD("[OP_BL] new_sp=0x%llx new_addr=0x%llx",
                  (unsigned long long)new_sp,
                  (unsigned long long)new_addr);

    uint64_t args[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    const uint32_t argCount = (ctx->register_count < 8) ? ctx->register_count : 8;
    for (uint32_t i = 0; i < argCount; ++i) {
        args[i] = GET_REG(i).value;
        if (!ctx->running) {
            return;
        }
    }

    uint64_t arg_x8 = 0;
    if (ctx->register_count > 8) {
        arg_x8 = GET_REG(8).value;
    }
    uint64_t value = call_native_with_x8(new_addr, args, arg_x8);

    if (ctx->register_count > 0) {
        GET_REG(0).value = value;
        if (!ctx->running) {
            return;
        }
    }

    ctx->pc += 2;
}

// OP_ADRP：基于模块基址 + offset 计算地址并写入目标寄存器。
void op_adrp(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_reg, [pc+2]=offset_low32, [pc+3]=offset_high32
    uint32_t dstReg = GET_INST(1);
    uint32_t low = GET_INST(2);
    uint32_t high = GET_INST(3);
    uint64_t offset = static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);

    GET_REG(dstReg).value = g_vm_module_base + offset;
    GET_REG(dstReg).ownership = 0;

    ctx->pc += 4;
}

// OP_ALLOC_MEMORY：按类型大小在堆上分配对象存储。
void op_alloc_memory(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=dst_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t dstReg = GET_INST(2);

    zType* type = GET_TYPE(typeIdx);
    uint32_t size = type ? type->size : 8;
    void* ptr = calloc(1, size);

    if (ctx->ret_buffer) {
        *static_cast<uint64_t*>(ctx->ret_buffer) = reinterpret_cast<uint64_t>(ptr);
    }
    VMRegSlot& dstSlot = GET_REG(dstReg);
    dstSlot.value = reinterpret_cast<uint64_t>(ptr);
    dstSlot.reserved = dstSlot.value;
    dstSlot.ownership = 1;

    ctx->pc += 3;
}

// OP_MOV：将源寄存器值直接移动到目标寄存器。
void op_mov(VMContext* ctx) {
    // 参数槽位：[pc+1]=src_reg, [pc+2]=dst_reg
    uint32_t srcReg = GET_INST(1);
    uint32_t dstReg = GET_INST(2);

    GET_REG(dstReg).value = GET_REG(srcReg).value;
    GET_REG(dstReg).ownership = 0;

    ctx->pc += 3;
}

// OP_LOAD_IMM：加载立即数并做必要的位宽处理。
void op_load_imm(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_reg, [pc+2]=imm_value
    uint32_t dstReg = GET_INST(1);
    uint32_t immValue = GET_INST(2);

    GET_REG(dstReg).value = immValue;
    GET_REG(dstReg).ownership = 0;

    ctx->pc += 3;
}

// OP_DYNAMIC_CAST：执行运行时类型转换或兼容性检查。
void op_dynamic_cast(VMContext* ctx) {
    // 布局: [opcode][cmp_reg][type_idx][default_branch][pair_count][pairs...]
    // 参数槽位：[pc+0]=opcode=22, [pc+1]=cmp_reg, [pc+2]=type_idx(取mask), [pc+3]=default_branch_idx, [pc+4]=pair_count
    // 随后 2*pair_count 个：(value_reg, branch_id)
    // 跳转: target_pc = branch_list[branch_idx], pc = target_pc
    
    uint32_t cmpReg = GET_INST(1);
    uint32_t typeIdx = GET_INST(2);
    uint32_t defaultBranchIdx = GET_INST(3);
    uint32_t pairCount = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    uint64_t cmpVal = GET_REG(cmpReg).value;
    uint64_t mask = type && type->bit_width > 0 && type->bit_width < 64 
                   ? ((1ULL << type->bit_width) - 1) 
                   : 0xFFFFFFFFFFFFFFFFULL;

    uint32_t targetBranchIdx = defaultBranchIdx;
    for (uint32_t i = 0; i < pairCount; i++) {
        uint32_t valReg = GET_INST(5 + i * 2);
        uint32_t branchId = GET_INST(5 + i * 2 + 1);
        uint64_t val = GET_REG(valReg).value;
        if (((cmpVal ^ val) & mask) == 0) {
            targetBranchIdx = branchId;
            break;
        }
    }

    ctx->saved_branch_id = targetBranchIdx;
    
    if (ctx->branch_id_list && targetBranchIdx < ctx->branch_count) {
        uint32_t targetPc = ctx->branch_id_list[targetBranchIdx];
        ctx->pc = targetPc;
    } else {
        ctx->pc += 5 + pairCount * 2;
    }
}

// OP_UNARY：执行一元算子并写回目标寄存器。
void op_unary(VMContext* ctx) {
    // 参数槽位：[pc+1]=sub_op, [pc+2]=type_idx, [pc+3]=src_reg, [pc+4]=dst_reg
    uint32_t subOp = GET_INST(1);
    uint32_t typeIdx = GET_INST(2);
    uint32_t srcReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    uint64_t src = GET_REG(srcReg).value;
    uint64_t result = execUnaryOp(subOp, src, type);
    GET_REG(dstReg).value = result;

    ctx->pc += 5;
}

// OP_PHI：在多前驱值中选择当前控制流对应的输入。
void op_phi(VMContext* ctx) {
    // 目前仅保留占位语义：直接跳过，后续可按 SSA 前驱补全。
    ctx->pc += 1;
}

// OP_SELECT：基于条件寄存器选择两路值之一。
void op_select(VMContext* ctx) {
    // 参数槽位：[pc+1]=cond_reg, [pc+2]=true_reg, [pc+3]=false_reg, [pc+4]=dst_reg
    uint32_t condReg = GET_INST(1);
    uint32_t trueReg = GET_INST(2);
    uint32_t falseReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    uint64_t cond = GET_REG(condReg).value;
    GET_REG(dstReg).value = cond ? GET_REG(trueReg).value : GET_REG(falseReg).value;

    ctx->pc += 5;
}

// OP_MEMCPY：执行内存块复制。
void op_memcpy(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_reg, [pc+2]=src_reg, [pc+3]=size_reg
    uint32_t dstReg = GET_INST(1);
    uint32_t srcReg = GET_INST(2);
    uint32_t sizeReg = GET_INST(3);

    void* dst = reinterpret_cast<void*>(GET_REG(dstReg).value);
    void* src = reinterpret_cast<void*>(GET_REG(srcReg).value);
    size_t size = static_cast<size_t>(GET_REG(sizeReg).value);

    if (dst && src && size > 0) {
        memcpy(dst, src, size);
    }

    ctx->pc += 4;
}

// OP_MEMSET：执行内存块填充。
void op_memset(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_reg, [pc+2]=value_reg, [pc+3]=size_reg
    uint32_t dstReg = GET_INST(1);
    uint32_t valueReg = GET_INST(2);
    uint32_t sizeReg = GET_INST(3);

    void* dst = reinterpret_cast<void*>(GET_REG(dstReg).value);
    int value = static_cast<int>(GET_REG(valueReg).value);
    size_t size = static_cast<size_t>(GET_REG(sizeReg).value);

    if (dst && size > 0) {
        memset(dst, value, size);
    }

    ctx->pc += 4;
}

// OP_STRLEN：计算字符串长度并写入目标寄存器。
void op_strlen(VMContext* ctx) {
    // 参数槽位：[pc+1]=str_reg, [pc+2]=dst_reg
    uint32_t strReg = GET_INST(1);
    uint32_t dstReg = GET_INST(2);

    const char* str = reinterpret_cast<const char*>(GET_REG(strReg).value);
    GET_REG(dstReg).value = str ? strlen(str) : 0;

    ctx->pc += 3;
}

// OP_FETCH_NEXT：推进到下一执行片段或下一条语义指令。
void op_fetch_next(VMContext* ctx) {
    // 布局: [opcode][has_cmp][branch_id][cmp_reg][type_idx][alt_branch]
    // 参数槽位：[pc+0]=opcode=29, [pc+1]=has_cmp, [pc+2]=branch_id, [pc+3]=cmp_reg, [pc+4]=type_idx, [pc+5]=alt_branch
    // pc 步进 = 6（如果不跳转），否则 pc = branch_list[target_branch]
    
    uint32_t hasCmp = GET_INST(1);
    uint32_t branchIdFromInst = GET_INST(2);
    uint32_t cmpReg = GET_INST(3);
    // uint32_t typeIdx = GET_INST(4);  // 类型索引，用于 mask
    uint32_t altBranchIdx = GET_INST(5);

    uint32_t targetBranchIdx = branchIdFromInst;
    if (hasCmp) {
        uint64_t cmpVal = GET_REG(cmpReg).value;
        if (cmpVal == 0) {
            targetBranchIdx = altBranchIdx;
        }
    }

    // 保存 branch_id（用于后续的 RESTORE_REG 匹配）
    ctx->saved_branch_id = branchIdFromInst;
    
    if (ctx->branch_id_list && targetBranchIdx < ctx->branch_count) {
        uint32_t targetPc = ctx->branch_id_list[targetBranchIdx];
        ctx->pc = targetPc;
    } else {
        ctx->pc += 6;
    }
}

// OP_CALL_INDIRECT：通过函数指针执行间接调用。
void op_call_indirect(VMContext* ctx) {
    // 复用 op_call 逻辑，调用目标由寄存器中函数指针决定。
    op_call(ctx);
}

// OP_SWITCH：根据 case 值跳转到对应分支目标。
void op_switch(VMContext* ctx) {
    // 参数槽位：[pc+1]=value_reg, [pc+2]=default_target, [pc+3]=case_count, [pc+4..]=cases
    uint32_t valueReg = GET_INST(1);
    uint32_t defaultTarget = GET_INST(2);
    uint32_t caseCount = GET_INST(3);

    uint64_t value = GET_REG(valueReg).value;
    uint32_t target = defaultTarget;

    for (uint32_t i = 0; i < caseCount; i++) {
        uint64_t caseValue = GET_INST(4 + i * 2);
        uint32_t caseTarget = GET_INST(4 + i * 2 + 1);
        if (value == caseValue) {
            target = caseTarget;
            break;
        }
    }

    if (target < ctx->inst_count) {
        ctx->pc = target;
    } else {
        ctx->pc += 4 + caseCount * 2;
    }
}

// OP_GET_PTR：获取地址值并写入目标寄存器。
void op_get_ptr(VMContext* ctx) {
    // 参数槽位：[pc+1]=base_reg, [pc+2]=offset, [pc+3]=dst_reg
    uint32_t baseReg = GET_INST(1);
    uint32_t offset = GET_INST(2);
    uint32_t dstReg = GET_INST(3);

    GET_REG(dstReg).value = GET_REG(baseReg).value + offset;

    ctx->pc += 4;
}

// OP_BITCAST：按位重解释，不改变底层 bit 模式。
void op_bitcast(VMContext* ctx) {
    // 参数槽位：[pc+1]=src_reg, [pc+2]=dst_reg
    uint32_t srcReg = GET_INST(1);
    uint32_t dstReg = GET_INST(2);

    GET_REG(dstReg).value = GET_REG(srcReg).value;

    ctx->pc += 3;
}

// OP_SIGN_EXTEND：按源位宽做有符号扩展。
void op_sign_extend(VMContext* ctx) {
    // 参数槽位：[pc+1]=src_type, [pc+2]=dst_type, [pc+3]=src_reg, [pc+4]=dst_reg
    uint32_t srcTypeIdx = GET_INST(1);
    uint32_t dstTypeIdx = GET_INST(2);
    uint32_t srcReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* srcType = GET_TYPE(srcTypeIdx);
    int64_t value = static_cast<int64_t>(GET_REG(srcReg).value);

    // 符号扩展
    if (srcType) {
        uint32_t srcBits = srcType->bit_width;
        if (srcBits < 64) {
            int64_t signBit = 1LL << (srcBits - 1);
            if (value & signBit) {
                value |= ~((1LL << srcBits) - 1);
            }
        }
    }

    GET_REG(dstReg).value = static_cast<uint64_t>(value);

    ctx->pc += 5;
}

// OP_ZERO_EXTEND：按源位宽做无符号零扩展。
void op_zero_extend(VMContext* ctx) {
    // 参数槽位：[pc+1]=src_type, [pc+2]=dst_type, [pc+3]=src_reg, [pc+4]=dst_reg
    uint32_t srcTypeIdx = GET_INST(1);
    uint32_t srcReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* srcType = GET_TYPE(srcTypeIdx);
    uint64_t value = GET_REG(srcReg).value;

    if (srcType && srcType->bit_width < 64) {
        value &= (1ULL << srcType->bit_width) - 1;
    }

    GET_REG(dstReg).value = value;

    ctx->pc += 5;
}

// OP_TRUNCATE：按目标位宽截断高位数据。
void op_truncate(VMContext* ctx) {
    // 参数槽位：[pc+1]=dst_type, [pc+2]=src_reg, [pc+3]=dst_reg
    uint32_t dstTypeIdx = GET_INST(1);
    uint32_t srcReg = GET_INST(2);
    uint32_t dstReg = GET_INST(3);

    zType* dstType = GET_TYPE(dstTypeIdx);
    uint64_t value = GET_REG(srcReg).value;

    if (dstType && dstType->bit_width < 64) {
        value &= (1ULL << dstType->bit_width) - 1;
    }

    GET_REG(dstReg).value = value;

    ctx->pc += 4;
}

// OP_FLOAT_EXTEND：浮点窄类型扩展到宽类型。
void op_float_extend(VMContext* ctx) {
    // 当前实现固定按 float -> double 扩展。
    uint32_t srcReg = GET_INST(1);
    uint32_t dstReg = GET_INST(2);

    float f;
    memcpy(&f, &GET_REG(srcReg).value, 4);
    double d = f;
    memcpy(&GET_REG(dstReg).value, &d, 8);

    ctx->pc += 3;
}

// OP_FLOAT_TRUNCATE：浮点宽类型截断到窄类型。
void op_float_truncate(VMContext* ctx) {
    // 当前实现固定按 double -> float 截断。
    uint32_t srcReg = GET_INST(1);
    uint32_t dstReg = GET_INST(2);

    double d;
    memcpy(&d, &GET_REG(srcReg).value, 8);
    float f = static_cast<float>(d);
    GET_REG(dstReg).value = 0;
    memcpy(&GET_REG(dstReg).value, &f, 4);

    ctx->pc += 3;
}

// OP_INT_TO_FLOAT：整数转浮点。
void op_int_to_float(VMContext* ctx) {
    // 参数槽位：[pc+1]=is_signed, [pc+2]=dst_type, [pc+3]=src_reg, [pc+4]=dst_reg
    uint32_t isSigned = GET_INST(1);
    uint32_t dstTypeIdx = GET_INST(2);
    uint32_t srcReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* dstType = GET_TYPE(dstTypeIdx);
    uint64_t src = GET_REG(srcReg).value;

    if (dstType && dstType->size == 4) {
        float f = isSigned ? static_cast<float>(static_cast<int64_t>(src)) : static_cast<float>(src);
        GET_REG(dstReg).value = 0;
        memcpy(&GET_REG(dstReg).value, &f, 4);
    } else {
        double d = isSigned ? static_cast<double>(static_cast<int64_t>(src)) : static_cast<double>(src);
        memcpy(&GET_REG(dstReg).value, &d, 8);
    }

    ctx->pc += 5;
}

// OP_ARRAY_ELEM：按元素下标和类型信息计算元素地址。
void op_array_elem(VMContext* ctx) {
    // 布局: [opcode][dst_reg][reserved][elem_type][dim_count][base_reg][idx_regs...]
    // 参数槽位：[pc+0]=opcode=40, [pc+1]=dst_reg, [pc+2]=reserved, [pc+3]=elem_type, [pc+4]=dim_count
    // 若 dim_count > 0: [pc+5]=base_reg, [pc+6..pc+5+dim_count]=各维索引寄存器
    // pc 步进 = 6 + dim_count (如果有维度) 或 5 (如果 dim_count=0)
    
    uint32_t dstReg = GET_INST(1);
    uint32_t elemTypeIdx = GET_INST(3);
    uint32_t dimCount = GET_INST(4);

    zType* elemType = GET_TYPE(elemTypeIdx);
    uint32_t elemSize = elemType ? elemType->getSize() : 8;

    uint64_t baseAddr = 0;
    uint64_t offset = 0;

    if (dimCount > 0) {
        uint32_t baseReg = GET_INST(5);
        baseAddr = GET_REG(baseReg).value;

        // 计算偏移量（简化：假设一维数组）
        for (uint32_t dim = 0; dim < dimCount; dim++) {
            uint32_t idxReg = GET_INST(6 + dim);
            uint64_t idx = GET_REG(idxReg).value;
            // 对于多维数组，需要更复杂的 stride 计算
            // 这里简化为一维处理
            if (dim == 0) {
                offset = idx * elemSize;
            }
        }
        
        ctx->pc += 6 + dimCount;
    } else {
        ctx->pc += 5;
    }

    GET_REG(dstReg).value = baseAddr + offset;
}

// OP_FLOAT_TO_INT：浮点转整数，按目标类型处理符号与位宽。
void op_float_to_int(VMContext* ctx) {
    // 参数槽位：[pc+1]=is_signed, [pc+2]=src_type, [pc+3]=src_reg, [pc+4]=dst_reg
    uint32_t isSigned = GET_INST(1);
    uint32_t srcTypeIdx = GET_INST(2);
    uint32_t srcReg = GET_INST(3);
    uint32_t dstReg = GET_INST(4);

    zType* srcType = GET_TYPE(srcTypeIdx);

    if (srcType && srcType->size == 4) {
        float f;
        memcpy(&f, &GET_REG(srcReg).value, 4);
        GET_REG(dstReg).value = isSigned ? static_cast<uint64_t>(static_cast<int64_t>(f)) : static_cast<uint64_t>(f);
    } else {
        double d;
        memcpy(&d, &GET_REG(srcReg).value, 8);
        GET_REG(dstReg).value = isSigned ? static_cast<uint64_t>(static_cast<int64_t>(d)) : static_cast<uint64_t>(d);
    }

    ctx->pc += 5;
}

// OP_READ：从地址读取值到寄存器。
void op_read(VMContext* ctx) {
    // 布局: [opcode][type_idx][dst_reg][addr_reg]
    // 参数槽位：[pc+0]=opcode=42, [pc+1]=type_idx, [pc+2]=dst_reg, [pc+3]=addr_reg
    // pc 步进 = 4
    
    uint32_t typeIdx = GET_INST(1);
    uint32_t dstReg = GET_INST(2);
    uint32_t addrReg = GET_INST(3);

    zType* type = GET_TYPE(typeIdx);
    readValue(&GET_REG(addrReg), type, &GET_REG(dstReg));

    ctx->pc += 4;
}

// OP_WRITE：把寄存器值写回地址。
void op_write(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=addr_reg, [pc+3]=value_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t valueReg = GET_INST(3);

    zType* type = GET_TYPE(typeIdx);
    writeValue(&GET_REG(addrReg), type, &GET_REG(valueReg));

    ctx->pc += 4;
}

// OP_LEA：执行地址计算（base + index * scale + offset）。
void op_lea(VMContext* ctx) {
    // 参数槽位：[pc+1]=base_reg, [pc+2]=index_reg, [pc+3]=scale, [pc+4]=offset, [pc+5]=dst_reg
    uint32_t baseReg = GET_INST(1);
    uint32_t indexReg = GET_INST(2);
    uint32_t scale = GET_INST(3);
    uint32_t offset = GET_INST(4);
    uint32_t dstReg = GET_INST(5);

    uint64_t base = GET_REG(baseReg).value;
    uint64_t index = GET_REG(indexReg).value;

    GET_REG(dstReg).value = base + index * scale + offset;

    ctx->pc += 6;
}

// OP_ATOMIC_ADD：执行原子加并返回旧值。
void op_atomic_add(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=addr_reg, [pc+3]=value_reg, [pc+4]=result_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t valueReg = GET_INST(3);
    uint32_t resultReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    void* addr = reinterpret_cast<void*>(GET_REG(addrReg).value);
    uint64_t value = GET_REG(valueReg).value;

    uint64_t oldValue = 0;
    if (addr && type) {
        switch (type->size) {
            case 4:
                oldValue = atomic_fetch_add(static_cast<uint32_t*>(addr), static_cast<uint32_t>(value));
                break;
            case 8:
                oldValue = atomic_fetch_add(static_cast<uint64_t*>(addr), value);
                break;
        }
    }

    GET_REG(resultReg).value = oldValue;

    ctx->pc += 5;
}

// OP_ATOMIC_SUB：执行原子减并返回旧值。
void op_atomic_sub(VMContext* ctx) {
    // 参数布局与 op_atomic_add 一致，仅运算符替换为减法。
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t valueReg = GET_INST(3);
    uint32_t resultReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    void* addr = reinterpret_cast<void*>(GET_REG(addrReg).value);
    uint64_t value = GET_REG(valueReg).value;

    uint64_t oldValue = 0;
    if (addr && type) {
        switch (type->size) {
            case 4:
                oldValue = atomic_fetch_sub(static_cast<uint32_t*>(addr), static_cast<uint32_t>(value));
                break;
            case 8:
                oldValue = atomic_fetch_sub(static_cast<uint64_t*>(addr), value);
                break;
        }
    }

    GET_REG(resultReg).value = oldValue;

    ctx->pc += 5;
}

// OP_ATOMIC_XCHG：执行原子交换并返回旧值。
void op_atomic_xchg(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=addr_reg, [pc+3]=value_reg, [pc+4]=result_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t valueReg = GET_INST(3);
    uint32_t resultReg = GET_INST(4);

    zType* type = GET_TYPE(typeIdx);
    void* addr = reinterpret_cast<void*>(GET_REG(addrReg).value);
    uint64_t value = GET_REG(valueReg).value;

    uint64_t oldValue = 0;
    if (addr && type) {
        switch (type->size) {
            case 4:
                oldValue = atomic_exchange(static_cast<uint32_t*>(addr), static_cast<uint32_t>(value));
                break;
            case 8:
                oldValue = atomic_exchange(static_cast<uint64_t*>(addr), value);
                break;
        }
    }

    GET_REG(resultReg).value = oldValue;

    ctx->pc += 5;
}

// OP_ATOMIC_CAS：执行原子比较交换并返回交换前值。
void op_atomic_cas(VMContext* ctx) {
    // 参数槽位：[pc+1]=type_idx, [pc+2]=addr_reg, [pc+3]=expected_reg, [pc+4]=new_reg, [pc+5]=result_reg
    uint32_t typeIdx = GET_INST(1);
    uint32_t addrReg = GET_INST(2);
    uint32_t expectedReg = GET_INST(3);
    uint32_t newReg = GET_INST(4);
    uint32_t resultReg = GET_INST(5);

    zType* type = GET_TYPE(typeIdx);
    void* addr = reinterpret_cast<void*>(GET_REG(addrReg).value);
    uint64_t expected = GET_REG(expectedReg).value;
    uint64_t newVal = GET_REG(newReg).value;

    uint64_t oldValue = expected;
    if (addr && type) {
        switch (type->size) {
            case 4:
                oldValue = atomic_compare_exchange(static_cast<uint32_t*>(addr), 
                    static_cast<uint32_t>(expected), static_cast<uint32_t>(newVal));
                break;
            case 8:
                oldValue = atomic_compare_exchange(static_cast<uint64_t*>(addr), expected, newVal);
                break;
        }
    }

    GET_REG(resultReg).value = oldValue;

    ctx->pc += 6;
}

// OP_FENCE：执行全内存栅栏。
void op_fence(VMContext* ctx) {
    atomic_fence();
    ctx->pc += 1;
}

// OP_UNREACHABLE：触发不可达错误并停止执行。
void op_unreachable(VMContext* ctx) {
    std::cerr << "[VM ERROR] Reached unreachable code at pc=" << ctx->pc << std::endl;
    ctx->running = false;
}

// 未知 opcode 兜底处理：打印警告并终止。
void op_unknown(VMContext* ctx) {
    uint32_t opcode = GET_INST(0);
    std::cerr << "[VM WARNING] Unknown opcode " << opcode << " at pc=" << ctx->pc << std::endl;
    ctx->running = false;
}




