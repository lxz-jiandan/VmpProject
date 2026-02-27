/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - opcode 常量与处理函数声明。
 * - 加固链路位置：解释器指令接口层。
 * - 输入：opcode 编号。
 * - 输出：对应处理入口。
 */
#ifndef Z_VM_OPCODES_H
#define Z_VM_OPCODES_H

#include "zVmEngine.h"

// ============================================================================
// Opcode 定义
// ============================================================================
enum Opcode : uint32_t {
    OP_END            = 0,
    OP_BINARY         = 1,      // 二元运算
    OP_TYPE_CONVERT   = 2,      // 类型转换
    OP_LOAD_CONST     = 3,      // 加载常量
    OP_STORE_CONST    = 4,      // 存储常量
    OP_GET_ELEMENT    = 5,      // 获取数组元素
    OP_ALLOC_RETURN   = 6,      // 申请一块用于存放返回值的内存；首条指令必须为本指令
    OP_STORE          = 7,      // 写入内存
    OP_LOAD_CONST64   = 8,      // 加载64位常量
    OP_NOP            = 9,      // 空操作
    OP_COPY           = 10,     // 复制值
    OP_GET_FIELD      = 11,     // 获取字段
    OP_CMP            = 12,     // 比较运算
    OP_SET_FIELD      = 13,     // 设置字段
    OP_RESTORE_REG    = 14,     // 恢复寄存器
    OP_CALL           = 15,     // 函数调用
    OP_RETURN         = 16,     // 返回
    OP_BRANCH         = 17,     // 无条件跳转
    OP_BRANCH_IF      = 18,     // 条件跳转
    OP_ALLOC_MEMORY   = 19,     // 分配单对象
    OP_MOV            = 20,     // 寄存器移动
    OP_LOAD_IMM       = 21,     // 加载立即数
    OP_DYNAMIC_CAST   = 22,     // 动态类型转换
    OP_UNARY          = 23,     // 一元运算
    OP_PHI            = 24,     // PHI 节点
    OP_SELECT         = 25,     // 条件选择
    OP_MEMCPY         = 26,     // 内存拷贝
    OP_MEMSET         = 27,     // 内存设置
    OP_STRLEN         = 28,     // 字符串长度
    OP_FETCH_NEXT     = 29,     // 取下一条
    OP_CALL_INDIRECT  = 30,     // 间接调用
    OP_SWITCH         = 31,     // 多路分支跳转
    OP_GET_PTR        = 32,     // 获取指针
    OP_BITCAST        = 33,     // 位转换
    OP_SIGN_EXTEND    = 34,     // 符号扩展
    OP_ZERO_EXTEND    = 35,     // 零扩展
    OP_TRUNCATE       = 36,     // 截断
    OP_FLOAT_EXTEND   = 37,     // 浮点扩展
    OP_FLOAT_TRUNCATE = 38,     // 浮点截断
    OP_INT_TO_FLOAT   = 39,     // 整数转浮点
    OP_ARRAY_ELEM     = 40,     // 数组元素
    OP_FLOAT_TO_INT   = 41,     // 浮点转整数
    OP_READ           = 42,     // 读取内存
    OP_WRITE          = 43,     // 写入内存
    OP_LEA            = 44,     // 计算地址
    OP_ATOMIC_ADD     = 45,     // 原子加
    OP_ATOMIC_SUB     = 46,     // 原子减
    OP_ATOMIC_XCHG    = 47,     // 原子交换
    OP_ATOMIC_CAS     = 48,     // 原子比较交换
    OP_FENCE          = 49,     // 内存屏障
    OP_UNREACHABLE    = 50,     // 不可达
    OP_ALLOC_VSP      = 51,     // 动态申请虚拟栈（堆上），紧接 OP_ALLOC_RETURN 后
    OP_BINARY_IMM     = 52,     // 二元运算（寄存器 + 立即数），结果写入目标寄存器
    OP_BRANCH_IF_CC   = 53,     // 按 NZCV 条件码跳转到 branch_list[branchId]
    OP_SET_RETURN_PC  = 54,     // 运行时写入返回地址寄存器（dstReg = 当前 pc + offset）
    OP_BL             = 55,     // 带链接跳转（branchId -> branches[branchId]）
    OP_ADRP           = 56,     // 基于模块基址 + 页偏移计算地址
    OP_ATOMIC_LOAD    = 57,     // 原子读取（带内存序）
    OP_ATOMIC_STORE   = 58,     // 原子写入（带内存序）
    OP_BRANCH_REG     = 59,     // 间接跳转（目标地址由寄存器给出）

    OP_MAX            = 64      // 最大 opcode 数量
};

// 条件码（与 AArch64/capstone AArch64CC_CondCode 数值一致，供 OP_BRANCH_IF_CC 使用）
enum VMConditionCode : uint32_t {
    CC_EQ = 0x0, CC_NE = 0x1, CC_HS = 0x2, CC_LO = 0x3, CC_MI = 0x4, CC_PL = 0x5,
    CC_VS = 0x6, CC_VC = 0x7, CC_HI = 0x8, CC_LS = 0x9, CC_GE = 0xa, CC_LT = 0xb,
    CC_GT = 0xc, CC_LE = 0xd, CC_AL = 0xe, CC_NV = 0xf
};

// 原子内存序（映射到 __ATOMIC_* 常量，供 OP_ATOMIC_LOAD/STORE 使用）
enum VMMemoryOrder : uint32_t {
    VM_MEM_ORDER_RELAXED = 0,   // relaxed
    VM_MEM_ORDER_ACQUIRE = 1,   // acquire
    VM_MEM_ORDER_RELEASE = 2,   // release
    VM_MEM_ORDER_ACQ_REL = 3,   // acq_rel
    VM_MEM_ORDER_SEQ_CST = 4,   // seq_cst
};

// ============================================================================
// 二元运算子操作码
// ============================================================================
enum BinaryOp : uint32_t {
    BIN_XOR  = 0,     // 异或
    BIN_SUB  = 1,     // 减法
    BIN_ASR  = 2,     // 算术右移
    BIN_DIV  = 3,     // 除法（浮点/整数）
    BIN_ADD  = 4,     // 加法
    BIN_OR   = 5,     // 或
    BIN_MOD  = 6,     // 取模
    BIN_IDIV = 7,     // 整数除法
    BIN_FMOD = 8,     // 浮点 fmod / 整数取模
    BIN_MUL  = 9,     // 乘法
    BIN_LSR  = 0xA,   // 逻辑右移
    BIN_SHL  = 0xB,   // 左移
    BIN_AND  = 0xC,   // 与
};

// ============================================================================
// 一元运算子操作码
// ============================================================================
enum UnaryOp : uint32_t {
    UNARY_NEG  = 0,   // 取负
    UNARY_NOT  = 1,   // 按位取反
    UNARY_LNOT = 2,   // 逻辑取反
    UNARY_ABS  = 3,   // 绝对值
    UNARY_SQRT = 4,   // 平方根
    UNARY_CEIL = 5,   // 向上取整
    UNARY_FLOOR= 6,   // 向下取整
    UNARY_ROUND= 7,   // 四舍五入
    UNARY_CLZ  = 8,   // 统计前导零（count leading zeros）
};

// ============================================================================
// 比较运算子操作码
// ============================================================================
enum CompareOp : uint32_t {
    // 浮点比较
    CMP_FEQ   = 1,    // ==
    CMP_FLE_N = 2,    // <= (取反)
    CMP_FLT_N = 3,    // <  (取反)
    CMP_FLT   = 4,    // <
    CMP_FGT_N = 5,    // >  (取反)
    CMP_FNE   = 6,    // != (取反)

    // 整数比较
    CMP_EQ    = 0x20, // ==
    CMP_NE    = 0x21, // !=
    CMP_GT    = 0x22, // >
    CMP_GE    = 0x23, // >=
    CMP_LT    = 0x24, // <
    CMP_LE    = 0x25, // <=
    CMP_UGT   = 0x26, // > (无符号)
    CMP_UGE   = 0x27, // >= (无符号)
    CMP_ULT   = 0x28, // < (无符号)
    CMP_ULE   = 0x29, // <= (无符号)
};

// ============================================================================
// 类型转换子操作码
// ============================================================================
enum ConvertOp : uint32_t {
    CONV_COPY       = 0,    // 同宽拷贝
    CONV_SEXT       = 1,    // 有符号扩展
    CONV_F2D        = 2,    // float 转 double
    CONV_F2U        = 3,    // float 转无符号整数
    CONV_F2I        = 4,    // float 转有符号整数
    CONV_COPY2      = 5,    // 同宽拷贝
    CONV_S2F        = 6,    // 有符号整数转 float
    CONV_TRUNC      = 7,    // 截断
    CONV_U2F        = 8,    // 无符号整数转 float
    CONV_ASR_TRUNC  = 9,    // 算术右移截断
    CONV_COPY3      = 0xA,  // 同宽拷贝
    CONV_D2F        = 0xB,  // double 转 float
    CONV_COPY4      = 0xC,  // 同宽拷贝
};

// ============================================================================
// Opcode 处理函数类型
// ============================================================================
namespace vm {

typedef void (*OpcodeHandler)(VMContext* ctx);


// ============================================================================
// Opcode 处理函数声明
// ============================================================================

// 终止执行并结束解释循环。
void op_end(VMContext* ctx);
// 执行二元运算：srcL op srcR -> dst。
void op_binary(VMContext* ctx);
// 执行类型转换并写回目标寄存器。
void op_type_convert(VMContext* ctx);
// 将 32 位常量写入目标寄存器。
void op_load_const(VMContext* ctx);
// 将常量值写入指定内存地址。
void op_store_const(VMContext* ctx);
// 按元素索引从数组/指针中取元素地址或值。
void op_get_element(VMContext* ctx);
// 为返回值分配存储空间并初始化返回槽。
void op_alloc_return(VMContext* ctx);
// 将寄存器值写入内存。
void op_store(VMContext* ctx);
// 将 64 位常量写入目标寄存器。
void op_load_const64(VMContext* ctx);
// 空操作，仅推进指令流。
void op_nop(VMContext* ctx);
// 按类型语义复制寄存器值（含深浅拷贝处理）。
void op_copy(VMContext* ctx);
// 按偏移读取结构体/对象字段。
void op_get_field(VMContext* ctx);
// 执行比较并写比较结果。
void op_cmp(VMContext* ctx);
// 按偏移写入结构体/对象字段。
void op_set_field(VMContext* ctx);
// 从保存区恢复寄存器内容。
void op_restore_reg(VMContext* ctx);
// 调用外部函数或 VM 内部函数入口。
void op_call(VMContext* ctx);
// 返回调用方并设置返回值。
void op_return(VMContext* ctx);
// 无条件跳转到 branch 表目标。
void op_branch(VMContext* ctx);
// 根据寄存器布尔值条件跳转。
void op_branch_if(VMContext* ctx);
// 根据 NZCV 条件码跳转。
void op_branch_if_cc(VMContext* ctx);
// 设置“返回地址寄存器”对应的 PC 值。
void op_set_return_pc(VMContext* ctx);
// 执行带链接跳转（BL）语义。
void op_bl(VMContext* ctx);
// ADRP：基于模块基址 + offset 计算地址。
void op_adrp(VMContext* ctx);
// 间接跳转：按目标地址查表跳转到函数内 PC。
void op_branch_reg(VMContext* ctx);
// 为单对象分配堆内存。
void op_alloc_memory(VMContext* ctx);
// 寄存器到寄存器移动。
void op_mov(VMContext* ctx);
// 加载立即数到寄存器。
void op_load_imm(VMContext* ctx);
// 动态类型转换（运行时检查/转换）。
void op_dynamic_cast(VMContext* ctx);
// 执行一元运算。
void op_unary(VMContext* ctx);
// 处理 SSA φ 节点选择。
void op_phi(VMContext* ctx);
// 按条件在两个值中选择一个。
void op_select(VMContext* ctx);
// 内存块拷贝。
void op_memcpy(VMContext* ctx);
// 内存块填充。
void op_memset(VMContext* ctx);
// 计算字符串长度。
void op_strlen(VMContext* ctx);
// 读取并执行下一条相关指令流程。
void op_fetch_next(VMContext* ctx);
// 间接调用函数指针。
void op_call_indirect(VMContext* ctx);
// 多分支跳转（switch）。
void op_switch(VMContext* ctx);
// 获取指针值/地址。
void op_get_ptr(VMContext* ctx);
// 按位重解释转换（bitcast）。
void op_bitcast(VMContext* ctx);
// 符号扩展。
void op_sign_extend(VMContext* ctx);
// 零扩展。
void op_zero_extend(VMContext* ctx);
// 位宽截断。
void op_truncate(VMContext* ctx);
// 浮点扩展（如 float -> double）。
void op_float_extend(VMContext* ctx);
// 浮点截断（如 double -> float）。
void op_float_truncate(VMContext* ctx);
// 整数转浮点。
void op_int_to_float(VMContext* ctx);
// 数组元素地址/值操作。
void op_array_elem(VMContext* ctx);
// 浮点转整数。
void op_float_to_int(VMContext* ctx);
// 从地址读取指定类型值。
void op_read(VMContext* ctx);
// 向地址写入指定类型值。
void op_write(VMContext* ctx);
// 地址计算（有效地址 LEA）。
void op_lea(VMContext* ctx);
// 原子读取（按 type 宽度 + 内存序）。
void op_atomic_load(VMContext* ctx);
// 原子写入（按 type 宽度 + 内存序）。
void op_atomic_store(VMContext* ctx);
// 原子加操作。
void op_atomic_add(VMContext* ctx);
// 原子减操作。
void op_atomic_sub(VMContext* ctx);
// 原子交换操作。
void op_atomic_xchg(VMContext* ctx);
// 原子比较交换操作。
void op_atomic_cas(VMContext* ctx);
// 内存栅栏。
void op_fence(VMContext* ctx);
// 不可达指令处理（通常终止执行）。
void op_unreachable(VMContext* ctx);
// 分配虚拟栈空间（VSP）。
void op_alloc_vsp(VMContext* ctx);
// 二元立即数运算。
void op_binary_imm(VMContext* ctx);

// 未知 opcode 处理
// 处理未识别 opcode，通常记录错误并停止执行。
void op_unknown(VMContext* ctx);

// ============================================================================
// Opcode 跳转表
// ============================================================================
extern OpcodeHandler g_opcode_table[OP_MAX];

// 初始化跳转表
// 将 g_opcode_table 填充为各 opcode 对应处理函数。
void initOpcodeTable();

// ============================================================================
// 辅助函数
// ============================================================================

// 执行二元运算
// 按 op 与 type 语义执行二元算术/位运算。
uint64_t execBinaryOp(uint32_t op, uint64_t lhs, uint64_t rhs, zType* type);

// 执行一元运算
// 按 op 与 type 语义执行一元运算。
uint64_t execUnaryOp(uint32_t op, uint64_t src, zType* type);

// 执行比较运算
// 按比较操作码计算比较结果（通常返回 0/1）。
uint64_t execCompareOp(uint32_t op, uint64_t lhs, uint64_t rhs, zType* type);

// 执行类型转换
// 在源类型与目标类型之间执行转换并返回转换后值。
uint64_t execTypeConvert(uint32_t op, uint64_t src, zType* srcType, zType* dstType);

// 调试：opcode 名称（VMP_DEBUG=1 时解释器会打日志）
// 将 opcode 编号映射为可读名称，用于日志输出。
const char* getOpcodeName(uint32_t opcode);

// 复制值
// 按类型信息复制一个槽位到另一个槽位。
void copyValue(VMRegSlot* src, zType* type, VMRegSlot* dst);

// 从内存读取值
// 从 addrSlot 指向地址读取 type 对应大小并写入 dst。
void readValue(VMRegSlot* addrSlot, zType* type, VMRegSlot* dst);

// 向内存写入值
// 将 valueSlot 的值按 type 宽度写到 addrSlot 指向地址。
void writeValue(VMRegSlot* addrSlot, zType* type, VMRegSlot* valueSlot);

// 模块基址设置（供 ADRP 语义使用）。
void setVmModuleBase(uint64_t base);

} // namespace vm


#endif // Z_VM_OPCODES_H
