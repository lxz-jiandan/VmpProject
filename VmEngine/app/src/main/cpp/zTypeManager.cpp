/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - VM 运行时类型系统实现：基础类型、组合类型、布局计算与生命周期管理。
 * - 加固链路位置：VmEngine 类型支撑层。
 * - 输入：类型标签/参数。
 * - 输出：可直接被解释器与对象布局逻辑使用的 zType 体系对象。
 */
#include "zTypeManager.h"

// size_t / nullptr 相关基础支持（当前文件直接依赖较少，保持原 include）。
#include <cstdlib>

// ============================================================================
// zTypeManager 实现
// ============================================================================

// 构造函数：当前无额外初始化逻辑。
zTypeManager::zTypeManager() {
}

// 析构函数：统一释放托管列表中的所有类型对象。
zTypeManager::~zTypeManager() {
    // allocatedTypes_ 中每个对象可能是派生类型，需走多态析构。
    for (auto* type : allocatedTypes_) {
        freeType(type);
    }
    // 清空托管列表，防止悬挂指针残留。
    allocatedTypes_.clear();
}

// 分配基础类型对象并纳入托管。
zType* zTypeManager::allocType() {
    // 构造基础类型对象。
    zType* type = new zType();
    // 交给管理器统一释放。
    allocatedTypes_.push_back(type);
    return type;
}

// 分配函数/结构体类型对象并纳入托管。
FunctionStructType* zTypeManager::allocFunctionStructType() {
    // 构造派生对象。
    FunctionStructType* type = new FunctionStructType();
    // 标记 kind 为结构体/函数类型。
    type->kind = TYPE_KIND_STRUCT;
    // 以基类指针形式放入托管列表。
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 分配指针类型对象并纳入托管。
PointerType* zTypeManager::allocPointerType() {
    // 构造派生对象。
    PointerType* type = new PointerType();
    // 标记 kind 为指针类型描述。
    type->kind = TYPE_KIND_PTR_TYPE;
    // 64 位进程下指针大小固定 8。
    type->size = 8;
    // 放入统一托管容器。
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 分配数组类型对象并纳入托管。
ArrayType* zTypeManager::allocArrayType() {
    // 构造派生对象。
    ArrayType* type = new ArrayType();
    // 放入托管容器。
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 分配调用签名类型对象并纳入托管。
CallType* zTypeManager::allocCallType() {
    // 构造派生对象。
    CallType* type = new CallType();
    // 标记 kind 为调用类型。
    type->kind = TYPE_KIND_CALL_TYPE;
    // 放入托管容器。
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 创建 8 位整数类型。
zType* zTypeManager::createInt8(bool isSigned) {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind（有符号/无符号）。
    type->kind = isSigned ? TYPE_KIND_INT8_SIGNED : TYPE_KIND_INT8_UNSIGNED;
    // 字节大小 = 1。
    type->size = 1;
    // 位宽 = 8。
    type->bit_width = 8;
    // 对齐 = 1。
    type->alignment = 1;
    // 有符号属性。
    type->is_signed = isSigned;
    // 整数类型非浮点。
    type->is_float = false;
    return type;
}

// 创建 16 位整数类型。
zType* zTypeManager::createInt16(bool isSigned) {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind。
    type->kind = isSigned ? TYPE_KIND_INT16_SIGNED : TYPE_KIND_INT16_UNSIGNED;
    // 字节大小 = 2。
    type->size = 2;
    // 位宽 = 16。
    type->bit_width = 16;
    // 对齐 = 2。
    type->alignment = 2;
    // 有符号属性。
    type->is_signed = isSigned;
    // 非浮点。
    type->is_float = false;
    return type;
}

// 创建 32 位整数类型。
zType* zTypeManager::createInt32(bool isSigned) {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind。
    type->kind = isSigned ? TYPE_KIND_INT32_SIGNED : TYPE_KIND_INT32_UNSIGNED;
    // 字节大小 = 4。
    type->size = 4;
    // 位宽 = 32。
    type->bit_width = 32;
    // 对齐 = 4。
    type->alignment = 4;
    // 有符号属性。
    type->is_signed = isSigned;
    // 非浮点。
    type->is_float = false;
    return type;
}

// 创建 64 位整数类型。
zType* zTypeManager::createInt64(bool isSigned) {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind。
    type->kind = isSigned ? TYPE_KIND_INT64_SIGNED : TYPE_KIND_INT64_UNSIGNED;
    // 字节大小 = 8。
    type->size = 8;
    // 位宽 = 64。
    type->bit_width = 64;
    // 对齐 = 8。
    type->alignment = 8;
    // 有符号属性。
    type->is_signed = isSigned;
    // 非浮点。
    type->is_float = false;
    return type;
}

// 创建 32 位浮点类型。
zType* zTypeManager::createFloat32() {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind 为 float32。
    type->kind = TYPE_KIND_FLOAT32;
    // 字节大小 = 4。
    type->size = 4;
    // 位宽 = 32。
    type->bit_width = 32;
    // 对齐 = 4。
    type->alignment = 4;
    // 浮点统一视作 signed 语义位域（沿用原实现）。
    type->is_signed = true;
    // 标记为浮点。
    type->is_float = true;
    return type;
}

// 创建 64 位浮点类型。
zType* zTypeManager::createFloat64() {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind 为 float64。
    type->kind = TYPE_KIND_FLOAT64;
    // 字节大小 = 8。
    type->size = 8;
    // 位宽 = 64。
    type->bit_width = 64;
    // 对齐 = 8。
    type->alignment = 8;
    // 浮点沿用 signed=true。
    type->is_signed = true;
    // 标记为浮点。
    type->is_float = true;
    return type;
}

// 创建通用指针基础类型。
zType* zTypeManager::createPointer() {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind 为通用指针。
    type->kind = TYPE_KIND_POINTER;
    // 字节大小 = 8。
    type->size = 8;
    // 位宽 = 64。
    type->bit_width = 64;
    // 对齐 = 8。
    type->alignment = 8;
    // 指针按无符号处理。
    type->is_signed = false;
    // 非浮点。
    type->is_float = false;
    return type;
}

// 创建可变位宽整数类型。
zType* zTypeManager::createIntegerWidth(uint32_t bitWidth) {
    // 分配基础类型对象。
    zType* type = allocType();
    // 设置 kind 为带位宽整数。
    type->kind = TYPE_KIND_INTEGER_WIDTH;
    // 记录位宽。
    type->bit_width = bitWidth;
    // 计算所需字节数：向上取整到 byte。
    type->size = (bitWidth + 7) / 8;
    // 对齐默认等于字节大小（沿用原实现）。
    type->alignment = type->size;
    // 默认按有符号整数处理。
    type->is_signed = true;
    // 非浮点。
    type->is_float = false;
    return type;
}

// 创建函数/结构体类型并分配参数数组。
FunctionStructType* zTypeManager::createFunctionStruct(bool hasReturn, uint32_t paramCount) {
    // 分配结构体类型对象。
    FunctionStructType* type = allocFunctionStructType();
    // 记录是否有返回值。
    type->has_return = hasReturn ? 1 : 0;
    // 记录参数数量。
    type->param_count = paramCount;
    // 有参数时分配类型数组与偏移数组。
    if (paramCount > 0) {
        // 参数类型数组，值初始化为 nullptr。
        type->param_list = new zType*[paramCount]();
        // 参数偏移数组，值初始化为 0。
        type->param_offsets = new uint32_t[paramCount]();
    }
    return type;
}

// 创建“指向某类型”的指针类型描述对象。
PointerType* zTypeManager::createPointerType(zType* pointeeType) {
    // 分配指针类型对象。
    PointerType* type = allocPointerType();
    // 记录所指向类型。
    type->pointee_type = pointeeType;
    return type;
}

// 创建数组类型对象。
ArrayType* zTypeManager::createArrayType(uint32_t elementCount, zType* elementType, uint32_t kind) {
    // 分配数组类型对象。
    ArrayType* type = allocArrayType();
    // 记录数组 kind（可区分数组维度/元素语义）。
    type->kind = kind;
    // 记录元素数量。
    type->element_count = elementCount;
    // 记录元素类型。
    type->element_type = elementType;
    // 元素类型有效时预计算总大小。
    if (elementType) {
        type->size = elementCount * getTypeSize(elementType);
    }
    return type;
}

// 创建调用签名类型对象。
CallType* zTypeManager::createCallType(bool hasReturn, zType* returnType, uint32_t paramCount) {
    // 分配调用类型对象。
    CallType* type = allocCallType();
    // 记录是否有返回值。
    type->has_return = hasReturn ? 1 : 0;
    // 记录返回类型。
    type->return_type = returnType;
    // 记录参数数量。
    type->param_count = paramCount;
    // 有参数时分配参数类型数组。
    if (paramCount > 0) {
        // 参数类型数组，默认置空。
        type->param_list = new zType*[paramCount]();
    }
    return type;
}

// 根据外部类型编码创建内部 zType 对象。
zType* zTypeManager::createFromCode(uint32_t code) {
    // 基础编码映射表（保持与原逻辑一致）。
    switch (code) {
        case TYPE_TAG_INT8_SIGNED:
            return createInt8(true);
        case TYPE_TAG_INT16_SIGNED:
            return createInt16(true);
        case TYPE_TAG_INT64_UNSIGNED:
            return createInt64(false);
        case TYPE_TAG_INT32_SIGNED_2:
            return createInt32(true);
        case TYPE_TAG_POINTER:
            return createPointer();
        case TYPE_TAG_INT16_UNSIGNED:
            return createInt16(false);
        case TYPE_TAG_INT32_UNSIGNED:
            return createInt32(false);
        case TYPE_TAG_INT64_SIGNED:
            return createInt64(true);
        case TYPE_TAG_FLOAT32:
            return createFloat32();
        case TYPE_TAG_FLOAT64:
            return createFloat64();
        case TYPE_TAG_INT8_UNSIGNED:
            return createInt8(false);
        default:
            // 未知编码回退到 uint64（沿用原实现行为）。
            return createInt64(false);
    }
}

// 释放单个类型对象。
void zTypeManager::freeType(zType* type) {
    // 空指针直接返回。
    if (!type) return;

    // 通过虚析构自动释放派生对象附带资源。
    delete type;
}

// 释放类型数组容器（不重复释放对象本体）。
void zTypeManager::freeTypeList(zType** types, uint32_t count) {
    // count 在当前实现中无需使用，保留签名兼容上层调用。
    (void)count;
    // 仅释放数组内存本体。
    if (types) {
        delete[] types;
    }
}

// 查询类型大小。
uint32_t zTypeManager::getTypeSize(zType* type) {
    // 空类型默认返回 8（与原行为一致）。
    if (!type) return 8;
    // 走多态接口。
    return type->getSize();
}

// 查询类型对齐。
uint32_t zTypeManager::getTypeAlignment(zType* type) {
    // 空类型默认返回 8（与原行为一致）。
    if (!type) return 8;
    // 走多态接口。
    return type->getAlignment();
}

// 计算结构体成员偏移、最终大小和整体对齐。
void zTypeManager::calcStructAlignment(zType* type) {
    // 非法或非结构体类型直接返回。
    if (!type || type->kind != TYPE_KIND_STRUCT) return;

    // 转为结构体类型对象。
    FunctionStructType* fst = reinterpret_cast<FunctionStructType*>(type);
    // 非完整类型或无成员时无需计算。
    if (!fst->is_complete || fst->param_count == 0) return;

    // 当前偏移游标。
    uint32_t offset = 0;
    // 结构体最大对齐（至少为 1）。
    uint32_t maxAlign = 1;

    // 遍历全部成员。
    for (uint32_t i = 0; i < fst->param_count; i++) {
        // 当前成员类型。
        zType* memberType = fst->param_list[i];
        // 空成员跳过。
        if (!memberType) continue;

        // 成员大小。
        uint32_t memberSize = getTypeSize(memberType);
        // 成员对齐。
        uint32_t memberAlign = getTypeAlignment(memberType);

        // 把当前 offset 向上对齐到 memberAlign。
        offset = (offset + memberAlign - 1) & ~(memberAlign - 1);
        // 记录成员起始偏移。
        fst->param_offsets[i] = offset;
        // 推进偏移到成员末尾。
        offset += memberSize;

        // 更新结构体最大对齐。
        if (memberAlign > maxAlign) {
            maxAlign = memberAlign;
        }
    }

    // 结构体总大小向上对齐到最大对齐值。
    fst->size = (offset + maxAlign - 1) & ~(maxAlign - 1);
    // 记录最终对齐值。
    fst->alignment = maxAlign;
}
