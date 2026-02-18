#include "zTypeManager.h"
#include <cstdlib>
#include <cstring>

// ============================================================================
// zTypeManager 实现
// ============================================================================

// 构造类型系统。
zTypeManager::zTypeManager() {
}

// 析构类型系统并释放所有托管类型对象。
zTypeManager::~zTypeManager() {
    for (auto* type : allocatedTypes_) {
        freeType(type);
    }
    allocatedTypes_.clear();
}

// 分配并初始化基础类型对象。
zType* zTypeManager::allocType() {
    zType* type = new zType();
    allocatedTypes_.push_back(type);
    return type;
}

// 分配并初始化函数/结构体类型对象。
FunctionStructType* zTypeManager::allocFunctionStructType() {
    FunctionStructType* type = new FunctionStructType();
    type->kind = TYPE_KIND_STRUCT;
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 分配并初始化指针类型对象。
PointerType* zTypeManager::allocPointerType() {
    PointerType* type = new PointerType();
    type->kind = TYPE_KIND_PTR_TYPE;
    type->size = 8;
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 分配并初始化数组类型对象。
ArrayType* zTypeManager::allocArrayType() {
    ArrayType* type = new ArrayType();
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 分配并初始化调用签名类型对象。
CallType* zTypeManager::allocCallType() {
    CallType* type = new CallType();
    type->kind = TYPE_KIND_CALL_TYPE;
    allocatedTypes_.push_back(reinterpret_cast<zType*>(type));
    return type;
}

// 创建 8 位整数类型。
zType* zTypeManager::createInt8(bool isSigned) {
    zType* type = allocType();
    type->kind = isSigned ? TYPE_KIND_INT8_SIGNED : TYPE_KIND_INT8_UNSIGNED;
    type->size = 1;
    type->bit_width = 8;
    type->alignment = 1;
    type->is_signed = isSigned;
    type->is_float = false;
    return type;
}

// 创建 16 位整数类型。
zType* zTypeManager::createInt16(bool isSigned) {
    zType* type = allocType();
    type->kind = isSigned ? TYPE_KIND_INT16_SIGNED : TYPE_KIND_INT16_UNSIGNED;
    type->size = 2;
    type->bit_width = 16;
    type->alignment = 2;
    type->is_signed = isSigned;
    type->is_float = false;
    return type;
}

// 创建 32 位整数类型。
zType* zTypeManager::createInt32(bool isSigned) {
    zType* type = allocType();
    type->kind = isSigned ? TYPE_KIND_INT32_SIGNED : TYPE_KIND_INT32_UNSIGNED;
    type->size = 4;
    type->bit_width = 32;
    type->alignment = 4;
    type->is_signed = isSigned;
    type->is_float = false;
    return type;
}

// 创建 64 位整数类型。
zType* zTypeManager::createInt64(bool isSigned) {
    zType* type = allocType();
    type->kind = isSigned ? TYPE_KIND_INT64_SIGNED : TYPE_KIND_INT64_UNSIGNED;
    type->size = 8;
    type->bit_width = 64;
    type->alignment = 8;
    type->is_signed = isSigned;
    type->is_float = false;
    return type;
}

// 创建 32 位浮点类型。
zType* zTypeManager::createFloat32() {
    zType* type = allocType();
    type->kind = TYPE_KIND_FLOAT32;
    type->size = 4;
    type->bit_width = 32;
    type->alignment = 4;
    type->is_signed = true;
    type->is_float = true;
    return type;
}

// 创建 64 位浮点类型。
zType* zTypeManager::createFloat64() {
    zType* type = allocType();
    type->kind = TYPE_KIND_FLOAT64;
    type->size = 8;
    type->bit_width = 64;
    type->alignment = 8;
    type->is_signed = true;
    type->is_float = true;
    return type;
}

// 创建通用指针基础类型。
zType* zTypeManager::createPointer() {
    zType* type = allocType();
    type->kind = TYPE_KIND_POINTER;
    type->size = 8;
    type->bit_width = 64;
    type->alignment = 8;
    type->is_signed = false;
    type->is_float = false;
    return type;
}

// 创建可变位宽整数类型。
zType* zTypeManager::createIntegerWidth(uint32_t bitWidth) {
    zType* type = allocType();
    type->kind = TYPE_KIND_INTEGER_WIDTH;
    type->bit_width = bitWidth;
    type->size = (bitWidth + 7) / 8;
    type->alignment = type->size;
    type->is_signed = true;
    type->is_float = false;
    return type;
}

// 创建函数/结构体描述类型并分配参数数组。
FunctionStructType* zTypeManager::createFunctionStruct(bool hasReturn, uint32_t paramCount) {
    FunctionStructType* type = allocFunctionStructType();
    type->has_return = hasReturn ? 1 : 0;
    type->param_count = paramCount;
    if (paramCount > 0) {
        type->param_list = new zType*[paramCount]();
        type->param_offsets = new uint32_t[paramCount]();
    }
    return type;
}

// 创建指向指定类型的指针类型。
PointerType* zTypeManager::createPointerType(zType* pointeeType) {
    PointerType* type = allocPointerType();
    type->pointee_type = pointeeType;
    return type;
}

// 创建数组类型并记录元素数量与元素类型。
ArrayType* zTypeManager::createArrayType(uint32_t elementCount, zType* elementType, uint32_t kind) {
    ArrayType* type = allocArrayType();
    type->kind = kind;
    type->element_count = elementCount;
    type->element_type = elementType;
    if (elementType) {
        type->size = elementCount * getTypeSize(elementType);
    }
    return type;
}

// 创建调用签名类型并分配参数类型数组。
CallType* zTypeManager::createCallType(bool hasReturn, zType* returnType, uint32_t paramCount) {
    CallType* type = allocCallType();
    type->has_return = hasReturn ? 1 : 0;
    type->return_type = returnType;
    type->param_count = paramCount;
    if (paramCount > 0) {
        type->param_list = new zType*[paramCount]();
    }
    return type;
}

// 将外部类型编码映射为内部 zType。
zType* zTypeManager::createFromCode(uint32_t code) {
    // 基础类型编码映射
    switch (code) {
        case TYPE_TAG_INT8_SIGNED:    // 0: kind = 1
            return createInt8(true);
        case TYPE_TAG_INT16_SIGNED:   // 1: kind = 0
            return createInt16(true);
        case TYPE_TAG_INT64_UNSIGNED: // 2: kind = 7
            return createInt64(false);
        case TYPE_TAG_INT32_SIGNED_2: // 4: kind = 4
            return createInt32(true);
        case TYPE_TAG_POINTER:        // 0xA: kind = 10
            return createPointer();
        case TYPE_TAG_INT16_UNSIGNED: // 0xB: kind = 2
            return createInt16(false);
        case TYPE_TAG_INT32_UNSIGNED: // 0xD: kind = 5
            return createInt32(false);
        case TYPE_TAG_INT64_SIGNED:   // 0xE: kind = 6
            return createInt64(true);
        case TYPE_TAG_FLOAT32:        // 0xF: kind = 9
            return createFloat32();
        case TYPE_TAG_FLOAT64:        // 0x11: kind = 8
            return createFloat64();
        case TYPE_TAG_INT8_UNSIGNED:  // 0x15: kind = 3
            return createInt8(false);
        default:
            return createInt64(false);  // 默认
    }
}

// 确保类型已初始化
// 确保指定下标类型已初始化（用于前向引用或延迟初始化场景）。
zType* zTypeManager::ensureTypeInitialized(zType** typeList, uint32_t index) {
    if (typeList[index]) {
        return typeList[index];
    }
    // 创建一个占位的结构体类型
    FunctionStructType* placeholder = allocFunctionStructType();
    placeholder->is_complete = 0;
    typeList[index] = reinterpret_cast<zType*>(placeholder);
    return typeList[index];
}

// 解码基础类型
// 解析基础类型标签并创建对应类型对象。
zType* zTypeManager::decodeBasicType(uint32_t typeTag) {
    return createFromCode(typeTag);
}

// 解码函数/结构体类型
// 解码函数/结构体类型：读取返回值、参数数量与参数类型下标。
zType* zTypeManager::decodeFunctionStructType(zByteCodeReader& reader, zType** typeList, uint32_t currentIdx) {
    uint32_t hasReturn = reader.read6bitExt();
    uint32_t paramCount = reader.read6bitExt();
    
    FunctionStructType* type = nullptr;
    if (typeList[currentIdx]) {
        type = reinterpret_cast<FunctionStructType*>(typeList[currentIdx]);
    } else {
        type = allocFunctionStructType();
    }
    
    type->is_complete = 1;
    type->has_return = (hasReturn == 1) ? 1 : 0;
    type->param_count = paramCount;
    
    if (paramCount > 0) {
        type->param_list = new zType*[paramCount]();
        type->param_offsets = new uint32_t[paramCount]();
        
        for (uint32_t i = 0; i < paramCount; i++) {
            uint32_t paramTypeIdx = reader.read6bitExt();
            zType* paramType = ensureTypeInitialized(typeList, paramTypeIdx);
            type->param_list[i] = paramType;
        }
    }
    
    // 读取名称长度和名称
    uint32_t nameLen = reader.read6bitExt();
    if (nameLen > 0) {
        type->name = new char[nameLen + 1]();
        for (uint32_t i = 0; i < nameLen; i++) {
            type->name[i] = static_cast<char>(reader.read6bitExt());
        }
        type->name[nameLen] = '\0';
    }
    
    return reinterpret_cast<zType*>(type);
}

// 解码带位宽的整数类型
// 解码带位宽整数类型。
zType* zTypeManager::decodeIntegerWidthType(zByteCodeReader& reader) {
    uint32_t bitWidth = reader.read6bitExt();
    return createIntegerWidth(bitWidth);
}

// 解码指针类型
// 解码指针类型并解析被指向类型。
zType* zTypeManager::decodePointerType(zByteCodeReader& reader, zType** typeList) {
    uint32_t pointeeIdx = reader.read6bitExt();
    zType* pointeeType = ensureTypeInitialized(typeList, pointeeIdx);
    return reinterpret_cast<zType*>(createPointerType(pointeeType));
}

// 解码数组类型
// 解码数组类型：读取元素数量与元素类型下标。
zType* zTypeManager::decodeArrayType(zByteCodeReader& reader, zType** typeList, uint32_t kindTag) {
    uint32_t elementCount = reader.read6bitExt();
    uint32_t elementTypeIdx = reader.read6bitExt();
    zType* elementType = ensureTypeInitialized(typeList, elementTypeIdx);
    
    uint32_t kind = (kindTag == TYPE_TAG_ARRAY_DIM) ? TYPE_KIND_ARRAY_DIM : TYPE_KIND_ARRAY_ELEM;
    return reinterpret_cast<zType*>(createArrayType(elementCount, elementType, kind));
}

// 解码函数调用类型
// 解码调用签名类型：读取返回类型与参数类型序列。
zType* zTypeManager::decodeCallType(zByteCodeReader& reader, zType** typeList) {
    uint32_t hasReturn = reader.read6bitExt();
    uint32_t returnTypeIdx = reader.read6bitExt();
    uint32_t paramCount = reader.read6bitExt();
    
    zType* returnType = ensureTypeInitialized(typeList, returnTypeIdx);
    CallType* type = createCallType(hasReturn == 1, returnType, paramCount);
    
    if (paramCount > 0) {
        for (uint32_t i = 0; i < paramCount; i++) {
            uint32_t paramTypeIdx = reader.read6bitExt();
            zType* paramType = ensureTypeInitialized(typeList, paramTypeIdx);
            type->param_list[i] = paramType;
        }
    }
    
    return reinterpret_cast<zType*>(type);
}

// 完整的类型表解码
// 解码完整类型表并在结尾执行结构体对齐计算。
zType** zTypeManager::decodeTypeList(zByteCodeReader& reader, uint32_t count) {
    if (count == 0) return nullptr;

    zType** types = new zType*[count]();
    memset(types, 0, sizeof(zType*) * count);
    
    for (uint32_t i = 0; i < count; i++) {
        uint32_t typeTag = reader.read6bitExt();
        zType* type = types[i]; // 可能已经被前向引用创建
        
        switch (typeTag) {
            case TYPE_TAG_INT8_SIGNED:    // 0: kind = 1
            case TYPE_TAG_INT16_SIGNED:   // 1: kind = 0
            case TYPE_TAG_INT64_UNSIGNED: // 2: kind = 7
            case TYPE_TAG_INT32_SIGNED_2: // 4: kind = 4
            case TYPE_TAG_POINTER:        // 0xA: kind = 10
            case TYPE_TAG_INT16_UNSIGNED: // 0xB: kind = 2
            case TYPE_TAG_INT32_UNSIGNED: // 0xD: kind = 5
            case TYPE_TAG_INT64_SIGNED:   // 0xE: kind = 6
            case TYPE_TAG_FLOAT32:        // 0xF: kind = 9
            case TYPE_TAG_FLOAT64:        // 0x11: kind = 8
            case TYPE_TAG_INT8_UNSIGNED:  // 0x15: kind = 3
                type = decodeBasicType(typeTag);
                break;
                
            case TYPE_TAG_FUNC_STRUCT:    // 5: kind = 13
            case TYPE_TAG_FUNC_STRUCT_2:  // 0xC: kind = 13
            case TYPE_TAG_FUNC_STRUCT_3:  // 0x13: kind = 13
                type = decodeFunctionStructType(reader, types, i);
                break;
                
            case TYPE_TAG_INTEGER_WIDTH:  // 6: kind = 11
                type = decodeIntegerWidthType(reader);
                break;
                
            case TYPE_TAG_PTR_TYPE:       // 7: kind = 15
                type = decodePointerType(reader, types);
                break;
                
            case TYPE_TAG_ARRAY_DIM:      // 8: kind = 16
            case TYPE_TAG_ARRAY_ELEM:     // 9: kind = 14
                type = decodeArrayType(reader, types, typeTag);
                break;
                
            case TYPE_TAG_CALL_TYPE:      // 0x14: kind = 12
                type = decodeCallType(reader, types);
                break;
                
            default:
                // 未知类型，创建默认类型
                type = createInt64(false);
                break;
        }
        
        types[i] = type;
    }
    
    // 计算所有结构体类型的对齐
    for (uint32_t i = 0; i < count; i++) {
        if (types[i] && types[i]->kind == TYPE_KIND_STRUCT) {
            calcStructAlignment(types[i]);
        }
    }
    
    return types;
}

// 释放单个类型对象及其内部动态资源。
void zTypeManager::freeType(zType* type) {
    if (!type) return;

    // 统一交由多态析构链处理资源释放。
    delete type;
}

// 释放类型数组容器（不重复销毁已由系统托管的对象本体）。
void zTypeManager::freeTypeList(zType** types, uint32_t count) {
    // 注意：类型对象由 allocatedTypes_ 管理，这里只释放数组
    if (types) {
        delete[] types;
    }
}

// 对外大小查询入口。
uint32_t zTypeManager::getTypeSize(zType* type) {
    if (!type) return 8;
    return type->getSize();
}

// 对外对齐查询入口。
uint32_t zTypeManager::getTypeAlignment(zType* type) {
    if (!type) return 8;
    return type->getAlignment();
}

// 计算结构体对齐（对应 vm_calc_alignment_1）
// 计算结构体成员偏移并推导最终结构体大小和对齐值。
void zTypeManager::calcStructAlignment(zType* type) {
    if (!type || type->kind != TYPE_KIND_STRUCT) return;
    
    FunctionStructType* fst = reinterpret_cast<FunctionStructType*>(type);
    if (!fst->is_complete || fst->param_count == 0) return;
    
    uint32_t offset = 0;
    uint32_t maxAlign = 1;
    
    for (uint32_t i = 0; i < fst->param_count; i++) {
        zType* memberType = fst->param_list[i];
        if (!memberType) continue;
        
        uint32_t memberSize = getTypeSize(memberType);
        uint32_t memberAlign = getTypeAlignment(memberType);
        
        // 对齐偏移
        offset = (offset + memberAlign - 1) & ~(memberAlign - 1);
        fst->param_offsets[i] = offset;
        offset += memberSize;
        
        if (memberAlign > maxAlign) {
            maxAlign = memberAlign;
        }
    }
    
    // 最终大小对齐到最大对齐
    fst->size = (offset + maxAlign - 1) & ~(maxAlign - 1);
    fst->alignment = maxAlign;
}




