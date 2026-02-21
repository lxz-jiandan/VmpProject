#ifndef Z_TYPE_SYSTEM_H
#define Z_TYPE_SYSTEM_H

#include <cstdint> // 固定宽度整数类型。
#include <vector>  // 类型对象托管容器。


// ============================================================================
// 类型种类枚举 (对应 IDA 中的 type_kind)
// ============================================================================
enum TypeKind : uint32_t {
    TYPE_KIND_INT16_SIGNED   = 0,   // int16_t
    TYPE_KIND_INT8_SIGNED    = 1,   // int8_t
    TYPE_KIND_INT16_UNSIGNED = 2,   // uint16_t
    TYPE_KIND_INT8_UNSIGNED  = 3,   // uint8_t (实际用于 1 字节)
    TYPE_KIND_INT32_SIGNED   = 4,   // int32_t
    TYPE_KIND_INT32_UNSIGNED = 5,   // uint32_t
    TYPE_KIND_INT64_UNSIGNED = 6,   // uint64_t
    TYPE_KIND_INT64_SIGNED   = 7,   // int64_t
    TYPE_KIND_FLOAT64        = 8,   // double
    TYPE_KIND_FLOAT32        = 9,   // float
    TYPE_KIND_POINTER        = 10,  // 指针
    TYPE_KIND_INTEGER_WIDTH  = 11,  // 带位宽的整数
    TYPE_KIND_CALL_TYPE      = 12,  // 函数调用类型
    TYPE_KIND_STRUCT         = 13,  // 结构体/函数类型
    TYPE_KIND_ARRAY_ELEM     = 14,  // 数组元素类型
    TYPE_KIND_PTR_TYPE       = 15,  // 指针类型
    TYPE_KIND_ARRAY_DIM      = 16,  // 数组维度类型
};

// ============================================================================
// 类型编码枚举 (字节码中的类型标签)
// ============================================================================
enum TypeTag : uint32_t {
    TYPE_TAG_INT8_SIGNED     = 0,   // kind = 1
    TYPE_TAG_INT16_SIGNED    = 1,   // kind = 0
    TYPE_TAG_INT64_UNSIGNED  = 2,   // kind = 7
    TYPE_TAG_INT32_SIGNED_2  = 4,   // kind = 4
    TYPE_TAG_FUNC_STRUCT     = 5,   // kind = 13 (函数/结构体)
    TYPE_TAG_INTEGER_WIDTH   = 6,   // kind = 11
    TYPE_TAG_PTR_TYPE        = 7,   // kind = 15
    TYPE_TAG_ARRAY_DIM       = 8,   // kind = 16
    TYPE_TAG_ARRAY_ELEM      = 9,   // kind = 14
    TYPE_TAG_POINTER         = 0xA, // kind = 10
    TYPE_TAG_INT16_UNSIGNED  = 0xB, // kind = 2
    TYPE_TAG_FUNC_STRUCT_2   = 0xC, // kind = 13
    TYPE_TAG_INT32_UNSIGNED  = 0xD, // kind = 5
    TYPE_TAG_INT64_SIGNED    = 0xE, // kind = 6
    TYPE_TAG_FLOAT32         = 0xF, // kind = 9
    TYPE_TAG_FLOAT64         = 0x11,// kind = 8
    TYPE_TAG_FUNC_STRUCT_3   = 0x13,// kind = 13
    TYPE_TAG_CALL_TYPE       = 0x14,// kind = 12
    TYPE_TAG_INT8_UNSIGNED   = 0x15,// kind = 3
};


// ============================================================================
// 基础类型对象
// ============================================================================
class zType {
public:
    // 虚析构保证派生类型通过基类指针删除时资源正确释放。
    virtual ~zType() = default;

    uint32_t kind = 0;            // 类型种类
    uint32_t size = 0;            // 类型大小（字节）
    uint32_t bit_width = 0;       // 对于整数类型，位宽
    uint32_t alignment = 0;       // 对齐要求
    bool     is_signed = false;   // 是否有符号
    bool     is_float = false;    // 是否浮点
    uint8_t  padding[2] = {0, 0}; // 对齐填充

    // 获取类型大小（默认返回 size 字段）。
    virtual uint32_t getSize() const { return size; }

    // 获取类型种类（默认返回 kind 字段）。
    virtual uint32_t getKind() const { return kind; }

    // 获取类型对齐（alignment=0 时回退到 size）。
    virtual uint32_t getAlignment() const { return alignment > 0 ? alignment : getSize(); }
};

// ============================================================================
// 函数/结构体类型（kind = 13）
// ============================================================================
class FunctionStructType : public zType {
public:
    uint8_t  has_return;      // 偏移 12: 是否有返回值
    uint8_t  is_vararg;       // 偏移 13: 是否变参
    uint8_t  is_complete;     // 偏移 14: 是否完整
    uint8_t  _pad;
    uint32_t param_count;     // 偏移 16: 参数数量
    zType** param_list;       // 偏移 24: 参数类型列表
    uint32_t* param_offsets;  // 偏移 32/40: 参数偏移列表
    char* name;               // 偏移 40/48: 名称

    ~FunctionStructType() override {
        // 参数类型数组由本对象拥有。
        delete[] param_list;
        // 参数偏移数组由本对象拥有。
        delete[] param_offsets;
        // 名称字符串由本对象拥有。
        delete[] name;
    }

    uint32_t getKind() const override { return TYPE_KIND_STRUCT; }
    uint32_t getSize() const override { return size; }
};

// ============================================================================
// 指针类型（kind = 15）
// ============================================================================
class PointerType : public zType {
public:
    zType* pointee_type; // 偏移 16: 指向的类型

    uint32_t getKind() const override { return TYPE_KIND_PTR_TYPE; }
    uint32_t getSize() const override { return 8; }
    uint32_t getAlignment() const override { return 8; }
};

// ============================================================================
// 数组类型（kind = 14/16）
// ============================================================================
class ArrayType : public zType {
public:
    uint32_t element_count;   // 偏移 12: 元素数量
    zType* element_type; // 偏移 16: 元素类型

    uint32_t getKind() const override { return kind; }
    // 数组大小 = 元素数 * 元素大小（元素为空时为 0）。
    uint32_t getSize() const override { return element_type ? element_count * element_type->getSize() : 0; }
    // 数组对齐沿用元素对齐（元素为空时回退 1）。
    uint32_t getAlignment() const override { return element_type ? element_type->getAlignment() : 1; }
};

// ============================================================================
// 函数调用类型（kind = 12）
// ============================================================================
class CallType : public zType {
public:
    uint8_t  has_return;      // 偏移 12: 是否有返回值
    uint8_t  _pad[3];
    zType* return_type;  // 偏移 16: 返回类型
    uint32_t param_count;     // 偏移 24: 参数数量
    zType** param_list;  // 偏移 32: 参数类型列表

    ~CallType() override {
        // 参数类型数组由本对象拥有。
        delete[] param_list;
    }

    uint32_t getKind() const override { return TYPE_KIND_CALL_TYPE; }
    uint32_t getSize() const override { return 8; }
    uint32_t getAlignment() const override { return 8; }
};

// ============================================================================
// 带位宽的整数类型（kind = 11）
// ============================================================================
class IntegerWidthType : public zType {
public:
    // bit_width 字段已在基类中定义
    uint32_t getKind() const override { return TYPE_KIND_INTEGER_WIDTH; }
};

// ============================================================================
// 类型管理器
// ============================================================================
class zTypeManager {
public:
    // 构造类型系统实例。
    zTypeManager();

    // 析构类型系统并释放内部托管的类型对象。
    ~zTypeManager();

    // 创建预定义类型（基础标量类型）。
    // 创建 8 位整数类型（有符号/无符号）。
    zType* createInt8(bool isSigned = true);
    // 创建 16 位整数类型（有符号/无符号）。
    zType* createInt16(bool isSigned = true);
    // 创建 32 位整数类型（有符号/无符号）。
    zType* createInt32(bool isSigned = true);
    // 创建 64 位整数类型（有符号/无符号）。
    zType* createInt64(bool isSigned = true);
    // 创建 32 位浮点类型。
    zType* createFloat32();
    // 创建 64 位浮点类型。
    zType* createFloat64();
    // 创建通用指针基础类型。
    zType* createPointer();
    
    // 创建复杂类型（组合类型）。
    // 创建带自定义位宽的整数类型。
    zType* createIntegerWidth(uint32_t bitWidth);
    // 创建函数/结构体描述类型并预分配参数槽。
    FunctionStructType* createFunctionStruct(bool hasReturn, uint32_t paramCount);
    // 创建指向给定类型的指针类型对象。
    PointerType* createPointerType(zType* pointeeType);
    // 创建数组类型对象（元素个数 + 元素类型 + kind）。
    ArrayType* createArrayType(uint32_t elementCount, zType* elementType, uint32_t kind);
    // 创建调用签名类型（返回值与参数列表）。
    CallType* createCallType(bool hasReturn, zType* returnType, uint32_t paramCount);

    // 从类型编码创建类型（供字节码解码路径使用）。
    // 根据外部编码值快速创建对应基础类型。
    zType* createFromCode(uint32_t code);

    // 释放类型（释放对象或数组容器）。
    // 释放单个类型对象及其内部附属内存。
    void freeType(zType* type);
    // 释放类型数组容器（不重复释放由类型系统托管的对象）。
    void freeTypeList(zType** types, uint32_t count);

    // 获取类型大小。
    // 获取类型的字节大小（null 时给出默认宽度）。
    static uint32_t getTypeSize(zType* type);

    // 获取类型对齐。
    // 获取类型对齐值（优先使用类型自身多态实现，缺省回退到大小）。
    static uint32_t getTypeAlignment(zType* type);
    
    // 计算结构体对齐（对应 vm_calc_alignment_1）
    // 计算结构体成员偏移、最终大小与最大对齐。
    static void calcStructAlignment(zType* type);

private:
    // 分配基础类型对象并纳入托管列表。
    zType* allocType();
    // 分配函数/结构体类型对象并纳入托管列表。
    FunctionStructType* allocFunctionStructType();
    // 分配指针类型对象并纳入托管列表。
    PointerType* allocPointerType();
    // 分配数组类型对象并纳入托管列表。
    ArrayType* allocArrayType();
    // 分配调用类型对象并纳入托管列表。
    CallType* allocCallType();
    
    // 托管所有已分配类型对象，析构时统一释放。
    std::vector<zType*> allocatedTypes_;
};


#endif // Z_TYPE_SYSTEM_H


