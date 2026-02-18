#include <vector>
#include "zElf.h"
#include "zLog.h"
#include "zFunction.h"

static const uint32_t reg_id_list[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
static const uint32_t reg_id_count = sizeof(reg_id_list)/sizeof(uint32_t);
static const uint32_t type_id_count = 2;
static const uint32_t type_id_list[] = { 14, 4 };
static const uint32_t branch_id_count = 6;
uint32_t branch_id_list[] = { 55, 119, 71, 0, 101, 0 };
static const uint64_t branch_addr_count = 6;
uint64_t branch_addr_list[] = { 0x1dd28, 0x1dd64, 0x1dd38, 0x425b0, 0x1dd54, 0x425c0 };
static const uint32_t inst_id_count = 173;
uint32_t inst_id_list[] = {
        6, 0, 0, 0, 0,                                // OP_ALLOC_RETURN
        51, 0, 0, 0, 29, 31,                          // OP_ALLOC_VSP
        52, 1, 0, 31, 32, 31,                         // OP_BINARY_IMM       0x1dd08: sub sp, sp, #0x20
        13, 0, 31, 16, 29, 13, 0, 31, 24, 30,         // OP_SET_FIELD        0x1dd0c: stp x29, x30, [sp, #0x10]
        52, 4, 0, 31, 16, 29,                         // OP_BINARY_IMM       0x1dd10: add x29, sp, #0x10
        13, 1, 29, 4294967292, 0,                     // OP_SET_FIELD        0x1dd14: stur w0, [x29, #-4]
        13, 1, 31, 8, 1,                              // OP_SET_FIELD        0x1dd18: str w1, [sp, #8]
        13, 1, 31, 4, 4294967295,                     // OP_SET_FIELD        0x1dd1c: str wzr, [sp, #4]
        13, 1, 31, 0, 4294967295,                     // OP_SET_FIELD        0x1dd20: str wzr, [sp]
        17, 0,                                        // OP_BRANCH           0x1dd24: b 0x1dd28
        11, 1, 31, 0, 8,                              // OP_GET_FIELD        0x1dd28: ldr w8, [sp]
        52, 65, 0, 8, 5, 8,                           // OP_BINARY_IMM       0x1dd2c: subs w8, w8, #5
        53, 10, 1,                                    // OP_BRANCH_IF_CC     0x1dd30: b.ge 0x1dd64
        17, 2,                                        // OP_BRANCH           0x1dd34: b 0x1dd38
        11, 1, 29, 4294967292, 0,                     // OP_GET_FIELD        0x1dd38: ldur w0, [x29, #-4]
        11, 1, 31, 8, 1,                              // OP_GET_FIELD        0x1dd3c: ldr w1, [sp, #8]
        55, 3,                                        // OP_BL               0x1dd40: bl 0x425b0
        11, 1, 31, 4, 8,                              // OP_GET_FIELD        0x1dd44: ldr w8, [sp, #4]
        1, 4, 1, 8, 0, 8,                             // OP_BINARY           0x1dd48: add w8, w8, w0
        13, 1, 31, 4, 8,                              // OP_SET_FIELD        0x1dd4c: str w8, [sp, #4]
        17, 4,                                        // OP_BRANCH           0x1dd50: b 0x1dd54
        11, 1, 31, 0, 8,                              // OP_GET_FIELD        0x1dd54: ldr w8, [sp]
        52, 4, 0, 8, 1, 8,                            // OP_BINARY_IMM       0x1dd58: add w8, w8, #1
        13, 1, 31, 0, 8,                              // OP_SET_FIELD        0x1dd5c: str w8, [sp]
        17, 0,                                        // OP_BRANCH           0x1dd60: b 0x1dd28
        11, 1, 31, 4, 3,                              // OP_GET_FIELD        0x1dd64: ldr w3, [sp, #4]
        21, 0, 6,                                     // OP_LOAD_IMM         0x1dd68: mov w0, #6
        56, 0, 81920, 0,                              // OP_ADRP             0x1dd6c: adrp x1, 0x14000
        52, 4, 0, 0, 250, 0,                          // OP_BINARY_IMM       0x1dd70: add x1, x1, #0xfa
        56, 0, 81920, 0,                              // OP_ADRP             0x1dd74: adrp x2, 0x14000
        52, 4, 0, 0, 254, 0,                          // OP_BINARY_IMM       0x1dd78: add x2, x2, #0xfe
        55, 5,                                        // OP_BL               0x1dd7c: bl 0x425c0
        11, 1, 31, 4, 0,                              // OP_GET_FIELD        0x1dd80: ldr w0, [sp, #4]
        11, 0, 31, 16, 29, 11, 0, 31, 24, 30,         // OP_GET_FIELD        0x1dd84: ldp x29, x30, [sp, #0x10]
        52, 4, 0, 31, 32, 31,                         // OP_BINARY_IMM       0x1dd88: add sp, sp, #0x20
        16, 1, 0,                                     // OP_RETURN           0x1dd8c: ret
};


int main(int argc, char* argv[]) {
    const char* so_path = "D:\\work\\2026\\0202_my_vmp\\VmProtect\\libdemo.so";

    // 加载和解析 ELF 文件
    zElf elf(so_path);

    // 要查找的函数名（可以从命令行参数获取，或者硬编码）fun_add fun_for fun_for_add
    const char* function_name = argc > 1 ? argv[1] : "fun_for_add";  // 默认查找 "fun_for_add" 函数

    zFunction* function = elf.getfunction(function_name);
    if (!function) {
        LOGE("获取 zFunction 失败: %s", function_name);
        return 1;
    }

    LOGI("找到函数 %s 在偏移: 0x%llx", function->name().c_str(), (unsigned long long)function->offset());
    LOGI("函数大小: %zu 字节 (0x%zx)", function->size(), function->size());

    LOGI("\n========== 汇编信息 %s ==========\n", function_name);
    function->analyzeasm();
    std::string asm_info = function->getasminfo();
    LOGI("%s", asm_info.c_str());

    function->dump("fun_for_add.txt", zFunction::DumpMode::UNENCODED);
    function->dump("fun_for_add.bin", zFunction::DumpMode::UNENCODED_BIN);

    zFunction function_from_txt = zFunction::fromUnencodedTxt("function_unencoded.txt", function->name(), function->offset());
    zFunction function_from_bin = zFunction::fromUnencodedBin("function_unencoded.bin", function->name(), function->offset());

    LOGI("\n========== 反序列化验证 %s ==========" , function_name);
    LOGI("from txt: name=%s offset=0x%llx", function_from_txt.name().c_str(), (unsigned long long)function_from_txt.offset());
    LOGI("from bin: name=%s offset=0x%llx", function_from_bin.name().c_str(), (unsigned long long)function_from_bin.offset());

    function_from_txt.dump("function_unencoded_test.txt", zFunction::DumpMode::UNENCODED);
    function_from_bin.dump("function_unencoded_bin_test.txt", zFunction::DumpMode::UNENCODED);

    return 0;
}
