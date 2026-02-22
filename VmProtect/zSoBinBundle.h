/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - expand so 打包器接口声明。
 * - 加固链路位置：离线封装接口层。
 * - 输入：payload 与元数据。
 * - 输出：可被 VmEngine 解析的 bundle。
 */
#ifndef VMPROTECT_ZSOBINBUNDLE_H
#define VMPROTECT_ZSOBINBUNDLE_H

#include <cstdint>  // uint64_t / uint8_t。
#include <vector>   // std::vector。

// 单个函数的编码 bin 载荷：以 fun_addr 作为唯一标识。
struct zSoBinPayload {
    // 函数地址（主键）。
    // 约束：同一次写入中必须唯一，且不能为 0。
    uint64_t fun_addr = 0;
    // 函数编码字节流（由 zFunctionData::serializeEncoded 产出）。
    // 约束：不能为空。
    std::vector<uint8_t> encoded_bytes;
};

// 把多个编码 bin 追加到 so 文件尾部，生成可被 Engine 直接解析的新 so。
class zSoBinBundleWriter {
public:
    // 写入 expanded so：
    // 1) 复制原始 so；
    // 2) 追加 bundle header/entry/branch 表/payload/footer；
    // 3) 输出 output_so_path。
    // 返回值：
    // true  = 写入成功；
    // false = 参数非法、读取失败、校验失败或写盘失败。
    static bool writeExpandedSo(
        const char* input_so_path,
        const char* output_so_path,
        const std::vector<zSoBinPayload>& payloads,
        const std::vector<uint64_t>& shared_branch_addrs
    );
};

#endif // VMPROTECT_ZSOBINBUNDLE_H
