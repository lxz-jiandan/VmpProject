#ifndef VMPROTECT_ZSOBINBUNDLE_H
#define VMPROTECT_ZSOBINBUNDLE_H

#include <cstdint>
#include <vector>

// 单个函数的编码 bin 载荷：以 fun_addr 作为唯一标识。
struct zSoBinPayload {
    uint64_t fun_addr = 0;
    std::vector<uint8_t> encoded_bytes;
};

// 把多个编码 bin 追加到 so 文件尾部，生成可被 Engine 直接解析的新 so。
class zSoBinBundleWriter {
public:
    static bool writeExpandedSo(
        const char* input_so_path,
        const char* output_so_path,
        const std::vector<zSoBinPayload>& payloads,
        const std::vector<uint64_t>& shared_branch_addrs
    );
};

#endif // VMPROTECT_ZSOBINBUNDLE_H
