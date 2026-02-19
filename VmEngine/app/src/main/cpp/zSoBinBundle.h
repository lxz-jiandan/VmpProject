#ifndef Z_SO_BIN_BUNDLE_H
#define Z_SO_BIN_BUNDLE_H

#include <cstdint>
#include <string>
#include <vector>

// 从扩展 so 尾部读取出的单条编码函数数据。
struct zSoBinEntry {
    uint64_t fun_addr = 0;
    std::vector<uint8_t> encoded_data;
};

// 读取 libdemo_expand.so 尾部容器，恢复多个函数编码 bin。
class zSoBinBundleReader {
public:
    static bool readFromExpandedSo(
        const std::string& so_path,
        std::vector<zSoBinEntry>& out_entries,
        std::vector<uint64_t>& out_shared_branch_addrs
    );
};

#endif // Z_SO_BIN_BUNDLE_H
