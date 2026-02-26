/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - bundle 读取接口声明。
 * - 加固链路位置：运行时 payload 解析接口层。
 * - 输入：so 路径。
 * - 输出：zSoBinEntry 列表。
 */
#ifndef Z_SO_BIN_BUNDLE_H
#define Z_SO_BIN_BUNDLE_H

#include <cstdint>
#include <string>
#include <vector>

// 从扩展 so 尾部读取出的单条编码函数数据。
// 一个函数地址对应一份 encoded_data。
struct zSoBinEntry {
    // 被保护函数地址（作为唯一标识）。
    uint64_t fun_addr = 0;
    // 对应函数的编码字节流。
    std::vector<uint8_t> encoded_data;
};

// 读取 libdemo_expand.so 尾部容器，恢复多个函数编码 bin。
class zSoBinBundleReader {
public:
    // 读取并解析 so 尾部 bundle：
    // 1) out_entries 返回每个函数的编码载荷；
    // 2) out_shared_branch_addrs 返回共享 branch_addr_list。
    static bool readFromExpandedSo(
        const std::string& so_path,
        std::vector<zSoBinEntry>& out_entries,
        std::vector<uint64_t>& out_shared_branch_addrs
    );
    // 直接从内存字节读取并解析 bundle（避免先写临时文件）。
    static bool readFromExpandedSoBytes(
        const uint8_t* soBytes,
        size_t soSize,
        std::vector<zSoBinEntry>& out_entries,
        std::vector<uint64_t>& out_shared_branch_addrs
    );
};

#endif // Z_SO_BIN_BUNDLE_H
