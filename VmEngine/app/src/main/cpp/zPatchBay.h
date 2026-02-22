/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - PatchBay 数据结构与接口声明。
 * - 加固链路位置：补丁布局接口层。
 * - 输入：预留区元信息。
 * - 输出：补丁定位能力。
 */
#ifndef VMPROJECT_VMENGINE_ZPATCHBAY_H
#define VMPROJECT_VMENGINE_ZPATCHBAY_H

#include <cstdint>

// Route4 PatchBay 设计目标：
// 1) 在编译期预留一个“文件内可写区域”（.vmp_patchbay），避免后处理时重排整个 ELF。
// 2) 后处理工具只需把新的 dynsym/dynstr/hash/versym 写入该区域，再改写 DT_* 指针即可完成接管。
// 3) 运行时代码段/数据段尽量不变，降低补丁对原始 so 布局的扰动。
#pragma pack(push, 1)
struct zPatchBayHeader {
    uint32_t magic;      // 'VMPB' = 0x42504d56，用于快速识别 patch bay。
    uint16_t version;    // Header 版本号，后续扩展字段时可做向后兼容判断。
    uint16_t flags;      // 运行时/补丁阶段状态位。

    uint32_t total_size;     // 整个 patch bay 大小（header + payload）。
    uint32_t header_size;    // sizeof(zPatchBayHeader)。
    uint32_t payload_size;   // header 之后可供写入的字节数。

    // 各子区域偏移与容量，全部相对 zPatchBayImage 起始地址。
    uint32_t dynsym_off;
    uint32_t dynsym_cap;
    uint32_t dynstr_off;
    uint32_t dynstr_cap;
    uint32_t gnuhash_off;
    uint32_t gnuhash_cap;
    uint32_t sysvhash_off;
    uint32_t sysvhash_cap;
    uint32_t versym_off;
    uint32_t versym_cap;
    uint32_t takeover_slot_total;  // 汇编桩总槽位数（编译期生成）。
    uint32_t takeover_slot_used;   // 当前补丁实际占用槽位数。

    // 记录“原始”动态表地址，用于调试和必要时回退。
    uint64_t orig_dt_symtab;
    uint64_t orig_dt_strtab;
    uint64_t orig_dt_gnu_hash;
    uint64_t orig_dt_hash;
    uint64_t orig_dt_versym;

    // 记录“当前补丁已写入”字节数，后处理工具据此计算有效负载与 CRC。
    uint32_t used_dynsym;
    uint32_t used_dynstr;
    uint32_t used_gnuhash;
    uint32_t used_sysvhash;
    uint32_t used_versym;

    // 允许槽位位图（支持最多 128 个槽），用于限制可接管符号范围。
    uint64_t takeover_slot_bitmap_lo;
    uint64_t takeover_slot_bitmap_hi;
    uint32_t crc32;  // crc32(header-with-zero-crc + used payload bytes)。
};
#pragma pack(pop)

constexpr uint32_t kPatchBayMagic = 0x42504d56U;  // 'VMPB'
constexpr uint16_t kPatchBayVersion = 1;

// 下面是各区域容量预算。当前值面向 demo 与回归规模，可按目标 so 体量调整。
constexpr uint32_t kPatchBayDynsymCap = 128U * 1024U;
constexpr uint32_t kPatchBayDynstrCap = 192U * 1024U;
constexpr uint32_t kPatchBayGnuHashCap = 128U * 1024U;
constexpr uint32_t kPatchBaySysvHashCap = 64U * 1024U;
constexpr uint32_t kPatchBayVersymCap = 32U * 1024U;

// 通过固定顺序串接子区域，保证补丁工具可用常量偏移直接寻址。
constexpr uint32_t kPatchBayHeaderSize = static_cast<uint32_t>(sizeof(zPatchBayHeader));
constexpr uint32_t kPatchBayDynsymOff = kPatchBayHeaderSize;
constexpr uint32_t kPatchBayDynstrOff = kPatchBayDynsymOff + kPatchBayDynsymCap;
constexpr uint32_t kPatchBayGnuHashOff = kPatchBayDynstrOff + kPatchBayDynstrCap;
constexpr uint32_t kPatchBaySysvHashOff = kPatchBayGnuHashOff + kPatchBayGnuHashCap;
constexpr uint32_t kPatchBayVersymOff = kPatchBaySysvHashOff + kPatchBaySysvHashCap;
constexpr uint32_t kPatchBayTotalSize = kPatchBayVersymOff + kPatchBayVersymCap;
constexpr uint32_t kPatchBayPayloadSize = kPatchBayTotalSize - kPatchBayHeaderSize;

static_assert(sizeof(zPatchBayHeader) == 148, "zPatchBayHeader size changed unexpectedly");

struct zPatchBayImage {
    zPatchBayHeader header;
    uint8_t payload[kPatchBayPayloadSize];
};

// 导出运行时可见入口，便于 JNI/测试脚本读取 patch bay 元数据。
extern "C" const zPatchBayHeader* zGetPatchBayHeader();

#endif  // VMPROJECT_VMENGINE_ZPATCHBAY_H
