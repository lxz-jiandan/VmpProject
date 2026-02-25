/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - PatchBay 数据结构与接口声明。
 * - 加固链路位置：补丁布局接口层。
 * - 输入：预留区元信息。
 * - 输出：补丁定位能力。
 */
#ifndef VMPROJECT_VMENGINE_ZPATCHBAY_H
#define VMPROJECT_VMENGINE_ZPATCHBAY_H

// 定宽整数用于固定头布局，避免不同 ABI 下大小变化。
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

    uint32_t totalSize;     // 整个 patch bay 大小（header + payload）。
    uint32_t headerSize;    // sizeof(zPatchBayHeader)。
    uint32_t payloadSize;   // header 之后可供写入的字节数。

    // 各子区域偏移与容量，全部相对 zPatchBayImage 起始地址。
    // dynsym 在 patch bay 中的起始偏移。
    uint32_t dynsymOffset;
    // dynsym 最大可写字节数。
    uint32_t dynsymCapacity;
    // dynstr 在 patch bay 中的起始偏移。
    uint32_t dynstrOffset;
    // dynstr 最大可写字节数。
    uint32_t dynstrCapacity;
    // gnu hash 在 patch bay 中的起始偏移。
    uint32_t gnuHashOffset;
    // gnu hash 最大可写字节数。
    uint32_t gnuHashCapacity;
    // sysv hash 在 patch bay 中的起始偏移。
    uint32_t sysvHashOffset;
    // sysv hash 最大可写字节数。
    uint32_t sysvHashCapacity;
    // versym 在 patch bay 中的起始偏移。
    uint32_t versymOffset;
    // versym 最大可写字节数。
    uint32_t versymCapacity;
    uint32_t takeoverSlotTotal;  // 汇编桩总槽位数（编译期生成）。
    uint32_t takeoverSlotUsed;   // 当前补丁实际占用槽位数。

    // 记录“原始”动态表地址，用于调试和必要时回退。
    uint64_t originalDtSymtab;
    uint64_t originalDtStrtab;
    uint64_t originalDtGnuHash;
    uint64_t originalDtHash;
    uint64_t originalDtVersym;

    // 记录“当前补丁已写入”字节数，后处理工具据此计算有效负载与 CRC。
    uint32_t usedDynsym;
    uint32_t usedDynstr;
    uint32_t usedGnuHash;
    uint32_t usedSysvHash;
    uint32_t usedVersym;

    // 允许槽位位图（支持最多 128 个槽），用于限制可接管符号范围。
    uint64_t takeoverSlotBitmapLo;
    uint64_t takeoverSlotBitmapHi;
    uint32_t crc32;  // crc32(header-with-zero-crc + used payload bytes)。
};
#pragma pack(pop)

constexpr uint32_t kPatchBayMagic = 0x42504d56U;  // 'VMPB'
// 当前 patch bay 头版本号。
constexpr uint16_t kPatchBayVersion = 1;

// 下面是各区域容量预算。当前值面向 demo 与回归规模，可按目标 so 体量调整。
constexpr uint32_t kPatchBayDynsymCap = 128U * 1024U;
constexpr uint32_t kPatchBayDynstrCap = 192U * 1024U;
constexpr uint32_t kPatchBayGnuHashCap = 128U * 1024U;
constexpr uint32_t kPatchBaySysvHashCap = 64U * 1024U;
constexpr uint32_t kPatchBayVersymCap = 32U * 1024U;

// 通过固定顺序串接子区域，保证补丁工具可用常量偏移直接寻址。
constexpr uint32_t kPatchBayHeaderSize = static_cast<uint32_t>(sizeof(zPatchBayHeader));
// dynsym 区起点紧跟 header。
constexpr uint32_t kPatchBayDynsymOff = kPatchBayHeaderSize;
// dynstr 区紧跟 dynsym 区。
constexpr uint32_t kPatchBayDynstrOff = kPatchBayDynsymOff + kPatchBayDynsymCap;
// gnu hash 区紧跟 dynstr 区。
constexpr uint32_t kPatchBayGnuHashOff = kPatchBayDynstrOff + kPatchBayDynstrCap;
// sysv hash 区紧跟 gnu hash 区。
constexpr uint32_t kPatchBaySysvHashOff = kPatchBayGnuHashOff + kPatchBayGnuHashCap;
// versym 区紧跟 sysv hash 区。
constexpr uint32_t kPatchBayVersymOff = kPatchBaySysvHashOff + kPatchBaySysvHashCap;
// patch bay 总大小 = 最后一区末尾。
constexpr uint32_t kPatchBayTotalSize = kPatchBayVersymOff + kPatchBayVersymCap;
// 可写 payload 大小 = 总大小 - header。
constexpr uint32_t kPatchBayPayloadSize = kPatchBayTotalSize - kPatchBayHeaderSize;

// 头结构大小固定约束，防止误改导致工具侧解析错位。
static_assert(sizeof(zPatchBayHeader) == 148, "zPatchBayHeader size changed unexpectedly");

struct zPatchBayImage {
    // 固定头，描述各区域偏移/容量与状态字段。
    zPatchBayHeader header;
    // 可写负载区，后处理工具在此写入新 dyn 表与 hash 表。
    uint8_t payload[kPatchBayPayloadSize];
};

// 导出运行时可见入口，便于 JNI/测试脚本读取 patch bay 元数据。
extern "C" const zPatchBayHeader* vm_get_patch_bay_header();

#endif  // VMPROJECT_VMENGINE_ZPATCHBAY_H
