/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - PatchBay 预留区解析实现（用于后续低破坏补丁扩展）。
 * - 加固链路位置：可补丁布局能力层。
 * - 输入：so 中预留区描述。
 * - 输出：可定位的补丁可写区域。
 */
#include "zPatchBay.h"
// 由构建阶段生成的“可接管符号槽位”常量。
#include "generated/zTakeoverSymbols.generated.h"

namespace {
// 由生成脚本产出的固定符号槽位数；PatchBay 会根据该值生成位图默认值。
constexpr uint32_t kTakeoverSlotTotal = static_cast<uint32_t>(kTakeoverGeneratedSymbolCount);

// 生成低 count 位为 1 的掩码，用于标记“可用接管槽”。
constexpr uint64_t bitmaskForCount(uint32_t count) {
    if (count == 0) {
        return 0ULL;
    }
    if (count >= 64U) {
        return ~0ULL;
    }
    return (1ULL << count) - 1ULL;
}

constexpr uint64_t kTakeoverSlotBitmapLo = bitmaskForCount(kTakeoverSlotTotal);
// 超过 64 槽时，高位位图用于表达第 65..128 槽的可用性。
constexpr uint64_t kTakeoverSlotBitmapHi = (kTakeoverSlotTotal > 64U)
                                           ? bitmaskForCount(kTakeoverSlotTotal - 64U)
                                           : 0ULL;
}  // namespace

// 将 patch bay 实例放入独立的 .vmp_patchbay 段中：
// 1) ALLOC+WRITE，保证存在于文件和内存映射中；
// 2) 地址稳定，后处理工具可以按 section 定位并原位写入；
// 3) 避免改动 text/data 主体布局。
extern "C" __attribute__((used, section(".vmp_patchbay"), visibility("default")))
zPatchBayImage vm_patch_bay = {
        {
                // magic: patch bay 签名。
                kPatchBayMagic,
                // version: 头版本。
                kPatchBayVersion,
                // flags: 运行时标志，初始 0。
                0,
                // totalSize: 整体大小（header + payload）。
                kPatchBayTotalSize,
                // headerSize: 头大小。
                kPatchBayHeaderSize,
                // payloadSize: 可写负载大小。
                kPatchBayPayloadSize,
                // dynsymOffset/dynsymCapacity。
                kPatchBayDynsymOff,
                kPatchBayDynsymCap,
                // dynstrOffset/dynstrCapacity。
                kPatchBayDynstrOff,
                kPatchBayDynstrCap,
                // gnuHashOffset/gnuHashCapacity。
                kPatchBayGnuHashOff,
                kPatchBayGnuHashCap,
                // sysvHashOffset/sysvHashCapacity。
                kPatchBaySysvHashOff,
                kPatchBaySysvHashCap,
                // versymOffset/versymCapacity。
                kPatchBayVersymOff,
                kPatchBayVersymCap,
                // takeoverSlotTotal: 编译期生成槽位总数。
                kTakeoverSlotTotal,
                // takeoverSlotUsed: 初始默认全部可用。
                kTakeoverSlotTotal,
                0,  // originalDtSymtab
                0,  // originalDtStrtab
                0,  // originalDtGnuHash
                0,  // originalDtHash
                0,  // originalDtVersym
                0,  // usedDynsym
                0,  // usedDynstr
                0,  // usedGnuHash
                0,  // usedSysvHash
                0,  // usedVersym
                kTakeoverSlotBitmapLo,  // 默认允许全部已生成槽位。
                kTakeoverSlotBitmapHi,  // 高 64 位掩码（槽位 > 64 时生效）。
                0,  // crc32
        },
        // payload 初始清零，等待后处理工具写入。
        {0},
};

extern "C" __attribute__((visibility("default")))
const zPatchBayHeader* vm_get_patch_bay_header() {
    // 只读访问入口：工具侧可通过 dlsym 调用并打印当前 patch bay 状态。
    return &vm_patch_bay.header;
}
