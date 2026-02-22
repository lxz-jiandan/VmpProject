/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - PatchBay 预留区解析实现（用于后续低破坏补丁扩展）。
 * - 加固链路位置：可补丁布局能力层。
 * - 输入：so 中预留区描述。
 * - 输出：可定位的补丁可写区域。
 */
#include "zPatchBay.h"
#include "generated/zTakeoverSymbols.generated.h"

namespace {
// 由生成脚本产出的固定符号槽位数；PatchBay 会根据该值生成位图默认值。
constexpr uint32_t kTakeoverSlotTotal = static_cast<uint32_t>(kTakeoverGeneratedSymbolCount);

// 生成低 count 位为 1 的掩码，用于标记“可用接管槽”。
constexpr uint64_t bitmask_for_count(uint32_t count) {
    if (count == 0) {
        return 0ULL;
    }
    if (count >= 64U) {
        return ~0ULL;
    }
    return (1ULL << count) - 1ULL;
}

constexpr uint64_t kTakeoverSlotBitmapLo = bitmask_for_count(kTakeoverSlotTotal);
constexpr uint64_t kTakeoverSlotBitmapHi = (kTakeoverSlotTotal > 64U)
                                           ? bitmask_for_count(kTakeoverSlotTotal - 64U)
                                           : 0ULL;
}  // namespace

// 将 patch bay 实例放入独立的 .vmp_patchbay 段中：
// 1) ALLOC+WRITE，保证存在于文件和内存映射中；
// 2) 地址稳定，后处理工具可以按 section 定位并原位写入；
// 3) 避免改动 text/data 主体布局。
extern "C" __attribute__((used, section(".vmp_patchbay"), visibility("default")))
zPatchBayImage g_patch_bay = {
        {
                kPatchBayMagic,
                kPatchBayVersion,
                0,
                kPatchBayTotalSize,
                kPatchBayHeaderSize,
                kPatchBayPayloadSize,
                kPatchBayDynsymOff,
                kPatchBayDynsymCap,
                kPatchBayDynstrOff,
                kPatchBayDynstrCap,
                kPatchBayGnuHashOff,
                kPatchBayGnuHashCap,
                kPatchBaySysvHashOff,
                kPatchBaySysvHashCap,
                kPatchBayVersymOff,
                kPatchBayVersymCap,
                kTakeoverSlotTotal,
                kTakeoverSlotTotal,
                0,  // orig_dt_symtab
                0,  // orig_dt_strtab
                0,  // orig_dt_gnu_hash
                0,  // orig_dt_hash
                0,  // orig_dt_versym
                0,  // used_dynsym
                0,  // used_dynstr
                0,  // used_gnuhash
                0,  // used_sysvhash
                0,  // used_versym
                kTakeoverSlotBitmapLo,  // 默认允许全部已生成槽位。
                kTakeoverSlotBitmapHi,  // 高 64 位掩码（槽位 > 64 时生效）。
                0,  // crc32
        },
        {0},
};

extern "C" __attribute__((visibility("default")))
const zPatchBayHeader* zGetPatchBayHeader() {
    // 只读访问入口：工具侧可通过 dlsym 调用并打印当前 patch bay 状态。
    return &g_patch_bay.header;
}
