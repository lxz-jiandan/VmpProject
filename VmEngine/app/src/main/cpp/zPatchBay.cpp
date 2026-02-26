/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - PatchBay 预留区解析实现（用于后续低破坏补丁扩展）。
 * - 加固链路位置：可补丁布局能力层。
 * - 输入：so 中预留区描述。
 * - 输出：可定位的补丁可写区域。
 */
#include "zPatchBay.h"

namespace {
// 旧版“编译期固定槽位”路线已移除，PatchBay 默认不再声明预置可用槽位。
constexpr uint32_t kTakeoverEntryTotal = 0U;
constexpr uint64_t kTakeoverEntryBitmapLo = 0ULL;
constexpr uint64_t kTakeoverEntryBitmapHi = 0ULL;
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
                // takeoverEntryTotal: 预置槽位已移除，默认 0。
                kTakeoverEntryTotal,
                // takeoverEntryUsed: 与 total 保持一致。
                kTakeoverEntryTotal,
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
                kTakeoverEntryBitmapLo,  // 预置槽位位图低位（默认 0）。
                kTakeoverEntryBitmapHi,  // 预置槽位位图高位（默认 0）。
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
