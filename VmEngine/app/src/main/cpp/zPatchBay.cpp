#include "zPatchBay.h"
#include "generated/zTakeoverSymbols.generated.h"

namespace {
constexpr uint32_t kTakeoverSlotTotal = static_cast<uint32_t>(kTakeoverGeneratedSymbolCount);

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

// Keep this image in a dedicated ALLOC+WRITE section to provide
// a stable file-backed patch bay for post-build ELF patching.
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
                kTakeoverSlotBitmapLo,
                kTakeoverSlotBitmapHi,
                0,  // crc32
        },
        {0},
};

extern "C" __attribute__((visibility("default")))
const zPatchBayHeader* zGetPatchBayHeader() {
    return &g_patch_bay.header;
}
