#ifndef VMPROJECT_VMENGINE_ZPATCHBAY_H
#define VMPROJECT_VMENGINE_ZPATCHBAY_H

#include <cstdint>

// Route4 patch bay:
// Pre-reserved ELF file-backed area for post-build symbol-table patching.
// zElfEditor writes dynsym/dynstr/hash/versym into this bay and switches DT_* pointers.
#pragma pack(push, 1)
struct zPatchBayHeader {
    uint32_t magic;      // 'VMPB' = 0x42504d56
    uint16_t version;    // header version
    uint16_t flags;      // runtime/patch flags

    uint32_t total_size;     // full image size: header + payload
    uint32_t header_size;    // sizeof(zPatchBayHeader)
    uint32_t payload_size;   // bytes after header

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
    uint32_t takeover_slot_total;
    uint32_t takeover_slot_used;

    uint64_t orig_dt_symtab;
    uint64_t orig_dt_strtab;
    uint64_t orig_dt_gnu_hash;
    uint64_t orig_dt_hash;
    uint64_t orig_dt_versym;

    uint32_t used_dynsym;
    uint32_t used_dynstr;
    uint32_t used_gnuhash;
    uint32_t used_sysvhash;
    uint32_t used_versym;

    uint64_t takeover_slot_bitmap_lo;
    uint64_t takeover_slot_bitmap_hi;
    uint32_t crc32;  // crc32(header-with-zero-crc + used payload bytes)
};
#pragma pack(pop)

constexpr uint32_t kPatchBayMagic = 0x42504d56U;  // 'VMPB'
constexpr uint16_t kPatchBayVersion = 1;

constexpr uint32_t kPatchBayDynsymCap = 128U * 1024U;
constexpr uint32_t kPatchBayDynstrCap = 192U * 1024U;
constexpr uint32_t kPatchBayGnuHashCap = 128U * 1024U;
constexpr uint32_t kPatchBaySysvHashCap = 64U * 1024U;
constexpr uint32_t kPatchBayVersymCap = 32U * 1024U;

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

extern "C" const zPatchBayHeader* zGetPatchBayHeader();

#endif  // VMPROJECT_VMENGINE_ZPATCHBAY_H
