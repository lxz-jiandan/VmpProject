#pragma once

#include <cstdint>
#include <functional>
#include <vector>

struct PatchStats {
    size_t adrp = 0;
    size_t adr = 0;
    size_t ldr_literal = 0;
    size_t ldr_simd = 0;
    size_t prfm = 0;
    size_t br = 0;
    size_t bl = 0;
    size_t cond_br = 0;
    size_t expanded = 0;
};

bool patch_aarch64_pc_relative_payload(
        const std::vector<uint8_t>& input,
        uint64_t old_pc_base,
        const std::function<uint64_t(uint64_t)>& relocate_old_addr,
        std::vector<uint8_t>* output,
        PatchStats* stats,
        const char* context_name);
