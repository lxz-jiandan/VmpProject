// [VMP_FLOW_NOTE] 自动生成文件
// - 由 tools/gen_takeover_stubs.py 生成，维护 symbol_id <-> symbol_name 映射。
// - 来源清单: tools/takeover_symbols.json
#ifndef Z_TAKEOVER_SYMBOLS_GENERATED_H
#define Z_TAKEOVER_SYMBOLS_GENERATED_H

#include <cstddef>
#include <cstdint>

struct zTakeoverGeneratedSymbolEntry {
    uint32_t symbol_id;
    const char* symbol_name;
};

static constexpr zTakeoverGeneratedSymbolEntry kTakeoverGeneratedSymbols[] = {
    {0u, "fun_add"},
    {1u, "fun_for"},
    {2u, "fun_if_sub"},
    {3u, "fun_for_add"},
    {4u, "fun_countdown_muladd"},
    {5u, "fun_loop_call_mix"},
    {6u, "fun_call_chain"},
    {7u, "fun_branch_call"},
    {8u, "fun_cpp_string_len"},
    {9u, "fun_cpp_vector_sum"},
    {10u, "fun_cpp_virtual_mix"},
    {11u, "fun_global_data_mix"},
    {12u, "fun_static_local_table"},
    {13u, "fun_global_struct_acc"},
    {14u, "fun_class_static_member"},
    {15u, "fun_multi_branch_path"},
    {16u, "fun_switch_dispatch"},
    {17u, "fun_bitmask_branch"},
    {18u, "fun_global_table_rw"},
    {19u, "fun_global_mutable_state"},
};

static constexpr size_t kTakeoverGeneratedSymbolCount = sizeof(kTakeoverGeneratedSymbols) / sizeof(kTakeoverGeneratedSymbols[0]);

inline const char* zTakeoverGeneratedSymbolNameById(uint32_t symbol_id) {
    switch (symbol_id) {
        case 0u: return "fun_add";
        case 1u: return "fun_for";
        case 2u: return "fun_if_sub";
        case 3u: return "fun_for_add";
        case 4u: return "fun_countdown_muladd";
        case 5u: return "fun_loop_call_mix";
        case 6u: return "fun_call_chain";
        case 7u: return "fun_branch_call";
        case 8u: return "fun_cpp_string_len";
        case 9u: return "fun_cpp_vector_sum";
        case 10u: return "fun_cpp_virtual_mix";
        case 11u: return "fun_global_data_mix";
        case 12u: return "fun_static_local_table";
        case 13u: return "fun_global_struct_acc";
        case 14u: return "fun_class_static_member";
        case 15u: return "fun_multi_branch_path";
        case 16u: return "fun_switch_dispatch";
        case 17u: return "fun_bitmask_branch";
        case 18u: return "fun_global_table_rw";
        case 19u: return "fun_global_mutable_state";
        default: return nullptr;
    }
}

#endif // Z_TAKEOVER_SYMBOLS_GENERATED_H
