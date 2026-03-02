#ifndef DEMO_APP_SRC_MAIN_CPP_DEMO_H
#define DEMO_APP_SRC_MAIN_CPP_DEMO_H

#include <string>
#include <vector>

// demo 导出函数声明：供 bridge 在链接期直接依赖调用。
// 说明：
// 1) 这些符号是离线加固的输入选择范围（fun_*）。
// 2) 运行时 bridge 会调用同名符号，并与 *_ref 对照实现比较结果。
// 3) 为了稳定回归，函数覆盖了算术、分支、内存、原子、返回类型等场景。
#ifdef __cplusplus
extern "C" {
#endif

// 基础算术与控制流场景。
int fun_add(int a, int b);
int fun_for(int a, int b);
int fun_for_add(int a, int b);
int fun_if_sub(int a, int b);
int fun_countdown_muladd(int a, int b);
int fun_loop_call_mix(int a, int b);
int fun_call_chain(int a, int b);
int fun_branch_call(int a, int b);

// C++ 对象与容器相关场景（保留 C 符号便于明文定位）。
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type-c-linkage"
#endif
// 保持 C 符号名，便于 VMP 通过明文函数名定位；仅用于 demo 回归链路。
std::string fun_cpp_make_string(int a, int b);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
int fun_cpp_string_len(int a, int b);
int fun_cpp_vector_sum(int a, int b);
int fun_cpp_virtual_mix(int a, int b);

// 分支、逻辑与数据访问场景。
int fun_div_mod_chain(int a, int b);
int fun_shift_mix(int a, int b);
int fun_do_while_path(int a, int b);
int fun_nested_continue_break(int a, int b);
int fun_indirect_call_mix(int a, int b);
int fun_unsigned_compare_fold(int a, int b);
int fun_local_array_walk(int a, int b);
int fun_switch_fallthrough(int a, int b);
int fun_short_circuit_logic(int a, int b);
int fun_select_mix(int a, int b);
int fun_global_data_mix(int a, int b);
int fun_static_local_table(int a, int b);
int fun_global_struct_acc(int a, int b);
int fun_class_static_member(int a, int b);
int fun_multi_branch_path(int a, int b);
int fun_switch_dispatch(int a, int b);
int fun_bitmask_branch(int a, int b);
int fun_global_table_rw(int a, int b);
int fun_global_mutable_state(int a, int b);
int fun_flag_merge_cbz(int a, int b);
int fun_ptr_stride_sum(int a, int b);
int fun_fn_table_dispatch(int a, int b);
int fun_clamp_window(int a, int b);

// 返回类型覆盖场景（64 位/布尔/窄整数）。
long long fun_ret_i64_mix(int a, int b);
unsigned long long fun_ret_u64_mix(int a, int b);
bool fun_ret_bool_gate(int a, int b);
short fun_ret_i16_pack(int a, int b);
int fun_switch_loop_acc(int a, int b);
int fun_struct_alias_walk(int a, int b);
int fun_unsigned_edge_paths(int a, int b);
int fun_reverse_ptr_mix(int a, int b);
int fun_guarded_chain_mix(int a, int b);
long long fun_ret_i64_steps(int a, int b);
unsigned long long fun_ret_u64_acc(int a, int b);
bool fun_ret_bool_mix2(int a, int b);
unsigned short fun_ret_u16_blend(int a, int b);
signed char fun_ret_i8_wave(int a, int b);

// 指令覆盖与原子语义相关场景。
int fun_ext_insn_mix(int a, int b);
int fun_bfm_nonwrap(int a, int b);
int fun_bfm_wrap(int a, int b);
int fun_csinc_path(int a, int b);
int fun_madd_msub_div(int a, int b);
int fun_orn_bic_extr(int a, int b);
int fun_mem_half_signed(int a, int b);
int fun_atomic_u8_order(int a, int b);
int fun_atomic_u16_order(int a, int b);
int fun_atomic_u64_order(int a, int b);

// 字符串与容器返回场景（供 bridge 做摘要比较）。
const char* fun_ret_cstr_pick(int a, int b);
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type-c-linkage"
#endif
std::string fun_ret_std_string_mix(int a, int b);
std::vector<int> fun_ret_vector_mix(int a, int b);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif
