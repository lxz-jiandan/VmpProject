// 参考函数镜像：
// 通过同源码二次编译生成 fun_*_ref 符号，作为未加固对照组。
// 约定：加固流程只选择 fun_*，不选择 fun_*_ref。
//
// 设计说明：
// 1) 通过宏重命名把 fun_* 映射到 fun_*_ref，复用同一份实现源码。
// 2) 这样可保证“被测实现”和“对照实现”在逻辑上同源，减少测试偏差。
// 3) bridge 会同时调用 fun_* 与 fun_*_ref，并做 expected/actual 对比。
// 4) 该文件不新增业务逻辑，仅负责符号重命名与编译拼接。
// 5) 若新增 fun_* 导出，需要同步补充对应宏映射。
// 6) 若漏配宏，回归会表现为 dlsym 失败或结果列缺失。
// 7) include native-lib.cpp 的顺序需保持在宏定义之后。
// 8) 该策略可避免手写一份 ref 副本导致维护漂移。
// 9) ref 版本不参与加固，职责是提供“语义基线”而不是性能基线。
// 10) 当 fun_* 与 fun_*_ref 出现差异时，优先怀疑翻译链路或符号接管链路。
// 11) 该文件按“一行一个映射”展开，便于 review 时快速检查漏项。
// 12) 若未来拆分 native-lib.cpp，需保持映射与 include 关系的一致性。

#define fun_add fun_add_ref
#define fun_for fun_for_ref
#define fun_for_add fun_for_add_ref
#define fun_if_sub fun_if_sub_ref
#define fun_countdown_muladd fun_countdown_muladd_ref
#define fun_loop_call_mix fun_loop_call_mix_ref
#define fun_call_chain fun_call_chain_ref
#define fun_branch_call fun_branch_call_ref
#define fun_cpp_make_string fun_cpp_make_string_ref
#define fun_cpp_string_len fun_cpp_string_len_ref
#define fun_cpp_vector_sum fun_cpp_vector_sum_ref
#define fun_cpp_virtual_mix fun_cpp_virtual_mix_ref
#define fun_div_mod_chain fun_div_mod_chain_ref
#define fun_shift_mix fun_shift_mix_ref
#define fun_do_while_path fun_do_while_path_ref
#define fun_nested_continue_break fun_nested_continue_break_ref
#define fun_indirect_call_mix fun_indirect_call_mix_ref
#define fun_unsigned_compare_fold fun_unsigned_compare_fold_ref
#define fun_local_array_walk fun_local_array_walk_ref
#define fun_switch_fallthrough fun_switch_fallthrough_ref
#define fun_short_circuit_logic fun_short_circuit_logic_ref
#define fun_select_mix fun_select_mix_ref
#define fun_global_data_mix fun_global_data_mix_ref
#define fun_static_local_table fun_static_local_table_ref
#define fun_global_struct_acc fun_global_struct_acc_ref
#define fun_class_static_member fun_class_static_member_ref
#define fun_multi_branch_path fun_multi_branch_path_ref
#define fun_switch_dispatch fun_switch_dispatch_ref
#define fun_bitmask_branch fun_bitmask_branch_ref
#define fun_global_table_rw fun_global_table_rw_ref
#define fun_global_mutable_state fun_global_mutable_state_ref
#define fun_flag_merge_cbz fun_flag_merge_cbz_ref
#define fun_ptr_stride_sum fun_ptr_stride_sum_ref
#define fun_fn_table_dispatch fun_fn_table_dispatch_ref
#define fun_clamp_window fun_clamp_window_ref
#define fun_ret_i64_mix fun_ret_i64_mix_ref
#define fun_ret_u64_mix fun_ret_u64_mix_ref
#define fun_ret_bool_gate fun_ret_bool_gate_ref
#define fun_ret_i16_pack fun_ret_i16_pack_ref
#define fun_switch_loop_acc fun_switch_loop_acc_ref
#define fun_struct_alias_walk fun_struct_alias_walk_ref
#define fun_unsigned_edge_paths fun_unsigned_edge_paths_ref
#define fun_reverse_ptr_mix fun_reverse_ptr_mix_ref
#define fun_guarded_chain_mix fun_guarded_chain_mix_ref
#define fun_ret_i64_steps fun_ret_i64_steps_ref
#define fun_ret_u64_acc fun_ret_u64_acc_ref
#define fun_ret_bool_mix2 fun_ret_bool_mix2_ref
#define fun_ret_u16_blend fun_ret_u16_blend_ref
#define fun_ret_i8_wave fun_ret_i8_wave_ref
#define fun_ext_insn_mix fun_ext_insn_mix_ref
#define fun_bfm_nonwrap fun_bfm_nonwrap_ref
#define fun_bfm_wrap fun_bfm_wrap_ref
#define fun_csinc_path fun_csinc_path_ref
#define fun_madd_msub_div fun_madd_msub_div_ref
#define fun_orn_bic_extr fun_orn_bic_extr_ref
#define fun_mem_half_signed fun_mem_half_signed_ref
#define fun_atomic_u8_order fun_atomic_u8_order_ref
#define fun_atomic_u16_order fun_atomic_u16_order_ref
#define fun_atomic_u64_order fun_atomic_u64_order_ref
#define fun_ret_cstr_pick fun_ret_cstr_pick_ref
#define fun_ret_std_string_mix fun_ret_std_string_mix_ref
#define fun_ret_vector_mix fun_ret_vector_mix_ref

#include "native-lib.cpp"
