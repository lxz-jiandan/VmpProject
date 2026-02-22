/* [VMP_FLOW_NOTE] 自动生成文件 */
/* - 由 tools/gen_takeover_stubs.py 生成，定义 ARM64 导出跳板。 */
/* - 来源清单: tools/takeover_symbols.json */

    .text
    .align 2

    .global fun_add
    .type fun_add, %function
fun_add:
    movz w2, #0
    b z_takeover_dispatch_by_id
    .size fun_add, .-fun_add

    .global fun_for
    .type fun_for, %function
fun_for:
    movz w2, #1
    b z_takeover_dispatch_by_id
    .size fun_for, .-fun_for

    .global fun_if_sub
    .type fun_if_sub, %function
fun_if_sub:
    movz w2, #2
    b z_takeover_dispatch_by_id
    .size fun_if_sub, .-fun_if_sub

    .global fun_for_add
    .type fun_for_add, %function
fun_for_add:
    movz w2, #3
    b z_takeover_dispatch_by_id
    .size fun_for_add, .-fun_for_add

    .global fun_countdown_muladd
    .type fun_countdown_muladd, %function
fun_countdown_muladd:
    movz w2, #4
    b z_takeover_dispatch_by_id
    .size fun_countdown_muladd, .-fun_countdown_muladd

    .global fun_loop_call_mix
    .type fun_loop_call_mix, %function
fun_loop_call_mix:
    movz w2, #5
    b z_takeover_dispatch_by_id
    .size fun_loop_call_mix, .-fun_loop_call_mix

    .global fun_call_chain
    .type fun_call_chain, %function
fun_call_chain:
    movz w2, #6
    b z_takeover_dispatch_by_id
    .size fun_call_chain, .-fun_call_chain

    .global fun_branch_call
    .type fun_branch_call, %function
fun_branch_call:
    movz w2, #7
    b z_takeover_dispatch_by_id
    .size fun_branch_call, .-fun_branch_call

    .global fun_cpp_string_len
    .type fun_cpp_string_len, %function
fun_cpp_string_len:
    movz w2, #8
    b z_takeover_dispatch_by_id
    .size fun_cpp_string_len, .-fun_cpp_string_len

    .global fun_cpp_vector_sum
    .type fun_cpp_vector_sum, %function
fun_cpp_vector_sum:
    movz w2, #9
    b z_takeover_dispatch_by_id
    .size fun_cpp_vector_sum, .-fun_cpp_vector_sum

    .global fun_cpp_virtual_mix
    .type fun_cpp_virtual_mix, %function
fun_cpp_virtual_mix:
    movz w2, #10
    b z_takeover_dispatch_by_id
    .size fun_cpp_virtual_mix, .-fun_cpp_virtual_mix

    .global fun_global_data_mix
    .type fun_global_data_mix, %function
fun_global_data_mix:
    movz w2, #11
    b z_takeover_dispatch_by_id
    .size fun_global_data_mix, .-fun_global_data_mix

    .global fun_static_local_table
    .type fun_static_local_table, %function
fun_static_local_table:
    movz w2, #12
    b z_takeover_dispatch_by_id
    .size fun_static_local_table, .-fun_static_local_table

    .global fun_global_struct_acc
    .type fun_global_struct_acc, %function
fun_global_struct_acc:
    movz w2, #13
    b z_takeover_dispatch_by_id
    .size fun_global_struct_acc, .-fun_global_struct_acc

    .global fun_class_static_member
    .type fun_class_static_member, %function
fun_class_static_member:
    movz w2, #14
    b z_takeover_dispatch_by_id
    .size fun_class_static_member, .-fun_class_static_member

    .global fun_multi_branch_path
    .type fun_multi_branch_path, %function
fun_multi_branch_path:
    movz w2, #15
    b z_takeover_dispatch_by_id
    .size fun_multi_branch_path, .-fun_multi_branch_path

    .global fun_switch_dispatch
    .type fun_switch_dispatch, %function
fun_switch_dispatch:
    movz w2, #16
    b z_takeover_dispatch_by_id
    .size fun_switch_dispatch, .-fun_switch_dispatch

    .global fun_bitmask_branch
    .type fun_bitmask_branch, %function
fun_bitmask_branch:
    movz w2, #17
    b z_takeover_dispatch_by_id
    .size fun_bitmask_branch, .-fun_bitmask_branch

    .global fun_global_table_rw
    .type fun_global_table_rw, %function
fun_global_table_rw:
    movz w2, #18
    b z_takeover_dispatch_by_id
    .size fun_global_table_rw, .-fun_global_table_rw

    .global fun_global_mutable_state
    .type fun_global_mutable_state, %function
fun_global_mutable_state:
    movz w2, #19
    b z_takeover_dispatch_by_id
    .size fun_global_mutable_state, .-fun_global_mutable_state
