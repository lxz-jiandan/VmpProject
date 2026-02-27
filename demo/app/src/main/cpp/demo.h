#ifndef DEMO_APP_SRC_MAIN_CPP_DEMO_H
#define DEMO_APP_SRC_MAIN_CPP_DEMO_H

// demo 导出函数声明：供 bridge 在链接期直接依赖调用。
extern "C" {

int fun_add(int a, int b);
int fun_for(int a, int b);
int fun_for_add(int a, int b);
int fun_if_sub(int a, int b);
int fun_countdown_muladd(int a, int b);
int fun_loop_call_mix(int a, int b);
int fun_call_chain(int a, int b);
int fun_branch_call(int a, int b);
int fun_cpp_string_len(int a, int b);
int fun_cpp_vector_sum(int a, int b);
int fun_cpp_virtual_mix(int a, int b);
int fun_global_data_mix(int a, int b);
int fun_static_local_table(int a, int b);
int fun_global_struct_acc(int a, int b);
int fun_class_static_member(int a, int b);
int fun_multi_branch_path(int a, int b);
int fun_switch_dispatch(int a, int b);
int fun_bitmask_branch(int a, int b);
int fun_global_table_rw(int a, int b);
int fun_global_mutable_state(int a, int b);

}

#endif
