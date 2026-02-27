// 引入 pipeline 类型定义。
#include "zPipelineTypes.h"

// 进入 pipeline 命名空间。
namespace vmp {

// 默认保护函数列表。
// 该列表用于“用户未显式传 --function”时的默认行为。
const std::vector<std::string> kDefaultFunctions = {
    // 基础算术/循环函数。
    "fun_for",
    // 基础算术函数。
    "fun_add",
    // 组合循环与加法函数。
    "fun_for_add",
    // 条件分支减法函数。
    "fun_if_sub",
    // 倒计时混合算术函数。
    "fun_countdown_muladd",
    // 循环 + 调用混合函数。
    "fun_loop_call_mix",
    // 调用链函数。
    "fun_call_chain",
    // 分支调用函数。
    "fun_branch_call",
    // C++ 字符串构造函数。
    "fun_cpp_make_string",
    // C++ 字符串长度函数。
    "fun_cpp_string_len",
    // C++ vector 求和函数。
    "fun_cpp_vector_sum",
    // C++ 虚函数混合函数。
    "fun_cpp_virtual_mix",
    // 全局数据混合访问函数。
    "fun_global_data_mix",
    // 静态局部表函数。
    "fun_static_local_table",
    // 全局结构体访问函数。
    "fun_global_struct_acc",
    // 类静态成员访问函数。
    "fun_class_static_member",
    // 多分支路径函数。
    "fun_multi_branch_path",
    // switch 分发函数。
    "fun_switch_dispatch",
    // 位掩码分支函数。
    "fun_bitmask_branch",
    // 全局表读写函数。
    "fun_global_table_rw",
    // 全局可变状态函数。
    "fun_global_mutable_state",
    // 复杂条件零分支函数（覆盖 cbz/cbnz 语义）。
    "fun_flag_merge_cbz",
    // 指针步进访问函数。
    "fun_ptr_stride_sum",
    // 函数表分发函数。
    "fun_fn_table_dispatch",
    // 窗口裁剪函数。
    "fun_clamp_window",
    // 64 位有符号返回函数。
    "fun_ret_i64_mix",
    // 64 位无符号返回函数。
    "fun_ret_u64_mix",
    // bool 返回函数。
    "fun_ret_bool_gate",
    // int16 返回函数。
    "fun_ret_i16_pack",
    // 循环 switch 聚合函数。
    "fun_switch_loop_acc",
    // 结构体别名访问函数。
    "fun_struct_alias_walk",
    // 无符号边界路径函数。
    "fun_unsigned_edge_paths",
    // 逆向指针遍历函数。
    "fun_reverse_ptr_mix",
    // 带 break 的保护链路函数。
    "fun_guarded_chain_mix",
    // 第二个 64 位有符号返回函数。
    "fun_ret_i64_steps",
    // 第二个 64 位无符号返回函数。
    "fun_ret_u64_acc",
    // 第二个 bool 返回函数。
    "fun_ret_bool_mix2",
    // uint16 返回函数。
    "fun_ret_u16_blend",
    // int8 返回函数。
    "fun_ret_i8_wave",
    // 扩展类指令覆盖函数（sxt*/uxt*/adds）。
    "fun_ext_insn_mix",
    // 位域移动指令覆盖函数（ubfm/sbfm non-wrap）。
    "fun_bfm_nonwrap",
    // 位域移动指令覆盖函数（ubfm/sbfm wrap）。
    "fun_bfm_wrap",
    // 条件选择自增指令覆盖函数（csinc）。
    "fun_csinc_path",
};

// 结束命名空间。
}  // namespace vmp
