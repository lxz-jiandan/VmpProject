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
};

// 结束命名空间。
}  // namespace vmp
