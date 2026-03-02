#include <cstdint>
#include <string>
#include <vector>
#include <numeric>
#include <android/log.h>
#include "demo.h"

// 设计说明（demo native 用例集）：
// 1) 本文件承载 fun_* 被测实现，是加固输入与运行时对照的核心样本集。
// 2) 用例目标不是追求算法复杂度，而是覆盖翻译链路中的关键语义组合。
// 3) 覆盖维度包含：算术、循环、条件分支、函数调用、间接调用、全局状态访问。
// 4) 还覆盖了：C++ 返回类型、容器返回、窄整数返回、布尔返回与 64 位返回。
// 5) 指令维度包含 AArch64 的扩展、位域、条件选择、乘加除法和访存指令路径。
// 6) 内存语义维度包含 release/acquire 原子读写，确保跨线程可见性语义可回归。
// 7) 设计原则一：输入固定、流程确定，保证偏差出现时可复现可定位。
// 8) 设计原则二：每个函数只验证一类主语义，避免单函数混杂过多变量。
// 9) 设计原则三：保留 fallback C++ 等价实现，便于非 AArch64 也能编译与验证。
// 10) helper_* 用于构造稳定的间接调用目标，避免函数表路径失真。
// 11) global/static 组用于验证数据段读写和静态状态更新语义。
// 12) ret_* 组用于覆盖不同 ABI 返回路径，减少仅 int 返回造成的盲区。
// 13) atomic_* 组用于覆盖不同位宽原子操作，检验内存序处理是否一致。
// 14) 本文件与 native-lib-ref.cpp 通过宏重命名形成同源对照，降低测试偏差。
// 15) bridge 层会逐项对比 fun_* 与 fun_*_ref，输出 expected/actual 报表。
// 16) 若新增 fun_*，应同步补充声明、ref 映射与 bridge case，避免覆盖缺口。
// 17) 命名上优先体现“验证点”而非业务含义，便于与 README 的能力分组对应。
// 18) 每个用例都尽量保持副作用可控，避免跨用例状态污染影响判定。
// 19) 对全局状态有写操作的函数，尽量在返回值中折叠写后结果以提升可观测性。
// 20) 对指令回归函数，AArch64 分支强调“触发目标指令”，fallback 分支强调“语义等价”。
// 21) 对 ABI 回归函数，返回值形态优先覆盖寄存器传递差异明显的类型组合。
// 22) 对控制流回归函数，优先构造多路径汇合点，放大分支选择错误带来的差异。
// 23) 对内存访问回归函数，尽量覆盖读取、写入、符号扩展和步进访问四类行为。
// 24) 以上分组并非互斥，函数可在主验证点之外附带覆盖次级语义。

#define DEMO_TEST_EXPORT extern "C" __attribute__((visibility("default"))) __attribute__((used)) __attribute__((noinline)) __attribute__((optnone))

namespace {

int g_global_bias = 7;
uint32_t g_global_table[5] = {3u, 2u, 11u, 5u, 9u};

struct GlobalPair {
    int left;
    int right;
};

GlobalPair g_global_pair = {4, 6};
// 原子内存序回归用全局槽位：分别覆盖 8/16/64 位 load/store。
alignas(1) uint8_t g_atomic_slot_u8 = 0x5Au;
alignas(2) uint16_t g_atomic_slot_u16 = 0x4321u;
alignas(8) uint64_t g_atomic_slot_u64 = 0x123456789ABCDEF0ull;
// 控制潜在 trap 指令路径是否执行：默认 0，仅用于保留指令覆盖而不触发运行时异常。
volatile int g_trap_gate = 0;

class StaticScaleBox {
public:
    static int s_scale;

    static int eval(int a, int b) {
        s_scale = a + 2;
        return s_scale * b + 1;
    }
};

int StaticScaleBox::s_scale = 3;

// [VMP_DEMO_HELPER] helper_abs_diff
// - 覆盖点：提供可复用的小型算术 helper，给间接调用和函数表分发提供稳定目标。
// - 实现思路：保持纯计算和低副作用，让翻译链路能稳定观察 call 边界与返回值。
int helper_abs_diff(int lhs, int rhs) {
    if (lhs > rhs) {
        return lhs - rhs;
    }
    return rhs - lhs;
}

// [VMP_DEMO_HELPER] helper_mul_add
// - 覆盖点：提供可复用的小型算术 helper，给间接调用和函数表分发提供稳定目标。
// - 实现思路：保持纯计算和低副作用，让翻译链路能稳定观察 call 边界与返回值。
int helper_mul_add(int lhs, int rhs) {
    return lhs * rhs + lhs - rhs;
}

// [VMP_DEMO_HELPER] helper_route0
// - 覆盖点：提供可复用的小型算术 helper，给间接调用和函数表分发提供稳定目标。
// - 实现思路：保持纯计算和低副作用，让翻译链路能稳定观察 call 边界与返回值。
int helper_route0(int x, int y) {
    return x + y + 1;
}

// [VMP_DEMO_HELPER] helper_route1
// - 覆盖点：提供可复用的小型算术 helper，给间接调用和函数表分发提供稳定目标。
// - 实现思路：保持纯计算和低副作用，让翻译链路能稳定观察 call 边界与返回值。
int helper_route1(int x, int y) {
    return x * y + 2;
}

// [VMP_DEMO_HELPER] helper_route2
// - 覆盖点：提供可复用的小型算术 helper，给间接调用和函数表分发提供稳定目标。
// - 实现思路：保持纯计算和低副作用，让翻译链路能稳定观察 call 边界与返回值。
int helper_route2(int x, int y) {
    return x - y + 3;
}

} // namespace

// [VMP_DEMO_CASE] fun_add
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_add(int a, int b) {
    return a + b;
}

// [VMP_DEMO_CASE] fun_for
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_for(int a, int b) {
    int ret = 0;
    for (int i = 0; i < 5; i++) {
        ret += a;
        ret += b;
    }
    return ret;
}

// [VMP_DEMO_CASE] fun_for_add
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_for_add(int a, int b) {
    int ret = 0;
    for (int i = 0; i < 5; i++) {
        ret += fun_add(a, b);
    }
    __android_log_print(6, "lxz", "fun_for_add ret: %d", ret);
    return ret;
}

// [VMP_DEMO_CASE] fun_if_sub
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
extern "C" int fun_if_sub(int a, int b) {
    if (a > b) {
        return a - b;
    }
    return b - a;
}

// [VMP_DEMO_CASE] fun_countdown_muladd
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_countdown_muladd(int a, int b) {
    int ret = 0;
    int n = a;
    while (n > 0) {
        ret += b;
        n -= 1;
    }
    return ret + a;
}

// [VMP_DEMO_CASE] fun_loop_call_mix
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_loop_call_mix(int a, int b) {
    int ret = 0;
    for (int i = 0; i < 4; i++) {
        if (i < 2) {
            ret += fun_add(a, b);
        } else {
            ret += fun_add(a, 1);
        }
    }
    return ret;
}

// [VMP_DEMO_CASE] fun_call_chain
// - 覆盖点：串联多个已导出函数，验证跨函数调用链在加固后仍保持语义一致。
// - 实现思路：顺序组合 fun_for、fun_add、fun_if_sub 的结果，构造可直观看差异的聚合返回。
extern "C" int fun_call_chain(int a, int b) {
    int first = fun_for(a, b);
    int second = fun_add(a, b);
    int third = fun_if_sub(a, b);
    return first + second + third;
}

// [VMP_DEMO_CASE] fun_branch_call
// - 覆盖点：同一入口内同时覆盖分支选择与后续函数调用，检验控制流拼接是否正确。
// - 实现思路：先按 a/b 关系选择不同路径，再统一叠加 fun_add 结果做二次校验。
extern "C" int fun_branch_call(int a, int b) {
    int ret = 0;
    if (a >= b) {
        ret = fun_countdown_muladd(a, b);
    } else {
        ret = fun_loop_call_mix(a, b);
    }
    return ret + fun_add(a, b);
}

// [VMP_DEMO_CASE] fun_cpp_make_string
// - 覆盖点：覆盖 C++ 对象与容器路径，验证加固后 C++ ABI 相关调用与返回。
// - 实现思路：通过字符串、向量、虚调度构造结果，避免仅算术路径通过回归。
extern "C" std::string fun_cpp_make_string(int a, int b) {
    std::string ret = "A";
    ret += std::to_string(a);
    ret.push_back(':');
    ret += std::to_string(b);
    return ret;
}

// [VMP_DEMO_CASE] fun_cpp_string_len
// - 覆盖点：覆盖 C++ 对象与容器路径，验证加固后 C++ ABI 相关调用与返回。
// - 实现思路：通过字符串、向量、虚调度构造结果，避免仅算术路径通过回归。
extern "C" int fun_cpp_string_len(int a, int b) {
    std::string value = fun_cpp_make_string(a, b);
    return static_cast<int>(value.size());
}

// [VMP_DEMO_CASE] fun_cpp_vector_sum
// - 覆盖点：覆盖 C++ 对象与容器路径，验证加固后 C++ ABI 相关调用与返回。
// - 实现思路：通过字符串、向量、虚调度构造结果，避免仅算术路径通过回归。
extern "C" int fun_cpp_vector_sum(int a, int b) {
    std::vector<int> values;
    values.push_back(a);
    values.push_back(b);
    values.push_back(a + b);
    values.push_back(a * 2 - b);
    return std::accumulate(values.begin(), values.end(), 0);
}

class CalcBase {
public:
    virtual ~CalcBase() = default;
    virtual int run(int a, int b) const = 0;
};

class CalcAdd final : public CalcBase {
public:
    int run(int a, int b) const override {
        return a + b;
    }
};

class CalcMix final : public CalcBase {
public:
    int run(int a, int b) const override {
        return a * b + a - b;
    }
};

// [VMP_DEMO_CASE] fun_cpp_virtual_mix
// - 覆盖点：覆盖 C++ 对象与容器路径，验证加固后 C++ ABI 相关调用与返回。
// - 实现思路：通过字符串、向量、虚调度构造结果，避免仅算术路径通过回归。
extern "C" int fun_cpp_virtual_mix(int a, int b) {
    CalcAdd add;
    CalcMix mix;
    const CalcBase* calc = (a & 1) != 0 ? static_cast<const CalcBase*>(&add)
                                         : static_cast<const CalcBase*>(&mix);
    return calc->run(a, b);
}

// [VMP_DEMO_CASE] fun_div_mod_chain
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_div_mod_chain(int a, int b) {
    const int lhs = a * b + 17;
    const int qBase = a + 1;
    int q = 0;
    int qRemain = lhs;
    while (qRemain >= qBase) {
        qRemain -= qBase;
        q += 1;
    }
    const int rBase = b + 1;
    int r = lhs;
    while (r >= rBase) {
        r -= rBase;
    }
    return q * 10 + r;
}

// [VMP_DEMO_CASE] fun_shift_mix
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
extern "C" int fun_shift_mix(int a, int b) {
    const int leftSeed = a + 5;
    int left = 0;
    for (int i = 0; i < 8; i++) {
        left += leftSeed;
    }
    int rightSeed = b + 3;
    int right = 0;
    while (rightSeed > 1) {
        rightSeed -= 2;
        right += 1;
    }
    const int mixed = left + right + ((a + 5) & (b + 3));
    return mixed;
}

// [VMP_DEMO_CASE] fun_do_while_path
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_do_while_path(int a, int b) {
    const int base = a + b;
    int acc = 0;
    int i = 0;
    do {
        acc += (base - i);
        if ((acc & 1) == 0) {
            acc += 2;
        } else {
            acc -= 1;
        }
        i += 1;
    } while (i < 4);
    return acc;
}

// [VMP_DEMO_CASE] fun_nested_continue_break
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
extern "C" int fun_nested_continue_break(int a, int b) {
    int acc = 0;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (((i + j) & 1) == 0) {
                continue;
            }
            acc += i * 3 + j + a;
            if (acc > b * 10) {
                break;
            }
        }
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_indirect_call_mix
// - 覆盖点：覆盖 helper 间接调用与条件分派混合场景，避免仅直连调用路径被验证。
// - 实现思路：先计算基础值，再按 index 奇偶切换 helper，最后叠加统一混合项。
extern "C" int fun_indirect_call_mix(int a, int b) {
    const int index = a + b;
    const int value0 = fun_add(a, b);
    int value1 = 0;
    if ((index & 1) == 0) {
        value1 = helper_abs_diff(a + 1, b - 1);
    } else {
        value1 = helper_mul_add(a + 1, b - 1);
    }
    const int value2 = helper_mul_add(a, b);
    return value0 + value1 + value2;
}

// [VMP_DEMO_CASE] fun_unsigned_compare_fold
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
extern "C" int fun_unsigned_compare_fold(int a, int b) {
    const uint32_t ua = static_cast<uint32_t>(a * 11 + 1);
    const uint32_t ub = static_cast<uint32_t>(b * 7 + 2);
    const uint32_t hi = (ua > ub) ? ua : ub;
    const uint32_t lo = (ua < ub) ? ua : ub;
    return static_cast<int>(hi - lo + (hi & 3u));
}

// [VMP_DEMO_CASE] fun_local_array_walk
// - 覆盖点：覆盖数组与指针步进访问，检验地址计算与别名访问语义。
// - 实现思路：通过多元素遍历与索引权重折叠结果，让内存路径更容易暴露偏差。
extern "C" int fun_local_array_walk(int a, int b) {
    int values[6] = {a, b, a + b, a - b, a * 2, b * 3};
    int acc = 0;
    for (int i = 0; i < 6; i++) {
        int value = values[i];
        if (value < 0) {
            value = -value;
        }
        acc += value + i;
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_switch_fallthrough
// - 覆盖点：覆盖 switch 分发与多分支汇合路径，检验 case 命中与落地语义。
// - 实现思路：先按 key 进入不同分支，再叠加循环或后处理，放大路径差异。
extern "C" int fun_switch_fallthrough(int a, int b) {
    const int key = (a << 2) + b;
    int acc = 1;
    switch (key) {
        case 6:
            acc += 3;
            [[fallthrough]];
        case 12:
            acc *= 5;
            break;
        case 15:
            acc -= 4;
            break;
        default:
            acc += 7;
            break;
    }
    int third = 0;
    int remain = key;
    while (remain >= 3) {
        remain -= 3;
        third += 1;
    }
    return acc + third;
}

// [VMP_DEMO_CASE] fun_short_circuit_logic
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
extern "C" int fun_short_circuit_logic(int a, int b) {
    int guard = 0;
    if (a > 0 && (++guard > 0)) {
        guard += 2;
    }
    if (b < 0 || (++guard > 0)) {
        guard += 3;
    }
    return guard + a + b;
}

// [VMP_DEMO_CASE] fun_select_mix
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
extern "C" int fun_select_mix(int a, int b) {
    const int x = (a > b) ? (a * 3) : (b * 2);
    const int y = (((a + b) & 1) != 0) ? (x + 5) : (x - 3);
    return y + ((a != 0 && b != 0) ? 7 : -7);
}

// [VMP_DEMO_CASE] fun_global_data_mix
// - 覆盖点：覆盖全局与静态状态访问，验证符号和数据段读写语义。
// - 实现思路：组合全局表、全局结构和静态成员结果，形成稳定可回归输出。
DEMO_TEST_EXPORT int fun_global_data_mix(int a, int b) {
    const int part0 = static_cast<int>(g_global_table[0]) + a + a;
    const int part1 = static_cast<int>(g_global_table[2]) + static_cast<int>(g_global_table[1]);
    return part0 + part1 + b + g_global_bias;
}

// [VMP_DEMO_CASE] fun_static_local_table
// - 覆盖点：覆盖全局与静态状态访问，验证符号和数据段读写语义。
// - 实现思路：组合全局表、全局结构和静态成员结果，形成稳定可回归输出。
DEMO_TEST_EXPORT int fun_static_local_table(int a, int b) {
    static const int kWeights[4] = {1, 3, 5, 7};
    int idx = a + b;
    while (idx >= 4) {
        idx -= 4;
    }
    if (idx < 0) {
        idx = 0;
    }

    int next = idx + 1;
    if (next >= 4) {
        next = 0;
    }

    const int tail = a + b + a;
    return kWeights[idx] + kWeights[next] + tail;
}

// [VMP_DEMO_CASE] fun_global_struct_acc
// - 覆盖点：覆盖全局与静态状态访问，验证符号和数据段读写语义。
// - 实现思路：组合全局表、全局结构和静态成员结果，形成稳定可回归输出。
DEMO_TEST_EXPORT int fun_global_struct_acc(int a, int b) {
    const int seed = g_global_pair.left + g_global_pair.right + a + b + a;
    const int selector = (a > b) ? 3 : 4;
    const int adjust = static_cast<int>(g_global_table[selector]);
    return seed - adjust + g_global_bias;
}

// [VMP_DEMO_CASE] fun_class_static_member
// - 覆盖点：覆盖全局与静态状态访问，验证符号和数据段读写语义。
// - 实现思路：组合全局表、全局结构和静态成员结果，形成稳定可回归输出。
DEMO_TEST_EXPORT int fun_class_static_member(int a, int b) {
    const int first = StaticScaleBox::eval(a, b);
    return first - StaticScaleBox::s_scale + g_global_bias;
}

// [VMP_DEMO_CASE] fun_multi_branch_path
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
DEMO_TEST_EXPORT int fun_multi_branch_path(int a, int b) {
    int x = a + b + a;
    int ret = 0;
    if (x < 5) {
        ret = x + 10;
    } else if (x < 9) {
        ret = x + 2;
    } else if (x < 14) {
        ret = x - 3;
    } else {
        ret = x - 8;
    }

    if (a > b) {
        ret += 4;
    } else if (a == b) {
        ret += 1;
    } else {
        ret -= 2;
    }
    return ret;
}

// [VMP_DEMO_CASE] fun_switch_dispatch
// - 覆盖点：覆盖 switch 分发与多分支汇合路径，检验 case 命中与落地语义。
// - 实现思路：先按 key 进入不同分支，再叠加循环或后处理，放大路径差异。
DEMO_TEST_EXPORT int fun_switch_dispatch(int a, int b) {
    int key = a + b;
    switch (key) {
        case 3:
            return a + b + 1;
        case 5:
            return a + a + b;
        case 6:
            return a + b + b;
        default:
            if (key > 8) {
                return key - 2;
            }
            return key + 2;
    }
}

// [VMP_DEMO_CASE] fun_bitmask_branch
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
DEMO_TEST_EXPORT int fun_bitmask_branch(int a, int b) {
    int mixed = (a & 7) | (b & 3);
    if ((mixed & 1) != 0) {
        return mixed + a;
    }
    if (mixed > 4) {
        return mixed + b;
    }
    return mixed - b;
}

// [VMP_DEMO_CASE] fun_global_table_rw
// - 覆盖点：覆盖全局数组写入后再读取的顺序语义，验证数据依赖不被破坏。
// - 实现思路：先改写两个槽位，再组合读取结果并叠加输入生成最终值。
DEMO_TEST_EXPORT int fun_global_table_rw(int a, int b) {
    g_global_table[2] = static_cast<uint32_t>(a + b + 30);
    g_global_table[3] = static_cast<uint32_t>(a + 40);
    const int merged = static_cast<int>(g_global_table[2] + g_global_table[3]);
    return merged - b;
}

// [VMP_DEMO_CASE] fun_global_mutable_state
// - 覆盖点：显式读写全局可变状态，检验加固后全局区访问与写回语义。
// - 实现思路：先更新 bias 和表项，再把全局结果折叠为返回值，便于回归断言。
DEMO_TEST_EXPORT int fun_global_mutable_state(int a, int b) {
    g_global_bias = a + b + 3;
    g_global_table[0] = static_cast<uint32_t>(a + 10);
    g_global_table[1] = static_cast<uint32_t>(b + 20);
    const int merged = static_cast<int>(g_global_table[0] + g_global_table[1]);
    return merged + g_global_bias;
}

// [VMP_DEMO_CASE] fun_flag_merge_cbz
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
DEMO_TEST_EXPORT int fun_flag_merge_cbz(int a, int b) {
    const int base = a + b;
    int acc = 0;
    for (int i = 0; i < 4; i++) {
        const int value = base - i * 2;
        if (value == 0) {
            acc += 9;
        } else if (value != 0 && ((value & 1) == 0)) {
            acc += value;
        } else {
            acc -= 3;
        }
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_ptr_stride_sum
// - 覆盖点：覆盖数组与指针步进访问，检验地址计算与别名访问语义。
// - 实现思路：通过多元素遍历与索引权重折叠结果，让内存路径更容易暴露偏差。
DEMO_TEST_EXPORT int fun_ptr_stride_sum(int a, int b) {
    int values[6] = {a, b, a + b, a - b, a * 2, b * 2};
    int* ptr = values;
    int sum = 0;
    for (int i = 0; i < 6; i++) {
        sum += ptr[i] * (i + 1);
    }
    return sum - ptr[3];
}

// [VMP_DEMO_CASE] fun_fn_table_dispatch
// - 覆盖点：通过函数指针表覆盖间接跳转路径，验证分发表在翻译后仍可正确命中。
// - 实现思路：用可控索引选择两次路由函数并合并结果，形成稳定可比对的输出。
DEMO_TEST_EXPORT int fun_fn_table_dispatch(int a, int b) {
    using RouteFn = int (*)(int, int);
    RouteFn table[3] = {helper_route0, helper_route1, helper_route2};

    int index = a + b + a;
    while (index >= 3) {
        index -= 3;
    }

    int nextIndex = index + 1;
    if (nextIndex >= 3) {
        nextIndex = 0;
    }

    const int first = table[index](a + 1, b);
    const int second = table[nextIndex](a, b + 1);
    return first + second;
}

// [VMP_DEMO_CASE] fun_clamp_window
// - 覆盖点：覆盖算术与循环主路径，作为回归基线验证加固前后结果一致性。
// - 实现思路：使用确定性输入与固定迭代流程，确保出现偏差时可快速复现定位。
DEMO_TEST_EXPORT int fun_clamp_window(int a, int b) {
    int values[5] = {a - 6, b - 1, a + b + 3, a * 4, b * 3 - 2};
    int sum = 0;
    for (int i = 0; i < 5; i++) {
        int value = values[i];
        if (value < 0) {
            value = 0;
        }
        if (value > 9) {
            value = 9;
        }
        sum += value;
    }
    return sum;
}

// [VMP_DEMO_CASE] fun_ret_i64_mix
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT long long fun_ret_i64_mix(int a, int b) {
    long long acc = 0;
    for (int i = 0; i < 8; i++) {
        acc += static_cast<long long>(a + b + i);
    }
    long long delta = 0;
    int loop = b + 2;
    while (loop > 0) {
        delta += 13LL;
        loop -= 1;
    }
    return acc + 100000LL - delta;
}

// [VMP_DEMO_CASE] fun_ret_u64_mix
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT unsigned long long fun_ret_u64_mix(int a, int b) {
    unsigned long long value =
        (static_cast<unsigned long long>(static_cast<uint32_t>(a)) << 32) |
        static_cast<unsigned long long>(static_cast<uint32_t>(b));
    unsigned long long step = 17ULL;
    for (int i = 0; i < 4; i++) {
        value += step;
        step += 17ULL;
    }
    value += 0x11111111ULL;
    return value;
}

// [VMP_DEMO_CASE] fun_ret_bool_gate
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT bool fun_ret_bool_gate(int a, int b) {
    const int left = a * 3 - b;
    const int right = b * 2 - a;
    return (left < right) && ((left + right) != 0);
}

// [VMP_DEMO_CASE] fun_ret_i16_pack
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT short fun_ret_i16_pack(int a, int b) {
    int acc = a;
    for (int i = 0; i < 5; i++) {
        acc += a;
    }
    for (int i = 0; i < 4; i++) {
        acc += b;
    }
    acc += 7;
    return static_cast<short>(acc);
}

// [VMP_DEMO_CASE] fun_switch_loop_acc
// - 覆盖点：覆盖 switch 分发与多分支汇合路径，检验 case 命中与落地语义。
// - 实现思路：先按 key 进入不同分支，再叠加循环或后处理，放大路径差异。
DEMO_TEST_EXPORT int fun_switch_loop_acc(int a, int b) {
    const int seed = a + b;
    int acc = 0;
    for (int i = 0; i < 6; i++) {
        int key = seed + i;
        while (key >= 4) {
            key -= 4;
        }
        switch (key) {
            case 0:
                acc += a + i;
                break;
            case 1: {
                int branch = i;
                branch += i;
                acc += b + branch;
                break;
            }
            case 2:
                acc += a + b + i;
                break;
            default:
                acc -= i;
                break;
        }
        if (acc > 80) {
            acc -= 13;
        }
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_struct_alias_walk
// - 覆盖点：覆盖数组与指针步进访问，检验地址计算与别名访问语义。
// - 实现思路：通过多元素遍历与索引权重折叠结果，让内存路径更容易暴露偏差。
DEMO_TEST_EXPORT int fun_struct_alias_walk(int a, int b) {
    struct LocalPair {
        int left;
        int right;
    };

    LocalPair pairs[3] = {
        {a, b},
        {a + b, a - b},
        {b + 3, a + 5},
    };

    LocalPair* mid = &pairs[1];
    mid->left += 2;
    mid->right -= 1;

    int acc = 0;
    for (int i = 0; i < 3; i++) {
        const LocalPair* current = &pairs[i];
        int doubled = current->left;
        doubled += current->left;
        int mixed = doubled + current->right;
        if (mixed < 0) {
            mixed = -mixed;
        }
        acc += mixed + i;
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_unsigned_edge_paths
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
DEMO_TEST_EXPORT int fun_unsigned_edge_paths(int a, int b) {
    const uint32_t ua = static_cast<uint32_t>(a + 15);
    const uint32_t ub = static_cast<uint32_t>(b + 9);
    uint32_t acc = 0;
    uint32_t step = ua;
    for (int i = 0; i < 5; i++) {
        if (step >= ub) {
            acc += step - ub;
        } else {
            acc += ub - step + 1u;
        }
        if ((acc & 1u) == 0u) {
            acc += 2u;
        } else {
            acc += 1u;
        }
        step += 3u;
    }
    return static_cast<int>(acc);
}

// [VMP_DEMO_CASE] fun_reverse_ptr_mix
// - 覆盖点：覆盖数组与指针步进访问，检验地址计算与别名访问语义。
// - 实现思路：通过多元素遍历与索引权重折叠结果，让内存路径更容易暴露偏差。
DEMO_TEST_EXPORT int fun_reverse_ptr_mix(int a, int b) {
    int values[7] = {
        a,
        b,
        a + b,
        a + b + b,
        b + a + a,
        b - a,
        a + b + a,
    };

    int* cursor = &values[6];
    int acc = 0;
    for (int i = 0; i < 7; i++) {
        int value = *cursor;
        if (value < 0) {
            value = -value;
        }
        acc += value + i;
        cursor -= 1;
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_guarded_chain_mix
// - 覆盖点：覆盖条件分支与标志位驱动路径，检验分支选择与短路语义。
// - 实现思路：设计互斥分支并在汇合点统一折叠输出，方便对照实现定位差异。
DEMO_TEST_EXPORT int fun_guarded_chain_mix(int a, int b) {
    const int x = a + b;
    const int y = a - b;
    int acc = 0;
    for (int i = 0; i < 5; i++) {
        const int token = x + i;
        if ((token & 1) == 0) {
            acc += token;
            if (token > 6) {
                acc -= 2;
            }
        } else {
            const int t = y + i;
            if (t < 0) {
                acc += -t;
            } else {
                acc += t + 1;
            }
        }
        if (acc > 40) {
            break;
        }
    }
    return acc + y;
}

// [VMP_DEMO_CASE] fun_ret_i64_steps
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT long long fun_ret_i64_steps(int a, int b) {
    long long acc = 50000LL;
    long long step = static_cast<long long>(a + b);
    for (int i = 0; i < 6; i++) {
        acc += step;
        step += 3LL;
    }
    int loop = b + 1;
    while (loop > 0) {
        acc -= 7LL;
        loop -= 1;
    }
    if (acc < 0) {
        acc = -acc;
    }
    return acc;
}

// [VMP_DEMO_CASE] fun_ret_u64_acc
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT unsigned long long fun_ret_u64_acc(int a, int b) {
    unsigned long long acc = static_cast<unsigned long long>(static_cast<uint32_t>(a + 1));
    acc <<= 40;
    unsigned long long tail = static_cast<unsigned long long>(static_cast<uint32_t>(b + 2));
    tail <<= 20;
    acc += tail;

    unsigned long long step = 1000ULL;
    for (int i = 0; i < 5; i++) {
        acc += step;
        step += 1000ULL;
    }
    acc += 77ULL;
    return acc;
}

// [VMP_DEMO_CASE] fun_ret_bool_mix2
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT bool fun_ret_bool_mix2(int a, int b) {
    const int left = a + b + b;
    const int right = a + a + a + b;
    const bool cond0 = left > right;
    const bool cond1 = (left - right) != 0;
    const bool cond2 = (a + b) > 0;
    return (cond0 || cond1) && cond2;
}

// [VMP_DEMO_CASE] fun_ret_u16_blend
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT unsigned short fun_ret_u16_blend(int a, int b) {
    unsigned int acc = static_cast<unsigned int>(a + 20);
    for (int i = 0; i < 4; i++) {
        unsigned int delta = static_cast<unsigned int>(b + i);
        delta += static_cast<unsigned int>(i);
        acc += delta;
    }
    unsigned int twice = acc;
    twice += acc;
    acc += twice;
    acc += 5u;
    while (acc >= 65535u) {
        acc -= 65535u;
    }
    return static_cast<unsigned short>(acc);
}

// [VMP_DEMO_CASE] fun_ret_i8_wave
// - 覆盖点：覆盖非 int 返回 ABI（宽整数、布尔、窄整数）的寄存器传递语义。
// - 实现思路：以 a/b 组合构造分段计算与边界处理，确保 expected/actual 易于比对。
DEMO_TEST_EXPORT signed char fun_ret_i8_wave(int a, int b) {
    int acc = a - b;
    for (int i = 0; i < 6; i++) {
        if ((i & 1) == 0) {
            acc += a + i;
        } else {
            acc -= (b - i);
        }
    }
    if (acc > 63) {
        acc = 63;
    }
    if (acc < -64) {
        acc = -64;
    }
    return static_cast<signed char>(acc);
}

// [VMP_DEMO_CASE] fun_ext_insn_mix
// - 覆盖点：覆盖扩展类指令（sxt/uxt）翻译路径，并保留非 AArch64 回退逻辑。
// - 实现思路：AArch64 走内联汇编显式触发目标指令，其他平台走等价 C++ 语义。
DEMO_TEST_EXPORT int fun_ext_insn_mix(int a, int b) {
#if defined(__aarch64__)
    int out = 0;
    // 显式使用扩展类指令，确保翻译器路径可回归验证。
    asm volatile(
        "sxtb w9, %w[inA]\n"
        "sxth w10, %w[inB]\n"
        "uxtb w11, %w[inA]\n"
        "uxth w12, %w[inB]\n"
        "uxtw x13, %w[inB]\n"
        "adds w9, w9, w11\n"
        "add w10, w10, w12\n"
        "add x13, x13, x13\n"
        "add %w[out], w9, w10\n"
        "add %w[out], %w[out], w13\n"
        : [out] "=&r"(out)
        : [inA] "r"(a), [inB] "r"(b)
        : "x9", "x10", "x11", "x12", "x13", "cc");
    return out;
#else
    int s0 = static_cast<int>(static_cast<signed char>(a));
    int s1 = static_cast<int>(static_cast<short>(b));
    int u0 = static_cast<int>(static_cast<unsigned char>(a));
    int u1 = static_cast<int>(static_cast<unsigned short>(b));
    unsigned long long u2 = static_cast<unsigned long long>(static_cast<uint32_t>(b));
    return (s0 + u0) + (s1 + u1) + static_cast<int>(u2 + u2);
#endif
}

// [VMP_DEMO_CASE] fun_bfm_nonwrap
// - 覆盖点：覆盖 ubfm/sbfm 非环绕位域提取语义，验证 immr<=imms 的翻译行为。
// - 实现思路：AArch64 使用显式指令路径，非 AArch64 用移位与符号扩展模拟。
DEMO_TEST_EXPORT int fun_bfm_nonwrap(int a, int b) {
#if defined(__aarch64__)
    int out = 0;
    // 显式使用 ubfm/sbfm（non-wrap）路径，验证位域提取翻译覆盖。
    asm volatile(
        "mov w9, %w[inA]\n"
        "mov w10, %w[inB]\n"
        "lsl w9, w9, #8\n"
        "add w9, w9, w10\n"
        "ubfm x11, x9, #8, #15\n"
        "sbfm x12, x9, #0, #7\n"
        "add w11, w11, w12\n"
        "add %w[out], w11, #5\n"
        : [out] "=&r"(out)
        : [inA] "r"(a), [inB] "r"(b)
        : "x9", "x10", "x11", "x12", "cc");
    return out;
#else
    int x = ((a & 0xFF) << 8) | (b & 0xFF);
    int u = (x >> 8) & 0xFF;
    int s = static_cast<int>(static_cast<signed char>(x & 0xFF));
    return u + s + 5;
#endif
}

// [VMP_DEMO_CASE] fun_bfm_wrap
// - 覆盖点：覆盖 ubfm/sbfm 环绕位域语义，验证 immr>imms 时的边界行为。
// - 实现思路：构造带高位种子的输入并做指令与等价 C++ 双路径对照。
DEMO_TEST_EXPORT int fun_bfm_wrap(int a, int b) {
#if defined(__aarch64__)
    uint32_t seed = 0xF0000000u |
                    ((static_cast<uint32_t>(a) & 0xFFu) << 8u) |
                    (static_cast<uint32_t>(b) & 0xFFu);
    int out = 0;
    // 显式使用 ubfm/sbfm（wrap）路径，验证 immr > imms 的位域语义。
    asm volatile(
        "mov w9, %w[inSeed]\n"
        "ubfm w10, w9, #28, #3\n"
        "sbfm w11, w9, #28, #3\n"
        "add w10, w10, w11\n"
        "add %w[out], w10, %w[inA]\n"
        : [out] "=&r"(out)
        : [inSeed] "r"(seed), [inA] "r"(a)
        : "x9", "x10", "x11", "cc");
    return out;
#else
    uint32_t seed = 0xF0000000u |
                    ((static_cast<uint32_t>(a) & 0xFFu) << 8u) |
                    (static_cast<uint32_t>(b) & 0xFFu);
    uint32_t u = (seed & 0xFu) << 4u;
    int sLow = static_cast<int>(seed & 0xFu);
    if ((sLow & 0x8) != 0) {
        sLow |= ~0xF;
    }
    int s = sLow << 4;
    return static_cast<int>(u) + s + a;
#endif
}

// [VMP_DEMO_CASE] fun_csinc_path
// - 覆盖点：覆盖条件选择并自增（csinc）路径，检验条件码驱动的结果选择。
// - 实现思路：AArch64 直接触发 csinc，回退路径用等价三元表达式保持一致语义。
DEMO_TEST_EXPORT int fun_csinc_path(int a, int b) {
#if defined(__aarch64__)
    int out = 0;
    // 显式使用 csinc，验证条件选择 + 自增翻译路径。
    asm volatile(
        "cmp %w[inA], %w[inB]\n"
        "csinc w9, %w[inA], %w[inB], gt\n"
        "add %w[out], w9, #3\n"
        : [out] "=&r"(out)
        : [inA] "r"(a), [inB] "r"(b)
        : "x9", "cc");
    return out;
#else
    return (a > b) ? (a + 3) : (b + 4);
#endif
}

// [VMP_DEMO_CASE] fun_madd_msub_div
// - 覆盖点：集中覆盖 madd/msub/udiv/sdiv 的组合翻译，验证整数算术主干指令。
// - 实现思路：先准备有符号和无符号分母分子，再按同序列折叠结果降低误判。
DEMO_TEST_EXPORT int fun_madd_msub_div(int a, int b) {
    const int lhs = a + 37;
    const int rhs = b + 11;
    const uint32_t uNumer = static_cast<uint32_t>(lhs + 500);
    const uint32_t uDenom = static_cast<uint32_t>((rhs & 31) + 3);
    const int sNumer = lhs - rhs - 55;
    int sDenom = rhs;
    if (sDenom == 0) {
        sDenom = 1;
    }
#if defined(__aarch64__)
    int out = 0;
    // 显式使用 madd/msub/udiv/sdiv，覆盖常见整数乘加与除法翻译路径。
    asm volatile(
        "mov w9, %w[inLhs]\n"
        "mov w10, %w[inRhs]\n"
        "madd w11, w9, w10, w9\n"
        "msub w12, w10, w9, w11\n"
        "mov w13, %w[inUNumer]\n"
        "mov w14, %w[inUDenom]\n"
        "udiv w15, w13, w14\n"
        "mov w16, %w[inSNumer]\n"
        "mov w17, %w[inSDenom]\n"
        "sdiv w6, w16, w17\n"
        "add w11, w11, w12\n"
        "add w11, w11, w15\n"
        "add %w[out], w11, w6\n"
        : [out] "=&r"(out)
        : [inLhs] "r"(lhs),
          [inRhs] "r"(rhs),
          [inUNumer] "r"(uNumer),
          [inUDenom] "r"(uDenom),
          [inSNumer] "r"(sNumer),
          [inSDenom] "r"(sDenom)
        : "x6", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "cc");
    return out;
#else
    const int maddValue = lhs * rhs + lhs;
    const int msubValue = maddValue - rhs * lhs;
    const uint32_t udivValue = uNumer / uDenom;
    const int sdivValue = sNumer / sDenom;
    return maddValue + msubValue + static_cast<int>(udivValue) + sdivValue;
#endif
}

// [VMP_DEMO_CASE] fun_orn_bic_extr
// - 覆盖点：覆盖 orn/bic/extr 的位运算与跨寄存器拼接提取路径。
// - 实现思路：AArch64 使用指令直测，回退实现用按位运算和 64 位拼接对齐语义。
DEMO_TEST_EXPORT int fun_orn_bic_extr(int a, int b) {
    const uint32_t lhs = static_cast<uint32_t>(a * 13 + 0x1234);
    const uint32_t rhs = static_cast<uint32_t>(b * 7 + 0x00AB00CD);
#if defined(__aarch64__)
    uint32_t out = 0;
    // 显式使用 orn/bic/extr，覆盖位运算与拼接提取翻译路径。
    asm volatile(
        "mov w9, %w[inLhs]\n"
        "mov w10, %w[inRhs]\n"
        "orn w11, w9, w10\n"
        "bic w12, w9, w10\n"
        "extr w13, w9, w10, #5\n"
        "add w11, w11, w12\n"
        "add %w[out], w11, w13\n"
        : [out] "=&r"(out)
        : [inLhs] "r"(lhs), [inRhs] "r"(rhs)
        : "x9", "x10", "x11", "x12", "x13", "cc");
    return static_cast<int>(out);
#else
    const uint32_t ornValue = lhs | (~rhs);
    const uint32_t bicValue = lhs & (~rhs);
    const uint64_t pair = (static_cast<uint64_t>(lhs) << 32u) | static_cast<uint64_t>(rhs);
    const uint32_t extrValue = static_cast<uint32_t>((pair >> 5u) & 0xFFFFFFFFull);
    return static_cast<int>(ornValue + bicValue + extrValue);
#endif
}

// [VMP_DEMO_CASE] fun_mem_half_signed
// - 覆盖点：覆盖半字节存取与有符号加载路径，检验内存访问翻译细节。
// - 实现思路：AArch64 走 sturh/ldurh/ldrsb/ldrsh，回退路径用对应类型转换模拟。
DEMO_TEST_EXPORT int fun_mem_half_signed(int a, int b) {
    const uint16_t rawHalf = static_cast<uint16_t>(a * 19 + b * 3 + 0x2345);
    const uint8_t rawByte = static_cast<uint8_t>(a - b * 5 - 33);
    const uint16_t rawSignHalf = static_cast<uint16_t>(b * 23 - a * 7 - 77);
#if defined(__aarch64__)
    uint16_t slotHalf = 0;
    uint8_t slotByte = 0;
    uint16_t slotSignHalf = 0;
    int out = 0;
    // 显式使用 sturh/ldurh/ldrsb/ldrsh，覆盖非扩展寻址和有符号读取路径。
    asm volatile(
        "mov x9, %[halfPtr]\n"
        "mov w10, %w[inHalf]\n"
        "sturh w10, [x9, #0]\n"
        "ldurh w11, [x9, #0]\n"
        "mov x12, %[bytePtr]\n"
        "mov w13, %w[inByte]\n"
        "strb w13, [x12, #0]\n"
        "ldrsb w14, [x12, #0]\n"
        "mov x15, %[signHalfPtr]\n"
        "mov w16, %w[inSignHalf]\n"
        "strh w16, [x15, #0]\n"
        "ldrsh w17, [x15, #0]\n"
        "add w11, w11, w14\n"
        "add %w[out], w11, w17\n"
        : [out] "=&r"(out)
        : [halfPtr] "r"(&slotHalf),
          [bytePtr] "r"(&slotByte),
          [signHalfPtr] "r"(&slotSignHalf),
          [inHalf] "r"(static_cast<uint32_t>(rawHalf)),
          [inByte] "r"(static_cast<uint32_t>(rawByte)),
          [inSignHalf] "r"(static_cast<uint32_t>(rawSignHalf))
        : "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory", "cc");
    return out;
#else
    const uint16_t loadedHalf = rawHalf;
    const int8_t loadedByte = static_cast<int8_t>(rawByte);
    const int16_t loadedSignHalf = static_cast<int16_t>(rawSignHalf);
    return static_cast<int>(loadedHalf) + static_cast<int>(loadedByte) + static_cast<int>(loadedSignHalf);
#endif
}

// [VMP_DEMO_CASE] fun_atomic_u8_order
// - 覆盖点：覆盖 8 位原子 release/acquire 读写顺序，校验内存序语义。
// - 实现思路：两轮 store/load 串联并折叠返回，确保顺序和可见性都被回归覆盖。
DEMO_TEST_EXPORT int fun_atomic_u8_order(int a, int b) {
    uint8_t seed = static_cast<uint8_t>((a * 17 + b * 3 + 0x21) & 0xFF);
    __atomic_store_n(&g_atomic_slot_u8, seed, __ATOMIC_RELEASE);
    uint8_t first = __atomic_load_n(&g_atomic_slot_u8, __ATOMIC_ACQUIRE);

    uint8_t next = static_cast<uint8_t>(first ^ static_cast<uint8_t>(b + 0x13));
    __atomic_store_n(&g_atomic_slot_u8, next, __ATOMIC_RELEASE);
    uint8_t second = __atomic_load_n(&g_atomic_slot_u8, __ATOMIC_ACQUIRE);

    return static_cast<int>(first) + static_cast<int>(second);
}

// [VMP_DEMO_CASE] fun_atomic_u16_order
// - 覆盖点：覆盖 16 位原子 release/acquire 读写顺序，补齐窄整数场景。
// - 实现思路：先写入种子再做增量写回，通过异或结果放大顺序偏差。
DEMO_TEST_EXPORT int fun_atomic_u16_order(int a, int b) {
    uint16_t seed = static_cast<uint16_t>((a * 257 + b * 17 + 0x1357) & 0xFFFF);
    __atomic_store_n(&g_atomic_slot_u16, seed, __ATOMIC_RELEASE);
    uint16_t first = __atomic_load_n(&g_atomic_slot_u16, __ATOMIC_ACQUIRE);

    uint16_t next = static_cast<uint16_t>(first + static_cast<uint16_t>(a + b + 0x33));
    __atomic_store_n(&g_atomic_slot_u16, next, __ATOMIC_RELEASE);
    uint16_t second = __atomic_load_n(&g_atomic_slot_u16, __ATOMIC_ACQUIRE);

    return static_cast<int>(first ^ second);
}

// [VMP_DEMO_CASE] fun_atomic_u64_order
// - 覆盖点：覆盖 64 位原子读写与高低位折叠，验证宽寄存器路径的稳定性。
// - 实现思路：构造宽位种子并二次写回，最后折叠高低 32 位生成可比较结果。
DEMO_TEST_EXPORT int fun_atomic_u64_order(int a, int b) {
    const uint64_t seedLeft = static_cast<uint64_t>((a + 1) * (b + 33));
    const uint64_t seedRight = static_cast<uint64_t>(a * 131 + b * 17 + 0x9D);
    const uint64_t seed = (seedLeft << 17) ^ seedRight;
    __atomic_store_n(&g_atomic_slot_u64, seed, __ATOMIC_RELEASE);
    uint64_t first = __atomic_load_n(&g_atomic_slot_u64, __ATOMIC_ACQUIRE);

    const uint64_t delta = 0x1020304050607080ull + static_cast<uint64_t>((a & 0xFF) << 8);
    const uint64_t next = first + delta;
    __atomic_store_n(&g_atomic_slot_u64, next, __ATOMIC_RELEASE);
    uint64_t second = __atomic_load_n(&g_atomic_slot_u64, __ATOMIC_ACQUIRE);

    const uint64_t folded = ((second >> 32) ^ (second & 0xFFFFFFFFull)) & 0x7FFFFFFFull;
    return static_cast<int>(folded);
}

// [VMP_DEMO_CASE] fun_insn_scalar_ctrl
// - 覆盖点：集中覆盖标量控制流/原子序列相关指令，补齐 adr/br/ldxr/stxr/svc 等翻译路径。
// - 实现思路：AArch64 显式发射目标指令；trap 指令放在 gate 分支中，保证回归执行稳定。
DEMO_TEST_EXPORT int fun_insn_scalar_ctrl(int a, int b) {
    const uint64_t seed0 =
        static_cast<uint64_t>(static_cast<uint32_t>(a * 17 + b + 0x100));
    const uint64_t seed1 =
        static_cast<uint64_t>(static_cast<uint32_t>(a * 3 + b * 7 + 0x200));
#if defined(__aarch64__)
    volatile uint64_t slot0 = seed0;
    volatile uint64_t slot1 = seed1;
    const int trapGate = g_trap_gate;
    uint64_t out64 = 0;
    asm volatile(
        "mov w9, %w[inA]\n"
        "mov w10, %w[inB]\n"
        "adr x11, 10f\n"
        "br x11\n"
        "nop\n"
        "10:\n"
        "add w12, w9, w10\n"
        "bics w13, w12, w10\n"
        "cmp w9, w10\n"
        "csinv w14, w9, w10, ge\n"
        "csneg x15, x9, x10, lt\n"
        "ccmp w14, w10, #0, ne\n"
        "clz w16, w13\n"
        "rev w17, w14\n"
        "rev16 x6, x15\n"
        "eon x7, x17, x6\n"
        "lsl x7, x7, x9\n"
        "lsr x7, x7, x10\n"
        "bfm x7, x7, #4, #11\n"
        "mov x14, %[slot0]\n"
        "ldxr x15, [x14]\n"
        "add x15, x15, #1\n"
        "stxr w6, x15, [x14]\n"
        "mov x16, %[slot1]\n"
        "ldaxr x17, [x16]\n"
        "add x17, x17, #2\n"
        "stlxr w8, x17, [x16]\n"
        "clrex\n"
        "smaddl x12, w9, w10, x15\n"
        "umaddl x13, w9, w10, x17\n"
        "smulh x14, x12, x13\n"
        "umulh x16, x13, x12\n"
        "hint #0\n"
        "cbz %w[trap], 11f\n"
        "svc #0\n"
        "brk #0\n"
        "11:\n"
        "add x12, x12, x13\n"
        "add x12, x12, x14\n"
        "add x12, x12, x16\n"
        "add x12, x12, x7\n"
        "add x12, x12, x6\n"
        "add %[out], x12, x8\n"
        : [out] "=&r"(out64)
        : [inA] "r"(a),
          [inB] "r"(b),
          [slot0] "r"(&slot0),
          [slot1] "r"(&slot1),
          [trap] "r"(trapGate)
        : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "cc", "memory");
    return static_cast<int>((out64 ^ (out64 >> 32u)) & 0x7FFFFFFFull);
#else
    uint64_t mix = seed0 + seed1;
    mix ^= ((mix << 3u) >> 1u);
    mix += static_cast<uint64_t>(static_cast<uint32_t>(a ^ b));
    return static_cast<int>((mix ^ (mix >> 32u)) & 0x7FFFFFFFull);
#endif
}

// [VMP_DEMO_CASE] fun_insn_simd_mix
// - 覆盖点：集中覆盖 SIMD 逻辑/比较/移位/窄化类指令，补齐 bit/bsl/ld4/shll 等翻译路径。
// - 实现思路：AArch64 使用向量内联汇编串联多条指令，回退路径保持确定性输出。
DEMO_TEST_EXPORT int fun_insn_simd_mix(int a, int b) {
    alignas(16) uint8_t lanes[64] = {};
    for (int i = 0; i < 64; i++) {
        lanes[i] = static_cast<uint8_t>((a * 13 + b * 7 + i * 3 + 0x21) & 0xFF);
    }
#if defined(__aarch64__)
    uint32_t out = 0;
    asm volatile(
        "mov x9, %[ptr]\n"
        "ld4 { v0.16b, v1.16b, v2.16b, v3.16b }, [x9]\n"
        "movi v4.16b, #0x39\n"
        "dup v5.4s, %w[inA]\n"
        "ins v5.s[1], %w[inB]\n"
        "cmeq v6.16b, v0.16b, v1.16b\n"
        "cmgt v7.4s, v2.4s, v3.4s\n"
        "cmhi v8.8h, v0.8h, v1.8h\n"
        "cmhs v9.8h, v1.8h, v0.8h\n"
        "cmlt v10.4s, v2.4s, #0\n"
        "bit v0.16b, v1.16b, v6.16b\n"
        "bsl v6.16b, v7.16b, v8.16b\n"
        "not v7.16b, v7.16b\n"
        "shl v11.8h, v0.8h, #1\n"
        "shll v12.8h, v0.8b, #8\n"
        "shll2 v13.8h, v0.16b, #8\n"
        "ushll v14.8h, v1.8b, #2\n"
        "ushll2 v15.8h, v1.16b, #2\n"
        "ushr v14.8h, v14.8h, #1\n"
        "shrn v16.8b, v14.8h, #1\n"
        "xtn v17.8b, v15.8h\n"
        "add v16.8b, v16.8b, v17.8b\n"
        "umov w10, v16.s[0]\n"
        "umov w11, v5.s[1]\n"
        "umov w12, v6.s[0]\n"
        "add w10, w10, w11\n"
        "add %w[out], w10, w12\n"
        : [out] "=&r"(out)
        : [ptr] "r"(lanes), [inA] "r"(a), [inB] "r"(b)
        : "x9", "x10", "x11", "x12", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "cc",
          "memory");
    return static_cast<int>(out);
#else
    uint32_t acc = 0;
    for (int i = 0; i < 64; i += 8) {
        acc ^= static_cast<uint32_t>(lanes[i]);
        acc += static_cast<uint32_t>(lanes[i + 1]);
        acc ^= static_cast<uint32_t>(lanes[i + 2] << 1u);
    }
    return static_cast<int>(acc + static_cast<uint32_t>(a ^ b));
#endif
}

// [VMP_DEMO_CASE] fun_insn_fp_convert
// - 覆盖点：集中覆盖浮点算术与转换类指令，补齐 scvtf/ucvtf/fcvt/fcvtzs/fcvtas 等路径。
// - 实现思路：AArch64 走显式浮点指令链；回退路径用浮点运算折叠出稳定整数结果。
DEMO_TEST_EXPORT int fun_insn_fp_convert(int a, int b) {
    const uint32_t bUnsigned = static_cast<uint32_t>(b < 0 ? -b + 7 : b + 7);
#if defined(__aarch64__)
    int out = 0;
    asm volatile(
        "scvtf s0, %w[inA]\n"
        "ucvtf s1, %w[inBU]\n"
        "fmov s7, %w[inA]\n"
        "fadd s2, s0, s1\n"
        "fneg s3, s0\n"
        "fmul s4, s2, s3\n"
        "fdiv s5, s4, s1\n"
        "fcmp s2, s5\n"
        "fcvt d6, s5\n"
        "fmov w9, s7\n"
        "fcvtzs w10, s5\n"
        "fcvtas w11, s5\n"
        "add w10, w10, w11\n"
        "add %w[out], w10, w9\n"
        : [out] "=&r"(out)
        : [inA] "r"(a), [inBU] "r"(bUnsigned)
        : "x9", "x10", "x11", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "cc");
    return out;
#else
    const float fa = static_cast<float>(a);
    const float fb = static_cast<float>(bUnsigned);
    const float mix = ((fa + fb) * (-fa)) / fb;
    const int towardZero = static_cast<int>(mix);
    const int nearest = static_cast<int>(mix >= 0.0f ? mix + 0.5f : mix - 0.5f);
    return towardZero + nearest + a;
#endif
}

// [VMP_DEMO_CASE] fun_ret_cstr_pick
// - 覆盖点：覆盖 const char* 返回 ABI 与线程局部缓存生命周期语义。
// - 实现思路：使用 thread_local 字符串缓存生成稳定 c_str，避免悬空指针。
DEMO_TEST_EXPORT const char* fun_ret_cstr_pick(int a, int b) {
    // 使用线程局部字符串，返回稳定的 c_str 指针（直到下一次同线程调用）。
    static thread_local std::string cache;
    static const char* kToken[4] = {"sun", "moon", "star", "sky"};

    int index = a * 3 + b + 11;
    while (index < 0) {
        index += 4;
    }
    while (index >= 4) {
        index -= 4;
    }

    int tail = a * 7 - b * 3 + index;
    cache = kToken[index];
    cache.push_back(':');
    cache += std::to_string(tail);
    return cache.c_str();
}

// [VMP_DEMO_CASE] fun_ret_std_string_mix
// - 覆盖点：覆盖 std::string 返回路径与字符串拼接场景。
// - 实现思路：组合数字、cstr 结果和奇偶标签，形成结构化且可读的输出。
DEMO_TEST_EXPORT std::string fun_ret_std_string_mix(int a, int b) {
    std::string out = "mix";
    out.push_back(':');
    out += std::to_string(a + b + 5);
    out.push_back('|');
    out += fun_ret_cstr_pick(a, b);
    out.push_back('|');
    if (((a + b) & 1) != 0) {
        out += "odd";
    } else {
        out += "even";
    }
    return out;
}

// [VMP_DEMO_CASE] fun_ret_vector_mix
// - 覆盖点：覆盖 std::vector 返回 ABI 与动态填充场景。
// - 实现思路：按索引奇偶构造序列并补充尾项，使桥接层可做摘要对比。
DEMO_TEST_EXPORT std::vector<int> fun_ret_vector_mix(int a, int b) {
    std::vector<int> values;
    values.reserve(6);

    int seed = a + b;
    for (int i = 0; i < 5; i++) {
        int value = seed + i;
        if ((i & 1) == 0) {
            value += (a - b);
        } else {
            value += (b - a);
        }
        values.push_back(value);
    }

    int tail = values[0] + values[2] - values[4] + a;
    values.push_back(tail);
    return values;
}
