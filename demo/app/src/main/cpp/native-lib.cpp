#include <jni.h>
#include <cstdint>
#include <string>
#include <vector>
#include <numeric>
#include <android/log.h>

#define DEMO_TEST_EXPORT extern "C" __attribute__((visibility("default"))) __attribute__((used)) __attribute__((noinline)) __attribute__((optnone))

namespace {

int g_global_bias = 7;
uint32_t g_global_table[5] = {3u, 2u, 11u, 5u, 9u};

struct GlobalPair {
    int left;
    int right;
};

GlobalPair g_global_pair = {4, 6};

class StaticScaleBox {
public:
    static int s_scale;

    static int eval(int a, int b) {
        s_scale = a + 2;
        return s_scale * b + 1;
    }
};

int StaticScaleBox::s_scale = 3;

} // namespace

extern "C" int fun_add(int a, int b) {
    return a + b;
}

extern "C" int fun_for(int a, int b) {
    int ret = 0;
    for (int i = 0; i < 5; i++) {
        ret += a;
        ret += b;
    }
    return ret;
}

extern "C" int fun_for_add(int a, int b) {
    int ret = 0;
    for (int i = 0; i < 5; i++) {
        ret += fun_add(a, b);
    }
    __android_log_print(6, "lxz", "fun_for_add ret: %d", ret);
    return ret;
}

extern "C" int fun_if_sub(int a, int b) {
    if (a > b) {
        return a - b;
    }
    return b - a;
}

extern "C" int fun_countdown_muladd(int a, int b) {
    int ret = 0;
    int n = a;
    while (n > 0) {
        ret += b;
        n -= 1;
    }
    return ret + a;
}

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

extern "C" int fun_call_chain(int a, int b) {
    int first = fun_for(a, b);
    int second = fun_add(a, b);
    int third = fun_if_sub(a, b);
    return first + second + third;
}

extern "C" int fun_branch_call(int a, int b) {
    int ret = 0;
    if (a >= b) {
        ret = fun_countdown_muladd(a, b);
    } else {
        ret = fun_loop_call_mix(a, b);
    }
    return ret + fun_add(a, b);
}

extern "C" std::string fun_cpp_make_string(int a, int b) {
    std::string ret = "A";
    ret += std::to_string(a);
    ret.push_back(':');
    ret += std::to_string(b);
    return ret;
}

extern "C" int fun_cpp_string_len(int a, int b) {
    std::string value = fun_cpp_make_string(a, b);
    return static_cast<int>(value.size());
}

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

extern "C" int fun_cpp_virtual_mix(int a, int b) {
    CalcAdd add;
    CalcMix mix;
    const CalcBase* calc = (a & 1) != 0 ? static_cast<const CalcBase*>(&add)
                                         : static_cast<const CalcBase*>(&mix);
    return calc->run(a, b);
}

DEMO_TEST_EXPORT int fun_global_data_mix(int a, int b) {
    const int part0 = static_cast<int>(g_global_table[0]) + a + a;
    const int part1 = static_cast<int>(g_global_table[2]) + static_cast<int>(g_global_table[1]);
    return part0 + part1 + b + g_global_bias;
}

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

DEMO_TEST_EXPORT int fun_global_struct_acc(int a, int b) {
    const int seed = g_global_pair.left + g_global_pair.right + a + b + a;
    const int selector = (a > b) ? 3 : 4;
    const int adjust = static_cast<int>(g_global_table[selector]);
    return seed - adjust + g_global_bias;
}

DEMO_TEST_EXPORT int fun_class_static_member(int a, int b) {
    const int first = StaticScaleBox::eval(a, b);
    return first - StaticScaleBox::s_scale + g_global_bias;
}

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

DEMO_TEST_EXPORT int fun_global_table_rw(int a, int b) {
    g_global_table[2] = static_cast<uint32_t>(a + b + 30);
    g_global_table[3] = static_cast<uint32_t>(a + 40);
    const int merged = static_cast<int>(g_global_table[2] + g_global_table[3]);
    return merged - b;
}

DEMO_TEST_EXPORT int fun_global_mutable_state(int a, int b) {
    g_global_bias = a + b + 3;
    g_global_table[0] = static_cast<uint32_t>(a + 10);
    g_global_table[1] = static_cast<uint32_t>(b + 20);
    const int merged = static_cast<int>(g_global_table[0] + g_global_table[1]);
    return merged + g_global_bias;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_demo_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    const int seed = static_cast<int>(reinterpret_cast<uintptr_t>(env) & 0x3u);
    volatile int export_probe = fun_global_data_mix(seed + 1, seed + 2)
                              + fun_static_local_table(seed + 2, seed + 3)
                              + fun_global_struct_acc(seed + 3, seed + 4)
                              + fun_class_static_member(seed + 1, seed + 4)
                              + fun_multi_branch_path(seed + 2, seed + 5)
                              + fun_switch_dispatch(seed + 1, seed + 5)
                              + fun_bitmask_branch(seed + 4, seed + 2)
                              + fun_global_table_rw(seed + 2, seed + 6)
                              + fun_global_mutable_state(seed + 3, seed + 6);
    (void)export_probe;
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
