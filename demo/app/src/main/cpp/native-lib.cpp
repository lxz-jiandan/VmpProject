#include <jni.h>
#include <string>
#include <vector>
#include <numeric>
#include <android/log.h>

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

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_demo_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
