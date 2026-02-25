// JNI 基础类型。
#include <jni.h>

// 原子状态机。
#include <atomic>
// dlsym/dlopen。
#include <dlfcn.h>
// 互斥锁。
#include <mutex>

// 日志。
#include "zLog.h"
// route4 核心初始化流程。
#include "zVmInitCore.h"

namespace {

// vm_init 生命周期状态。
enum zVmInitState : int {
    // 尚未开始初始化。
    kVmInitStateUninitialized = 0,
    // 正在初始化（仅一个线程进入）。
    kVmInitStateInitializing = 1,
    // 初始化成功，可直接复用。
    kVmInitStateReady = 2,
    // 初始化失败，后续快速失败。
    kVmInitStateFailed = 3,
};

// 全局初始化状态（原子可无锁读取）。
static std::atomic<int> g_vm_init_state{kVmInitStateUninitialized};
// 初始化临界区锁（防止并发重复初始化）。
static std::mutex g_vm_init_mutex;

// 获取当前线程可用的 JNIEnv。
bool acquireCurrentJniEnv(JavaVM** out_vm, JNIEnv** out_env, bool* out_attached) {
    // 输出参数必须完整。
    if (out_vm == nullptr || out_env == nullptr || out_attached == nullptr) {
        return false;
    }
    // 先清空输出，避免调用方读取旧值。
    *out_vm = nullptr;
    *out_env = nullptr;
    *out_attached = false;

    // JNI_GetCreatedJavaVMs 的函数指针类型。
    using GetCreatedJavaVMsFn = jint (*)(JavaVM**, jsize, jsize*);
    // 优先在当前符号空间里找该符号。
    GetCreatedJavaVMsFn get_created_java_vms = reinterpret_cast<GetCreatedJavaVMsFn>(
        dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    // 若未找到，则尝试常见系统 so。
    if (get_created_java_vms == nullptr) {
        const char* candidates[] = {"libart.so", "libnativehelper.so"};
        for (const char* soname : candidates) {
            // 尝试打开候选 so。
            void* handle = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
            if (handle == nullptr) {
                continue;
            }
            // 在候选 so 中查询符号。
            get_created_java_vms = reinterpret_cast<GetCreatedJavaVMsFn>(
                dlsym(handle, "JNI_GetCreatedJavaVMs"));
            if (get_created_java_vms != nullptr) {
                break;
            }
        }
    }
    // 最终仍未拿到函数指针则失败。
    if (get_created_java_vms == nullptr) {
        LOGE("vm_init failed: JNI_GetCreatedJavaVMs symbol not found");
        return false;
    }

    // 只取第一个 JavaVM（Android 单进程通常只有一个 VM）。
    JavaVM* vms[1] = {nullptr};
    jsize vm_count = 0;
    if (get_created_java_vms(vms, 1, &vm_count) != JNI_OK || vm_count <= 0 || vms[0] == nullptr) {
        LOGE("vm_init failed: JNI_GetCreatedJavaVMs returned no vm");
        return false;
    }
    // 拿到 VM 实例。
    JavaVM* vm = vms[0];
    // 当前线程的 JNI 环境指针。
    JNIEnv* env = nullptr;
    // 先尝试“已附着线程”路径。
    const jint env_result = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (env_result == JNI_OK && env != nullptr) {
        *out_vm = vm;
        *out_env = env;
        // 当前线程原本已附着，后续无需 Detach。
        *out_attached = false;
        return true;
    }
    // 线程未附着时，主动附着。
    if (env_result == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || env == nullptr) {
            LOGE("vm_init failed: AttachCurrentThread failed");
            return false;
        }
        *out_vm = vm;
        *out_env = env;
        // 记录是本函数附着，后续需要 Detach。
        *out_attached = true;
        return true;
    }
    // 其它错误码统一失败。
    LOGE("vm_init failed: GetEnv failed result=%d", static_cast<int>(env_result));
    return false;
}

} // namespace

// 对外导出初始化函数（给 native loader 调用）。
extern "C" __attribute__((visibility("default"))) int vm_init() {
    // 无锁快速路径：已就绪直接成功。
    const int state = g_vm_init_state.load(std::memory_order_acquire);
    if (state == kVmInitStateReady) {
        return 1;
    }
    // 无锁快速路径：已失败直接失败。
    if (state == kVmInitStateFailed) {
        return 0;
    }

    // 进入串行初始化临界区。
    std::lock_guard<std::mutex> lock(g_vm_init_mutex);
    // 再次读取状态，处理并发竞争。
    const int locked_state = g_vm_init_state.load(std::memory_order_acquire);
    if (locked_state == kVmInitStateReady) {
        return 1;
    }
    if (locked_state == kVmInitStateFailed) {
        return 0;
    }
    // 标记“初始化中”。
    g_vm_init_state.store(kVmInitStateInitializing, std::memory_order_release);

    // JNI 环境获取结果。
    JavaVM* vm = nullptr;
    JNIEnv* env = nullptr;
    bool attached = false;
    if (!acquireCurrentJniEnv(&vm, &env, &attached)) {
        // JNI 环境失败则直接落失败状态。
        g_vm_init_state.store(kVmInitStateFailed, std::memory_order_release);
        return 0;
    }

    // 执行核心初始化逻辑。
    const bool ok = runVmInitCore(env);
    // 若本函数曾附着线程，完成后主动分离。
    if (attached && vm != nullptr) {
        vm->DetachCurrentThread();
    }
    // 按初始化结果写入最终状态。
    g_vm_init_state.store(ok ? kVmInitStateReady : kVmInitStateFailed, std::memory_order_release);
    // C 接口返回 1/0。
    return ok ? 1 : 0;
}

// 对外导出状态查询函数（用于调试与诊断）。
extern "C" __attribute__((visibility("default"))) int vm_get_init_state() {
    return g_vm_init_state.load(std::memory_order_acquire);
}

// so 加载后自动触发初始化。
__attribute__((constructor)) static void vm_library_ctor() {
    // 调用统一初始化入口。
    const int ok = vm_init();
    // 记录初始化结果和最终状态。
    LOGI("vm_library_ctor vm_init=%d state=%d", ok, vm_get_init_state());
}
