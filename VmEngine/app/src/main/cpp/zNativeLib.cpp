#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include "zLog.h"

#include "zAssestManager.h"
#include "zVmEngine.h"
#include "zByteCodeReader.h"
#include "zTypeManager.h"
#include "zVmOpcodes.h"
#include "zFunction.h"

static std::string g_custom_so_path;

extern "C" JNIEXPORT
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv* env = nullptr;
    if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    if (!zAssetManager::extractAssetToFile(env, "libdemo.so", g_custom_so_path)) {
        LOGE("extract asset failed: libdemo.so");
        return JNI_ERR;
    }

    zVmEngine& engine = zVmEngine::getInstance();
    if (!engine.LoadLibrary(g_custom_so_path.c_str())) {
        LOGE("custom linker load failed: %s", g_custom_so_path.c_str());
        return JNI_ERR;
    }

    std::string textOut;
    if (!zAssetManager::loadAssetTextByFileName(env, "fun_for_add.txt", textOut)){
        LOGE("loadAssetTextByFileName failed: fun_for_add.txt");
        return JNI_ERR;
    }

    std::unique_ptr<zFunction> function = std::make_unique<zFunction>();
    if (!function->loadUnencodedText(textOut.data(), textOut.size())) {
        LOGE("load function from text failed: fun_for_add.txt");
        return JNI_ERR;
    }

    const uint64_t funAddr = function->funAddr();
    if (funAddr == 0) {
        LOGE("invalid fun_addr from text: fun_for_add.txt");
        return JNI_ERR;
    }

    if (!engine.cacheFunction(std::move(function))) {
        LOGE("cache function failed: fun_addr=0x%llx", static_cast<unsigned long long>(funAddr));
        return JNI_ERR;
    }

    zParams params(std::vector<uint64_t>{2, 4});
    uint64_t result = 0;
    result = engine.execute(&result, funAddr, params);
    LOGI("execute by fun_addr=0x%llx result=%llu",
         static_cast<unsigned long long>(funAddr),
         static_cast<unsigned long long>(result));


    return JNI_VERSION_1_6;
}
