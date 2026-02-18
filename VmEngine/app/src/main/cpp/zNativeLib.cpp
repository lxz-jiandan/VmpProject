#include <jni.h>
#include <memory>
#include <string>
#include <vector>

#include "zAssestManager.h"
#include "zFunction.h"
#include "zLog.h"
#include "zVmEngine.h"

// 保存解包后的 so 绝对路径，供 zLinker 直接加载。
static std::string g_custom_so_path;

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    // 1) 校验并获取 JNIEnv。JNI_OnLoad 失败必须返回 JNI_ERR。
    JNIEnv* env = nullptr;
    if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    // 2) 解包 assets/libdemo.so 到应用私有目录。
    if (!zAssetManager::extractAssetToFile(env, "libdemo.so", g_custom_so_path)) {
        LOGE("extract asset failed: libdemo.so");
        return JNI_ERR;
    }

    // 3) 初始化 VM 引擎并加载 so。
    zVmEngine& engine = zVmEngine::getInstance();
    if (!engine.LoadLibrary(g_custom_so_path.c_str())) {
        LOGE("custom linker load failed: %s", g_custom_so_path.c_str());
        return JNI_ERR;
    }

    // 4) 先测试未编码文本路线（fun_for_add.txt -> loadUnencodedText）。
    std::vector<uint8_t> textData;
    if (!zAssetManager::loadAssetDataByFileName(env, "fun_for_add.txt", textData)) {
        LOGE("loadAssetDataByFileName failed: fun_for_add.txt");
        return JNI_ERR;
    }

    std::unique_ptr<zFunction> textFunction = std::make_unique<zFunction>();
    if (!textFunction->loadUnencodedText(reinterpret_cast<const char*>(textData.data()), textData.size())) {
        LOGE("loadUnencodedText failed: fun_for_add.txt");
        return JNI_ERR;
    }

    const uint64_t textFunctionAddress = textFunction->functionAddress();
    if (textFunctionAddress == 0) {
        LOGE("invalid fun_addr from unencoded text");
        return JNI_ERR;
    }

    if (!engine.cacheFunction(std::move(textFunction))) {
        LOGE("cache unencoded function failed: fun_addr=0x%llx",
             static_cast<unsigned long long>(textFunctionAddress));
        return JNI_ERR;
    }

    // 统一测试参数：fun_for_add(2, 4) 期望结果为 30。
    zParams params(std::vector<uint64_t>{2, 4});
    uint64_t textResult = 0;
    textResult = engine.execute(&textResult, textFunctionAddress, params);
    LOGI("execute unencoded by fun_addr=0x%llx result=%llu",
         static_cast<unsigned long long>(textFunctionAddress),
         static_cast<unsigned long long>(textResult));

    // 5) 再测试编码二进制路线（fun_for_add.bin -> loadEncodedData）。
    std::vector<uint8_t> encodedData;
    if (!zAssetManager::loadAssetDataByFileName(env, "fun_for_add.bin", encodedData)) {
        LOGE("loadAssetDataByFileName failed: fun_for_add.bin");
        return JNI_ERR;
    }

    std::unique_ptr<zFunction> encodedFunction = std::make_unique<zFunction>();
    if (!encodedFunction->loadEncodedData(encodedData.data(), encodedData.size())) {
        LOGE("loadEncodedData failed: fun_for_add.bin");
        return JNI_ERR;
    }

    const uint64_t encodedFunctionAddress = encodedFunction->functionAddress();
    if (encodedFunctionAddress == 0) {
        LOGE("invalid fun_addr from encoded data");
        return JNI_ERR;
    }

    if (!engine.cacheFunction(std::move(encodedFunction))) {
        LOGE("cache encoded function failed: fun_addr=0x%llx",
             static_cast<unsigned long long>(encodedFunctionAddress));
        return JNI_ERR;
    }

    uint64_t encodedResult = 0;
    encodedResult = engine.execute(&encodedResult, encodedFunctionAddress, params);
    LOGI("execute encoded by fun_addr=0x%llx result=%llu",
         static_cast<unsigned long long>(encodedFunctionAddress),
         static_cast<unsigned long long>(encodedResult));

    return JNI_VERSION_1_6;
}
