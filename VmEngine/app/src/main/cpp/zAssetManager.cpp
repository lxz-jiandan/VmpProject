#include "zAssestManager.h"

#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <android/asset_manager_jni.h>

#include "zLog.h"

// 通过反射调用 ActivityThread.currentApplication() 获取进程级 Application。
// 这是 native 层在“没有 Java 显式传 context”时最通用的兜底方案。
jobject zAssetManager::getCurrentApplicationContext(JNIEnv* env) {
    if (env == nullptr) {
        return nullptr;
    }

    jclass activityThreadCls = env->FindClass("android/app/ActivityThread");
    if (activityThreadCls == nullptr) {
        return nullptr;
    }

    jmethodID currentApplicationMid = env->GetStaticMethodID(
            activityThreadCls,
            "currentApplication",
            "()Landroid/app/Application;");
    if (currentApplicationMid == nullptr) {
        env->DeleteLocalRef(activityThreadCls);
        return nullptr;
    }

    jobject appContext = env->CallStaticObjectMethod(activityThreadCls, currentApplicationMid);
    env->DeleteLocalRef(activityThreadCls);
    return appContext;
}

bool zAssetManager::loadAssetDataByFileName(JNIEnv* env, const char* assetFileName, std::vector<uint8_t>& dataOut) {
    // 无 context 场景：先拿到 Application 再复用重载实现。
    jobject appContext = getCurrentApplicationContext(env);
    if (appContext == nullptr) {
        return false;
    }
    bool ok = loadAssetDataByFileName(env, appContext, assetFileName, dataOut);
    env->DeleteLocalRef(appContext);
    return ok;
}

bool zAssetManager::loadAssetDataByFileName(JNIEnv* env, jobject context, const char* assetFileName, std::vector<uint8_t>& dataOut) {
    if (env == nullptr || context == nullptr) {
        return false;
    }
    if (assetFileName == nullptr || assetFileName[0] == '\0') {
        return false;
    }

    dataOut.clear();

    AAssetManager* assetManager = getAssetManagerFromContext(env, context);
    if (assetManager == nullptr) {
        return false;
    }

    AAsset* asset = AAssetManager_open(assetManager, assetFileName, AASSET_MODE_BUFFER);
    if (asset == nullptr) {
        LOGW("open asset failed: %s", assetFileName);
        return false;
    }

    off_t len = AAsset_getLength(asset);
    if (len < 0) {
        AAsset_close(asset);
        return false;
    }

    if (len == 0) {
        AAsset_close(asset);
        return true;
    }

    dataOut.resize(static_cast<size_t>(len));
    int64_t readLen = AAsset_read(asset, dataOut.data(), static_cast<size_t>(len));
    AAsset_close(asset);
    if (readLen != len) {
        LOGW("read asset failed: %s read=%lld len=%lld", assetFileName, static_cast<long long>(readLen), static_cast<long long>(len));
        dataOut.clear();
        return false;
    }

    return true;
}

bool zAssetManager::jstringToString(JNIEnv* env, jstring str, std::string& out) {
    if (env == nullptr || str == nullptr) {
        return false;
    }
    const char* chars = env->GetStringUTFChars(str, nullptr);
    if (chars == nullptr) {
        return false;
    }
    out.assign(chars);
    env->ReleaseStringUTFChars(str, chars);
    return true;
}

bool zAssetManager::writeAll(int fd, const void* data, size_t size) {
    const char* ptr = static_cast<const char*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t wrote = write(fd, ptr, remaining);
        if (wrote <= 0) {
            return false;
        }
        ptr += wrote;
        remaining -= static_cast<size_t>(wrote);
    }
    return true;
}

bool zAssetManager::getFilesDirPath(JNIEnv* env, jobject context, std::string& outPath) {
    if (env == nullptr || context == nullptr) {
        return false;
    }

    jclass contextCls = env->GetObjectClass(context);
    if (contextCls == nullptr) {
        return false;
    }

    jmethodID getFilesDirMid = env->GetMethodID(contextCls, "getFilesDir", "()Ljava/io/File;");
    if (getFilesDirMid == nullptr) {
        env->DeleteLocalRef(contextCls);
        return false;
    }

    jobject fileObj = env->CallObjectMethod(context, getFilesDirMid);
    env->DeleteLocalRef(contextCls);
    if (fileObj == nullptr) {
        return false;
    }

    jclass fileCls = env->GetObjectClass(fileObj);
    if (fileCls == nullptr) {
        env->DeleteLocalRef(fileObj);
        return false;
    }

    jmethodID getAbsPathMid = env->GetMethodID(fileCls, "getAbsolutePath", "()Ljava/lang/String;");
    if (getAbsPathMid == nullptr) {
        env->DeleteLocalRef(fileCls);
        env->DeleteLocalRef(fileObj);
        return false;
    }

    jstring pathStr = static_cast<jstring>(env->CallObjectMethod(fileObj, getAbsPathMid));
    env->DeleteLocalRef(fileCls);
    env->DeleteLocalRef(fileObj);

    if (pathStr == nullptr) {
        return false;
    }

    bool ok = jstringToString(env, pathStr, outPath);
    env->DeleteLocalRef(pathStr);
    return ok;
}

AAssetManager* zAssetManager::getAssetManagerFromContext(JNIEnv* env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return nullptr;
    }

    jclass contextCls = env->GetObjectClass(context);
    if (contextCls == nullptr) {
        return nullptr;
    }

    jmethodID getAssetsMid = env->GetMethodID(contextCls, "getAssets", "()Landroid/content/res/AssetManager;");
    if (getAssetsMid == nullptr) {
        env->DeleteLocalRef(contextCls);
        return nullptr;
    }

    jobject assetManagerObj = env->CallObjectMethod(context, getAssetsMid);
    env->DeleteLocalRef(contextCls);
    if (assetManagerObj == nullptr) {
        return nullptr;
    }

    AAssetManager* assetManager = AAssetManager_fromJava(env, assetManagerObj);
    env->DeleteLocalRef(assetManagerObj);
    return assetManager;
}

bool zAssetManager::extractAssetToFile(JNIEnv* env, const char* assetFileName, std::string& outPath) {
    // 无 context 场景：先拿 Application 再复用重载版本。
    jobject appContext = getCurrentApplicationContext(env);
    if (appContext == nullptr) {
        return false;
    }
    bool ok = extractAssetToFile(env, appContext, assetFileName, outPath);
    env->DeleteLocalRef(appContext);
    return ok;
}

bool zAssetManager::extractAssetToFile(JNIEnv* env, jobject context, const char* assetFileName, std::string& outPath) {
    if (env == nullptr || context == nullptr || assetFileName == nullptr || assetFileName[0] == '\0') {
        return false;
    }

    AAssetManager* assetManager = getAssetManagerFromContext(env, context);
    if (assetManager == nullptr) {
        LOGE("AAssetManager is null");
        return false;
    }

    std::string filesDir;
    if (!getFilesDirPath(env, context, filesDir)) {
        LOGE("getFilesDir failed");
        return false;
    }

    outPath = filesDir;
    if (!outPath.empty() && outPath.back() != '/') {
        outPath.push_back('/');
    }
    // 最终目标路径形如：/data/user/0/<pkg>/files/<assetFileName>
    outPath += assetFileName;

    AAsset* asset = AAssetManager_open(assetManager, assetFileName, AASSET_MODE_STREAMING);
    if (asset == nullptr) {
        LOGE("open asset failed: %s", assetFileName);
        return false;
    }

    int fd = open(outPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        LOGE("open output failed: %s", outPath.c_str());
        AAsset_close(asset);
        return false;
    }

    const size_t kBufferSize = 16 * 1024;
    std::vector<char> buffer(kBufferSize);
    int readBytes = 0;
    bool ok = true;

    // 流式拷贝避免一次性申请大块内存，适合任意大小二进制资源（so/dat/bin）。
    while ((readBytes = AAsset_read(asset, buffer.data(), buffer.size())) > 0) {
        if (!writeAll(fd, buffer.data(), static_cast<size_t>(readBytes))) {
            LOGE("write asset failed: %s", outPath.c_str());
            ok = false;
            break;
        }
    }

    if (readBytes < 0) {
        LOGE("read asset failed: %s", assetFileName);
        ok = false;
    }

    close(fd);
    AAsset_close(asset);
    return ok;
}
