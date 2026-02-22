/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - Android assets/file 读写与解包实现。
 * - 加固链路位置：运行时准备阶段。
 * - 输入：assets 文件名。
 * - 输出：本地文件路径或内存字节。
 */
#include "zAssestManager.h"

#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <android/asset_manager_jni.h>

#include "zLog.h"

// 通过反射调用 ActivityThread.currentApplication() 获取进程级 Application。
// 这是 native 层在“没有 Java 显式传 context”时最通用的兜底方案。
jobject zAssetManager::getCurrentApplicationContext(JNIEnv* env) {
    // 传入的 JNI 环境无效时，无法继续调用任何 Java API。
    if (env == nullptr) {
        return nullptr;
    }

    // 反射拿到 ActivityThread 类对象。
    jclass activityThreadCls = env->FindClass("android/app/ActivityThread");
    // 类查找失败通常意味着运行时环境异常或类加载受限。
    if (activityThreadCls == nullptr) {
        return nullptr;
    }

    // 获取 ActivityThread.currentApplication() 静态方法。
    jmethodID currentApplicationMid = env->GetStaticMethodID(
            activityThreadCls,
            "currentApplication",
            "()Landroid/app/Application;");
    // 方法查找失败时释放局部引用并返回失败。
    if (currentApplicationMid == nullptr) {
        env->DeleteLocalRef(activityThreadCls);
        return nullptr;
    }

    // 调用静态方法得到 Application（即 Context 子类）。
    jobject appContext = env->CallStaticObjectMethod(activityThreadCls, currentApplicationMid);
    // 使用完类引用后及时释放，避免局部引用表膨胀。
    env->DeleteLocalRef(activityThreadCls);
    // 返回给调用方，调用方负责生命周期管理。
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
    // 基础参数校验：env/context 缺失都无法访问 assets。
    if (env == nullptr || context == nullptr) {
        return false;
    }
    // 文件名为空直接失败，避免调用 NDK API 出现未定义行为。
    if (assetFileName == nullptr || assetFileName[0] == '\0') {
        return false;
    }

    // 每次读取前先清空输出缓冲，保证失败时不残留旧数据。
    dataOut.clear();

    // 把 Java AssetManager 转成 NDK AAssetManager。
    AAssetManager* assetManager = getAssetManagerFromContext(env, context);
    if (assetManager == nullptr) {
        return false;
    }

    // 以 BUFFER 模式打开，适合一次性读取完整文件。
    AAsset* asset = AAssetManager_open(assetManager, assetFileName, AASSET_MODE_BUFFER);
    if (asset == nullptr) {
        LOGW("open asset failed: %s", assetFileName);
        return false;
    }

    // 获取资源总长度，后续用于一次性分配目标缓冲。
    off_t len = AAsset_getLength(asset);
    if (len < 0) {
        AAsset_close(asset);
        return false;
    }

    // 空文件合法，返回 true 且输出空 vector。
    if (len == 0) {
        AAsset_close(asset);
        return true;
    }

    // 分配目标缓冲区并直接读取整段数据。
    dataOut.resize(static_cast<size_t>(len));
    int64_t readLen = AAsset_read(asset, dataOut.data(), static_cast<size_t>(len));
    // 读取完成后立即关闭句柄。
    AAsset_close(asset);
    // 实际读取长度不一致视为失败并清空输出。
    if (readLen != len) {
        LOGW("read asset failed: %s read=%lld len=%lld", assetFileName, static_cast<long long>(readLen), static_cast<long long>(len));
        dataOut.clear();
        return false;
    }

    return true;
}

bool zAssetManager::jstringToString(JNIEnv* env, jstring str, std::string& out) {
    // 基础参数校验。
    if (env == nullptr || str == nullptr) {
        return false;
    }
    // 取 UTF-8 临时指针；失败时返回 nullptr。
    const char* chars = env->GetStringUTFChars(str, nullptr);
    if (chars == nullptr) {
        return false;
    }
    // 拷贝到 std::string，避免依赖 JNI 缓冲区生命周期。
    out.assign(chars);
    // 释放 JNI 返回的 UTF 字符缓冲。
    env->ReleaseStringUTFChars(str, chars);
    return true;
}

bool zAssetManager::writeAll(int fd, const void* data, size_t size) {
    // 把 void* 显式转成字节指针，便于按偏移推进。
    const char* ptr = static_cast<const char*>(data);
    // 剩余待写字节数。
    size_t remaining = size;
    // 循环写入直到全部落盘或发生错误。
    while (remaining > 0) {
        ssize_t wrote = write(fd, ptr, remaining);
        // 写失败或返回 0 都视为异常。
        if (wrote <= 0) {
            return false;
        }
        // 指针前移到未写入位置。
        ptr += wrote;
        // 更新剩余字节数。
        remaining -= static_cast<size_t>(wrote);
    }
    return true;
}

bool zAssetManager::getFilesDirPath(JNIEnv* env, jobject context, std::string& outPath) {
    // 参数无效直接失败。
    if (env == nullptr || context == nullptr) {
        return false;
    }

    // 获取 context 的运行时类。
    jclass contextCls = env->GetObjectClass(context);
    if (contextCls == nullptr) {
        return false;
    }

    // 反射获取 getFilesDir() 方法。
    jmethodID getFilesDirMid = env->GetMethodID(contextCls, "getFilesDir", "()Ljava/io/File;");
    // 方法不存在时释放类引用后返回失败。
    if (getFilesDirMid == nullptr) {
        env->DeleteLocalRef(contextCls);
        return false;
    }

    // 调用 getFilesDir() 拿到 java.io.File 对象。
    jobject fileObj = env->CallObjectMethod(context, getFilesDirMid);
    // context 类引用已无用，立即释放。
    env->DeleteLocalRef(contextCls);
    if (fileObj == nullptr) {
        return false;
    }

    // 获取 File 对象对应的类。
    jclass fileCls = env->GetObjectClass(fileObj);
    if (fileCls == nullptr) {
        env->DeleteLocalRef(fileObj);
        return false;
    }

    // 反射获取 getAbsolutePath() 方法。
    jmethodID getAbsPathMid = env->GetMethodID(fileCls, "getAbsolutePath", "()Ljava/lang/String;");
    // 方法不存在时清理所有局部引用。
    if (getAbsPathMid == nullptr) {
        env->DeleteLocalRef(fileCls);
        env->DeleteLocalRef(fileObj);
        return false;
    }

    // 调用 getAbsolutePath() 获得 jstring 路径。
    jstring pathStr = static_cast<jstring>(env->CallObjectMethod(fileObj, getAbsPathMid));
    // File 相关引用已无用，及时释放。
    env->DeleteLocalRef(fileCls);
    env->DeleteLocalRef(fileObj);

    // 调用失败返回空字符串对象。
    if (pathStr == nullptr) {
        return false;
    }

    // 转换为 C++ 字符串。
    bool ok = jstringToString(env, pathStr, outPath);
    // 释放局部 jstring 引用。
    env->DeleteLocalRef(pathStr);
    return ok;
}

AAssetManager* zAssetManager::getAssetManagerFromContext(JNIEnv* env, jobject context) {
    // 参数校验。
    if (env == nullptr || context == nullptr) {
        return nullptr;
    }

    // 获取 Context 运行时类。
    jclass contextCls = env->GetObjectClass(context);
    if (contextCls == nullptr) {
        return nullptr;
    }

    // 反射获取 Context.getAssets()。
    jmethodID getAssetsMid = env->GetMethodID(contextCls, "getAssets", "()Landroid/content/res/AssetManager;");
    if (getAssetsMid == nullptr) {
        env->DeleteLocalRef(contextCls);
        return nullptr;
    }

    // 调用 getAssets() 得到 Java 层 AssetManager。
    jobject assetManagerObj = env->CallObjectMethod(context, getAssetsMid);
    // Context 类引用已无用，释放。
    env->DeleteLocalRef(contextCls);
    if (assetManagerObj == nullptr) {
        return nullptr;
    }

    // 转换为 NDK AAssetManager 指针。
    AAssetManager* assetManager = AAssetManager_fromJava(env, assetManagerObj);
    // Java 侧对象引用已不需要，释放即可。
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

bool zAssetManager::getCurrentFilesDirPath(JNIEnv* env, std::string& outPath) {
    outPath.clear();
    jobject appContext = getCurrentApplicationContext(env);
    if (appContext == nullptr) {
        return false;
    }
    bool ok = getFilesDirPath(env, appContext, outPath);
    env->DeleteLocalRef(appContext);
    return ok;
}

bool zAssetManager::extractAssetToFile(JNIEnv* env, jobject context, const char* assetFileName, std::string& outPath) {
    // 基础参数校验。
    if (env == nullptr || context == nullptr || assetFileName == nullptr || assetFileName[0] == '\0') {
        return false;
    }

    // 获取可用于打开资源的 AAssetManager。
    AAssetManager* assetManager = getAssetManagerFromContext(env, context);
    if (assetManager == nullptr) {
        LOGE("AAssetManager is null");
        return false;
    }

    // 读取应用私有 files 目录绝对路径。
    std::string filesDir;
    if (!getFilesDirPath(env, context, filesDir)) {
        LOGE("getFilesDir failed");
        return false;
    }

    // 拼接输出路径前缀。
    outPath = filesDir;
    // 保证目录与文件名之间存在 '/' 分隔。
    if (!outPath.empty() && outPath.back() != '/') {
        outPath.push_back('/');
    }
    // 最终目标路径形如：/data/user/0/<pkg>/files/<assetFileName>
    outPath += assetFileName;

    // 以流式模式打开资源，适合分块复制。
    AAsset* asset = AAssetManager_open(assetManager, assetFileName, AASSET_MODE_STREAMING);
    if (asset == nullptr) {
        LOGE("open asset failed: %s", assetFileName);
        return false;
    }

    // 创建/截断目标文件，权限限定为应用私有可读写。
    int fd = open(outPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        LOGE("open output failed: %s", outPath.c_str());
        AAsset_close(asset);
        return false;
    }

    // 固定分块大小，避免大文件一次性占用大量内存。
    const size_t kBufferSize = 16 * 1024;
    // 临时缓冲。
    std::vector<char> buffer(kBufferSize);
    // 记录每次读取字节数。
    int readBytes = 0;
    // 记录整体流程是否成功。
    bool ok = true;

    // 流式拷贝避免一次性申请大块内存，适合任意大小二进制资源（so/dat/bin）。
    while ((readBytes = AAsset_read(asset, buffer.data(), buffer.size())) > 0) {
        if (!writeAll(fd, buffer.data(), static_cast<size_t>(readBytes))) {
            LOGE("write asset failed: %s", outPath.c_str());
            ok = false;
            break;
        }
    }

    // readBytes < 0 表示读取发生错误。
    if (readBytes < 0) {
        LOGE("read asset failed: %s", assetFileName);
        ok = false;
    }

    // 关闭文件描述符。
    close(fd);
    // 关闭资源句柄。
    AAsset_close(asset);
    // 返回最终执行结果。
    return ok;
}
