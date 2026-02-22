/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - Asset 管理接口声明（历史命名保留）。
 * - 加固链路位置：运行时 I/O 接口层。
 * - 输入：JNI 环境与资产名。
 * - 输出：统一文件/字节访问能力。
 */
#ifndef Z_ASSEST_MANAGER_H
#define Z_ASSEST_MANAGER_H

#include <jni.h>                  // JNI 基础类型。
#include <string>                 // std::string。
#include <vector>                 // std::vector<uint8_t>。
#include <android/asset_manager.h> // AAssetManager 声明。

class zAssetManager {
public:
    // 通过 ActivityThread.currentApplication() 获取当前 Application 上下文。
    // 该方法允许在 JNI_OnLoad 等没有显式传入 Context 的场景中访问 assets。
    static jobject getCurrentApplicationContext(JNIEnv* env);

    // 读取 assets 下的二进制文件（自动获取当前 Application 作为 context）。
    static bool loadAssetDataByFileName(JNIEnv* env, const char* assetFileName, std::vector<uint8_t>& dataOut);

    // 读取 assets 下的二进制文件（调用方显式提供 context）。
    static bool loadAssetDataByFileName(JNIEnv* env, jobject context, const char* assetFileName, std::vector<uint8_t>& dataOut);

    // 将 assets 文件落盘到应用私有 files 目录（自动获取 context）。
    // 常用于把 so 从 apk 资源中导出后交给自定义加载器处理。
    static bool extractAssetToFile(JNIEnv* env, const char* assetFileName, std::string& outPath);

    // 将 assets 文件落盘到应用私有 files 目录（调用方显式提供 context）。
    static bool extractAssetToFile(JNIEnv* env, jobject context, const char* assetFileName, std::string& outPath);

    // 读取当前 Application 的 files 目录绝对路径。
    static bool getCurrentFilesDirPath(JNIEnv* env, std::string& outPath);

private:
    // jstring -> std::string 便捷转换，内部负责 UTFChars 生命周期。
    static bool jstringToString(JNIEnv* env, jstring str, std::string& out);

    // 可靠写文件：循环 write 直到全部字节落盘。
    static bool writeAll(int fd, const void* data, size_t size);

    // 查询 context.getFilesDir().getAbsolutePath()。
    static bool getFilesDirPath(JNIEnv* env, jobject context, std::string& outPath);

    // 通过 Java AssetManager 获取 NDK AAssetManager 句柄。
    static AAssetManager* getAssetManagerFromContext(JNIEnv* env, jobject context);
};

#endif // Z_ASSEST_MANAGER_H
