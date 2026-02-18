#ifndef Z_ASSEST_MANAGER_H
#define Z_ASSEST_MANAGER_H

#include <jni.h>
#include <string>
#include <android/asset_manager.h>

class zAssetManager {
public:
    static jobject getCurrentApplicationContext(JNIEnv* env);
    static bool loadAssetTextByFileName(JNIEnv* env, const char* assetFileName, std::string& textOut);
    static bool loadAssetTextByFileName(JNIEnv* env, jobject context, const char* assetFileName, std::string& textOut);
    static bool extractAssetToFile(JNIEnv* env, const char* assetFileName, std::string& outPath);
    static bool extractAssetToFile(JNIEnv* env, jobject context, const char* assetFileName, std::string& outPath);

private:
    static bool jstringToString(JNIEnv* env, jstring str, std::string& out);
    static bool writeAll(int fd, const void* data, size_t size);
    static bool getFilesDirPath(JNIEnv* env, jobject context, std::string& outPath);
    static AAssetManager* getAssetManagerFromContext(JNIEnv* env, jobject context);
};

#endif // Z_ASSEST_MANAGER_H
