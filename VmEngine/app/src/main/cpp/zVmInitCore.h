#pragma once

// JNI 接口类型。
#include <jni.h>

// route4 启动核心流程入口：
// 1) 提取并加载嵌入 expand so；
// 2) 预热函数缓存与共享分支表；
// 3) 初始化符号 takeover 映射。
bool runVmInitCore(JNIEnv* env);
