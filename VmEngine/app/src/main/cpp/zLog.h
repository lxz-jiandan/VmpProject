#ifndef Z_LOG_H
#define Z_LOG_H

#include <android/log.h>


// 模块配置开关 - 可以通过修改这个宏来控制日志输出
#define ZLOG_ENABLE_LOGGING 1

// 当全局配置宏启用时，全局宏配置覆盖模块宏配置
#if ZCONFIG_ENABLE
#undef ZLOG_ENABLE_LOGGING
#define ZLOG_ENABLE_LOGGING ZCONFIG_ENABLE_LOGGING
#endif

// 日志级别定义
#ifndef LOG_LEVEL_VERBOSE
#define LOG_LEVEL_VERBOSE 2
#endif

#ifndef LOG_LEVEL_DEBUG
#define LOG_LEVEL_DEBUG   3
#endif

#ifndef LOG_LEVEL_INFO
#define LOG_LEVEL_INFO    4
#endif

#ifndef LOG_LEVEL_WARN
#define LOG_LEVEL_WARN    5
#endif

#ifndef LOG_LEVEL_ERROR
#define LOG_LEVEL_ERROR   6
#endif


// 当前日志级别 - 可以通过修改这个值来控制日志输出级别
#ifndef CURRENT_LOG_LEVEL
#define CURRENT_LOG_LEVEL LOG_LEVEL_DEBUG
#endif

// 日志标签
#ifndef LOG_TAG
#define LOG_TAG "zLog"
#endif

// 日志宏定义
#if ZLOG_ENABLE_LOGGING

    #define LOGV(...) zLogPrint(LOG_LEVEL_VERBOSE, LOG_TAG, __FILE_NAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define LOGD(...) zLogPrint(LOG_LEVEL_DEBUG, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    #define LOGI(...) zLogPrint(LOG_LEVEL_INFO, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    #define LOGW(...) zLogPrint(LOG_LEVEL_WARN, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    #define LOGE(...) zLogPrint(LOG_LEVEL_ERROR, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)

#else
    #define LOGV(...)
    #define LOGD(...)
    #define LOGI(...)
    #define LOGW(...)
    #define LOGE(...)
#endif

// 统一日志输出函数：根据 level 输出到 Android logcat，
// 并附带文件名、函数名与行号，支持 printf 风格可变参数。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...);

#endif // Z_LOG_H



