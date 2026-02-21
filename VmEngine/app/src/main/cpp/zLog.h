#ifndef Z_LOG_H
#define Z_LOG_H

#include <android/log.h>  // Android logcat 输出接口。


// 日志总开关：1=启用日志，0=关闭日志。
// 注意：关闭后 LOGV/LOGD/LOGI/LOGW/LOGE 都会被展开为空。
#define ZLOG_ENABLE_LOGGING 1

// 若存在全局配置宏，优先使用全局配置覆盖本地开关。
#if ZCONFIG_ENABLE
// 先取消本地默认值。
#undef ZLOG_ENABLE_LOGGING
// 继承全局配置结果。
#define ZLOG_ENABLE_LOGGING ZCONFIG_ENABLE_LOGGING
#endif

// 日志级别定义（数值越大等级越高）。
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


// 当前日志级别阈值：低于该等级的日志不会输出。
// 建议 Release 设为 LOG_LEVEL_INFO 或更高。
#ifndef CURRENT_LOG_LEVEL
#define CURRENT_LOG_LEVEL LOG_LEVEL_DEBUG
#endif

// 默认日志标签。
#ifndef LOG_TAG
#define LOG_TAG "zLog"
#endif

// 日志宏封装：统一补充文件名、函数名和行号。
// 这样排查问题时可以直接定位到源码位置。
#if ZLOG_ENABLE_LOGGING

    // 详细跟踪日志。
    #define LOGV(...) zLogPrint(LOG_LEVEL_VERBOSE, LOG_TAG, __FILE_NAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    // 调试日志。
    #define LOGD(...) zLogPrint(LOG_LEVEL_DEBUG, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    // 信息日志。
    #define LOGI(...) zLogPrint(LOG_LEVEL_INFO, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    // 警告日志。
    #define LOGW(...) zLogPrint(LOG_LEVEL_WARN, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    // 错误日志。
    #define LOGE(...) zLogPrint(LOG_LEVEL_ERROR, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)

#else
    // 关闭日志时，所有宏都折叠为空语句。
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



