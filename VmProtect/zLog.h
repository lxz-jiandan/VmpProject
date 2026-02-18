#ifndef TESTPOST_LOGQUEUE_H
#define TESTPOST_LOGQUEUE_H

#include <cstdarg>

// 日志总开关：1=启用日志，0=关闭日志。
#define ZLOG_ENABLE_LOGGING 1

// 日志级别定义（数值越大等级越高）。
#define LOG_LEVEL_VERBOSE 2
#define LOG_LEVEL_DEBUG   3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_WARN    5
#define LOG_LEVEL_ERROR   6

// 当前日志级别阈值：低于该等级的日志不会输出。
#ifndef CURRENT_LOG_LEVEL
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO
#endif

// 默认日志标签。
#ifndef LOG_TAG
#define LOG_TAG "zLog"
#endif

// 兼容没有 __FILE_NAME__ 的编译环境。
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

// 日志宏封装：统一补充文件名、函数名和行号。
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

// 统一日志输出函数。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...);

#endif // TESTPOST_LOGQUEUE_H
