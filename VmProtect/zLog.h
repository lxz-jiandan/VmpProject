#ifndef TESTPOST_LOGQUEUE_H
#define TESTPOST_LOGQUEUE_H

#include <cstdarg>

// 模块配置开关
#define ZLOG_ENABLE_LOGGING 1

// 日志级别定义
#define LOG_LEVEL_VERBOSE 2
#define LOG_LEVEL_DEBUG   3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_WARN    5
#define LOG_LEVEL_ERROR   6

// 当前日志级别
#ifndef CURRENT_LOG_LEVEL
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO
#endif

// 日志标签
#ifndef LOG_TAG
#define LOG_TAG "zLog"
#endif

// __FILE_NAME__ macro for compatibility
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
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

void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...);

#endif //TESTPOST_LOGQUEUE_H
