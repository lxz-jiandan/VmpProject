#ifndef TESTPOST_LOGQUEUE_H
#define TESTPOST_LOGQUEUE_H

#include <cstdarg>

// 日志总开关：1 启用，0 关闭
#define ZLOG_ENABLE_LOGGING 1

// 日志级别定义（数值越大，级别越高）
#define LOG_LEVEL_VERBOSE 2
#define LOG_LEVEL_DEBUG   3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_WARN    5
#define LOG_LEVEL_ERROR   6

// 当前最小输出级别（低于该级别的日志会被丢弃）
#ifndef CURRENT_LOG_LEVEL
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO
#endif

// 默认日志标签
#ifndef LOG_TAG
#define LOG_TAG "zLog"
#endif

// 兼容性：若编译器未提供 __FILE_NAME__，退化为 __FILE__
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

// 日志宏：自动附加文件名、函数名与行号
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

/**
 * @brief 统一日志输出函数。
 * @param level 日志级别。
 * @param tag 日志标签。
 * @param file_name 源文件名。
 * @param function_name 函数名。
 * @param line_num 行号。
 * @param format printf 风格格式化字符串。
 */
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...);

#endif //TESTPOST_LOGQUEUE_H
