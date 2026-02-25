/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 日志宏与接口声明。
 * - 加固链路位置：全局基础设施。
 * - 输入：模块日志请求。
 * - 输出：统一日志格式。
 */
#ifndef TESTPOST_LOGQUEUE_H
#define TESTPOST_LOGQUEUE_H

#include <cstdarg>  // `va_list` / 可变参数接口需要。

// 日志总开关：
// 1 = 启用日志宏；
// 0 = 关闭日志宏。
// 注意：关闭后 `LOGV/LOGD/LOGI/LOGW/LOGE` 会被预处理为“空语句”。
#define ZLOG_ENABLE_LOGGING 1

// 日志级别定义（数值越大表示等级越高、越重要）。
// 这里保持与 Android Log 优先级顺序一致，方便跨端比对日志。
#define LOG_LEVEL_VERBOSE 2
#define LOG_LEVEL_DEBUG   3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_WARN    5
#define LOG_LEVEL_ERROR   6

// 当前日志级别阈值：
// 运行时调用 `zLogPrint` 时，`level < CURRENT_LOG_LEVEL` 的日志会被丢弃。
// 这里允许通过编译参数在不同构建模式下覆盖（例如 Release 提升阈值）。
#ifndef CURRENT_LOG_LEVEL
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO
#endif

// 默认日志标签（跨模块可通过重新定义 `LOG_TAG` 覆盖）。
#ifndef LOG_TAG
#define LOG_TAG "zLog"
#endif

// 兼容没有 __FILE_NAME__ 的编译环境。
// MSVC/部分工具链默认只提供 `__FILE__`。
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

// 日志宏封装：统一把文件名、函数名和行号传入 `zLogPrint`。
// 这样上层调用只需要传业务消息，不需要重复拼位置信息参数。
#if ZLOG_ENABLE_LOGGING
    // 详细跟踪日志（最高噪音等级）。
    #define LOGV(...) zLogPrint(LOG_LEVEL_VERBOSE, LOG_TAG, __FILE_NAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    // 调试日志（开发排查常用）。
    #define LOGD(...) zLogPrint(LOG_LEVEL_DEBUG, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    // 信息日志（默认建议保留的业务轨迹）。
    #define LOGI(...) zLogPrint(LOG_LEVEL_INFO, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    // 警告日志（可恢复异常或异常前兆）。
    #define LOGW(...) zLogPrint(LOG_LEVEL_WARN, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
    // 错误日志（明确失败路径）。
    #define LOGE(...) zLogPrint(LOG_LEVEL_ERROR, LOG_TAG, __FILE_NAME__, __FUNCTION__,__LINE__, ##__VA_ARGS__)
#else
    // 关闭日志时宏直接清空，不产生运行时代码。
    #define LOGV(...)
    #define LOGD(...)
    #define LOGI(...)
    #define LOGW(...)
    #define LOGE(...)
#endif

// 统一日志输出函数。
// 参数语义：
// `level`         日志等级（用于阈值过滤）；
// `tag`           模块标签（当前 console 实现里未使用）；
// `fileName`      源文件名（可用于扩展输出模板）；
// `functionName`  函数名（可用于扩展输出模板）；
// `lineNum`       行号（可用于扩展输出模板）；
// `format`        printf 风格格式串。
void zLogPrint(int level, const char* tag, const char* fileName, const char* functionName, int lineNum, const char* format, ...);

#endif // TESTPOST_LOGQUEUE_H
