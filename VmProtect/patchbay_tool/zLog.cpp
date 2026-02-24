#include "zLog.h"
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>

// 单条日志格式化缓冲上限。
#define MAX_LOG_BUF_LEN 3000
// 预留给未来分段输出逻辑（当前实现未使用，但保留兼容）。
#define MAX_SEGMENT_LEN 3000

// 统一日志输出实现：进行级别过滤、格式化并打印到标准输出。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...) {
    // 先按全局等级做过滤，低优先级日志直接丢弃。
    if(level < CURRENT_LOG_LEVEL) return;

    va_list args;
    va_start(args, format);

    // 使用栈缓冲完成格式化，避免动态分配。
    char buffer[MAX_LOG_BUF_LEN];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // 把内部等级枚举转成可读字符串。
    const char* level_str = "INFO";
    if (level == LOG_LEVEL_ERROR) level_str = "ERROR";
    else if (level == LOG_LEVEL_WARN) level_str = "WARN";
    else if (level == LOG_LEVEL_DEBUG) level_str = "DEBUG";
    else if (level == LOG_LEVEL_VERBOSE) level_str = "VERBOSE";

    // 统一日志格式：级别 + 函数名 + 文件行号 + 消息。
    printf("[%s][%s][%s:%d] %s\n", level_str, function_name, file_name, line_num, buffer);
}

