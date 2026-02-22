#include "zLog.h"
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>

#define MAX_LOG_BUF_LEN 3000
#define MAX_SEGMENT_LEN 3000

// 统一日志输出实现：进行级别过滤、格式化并打印到标准输出。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...) {
    if(level < CURRENT_LOG_LEVEL) return;

    va_list args;
    va_start(args, format);

    char buffer[MAX_LOG_BUF_LEN];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    const char* level_str = "INFO";
    if (level == LOG_LEVEL_ERROR) level_str = "ERROR";
    else if (level == LOG_LEVEL_WARN) level_str = "WARN";
    else if (level == LOG_LEVEL_DEBUG) level_str = "DEBUG";
    else if (level == LOG_LEVEL_VERBOSE) level_str = "VERBOSE";

    printf("[%s][%s][%s:%d] %s\n", level_str, function_name, file_name, line_num, buffer);
}

