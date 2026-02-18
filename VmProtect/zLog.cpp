#include "zLog.h"
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>

#define MAX_LOG_BUF_LEN 3000
#define MAX_SEGMENT_LEN 3000

// 控制台日志实现：先格式化，再按最终文本输出。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...) {
    if(level < CURRENT_LOG_LEVEL) return;

    va_list args;
    va_start(args, format);

    // 先把可变参数格式化到固定缓冲区，避免重复遍历参数列表。
    char buffer[MAX_LOG_BUF_LEN];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // 根据 level 生成可读字符串，便于切换不同输出模板时复用。
    const char* level_str = "INFO";
    if (level == LOG_LEVEL_ERROR) level_str = "ERROR";
    else if (level == LOG_LEVEL_WARN) level_str = "WARN";
    else if (level == LOG_LEVEL_DEBUG) level_str = "DEBUG";
    else if (level == LOG_LEVEL_VERBOSE) level_str = "VERBOSE";

    // 如需带位置信息的完整输出，可打开下面一行。
    // 示例：printf("[%s][%s][%s:%d] %s\n", level_str, function_name, file_name, line_num, buffer);
    printf("%s\n", buffer);
}

