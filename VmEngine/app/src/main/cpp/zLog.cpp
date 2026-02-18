#include <stdlib.h>
#include "zLog.h"

#define MAX_LOG_BUF_LEN 3000
#define MAX_SEGMENT_LEN 3000


// 统一日志实现：格式化后按固定分片写入 Android 日志系统。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...) {
    if(level < CURRENT_LOG_LEVEL) return;

    va_list args;
    va_start(args, format);

    char* buffer = nullptr;
    int len = vasprintf(&buffer, format, args);
    va_end(args);

    if (len <= 0 || !buffer) return;

    // 分片写入，避免超长日志被单次输出截断。
    for (int i = 0; i < len; i += MAX_SEGMENT_LEN) {
        __android_log_print(level, tag, "[%s][%s][%d]%.*s", file_name, function_name, line_num, MAX_SEGMENT_LEN, buffer + i);
    }
    free(buffer);
}

