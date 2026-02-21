// vasprintf/free 定义。
#include <stdlib.h>
#include "zLog.h"

// 单次格式化缓冲最大长度（保留兼容常量，当前实现主要用 vasprintf 动态分配）。
#define MAX_LOG_BUF_LEN 3000
// 每次写入 logcat 的分片长度，避免超长日志被系统截断。
#define MAX_SEGMENT_LEN 3000


// 统一日志实现：格式化后按固定分片写入 Android 日志系统。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...) {
    // 小于当前阈值的日志直接丢弃。
    if(level < CURRENT_LOG_LEVEL) return;

    // 初始化可变参数列表。
    va_list args;
    va_start(args, format);

    // 动态分配格式化缓冲并写入完整日志文本。
    char* buffer = nullptr;
    int len = vasprintf(&buffer, format, args);
    // 参数读取结束，及时关闭 va_list。
    va_end(args);

    // 格式化失败或未分配缓冲时直接返回。
    if (len <= 0 || !buffer) return;

    // 分片写入，避免超长日志被单次输出截断。
    for (int i = 0; i < len; i += MAX_SEGMENT_LEN) {
        // 每片都补充文件/函数/行号，方便定位来源。
        __android_log_print(level, tag, "[%s][%s][%d]%.*s", file_name, function_name, line_num, MAX_SEGMENT_LEN, buffer + i);
    }
    // 释放 vasprintf 分配的堆内存。
    free(buffer);
}

