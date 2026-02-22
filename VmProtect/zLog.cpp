/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 离线工具日志实现，统一调试/错误输出。
 * - 加固链路位置：离线工具观测层。
 * - 输入：日志级别与格式化参数。
 * - 输出：控制台可读日志。
 */
#include "zLog.h"
#include <cstdio>   // printf / vsnprintf。
#include <cstdlib>  // 保留：兼容历史实现可能引入的标准库依赖。
#include <cstdarg>  // va_list / va_start / va_end。
#include <cstring>  // 保留：兼容历史实现可能引入的字符串操作。

// 单次格式化缓冲长度上限（含结尾 '\0'）。
#define MAX_LOG_BUF_LEN 3000
// 分片长度常量（当前实现控制台输出可不分片，保留兼容字段）。
#define MAX_SEGMENT_LEN 3000

// 控制台日志实现：先格式化，再按最终文本输出。
void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...) {
    // 小于阈值的日志直接忽略，减少高频路径开销。
    if(level < CURRENT_LOG_LEVEL) return;

    // 初始化可变参数读取。
    va_list args;
    va_start(args, format);

    // 先把可变参数格式化到固定缓冲区，避免重复遍历参数列表。
    char buffer[MAX_LOG_BUF_LEN];
    // 安全格式化，自动截断超长内容。
    vsnprintf(buffer, sizeof(buffer), format, args);
    // 结束可变参数读取。
    va_end(args);

    // 根据 level 生成可读字符串：
    // 当前默认模板未直接输出该字段，但保留映射便于后续切换模板。
    const char* level_str = "INFO";
    if (level == LOG_LEVEL_ERROR) level_str = "ERROR";
    else if (level == LOG_LEVEL_WARN) level_str = "WARN";
    else if (level == LOG_LEVEL_DEBUG) level_str = "DEBUG";
    else if (level == LOG_LEVEL_VERBOSE) level_str = "VERBOSE";

    // 如需带位置信息的完整输出，可打开下面一行。
    // 示例：printf("[%s][%s][%s:%d] %s\n", level_str, function_name, file_name, line_num, buffer);
    // 当前实现不使用以下参数，显式 (void) 抑制“未使用形参”告警。
    (void)tag;
    (void)file_name;
    (void)function_name;
    (void)line_num;
    (void)level_str;
    // 当前默认只输出消息正文，保持回归日志简洁。
    printf("%s\n", buffer);
    // 这里不主动 flush，沿用 C 运行时标准缓冲策略。
    (void)MAX_SEGMENT_LEN;
}

