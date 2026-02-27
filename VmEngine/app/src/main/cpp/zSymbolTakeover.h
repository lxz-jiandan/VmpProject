/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - 符号接管模块接口声明。
 * - 加固链路位置：route4 L2 接口层。
 * - 输入：接管配置与映射。
 * - 输出：dispatch 能力与状态查询。
 */
#ifndef Z_SYMBOL_TAKEOVER_H
#define Z_SYMBOL_TAKEOVER_H

#include <cstdint>

// 注册接管模块：soId -> soName。
bool zSymbolTakeoverRegisterModule(uint32_t soId, const char* soName);

// 清理运行态接管状态（映射、句柄、缓存），用于回归/重复初始化场景。
void zSymbolTakeoverClear();

// 汇编符号桩统一跳转到该入口（a,b 保持在 x0/x1，symbol_key 走 x2，so_id 走 w3）。
extern "C" int vm_takeover_dispatch_by_key(int a, int b, uint64_t symbolKey, uint32_t soId);

#endif // Z_SYMBOL_TAKEOVER_H

