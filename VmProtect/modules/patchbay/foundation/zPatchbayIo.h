#ifndef VMPROTECT_PATCHBAY_IO_H
#define VMPROTECT_PATCHBAY_IO_H

// 引入字节类型。
#include <cstdint>
// 引入动态字节数组容器。
#include <vector>

// 读取整文件到字节数组。
// 入参：
// - path: 输入文件路径。
// - out: 输出字节数组指针。
// 出参：
// - out: 成功时写入完整文件内容。
// 返回：
// - true: 读取成功。
// - false: 路径无效或读取失败。
bool loadFileBytes(const char* path, std::vector<uint8_t>* out);

// 将字节数组覆盖写回文件。
// 入参：
// - path: 输出文件路径。
// - bytes: 待写入字节数据。
// 返回：
// - true: 写入成功。
// - false: 路径无效或写入失败。
bool saveFileBytes(const char* path, const std::vector<uint8_t>& bytes);

#endif // VMPROTECT_PATCHBAY_IO_H
