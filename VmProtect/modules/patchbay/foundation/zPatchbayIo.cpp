#include "zPatchbayIo.h"

// 引入基础 IO 实现。
#include "zIo.h"

// 读取整文件字节。
bool loadFileBytes(const char* path, std::vector<uint8_t>* out) {
    // 直接委托给基础层 readFileBytes。
    return vmp::base::io::readFileBytes(path, out);
}

// 覆盖写回整文件字节。
bool saveFileBytes(const char* path, const std::vector<uint8_t>& bytes) {
    // 输出路径为空时直接失败。
    if (path == nullptr) {
        return false;
    }
    // 直接委托给基础层 writeFileBytes。
    return vmp::base::io::writeFileBytes(path, bytes);
}

