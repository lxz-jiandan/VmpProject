#include "zFileBytes.h"

// open 标志位。
#include <fcntl.h>
// ifstream。
#include <fstream>
// open/write/close。
#include <unistd.h>

namespace zFileBytes {

// 二进制读取整个文件到内存。
bool readFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    // 先清空输出，避免失败时残留旧数据。
    out.clear();
    // 路径不能为空。
    if (path.empty()) {
        return false;
    }

    // 以二进制方式打开文件。
    std::ifstream in(path, std::ios::binary);
    // 打开失败直接返回。
    if (!in) {
        return false;
    }

    // 定位到末尾读取总长度。
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    // tellg 返回负值表示流状态异常。
    if (size < 0) {
        return false;
    }
    // 回到开头准备读取内容。
    in.seekg(0, std::ios::beg);

    // 按文件大小分配输出缓冲。
    out.resize(static_cast<size_t>(size));
    // 非空时才执行 read，避免传入空指针。
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }
    // 返回流状态，确保读取过程完整成功。
    return static_cast<bool>(in);
}

// 以“覆盖写”方式把内存字节写入文件。
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    // 路径不能为空。
    if (path.empty()) {
        return false;
    }

    // 以 0600 权限新建/截断写入，避免其它用户读取。
    int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    // 打开失败。
    if (fd < 0) {
        return false;
    }

    // 当前写入指针；空数据时保持 nullptr。
    const uint8_t* ptr = data.empty() ? nullptr : data.data();
    // 剩余未写字节数。
    size_t remain = data.size();
    // 循环写，处理短写场景。
    while (remain > 0) {
        // 一次 write 可能只写入部分字节。
        const ssize_t wrote = write(fd, ptr, remain);
        // <=0 表示错误或异常中止。
        if (wrote <= 0) {
            close(fd);
            return false;
        }
        // 前移指针到下一段待写位置。
        ptr += wrote;
        // 扣减已写长度。
        remain -= static_cast<size_t>(wrote);
    }
    // 全部写完后关闭文件描述符。
    close(fd);
    return true;
}

} // namespace zFileBytes
