/*
 * [VMP_FLOW_NOTE] 文件级流程注释。
 * - 文件：patchbayModel/zPatchElf.cpp
 * - 主要职责：Patch ELF 主编排：负责补丁模型驱动下的装载、修改、重建与写回流程。
 * - 输入：ELF 原始字节、补丁模型状态以及段/节/符号元数据。
 * - 输出：经过校验的补丁模型或重建后的 ELF 输出数据。
 * - 关键约束：
 *   1) 严格保持 ELF 布局与索引一致性，避免地址/偏移漂移。
 *   2) 失败路径必须可定位（返回值/错误信息/日志三者保持一致）。
 *   3) 本文件改动优先保证与上游调用契约兼容，不隐式改变既有语义。
 */
#include "zPatchElf.h"
#include "zLog.h"
#include "zFile.h"

// 错误信息字符串。
#include <string>

/**
 * @file zPatchElf.cpp
 * @brief PatchElf 对外入口与最小流程调度。
 */

// 对外重构入口：委托到核心实现。
bool PatchElf::reconstruct() {
    // 当前只保留统一入口，实际逻辑由 reconstructionImpl 控制。
    return reconstructionImpl();
}

// 保存 ELF：若模型有脏数据则先重构，再写出 file_image_。
bool PatchElf::save(const char* outputPath) {
    // 输出路径不能为空。
    if (!outputPath) {
        return false;
    }
    // 模型有脏数据时先重构。
    if (reconstruction_dirty_ && !reconstruct()) {
        return false;
    }
    // 把 file_image_ 写入目标文件。
    if (!vmp::base::file::writeFileBytes(outputPath, file_image_)) {
        LOGE("Failed to write output file: %s", outputPath);
        return false;
    }
    return true;
}

// 判断当前对象是否处于“已加载可用”状态。
bool PatchElf::isLoaded() const {
    // 既要有字节镜像，也要通过 ELF64+AArch64 头校验才算“已加载”。
    return !file_image_.empty() && header_model_.isElf64AArch64();
}

// 返回当前内存镜像大小。
size_t PatchElf::getFileImageSize() const {
    // 可能尚未 save 到磁盘，这里返回内存态大小。
    return file_image_.size();
}

// 返回当前内存镜像首地址。
const uint8_t* PatchElf::getFileImageData() const {
    // 空镜像返回 nullptr，避免调用方误解为可访问缓冲。
    return file_image_.empty() ? nullptr : file_image_.data();
}

// 统一校验入口。
bool PatchElf::validate(std::string* error) const {
    // 把校验责任委托给 zElfValidator。
    return zElfValidator::validateAll(*this, error);
}

// 析构函数（当前无额外资源释放逻辑）。
PatchElf::~PatchElf() {
}

// 完整重构流程已从当前生产链路移除，保留失败返回避免误写文件。
bool PatchElf::reconstructionImpl() {
    LOGE("reconstructionImpl is removed from current patchbay runtime");
    return false;
}


