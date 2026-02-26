/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - PatchBay 数据结构与接口声明。
 * - 加固链路位置：补丁布局接口层。
 * - 输入：预留区元信息。
 * - 输出：补丁定位能力。
 */
#ifndef VMPROJECT_VMENGINE_ZPATCHBAY_H
#define VMPROJECT_VMENGINE_ZPATCHBAY_H

// 定宽整数用于固定头布局，避免不同 ABI 下大小变化。
#include <cstdint>
// 引入跨端共享 PatchBay 协议定义。
#include "shared/patchbay/zPatchbayProtocol.h"

// Route4 PatchBay 设计目标：
// 1) 在编译期预留一个“文件内可写区域”（.vmp_patchbay），避免后处理时重排整个 ELF。
// 2) 后处理工具只需把新的 dynsym/dynstr/hash/versym 写入该区域，再改写 DT_* 指针即可完成接管。
// 3) 运行时代码段/数据段尽量不变，降低补丁对原始 so 布局的扰动。
// 运行时协议头类型（直接复用共享定义）。
using zPatchBayHeader = vmp::patchbay::protocol::PatchBayHeader;
// 兼容旧常量名，避免调用侧大面积改名。
constexpr uint32_t kPatchBayMagic = vmp::patchbay::protocol::kPatchBayMagic;
constexpr uint16_t kPatchBayVersion = vmp::patchbay::protocol::kPatchBayVersion;
constexpr uint32_t kPatchBayDynsymCap = vmp::patchbay::protocol::kPatchBayDynsymCap;
constexpr uint32_t kPatchBayDynstrCap = vmp::patchbay::protocol::kPatchBayDynstrCap;
constexpr uint32_t kPatchBayGnuHashCap = vmp::patchbay::protocol::kPatchBayGnuHashCap;
constexpr uint32_t kPatchBaySysvHashCap = vmp::patchbay::protocol::kPatchBaySysvHashCap;
constexpr uint32_t kPatchBayVersymCap = vmp::patchbay::protocol::kPatchBayVersymCap;
constexpr uint32_t kPatchBayHeaderSize = vmp::patchbay::protocol::kPatchBayHeaderSize;
constexpr uint32_t kPatchBayDynsymOff = vmp::patchbay::protocol::kPatchBayDynsymOff;
constexpr uint32_t kPatchBayDynstrOff = vmp::patchbay::protocol::kPatchBayDynstrOff;
constexpr uint32_t kPatchBayGnuHashOff = vmp::patchbay::protocol::kPatchBayGnuHashOff;
constexpr uint32_t kPatchBaySysvHashOff = vmp::patchbay::protocol::kPatchBaySysvHashOff;
constexpr uint32_t kPatchBayVersymOff = vmp::patchbay::protocol::kPatchBayVersymOff;
constexpr uint32_t kPatchBayTotalSize = vmp::patchbay::protocol::kPatchBayTotalSize;
constexpr uint32_t kPatchBayPayloadSize = vmp::patchbay::protocol::kPatchBayPayloadSize;
// 协议大小一致性保护。
static_assert(sizeof(zPatchBayHeader) == sizeof(vmp::patchbay::protocol::PatchBayHeader),
              "zPatchBayHeader size changed unexpectedly");

struct zPatchBayImage {
    // 固定头，描述各区域偏移/容量与状态字段。
    zPatchBayHeader header;
    // 可写负载区，后处理工具在此写入新 dyn 表与 hash 表。
    uint8_t payload[kPatchBayPayloadSize];
};

// 导出运行时可见入口，便于 JNI/测试脚本读取 patch bay 元数据。
extern "C" const zPatchBayHeader* vm_get_patch_bay_header();

#endif  // VMPROJECT_VMENGINE_ZPATCHBAY_H
