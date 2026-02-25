/*
 * [VMP_FLOW_NOTE] 文件级流程注释
 * - zFunction 数据结构与翻译 API 声明。
 * - 加固链路位置：离线翻译接口层。
 * - 输入：函数原始数据与上下文。
 * - 输出：编码结果与调试导出能力。
 */
#ifndef VMPROTECT_ZFUNCTION_H
#define VMPROTECT_ZFUNCTION_H

#include "zElfTypes.h"
#include "zInst.h"
#include "zFunctionData.h"
#include <string>
#include <vector>
#include <map>
#include <cstddef>
#include <cstdint>

class zFunction : public zFunctionData {
public:
    // 导出模式：
    // `UNENCODED`      生成历史文本格式（fun_xxx.txt），用于人工排查与文本回归。
    // `UNENCODED_BIN`  生成未编码二进制中间格式，便于快速加载和比对。
    // `ENCODED`        生成最终压缩编码格式，供引擎侧高效加载执行。
    enum class DumpMode {
        UNENCODED,
        UNENCODED_BIN,
        ENCODED,
    };

    // 基于现有 `zFunctionData` 构造函数对象。
    // 说明：`zFunction` 是在数据结构之上附加“分析与导出能力”的薄封装。
    explicit zFunction(const zFunctionData& data);

    // 基础访问器：
    // `name`   返回函数逻辑名；
    // `offset` 返回函数地址信息；
    // `size`   返回原始机器码长度；
    // `data`   返回原始机器码首地址；
    // `empty`  判空快捷接口。
    const std::string& getName() const;
    Elf64_Addr getOffset() const;
    size_t getSize() const;
    const uint8_t* getData() const;
    bool isEmpty() const;

    // 反汇编分析与输出：
    // `analyzeAssembly` 触发惰性分析；
    // `getAssemblyList` 返回结构化指令列表；
    // `getAssemblyInfo` 返回可读文本。
    zFunction& analyzeAssembly();
    const std::vector<zInst>& getAssemblyList() const;
    std::string getAssemblyInfo() const;

    // 按指定模式导出到文件路径。
    // 返回 true 表示导出成功，false 表示失败（失败原因在日志中）。
    bool dump(const char* filePath, DumpMode mode) const;

    // 触发一次翻译准备并返回是否成功。
    // 失败时可选写出错误文本，便于上层聚合覆盖统计。
    bool prepareTranslation(std::string* error = nullptr) const;

    // 返回最近一次翻译错误文本（成功时为空）。
    const std::string& getLastTranslationError() const;

    // 读取当前未编码缓存中的全局 `branch_addr_list`。
    // 若缓存尚未准备，会触发懒加载翻译流程。
    const std::vector<uint64_t>& getSharedBranchAddrs() const;

    // 将本函数内 `OP_BL` 的“局部索引”重映射到“全局索引”。
    // 成功后会把缓存中的 `branch_addrs_cache_` 替换成共享全局地址表。
    bool remapBlToSharedBranchAddrs(const std::vector<uint64_t>& sharedBranchAddrs);

private:
    // 确保反汇编缓存可用（惰性构建）。
    void ensureAsmReady() const;
    // 确保未编码缓存可用（惰性构建）。
    void ensureUnencodedReady() const;

    // 更新未编码缓存快照：
    // 文本导入路径与机器码翻译路径都统一写入该缓存，减少分叉逻辑。
    void setUnencodedCache(
        uint32_t registerCount,
        std::vector<uint32_t> regIdList,
        uint32_t typeCount,
        std::vector<uint32_t> typeTags,
        uint32_t initValueCount,
        std::map<uint64_t, std::vector<uint32_t>> instByAddress,
        std::map<uint64_t, std::string> asmByAddress,
        uint32_t instCount,
        uint32_t branchCount,
        std::vector<uint32_t> branchWords,
        std::vector<uint64_t> branchAddrWords
    ) const;

    // 用未编码缓存重建 `asm_list_` 展示结果。
    // 该路径主要用于避免重复依赖 Capstone 做反汇编。
    void rebuildAsmListFromUnencoded() const;

    // `asm_ready_`：`asm_list_` 是否已构建完成。
    mutable bool asm_ready_ = false;
    // 反汇编展示列表（供 UI/日志输出）。
    mutable std::vector<zInst> asm_list_;

    // `unencoded_ready_`：未编码缓存是否可直接复用。
    mutable bool unencoded_ready_ = false;
    // `unencoded_translate_ok_`：最近一次翻译是否成功。
    mutable bool unencoded_translate_ok_ = true;
    // `unencoded_translate_error_`：最近一次翻译失败时的错误文本。
    mutable std::string unencoded_translate_error_;
    // 缓存的寄存器槽总数。
    mutable uint32_t register_count_cache_ = 0;
    // 缓存的寄存器索引列表（reg_id_list）。
    mutable std::vector<uint32_t> register_ids_cache_;
    // 缓存的类型数量。
    mutable uint32_t type_count_cache_ = 0;
    // 缓存的类型标签列表（type_id_list）。
    mutable std::vector<uint32_t> type_tags_cache_;
    // 缓存的初始化值条目数。
    mutable uint32_t init_value_count_cache_ = 0;
    // 缓存的“地址 -> opcode words”映射。
    mutable std::map<uint64_t, std::vector<uint32_t>> inst_words_by_addr_cache_;
    // 缓存的“地址 -> 汇编文本”映射。
    mutable std::map<uint64_t, std::string> asm_text_by_addr_cache_;
    // 缓存的 inst 总 word 数。
    mutable uint32_t inst_count_cache_ = 0;
    // 缓存的本地分支数量。
    mutable uint32_t branch_count_cache_ = 0;
    // 缓存的本地分支表（branch_id_list）。
    mutable std::vector<uint32_t> branch_words_cache_;
    // 缓存的全局调用目标地址表（branch_addr_list）。
    mutable std::vector<uint64_t> branch_addrs_cache_;
};

#endif

