/*
 * [VMP_FLOW_NOTE] zFunction 未编码缓存编排层。
 * - 本文件只保留缓存写入与翻译触发职责，避免承担具体汇编翻译细节。
 * - Capstone 解码与 AArch64->VM 映射已下沉到 zInstAsm，降低类职责耦合。
 */
#include "zFunction.h"
#include "zInstAsm.h"
#include "zLog.h"

#include <utility>
#include <algorithm>
#include <cinttypes>
#include <sstream>
#include <iomanip>

namespace {

static std::string buildBytesPreview(const uint8_t* data, size_t size, size_t maxBytes = 24) {
    if (data == nullptr || size == 0) {
        return "empty";
    }
    const size_t count = std::min(size, maxBytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    if (size > count) {
        oss << " ...";
    }
    return oss.str();
}

} // namespace

void zFunction::setUnencodedCache(
    uint32_t registerCount,
    std::vector<uint32_t> regIdList,
    uint32_t typeCount,
    std::vector<uint32_t> typeTags,
    uint32_t initValueCount,
    std::vector<uint32_t> preludeWords,
    std::map<uint64_t, std::vector<uint32_t>> instByAddress,
    std::map<uint64_t, std::string> instTextByAddress,
    uint32_t instCount,
    uint32_t branchCount,
    std::vector<uint32_t> branchWords,
    std::vector<uint32_t> branchLookupWords,
    std::vector<uint64_t> branchLookupAddrs,
    std::vector<uint64_t> branchAddrWords
) const {
    // 统一缓存写入口：
    // 文本导入路径与 Capstone 翻译路径都写入同一套缓存字段，避免双轨逻辑漂移。
    register_count_cache_ = registerCount;
    register_ids_cache_ = std::move(regIdList);
    type_count_cache_ = typeCount;
    type_tags_cache_ = std::move(typeTags);
    init_value_count_cache_ = initValueCount;
    prelude_words_cache_ = std::move(preludeWords);
    inst_words_by_addr_cache_ = std::move(instByAddress);
    inst_text_by_addr_cache_ = std::move(instTextByAddress);
    inst_count_cache_ = instCount;
    branch_count_cache_ = branchCount;
    branch_words_cache_ = std::move(branchWords);
    branch_lookup_words_cache_ = std::move(branchLookupWords);
    branch_lookup_addrs_cache_ = std::move(branchLookupAddrs);
    branch_addrs_cache_ = std::move(branchAddrWords);
    unencoded_translate_ok_ = true;
    unencoded_translate_error_.clear();
    unencoded_ready_ = true;
}

void zFunction::ensureUnencodedReady() const {
    // 快速路径：缓存已经可用时直接返回。
    if (unencoded_ready_) {
        return;
    }

    // 原始机器码为空时没有翻译源，直接写空缓存并标记失败。
    if (!getData() || getSize() == 0) {
        setUnencodedCache(0, {}, 0, {}, 0, {}, {}, {}, 0, 0, {}, {}, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = "function bytes are empty";
        return;
    }

    // 汇编解码与指令翻译职责全部委托到 zInstAsm。
    zInstAsmUnencodedBytecode unencoded = zInstAsm::buildUnencodedBytecode(getData(), getSize(), getOffset());

    if (!unencoded.translationOk) {
        setUnencodedCache(0, {}, 0, {}, 0, {}, {}, {}, 0, 0, {}, {}, {}, {});
        unencoded_translate_ok_ = false;
        unencoded_translate_error_ = unencoded.translationError.empty()
                                     ? "capstone translation failed"
                                     : unencoded.translationError;
        const std::string bytes_preview = buildBytesPreview(getData(), getSize());
        LOGE("ensureUnencodedReady failed for %s: %s (offset=0x%" PRIx64 ", size=%zu, bytes=[%s])",
             function_name.c_str(),
             unencoded_translate_error_.c_str(),
             static_cast<uint64_t>(getOffset()),
             getSize(),
             bytes_preview.c_str());
        return;
    }

    setUnencodedCache(
        unencoded.registerCount,
        std::move(unencoded.regList),
        unencoded.typeCount,
        std::move(unencoded.typeTags),
        unencoded.initValueCount,
        std::move(unencoded.preludeWords),
        std::move(unencoded.instByAddress),
        std::move(unencoded.asmByAddress),
        unencoded.instCount,
        unencoded.branchCount,
        std::move(unencoded.branchWords),
        std::move(unencoded.branchLookupWords),
        std::move(unencoded.branchLookupAddrs),
        std::move(unencoded.branchAddrWords)
    );
}
