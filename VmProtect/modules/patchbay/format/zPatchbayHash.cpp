#include "zPatchbayHash.h"

// 引入字节序列化工具。
#include "zCodec.h"
// 引入基础 hash 算法与 bucket 选择策略。
#include "zHash.h"

// 进入匿名命名空间，收敛内部辅助函数。
namespace {

// 序列化 SYSV hash payload。
// 输出格式：
// [nbucket(u32), nchain(u32), buckets[nbucket], chains[nchain]]
std::vector<uint8_t> serializeSysvHashPayload(const uint32_t nbucket,
                                              const uint32_t nchain,
                                              const std::vector<uint32_t>& buckets,
                                              const std::vector<uint32_t>& chains) {
    // 预留目标容量，避免多次扩容。
    std::vector<uint8_t> payload;
    payload.reserve(static_cast<size_t>(2 + buckets.size() + chains.size()) * sizeof(uint32_t));
    // 写入 nbucket。
    vmp::base::codec::appendU32Le(&payload, nbucket);
    // 写入 nchain。
    vmp::base::codec::appendU32Le(&payload, nchain);
    // 写入 bucket 数组。
    vmp::base::codec::appendU32LeArray(&payload, buckets.data(), buckets.size());
    // 写入 chain 数组。
    vmp::base::codec::appendU32LeArray(&payload, chains.data(), chains.size());
    return payload;
}

// 结束匿名命名空间。
}  // namespace

// 对外导出 SYSV hash 算法入口。
uint32_t elfSysvHash(const char* name) {
    return vmp::base::hash::elfSysvHash(name);
}

// 对外导出 bucket 选择策略。
uint32_t chooseBucketCount(uint32_t nchain) {
    return vmp::base::hash::chooseBucketCount(nchain);
}

// 读取 dynstr 中 offset 对应的符号名指针。
static const char* dynstrNameAt(const std::vector<uint8_t>& dynstrBytes, uint32_t offset) {
    // 偏移越界直接返回空指针。
    if (offset >= dynstrBytes.size()) {
        return nullptr;
    }
    // 返回 dynstr 起点 + offset 的 C 字符串指针。
    return reinterpret_cast<const char*>(dynstrBytes.data() + offset);
}

// 构建 SYSV hash（.hash）内容。
std::vector<uint8_t> buildSysvHashPayloadFromBytes(const std::vector<Elf64_Sym>& dynsymSymbols,
                                                   const std::vector<uint8_t>& dynstrBytes) {
    // 空 dynsym 无法构建合法 hash 表。
    if (dynsymSymbols.empty()) {
        return {};
    }

    // nchain 等于 dynsym 条目总数。
    const uint32_t nchain = static_cast<uint32_t>(dynsymSymbols.size());
    // 根据 nchain 选择 bucket 数。
    const uint32_t nbucket = chooseBucketCount(nchain);
    // 初始化 bucket 数组（0 表示空桶）。
    std::vector<uint32_t> buckets(nbucket, 0);
    // 初始化 chain 数组（0 表示链尾）。
    std::vector<uint32_t> chains(nchain, 0);

    // 从 1 开始（跳过 STN_UNDEF）。
    for (uint32_t symIndex = 1; symIndex < nchain; ++symIndex) {
        const Elf64_Sym& sym = dynsymSymbols[symIndex];
        // 从 dynstr 解析符号名。
        const char* name = dynstrNameAt(dynstrBytes, sym.st_name);
        // 空名符号跳过。
        if (name == nullptr || name[0] == '\0') {
            continue;
        }
        // 计算 SYSV hash。
        const uint32_t h = elfSysvHash(name);
        // 映射到 bucket。
        const uint32_t b = h % nbucket;
        // 桶为空时当前符号直接作为桶首。
        if (buckets[b] == 0) {
            buckets[b] = symIndex;
            continue;
        }
        // 桶非空时挂到链尾。
        uint32_t cursor = buckets[b];
        while (chains[cursor] != 0) {
            cursor = chains[cursor];
        }
        chains[cursor] = symIndex;
    }

    // 输出序列化结果。
    return serializeSysvHashPayload(nbucket, nchain, buckets, chains);
}

// 对外导出 GNU hash 算法入口。
uint32_t elfGnuHash(const char* name) {
    return vmp::base::hash::elfGnuHash(name);
}

// 构建 GNU hash（.gnu.hash）内容。
std::vector<uint8_t> buildGnuHashPayloadFromBytes(const std::vector<Elf64_Sym>& dynsymSymbols,
                                                  const std::vector<uint8_t>& dynstrBytes) {
    // 只有 STN_UNDEF 时没有可参与哈希的符号。
    if (dynsymSymbols.size() <= 1) {
        return {};
    }

    // 符号总数。
    const uint32_t nchain = static_cast<uint32_t>(dynsymSymbols.size());
    // 第一个可哈希符号索引（跳过 STN_UNDEF）。
    const uint32_t symoffset = 1;
    // patchbay 模式保持 dynsym 原顺序，不做 GNU 规则重排。
    // 为降低重排风险，这里固定使用单 bucket 模型。
    const uint32_t nbuckets = 1;
    // bloom 词个数固定为 1。
    const uint32_t bloomSize = 1;
    // bloom 第二位偏移。
    const uint32_t bloomShift = 6;

    // 初始化 bloom 过滤器区。
    std::vector<uint64_t> bloom(bloomSize, 0);
    // 初始化 bucket 区。
    std::vector<uint32_t> buckets(nbuckets, 0);
    // 初始化 chain 区（覆盖 [symoffset, nchain)）。
    std::vector<uint32_t> chain(nchain > symoffset ? (nchain - symoffset) : 0, 0);
    // 记录每个桶最后一个符号索引，用于设置 chain 尾标记位。
    std::vector<uint32_t> lastInBucket(nbuckets, 0);

    // 第一遍：填充 bucket、bloom 和 lastInBucket。
    for (uint32_t symbolIndex = symoffset; symbolIndex < nchain; ++symbolIndex) {
        const Elf64_Sym& symbol = dynsymSymbols[symbolIndex];
        const char* symbolName = dynstrNameAt(dynstrBytes, symbol.st_name);
        if (symbolName == nullptr || symbolName[0] == '\0') {
            continue;
        }
        const uint32_t hashValue = elfGnuHash(symbolName);
        const uint32_t bucketIndex = hashValue % nbuckets;
        if (buckets[bucketIndex] == 0) {
            // 记录桶中第一个符号。
            buckets[bucketIndex] = symbolIndex;
        }
        // 持续更新桶尾索引。
        lastInBucket[bucketIndex] = symbolIndex;
        // 计算 bloom 词索引。
        const uint32_t bloomWordIndex = (hashValue / 64U) % bloomSize;
        // 计算 bloom 第一位。
        const uint32_t bit1 = hashValue % 64U;
        // 计算 bloom 第二位。
        const uint32_t bit2 = (hashValue >> bloomShift) % 64U;
        // 设置 bloom 位。
        bloom[bloomWordIndex] |= (1ULL << bit1) | (1ULL << bit2);
    }

    // 第二遍：构建 chain 值，桶尾元素最低位置 1。
    for (uint32_t symbolIndex = symoffset; symbolIndex < nchain; ++symbolIndex) {
        const Elf64_Sym& symbol = dynsymSymbols[symbolIndex];
        const char* symbolName = dynstrNameAt(dynstrBytes, symbol.st_name);
        if (symbolName == nullptr || symbolName[0] == '\0') {
            continue;
        }
        const uint32_t hashValue = elfGnuHash(symbolName);
        const uint32_t bucketIndex = hashValue % nbuckets;
        const uint32_t chainIndex = symbolIndex - symoffset;
        // 链值保留高 31 位哈希，最低位留给“桶尾标记”。
        uint32_t chainValue = hashValue & ~1U;
        if (symbolIndex == lastInBucket[bucketIndex]) {
            chainValue |= 1U;
        }
        if (chainIndex < chain.size()) {
            chain[chainIndex] = chainValue;
        }
    }

    // 序列化输出：
    // header(4*u32) + bloom + buckets + chain。
    std::vector<uint8_t> payload;
    payload.reserve(sizeof(uint32_t) * 4 +
                    sizeof(uint64_t) * bloom.size() +
                    sizeof(uint32_t) * buckets.size() +
                    sizeof(uint32_t) * chain.size());
    vmp::base::codec::appendU32Le(&payload, nbuckets);
    vmp::base::codec::appendU32Le(&payload, symoffset);
    vmp::base::codec::appendU32Le(&payload, static_cast<uint32_t>(bloom.size()));
    vmp::base::codec::appendU32Le(&payload, bloomShift);
    vmp::base::codec::appendU64LeArray(&payload, bloom.data(), bloom.size());
    vmp::base::codec::appendU32LeArray(&payload, buckets.data(), buckets.size());
    vmp::base::codec::appendU32LeArray(&payload, chain.data(), chain.size());
    return payload;
}
