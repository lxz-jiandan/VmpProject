// 段校验实现：负责 Program Header 与 Section/Segment 映射的一致性检查。
#include "zPatchElfValidator.h"

// PatchElf 聚合模型定义。
#include "zPatchElf.h"
// 通用校验工具（对齐/溢出/区间工具）。
#include "zPatchElfUtils.h"

// 区间运算辅助。
#include <algorithm>
// 错误信息拼接。
#include <string>

namespace {

// 向下按对齐粒度取整。
// 例：alignDownU64(0x1234, 0x1000) -> 0x1000。
uint64_t alignDownU64(uint64_t value, uint64_t align) {
    // align=0 时不做任何处理，直接返回原值。
    if (align == 0) {
        return value;
    }
    // 按 2 的幂对齐向下取整。
    return value & ~(align - 1ULL);
}

// 判断两个 PT_LOAD 的重叠是否属于可接受特例。
// 规则：
// 1) 仅 PT_LOAD 参与；
// 2) VA/OFFSET 映射增量必须一致；
// 3) 重叠范围不得超过一页；
// 4) 若存在重叠，需限制在同一页内。
bool isLoadOverlapOk(const zProgramTableElement& a,
                     const zProgramTableElement& b,
                     uint64_t pageSize) {
    // 非 LOAD 段不做这条重叠规则校验。
    if (a.type != PT_LOAD || b.type != PT_LOAD) {
        return true;
    }

    // 计算文件区间重叠范围起点。
    const uint64_t overlap_file_begin = std::max<uint64_t>(a.offset, b.offset);
    // 计算文件区间重叠范围终点（开区间右端）。
    const uint64_t overlap_file_end = std::min<uint64_t>(a.offset + a.filesz, b.offset + b.filesz);
    // 计算文件区间重叠字节数。
    const uint64_t overlap_file_size = overlap_file_end > overlap_file_begin ? overlap_file_end - overlap_file_begin : 0;

    // 计算虚拟地址区间重叠范围起点。
    const uint64_t overlap_va_begin = std::max<uint64_t>(a.vaddr, b.vaddr);
    // 计算虚拟地址区间重叠范围终点（开区间右端）。
    const uint64_t overlap_va_end = std::min<uint64_t>(a.vaddr + a.memsz, b.vaddr + b.memsz);
    // 计算虚拟地址区间重叠字节数。
    const uint64_t overlap_va_size = overlap_va_end > overlap_va_begin ? overlap_va_end - overlap_va_begin : 0;

    // 文件区间与 VA 区间都不重叠，直接认为可接受。
    if (overlap_file_size == 0 && overlap_va_size == 0) {
        return true;
    }

    // 计算 VA-OFFSET 的线性映射增量。
    const int64_t delta_a = (int64_t)a.vaddr - (int64_t)a.offset;
    // 计算另一段的映射增量。
    const int64_t delta_b = (int64_t)b.vaddr - (int64_t)b.offset;
    // 增量不一致说明两段映射关系不同，不允许重叠。
    if (delta_a != delta_b) {
        return false;
    }

    // 若无法推断页大小，回退 4KB。
    const uint64_t checked_page = pageSize == 0 ? 0x1000ULL : pageSize;
    // 文件或 VA 的重叠超过一页，认为风险过高。
    if (overlap_file_size > checked_page || overlap_va_size > checked_page) {
        return false;
    }

    // 若文件区间有重叠，要求重叠必须在同一页内。
    if (overlap_file_size > 0) {
        // 重叠起点所在页。
        const uint64_t first_page = alignDownU64(overlap_file_begin, checked_page);
        // 重叠终点前一字节所在页。
        const uint64_t last_page = alignDownU64(overlap_file_end - 1, checked_page);
        // 跨页则拒绝。
        if (first_page != last_page) {
            return false;
        }
    }

    // 若 VA 区间有重叠，同样要求重叠在同一页。
    if (overlap_va_size > 0) {
        // VA 重叠起点页。
        const uint64_t first_page = alignDownU64(overlap_va_begin, checked_page);
        // VA 重叠终点前一字节页。
        const uint64_t last_page = alignDownU64(overlap_va_end - 1, checked_page);
        // 跨页则拒绝。
        if (first_page != last_page) {
            return false;
        }
    }

    // 满足所有特例条件，允许重叠。
    return true;
}

} // namespace

// 段布局校验：对齐、覆盖、PT_PHDR/PT_DYNAMIC/PT_INTERP 等关键约束。
bool zElfValidator::validateProgramSegmentLayout(const PatchElf& elf, std::string* error) {
    // 读取 Program Header 列表。
    const auto& phs = elf.getProgramHeaderModel().elements;
    // 空表直接失败。
    if (phs.empty()) {
        if (error) {
            *error = "Program header table is empty";
        }
        return false;
    }

    // 文件镜像总大小。
    const size_t file_size = elf.getFileImageSize();
    // 由段信息推断运行时页大小。
    const uint64_t runtime_page_size = inferRuntimePageSizeFromPhdrs(phs);
    // 按 e_phnum 计算理论 phdr 区域大小。
    const uint64_t expected_phdr_size = (uint64_t)elf.getHeaderModel().raw.e_phnum * sizeof(Elf64_Phdr);

    // PT_LOAD 计数。
    int load_count = 0;
    // 是否存在 PT_GNU_RELRO。
    bool has_gnu_relro = false;
    // 是否存在 PT_TLS。
    bool has_tls = false;
    // 缓存 RELRO 段。
    zProgramTableElement gnu_relro;
    // 缓存 TLS 段。
    zProgramTableElement tls_segment;

    // 第一轮：逐段做本段约束校验。
    for (size_t programHeaderIndex = 0; programHeaderIndex < phs.size(); ++programHeaderIndex) {
        // 当前段引用。
        const auto& ph = phs[programHeaderIndex];

        // 统计 LOAD 段数量。
        if (ph.type == PT_LOAD) {
            ++load_count;
        }
        // 记录 RELRO 段。
        if (ph.type == PT_GNU_RELRO) {
            has_gnu_relro = true;
            gnu_relro = ph;
        }
        // 记录 TLS 段。
        if (ph.type == PT_TLS) {
            has_tls = true;
            tls_segment = ph;
        }

        // 对齐检查：p_align>1 时必须是 2 的幂，且 offset/vaddr 同余。
        if (ph.align > 1) {
            // p_align 非 2 的幂直接失败。
            if (!isPowerOfTwoU64(ph.align)) {
                if (error) {
                    *error = "p_align is not power-of-two at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
            // ELF 约束：p_offset % p_align 必须等于 p_vaddr % p_align。
            if ((ph.offset % ph.align) != (ph.vaddr % ph.align)) {
                if (error) {
                    *error = "p_offset % p_align != p_vaddr % p_align at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
        }

        // 文件区间检查：filesz 区间必须完全落在文件内。
        if (ph.filesz > 0) {
            // 段文件末尾。
            uint64_t end = 0;
            // 加法溢出或越过文件末尾都视为非法。
            if (!addU64Checked(ph.offset, ph.filesz, &end) || end > file_size) {
                if (error) {
                    *error = "Segment file range out of file at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
        }

        // 虚拟地址区间检查：防止 vaddr+memsz 溢出。
        if (ph.memsz > 0) {
            // 段虚拟地址末尾。
            uint64_t vaddr_end = 0;
            // 发生溢出直接失败。
            if (!addU64Checked(ph.vaddr, ph.memsz, &vaddr_end)) {
                if (error) {
                    *error = "Segment virtual range overflow at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
        }

        // PT_PHDR 专项检查。
        if (ph.type == PT_PHDR) {
            // PHDR 段至少要能容纳完整 PHDR 表，且 memsz>=filesz。
            if (ph.filesz < expected_phdr_size || ph.memsz < ph.filesz) {
                if (error) {
                    *error = "PT_PHDR size mismatch at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
            // PHDR 文件起点。
            const uint64_t phdr_begin = ph.offset;
            // PHDR 文件终点（开区间）。
            const uint64_t phdr_end = ph.offset + ph.filesz;
            // 记录是否被某个 PT_LOAD 覆盖。
            bool covered_by_load = false;
            // 在 LOAD 段中寻找覆盖它的映射关系。
            for (const auto& load : phs) {
                // 仅关注有文件内容的 LOAD 段。
                if (load.type != PT_LOAD || load.filesz == 0) {
                    continue;
                }
                // LOAD 文件起点。
                const uint64_t load_begin = load.offset;
                // LOAD 文件终点（开区间）。
                const uint64_t load_end = load.offset + load.filesz;
                // PHDR 区间不在该 LOAD 内则跳过。
                if (phdr_begin < load_begin || phdr_end > load_end) {
                    continue;
                }
                // 按文件位移推导 PHDR 应有的虚拟地址。
                const uint64_t expected_vaddr = (uint64_t)load.vaddr + (phdr_begin - load_begin);
                // vaddr 或 paddr 与推导值不一致则失败。
                if ((uint64_t)ph.vaddr != expected_vaddr || (uint64_t)ph.paddr != expected_vaddr) {
                    if (error) {
                        *error = "PT_PHDR vaddr/paddr mismatch at phdr index " +
                                 std::to_string(programHeaderIndex);
                    }
                    return false;
                }
                // 命中覆盖。
                covered_by_load = true;
                break;
            }
            // 未被任何 LOAD 覆盖则失败。
            if (!covered_by_load) {
                if (error) {
                    *error = "PT_PHDR is not covered by any PT_LOAD at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
        }

        // PT_DYNAMIC 专项检查。
        if (ph.type == PT_DYNAMIC && ph.filesz > 0) {
            // 动态段文件起点。
            const uint64_t dyn_begin = ph.offset;
            // 动态段文件终点（开区间）。
            const uint64_t dyn_end = ph.offset + ph.filesz;
            // 标记是否映射到某个 LOAD。
            bool mapped = false;
            // 在 LOAD 段中寻找包含它的映射。
            for (const auto& load : phs) {
                // 仅关注有文件内容的 LOAD 段。
                if (load.type != PT_LOAD || load.filesz == 0) {
                    continue;
                }
                // LOAD 文件起点。
                const uint64_t load_begin = load.offset;
                // LOAD 文件终点（开区间）。
                const uint64_t load_end = load.offset + load.filesz;
                // 动态段不在该 LOAD 内则继续找。
                if (dyn_begin < load_begin || dyn_end > load_end) {
                    continue;
                }
                // 推导 dynamic 段应有虚拟地址。
                const uint64_t expected_vaddr = (uint64_t)load.vaddr + (dyn_begin - load_begin);
                // vaddr 不匹配则失败。
                if ((uint64_t)ph.vaddr != expected_vaddr) {
                    if (error) {
                        *error = "PT_DYNAMIC vaddr mismatch at phdr index " +
                                 std::to_string(programHeaderIndex);
                    }
                    return false;
                }
                // 映射关系成立。
                mapped = true;
                break;
            }
            // 没有任何 LOAD 覆盖 PT_DYNAMIC 则失败。
            if (!mapped) {
                if (error) {
                    *error = "PT_DYNAMIC is not covered by any PT_LOAD at phdr index " +
                             std::to_string(programHeaderIndex);
                }
                return false;
            }
        }
    }

    // 至少要有一个 PT_LOAD。
    if (load_count == 0) {
        if (error) {
            *error = "No PT_LOAD segments found";
        }
        return false;
    }

    // RELRO 检查：PT_GNU_RELRO 必须位于可写 LOAD 内（满足装载前可写后保护的语义）。
    if (has_gnu_relro && gnu_relro.memsz > 0) {
        // RELRO 起始虚拟地址。
        const uint64_t relro_begin = (uint64_t)gnu_relro.vaddr;
        // RELRO 结束虚拟地址（开区间）。
        const uint64_t relro_end = relro_begin + (uint64_t)gnu_relro.memsz;

        // 记录是否被可写 LOAD 覆盖。
        bool relro_covered = false;
        // 在所有 LOAD 中找“可写且覆盖 RELRO”的段。
        for (const auto& load : phs) {
            // 仅保留可写 LOAD。
            if (load.type != PT_LOAD || (load.flags & PF_W) == 0) {
                continue;
            }
            // LOAD 虚拟地址起点。
            const uint64_t load_begin = (uint64_t)load.vaddr;
            // LOAD 虚拟地址终点（开区间）。
            const uint64_t load_end = load_begin + (uint64_t)load.memsz;
            // 覆盖成功。
            if (relro_begin >= load_begin && relro_end <= load_end) {
                relro_covered = true;
                break;
            }
        }

        // 找不到覆盖段则失败。
        if (!relro_covered) {
            if (error) {
                *error = "PT_GNU_RELRO is not fully covered by a writable PT_LOAD";
            }
            return false;
        }
    }

    // TLS 检查：PT_TLS 的文件区间/VA 区间都必须被某个 LOAD 覆盖。
    if (has_tls) {
        // 标记是否找到覆盖段。
        bool tls_covered = false;
        // 遍历所有 LOAD 段。
        for (const auto& load : phs) {
            if (load.type != PT_LOAD) {
                continue;
            }
            // LOAD 文件起点。
            const uint64_t load_file_begin = load.offset;
            // LOAD 文件终点（开区间）。
            const uint64_t load_file_end = load.offset + load.filesz;
            // LOAD VA 起点。
            const uint64_t load_va_begin = load.vaddr;
            // LOAD VA 终点（开区间）。
            const uint64_t load_va_end = load.vaddr + load.memsz;

            // TLS 文件起点。
            const uint64_t tls_file_begin = tls_segment.offset;
            // TLS 文件终点（开区间）。
            const uint64_t tls_file_end = tls_segment.offset + tls_segment.filesz;
            // TLS VA 起点。
            const uint64_t tls_va_begin = tls_segment.vaddr;
            // TLS VA 终点（开区间）。
            const uint64_t tls_va_end = tls_segment.vaddr + tls_segment.memsz;

            // TLS filesz 为 0 时视为文件覆盖成立，否则必须完整落在 LOAD 文件区间。
            const bool file_covered = tls_segment.filesz == 0 ||
                                      (tls_file_begin >= load_file_begin && tls_file_end <= load_file_end);
            // TLS memsz 为 0 时视为 VA 覆盖成立，否则必须完整落在 LOAD VA 区间。
            const bool va_covered = tls_segment.memsz == 0 ||
                                    (tls_va_begin >= load_va_begin && tls_va_end <= load_va_end);
            // 两个维度都满足即覆盖成功。
            if (file_covered && va_covered) {
                tls_covered = true;
                break;
            }
        }

        // TLS 未被任何 LOAD 覆盖则失败。
        if (!tls_covered) {
            if (error) {
                *error = "PT_TLS is not covered by any PT_LOAD";
            }
            return false;
        }
    }

    // LOAD 段两两重叠检查。
    for (size_t leftLoadIndex = 0; leftLoadIndex < phs.size(); ++leftLoadIndex) {
        // 第一个段。
        const auto& leftLoad = phs[leftLoadIndex];
        // 非 LOAD 跳过。
        if (leftLoad.type != PT_LOAD) {
            continue;
        }
        // 与后续段配对检查。
        for (size_t rightLoadIndex = leftLoadIndex + 1;
             rightLoadIndex < phs.size();
             ++rightLoadIndex) {
            // 第二个段。
            const auto& rightLoad = phs[rightLoadIndex];
            // 非 LOAD 跳过。
            if (rightLoad.type != PT_LOAD) {
                continue;
            }

            // 文件区间是否重叠。
            const bool file_overlap = rangesOverlapU64(
                    leftLoad.offset, leftLoad.filesz, rightLoad.offset, rightLoad.filesz);
            // 虚拟地址区间是否重叠。
            const bool va_overlap = rangesOverlapU64(
                    leftLoad.vaddr, leftLoad.memsz, rightLoad.vaddr, rightLoad.memsz);
            // 只要有重叠，且不满足可接受特例，就判失败。
            if ((file_overlap || va_overlap) &&
                !isLoadOverlapOk(leftLoad, rightLoad, runtime_page_size)) {
                if (error) {
                    *error = "PT_LOAD overlap is not acceptable between phdr " +
                             std::to_string(leftLoadIndex) + " and " + std::to_string(rightLoadIndex);
                }
                return false;
            }
        }
    }

    // 全部检查通过。
    return true;
}

// 节与段映射校验：ALLOC 节必须能被 LOAD 段覆盖并满足边界关系。
bool zElfValidator::validateSectionSegmentMapping(const PatchElf& elf, std::string* error) {
    // 读取 Program Header 列表。
    const auto& phs = elf.getProgramHeaderModel().elements;
    // 读取 Section Header 列表。
    const auto& secs = elf.getSectionHeaderModel().elements;
    // 文件总大小。
    const size_t file_size = elf.getFileImageSize();
    // 没有节时默认通过。
    if (secs.empty()) {
        return true;
    }

    // 遍历每一个 section。
    for (size_t sectionIndex = 0; sectionIndex < secs.size(); ++sectionIndex) {
        // 当前节引用。
        const auto& section = *secs[sectionIndex];
        // 空节占位项直接跳过。
        if (section.type == SHT_NULL) {
            continue;
        }

        // 非 NOBITS 节且有文件体积时，必须完全落在文件内。
        if (section.type != SHT_NOBITS && section.size > 0 &&
            ((uint64_t)section.offset + section.size > file_size)) {
            if (error) {
                *error = "Section out of file range at index " + std::to_string(sectionIndex);
            }
            return false;
        }

        // 非 ALLOC 节不要求被 LOAD 覆盖。
        if ((section.flags & SHF_ALLOC) == 0) {
            continue;
        }

        // 标记当前 ALLOC 节是否映射到某个 LOAD。
        bool mapped_to_load = false;
        // 在所有 Program Header 中寻找匹配段。
        for (const auto& ph : phs) {
            // 先做 flags/type 快速过滤。
            if (!loadSegmentMatchesSectionFlags(ph, section)) {
                continue;
            }

            // 段文件区间起点。
            const uint64_t seg_file_start = ph.offset;
            // 段文件区间终点（开区间）。
            const uint64_t seg_file_end = ph.offset + ph.filesz;
            // 节文件区间起点。
            const uint64_t sec_file_start = section.offset;
            // 节文件区间终点（开区间）。
            const uint64_t sec_file_end = section.offset + section.size;
            // NOBITS 不要求文件覆盖；其他节要求文件区间完整包含。
            const bool in_file_range = section.type == SHT_NOBITS ||
                                       (sec_file_start >= seg_file_start && sec_file_end <= seg_file_end);

            // 段 VA 区间起点。
            const uint64_t seg_va_start = ph.vaddr;
            // 段 VA 区间终点（开区间）。
            const uint64_t seg_va_end = ph.vaddr + ph.memsz;
            // 节 VA 区间起点。
            const uint64_t sec_va_start = section.addr;
            // 节 VA 区间终点（开区间）。
            const uint64_t sec_va_end = section.addr + section.size;
            // ALLOC 节要求 VA 区间完整被段覆盖。
            const bool in_va_range = sec_va_start >= seg_va_start && sec_va_end <= seg_va_end;

            // 文件与 VA 两个维度都满足才视为映射成立。
            if (in_file_range && in_va_range) {
                mapped_to_load = true;
                break;
            }
        }

        // ALLOC 节找不到任何覆盖段则失败。
        if (!mapped_to_load) {
            if (error) {
                *error = "ALLOC section not mapped to LOAD at index " + std::to_string(sectionIndex) +
                         " (" + section.resolved_name + ")";
            }
            return false;
        }
    }
    // 全部 section 检查通过。
    return true;
}

