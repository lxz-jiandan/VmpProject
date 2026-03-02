#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 统计项目源码注释覆盖率，并按文件输出覆盖率明细。
# - 目标：让读者快速看到“每个源码文件”的注释覆盖情况。
#
# 设计说明（统计口径）：
# 1) 覆盖率定义为 comment_lines / non_empty_lines。
# 2) comment_lines 包含“纯注释行”和“代码+注释混合行”。
# 3) 空白行不参与统计，避免格式化差异影响结果。
# 4) 该工具关注“可读性信号”，并不等价于代码质量评分。
#
# 设计说明（解析策略）：
# 1) C 风格文件解析 // 与 /* */，并处理跨行块注释状态。
# 2) Python/Shell 解析 # 注释，并跟踪字符串状态以降低误判。
# 3) 当前实现不把 Python 三引号文档字符串计入注释覆盖率。
# 4) 解析器目标是稳定可复现，而不是完整语法级解析器。
#
# 设计说明（工程兼容）：
# 1) roots/exts/exclude-dirs 都支持命令行覆盖，便于分模块统计。
# 2) 默认排除构建缓存目录，避免统计中间产物噪声。
# 3) relative_to 在盘符/UNC 混用场景可能失败，因此提供 relpath 兜底。
# 4) fail-under 仅基于总覆盖率，用于 CI 门禁接入。
#
# 维护建议：
# 1) 若扩展语言解析，先明确注释语法与误判边界再落实现。
# 2) 若调整覆盖率定义，需同步更新报告标题与 README 说明。
# 3) 任何变更都应保留“逐文件明细 + 汇总”的输出结构。
# 4) Windows 路径兼容逻辑变更后必须做映射盘/UNC 双场景验证。
#
# 维护建议（结果解释）：
# 1) 覆盖率偏低不等于实现错误，通常代表可读性文档化不足。
# 2) 覆盖率偏高也不代表设计质量高，仍需评估注释是否描述有效信息。
# 3) 建议结合文件职责分层设置不同阈值，而非统一阈值一刀切。
# 4) 对于自动生成或第三方代码，建议通过 roots/exclude 策略排除。
# 5) 输出中 mixed_lines 可用于识别“行尾注释风格”比例。
# 6) 当统计结果异常跳变时，先检查排除目录配置是否被修改。
# 7) CI 中建议固定 exts 列表，避免环境差异导致统计漂移。
# 8) 若要统计文档字符串，可在 hash 解析器中增加三引号识别规则。
# 9) 若接入前端语言，可按语言特性增加独立解析函数。
# 10) 该脚本优先保证稳定口径，其次追求语法覆盖完整度。
# 11) 当口径变更时，应在变更说明中明确“与历史数据不可直接比较”。
# 12) 建议定期输出按目录聚合报表，辅助定位注释薄弱区域。
# 13) 结果文件可用于评审前自检，不建议单独作为质量放行依据。
# 14) 对临界值文件可优先补“流程/约束/异常语义”注释，效果更稳定。
# 15) 任何自动补注释脚本都应人工复核，避免机械注释污染可读性。
# 16) 建议在版本升级后复跑样例仓库，校验统计口径是否保持一致。
# 17) 对于多语言混编仓库，可分语言输出独立摘要以辅助治理。
# 18) 若要支持增量统计，可基于 git diff 文件列表做 roots 子集扫描。

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Set


# C/C++/Java/Groovy/Gradle/Kotlin 等常见源码注释风格：// 与 /* */
C_STYLE_EXTS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".java",
    ".kt",
    ".kts",
    ".gradle",
    ".groovy",
    ".js",
    ".ts",
}

# Python/Shell 等注释风格：#
HASH_STYLE_EXTS = {
    ".py",
    ".sh",
    ".bash",
    ".zsh",
}

DEFAULT_ROOTS = [
    "VmProtect",
    "VmEngine",
    "demo",
    "shared",
    "tools",
]

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    ".vscode",
    "__pycache__",
    "build",
    ".cxx",
    "intermediates",
    "cmake-build-debug",
    "cmake-build-release",
    "capstone_sdk",
}


# 结果模型设计说明：
# 1) 把“每文件统计值”封装成 dataclass，便于排序、汇总和格式化输出。
# 2) 覆盖率口径固定为 comment_lines / non_empty_lines。
# 3) mixed_lines 单独保留，便于后续做“纯注释率”扩展分析。
@dataclass
class FileCoverage:
    """单文件注释覆盖率统计结果。

    字段说明：
    - non_empty_lines：非空行总数（覆盖率分母）。
    - comment_lines：含注释的行数（覆盖率分子）。
    - comment_only_lines：纯注释行。
    - mixed_lines：代码+注释混合行。
    """
    path: Path
    non_empty_lines: int
    comment_lines: int
    code_lines: int
    comment_only_lines: int
    mixed_lines: int

    @property
    def coverage(self) -> float:
        if self.non_empty_lines <= 0:
            return 0.0
        return (self.comment_lines / self.non_empty_lines) * 100.0


def should_exclude(path: Path, exclude_dirs: Set[str]) -> bool:
    # 路径过滤策略说明：
    # - 只要命中排除目录段即跳过；
    # - cmake-build-* 作为变体目录统一忽略；
    # - 该函数仅判定，不做文件系统副作用。
    """判断文件路径是否应被排除。"""
    # 任一路径段命中排除目录即跳过。
    for part in path.parts:
        if part in exclude_dirs:
            return True
        # 统一过滤 cmake-build-* 变体目录。
        if part.startswith("cmake-build-"):
            return True
    return False


def iter_source_files(
    project_root: Path,
    roots: Iterable[str],
    exts: Set[str],
    exclude_dirs: Set[str],
) -> List[Path]:
    # 源码收集策略说明：
    # - 先按 roots 收敛扫描范围，避免全盘递归；
    # - 再按扩展名与排除目录过滤；
    # - 输出排序后的稳定文件列表，便于 diff 对比。
    """遍历并收集参与统计的源码文件。

    过滤条件：
    - 路径在 roots 下。
    - 扩展名命中 exts。
    - 路径不命中 exclude_dirs。
    """
    files: List[Path] = []
    for root in roots:
        base = (project_root / root)
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if should_exclude(path, exclude_dirs):
                continue
            if path.suffix.lower() not in exts:
                continue
            files.append(path)
    files.sort()
    return files


def analyze_c_style_text(text: str):
    # C 风格解析器设计说明：
    # - 使用 in_block_comment 状态机处理跨行块注释；
    # - 兼容行注释 // 与块注释 /* */；
    # - 对字符串字面量进行跳过，降低误判概率。
    """统计 C 风格注释（// 与 /* */）文本的覆盖情况。

    实现重点：
    - 支持跨行块注释状态机；
    - 避免把字符串字面量中的 // 或 /* 误判为注释起点。
    """
    in_block_comment = False
    non_empty_lines = 0
    comment_lines = 0
    code_lines = 0
    comment_only_lines = 0
    mixed_lines = 0

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        non_empty_lines += 1
        has_comment = False
        has_code = False
        i = 0
        n = len(raw_line)

        while i < n:
            if in_block_comment:
                has_comment = True
                end = raw_line.find("*/", i)
                if end < 0:
                    i = n
                    break
                in_block_comment = False
                i = end + 2
                continue

            ch = raw_line[i]
            if ch in (" ", "\t", "\r", "\n"):
                i += 1
                continue

            if raw_line.startswith("//", i):
                has_comment = True
                break

            if raw_line.startswith("/*", i):
                has_comment = True
                in_block_comment = True
                i += 2
                continue

            if ch in ("'", "\""):
                # 字符串内容视作代码，内部的 // 或 /* 不作为注释起点。
                has_code = True
                quote = ch
                i += 1
                escaped = False
                while i < n:
                    c = raw_line[i]
                    if escaped:
                        escaped = False
                        i += 1
                        continue
                    if c == "\\":
                        escaped = True
                        i += 1
                        continue
                    if c == quote:
                        i += 1
                        break
                    i += 1
                continue

            has_code = True
            i += 1

        if has_comment:
            comment_lines += 1
        if has_code:
            code_lines += 1
        if has_comment and has_code:
            mixed_lines += 1
        elif has_comment:
            comment_only_lines += 1

    return non_empty_lines, comment_lines, code_lines, comment_only_lines, mixed_lines


def analyze_hash_style_text(text: str):
    # Hash 风格解析器设计说明：
    # - 以 # 作为注释起点；
    # - 显式跟踪单双引号状态，避免把字符串中的 # 当成注释；
    # - 统计逻辑与 C 风格保持一致口径。
    """统计 Hash 风格注释（#）文本的覆盖情况。

    实现重点：
    - 处理单双引号字符串，避免把字符串中的 # 误判为注释起点。
    """
    non_empty_lines = 0
    comment_lines = 0
    code_lines = 0
    comment_only_lines = 0
    mixed_lines = 0

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        non_empty_lines += 1
        has_comment = False
        has_code = False

        i = 0
        n = len(raw_line)
        in_single = False
        in_double = False
        escaped = False

        while i < n:
            ch = raw_line[i]
            if escaped:
                has_code = True
                escaped = False
                i += 1
                continue
            if ch == "\\":
                escaped = True
                has_code = True
                i += 1
                continue

            if in_single:
                has_code = True
                if ch == "'":
                    in_single = False
                i += 1
                continue

            if in_double:
                has_code = True
                if ch == "\"":
                    in_double = False
                i += 1
                continue

            if ch in (" ", "\t", "\r", "\n"):
                i += 1
                continue
            if ch == "'":
                has_code = True
                in_single = True
                i += 1
                continue
            if ch == "\"":
                has_code = True
                in_double = True
                i += 1
                continue
            if ch == "#":
                has_comment = True
                break

            has_code = True
            i += 1

        if has_comment:
            comment_lines += 1
        if has_code:
            code_lines += 1
        if has_comment and has_code:
            mixed_lines += 1
        elif has_comment:
            comment_only_lines += 1

    return non_empty_lines, comment_lines, code_lines, comment_only_lines, mixed_lines


def analyze_file(path: Path) -> FileCoverage:
    # 单文件分析策略说明：
    # - 统一 UTF-8 读取并替换非法字节；
    # - 按扩展名选择解析器；
    # - 最终返回 FileCoverage 供上层汇总。
    """分析单个文件并返回覆盖率统计对象。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"failed to read file: {path} ({exc})") from exc

    ext = path.suffix.lower()
    if ext in C_STYLE_EXTS:
        stats = analyze_c_style_text(text)
    elif ext in HASH_STYLE_EXTS:
        stats = analyze_hash_style_text(text)
    else:
        # 未知扩展默认走 C 风格，尽量覆盖常见语言。
        stats = analyze_c_style_text(text)

    return FileCoverage(
        path=path,
        non_empty_lines=stats[0],
        comment_lines=stats[1],
        code_lines=stats[2],
        comment_only_lines=stats[3],
        mixed_lines=stats[4],
    )


def format_pct(value: float) -> str:
    # 输出格式固定两位小数并右对齐，便于表格阅读。
    """格式化百分比文本，便于列对齐输出。"""
    return f"{value:6.2f}%"


def safe_relpath(path: Path, project_root: Path) -> str:
    # 路径兼容策略说明：
    # - 优先使用 Path.relative_to；
    # - 盘符/UNC 混用时回退 os.path.relpath；
    # - 再失败则输出绝对路径兜底。
    """计算相对路径，兼容 Windows 盘符/UNC 混用场景。"""
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        try:
            return Path(os.path.relpath(str(path), str(project_root))).as_posix()
        except ValueError:
            return path.as_posix()


def print_report(project_root: Path, results: List[FileCoverage], fail_under: float):
    # 报告输出策略说明：
    # - 先输出逐文件明细，再输出汇总统计；
    # - fail-under 仅作用于总覆盖率；
    # - 返回码由上层 main 直接传给 SystemExit。
    """打印逐文件明细和汇总统计，并返回进程退出码。"""
    if not results:
        print("No source files found.")
        return 0

    total_non_empty = sum(item.non_empty_lines for item in results)
    total_comment = sum(item.comment_lines for item in results)
    total_code = sum(item.code_lines for item in results)
    total_comment_only = sum(item.comment_only_lines for item in results)
    total_mixed = sum(item.mixed_lines for item in results)
    total_cov = (total_comment / total_non_empty * 100.0) if total_non_empty else 0.0

    print(
        "Coverage = comment_lines / non_empty_lines "
        "(comment_lines includes comment-only + mixed code/comment lines)\n"
    )
    header = (
        f"{'Coverage':>9} {'NonEmpty':>9} {'Comment':>9} "
        f"{'Code':>9} {'OnlyCmt':>9} {'Mixed':>9}  Path"
    )
    print(header)
    print("-" * len(header))
    for item in results:
        rel = safe_relpath(item.path, project_root)
        print(
            f"{format_pct(item.coverage):>9} {item.non_empty_lines:9d} {item.comment_lines:9d} "
            f"{item.code_lines:9d} {item.comment_only_lines:9d} {item.mixed_lines:9d}  {rel}"
        )

    print("\nSummary")
    print("-" * 72)
    print(f"Files      : {len(results)}")
    print(f"NonEmpty   : {total_non_empty}")
    print(f"Comment    : {total_comment}")
    print(f"Code       : {total_code}")
    print(f"OnlyCmt    : {total_comment_only}")
    print(f"Mixed      : {total_mixed}")
    print(f"Coverage   : {total_cov:.2f}%")

    if fail_under > 0.0 and total_cov < fail_under:
        print(f"[FAIL] total coverage {total_cov:.2f}% < fail-under {fail_under:.2f}%")
        return 1
    return 0


def parse_args():
    # 参数设计说明：
    # - roots/exts/exclude-dirs 允许按项目特性自定义；
    # - sort 支持 path/coverage 两种视角；
    # - fail-under 便于 CI 门禁接入。
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(
        description="Check comment coverage for each source file in VmpProject."
    )
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).parent.parent),
        help="Path to project root (default: repo root).",
    )
    parser.add_argument(
        "--roots",
        nargs="+",
        default=DEFAULT_ROOTS,
        help="Directories to scan (default: VmProtect VmEngine demo shared tools).",
    )
    parser.add_argument(
        "--exts",
        nargs="*",
        default=sorted(C_STYLE_EXTS | HASH_STYLE_EXTS),
        help="File extensions to scan (default: common source extensions).",
    )
    parser.add_argument(
        "--exclude-dirs",
        nargs="*",
        default=sorted(DEFAULT_EXCLUDE_DIRS),
        help="Directory names to exclude recursively.",
    )
    parser.add_argument(
        "--sort",
        choices=("path", "coverage"),
        default="path",
        help="Sort by path or coverage (default: path).",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=0.0,
        help="Exit with code 1 when total coverage is below this percentage.",
    )
    return parser.parse_args()


def main():
    # 主流程设计说明：
    # 1) 解析参数并标准化配置；
    # 2) 扫描文件并执行逐文件分析；
    # 3) 排序输出并按阈值返回退出码。
    """脚本主流程：解析参数 -> 扫描 -> 统计 -> 输出报告。"""
    args = parse_args()
    project_root = Path(os.path.abspath(args.project_root))
    if not project_root.exists():
        raise RuntimeError(f"project root not found: {project_root}")

    exts = {ext if ext.startswith(".") else f".{ext}" for ext in args.exts}
    exts = {ext.lower() for ext in exts}
    exclude_dirs = {name.strip() for name in args.exclude_dirs if name.strip()}

    files = iter_source_files(
        project_root=project_root,
        roots=args.roots,
        exts=exts,
        exclude_dirs=exclude_dirs,
    )
    results = [analyze_file(path) for path in files]

    if args.sort == "coverage":
        results.sort(key=lambda x: (x.coverage, x.path.as_posix()))
    else:
        results.sort(key=lambda x: x.path.as_posix())

    return print_report(project_root, results, fail_under=args.fail_under)


if __name__ == "__main__":
    raise SystemExit(main())
