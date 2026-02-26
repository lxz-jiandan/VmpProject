#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 生成通用 takeover entry 桩与 entry 头文件。
# - 加固链路位置：route4 L2 代码生成阶段。
# - 输入：槽位总数。
# - 输出：generated stubs/header。
import argparse
from pathlib import Path
from typing import List


def emitMovW2(slot_id: int) -> List[str]:
    # 生成把 slot_id 写入 w2 的指令序列（w2 作为 dispatch 第三个参数）。
    lo16 = slot_id & 0xFFFF
    hi16 = (slot_id >> 16) & 0xFFFF
    lines = [f"    movz w2, #{lo16}"]
    if hi16 != 0:
        lines.append(f"    movk w2, #{hi16}, lsl #16")
    return lines


def slotSymbolName(slot_id: int) -> str:
    # entry 符号统一命名：vm_takeover_entry_0000。
    return f"vm_takeover_entry_{slot_id:04d}"


def generateAsm(slot_count: int, label: str) -> str:
    out = []
    out.append("/* [VMP_FLOW_NOTE] 自动生成文件 */")
    out.append("/* - 由 tools/gen_takeover_stubs.py 生成，定义 ARM64 通用 takeover entry 跳板。 */")
    out.append(f"/* - 来源: {label} */")
    out.append("")
    out.append("    .text")
    out.append("    .align 2")
    out.append("")
    for slot_id in range(slot_count):
        symbol_name = slotSymbolName(slot_id)
        out.append(f"    .global {symbol_name}")
        out.append(f"    .type {symbol_name}, %function")
        out.append(f"{symbol_name}:")
        out.extend(emitMovW2(slot_id))
        out.append("    b vm_takeover_dispatch_by_id")
        out.append(f"    .size {symbol_name}, .-{symbol_name}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def generateHeader(slot_count: int, label: str) -> str:
    out = []
    out.append("// [VMP_FLOW_NOTE] 自动生成文件")
    out.append("// - 由 tools/gen_takeover_stubs.py 生成，维护槽位总数常量。")
    out.append(f"// - 来源: {label}")
    out.append("#ifndef Z_TAKEOVER_SYMBOLS_GENERATED_H")
    out.append("#define Z_TAKEOVER_SYMBOLS_GENERATED_H")
    out.append("")
    out.append("#include <cstdint>")
    out.append("")
    out.append(f"static constexpr uint32_t kTakeoverGeneratedSymbolCount = {slot_count}u;")
    out.append("")
    out.append("#endif // Z_TAKEOVER_SYMBOLS_GENERATED_H")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate arm64 takeover entry stubs.")
    parser.add_argument("--slot-count", required=True, type=int, help="Total takeover entry count")
    parser.add_argument("--source-label", default="slot-count", help="Label written into generated comments")
    parser.add_argument("--out-asm", required=True, help="Output .S path")
    parser.add_argument("--out-header", required=True, help="Output .h path")
    args = parser.parse_args()

    if args.slot_count <= 0 or args.slot_count > 65535:
        raise ValueError("--slot-count must be in [1, 65535]")

    out_asm = Path(args.out_asm).resolve()
    out_header = Path(args.out_header).resolve()
    out_asm.parent.mkdir(parents=True, exist_ok=True)
    out_header.parent.mkdir(parents=True, exist_ok=True)
    out_asm.write_text(generateAsm(args.slot_count, args.source_label), encoding="utf-8")
    out_header.write_text(generateHeader(args.slot_count, args.source_label), encoding="utf-8")
    print(f"[OK] generated asm: {out_asm}")
    print(f"[OK] generated header: {out_header}")
    print(f"[OK] slot_count={args.slot_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
