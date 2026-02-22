#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 根据清单生成导出桩与符号映射头文件。
# - 加固链路位置：route4 L2 代码生成阶段。
# - 输入：takeover_symbols.json。
# - 输出：generated stubs/header。
import argparse
import json
from pathlib import Path
from typing import Dict, List


def load_manifest(path: Path) -> List[Dict[str, object]]:
    # 读取并校验 symbol 清单：
    # - id/name 必须存在且合法；
    # - id、name 都不能重复；
    # - 最终按 id 升序，保证生成代码稳定。
    data = json.loads(path.read_text(encoding="utf-8"))
    symbols = data.get("symbols")
    if not isinstance(symbols, list) or not symbols:
        raise ValueError("manifest.symbols must be a non-empty array")

    normalized = []
    seen_ids = set()
    seen_names = set()
    for index, raw in enumerate(symbols):
        if not isinstance(raw, dict):
            raise ValueError(f"symbols[{index}] must be object")
        symbol_id = raw.get("id")
        symbol_name = raw.get("name")
        if not isinstance(symbol_id, int) or symbol_id < 0 or symbol_id > 0xFFFFFFFF:
            raise ValueError(f"symbols[{index}].id must be uint32")
        if not isinstance(symbol_name, str) or not symbol_name:
            raise ValueError(f"symbols[{index}].name must be non-empty string")
        if symbol_id in seen_ids:
            raise ValueError(f"duplicate symbol id: {symbol_id}")
        if symbol_name in seen_names:
            raise ValueError(f"duplicate symbol name: {symbol_name}")
        seen_ids.add(symbol_id)
        seen_names.add(symbol_name)
        normalized.append({"id": symbol_id, "name": symbol_name})

    normalized.sort(key=lambda item: int(item["id"]))
    return normalized


def emit_mov_w2(symbol_id: int) -> List[str]:
    # 生成把 symbol_id 写入 w2 的指令序列（w2 作为 dispatch 第三个参数）。
    lo16 = symbol_id & 0xFFFF
    hi16 = (symbol_id >> 16) & 0xFFFF
    lines = [f"    movz w2, #{lo16}"]
    if hi16 != 0:
        lines.append(f"    movk w2, #{hi16}, lsl #16")
    return lines


def generate_asm(symbols: List[Dict[str, object]], manifest_label: str) -> str:
    out = []
    out.append("/* [VMP_FLOW_NOTE] 自动生成文件 */")
    out.append("/* - 由 tools/gen_takeover_stubs.py 生成，定义 ARM64 导出跳板。 */")
    out.append(f"/* - 来源清单: {manifest_label} */")
    out.append("")
    out.append("    .text")
    out.append("    .align 2")
    out.append("")
    for item in symbols:
        symbol_id = int(item["id"])
        symbol_name = str(item["name"])
        out.append(f"    .global {symbol_name}")
        out.append(f"    .type {symbol_name}, %function")
        out.append(f"{symbol_name}:")
        out.extend(emit_mov_w2(symbol_id))
        out.append("    b z_takeover_dispatch_by_id")
        out.append(f"    .size {symbol_name}, .-{symbol_name}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def generate_header(symbols: List[Dict[str, object]], manifest_label: str) -> str:
    out = []
    out.append("// [VMP_FLOW_NOTE] 自动生成文件")
    out.append("// - 由 tools/gen_takeover_stubs.py 生成，维护 symbol_id <-> symbol_name 映射。")
    out.append(f"// - 来源清单: {manifest_label}")
    out.append("#ifndef Z_TAKEOVER_SYMBOLS_GENERATED_H")
    out.append("#define Z_TAKEOVER_SYMBOLS_GENERATED_H")
    out.append("")
    out.append("#include <cstddef>")
    out.append("#include <cstdint>")
    out.append("")
    out.append("struct zTakeoverGeneratedSymbolEntry {")
    out.append("    uint32_t symbol_id;")
    out.append("    const char* symbol_name;")
    out.append("};")
    out.append("")
    out.append("static constexpr zTakeoverGeneratedSymbolEntry kTakeoverGeneratedSymbols[] = {")
    for item in symbols:
        out.append(f"    {{{int(item['id'])}u, \"{str(item['name'])}\"}},")
    out.append("};")
    out.append("")
    out.append(
        "static constexpr size_t kTakeoverGeneratedSymbolCount = "
        "sizeof(kTakeoverGeneratedSymbols) / sizeof(kTakeoverGeneratedSymbols[0]);"
    )
    out.append("")
    out.append("inline const char* zTakeoverGeneratedSymbolNameById(uint32_t symbol_id) {")
    out.append("    switch (symbol_id) {")
    for item in symbols:
        out.append(f"        case {int(item['id'])}u: return \"{str(item['name'])}\";")
    out.append("        default: return nullptr;")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("#endif // Z_TAKEOVER_SYMBOLS_GENERATED_H")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate arm64 takeover stubs and id->symbol header.")
    parser.add_argument("--manifest", required=True, help="Path to takeover symbol manifest JSON")
    parser.add_argument("--manifest-label", default=None, help="Label string written into generated comments")
    parser.add_argument("--out-asm", required=True, help="Output .S path")
    parser.add_argument("--out-header", required=True, help="Output .h path")
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    manifest_label = (args.manifest_label or args.manifest).replace("\\", "/")
    out_asm = Path(args.out_asm).resolve()
    out_header = Path(args.out_header).resolve()
    symbols = load_manifest(manifest_path)

    out_asm.parent.mkdir(parents=True, exist_ok=True)
    out_header.parent.mkdir(parents=True, exist_ok=True)
    out_asm.write_text(generate_asm(symbols, manifest_label), encoding="utf-8")
    out_header.write_text(generate_header(symbols, manifest_label), encoding="utf-8")
    print(f"[OK] generated asm: {out_asm}")
    print(f"[OK] generated header: {out_header}")
    print(f"[OK] symbol_count={len(symbols)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
