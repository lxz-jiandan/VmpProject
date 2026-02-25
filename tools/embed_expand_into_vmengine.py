#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 把 libdemo_expand.so 作为 payload 嵌入 libvmengine.so 尾部。
# - 加固链路位置：route4 L1 产物构建。
# - 输入：vmengine so + expand so。
# - 输出：带 footer 的宿主 so。
import argparse
import struct
import zlib
from pathlib import Path


FOOTER_MAGIC = 0x34454D56  # 'VME4'
FOOTER_VERSION = 1
FOOTER_STRUCT = struct.Struct("<IIQII")


class EmbedError(RuntimeError):
    pass


def readBytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise EmbedError(f"failed to read {path}: {exc}") from exc


def writeBytes(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        raise EmbedError(f"failed to write {path}: {exc}") from exc


def parseExistingFooter(host: bytes):
    # 若宿主已带历史 payload，先解析并校验，后续会覆盖旧 payload。
    if len(host) < FOOTER_STRUCT.size:
        return None
    magic, version, payload_size, payload_crc32, _reserved = FOOTER_STRUCT.unpack_from(
        host, len(host) - FOOTER_STRUCT.size
    )
    if magic != FOOTER_MAGIC or version != FOOTER_VERSION:
        return None

    if payload_size == 0 or payload_size > len(host) - FOOTER_STRUCT.size:
        raise EmbedError(
            f"host has embedded footer but invalid payload_size={payload_size}"
        )

    payload_begin = len(host) - FOOTER_STRUCT.size - payload_size
    payload = host[payload_begin : payload_begin + payload_size]
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if actual_crc != payload_crc32:
        raise EmbedError(
            "host has embedded footer but crc mismatch: "
            f"expected=0x{payload_crc32:08x}, actual=0x{actual_crc:08x}"
        )

    return payload_begin, payload_size


def buildFooter(payload: bytes) -> bytes:
    # footer 只记录最小必要信息：magic/version/size/crc，便于运行时快速校验。
    payload_crc = zlib.crc32(payload) & 0xFFFFFFFF
    return FOOTER_STRUCT.pack(
        FOOTER_MAGIC,
        FOOTER_VERSION,
        len(payload),
        payload_crc,
        0,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Append libdemo_expand.so payload to libvmengine.so tail (route4 L1)."
    )
    parser.add_argument("--host-so", required=True, help="Path to libvmengine.so")
    parser.add_argument("--payload-so", required=True, help="Path to libdemo_expand.so")
    parser.add_argument(
        "--output-so",
        default="",
        help="Output path for patched host so (default: overwrite host-so)",
    )
    args = parser.parse_args()

    host_path = Path(args.host_so)
    payload_path = Path(args.payload_so)
    out_path = Path(args.output_so) if args.output_so else host_path

    host_bytes = readBytes(host_path)
    payload_bytes = readBytes(payload_path)
    if not payload_bytes:
        raise EmbedError(f"payload is empty: {payload_path}")

    existing = parseExistingFooter(host_bytes)
    if existing is None:
        base_host = host_bytes
        print("existing embedded payload: none")
    else:
        payload_begin, payload_size = existing
        base_host = host_bytes[:payload_begin]
        print(f"existing embedded payload: found size={payload_size}, replacing")

    footer = buildFooter(payload_bytes)
    out_bytes = base_host + payload_bytes + footer
    writeBytes(out_path, out_bytes)

    print(f"host: {host_path}")
    print(f"payload: {payload_path} ({len(payload_bytes)} bytes)")
    print(f"output: {out_path} ({len(out_bytes)} bytes)")
    print("embed complete")


if __name__ == "__main__":
    try:
        main()
    except EmbedError as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
