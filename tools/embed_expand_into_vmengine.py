#!/usr/bin/env python3
# [VMP_FLOW_NOTE] 文件级流程注释
# - 把 libdemo_expand.so 作为 payload 嵌入 libvmengine.so 尾部。
# - 加固链路位置：route4 L1 产物构建。
# - 输入：vmengine so + expand so。
# - 输出：带 footer 的宿主 so。
#
# 维护说明（嵌入结构约束）：
# 1) footer 的字段布局是运行时解析协议，不可随意调整。
# 2) payload_size 与 crc32 校验逻辑属于强约束，失败必须中断。
# 3) 若宿主已有旧 payload，必须采用“替换”而非“叠加”策略。
# 4) 输出流程需保持原子性语义：读取完成后一次性写回结果。
# 5) 错误信息应包含路径与关键字段，便于离线排障。
import argparse
import struct
import zlib
from pathlib import Path


FOOTER_MAGIC = 0x34454D56  # 'VME4'
FOOTER_VERSION = 1
FOOTER_STRUCT = struct.Struct("<IIQII")


class EmbedError(RuntimeError):
    # 统一脚本内业务异常类型，便于主入口集中转成退出码 1。
    pass


def readBytes(path: Path) -> bytes:
    """读取文件字节。

    读取失败时抛出 EmbedError，避免上层拿到半状态结果继续处理。
    """
    # read_bytes 失败通常意味着路径错误或文件句柄占用。
    try:
        return path.read_bytes()
    except OSError as exc:
        raise EmbedError(f"failed to read {path}: {exc}") from exc


def writeBytes(path: Path, data: bytes) -> None:
    """写入文件字节并确保父目录存在。"""
    # 写回前确保父目录存在，兼容 --output-so 指向新目录的场景。
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        raise EmbedError(f"failed to write {path}: {exc}") from exc


def parseExistingFooter(host: bytes):
    """解析宿主 so 尾部是否已存在嵌入 footer。

    返回：
    - None：宿主没有可识别 footer。
    - (payload_begin, payload_size)：可替换旧 payload 的位置。
    """
    # 若宿主已带历史 payload，先解析并校验，后续会覆盖旧 payload。
    # 宿主长度不足以容纳 footer 时直接判定“无旧 payload”。
    if len(host) < FOOTER_STRUCT.size:
        return None
    magic, version, payload_size, payload_crc32, _reserved = FOOTER_STRUCT.unpack_from(
        host, len(host) - FOOTER_STRUCT.size
    )
    # magic/version 不匹配时按“无旧 payload”处理，而不是报错。
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
    """根据 payload 构建最小校验 footer。"""
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
    """脚本主流程：读取、校验、替换/追加、写回。"""
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

    # 读取输入宿主与 payload。
    host_bytes = readBytes(host_path)
    payload_bytes = readBytes(payload_path)
    if not payload_bytes:
        raise EmbedError(f"payload is empty: {payload_path}")

    # 若已存在历史 payload，则先剥离旧 payload 后再写入新 payload。
    existing = parseExistingFooter(host_bytes)
    if existing is None:
        base_host = host_bytes
        print("existing embedded payload: none")
    else:
        payload_begin, payload_size = existing
        base_host = host_bytes[:payload_begin]
        print(f"existing embedded payload: found size={payload_size}, replacing")

    # 生成新 footer 并重组输出字节序列。
    footer = buildFooter(payload_bytes)
    out_bytes = base_host + payload_bytes + footer
    writeBytes(out_path, out_bytes)

    # 输出关键摘要，便于调用方在 CI 日志中定位结果文件。
    print(f"host: {host_path}")
    print(f"payload: {payload_path} ({len(payload_bytes)} bytes)")
    print(f"output: {out_path} ({len(out_bytes)} bytes)")
    print("embed complete")


if __name__ == "__main__":
    try:
        main()
    except EmbedError as exc:
        # 统一错误出口：打印业务错误并返回非 0。
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
