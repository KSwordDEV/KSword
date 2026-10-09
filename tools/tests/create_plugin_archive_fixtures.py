"""共享 ZIP 门禁离线数据夹具；文件仅含无执行能力的文本，不下载任何资产。"""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import warnings
import zipfile


def main() -> None:
    # 输出由现有 Qt 夹具目录拥有；mode 只改变 ZIP 条目，不操作真实安装目录。
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--wrapped", action="store_true")
    arguments = parser.parse_args()
    prefix = "fixture/" if arguments.wrapped else ""
    rows: list[tuple[str, bytes, int]] = [(prefix + "plugin.json", b"{}", 0),
        (prefix + "payload.txt", b"abcdefgh", 0), (prefix + "other.txt", b"abcdefgh", 0)]
    # 非法路径/别名/重复/链接/文件目录冲突，必须在写任何文件前被拒绝。
    extra = {
        "traversal": (prefix + "../outside.txt", b"bad", 0),
        "absolute": ("/outside.txt", b"bad", 0),
        "ads": (prefix + "payload.txt:stream", b"bad", 0),
        "device": (prefix + "CON.txt", b"bad", 0),
        "superscript-device": (prefix + "COM\u00b9.txt", b"bad", 0),
        "dot-alias": (prefix + "path. ", b"bad", 0),
        "empty-component": (prefix + "dir//payload.txt", b"bad", 0),
        "duplicate": (prefix + "payload.txt", b"bad", 0),
        "case-duplicate": (prefix + "PAYLOAD.TXT", b"bad", 0),
        "slash-duplicate": ((prefix + "payload.txt").replace("/", "\\"), b"bad", 0),
        "collision": (prefix + "payload.txt/child", b"bad", 0),
        "link": (prefix + "link", b"outside.txt", 0o120777 << 16),
        "reparse": (prefix + "reparse", b"outside.txt", 0x400),
        "special": (prefix + "pipe", b"bad", 0o010600 << 16),
        "depth": (prefix + "a/b/c/d/e/f", b"bad", 0),
        "wrong-wrapper": ("unexpected/plugin.json", b"{}", 0),
    }
    if arguments.mode in extra:
        rows.append(extra[arguments.mode])
    if arguments.mode == "ambiguous":
        rows.append(("fixture/plugin.json", b"{}", 0))
    if arguments.mode == "forged-length":
        rows.append((prefix + "forged.txt", b"X" * 128, 0))
    # 预算测试用真正可解压文本；降低共享生产预算，不创建 GB 大文件。
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(arguments.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content, attributes in rows:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                if attributes:
                    info.external_attr = attributes
                archive.writestr(info, content)
    if arguments.mode == "forged-length":
        # 篡改中央目录与本地头声称长度，实际 Deflate 数据保留 128 字节。
        payload = bytearray(arguments.output.read_bytes())
        position = 0
        while (position := payload.find(b"PK\x01\x02", position)) != -1:
            name_length = struct.unpack_from("<H", payload, position + 28)[0]
            name = payload[position + 46:position + 46 + name_length]
            if name.endswith(b"forged.txt"):
                struct.pack_into("<I", payload, position + 24, 1)
                local = struct.unpack_from("<I", payload, position + 42)[0]
                struct.pack_into("<I", payload, local + 22, 1)
            position += 4
        arguments.output.write_bytes(payload)


if __name__ == "__main__":
    main()
