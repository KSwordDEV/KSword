"""v4 完整布局发布/拒绝回归；配置写入固定 IntDir，结束删除，不创建运行副本。"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest
import zlib

from pdb_offset_generator.ksword_v4_structure_layouts import (
    KINDS, build_structure_layouts, validate_structure_layouts,
)


ROOT = Path(__file__).resolve().parents[1]  # 当前仓库根，不使用个人机器路径。
FIXTURE = ROOT / "KswordCLI/x64/Release/StructureLayoutPackFixtures"
NATIVE = ROOT / "Ksword5.1/x64/Release/StructureLayoutPackTests.exe"


def compressed(pack: dict) -> bytes:
    """输入测试 JSON，返回和正式构建一致的 qCompress 容器。"""
    raw = json.dumps(pack, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(raw)) + zlib.compress(raw, 9)


class StructureLayouts(unittest.TestCase):
    """验证完整正文、索引及精确身份的发布边界，并调用实际原生消费者。"""

    @classmethod
    def setUpClass(cls) -> None:
        """建立两个根类型的固定最小源资产；已有目录不覆盖，防止清理其他任务。"""
        if FIXTURE.exists():
            raise RuntimeError(f"Inspect existing fixture before retrying: {FIXTURE}")
        FIXTURE.mkdir(parents=True)
        cls.body = "0\t0\tField\tunsigned long\t\t\tmember\n"
        cls.identity = "34404\t1\t4096\t" + "A" * 32 + "1"
        for kind, marker in KINDS.items():
            directory = FIXTURE / kind  # 仅在固定测试目录下创建源夹具。
            directory.mkdir()
            (directory / "_versions.index").write_bytes(
                ("KSWLAYOUTVERSIONS1\n" + cls.identity + "\t10.0.19041.1\n").encode("ascii"))
            (directory / "34404-1-4096.tsv").write_bytes(
                (marker + "\t" + cls.identity + "\t8\n" + cls.body).encode("ascii"))
        cls.layouts = build_structure_layouts(FIXTURE)
        cls.pack = {"schemaVersion": 1, "packVersion": 4, "profiles": [], "structureLayouts": cls.layouts}

    @classmethod
    def tearDownClass(cls) -> None:
        """只删除本测试独占且实际创建的固定配置，不触碰正式包及产品。"""
        if FIXTURE.parent == ROOT / "KswordCLI/x64/Release":
            shutil.rmtree(FIXTURE)

    def test_lossless_deduplication(self) -> None:
        """同一完整正文去重，但两类根记录与数字索引各自保留。"""
        validate_structure_layouts(self.layouts)
        self.assertEqual(list(self.layouts["fieldSets"].values()), [self.body])
        for kind in KINDS:
            self.assertEqual(len(self.layouts[kind]["profiles"]), 1)
            self.assertEqual(self.layouts[kind]["catalog"], (FIXTURE / kind / "_versions.index").read_text())

    def test_source_missing_rejected(self) -> None:
        """缺少一种根或任一分片时必须构建失败，不能保留旧发布文件冒充成功。"""
        with self.assertRaises(FileNotFoundError):
            build_structure_layouts(FIXTURE / "missing")

    def test_body_hash_and_parent_rejected(self) -> None:
        """校验内容引用与生产父子边界，不接受仅包外层合法的数据。"""
        changed = copy.deepcopy(self.layouts)
        key = next(iter(changed["fieldSets"]))  # 原去重引用，修改正文后必须失效。
        changed["fieldSets"][key] = self.body.replace("Field", "Other")
        with self.assertRaises(ValueError):
            validate_structure_layouts(changed)
        bad_body = self.body.replace("0\t0\t", "1\t0\t")
        digest = hashlib.sha256(bad_body.encode()).hexdigest()
        changed["fieldSets"] = {digest: bad_body}
        for kind in KINDS:
            changed[kind]["profiles"]["34404-1-4096.tsv"][1] = digest
        with self.assertRaises(ValueError):
            validate_structure_layouts(changed)

    def test_native_consumer(self) -> None:
        """原生读取器真实解压最小包，并拒绝缺身份、坏索引、坏引用及损坏流。"""
        self.assertTrue(NATIVE.is_file(), "Build Invoke-StructureSampleTests.ps1 first")
        valid = FIXTURE / "valid.qz"
        valid.write_bytes(compressed(self.pack))
        subprocess.run([str(NATIVE), str(valid), str(FIXTURE)], check=True)
        mutations = []  # 每个变异单独发布为固定配置，最后统一调用原生拒绝路径。
        for change in ("format", "missing_kind", "missing_record", "bad_catalog", "bad_reference", "bad_size", "empty_body"):
            pack = copy.deepcopy(self.pack)
            layouts = pack["structureLayouts"]
            if change == "format":
                layouts["formatVersion"] = 2
            elif change == "missing_kind":
                del layouts["process_layouts"]
            elif change == "missing_record":
                layouts["thread_layouts"]["profiles"].clear()
            elif change == "bad_catalog":
                layouts["thread_layouts"]["catalog"] += "bad\n"
            elif change == "bad_reference":
                layouts["thread_layouts"]["profiles"]["34404-1-4096.tsv"][1] = "f" * 64
            elif change == "bad_size":
                layouts["thread_layouts"]["profiles"]["34404-1-4096.tsv"][0] = 1.5
            else:
                layouts["fieldSets"][next(iter(layouts["fieldSets"]))] = ""
            path = FIXTURE / (change + ".qz")
            path.write_bytes(compressed(pack))
            mutations.append(path)
        good = valid.read_bytes()
        for name, data in {"short": good[:12], "crc": good[:-1] + bytes([good[-1] ^ 1]),
                           "suffix": good + b"suffix", "length": b"\x7f\xff\xff\xff" + good[4:],
                           "legacy": compressed({"schemaVersion": 1, "packVersion": 4, "profiles": []})}.items():
            path = FIXTURE / (name + ".qz")
            path.write_bytes(data)
            mutations.append(path)
        subprocess.run([str(NATIVE), "--reject", *map(str, mutations)], check=True)


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
