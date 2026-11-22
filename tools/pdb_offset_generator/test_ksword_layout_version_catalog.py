"""版本目录只读联接与边界元数据回归；不连接驱动或虚拟机。"""

import json
from pathlib import Path
import unittest

from ksword_layout_version_catalog import build_catalog, identities_from_pack


class CatalogTests(unittest.TestCase):
    """使用固定 IntDir 下的单一夹具，不生成运行副本或修改生产 profiles。"""

    def setUp(self):
        """建立本测试独占的固定配置目录；已有残留时先失败，不覆盖旧文件。"""
        self.directory = Path(__file__).resolve().parents[2] / 'KswordCLI/x64/Release/LayoutCatalogFixtures'
        self.directory.mkdir(exist_ok=False)
        self.shard = self.directory / '34404-123-4096.tsv'
        self.key = 'A' * 32 + '1'
        self.shard.write_text(f'KSWTHREAD1\t34404\t123\t4096\t{self.key}\t64\n', encoding='ascii')

    def tearDown(self):
        """仅删除本测试创建的确定文件；目录非空时保留证据并报错。"""
        self.shard.unlink(missing_ok=True)
        self.directory.rmdir()

    def pack(self):
        """返回具有显式身份与文件版本的最小正式包形态，不包含任何采样地址。"""
        return {'packVersion': 4, 'profiles': [{
            'moduleClassId': 0, 'machine': 34404, 'timeDateStamp': 123, 'sizeOfImage': 4096,
            'pdbGuid': 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA', 'pdbAge': 1,
            'profileName': 'ntoskrnl_amd64_10.0.19041.9_' + self.key.lower(),
        }]}

    def test_exact_metadata_join(self):
        """完整身份联接后仍保持数字版本，不以时间戳顺序代替版本号。"""
        versions = identities_from_pack(self.pack())
        body = build_catalog(self.directory, 'KSWTHREAD1', versions).decode('ascii')
        self.assertIn(f'34404\t123\t4096\t{self.key}\t10.0.19041.9\n', body)
        self.assertEqual(len(body.splitlines()), 2)

    def test_missing_version_refused(self):
        """包中没有该分片的显式身份版本时，不发布伪造的覆盖边界。"""
        with self.assertRaises(ValueError):
            build_catalog(self.directory, 'KSWTHREAD1', {})

    def test_conflicting_versions_refused(self):
        """同一完整身份不能同时被声明为两个不同修订版。"""
        pack = self.pack()
        duplicate = json.loads(json.dumps(pack['profiles'][0]))
        duplicate['profileName'] = duplicate['profileName'].replace('19041.9_', '19041.10_')
        pack['profiles'].append(duplicate)
        with self.assertRaises(ValueError):
            identities_from_pack(pack)

    def test_rsds_and_root_kind_refused(self):
        """名字中的符号键或布局根类别不符时，不接受该元数据。"""
        pack = self.pack()
        pack['profiles'][0]['pdbAge'] = 2
        with self.assertRaises(ValueError):
            identities_from_pack(pack)
        with self.assertRaises(ValueError):
            build_catalog(self.directory, 'KSWPROCESS1', identities_from_pack(self.pack()))


if __name__ == '__main__':
    unittest.main()
