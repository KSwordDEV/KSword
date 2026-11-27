"""打开既有Qt采样并只读验收行为树叶与原坐标Enter定位；不执行采集。"""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import json
from pathlib import Path
import struct
import sys
import traceback

from desktop_behavior_history import RELEASE, release_window
from desktop_behavior_tree import verify_tree
from isolated_desktop import require_isolated_desktop
from archive_api_preview import open_project_sample
from cooperative_api_capture import self_write_detail
from live_cooperative_api import decode_raw, subtree, until

# 既有归档解码器位于Light合作回放助手目录，双端共用同一只读实现。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'light'))
from cooperative_archive_replay import read_cooperative_archive
from support import BEHAVIOR, screenshot


def latest_behavior(project, sample, target):
    """输入已保留项目与目标身份，扫描Stored包并返回最后一个真实拒绝调用原坐标。"""
    digests, packets, last_raw = read_cooperative_archive(project / 'samples' / sample, decode_raw)
    matches = []
    for segment, raw, metadata, wire in packets:
        api = wire[96:224].decode('utf-16-le').split('\0', 1)[0]
        status = struct.unpack_from('<i', wire, 28)[0]
        if api != 'WriteProcessMemory' or status != 5:
            continue
        fields = self_write_detail(wire)
        assert fields['process'] == target['queryHandle'] and fields['requested'] == 1 and fields['completed'] == 0
        matches.append((segment, raw, int(metadata['sourceSequence'])))
    assert matches and last_raw > matches[-1][1], (len(packets), last_raw, matches[-1:] if matches else [])
    return {'coordinate': list(matches[-1]), 'rule': BEHAVIOR, 'packets': len(packets),
            'terminalRaw': last_raw, 'segmentDigests': len(digests)}


def main():
    """输入冻结Qt SHA；在隔离桌面打开已保存样本并回执真实行为叶与详情。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui-sha256', required=True)
    args = parser.parse_args()
    base = Path(__file__).resolve().parents[1] / 'desktop_behavior_history' / 'qt'
    output = base / 'archive-tree-inspection'
    output.mkdir(exist_ok=False)
    receipt = {'status': 'RUNNING', 'guiSha256': args.gui_sha256.lower(), 'collectionStarted': False}
    try:
        with (output / 'run.log').open('x', encoding='utf-8', buffering=1) as log:
            with redirect_stdout(log), redirect_stderr(log):
                require_isolated_desktop()
                gui = (RELEASE / 'Ksword5.1.exe').read_bytes()
                assert hashlib.sha256(gui).hexdigest() == args.gui_sha256.lower()
                main_receipt = json.loads((base / 'receipt.json').read_text(encoding='utf-8'))
                target = main_receipt['target']
                project = base / 'archived-project'
                manifest = project / 'project.ksaproj'
                catalog = json.loads((project / 'catalog/2/1.json').read_bytes())
                sample_entry, = catalog['samples']
                sample = sample_entry['sampleId']
                identity = latest_behavior(project, sample, target)
                with release_window() as client:
                    nodes = open_project_sample(client, manifest, sample, title=sample_entry['title'])
                    overview = next(item for item in nodes()
                        if item['visible'] and item['object_name'] == 'action_analyze_overview')
                    overview_nodes = lambda: subtree(client, overview, depth=16, max_nodes=800)
                    archive_status = until(lambda: client.call('snapshot', {'max_nodes': 800, 'depth': 16})
                        ['data']['nodes'], lambda items: any(item['visible'] and
                        '已验证至第 26 段。' in item['name'] for item in items), timeout=30)
                    screenshot(client.pid, output, 'archive-loaded')
                    tree_result = verify_tree(client, overview_nodes, sample, [identity], output)
                    receipt.update(status='PASS', sample=sample, projectPath=str(project),
                                   sourcePacketScan=identity, behaviorTree=tree_result,
                                   projectPreserved=True, guiExitedAfterReadOnlyView=True)
    except BaseException:
        receipt['status'] = 'FAIL'
        (output / 'traceback.txt').write_text(traceback.format_exc(), encoding='utf-8')
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
        (output / 'acceptance.md').write_text(
            f"只读归档树检查：{receipt['status']}\n\n"
            f"- 采集未启动：{receipt['collectionStarted']}\n"
            f"- 样本：{receipt.get('sample', '未验')}\n"
            f"- 行为树 Enter 与原坐标详情：{'PASS' if receipt.get('behaviorTree') else '未验'}\n",
            encoding='utf-8')
        print(f"QT_ARCHIVE_BEHAVIOR_TREE={receipt['status']} RECEIPT={output / 'receipt.json'}", flush=True)


if __name__ == '__main__':
    main()
