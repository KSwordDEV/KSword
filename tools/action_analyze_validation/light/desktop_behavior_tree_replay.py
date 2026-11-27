"""打开既有Light采样并只读验收行为树叶与原坐标Enter定位；不执行采集。"""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import traceback

from desktop_behavior_history import existing, light_window, require_idle_environment
from desktop_behavior_tree import verify_tree
from isolated_desktop import require_isolated_desktop
from live_project_preview import OPEN_TITLE
from cooperative_archive_replay import read_cooperative_archive
from support import screenshot, write_json


def main():
    """输入冻结Light SHA；在隔离桌面打开现有项目，输出只读树验收回执。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui-sha256', required=True)
    args = parser.parse_args()
    history_root = Path(__file__).resolve().parents[1] / 'desktop_behavior_history'
    endpoint_root = history_root / 'light'
    output = history_root / 'release-5ba974a93' / 'light-archive-tree'
    output.mkdir(exist_ok=False)
    receipt = {
        'status': 'RUNNING', 'sourceCommit': '5ba974a93b4c373a393ce9740ed8c85f81cfacfa',
        'endpoint': 'light', 'guiSha256': args.gui_sha256.lower(), 'collectionStarted': False,
        'cliInvoked': False, 'newSampleCreated': False,
    }  # 只记录本轮要回放的正式镜像身份和禁止项。
    project = endpoint_root / 'archived-project'
    project_hashes = {}
    try:
        with (output / 'run.log').open('x', encoding='utf-8', buffering=1) as log:
            with redirect_stdout(log), redirect_stderr(log):
                require_isolated_desktop()
                gui = existing.BINARY.read_bytes()
                assert hashlib.sha256(gui).hexdigest() == args.gui_sha256.lower()
                receipt['driverState'] = require_idle_environment()
                main_receipt = json.loads((endpoint_root / 'receipt.json').read_text(encoding='utf-8'))
                target_receipt = main_receipt['target']
                sample = main_receipt['sample']
                manifest = project / 'project.ksaproj'
                history = json.loads((endpoint_root / 'stopped.json').read_text(encoding='utf-8'))['history']['entries']
                assert manifest.is_file() and history
                project_hashes = {
                    path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(project.rglob('*')) if path.is_file()
                }  # 对整份既有项目做回放前身份快照。
                _, packets, terminal_raw = read_cooperative_archive(
                    project / 'samples' / sample, existing.decode_raw)
                process_query_rows = sum(
                    wire[96:224].decode('utf-16-le').split('\0', 1)[0] == 'NtQueryInformationProcess'
                    for _, _, _, wire in packets
                )  # 新增字段仅核对已有原包，不以没有样本的项目推断 Hook 覆盖。
                receipt['existingArchive'] = {
                    'sample': sample, 'packets': len(packets), 'terminalRaw': terminal_raw,
                    'processQueryRows': process_query_rows,
                    'processQueryFieldCoverage': 'NOT_COVERED_NO_EXISTING_ROWS' if not process_query_rows else 'ARCHIVE_ROWS_PRESENT',
                    'liveHookCoverage': 'NOT_TESTED',
                }
                environment = dict(os.environ)
                with light_window(environment) as page:
                    receipt['guiPid'] = page.process.pid
                    page.default_page()
                    page.controls.update({name: existing.control(page.page, identifier)
                        for name, identifier in (existing.API_CONTROLS | {'source': 58332}).items()})
                    page.browse('open', OPEN_TITLE, manifest)
                    page.wait_catalog(manifest, {sample})
                    combo = page.controls['samples']
                    index = page.sample_entries()[sample]
                    assert existing.gui.SendMessage(combo, existing.con.CB_SETCURSEL, index, 0) == index
                    existing.gui.SendMessage(page.page, existing.con.WM_COMMAND,
                        58310 | (existing.con.CBN_SELCHANGE << 16), combo)
                    page.wait_status('现有采样预览', lambda value:
                        f'快速预览 · {sample}' in value and '正在读取' not in value)
                    page.click('replay')
                    page.wait_status('既有采样只读打开', lambda value:
                        sample in value and '当前归档' in value and '正在读取' not in value)
                    assert set(page.sample_entries()) == {sample}
                    api = page.controls['api_only']
                    if existing.gui.SendMessage(api, existing.con.BM_GETCHECK, 0, 0) != existing.con.BST_CHECKED:
                        page.click('api_only')
                    screenshot(page.process.pid, output, 'archive-loaded')
                    tree_result = verify_tree(page, sample, history, output)
                    receipt.update(sample=sample, target=target_receipt,
                                   historyEntries=len(history), behaviorTree=tree_result,
                                   projectPath=str(project))
                receipt['guiExitCode'] = page.process.returncode
                receipt['guiExitedAfterReadOnlyView'] = page.process.returncode == 0
                current_hashes = {
                    path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(project.rglob('*')) if path.is_file()
                }  # 确认退出后的归档项目逐文件不变。
                receipt['projectUnchanged'] = current_hashes == project_hashes
                assert receipt['projectUnchanged'], '只读 GUI 回放修改了既有项目'
                receipt['status'] = 'PASS'
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
        print(f"LIGHT_ARCHIVE_BEHAVIOR_TREE={receipt['status']} RECEIPT={output / 'receipt.json'}", flush=True)


if __name__ == '__main__':
    main()
