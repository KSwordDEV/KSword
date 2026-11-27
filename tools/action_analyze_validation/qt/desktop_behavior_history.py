"""Qt真实主采集最小验收；只在主协调CLI新包实测后经isolated_desktop.py放行。"""

import json
import os
from contextlib import contextmanager
from pathlib import Path
import sys
from unittest.mock import patch

import live_cooperative_api as existing
from archive_api_preview import choose_project_path
from continuous_etw import owned_scratch
from cooperative_api_capture import CLI, COOPERATIVE_ENV, cleanup_session, create_session_directory
from isolated_desktop import require_isolated_desktop
from live_preview import open_workspace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'desktop_behavior_history'))
from support import artifacts, preserve_project, release_arguments, screenshot, verify_archive, verify_history, write_json


def read_groups(client, pane, include_history=True):
    """输入真实回执根；按共享字段模型读取分组，保留重复行为分组而不压成字典。"""
    tables = [item for item in existing.subtree(client, pane, depth=6, max_nodes=120)
              if item['visible'] and item['type'] == 'item_view']
    if not tables:
        return []
    table, = tables  # 回执正文唯一共享模型，不扫描整个工作台。

    def rows(parent=()):
        return client.call('read_table', {'object_id': table['id'], 'row_count': 128,
                                         'column_count': 2, 'parent_rows': list(parent)})['data']['rows']

    roots = rows()
    groups = []  # 每个分组单独存储，32条行为的字段名可以重复。
    for index, row in enumerate(roots):
        accepted = {'合作 Agent 来源', 'API 规则回执'}
        if include_history:
            accepted.add('行为释义')
        if row and row[0] in accepted:
            values = rows((index,))
            groups.append((row[0], dict((str(value[0]), str(value[1])) for value in values if len(value) >= 2)))
    return groups


def fields_from(groups, title):
    """输入已回读分组与标题；返回该唯一来源或规则组，不混入行为历史的重名字段。"""
    return next((fields for name, fields in groups if name == title), {})


def history_from(groups):
    """输入停止后的字段分组；返回每条实际行为自身的坐标、释义及证据。"""
    result = []  # 只收集正式回执中的历史条目。
    for name, fields in groups:
        if name != '行为释义' or '行为规则 ID' not in fields:
            continue
        result.append({'coordinate': [int(value) for value in fields['命中坐标（段 / 原包 / 普通包流水号）'].split(' / ')],
                       'rule': fields['最近命中的规则'], 'behavior': fields['行为规则 ID'],
                       'summary': fields['行为释义'], 'evidence': fields['证据级别']})
    return result


@contextmanager
def owned_target(client, nodes, session):
    """复用原合作目标；异常时先走GUI停止并等待清退，再让原fixture发送EOF退出。"""
    with existing.owned_behavior_target(session) as target:
        try:
            yield target
        finally:
            stop = existing.visible(nodes, 'action_analyze_api_stop')
            if stop['enabled']:
                existing.press(client, stop)
                existing.until(lambda: existing.visible(nodes, 'action_analyze_api_stop')['enabled'],
                               lambda enabled: not enabled, timeout=25)


def run(directory, receipt):
    """输入本端固定输出目录；执行唯一自有合作源→主GUI采集→停止→归档→退出并清理。"""
    existing.require_inactive_driver()
    with owned_scratch(directory / 'work') as work:
        project = work / 'project'  # 测试项目由实际Qt创建按钮产生。
        manifest = project / 'project.ksaproj'
        session = work / 'KswordApiMonCooperative'
        create_session_directory(session)
        identity = None
        controller = None
        try:
            with patch.dict(os.environ, {COOPERATIVE_ENV: str(session)}), existing.test_window() as client:
                controller = client.pid
                nodes, _ = open_workspace(client)
                choose_project_path(client, existing.visible(nodes, 'action_analyze_create_project'), project)
                existing.until(manifest.is_file, bool)
                existing.select_tab(client, nodes, '总览')
                overview = existing.wait_visible(nodes, 'action_analyze_overview')

                def overview_nodes():
                    return existing.subtree(client, overview, depth=16, max_nodes=800)

                existing.press(client, existing.visible(overview_nodes, 'action_analyze_api_capture'))
                source_mode = existing.wait_visible(overview_nodes, 'action_analyze_api_source_mode')
                if 'set_field' in source_mode['actions']:
                    existing.dispatch(client, 'set_field', object_id=source_mode['id'], value=1, confirmed=True)
                else:
                    existing.click_cooperation(client, directory)
                existing.until(lambda: existing.visible(overview_nodes, 'action_analyze_api_start')['name'],
                               lambda value: value == '开始合作 API 采样')
                with owned_target(client, overview_nodes, session) as (child, identity):
                    receipt['target'] = identity
                    for suffix, value in (('pid', child.pid), ('creation', identity['creation'])):
                        existing.dispatch(client, 'set_field', object_id=existing.visible(
                            overview_nodes, 'action_analyze_api_' + suffix)['id'], value=str(value), confirmed=True)
                    pane = existing.visible(overview_nodes, 'action_analyze_api_receipt')
                    existing.press(client, existing.visible(overview_nodes, 'action_analyze_api_start'))
                    existing.until(lambda: existing.visible(overview_nodes, 'action_analyze_api_status')['name'],
                                   lambda value: 'Agent 已就绪' in value and '正在采样' in value, timeout=25)

                    def progress():
                        groups = read_groups(client, pane, include_history=False)
                        rules = fields_from(groups, 'API 规则回执')
                        source = fields_from(groups, '合作 Agent 来源')
                        if int(rules.get('行为命中数', '0')) > 32:
                            return source, rules
                        return None

                    running_source, running_rules = existing.until(progress, bool, timeout=25)
                    sample = running_source['采样 ID']  # 运行与终态必须归属同一sample。
                    receipt['sample'] = sample
                    write_json(directory, 'running', {'source': running_source, 'rules': running_rules})
                    screenshot(client.pid, directory, 'running')
                    assert child.poll() is None and existing.visible(overview_nodes, 'action_analyze_api_stop')['enabled']
                    existing.press(client, existing.visible(overview_nodes, 'action_analyze_api_stop'))
                    existing.until(lambda: existing.visible(overview_nodes, 'action_analyze_api_status')['name'],
                                   lambda value: value.startswith('API 活采已结束'), timeout=25)
                    groups = existing.until(lambda: read_groups(client, pane),
                        lambda value: fields_from(value, '合作 Agent 来源').get('已清退') == '是', timeout=20)
                    source = fields_from(groups, '合作 Agent 来源')
                    rules = fields_from(groups, 'API 规则回执')
                    assert source['采样 ID'] == sample and child.poll() is None, source
                    assert all(source[key] == '是' for key in ('Agent 已就绪', '已确认停钩', '管道正常读完', '已清退')), source
                    assert not existing.visible(overview_nodes, 'action_analyze_api_stop')['enabled']
                    total = int(rules['行为命中数'])
                    assert total >= int(running_rules['行为命中数']), (running_rules, rules)
                    history = verify_history(history_from(groups), total, rules['行为窗口截断'] == '是')
                    write_json(directory, 'stopped', groups)
                    screenshot(client.pid, directory, 'stopped')
                    # 先验证目标在Stop后仍活着，再通过已有EOF退出协议清退自有合作源。
                    tail, error = child.communicate(timeout=10)
                    assert child.returncode == 0 and not error and json.loads(tail)['agentLoaded'], (tail, error)
                archive = verify_archive(project, sample, history, identity, existing.decode_raw,
                                         existing.cooperative_archive_replay.read_cooperative_archive)
                receipt.update(archive=archive, behaviorMatches=total, sourceClean=True)
                write_json(directory, 'archive-evidence', archive)
                existing.press(client, existing.wait_visible(overview_nodes, 'action_analyze_api_archive', lambda item: item['enabled']))
                existing.until(overview_nodes, lambda items: any(item['visible'] and
                    f'已验证至第 {archive["terminal"]} 段。' in item['name'] for item in items), timeout=20)
                # 复用项目页规则回放，验证真实GUI报告含同一历史见证的原坐标。
                digests, packets, last_raw = existing.cooperative_archive_replay.read_cooperative_archive(
                    project / 'samples' / sample, existing.decode_raw)
                witness = next(item for item in packets if [item[0], item[1], int(item[2]['sourceSequence'])] == history[-1]['coordinate'])
                existing.verify_project(client, nodes, source, identity, (witness, digests, packets, last_raw))
                screenshot(client.pid, directory, 'archive')
        finally:
            try:
                preserve_project(project, directory, receipt)
            finally:
                if identity is not None:
                    cleanup_session(session, identity['pid'], identity['creation'], controller)
                assert not list(session.iterdir()), session
                session.rmdir()
    receipt['cleanup'] = {'workRemoved': not (directory / 'work').exists(), 'guiClosed': True,
                          'settingsRestored': True, 'targetExit': child.returncode}


def main():
    """协调放行入口；本批准备时只做AST静态校验，不调用此函数。"""
    hashes = release_arguments('qt', existing.RELEASE / 'Ksword5.1.exe', CLI)
    require_isolated_desktop()
    with artifacts('qt', hashes) as (directory, receipt):
        run(directory, receipt)


if __name__ == '__main__':
    main()
