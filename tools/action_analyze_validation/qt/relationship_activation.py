"""在独立非输入桌面验证正式 Qt 归档关系叶项，不启动活采集。"""

from base64 import b64encode
import ctypes
import json
from pathlib import Path
import subprocess
from time import sleep

import win32api
import win32con
import win32gui
import win32process

from archive_api_preview import RELEASE, PREVIEW, dispatch, fixture_directory, open_project_sample
from archive_api_preview import read_table, test_window, unique, until
from isolated_desktop import launch_gui, require_isolated_desktop, test_windows
from passive_api_session import run


SCRATCH = RELEASE / 'action-analyze-qt-relation-activation'  # 本轮独占的固定夹具目录。
PREVIOUS = 'raw/3 #8 · WriteProcessMemory'  # 筛选后留在事件表的对照记录。
TARGET = 'raw/3 #9 · WriteProcessMemory'  # 只能经关系叶项实际激活来跳转。
HIDDEN = '当前筛选隐藏了所选原始行，仍可查看详情。'  # 底部关系区的实际状态。

# Windows PowerShell 自带的 UIAutomationClient 只负责读控件坐标和真实选区。
# 输入：本轮主窗 HWND、事件列、当前表行数、叶名和回执路径；不调用任何 UIA 动作。
UIA_QUERY = r'''
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    $root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$request.hwnd)
    $scope = [System.Windows.Automation.TreeScope]::Descendants
    $class = [System.Windows.Automation.AutomationElement]::ClassNameProperty
    $tableCondition = [System.Windows.Automation.PropertyCondition]::new($class, 'QTableView')
    # 表格无专用无障碍名称，按控件类型、大小和第一行的事件列绑定实际事件表。
    $tables = @(foreach ($candidate in $root.FindAll($scope, $tableCondition)) {
        $grid = $null
        if ($candidate.TryGetCurrentPattern([System.Windows.Automation.GridPattern]::Pattern, [ref]$grid) -and
            $grid.Current.RowCount -eq $request.row_count -and $grid.Current.ColumnCount -gt $request.event_col) {
            if ($grid.GetItem(0, $request.event_col).Current.Name -eq 'WriteProcessMemory') { $candidate }
        }
    })
    if ($tables.Count -ne 1) { throw "事件表 UIA 匹配数：$($tables.Count)" }
    $selection = $tables[0].GetCurrentPattern([System.Windows.Automation.SelectionPattern]::Pattern)
    $rows = @(foreach ($cell in $selection.Current.GetSelection()) {
        $cell.GetCurrentPattern([System.Windows.Automation.GridItemPattern]::Pattern).Current.Row
    })
    $result = @{ rows = @($rows | Sort-Object -Unique) }

    # 仅在需要发输入时取得树叶坐标；范围取叶项与树实际几何的交集。
    if ($request.leaf) {
        $name = [System.Windows.Automation.AutomationElement]::NameProperty
        $treeCondition = [System.Windows.Automation.AndCondition]::new([System.Windows.Automation.Condition[]]@(
            [System.Windows.Automation.PropertyCondition]::new($class, 'QTreeView'),
            [System.Windows.Automation.PropertyCondition]::new($name, '归档关系')))
        $tree = $root.FindFirst($scope, $treeCondition)
        if (!$tree) { throw 'UIA 找不到实际归档关系树' }
        $leafCondition = [System.Windows.Automation.PropertyCondition]::new($name, $request.leaf)
        $leaf = $tree.FindFirst($scope, $leafCondition)
        if (!$leaf) { throw "UIA 找不到实际叶项：$($request.leaf)" }
        $rect = [System.Windows.Rect]::Intersect($tree.Current.BoundingRectangle, $leaf.Current.BoundingRectangle)
        if ($rect.IsEmpty -or $rect.Width -lt 2 -or $rect.Height -lt 2) { throw '关系叶项不在树的可见范围' }
        $result.point = @([int]($rect.X + $rect.Width / 2), [int]($rect.Y + $rect.Height / 2))
        $item = $leaf.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
        $result.leaf_selected = $item.Current.IsSelected
    }
} catch {
    $result = @{ error = $_.Exception.Message }
}
ConvertTo-Json -InputObject $result -Compress | Set-Content -LiteralPath $request.output -Encoding UTF8
'''


class InputUnavailable(RuntimeError):
    """非输入桌面没有提供可靠的窗口、点位、焦点或选区，不把未执行当产品失败。"""


def uia_probe(directory, hwnd, model, leaf=''):
    """同一独立桌面读取指定主窗的表格选区及可选树叶的坐标，返回 JSON 字段。"""
    output = directory / 'uia-receipt.json'  # 仅在本轮固定夹具目录交换小型诊断回执。
    output.unlink(missing_ok=True)
    request = json.dumps(dict(hwnd=hwnd, row_count=model['row_total'],
                              event_col=model['headers'].index('事件'), leaf=leaf, output=str(output)),
                         ensure_ascii=False)  # 通过 PowerShell 单引号字符串传入结构化参数。
    command = "$request = ConvertFrom-Json -InputObject '" + request.replace("'", "''") + "'\n" + UIA_QUERY
    encoded = b64encode(command.encode('utf-16-le')).decode('ascii')  # Windows PowerShell 命令编码。
    powershell = Path(win32api.GetSystemDirectory()) / 'WindowsPowerShell/v1.0/powershell.exe'
    probe = launch_gui([powershell, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
                        '-EncodedCommand', encoded], cwd=directory)
    try:
        if probe.wait(8) != 0 or not output.is_file():
            raise InputUnavailable('独立桌面的 UIA 读取器没有返回回执')
    except subprocess.TimeoutExpired as error:
        probe.terminate()  # 只收尾本函数创建的 UIA 读取进程。
        probe.wait(5)
        raise InputUnavailable('独立桌面 UIA 查询超时') from error
    result = json.loads(output.read_text(encoding='utf-8-sig'))  # 兼容 Windows PowerShell 写出的 UTF-8 BOM。
    if 'error' in result:
        raise InputUnavailable(result['error'])
    return result


def post_click(pid, hwnd, point, *, double=False):
    """向本轮主窗投递客户端鼠标消息；坐标来自实际树叶，不移动系统光标。"""
    require_isolated_desktop()
    if win32process.GetWindowThreadProcessId(hwnd)[1] != pid:
        raise InputUnavailable('按钮消息目标不再属于本轮 Qt 窗口')
    dpi_context = ctypes.WinDLL('user32', use_last_error=True).SetThreadDpiAwarenessContext
    dpi_context.argtypes = (ctypes.c_void_p,)
    dpi_context.restype = ctypes.c_void_p
    previous = dpi_context(-4)  # UIA 返回物理屏幕坐标，以 Per Monitor V2 换算到原生客户区。
    if not previous:
        raise InputUnavailable('不能建立坐标换算所需的线程 DPI 上下文')
    try:
        x, y = win32gui.ScreenToClient(hwnd, tuple(point))  # 得到 Qt 原生窗的客户区坐标。
        left, top, right, bottom = win32gui.GetClientRect(hwnd)
    finally:
        dpi_context(previous)
    if not left <= x < right or not top <= y < bottom:
        raise InputUnavailable(f'树叶不在本轮主窗口客户区内：{point}')
    position = win32api.MAKELONG(x, y)  # Win32 鼠标消息的客户区位置。
    win32gui.PostMessage(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, position)
    win32gui.PostMessage(hwnd, win32con.WM_LBUTTONUP, 0, position)
    if double:
        # Qt Windows 后端把 DBLCLK 当作第二次按下，且要求两次的消息时间戳有正差。
        sleep(0.035)
        win32gui.PostMessage(hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, position)
        win32gui.PostMessage(hwnd, win32con.WM_LBUTTONUP, 0, position)


def post_key(pid, hwnd, key):
    """向已由实际树叶点击聚焦的本轮 Qt 主窗投递成对的按键消息。"""
    require_isolated_desktop()
    if win32process.GetWindowThreadProcessId(hwnd)[1] != pid:
        raise InputUnavailable('键盘消息目标不再属于本轮 Qt 窗口')
    bits = 1 | (win32api.MapVirtualKey(key, 0) << 16)  # 一次按下和实际扫描码。
    if key == win32con.VK_DOWN:
        bits |= 1 << 24  # 方向键是扩展扫描码。
    win32gui.PostMessage(hwnd, win32con.WM_KEYDOWN, key, bits)
    release_bits = (bits | 0xC0000000) - (1 << 32)  # 前一状态与释放标志置位，保留有符号消息参数。
    win32gui.PostMessage(hwnd, win32con.WM_KEYUP, key, release_bits)


def verify(client, directory, sample, packets):
    """回放同一合成采样，两次独立从 #8 进入隐藏的 #9，再对账详情和选区。"""
    manifest = directory / 'project' / 'project.ksaproj'  # CLI 创建、正式 Qt 打开的同一清单。
    nodes = open_project_sample(client, manifest, sample, title='Passive API fixture')

    def status_has(text):
        """查询实际可见状态或证据标签是否包含指定文字。"""
        return any(node['visible'] and text in node['name'] for node in nodes())

    until(lambda: status_has('已验证至第 4 段。'), bool)
    assert status_has('已核验 6 条源归档记录。覆盖范围未知。')
    table = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QTableView'
                   and {'PID', 'TID', '事件'} <= set(read_table(client, node)['headers']))  # 实际事件模型。
    api = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QCheckBox' and node['name'] == 'API')
    keyword = unique(nodes(), lambda node: node['visible'] and node['name'] == '记录关键字')
    toggle = unique(nodes(), lambda node: node['visible'] and node['object_name'] == 'aa_archive_relation_toggle')
    dispatch(client, 'set_field', object_id=api['id'], value=True, confirmed=True)
    full = read_table(client, table)  # 六个已核验 API 行，不含跟随计划和尾记。
    assert full['row_total'] == 6, full
    dispatch(client, 'set_field', object_id=toggle['id'], value=True, confirmed=True)
    tree = unique(nodes(), lambda node: node['visible'] and node['object_name'] == 'aa_archive_relation_tree')
    groups = read_table(client, tree)['rows']  # 通过实际显示分组定位，不假定组序。
    group, = (index for index, row in enumerate(groups) if row == ['未解析候选（6）'])
    leaves = read_table(client, tree, [group])  # 同一未解析分组下的六个归档引用。
    target_row, = (index for index, row in enumerate(leaves['rows']) if row == [TARGET])
    assert target_row == 5 and leaves['rows'][target_row - 1] == [PREVIOUS], leaves

    # 正式主窗仅从本轮的隔离桌面、产品 PID 及窗口样式中确认。
    main_windows = [hwnd for hwnd in test_windows() if win32process.GetWindowThreadProcessId(hwnd)[1] == client.pid
                    and win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd).startswith('Qt')
                    and not win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOOLWINDOW]
    if len(main_windows) != 1:
        raise InputUnavailable(f'独立桌面可见 Qt 主窗匹配数：{len(main_windows)}')
    hwnd, = main_windows  # 不从其它桌面或其它进程寻找窗口。

    def details():
        """返回当前原始证据的段号、记录号、源行和原包前缀等结构化字段。"""
        for node in nodes():
            if not node['visible'] or node['type'] != 'item_view' or node['id'] in (table['id'], tree['id']):
                continue
            rows = read_table(client, node)['rows']  # 复用共享详情的平铺和分组表示。
            for index, row in enumerate(rows):
                if row and row[0] == '归档 API 线索':
                    rows = read_table(client, node, [index])['rows']
                    break
            fields = {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}
            if PREVIEW in fields:
                return fields
        return {}

    def check_record(sequence, source):
        """核对同一采样下指定的原始坐标、源行与夹具原包，返回实际详情。"""
        fields = until(details, lambda values: values.get('记录序号') == str(sequence))
        assert (fields['采样 ID'], fields['归档段号'], fields['源归档行号'], fields[PREVIEW]) == (
            sample, '3', str(source), packets[source - 1][:64].hex(' ')), fields
        assert status_has(f'未解析候选 · raw/3 #{sequence}')
        return fields

    def exercise(method):
        """单独验证一种叶项激活方式，每轮重新建立筛选和对照选择。"""
        # select_row 仅用来展开并滚到目标以及选中对照行；它不是任何一次激活的判据。
        dispatch(client, 'set_field', object_id=keyword['id'], value='8', confirmed=True)
        filtered = until(lambda: read_table(client, table), lambda data: data['row_total'] == 1)
        assert filtered['rows'] == [full['rows'][4]], filtered
        dispatch(client, 'select_row', object_id=table['id'], row=0, revision=filtered['revision'], confirmed=True)
        baseline = check_record(8, 5)
        dispatch(client, 'select_row', object_id=tree['id'], row=target_row, parent_rows=[group],
                 revision=leaves['revision'], confirmed=True)
        if method == 'DOUBLE_CLICK':
            # 只滚到目标不算激活；先退到上一叶，再用单击对照核实点击位置但不切换详情。
            dispatch(client, 'select_row', object_id=tree['id'], row=target_row - 1, parent_rows=[group],
                     revision=leaves['revision'], confirmed=True)
        leaf = PREVIOUS if method == 'ENTER' else TARGET  # 这次鼠标确实要点的树叶。
        before = uia_probe(directory, hwnd, filtered, leaf=leaf)
        assert before['rows'] == [0] and details() == baseline and not status_has(HIDDEN), before
        assert not before['leaf_selected'], before

        post_click(client.pid, hwnd, before['point'])
        clicked = uia_probe(directory, hwnd, filtered, leaf=leaf)
        if not clicked['leaf_selected']:
            raise InputUnavailable(f'隔离桌面单击未切到关系树叶：{leaf}')
        assert clicked['rows'] == [0] and details() == baseline and not status_has(HIDDEN), clicked

        if method == 'ENTER':
            post_key(client.pid, hwnd, win32con.VK_DOWN)
            navigated = uia_probe(directory, hwnd, filtered, leaf=TARGET)
            if not navigated['leaf_selected']:
                raise InputUnavailable('隔离桌面方向键未送达关系树，不能确认随后 Enter 的去向')
            assert navigated['rows'] == [0] and details() == baseline and not status_has(HIDDEN), navigated
            post_key(client.pid, hwnd, win32con.VK_RETURN)
        else:
            # 单击对照不应成为双击的第一击，等完系统配置的整个双击间隔才投递一对点击。
            double_click_time = ctypes.WinDLL('user32').GetDoubleClickTime()
            sleep(double_click_time / 1000)
            post_click(client.pid, hwnd, clicked['point'], double=True)

        # 先验证隐藏状态；不以清空筛选后的可见选中行反推激活已经发生。
        located = check_record(9, 6)
        assert status_has(HIDDEN)
        assert unique(nodes(), lambda node: node['id'] == keyword['id'])['value'] == '8'
        assert read_table(client, table)['rows'] == filtered['rows']
        assert uia_probe(directory, hwnd, filtered)['rows'] == [], '激活隐藏叶项后仍保留旧表格高亮'
        dispatch(client, 'set_field', object_id=keyword['id'], value='', confirmed=True)
        restored = until(lambda: read_table(client, table), lambda data: data['rows'] == full['rows'])
        assert check_record(9, 6) == located and not status_has(HIDDEN)
        assert uia_probe(directory, hwnd, restored)['rows'] == [5], '清筛后未恢复目标行高亮'
        print(f'QT_RELATION_FILTERED_{method}=PASS SAMPLE={sample} FROM=3#8 RAW=3#9 SOURCE=6', flush=True)

    # 键盘焦点受限时，双击仍可能可验。每轮失败单独保留原始阶段与诊断。
    blocked = []
    for method in ('ENTER', 'DOUBLE_CLICK'):
        try:
            exercise(method)
        except InputUnavailable as error:
            blocked.append(f'{method}: {error}')
    if blocked:
        raise InputUnavailable('; '.join(blocked))


def main():
    """只在独立桌面下运行固定目录的离线夹具，关闭正式窗口并清理配置。"""
    require_isolated_desktop()
    try:
        with fixture_directory(SCRATCH) as directory:
            sample, _, _, packets = run(directory / 'project')  # CLI 只被动读取固定 JSONL。
            with test_window() as client:
                verify(client, directory, sample, packets)
    except InputUnavailable as error:
        raise SystemExit(f'QT_RELATION_ACTIVATION=BLOCKED: {error}') from None
    print('QT_RELATION_ACTIVATION=PASS', flush=True)


if __name__ == '__main__':
    main()
