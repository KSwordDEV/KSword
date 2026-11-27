"""Light原归档树的真实行为叶与Enter定位验收；只操作本次已打开的正式窗口。"""

from base64 import b64encode
import ctypes
import json
from pathlib import Path
import subprocess

import win32api
import win32con as con
import win32gui as gui

from archive_etw_preview import control, text, wait_for
from isolated_desktop import launch_gui, require_isolated_desktop
from api_rule_profile import behavior_rule
from support import BEHAVIOR, EVIDENCE, screenshot, write_json


def verify_tree(page, sample, history, directory):
    """输入本轮Light归档及历史；读取真实UIA树叶并以原生Enter定位，返回原坐标详情。"""
    require_isolated_desktop()
    tree = control(page.page, 58333)  # 已有kTransferCandidates控件，不新造窗口或采集源。
    assert tree and gui.IsWindowVisible(tree), '原归档树不可见'
    segment, raw, source = history[-1]['coordinate']
    coordinate = f'raw/{segment} #{raw}'
    output = directory / 'behavior-tree-uia.json'
    request = json.dumps({'tree': tree, 'coordinate': coordinate, 'output': str(output)})
    # 沿用既有UIA只读PowerShell方法；动作仍通过当前测试桌面的原生控件消息执行。
    command = "$request = ConvertFrom-Json '" + request.replace("'", "''") + "'\n" + r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$tree = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$request.tree)
$condition = [System.Windows.Automation.PropertyCondition]::new(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::TreeItem)
$items = $tree.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
$root = @($items | Where-Object { $_.Current.Name -in @('行为规则', 'Behavior Rules') })
if ($root.Count -ne 1) {
    @{ rootCount = $root.Count; treeName = $tree.Current.Name;
       itemNames = @($items | ForEach-Object { $_.Current.Name }) } |
        ConvertTo-Json -Compress -Depth 4 | Set-Content -LiteralPath $request.output -Encoding UTF8
    exit 0
}
$children = $root[0].FindAll([System.Windows.Automation.TreeScope]::Children, $condition)
$leaf = @($children | Where-Object { $_.Current.Name.Contains($request.coordinate + ' ·') })
if ($leaf.Count -ne 1) {
    @{ rootCount = $root.Count; childCount = $children.Count; root = $root[0].Current.Name;
       childNames = @($children | ForEach-Object { $_.Current.Name }) } |
        ConvertTo-Json -Compress -Depth 4 | Set-Content -LiteralPath $request.output -Encoding UTF8
    exit 0
}
$scroll = $null
if ($leaf[0].TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
    $scroll.ScrollIntoView()
}
$rect = $leaf[0].Current.BoundingRectangle
@{ rootCount = $root.Count; root = $root[0].Current.Name; leaf = $leaf[0].Current.Name;
   count = $children.Count; rectEmpty = $rect.IsEmpty; width = $rect.Width; height = $rect.Height;
   point = if ($rect.IsEmpty) { @() } else { @([int]($rect.X + $rect.Width / 2), [int]($rect.Y + $rect.Height / 2)) } } |
    ConvertTo-Json -Compress | Set-Content -LiteralPath $request.output -Encoding UTF8
'''
    # UIA按根名称和原坐标定位，避免假设新增根永远位于原生树末尾。
    powershell = Path(win32api.GetSystemDirectory()) / 'WindowsPowerShell/v1.0/powershell.exe'
    probe = launch_gui([powershell, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
                        '-EncodedCommand', b64encode(command.encode('utf-16-le')).decode('ascii')], cwd=directory)
    try:
        assert probe.wait(8) == 0 and output.is_file(), 'Light行为树UIA只读查询失败'
    except subprocess.TimeoutExpired:
        probe.terminate()
        probe.wait(5)
        raise
    shown = json.loads(output.read_text(encoding='utf-8-sig'))
    assert shown.get('rootCount') == 1, shown
    assert shown.get('width', 0) >= 2 and shown.get('height', 0) >= 2, shown
    summaries = behavior_rule(BEHAVIOR)
    assert any(summary in shown['leaf'] for summary in (summaries['summary'], summaries['summaryZh'])), shown
    # UIA返回真实叶的物理坐标；客户端消息不移动系统光标或切换输入桌面。
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    set_dpi = user32.SetThreadDpiAwarenessContext
    set_dpi.argtypes = (ctypes.c_void_p,)
    set_dpi.restype = ctypes.c_void_p
    previous_dpi = set_dpi(-4)
    if not previous_dpi:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        x, y = gui.ScreenToClient(tree, tuple(shown['point']))
    finally:
        set_dpi(previous_dpi)
    position = win32api.MAKELONG(x, y)
    gui.SetFocus(tree)
    gui.SendMessage(tree, con.WM_LBUTTONDOWN, con.MK_LBUTTON, position)
    gui.SendMessage(tree, con.WM_LBUTTONUP, 0, position)
    assert gui.SendMessage(tree, 0x110A, 9, 0), '真实行为叶点击后TreeView没有当前选区'
    # 已选叶的Enter沿产品原生通知链定位，之后详情必须回到同一条归档记录。
    gui.SendMessage(tree, con.WM_KEYDOWN, con.VK_RETURN, 0)
    gui.SendMessage(tree, con.WM_KEYUP, con.VK_RETURN, 0)
    details = wait_for('行为叶Enter后的原坐标详情', lambda: value if
        (value := text(page.controls['detail'])) and
        f'归档记录序号：{raw}    所属段号：{segment}' in value and f'行为规则 ID：{BEHAVIOR}' in value else '')
    assert f'当前归档 · 采样：{sample}' in details and f'证据级别：{EVIDENCE}' in details, details
    assert f'合作流水号（非 JSONL 行号）：{source}' in details, details
    assert any(summary in details for summary in (summaries['summary'], summaries['summaryZh'])), details
    input_lines = {
        'api.family [text]=memory-write',
        'api.name [text]=WriteProcessMemory',
        'result.returned [bool]=false',
        'result.win32Status [u64]=5',
    }  # 由同一已存原包的拒绝返回字段推得，不宣称实时 Hook 覆盖。
    assert '规则比对输入：' in details or 'Rule match inputs:' in details, details
    assert input_lines <= set(details.splitlines()), details
    write_json(directory, 'archive-behavior-tree', {**shown, 'coordinate': [segment, raw, source],
               'enter': True, 'details': details})
    screenshot(page.process.pid, directory, 'archive-behavior-tree')
    return {'root': shown['root'], 'coordinate': [segment, raw, source], 'enter': True}
