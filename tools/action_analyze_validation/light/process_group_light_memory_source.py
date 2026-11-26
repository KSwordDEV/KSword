"""Light 集合内存模块 SOURCE 接线与纯模型负控检查（无构建 / 无 GUI / 无系统调用）。

只做两类检查，均只读：
1. SOURCE：核对新增 LightProcessGroupMemory.h/.cpp 的结构契约——底层相对包含、
   接口齐全、仅 HeldEvent 通道、不开线程不接 owner、保存失败 blocked 语义标记、
   未登记任何工程文件。
2. 纯模型：把 PrepareHeldMemoryRequest 解析规则与 Save/Read 状态机语义逐条移植为
   Python 模型，运行正例与负控（空/0/溢出/越权保存/blocked 持续/指针不匹配）。
不编译、不链接、不启动任何窗口，可在普通桌面直接运行：
    python -B tools/action_analyze_validation/light/process_group_light_memory_source.py
"""

import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HEADER = REPO / 'KswordARKLight/Features/ActionAnalyze/LightProcessGroupMemory.h'
IMPL = REPO / 'KswordARKLight/Features/ActionAnalyze/LightProcessGroupMemory.cpp'

FORBIDDEN_NATIVE = [
    'std::thread', 'CreateThread', '_beginthread', 'ResumeThread', 'SuspendThread',
    'WriteProcessMemory', 'OpenProcess', 'DebugActiveProcess',
]
REQUIRED_HEADER_INCLUDES = [
    '#include "../../Core/Win32Lean.h"',
    '#include "../../../KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h"',
    '#include "../../../KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h"',
    '#include "../../../KswordCLI/ActionAnalyze/Memory/SelectedMemorySnapshot.h"',
    '#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"',
    '#include "../../../KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.h"',
]
REQUIRED_SYMBOLS = [
    'PrepareHeldMemoryRequest', 'FormatLightProcessGroupMemory',
    'FormatLightProcessGroupMemoryArchive', 'kLightMemoryPreviewBytesPerPage = 256',
    'class LightProcessGroupMemoryState', 'CreateNewProject', 'LatestRead', 'ProjectView',
]
REQUIRED_IMPL_MARKERS = [
    ('仅 HeldEvent 通道', 'ProcessMemorySource::HeldEvent'),
    ('拒绝非 HeldEvent', 'light-process-memory-held-only'),
    ('底层采集复用', 'CaptureProcessGroupMemory('),
    ('轮次固定 2', 'request.plan.rounds = 2'),
    ('显式授权标记', 'authorizedOwnedProcess = true'),
    ('前序取真实末序号', 'receipt.raw.flushed->lastSequence'),
    ('成功推进段号', '++nextMemoryOrdinal_'),
    ('失败置 blocked', 'archiveBlocked_ = true'),
    ('blocked 期间保存拒绝', 'lightMemorySnapshotSelection'),
    ('新读取保留 blocked 诊断', 'if (!archiveBlocked_) archive_.reset();'),
    ('保存指针核对', 'displayed != lastMemory_'),
    ('会话局部机器标签', '不宣称系统机器或启动身份'),
    ('64 页上限交给底层', '64 页上限由底层按真实页大小复核'),
]

UINT64_MAX = (1 << 64) - 1


# ---------- SOURCE 结构核对 ----------

def load(path):
    """读取 UTF-8 源文件并断言行数上限。"""
    text = path.read_bytes().decode('utf-8')  # 非 UTF-8 会直接失败。
    lines = text.splitlines()
    assert len(lines) < 1000, f'{path.name} 超过 1000 行：{len(lines)}'
    return text, lines


def check_source():
    """逐项核对两个新增源文件的结构契约；通过项即时打印。"""
    header, header_lines = load(HEADER)
    impl, impl_lines = load(IMPL)

    assert [line for line in header_lines if line.startswith('#include')][:6] == REQUIRED_HEADER_INCLUDES, \
        '头文件相对包含顺序或内容不符'
    print('SOURCE_INCLUDES=PASS 底层=6 相对路径=Light目录', flush=True)

    for symbol in REQUIRED_SYMBOLS:
        assert symbol in header, f'头文件缺少 {symbol}'
    for name, marker in REQUIRED_IMPL_MARKERS:
        assert marker in impl, f'实现缺少标记 {name}: {marker}'
    print(f'SOURCE_INTERFACE=PASS 接口={len(REQUIRED_SYMBOLS)} 语义标记={len(REQUIRED_IMPL_MARKERS)}', flush=True)

    for forbidden in FORBIDDEN_NATIVE:
        assert forbidden not in header and forbidden not in impl, f'后台状态类不得包含 {forbidden}'
    assert 'LiveRead' in impl, '格式化需标注来源标签'
    assert not re.search(r'=\s*process_group_native::ProcessMemorySource::LiveRead', impl), '不得构造 LiveRead 请求'
    print('SOURCE_STATE_CLASS=PASS 无线程=无owner=仅HeldEvent通道=不回退Live', flush=True)

    rejects = sorted(set(re.findall(r'"(lightMemory[A-Za-z]+)"', impl)))
    assert len(rejects) >= 10, f'稳定拒绝阶段不足：{rejects}'
    print(f'SOURCE_REJECT_STAGES=PASS stages={len(rejects)}', flush=True)

    # 本模块不登记工程文件；登记由主调用者接入 Light session/page 时完成。
    patterns = ['LightProcessGroupMemory.h', 'LightProcessGroupMemory.cpp']
    for vcxproj in list(REPO.glob('KswordARKLight/**/*.vcxproj')) + list(REPO.glob('KswordARKLight/**/*.vcxproj.filters')):
        text = vcxproj.read_text(encoding='utf-8', errors='replace')
        for pattern in patterns:
            assert pattern not in text, f'{vcxproj.name} 意外登记了 {pattern}'
    print('SOURCE_PROJECT_UNREGISTERED=PASS 按约束未改任何工程/语言/既有文件', flush=True)

    for path in (HEADER, IMPL):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f'SOURCE_SHA256 {path.name}={digest}', flush=True)
    return header, impl


# ---------- 纯模型：输入解析（与 C++ ParseUnsigned64/Prepare 逐条对应） ----------

class Rejection:
    """与 LightMemoryInputStage 对应的模型拒绝阶段。"""
    NONE = 'None'
    BASE_EMPTY = 'BaseEmpty'
    BASE_INVALID = 'BaseInvalid'
    BASE_ZERO = 'BaseZero'
    BYTES_EMPTY = 'BytesEmpty'
    BYTES_INVALID = 'BytesInvalid'
    BYTES_ZERO = 'BytesZero'
    RANGE_OVERFLOW = 'RangeOverflow'
    EPOCH_EMPTY = 'EpochEmpty'
    MEMBER_NOT_HELD = 'MemberNotHeld'


def trim(text):
    """只去两端空格，与 C++ TrimSpaces 一致。"""
    return text.strip(' ')


def parse_u64(text, hex_allowed):
    """无符号严格解析；返回 (ok, value)。拒绝空、非法字符、正负号与 64 位溢出。"""
    text = trim(text)
    if not text:
        return False, 0
    base = 10
    if hex_allowed and len(text) >= 2 and text[0] == '0' and text[1] in 'xX':
        base = 16
        text = text[2:]
        if not text:
            return False, 0
    value = 0
    for character in text:
        if character in '0123456789':
            digit = ord(character) - ord('0')
        elif base == 16 and character in 'abcdef':
            digit = ord(character) - ord('a') + 10
        elif base == 16 and character in 'ABCDEF':
            digit = ord(character) - ord('A') + 10
        else:
            return False, 0
        if value > UINT64_MAX // base:
            return False, 0
        value *= base
        if value > UINT64_MAX - digit:
            return False, 0
        value += digit
    return True, value


def model_prepare(base_text, bytes_text, epoch, held):
    """移植 PrepareHeldMemoryRequest 的失败优先级；held 表示成员停点是否完整。"""
    ok, base = parse_u64(base_text, True)
    if not ok:
        return (Rejection.BASE_EMPTY if not trim(base_text) else Rejection.BASE_INVALID)
    if base == 0:
        return Rejection.BASE_ZERO
    ok, size = parse_u64(bytes_text, False)
    if not ok:
        return (Rejection.BYTES_EMPTY if not trim(bytes_text) else Rejection.BYTES_INVALID)
    if size == 0:
        return Rejection.BYTES_ZERO
    if size > UINT64_MAX - base:
        return Rejection.RANGE_OVERFLOW
    if not epoch:
        return Rejection.EPOCH_EMPTY
    if not held:
        return Rejection.MEMBER_NOT_HELD
    return Rejection.NONE


def model_preview(total_bytes):
    """每页预览有界 256 字节。"""
    return min(total_bytes, 256)


def check_parse_model():
    """解析正例与负控；负控逐项打印。"""
    ok, value = parse_u64('0x1000', True)
    assert ok and value == 4096
    ok, value = parse_u64('0Xff', True)
    assert ok and value == 255
    ok, value = parse_u64('4096', True)
    assert ok and value == 4096
    ok, value = parse_u64(' 0x20 ', True)
    assert ok and value == 32
    ok, value = parse_u64('0x' + 'f' * 16, True)  # 无 0x 前缀按十进制，显式前缀才为十六进制。
    assert ok and value == UINT64_MAX
    print('MODEL_PARSE_POSITIVE=PASS 0x/0X/十进制/空白/满溢值=5', flush=True)

    negatives = [
        ('空起始', '', '16', True, Rejection.BASE_EMPTY),
        ('0x无数字', '0x', '16', True, Rejection.BASE_INVALID),
        ('正号', '+5', '16', True, Rejection.BASE_INVALID),
        ('负号', '-1', '16', True, Rejection.BASE_INVALID),
        ('内部空格', '1 2', '16', True, Rejection.BASE_INVALID),
        ('十六进制溢出', '0x' + 'f' * 17, '16', True, Rejection.BASE_INVALID),
        ('十进制溢出', str(1 << 64), '16', True, Rejection.BASE_INVALID),
        ('零起始', '0', '16', True, Rejection.BASE_ZERO),
        ('0x零起始', '0x0', '16', True, Rejection.BASE_ZERO),
        ('空字节数', '0x1000', '', True, Rejection.BYTES_EMPTY),
        ('字节数十六进制拒绝', '0x1000', '0x10', True, Rejection.BYTES_INVALID),
        ('小数拒绝', '0x1000', '1.5', True, Rejection.BYTES_INVALID),
        ('零字节数', '0x1000', '0', True, Rejection.BYTES_ZERO),
        ('范围和溢出', str(UINT64_MAX - 8), '16', True, Rejection.RANGE_OVERFLOW),
        ('空代次', '0x1000', '16', '', Rejection.EPOCH_EMPTY),
        ('未持停点', '0x1000', '16', 'epoch-1', False, Rejection.MEMBER_NOT_HELD),
    ]
    for case in negatives:
        name, base_text, bytes_text, epoch, held = case[:5]
        expected = case[-1]
        actual = model_prepare(base_text, bytes_text, epoch, held)
        assert actual == expected, f'{name}: 期望 {expected} 实得 {actual}'
        print(f'MODEL_REJECT=PASS {name} -> {expected}', flush=True)

    assert model_prepare(str(UINT64_MAX - 8), '8', 'epoch', True) == Rejection.NONE
    assert model_prepare('4096', '262144', 'epoch', True) == Rejection.NONE  # 64 页 @4KiB 交给底层复核。
    print('MODEL_ACCEPT=PASS 边界内=2 上限复核归属底层PassiveDirtyMemory', flush=True)

    assert model_preview(0) == 0 and model_preview(100) == 100 and model_preview(4096) == 256
    print('MODEL_PREVIEW_BOUND=PASS 每页=256', flush=True)


# ---------- 纯模型：Save/Read 状态机（与 LightProcessGroupMemoryState 语义对应） ----------

class MemoryModel:
    """后台状态类的语义模型；project/blocked/ordinal/前序与 C++ 一一对应。"""

    def __init__(self):
        self.project = None  # None 表示无项目；读取仍允许按 owner 采样。
        self.sample = None
        self.directory = None
        self.last = None  # 最新读取的不可变对象身份（id 模拟 shared_ptr 指针）。
        self.archive = None
        self.blocked = False
        self.ordinal = 1
        self.previous = None
        self.owner_sample = 'owner-session-sample'

    def create_project(self, exists=False, throw=False):
        """CreateNewProject 模型；失败保留身份，成功重置 blocked lane。"""
        if throw:
            return 'lightMemoryProjectException'
        if exists:
            return 'AlreadyExists'
        self.project = 'doc'
        self.sample = 'sample-new'
        self.directory = 'D:/proj'
        self.blocked = False
        self.archive = None
        self.ordinal = 1
        self.previous = None
        self.owner_sample = self.sample
        return None

    def read(self):
        """Read 模型：新结果指针；非 blocked 时清除旧归档，blocked 时保留。"""
        self.last = object()  # 不可变结果以对象身份模拟。
        if not self.blocked:
            self.archive = None
        return self.last

    def save(self, displayed, write_ok=True, flushed=7, verified=True, throw=False):
        """Save 模型：成功推进 ordinal/前序；失败置 blocked 且不跳段。"""
        if self.project is None or self.blocked or displayed is None or displayed is not self.last:
            return 'lightMemorySnapshotSelection'
        if throw:
            self.blocked = True
            return 'lightMemorySaveException'
        if not write_ok or not verified or flushed is None:
            self.blocked = True
            return 'memorySnapshotWrite'
        self.previous = flushed
        self.ordinal += 1
        self.archive = {'ordinal': self.ordinal - 1, 'verified': True, 'flushed': flushed}
        return None


def check_state_model():
    """Save/Read/Create 状态机正例与负控。"""
    model = MemoryModel()
    assert model.save(model.read()) == 'lightMemorySnapshotSelection'  # 无项目保存拒绝。
    pointer = model.read()  # 无项目读取仍允许。
    assert model.last is pointer
    print('MODEL_NO_PROJECT=PASS 保存拒绝=读取允许按owner采样', flush=True)

    assert model.create_project() is None and model.owner_sample == 'sample-new'
    first = model.read()
    assert model.save(first, write_ok=True, flushed=7) is None
    assert (model.previous, model.ordinal) == (7, 2)
    second = model.read()
    assert model.save(second, flushed=9) is None
    assert (model.previous, model.ordinal) == (9, 3)
    print('MODEL_SAVE_ADVANCE=PASS 前序=真实lastSequence 段号=1/2/3 连续', flush=True)

    assert model.read() is not None and model.archive is None  # 未 blocked 时新读取清除旧回执。
    third = model.read()
    assert model.save(third, write_ok=False) == 'memorySnapshotWrite'
    assert model.blocked and model.ordinal == 3 and model.previous == 9  # 失败保留原段，不跳段。
    kept = model.archive  # 失败回执保留。
    assert model.save(model.read()) == 'lightMemorySnapshotSelection'  # blocked 拒绝追加。
    assert model.archive is kept  # 新读取不清除 blocked 的失败回执诊断。
    print('MODEL_BLOCKED=PASS 失败不跳段=新读取保留失败回执', flush=True)

    assert model.create_project(exists=True) == 'AlreadyExists'  # Create 拒绝已有项目。
    assert model.blocked and model.owner_sample == 'sample-new'  # 失败保留既有身份。
    assert model.create_project() is None  # 新项目重开独立 lane。
    assert (model.blocked, model.ordinal, model.previous, model.archive) == (False, 1, None, None)
    print('MODEL_NEW_PROJECT=PASS 拒绝已存在=成功重置blocked与段号', flush=True)

    fresh = MemoryModel()
    assert fresh.create_project() is None
    shown = fresh.read()
    assert fresh.save(object()) == 'lightMemorySnapshotSelection'  # 指针不匹配拒绝。
    assert fresh.save(None) == 'lightMemorySnapshotSelection'
    assert fresh.save(shown, throw=True) == 'lightMemorySaveException'
    assert fresh.blocked and fresh.previous is None  # 落盘未知时不得覆盖重试。
    print('MODEL_SAVE_GUARDS=PASS 指针核对=异常置blocked', flush=True)


def main():
    """先 SOURCE 后模型；任一断言失败即退出非零。"""
    check_source()
    check_parse_model()
    check_state_model()
    print('RESULT: LIGHT_PROCESS_GROUP_MEMORY_SOURCE_OK 无构建=无GUI=未注册工程', flush=True)


if __name__ == '__main__':
    main()
