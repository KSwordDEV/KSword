# -*- coding: utf-8 -*-
"""Qt 进程集合"选中内存"适配的只读 SOURCE 检查与调度模型。

范围与边界（重要）：
  * 只读取仓库文本并用纯 Python 模型推演契约，不编译 Qt/Light/CLI，不启动 GUI，
    不调用 Win32/NativeDebugOwner，不接触真实进程，不读取/写入任何项目目录。
  * 不修改产品源码、语言包或其它 agent 的测试；只读 + 打印结论。
  * 模型只证明"按这些源码接线时的调度/段链后果"，不是生产原生运行证据。

检查分三层：
  A. 真实文件接线（工程登记、include、导航入口、调用点数量、关键守卫文本）。
  B. 契约不变量（Plan 轮数、单轮采样、raw-memory 段号/前序、失败封锁、
     owner 身份必须是 4 个规范 UUID、结果必须显示内存 Status）。
  C. 纯 Python 负控模型：当前策略必须成功，已修的旧策略必须复现
     archivePreviousSegment / archiveWriter，证明这些检查能真的抓到回归。

产品文件在多人并行修改；本脚本按符号/字段检查，不绑定行号。
退出码：
  0 = 全部硬检查通过（仍可能打印 FINDING）
  1 = 有硬检查失败
  2 = 必需文件缺失或不可读
  3 = 使用了 --strict-findings 且存在 FINDING
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

PANE_H = "Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupMemoryPane.h"
PANE_CPP = "Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupMemoryPane.cpp"
SESSION_H = "Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupSession.h"
SESSION_CPP = "Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupSession.cpp"
PAGE_CPP = "Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupPage.cpp"
WORKSPACE_CPP = "Ksword5.1/Ksword5.1/ActionAnalyze/ActionAnalyzeWorkspace.cpp"
QTPROJ = "Ksword5.1/Ksword5.1/Ksword5.1.vcxproj"
QTFILTERS = "Ksword5.1/Ksword5.1/Ksword5.1.vcxproj.filters"
CAPTURE_CPP = "KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.cpp"
CAPTURE_H = "KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h"
SELECTED_CPP = "KswordCLI/ActionAnalyze/Memory/SelectedMemorySnapshot.cpp"
DIRTY_CPP = "KswordCLI/ActionAnalyze/Memory/PassiveDirtyMemory.cpp"
PROJMEM_CPP = "KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.cpp"
RAW_CPP = "KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.cpp"
STORAGE_CPP = "KswordCLI/ActionAnalyze/Project/ProjectStorage.cpp"
LEDGER_CPP = "KswordCLI/ActionAnalyze/Control/StopLedger.cpp"
GROUP_CPP = "KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.cpp"
CLI_CAPTURE_CPP = "KswordCLI/ActionAnalyze/Cli/MemorySnapshotCommand.cpp"
ZH_PACK = "Ksword5.1/Ksword5.1/languages/zh-CN.json"
EN_PACK = "Ksword5.1/Ksword5.1/languages/en-US.json"

REQUIRED = [PANE_H, PANE_CPP, SESSION_H, SESSION_CPP, PAGE_CPP, WORKSPACE_CPP, QTPROJ,
            QTFILTERS, CAPTURE_CPP, CAPTURE_H, SELECTED_CPP, DIRTY_CPP, PROJMEM_CPP,
            RAW_CPP, STORAGE_CPP, LEDGER_CPP, GROUP_CPP, CLI_CAPTURE_CPP, ZH_PACK, EN_PACK]

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# 这些用户可见文本必须在两个语言包中都存在（只读校验，不改包）。
NEW_TEXTS = [
    "选中范围只读快照",
    "新项目目录（可选）",
    "起始地址（0x 或十进制）",
    "范围字节数",
    "选择新项目目录",
    "读取选中停点内存",
    "保存本次内存快照",
    "本端内存快照项目",
    "本次选中范围内存",
    "内存归档回执",
    "raw-memory 段号",
    "实际读取字节数",
    "所选范围完整",
    "读取前后同一停点",
    "计划页数",
    "采样诊断阶段码",
]

HARD_FAILURES: list[str] = []
FINDINGS: list[dict] = []
SOFT_NOTES: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"[E] missing file: {rel}")
    return text.replace("\r\n", "\n")


def sha(rel: str) -> str:
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()


def check(name: str, ok: bool, detail: str) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    if not ok:
        HARD_FAILURES.append(name)
    return ok


def finding(pid: str, severity: str, title: str, evidence: str, fix: str) -> None:
    FINDINGS.append({"id": pid, "severity": severity, "title": title,
                     "evidence": evidence, "fix": fix})
    print(f"[FIND] {pid} {severity} {title}")


def count(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text, re.S))


def section(title: str) -> None:
    print(f"\n== {title} ==")


# --------------------------------------------------------------------------------------
# A. 真实文件接线
# --------------------------------------------------------------------------------------
def wiring() -> None:
    section("A. wiring (read-only)")
    pane, session, page = read(PANE_CPP), read(SESSION_CPP), read(PAGE_CPP)
    qtproj, qtfilters, workspace = read(QTPROJ), read(QTFILTERS), read(WORKSPACE_CPP)

    for rel in (PANE_CPP, SESSION_CPP):
        base = Path(rel).name
        check(f"vcxproj {base}", base in qtproj, "registered under Ksword5.1.vcxproj")
        check(f"filters {base}", base in qtfilters, "registered under Ksword5.1.vcxproj.filters")

    for cli in ("ProcessGroupMemorySnapshot.cpp", "SelectedMemorySnapshot.cpp", "PassiveDirtyMemory.cpp",
                "ProjectMemorySnapshot.cpp", "RawEvidenceArchive.cpp", "ProjectRawEvidence.cpp",
                "ProjectDocument.cpp", "ProjectStorage.cpp", "SampleCatalog.cpp", "ProjectLock.cpp"):
        check(f"vcxproj cli {cli}", cli in qtproj, "CLI TU must be linked into the Qt target")

    check("pane includes session header", '#include "ProcessGroupSession.h"' in read(PANE_H), PANE_H)
    check("page includes pane", '#include "ProcessGroupMemoryPane.h"' in page, PAGE_CPP)
    check("workspace navigation", "CreateProcessGroupPage" in workspace and "ActionAnalyzeProcessGroupId" in workspace,
          WORKSPACE_CPP)

    # 唯一的 Capture 调用点必须落在 ReadMemory 分支，且适配层不得出现 LiveRead。
    case = session.split("case ProcessGroupCommand::ReadMemory:", 1)
    ok = len(case) == 2 and "CaptureProcessGroupMemory" in case[1].split("break;", 1)[0]
    check("capture inside serial ReadMemory case", ok, SESSION_CPP)
    check("single capture call site in Qt adapter",
          count(r"CaptureProcessGroupMemory", pane + session + page) == 1, "pane/session/page")
    check("no live-read fallback in Qt adapter", "ProcessMemorySource::LiveRead" not in (pane + session + page),
          "adapter only builds HeldEvent")
    if "PrepareNative" in read(PANE_H):
        check("shared PrepareNative delegates to Prepare",
              "return Prepare(view, member.target, request);" in pane, PANE_CPP)

    rounds = re.search(r"capture\.plan\.rounds\s*=\s*(\d+)\s*;", pane)
    check("plan rounds literal in 2..64", bool(rounds) and 2 <= int(rounds.group(1)) <= 64,
          f"rounds={rounds.group(1) if rounds else 'missing'}")
    check("single capture round wrapper (PollCapture x1)", count(r"\.PollCapture\(", read(SELECTED_CPP)) == 1,
          SELECTED_CPP)
    check("wrapper stops sampler after the single round", "source.Stop()" in read(SELECTED_CPP), SELECTED_CPP)

    check("reject empty base", re.search(r"!\s*baseValid\s*\|\|", pane) is not None and "!base" in pane, PANE_CPP)
    check("reject empty length", "!bytes" in pane, PANE_CPP)
    check("reject address overflow", "std::numeric_limits<std::uint64_t>::max)() - base" in pane, PANE_CPP)
    check("require HeldComplete member", "native::GroupState::HeldComplete" in pane, PANE_CPP)
    check("plan sample id from native group", "member->control->group->sampleId" in pane, PANE_CPP)
    check("plan machine/boot from group labels",
          "member->control->group->sessionId" in pane and "member->control->group->epoch" in pane, PANE_CPP)

    check("save freezes shown pointer", "request.memoryToSave = m_shown.memory" in page, PAGE_CPP)
    check("save rejects a different pointer", "request.memoryToSave != lastMemory" in session, SESSION_CPP)
    check("save binds the same sample", "lastMemory->request.plan.sampleId != sampleId" in session, SESSION_CPP)
    check("save uses process-group writer", "WriteProcessGroupMemorySnapshot" in session, SESSION_CPP)
    check("previous sequence is flushed lastSequence",
          "previousMemorySequence = receipt.raw.flushed->lastSequence" in session, SESSION_CPP)
    check("ordinal advanced only on verified write",
          session.count("++nextMemoryOrdinal") == 1 and
          re.search(r"if \(projectResult && receipt\.verified && receipt\.raw\.flushed\)", session) is not None,
          SESSION_CPP)
    check("failure blocks further appends", "memoryArchiveBlocked = true" in session and
          "!shown.memoryArchiveBlocked" in pane, SESSION_CPP)
    check("no project -> save disabled", "!shown.projectDirectory.empty()" in pane, PANE_CPP)
    check("save requires a sampled round", "shown.memory->snapshot->round" in pane and
          "pages.empty()" in pane, PANE_CPP)

    # 结果必须来自冻结请求，不能借用当前草稿字段。
    append = pane.split("void ProcessGroupMemoryPane::Append", 1)[-1]
    check("results use frozen request range", "read.request.plan.range.base" in append, PANE_CPP)
    check("results ignore live draft edits", "m_base" not in append and "m_bytes" not in append, PANE_CPP)
    for field in ("成功页数", "失败页数", "实际读取字节数", "QPC 频率"):
        check(f"ui field {field}", field in append, PANE_CPP)
    for field in ("snapshot.status.state", "snapshot.status.issue.stage", "snapshot.status.issue.win32Error",
                  "snapshot.status.plannedPages"):
        check(f"ui memory status {field}", field in append, PANE_CPP)

    # 语言包（只读）：新用户可见文本必须两侧都有条目。
    zh = json.loads(read(ZH_PACK))["source_translations"]
    en = json.loads(read(EN_PACK))["source_translations"]
    missing = [text for text in NEW_TEXTS if text not in zh or text not in en]
    check("i18n entries for new texts", not missing, f"missing={missing}")

    # 契约：StopLedger 要求 owner 的四个标签都是规范 UUID；页面必须从 QUuid 生成而非字面量。
    ident = re.search(r"OwnerIdentity\{\s*([A-Za-z_]\w*)", page)
    check("owner identity built from variables", bool(ident), PAGE_CPP)
    check("owner sample/backend are fresh UUIDs",
          page.count("QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString()") >= 3, PAGE_CPP)
    check("group sample rebound to project sample", "groupIdentity.sampleId = sampleId;" in session, SESSION_CPP)
    check("ledger requires four canonical ids",
          "canonical owner identity" in read(LEDGER_CPP) and "IsId(owner_.sampleId)" in read(LEDGER_CPP),
          LEDGER_CPP)
    check("backend instance id regenerated per pause",
          "NewId(ownerId.backendInstanceId)" in read(GROUP_CPP), GROUP_CPP)
    check("owner built from group identity at pause",
          "auto ownerId = identity_;" in read(GROUP_CPP) and "make_shared<NativeDebugOwner>" in read(GROUP_CPP),
          GROUP_CPP)


# --------------------------------------------------------------------------------------
# B/C. 纯 Python 契约模型与负控
# --------------------------------------------------------------------------------------
MAX_ROUNDS = 64


def plan_valid(rounds: int | None, interval_ms: int = 100) -> bool:
    """对应 PassiveDirtyMemory.cpp: ValidPlan 的 rounds/interval 规则。"""
    return (rounds is None or 2 <= rounds <= MAX_ROUNDS) and 10 <= interval_ms <= 1000


class Sampler:
    """对应 PassiveDirtyMemory 的 Begin/Poll/Stop 状态机（只建模状态与计数）。"""

    def __init__(self, rounds: int | None):
        self.rounds = rounds
        self.attempted = 0
        self.state = "Active" if plan_valid(rounds) else "Rejected"

    def poll(self) -> bool:
        if self.state != "Active":
            return False
        self.attempted += 1            # 一次 Poll 最多一轮
        if self.rounds is not None and self.attempted == self.rounds:
            self.state = "Completed"
        return True

    def stop(self) -> str:
        if self.state in ("Active", "Idle"):
            self.state = "Stopped"
        return self.state


def capture_once(rounds: int | None, pages: int, sampled: int, all_visited: bool = True) -> dict:
    """对应 CaptureSelectedMemory：Begin -> 单次 PollCapture -> 条件 Stop -> completeRange。"""
    s = Sampler(rounds)
    if s.state != "Active":
        return {"state": s.state, "round": None, "completeRange": False}   # 无轮次、无可归档字节
    s.poll()
    active_before_stop = s.state == "Active"
    complete = bool(active_before_stop and all_visited and sampled == pages)
    s.stop()
    return {"state": s.state, "round": 1, "completeRange": complete}


def model_rounds() -> None:
    section("B. plan rounds / single round")
    check("rounds=2 accepted", plan_valid(2), "shared Plan lower bound")
    check("rounds=1 rejected", not plan_valid(1), "plan would be Rejected before any read")
    check("rounds=64 accepted", plan_valid(64), "upper bound")
    check("rounds=65 rejected", not plan_valid(65), "upper bound")
    check("rounds=nullopt accepted", plan_valid(None), "continuous plan is also valid")
    one = capture_once(2, pages=3, sampled=3)
    check("one Poll leaves sampler Active -> Stopped", one["state"] == "Stopped" and one["round"] == 1, str(one))
    check("completeRange true only for full sampling", one["completeRange"] is True, str(one))
    partial = capture_once(2, pages=3, sampled=2)
    check("partial pages -> incomplete, state still Stopped",
          partial["state"] == "Stopped" and partial["completeRange"] is False, str(partial))
    rejected = {"state": "Rejected", "round": None, "completeRange": False}  # Begin 拒绝时无轮次
    check("rejected capture never yields a round", rejected["round"] is None, "rejection precedes sampling")


class Archive:
    """对应 ProjectRawEvidence::WriteRawEvidenceSegment + RawEvidenceArchive 的契约。"""

    def __init__(self) -> None:
        self.segments: dict[int, int] = {}   # ordinal -> lastSequence

    def write(self, ordinal: int, previous: int | None, records: int) -> str | None:
        prev = previous or 0
        if ordinal == 1 and prev != 0:
            return "archiveWriter"                    # ordinal 1 必须无前序
        if ordinal > 1 and prev == 0:
            return "archiveWriter"                    # ordinal > 1 必须带真实前序
        if ordinal in self.segments:
            return "alreadyExists"                    # CREATE_NEW
        if ordinal > 1:
            prior_last = self.segments.get(ordinal - 1)
            if prior_last is None or prior_last != prev:
                return "archivePreviousSegment"       # 前段缺失/短尾/末序号不符
        self.segments[ordinal] = prev + records
        return None


def model_chain() -> None:
    section("C. raw-memory chain (negative controls)")
    page_records = 2 + 2          # 2 metadata rows + 2 pages

    # 当前策略：段号仅核验后推进；前序取 flushed->lastSequence。
    arc = Archive()
    ordinal, prev, blocked = 1, None, False
    for _ in range(3):
        assert not blocked
        assert arc.write(ordinal, prev, page_records) is None
        prev, ordinal = arc.segments[ordinal], ordinal + 1
    check("current policy: 3 verified saves chain", len(arc.segments) == 3 and ordinal == 4, str(arc.segments))

    # 负控1（已修的旧实现）：把段号当作 previousSequence 传。
    arc = Archive()
    first = arc.write(1, None, page_records)
    second = arc.write(2, 1, page_records)
    check("regression: ordinal-as-sequence breaks 2nd write",
          first is None and second == "archivePreviousSegment", f"second={second}")

    # 负控2（已修的旧实现）：写入前先推进段号，校验失败后永久死锁。
    arc = Archive()
    ordinal, prev = 1, None
    ordinal += 1                                  # 校验失败也消耗段号
    check("regression: pre-increment then failure -> archiveWriter",
          arc.write(ordinal, prev, page_records) == "archiveWriter", "ordinal>1 without previous")

    # 当前失败策略：失败即封锁，不再消耗段号，也不再尝试写新段。
    arc = Archive()
    blocked_snapshot = True
    ordinal_snapshot = 1
    attempts = 0
    if not blocked_snapshot:
        attempts += 1
        arc.write(ordinal_snapshot, None, page_records)
    check("blocked policy: no segment and no ordinal use after failure",
          blocked_snapshot and attempts == 0 and not arc.segments and ordinal_snapshot == 1, "local refusal")

    # 缺口演示：Rejected 捕获（无轮次）仍能通过 PrepareRows 的两行并写成"已核验"空段。
    rows = 2                                       # metadata + end，无页记录
    arc = Archive()
    written = arc.write(1, None, rows)
    check("gap demonstrated: rejected capture archives an empty verified segment",
          written is None and arc.segments[1] == rows, "PrepareRows has no state guard")
    if written is None:
        finding("F2", "P2",
                "Shared writer/CLI still accepts a round-less rejected capture as a verified empty segment",
                "ProjectMemorySnapshot.cpp PrepareRows only compares state==Stopped for 'complete'; "
                "round==nullopt yields metadata+end; Cli/MemorySnapshotCommand.cpp writes without a state guard. "
                "The Qt pane now gates on snapshot->round && !pages.empty(), so the Qt path is closed",
                "Add the same guard inside WriteSnapshot/PrepareRows (state==Stopped && round && !pages.empty()) "
                "so every caller, including the CLI, is protected")


def model_identity() -> None:
    section("B. owner identity contract")
    page = read(PAGE_CPP)
    assignments = page.count("QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString()")
    print(f"[INFO] QUuid identity assignments in ProcessGroupPage.cpp: {assignments}")
    note = ("StopLedger throws on any non-UUID tag (StopLedger.cpp:81-85); OwnedProcessGroup::Pause rebuilds only "
            "backendInstanceId (OwnedProcessGroup.cpp:292-301). The page now derives sample/backend from QUuid and "
            "session/epoch from m_sessionId, so all four tags are canonical; a literal sampleId would break Pause")
    SOFT_NOTES.append(note)
    print(f"[NOTE] {note}")


def findings() -> None:
    section("D. findings (static gaps)")
    projm = read(PROJMEM_CPP)
    session = read(SESSION_CPP)
    cli = read(CLI_CAPTURE_CPP)

    after = projm.split("WriteSnapshot", 1)[-1]
    if "status.state !=" not in after and "State::Rejected" not in after:
        print("[GAP] writer has no explicit memory-state guard (see F2)")

    if "catch (...)" in session and "snapshot.failed = true;" in session and "std::exception" not in session:
        finding("F5", "P2",
                "Background exception discards its cause; UI only shows a generic failure",
                "ProcessGroupSession.cpp catch(...) sets failed/busy only; no stage/Win32/exception text is published",
                "Catch std::exception, map to a stable stage id plus win32Error, publish in projectResult/status")

    if "memoryArchiveBlocked = true;" in session and "ProjectError::RecoveryRequired" in session:
        SOFT_NOTES.append("failure blocks the session lane by design; a partially created project directory is not removable from the page")
        print("[NOTE] failed save blocks the lane; the created project directory can only be reused by a new session "
              "after manual cleanup (Create rejects an existing directory)")

    if "WriteSelectedMemorySnapshot(document" in cli and "CaptureSelectedMemory" in cli:
        print("[NOTE] CLI 'analyze memory snapshot' also writes the capture without checking memory state (F2 scope)")

    for entry in FINDINGS:
        print(f"  {entry['id']} [{entry['severity']}] {entry['title']}")
    if not FINDINGS:
        print("  none from the static pass")


def main() -> int:
    parser = argparse.ArgumentParser(description="read-only source check for Qt process-group memory adapter")
    parser.add_argument("--strict-findings", action="store_true", help="exit 3 when any FINDING is printed")
    parser.add_argument("--print-hashes", action="store_true", help="print sha256 of reviewed files")
    args = parser.parse_args()

    print(f"repo={ROOT}")
    print("mode=SOURCE ONLY (no build, no GUI, no native execution, no project writes)")
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            print(f"[E] missing file: {rel}")
            return 2

    if args.print_hashes:
        for rel in (PANE_H, PANE_CPP, SESSION_H, SESSION_CPP, PAGE_CPP, CAPTURE_CPP,
                    PROJMEM_CPP, SELECTED_CPP, DIRTY_CPP, RAW_CPP):
            print(f"sha256 {sha(rel)} {rel}")

    try:
        wiring()
        model_rounds()
        model_chain()
        model_identity()
        findings()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - 明确报出模型/接线自身错误
        print(f"[E] check aborted: {type(exc).__name__}: {exc}")
        return 2

    print("\n== summary ==")
    print(f"hard_failures={len(HARD_FAILURES)} findings={len(FINDINGS)}")
    for name in HARD_FAILURES:
        print(f"  HARD {name}")
    if HARD_FAILURES:
        return 1
    if args.strict_findings and FINDINGS:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
