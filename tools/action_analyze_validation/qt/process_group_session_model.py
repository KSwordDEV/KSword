# -*- coding: utf-8 -*-
"""Qt ProcessGroupSession 的无构建调度模型用例。

用途：在不编译、不启动 Qt/GUI、不触碰 NativeDebugOwner 的前提下，用测试替身
验证 ProcessGroupSession::Shared::Run / Submit / Close 的调度与生命周期契约：

  1. 后台单在途（同一 group 任一时刻只有一项原生调用）；
  2. 已接纳命令在 Close 后不被丢弃（pending 优先级高于关闭）；
  3. 清退未 clean 时不销毁原生 group，线程与共享状态保活；
  4. Close 之后仅 Recover 可被 Submit 接纳；
  5. worker 先把 pending 取完才转 Close；
  6. 只有 clean Close 的那一轮才销毁 group 并置 retired。

模型逐字对应 Ksword5.1/Ksword5.1/ActionAnalyze/ProcessGroupSession.cpp 的分支，
只把原生 group 换成 FakeGroup。用例是确定性的交错调度（用 hook 在“原生调用
执行中”注入 UI 动作），不验证原生调试器本身的任何行为。
"""

from __future__ import annotations

import sys


class FakeGroup:
    """原生 OwnedProcessGroup 的测试替身：只记录调用与销毁，不模拟原生事件。"""

    def __init__(self, clean_script):
        self.clean_script = list(clean_script)
        self.calls = []
        self.destroyed = False
        self.in_flight = 0
        self.max_in_flight = 0

    def call(self, command):
        assert not self.destroyed, "clean 之后不得再调用已销毁的 group"
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.calls.append(command)
        # 原生调用在锁外执行；本替身不做任何真实等待。
        self.in_flight -= 1
        clean = self.clean_script.pop(0) if self.clean_script else True
        return {"clean": clean, "state": "Closed" if clean else "Closing"}

    def destroy(self):
        assert not self.destroyed
        self.destroyed = True


class SessionModel:
    """ProcessGroupSession::Shared 的逐分支模型。"""

    def __init__(self, clean_script, hook=None):
        self.group = FakeGroup(clean_script)
        self.hook = hook  # hook(command, model) 在“原生调用执行中”触发 UI 动作。
        self.pending = None
        self.conn = {
            "busy": False, "closing": False, "retired": False,
            "failed": False, "revision": 0,
        }
        self.close_requested = False
        self.ended = False
        self.rounds = 0

    # Submit：忙/已结束/关闭中（除 Recover）/已有 pending 都拒绝。
    def submit(self, request):
        recovery = request == "Recover"
        if (self.ended or (self.close_requested and not recovery)
                or self.pending is not None or self.conn["busy"]):
            return False
        self.pending = request
        self.conn["busy"] = True
        return True

    # Close：不取消已接纳的 pending；只置标志并唤醒。
    def close(self):
        self.close_requested = True
        self.conn["closing"] = True
        return True

    def read(self):
        return dict(self.conn)

    # worker 一轮：wait -> 取 pending（优先）否则 Close 否则周期 Query -> 执行 -> 发布。
    def worker_round(self):
        self.rounds += 1
        closing = self.close_requested  # 循环开头捕获的 closing（发布 cleanClose 用它）。
        if self.pending is not None:
            request = self.pending
            self.pending = None
        elif closing:
            request = "Close"
        else:
            request = "Query"  # wait_for 超时后的真实状态回读。
        self.conn["busy"] = True

        if self.hook is not None:
            self.hook(request, self)  # UI 在原生调用执行中的交错动作。

        result = self.group.call(request)
        clean_close = closing and request == "Close" and result["clean"]

        self.conn["busy"] = False
        self.conn["closing"] = self.close_requested  # 发布时读当前值，不是捕获值。
        self.conn["retired"] = clean_close
        self.ended = clean_close
        self.conn["revision"] += 1
        if clean_close:
            self.group.destroy()
            return "exit"
        return "continue"


def check(label, condition):
    if not condition:
        print("FAIL:", label)
        return False
    print("PASS:", label)
    return True


def case_single_in_flight():
    # 原生调用执行中再次 Submit 必被拒；max_in_flight 恒为 1。
    seen = {}

    def hook(command, model):
        seen["during"] = model.submit("Query")

    m = SessionModel([True, True], hook=hook)
    assert m.submit("Pause") is True
    m.worker_round()
    return (check("后台单在途：忙时 Submit 被拒", seen.get("during") is False)
            and check("后台单在途：最大并发调用数为 1", m.group.max_in_flight == 1))


def case_accepted_not_dropped_on_close():
    # pending 中的 Pause 在 Close 之后仍先执行，之后才轮到 Close。
    m = SessionModel([True, True, True])
    assert m.submit("Pause") is True
    m.close()  # 接纳后才请求关闭。
    m.worker_round()  # 取 pending，不转 Close。
    m.worker_round()  # 无 pending，才执行 Close。
    return (check("已接纳命令不被丢弃：先 Pause 后 Close",
                  m.group.calls[:2] == ["Pause", "Close"])
            and check("已接纳命令不被丢弃：Pause 确实执行过", "Pause" in m.group.calls))


def case_not_clean_keeps_owner():
    # 首次 Close 未 clean：group 不销毁、线程不结束；下一轮重试到 clean 才销毁。
    m = SessionModel([False, True])
    m.close()
    first = m.worker_round()
    preserved = (not m.group.destroyed and not m.ended
                 and m.read()["retired"] is False and first == "continue")
    second = m.worker_round()
    return (check("清退未 clean：group 保活且线程未结束", preserved)
            and check("清退未 clean：重试到 clean 后才销毁并 retired",
                      second == "exit" and m.group.destroyed
                      and m.ended and m.read()["retired"] is True))


def case_pending_before_close():
    # Close 未 clean 后 worker 在 500ms 等待窗口内 busy=false；
    # 此时 Submit(Recover) 被接纳，worker 下一轮先把 Recover 取完才再 Close。
    m = SessionModel([False, True])
    m.close()
    m.worker_round()  # Close（未 clean），进入等待窗口，busy=false。
    accepted_recover = m.submit("Recover")  # 等待窗口内 UI 提交恢复。
    accepted_query = m.submit("Query")      # 已有 pending，且关闭中，必拒。
    m.worker_round()  # pending 优先，执行 Recover。
    m.worker_round()  # 无 pending，执行 Close（clean）并退出。
    return (check("关闭后仅 Recover 可 Submit（等待窗口）",
                  accepted_recover is True and accepted_query is False)
            and check("worker 先取 pending 才转 Close",
                      m.group.calls == ["Close", "Recover", "Close"])
            and check("Recover 与重试完成后才销毁 group", m.group.destroyed is True))


def case_shared_lifetime_until_clean():
    # 共享状态（由 group.destroyed 代表）只在 clean Close 那一轮释放。
    m = SessionModel([False, False, True])
    m.close()
    states = []
    for _ in range(2):
        m.worker_round()
        states.append((m.group.destroyed, m.ended, m.read()["retired"]))
    alive = all(not destroyed and not ended and not retired
                for destroyed, ended, retired in states)
    m.worker_round()
    return (check("clean 前共享状态一直保活", alive)
            and check("clean Close 后才结算", m.group.destroyed and m.ended
                      and m.read()["retired"] is True))


def applied_operation(operation):
    """对应 ProcessGroupPage.cpp 的 AppliedOperation：准入且真实执行过成员。"""
    return operation["ledgerResult"] == "Applied" and bool(operation["outcomes"])


def project_operation(result):
    """对应状态/最近操作/历史票据三处投影：取原 operation 三字段，不用重放顶层。"""
    operation = result["operation"]
    shown = {
        "ledgerResult": operation["ledgerResult"],
        "stage": operation["stage"],
        "win32Error": operation["win32Error"],
        "replay": result["ledgerResult"] == "Duplicate",
        "noMemberAction": not applied_operation(operation),
        "outcomes": [(item["target"], item["control"]) for item in operation["outcomes"]],
    }
    return shown


def case_operation_projection_replay():
    # Duplicate 顶层不是首次成功：三字段取原票据，且显示重放而非首次执行。
    result = {
        "ledgerResult": "Duplicate",
        "stage": "process-group-observed",
        "win32Error": 0,
        "operation": {
            "ledgerResult": "Applied", "stage": "process-group-held", "win32Error": 0,
            "outcomes": [{"target": 100, "control": "Held"}],
        },
    }
    shown = project_operation(result)
    return (check("重放：展示原票据账本结果而非顶层Duplicate",
                  shown["ledgerResult"] == "Applied")
            and check("重放：展示原票据诊断/错误而非当前集合状态",
                      shown["stage"] == "process-group-held" and shown["win32Error"] == 0)
            and check("重放：标记原票据重放非首次执行", shown["replay"] is True)
            and check("重放：有outcomes不算无成员动作", shown["noMemberAction"] is False))


def case_operation_projection_rejected():
    # 无outcomes的拒绝票据不能当作成功，也不能进入Recover资格。
    operation = {
        "ledgerResult": "InvalidTransition", "stage": "process-group-pause-unavailable",
        "win32Error": 5, "outcomes": [],
    }
    result = {"ledgerResult": "InvalidTransition", "operation": operation}
    shown = project_operation(result)
    return (check("拒绝票据：AppliedOperation为假", applied_operation(operation) is False)
            and check("拒绝票据：展示原拒绝三字段",
                      shown["ledgerResult"] == "InvalidTransition"
                      and shown["stage"] == "process-group-pause-unavailable"
                      and shown["win32Error"] == 5)
            and check("拒绝票据：标记未执行成员", shown["noMemberAction"] is True)
            and check("拒绝票据：不被当成成功票据", shown["replay"] is False))


def case_member_control_preserved():
    # 成员control逐项保留，顶层三字段不覆盖各行回执。
    result = {
        "ledgerResult": "Applied",
        "operation": {
            "ledgerResult": "Applied", "stage": "process-group-held", "win32Error": 0,
            "outcomes": [
                {"target": 100, "control": "Held"},
                {"target": 200, "control": "Rejected"},
            ],
        },
    }
    shown = project_operation(result)
    return (check("成员control各自保留，不由顶层三字段推断",
                  shown["outcomes"] == [(100, "Held"), (200, "Rejected")])
            and check("部分失败不再被汇总为全组成功",
                      any(control == "Rejected" for _, control in shown["outcomes"])))


def main():
    cases = [
        case_single_in_flight,
        case_accepted_not_dropped_on_close,
        case_not_clean_keeps_owner,
        case_pending_before_close,
        case_shared_lifetime_until_clean,
        case_operation_projection_replay,
        case_operation_projection_rejected,
        case_member_control_preserved,
    ]
    failed = sum(0 if case() else 1 for case in cases)
    print("RESULT: %d/%d cases passed" % (len(cases) - failed, len(cases)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
