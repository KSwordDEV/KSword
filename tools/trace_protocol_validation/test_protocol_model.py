"""用标准库验证示意协议状态模型；固定时序与独立预期，不验证产品实现。"""

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
from itertools import combinations, permutations
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
# 先禁用字节码再导入同目录模型；不导入生产模块或外部依赖。
from model import (
    Capacity, ConfigAck, Faults, Generation, ProhibitedTransition,
    SemanticBudget, Startup, StopControl, StopToken,
)


# 只收集本轮有限实验摘要；EVENTS 是枚举使用的固定六事件字母表。
EXPERIMENTS = {}
EVENTS = ("reader", "ready", "apply", "ack", "coverage", "release")
RESULT_RELATIVE = ".codex-build-logs/behavior-planning/action-analyze-protocol-model-results.json"


def ready_startup(faults=Faults()):
    """输入可选负控开关，返回已应用配置、尚未接收 ACK 的启动模型。"""
    model = Startup(faults=faults)
    model.start_reader()
    model.agent_ready()
    model.apply_config()
    return model


def stopped(faults=Faults(), foreign_holds=frozenset()):
    """输入负控和外部持有集合，返回已收到双线程停止回执的模型与停点。"""
    model = StopControl(faults=faults, foreign_holds=foreign_holds)
    token = model.request_stop(1)
    model.confirm_stopped(token, 0)
    model.confirm_stopped(token, 1)
    return model, token


def execute_event(model, event):
    """输入启动模型及固定事件名，执行一次模型操作并返回其可观察结果。"""
    # 事件与操作是测试中的固定映射，不接受外部代码或任意事件处理器。
    actions = {
        "reader": model.start_reader,
        "ready": model.agent_ready,
        "apply": model.apply_config,
        "ack": lambda: model.receive_ack(model.produce_ack()),
        "coverage": lambda: model.publish_coverage(frozenset(("api", "execution_probe"))),
        "release": model.release_initiator,
    }
    return actions[event]()


def oracle_order(order):
    """输入事件排列，按独立声明的先决条件返回合法性，不读取模型实现。"""
    # 预期来自测试规格；不能向被测模型询问下一步应当是什么。
    prerequisites = {
        "reader": set(), "ready": {"reader"}, "apply": {"ready"},
        "ack": {"apply"}, "coverage": {"ready"}, "release": {"ack", "coverage"},
    }
    seen = set()  # 最多六项，记录此排列已经经过的事件。
    for event in order:
        if not prerequisites[event] <= seen:
            return False
        seen.add(event)
    return True


def startup_accepts(order, faults=Faults()):
    """输入排列与负控开关，仅观察是否放行，返回布尔结果。"""
    model = Startup(faults=faults)
    try:
        for event in order:
            execute_event(model, event)
    except ProhibitedTransition:
        return False
    return model.phase == "admitted"


class ModelCase(unittest.TestCase):
    """断言辅助类；所有 test_ 方法仅输入 self，返回 None 或抛出断言失败。"""

    def rejected(self, code, action):
        """输入预期原因码和测试动作，断言它明确拒绝；不把拒绝视为进度。"""
        with self.assertRaises(ProhibitedTransition) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def trace(self, actions):
        """输入有限测试动作序列，返回结果列表；禁止转换保留其明确原因码。"""
        values = []
        for action in actions:
            try:
                values.append(action())
            except ProhibitedTransition as error:
                values.append("reject:" + error.code)
        return values


class StartupTests(ModelCase):
    """启动、覆盖、配置代次与目标可执行依赖的确定性测试。"""

    def test_independent_expected_startup_trace(self):
        """用手写结果序列核对读端、配置 ACK 与完整覆盖三个屏障。"""
        model = Startup()
        actual = self.trace((
            model.agent_ready, model.start_reader, model.agent_ready,
            model.release_initiator, model.apply_config,
            lambda: model.receive_ack(model.produce_ack()), model.release_initiator,
            lambda: model.publish_coverage(frozenset(("api",))), model.release_initiator,
            lambda: model.publish_coverage(frozenset(("api", "execution_probe"))),
            model.release_initiator,
        ))
        self.assertEqual(actual, [
            "reject:READER_NOT_STARTED", "reader_started", "agent_ready",
            "reject:CONFIG_ACK_MISSING", "config_applied", "config_ack_received",
            "reject:REQUIRED_COVERAGE_MISSING", "coverage_received",
            "reject:REQUIRED_COVERAGE_MISSING", "coverage_received", "initiator_released",
        ])
        model.check()

    def test_all_720_startup_event_orders_against_independent_oracle(self):
        """枚举六事件的全部排列，与独立先决关系比较，统计接受和拒绝数。"""
        totals = Counter()
        for order in permutations(EVENTS):
            with self.subTest(order=order):
                model = Startup()
                accepted = True
                try:
                    for event in order:
                        execute_event(model, event)
                        model.check()
                except ProhibitedTransition:
                    accepted = False
                # 每个排列单独建模；第一个非法转换就终止，不假装后续已执行。
                self.assertEqual(accepted, oracle_order(order))
                self.assertEqual(model.phase == "admitted", accepted)
                totals["accepted" if accepted else "rejected"] += 1
        self.assertEqual(dict(totals), {"accepted": 3, "rejected": 717})
        EXPERIMENTS["startup_permutations"] = dict(totals, total=720)

    def test_each_missing_handshake_event_blocks_admission(self):
        """依次丢弃五种必要握手事件，确认每种故障都无法完成准入。"""
        cases = []
        for omitted in EVENTS[:-1]:
            order = tuple(event for event in EVENTS if event != omitted)
            with self.subTest(omitted=omitted):
                self.assertFalse(startup_accepts(order))
                cases.append(omitted)
        EXPERIMENTS["lost_handshake_event_cases"] = cases

    def test_cancelled_generation_stale_ack_cannot_admit_next_generation(self):
        """延迟上一代已生成 ACK，再取消重启，核对旧 ACK 不能替代新回执。"""
        model = ready_startup()
        delayed = model.produce_ack()
        actual = self.trace((model.cancel, model.next_generation, model.start_reader,
                             model.agent_ready, model.apply_config,
                             lambda: model.receive_ack(delayed),
                             lambda: model.publish_coverage(frozenset(("api", "execution_probe"))),
                             model.release_initiator,
                             lambda: model.receive_ack(model.produce_ack()),
                             model.release_initiator))
        self.assertEqual(actual, [
            "generation_cancelled", "generation_started", "reader_started", "agent_ready",
            "config_applied", "stale_ack_rejected", "coverage_received",
            "reject:CONFIG_ACK_MISSING", "config_ack_received", "initiator_released",
        ])
        self.assertEqual(model.stale_acks, 1)
        model.check()

    def test_wrong_session_revision_and_ack_before_config(self):
        """分别验证未应用配置、其它会话和错误版本回执的明确拒绝。"""
        model = Startup()
        self.rejected("ACK_BEFORE_APPLY", model.produce_ack)
        model.start_reader()
        model.agent_ready()
        self.rejected("ACK_BEFORE_APPLY", lambda: model.receive_ack(ConfigAck(model.token, 1)))
        model.apply_config()
        self.assertEqual(model.receive_ack(ConfigAck(Generation(2, 1), 1)),
                         "stale_ack_rejected")
        self.rejected("CONFIG_REVISION_MISMATCH",
                      lambda: model.receive_ack(ConfigAck(model.token, 2)))
        self.assertIsNone(model.ack)
        model.check()

    def test_all_user_threads_frozen_split_pipe_cannot_produce_fresh_ack(self):
        """全部用户线程停止后拆分管道仍无新 ACK，必须先由外部恢复选定线程。"""
        model = ready_startup()
        actual = self.trace((model.suspend_all_target_user_threads, model.split_pipe,
                             model.produce_ack,
                             model.external_resume_selected_control_thread,
                             lambda: model.receive_ack(model.produce_ack())))
        self.assertEqual(actual, [
            "all_target_user_threads_suspended", "split_pipe_only",
            "reject:TARGET_CANNOT_EXECUTE", "external_control_resumed_thread_0",
            "config_ack_received",
        ])
        self.assertEqual(model.runnable, frozenset((0,)))
        model.check()

    def test_all_user_threads_frozen_also_blocks_ready_and_config(self):
        """同一可执行约束也必须阻止目标就绪、应用配置及发布覆盖。"""
        model = Startup()
        model.start_reader()
        model.suspend_all_target_user_threads()
        self.rejected("TARGET_CANNOT_EXECUTE", model.agent_ready)
        model.external_resume_selected_control_thread()
        model.agent_ready()
        model.suspend_all_target_user_threads()
        self.rejected("TARGET_CANNOT_EXECUTE", model.apply_config)
        self.rejected("TARGET_CANNOT_EXECUTE",
                      lambda: model.publish_coverage(frozenset(("api",))))
        model.check()

    def test_buffered_ack_is_distinct_from_fresh_target_execution(self):
        """区分此前已生成的缓冲回执与停止之后依赖目标代码执行的新回执。"""
        model = ready_startup()
        buffered_ack = model.produce_ack()
        model.suspend_all_target_user_threads()
        self.assertEqual(model.receive_ack(buffered_ack), "config_ack_received")
        self.assertEqual(model.runnable, frozenset())
        model.check()

    def test_generation_counter_never_wraps(self):
        """以固定 254 次推进到有限代次边界，确认下一次推进显式拒绝。"""
        model = Startup()
        for _ in range(254):
            model.cancel()
            model.next_generation()
        model.cancel()
        self.rejected("GENERATION_EXHAUSTED", model.next_generation)
        self.assertEqual(model.token, Generation(1, 255))


class StopTests(ModelCase):
    """停止屏障、重设防、命令幂等与会话/停点隔离的模型测试。"""

    def test_partial_stop_barrier_and_rearm_order_expected_trace(self):
        """用手写时序验证停稳后才恢复执行，离页并重设防后才继续。"""
        model = StopControl()
        token = model.request_stop(1)
        actual = self.trace((
            lambda: model.external_run_selected(token, 0),
            lambda: model.confirm_stopped(token, 0),
            lambda: model.external_run_selected(token, 0),
            lambda: model.confirm_stopped(token, 1),
            lambda: model.external_run_selected(token, 0),
            lambda: model.rearm(token), lambda: model.continue_command(2, token),
            lambda: model.selected_left_page(token), lambda: model.rearm(token),
            lambda: model.continue_command(2, token),
        ))
        self.assertEqual(actual, [
            "reject:STOP_BARRIER_INCOMPLETE", "thread_stop_confirmed",
            "reject:STOP_BARRIER_INCOMPLETE", "thread_stop_confirmed",
            "selected_thread_released", "reject:SELECTED_STILL_INSIDE_OR_BARRIER_INCOMPLETE",
            "reject:PAGE_NOT_REARMED", "selected_thread_outside_page", "page_rearmed",
            "own_holds_released",
        ])
        self.assertEqual(model.foreign_holds, frozenset())
        model.check()

    def test_foreign_hold_blocks_selected_execution_and_survives_own_continue(self):
        """其它所有者的持有既阻止选定执行，也不会被本模型的继续操作解除。"""
        model, token = stopped(foreign_holds=frozenset((0,)))
        self.rejected("FOREIGN_HOLD_BLOCKS_EXECUTION", lambda: model.external_run_selected(token, 0))
        self.assertEqual((model.holds, model.executable), (frozenset((0, 1)), False))
        model.rearm(token)
        self.assertEqual(model.continue_command(2, token), "own_holds_released")
        self.assertEqual((model.holds, model.foreign_holds), (frozenset(), frozenset((0,))))
        model.check()

    def test_duplicate_request_is_idempotent_and_new_id_is_new_command(self):
        """同 ID 返回缓存且无副作用；新 ID 另作命令，不把两者混淆。"""
        model, token = stopped()
        self.assertEqual(model.request_stop(1), token)
        self.assertEqual((model.epoch, model.effects), (1, 1))
        self.rejected("STOP_STATE", lambda: model.request_stop(2))
        model.rearm(token)
        model.continue_command(2, token)
        new_token = model.request_stop(3)
        self.assertEqual(new_token, StopToken(1, 2))
        self.assertEqual(model.effects, 3)
        self.assertEqual(model.request_stop(1), token)  # 返回旧回执，不创建新停点。
        self.assertEqual(model.stop, new_token)
        model.check()

    def test_duplicate_continue_cannot_release_next_stop_and_new_stale_rejected(self):
        """重放旧继续只返回缓存；改用新命令 ID 仍须通过当前停点身份检查。"""
        model, old = stopped()
        model.rearm(old)
        model.continue_command(2, old)
        current = model.request_stop(3)
        model.confirm_stopped(current, 0)
        model.confirm_stopped(current, 1)
        model.rearm(current)
        self.assertEqual(model.continue_command(2, old), "own_holds_released")
        self.assertEqual((model.stop, model.holds, model.effects),
                         (StopToken(1, 2), frozenset((0, 1)), 3))
        self.rejected("STALE_STOP", lambda: model.continue_command(4, old))
        self.assertEqual(model.continue_command(4, current), "own_holds_released")
        self.assertEqual(model.effects, 4)
        model.check()

    def test_reused_command_id_different_payload_is_explicit_conflict(self):
        """同一命令 ID 改成不同载荷时必须报告冲突，不能改写原始结果。"""
        model, token = stopped()
        model.rearm(token)
        self.rejected("COMMAND_ID_CONFLICT", lambda: model.continue_command(1, token))
        self.assertEqual(model.holds, frozenset((0, 1)))
        model.check()

    def test_session_epoch_prevents_same_stop_number_replay(self):
        """新会话复用停点序号 1 时，旧会话的继续不能释放新停止组。"""
        model, old = stopped()
        model.rearm(old)
        model.continue_command(2, old)
        model.begin_shutdown()
        model.finish_shutdown()
        model.next_session()
        current = model.request_stop(1)
        model.confirm_stopped(current, 0)
        model.confirm_stopped(current, 1)
        model.rearm(current)
        self.assertEqual(current, StopToken(2, 1))
        self.rejected("STALE_STOP", lambda: model.continue_command(2, old))
        self.assertEqual(model.stop, current)
        model.check()

    def test_command_ledger_exhaustion_is_explicit_and_keeps_recovery(self):
        """四条命令后显式拒绝新命令，同时保留旧命令的可重试缓存。"""
        model = StopControl()
        for request_id, continue_id in ((1, 2), (3, 4)):
            token = model.request_stop(request_id)
            model.confirm_stopped(token, 0)
            model.confirm_stopped(token, 1)
            model.rearm(token)
            model.continue_command(continue_id, token)
        self.rejected("COMMAND_LEDGER_EXHAUSTED", lambda: model.request_stop(5))
        self.assertEqual((len(model.commands), model.epoch), (4, 2))
        self.assertEqual(model.continue_command(4, StopToken(1, 2)), "own_holds_released")
        model.check()


class CapacityAndLifetimeTests(ModelCase):
    """容量与关闭故障测试；不测量真实传输、线程调度或恢复时延。"""

    def test_every_six_telemetry_two_control_interleaving_preserves_reserve(self):
        """直接构造控制事件的两个位置，核对全部 28 种到达次序均无丢失。"""
        # combinations 只产生 28 项，避免先生成含重复项的 8! 个排列。
        schedules = [tuple("C" if index in positions else "T" for index in range(8))
                     for positions in combinations(range(8), 2)]
        self.assertEqual(len(schedules), 28)
        for schedule in sorted(schedules):
            queue = Capacity()
            for event in schedule:
                outcome = queue.put_telemetry() if event == "T" else queue.put_control()
                self.assertEqual(outcome, "telemetry_queued" if event == "T" else "control_queued")
                queue.check()
            self.assertEqual((queue.telemetry, queue.control, queue.telemetry_dropped), (6, 2, 0))
        EXPERIMENTS["queue_interleavings"] = {"total": 28, "accepted_without_loss": 28}

    def test_telemetry_saturation_preserves_both_reserved_control_slots(self):
        """遥测超量时保留两个控制槽位，控制也满时必须报告显式错误。"""
        queue = Capacity()
        actual = [queue.put_telemetry() for _ in range(10)]
        actual.extend((queue.put_control(), queue.put_control()))
        self.assertEqual(actual, ["telemetry_queued"] * 6
                         + ["telemetry_capacity_rejected"] * 4 + ["control_queued"] * 2)
        self.rejected("CONTROL_CAPACITY_EXHAUSTED", queue.put_control)
        self.assertEqual((queue.telemetry, queue.control, queue.pending), (6, 2, 8))
        self.assertEqual([queue.drain_one() for _ in range(8)],
                         ["control_drained"] * 2 + ["telemetry_drained"] * 6)
        self.rejected("QUEUE_EMPTY", queue.drain_one)
        self.assertEqual((queue.telemetry_dropped, queue.control_rejected), (4, 1))
        queue.check()

    def test_control_can_borrow_free_telemetry_capacity_but_not_exceed_total(self):
        """控制可借用空闲遥测容量，但不得越过总量上限。"""
        queue = Capacity()
        for _ in range(8):
            queue.put_control()
        self.assertEqual(queue.put_telemetry(), "telemetry_capacity_rejected")
        self.rejected("CONTROL_CAPACITY_EXHAUSTED", queue.put_control)
        queue.check()

    def test_shutdown_drains_control_before_telemetry_and_counts_late_events(self):
        """排空期间拒收新遥测、接收有界控制，并在队列清零前拒绝关闭。"""
        model = StopControl()
        model.queue.put_telemetry()
        actual = self.trace((model.begin_shutdown, model.queue.put_telemetry,
                             model.queue.put_control, model.finish_shutdown,
                             model.queue.drain_one, model.queue.drain_one,
                             model.finish_shutdown))
        self.assertEqual(actual, [
            "shutdown_draining", "late_telemetry_rejected", "control_queued",
            "reject:DRAIN_INCOMPLETE", "control_drained", "telemetry_drained",
            "shutdown_closed",
        ])
        self.assertEqual(model.queue.late_events, 1)
        model.check()

    def test_closed_session_rejects_late_control_and_telemetry_without_reopening(self):
        """已关闭模型必须拒绝迟到控制和遥测，不能重新开启旧队列。"""
        model = StopControl()
        model.begin_shutdown()
        model.finish_shutdown()
        self.rejected("QUEUE_CLOSED", model.queue.put_control)
        self.rejected("QUEUE_CLOSED", model.queue.put_telemetry)
        self.rejected("STOP_STATE", lambda: model.request_stop(1))
        self.assertEqual((model.phase, model.queue.pending), ("closed", 0))
        model.check()

    def test_pending_stop_shutdown_keeps_responsibility_and_accepts_late_stop_ack(self):
        """未确认的停止请求仍有责任；排空期收到停止回执后继续完成恢复。"""
        model = StopControl()
        token = model.request_stop(1)
        model.begin_shutdown()
        self.rejected("RECOVERY_UNRESOLVED", model.finish_shutdown)
        self.rejected("STOP_STATE", lambda: model.request_stop(2))
        model.confirm_stopped(token, 0)
        model.confirm_stopped(token, 1)
        model.rearm(token)
        model.continue_command(2, token)
        self.assertEqual(model.finish_shutdown(), "shutdown_closed")
        model.check()

    def test_owner_lost_failed_recovery_never_clears_own_or_foreign_holds(self):
        """失联及恢复失败保留全部责任；只有外部成功确认才清理自身持有。"""
        model, token = stopped(foreign_holds=frozenset((0, 1)))
        actual = self.trace((model.owner_lost,
                             lambda: model.external_recovery_result(token, False),
                             model.finish_shutdown, model.next_session))
        self.assertEqual(actual, [
            "owner_lost_recovery_pending", "recovery_failed_responsibility_retained",
            "reject:RECOVERY_UNRESOLVED", "reject:SESSION_UNRESOLVED",
        ])
        self.assertEqual((model.stop, model.holds, model.foreign_holds),
                         (token, frozenset((0, 1)), frozenset((0, 1))))
        self.assertTrue(model.recovery_required)
        model.check()
        self.assertEqual(model.external_recovery_result(token, True), "external_recovery_confirmed")
        self.assertEqual(model.finish_shutdown(), "shutdown_closed")
        self.assertEqual(model.foreign_holds, frozenset((0, 1)))
        model.check()

    def test_owner_lost_before_stop_ack_retains_unresolved_request(self):
        """停止 ACK 尚未到达时失联，不能因当前持有集合为空而假报恢复完成。"""
        model = StopControl()
        token = model.request_stop(1)
        model.owner_lost()
        self.assertTrue(model.recovery_required)
        self.assertEqual(model.holds, frozenset())
        self.rejected("RECOVERY_UNRESOLVED", model.finish_shutdown)
        model.confirm_stopped(token, 0)
        self.rejected("STALE_STOP", lambda: model.external_recovery_result(StopToken(2, 1), True))
        self.assertEqual((model.stop, model.holds), (token, frozenset((0,))))
        model.check()

    def test_owner_lost_cannot_issue_ordinary_continue_or_selected_run(self):
        """失联所有者的普通命令不能绕过独立恢复确认来释放停止责任。"""
        model, token = stopped()
        model.rearm(token)
        model.owner_lost()
        self.rejected("CONTINUE_OWNER_UNAVAILABLE", lambda: model.continue_command(2, token))
        self.rejected("SELECTED_RUN_STATE", lambda: model.external_run_selected(token, 0))
        self.assertEqual((model.stop, model.holds, model.recovery_required),
                         (token, frozenset((0, 1)), True))
        model.check()

    def test_diagnostic_counter_exhaustion_is_not_wrapped_or_silenced(self):
        """诊断计数达到有限域边界后显式报错，保持旧值且不产生队列记录。"""
        queue = Capacity()
        queue.draining = True
        queue.late_events = 65535
        self.rejected("COUNTER_EXHAUSTED", queue.put_telemetry)
        self.assertEqual((queue.late_events, queue.pending), (65535, 0))


class SemanticBudgetTests(ModelCase):
    """仅验证有界状态与引用清理，不把这些计数测试表述为语义规则通过。"""

    def test_entities_partials_and_evidence_all_have_independent_limits(self):
        """分别填满对象、部分匹配及证据引用预算，核对各层拒绝和覆盖提示。"""
        model = SemanticBudget()
        self.assertEqual([model.add_entity(i) for i in range(4)],
                         ["entity_added"] * 3 + ["entity_limit_rejected"])
        self.assertEqual(model.add_entity(0), "entity_duplicate")
        for key in ((0, 0), (0, 1), (1, 0), (1, 1)):
            self.assertEqual(model.start_partial(*key), "partial_started")
        self.assertEqual(model.start_partial(2, 0), "partial_limit_rejected")
        # 每个匹配只保留两个事件 ID；重复引用不增量，第三个新引用明确拒绝。
        for entity, match in model.partials:
            self.assertEqual(model.add_evidence(entity, match, 10), "evidence_added")
            self.assertEqual(model.add_evidence(entity, match, 11), "evidence_added")
            self.assertEqual(model.add_evidence(entity, match, 11), "evidence_duplicate")
            self.assertEqual(model.add_evidence(entity, match, 12), "evidence_limit_rejected")
        self.assertEqual((len(model.entities), len(model.partials),
                          sum(len(p.evidence) for p in model.partials.values())), (3, 4, 8))
        self.assertEqual(model.notices["evidence_limit"], 4)
        self.assertTrue(model.incomplete)
        model.check()

    def test_per_entity_limit_and_normal_expiry_are_distinct(self):
        """单对象超限与正常窗口过期分别记账，过期后可以重新使用空闲容量。"""
        model = SemanticBudget()
        model.add_entity(1)
        model.start_partial(1, 0, window=1)
        model.start_partial(1, 1, window=2)
        self.assertEqual(model.start_partial(1, 2), "per_entity_limit_rejected")
        model.advance_to(1)
        self.assertEqual(set(model.partials), {(1, 1)})
        self.assertEqual(model.notices["expired"], 1)
        self.assertEqual(model.start_partial(1, 2), "partial_started")
        model.check()

    def test_expiry_and_entity_exit_reclaim_references_without_marking_loss(self):
        """正常过期和对象退出回收全部相关引用，但不伪造覆盖丢失。"""
        model = SemanticBudget()
        model.add_entity(1)
        model.add_entity(2)
        model.start_partial(1, 0, window=1)
        model.start_partial(2, 0, window=2)
        model.add_evidence(1, 0, 3)
        model.add_evidence(2, 0, 4)
        model.advance_to(1)
        self.assertEqual(set(model.partials), {(2, 0)})
        model.remove_entity(2)
        self.assertEqual((model.partials, model.notices["expired"],
                          model.notices["entity_exit"], model.incomplete), ({}, 1, 1, False))
        self.rejected("UNKNOWN_ENTITY", lambda: model.start_partial(2, 1))
        self.rejected("UNKNOWN_PARTIAL", lambda: model.add_evidence(2, 0, 5))
        self.rejected("CLOCK_REVERSED", lambda: model.advance_to(0))
        model.check()

    def test_finite_input_domain_and_logical_window(self):
        """禁止无界字符串身份和越界窗口，以显式逻辑时间确定清理边界。"""
        model = SemanticBudget()
        self.rejected("IDENTIFIER_DOMAIN", lambda: model.add_entity(256))
        self.rejected("IDENTIFIER_DOMAIN", lambda: model.add_entity("unbounded string"))
        model.add_entity(1)
        model.advance_to(254)
        self.rejected("WINDOW_DOMAIN", lambda: model.start_partial(1, 0, window=2))
        model.start_partial(1, 0, window=1)
        model.advance_to(255)
        self.assertEqual(model.partials, {})
        model.check()


class FaultInjectionTests(ModelCase):
    """预声明约束的反例注入；结果仅说明模型测试能发现对应错误。"""

    def test_predeclared_faults_are_falsified_by_independent_safety_checks(self):
        """输入九类固定错误变体，逐项观察违反独立预期的结果并记录反例。"""
        killed = []

        # 不调用模型自己的不变式判定：用外部可观察结果与手写预期比较。
        for name, order in (
            ("ready_before_reader", ("ready", "reader", "apply", "ack", "coverage", "release")),
            ("omit_config_barrier", ("reader", "ready", "apply", "coverage", "release")),
            ("omit_coverage_barrier", ("reader", "ready", "apply", "ack", "release")),
        ):
            with self.subTest(fault=name):
                self.assertFalse(startup_accepts(order))
                self.assertTrue(startup_accepts(order, Faults(**{name: True})))
                killed.append(name)

        # 代次反例：旧回执不能成为当前准备代次的已确认配置。
        for faulty in (False, True):
            model = ready_startup(Faults(accept_stale_ack=faulty))
            stale = model.produce_ack()
            model.cancel()
            model.next_generation()
            model.start_reader()
            model.agent_ready()
            model.apply_config()
            model.receive_ack(stale)
            self.assertEqual(model.ack is not None, faulty)
        killed.append("accept_stale_ack")

        # 可执行依赖反例：全部目标用户线程停止后，拆管道仍不能产生新 ACK。
        for faulty in (False, True):
            model = ready_startup(Faults(ack_while_frozen=faulty))
            model.suspend_all_target_user_threads()
            model.split_pipe()
            if faulty:
                self.assertIsInstance(model.produce_ack(), ConfigAck)
            else:
                self.rejected("TARGET_CANNOT_EXECUTE", model.produce_ack)
        killed.append("ack_while_frozen")

        # 停点身份反例：旧继续使用新命令 ID，也不能影响当前停止组。
        for faulty in (False, True):
            model, old = stopped(Faults(ignore_stop_identity=faulty))
            model.rearm(old)
            model.continue_command(2, old)
            new = model.request_stop(3)
            model.confirm_stopped(new, 0)
            model.confirm_stopped(new, 1)
            model.rearm(new)
            if faulty:
                model.continue_command(4, old)
                self.assertIsNone(model.stop)  # 反例：错误变体释放了新的停点。
            else:
                self.rejected("STALE_STOP", lambda: model.continue_command(4, old))
                self.assertEqual(model.stop, StopToken(1, 2))
        killed.append("ignore_stop_identity")

        # 幂等反例：没有去重时，旧停止命令会被错误地再次执行或拒绝。
        for faulty in (False, True):
            model, token = stopped(Faults(forget_command_dedup=faulty))
            if faulty:
                self.rejected("STOP_STATE", lambda: model.request_stop(1))
            else:
                self.assertEqual(model.request_stop(1), token)
                self.assertEqual(model.effects, 1)
        killed.append("forget_command_dedup")

        # 容量反例：遥测侵占预留空间后，可观察到八个遥测而不是最多六个。
        for faulty in (False, True):
            queue = Capacity(Faults(steal_control_reserve=faulty))
            for _ in range(8):
                queue.put_telemetry()
            self.assertEqual(queue.telemetry, 8 if faulty else 6)
        killed.append("steal_control_reserve")

        # 失联恢复反例：错误变体在责任尚存时报告关闭成功，正常模型应拒绝。
        for faulty in (False, True):
            model, _ = stopped(Faults(discard_recovery_on_close=faulty))
            model.owner_lost()
            if faulty:
                self.assertEqual(model.finish_shutdown(), "shutdown_closed")
                self.assertTrue(model.recovery_required)  # 反例：责任未清却报告关闭。
            else:
                self.rejected("RECOVERY_UNRESOLVED", model.finish_shutdown)
                self.assertEqual(model.phase, "owner_lost")
        killed.append("discard_recovery_on_close")
        self.assertEqual(len(killed), 9)
        self.assertEqual(set(killed), set(asdict(Faults())))
        EXPERIMENTS["fault_injection"] = {
            "predeclared_variants": 9, "falsified_variants": killed, "survivors": [],
            "interpretation": "Demonstrates sensitivity of these model oracles only.",
        }


class RecordingResult(unittest.TextTestResult):
    """保留标准库输出，并收集成功用例身份供固定 JSON 结果核对。"""

    def __init__(self, *args, **kwargs):
        """接收标准库测试结果构造参数，增加本轮成功用例列表。"""
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        """输入通过的测试对象，记录其稳定名称，再调用标准库输出行为。"""
        self.passed.append(test.id())
        super().addSuccess(test)


def main():
    """读取固定写结果开关，运行全部测试，按需写唯一 JSON 并返回退出码。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-results", action="store_true",
                        help="Write only the fixed, authorized JSON text results path.")
    args = parser.parse_args()
    if not __debug__:
        parser.error("Do not use -O: model invariant assertions must remain enabled.")
    # 测试时长由 unittest 原样输出，不作为性能测量或暂停时延结论。
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2,
                                     resultclass=RecordingResult).run(suite)
    # 结果明确标记模型证据等级；这些逻辑容量不是实测内存或已批准产品预算。
    report = {
        "schema": 1,
        "classification": "illustrative_offline_protocol_model_invariants",
        "status": "passed" if result.wasSuccessful() else "failed",
        "command": "py -3 -B tools/trace_protocol_validation/test_protocol_model.py --write-results",
        "python": sys.version.split()[0],
        "tests": {"run": result.testsRun, "passed": len(result.passed),
                  "failures": len(result.failures), "errors": len(result.errors),
                  "skipped": len(result.skipped)},
        "experiments": EXPERIMENTS,
        "analytical_bounds": {
            "identifier_max": 255, "diagnostic_counter_max": 65535,
            "queue_total_records": 8, "telemetry_max_records": 6,
            "reserved_control_records": 2, "command_cache_records": 4,
            "stop_group_thread_ids": 2, "entity_records": 3,
            "partial_records": 4, "partial_records_per_entity": 2,
            "evidence_id_references": 8,
            "interpretation": "Logical count bounds only; no measured byte/RSS/latency claim.",
        },
        # 模型无法证明真实 API、操作系统、IPC 或恢复动作执行正确。
        "validated_production_api_correctness": False,
        "validated_os_or_ipc": False,
        "validated_real_suspension_or_recovery": False,
        "limitations": [
            "No production code imported, no wire ABI/framing or physical IPC exercised.",
            "No driver, injection, UI, target process, real suspension, network or external packages.",
            "Fixed two-thread scheduler assumption, explicit external control, finite event alphabet.",
            "Fresh target ACK needs runnable target code; buffered ACK receipt is distinguished.",
            "No fairness, elapsed-time deadline, exhaustive product state-space or performance proof.",
            "Recovery confirmation is an assumed input; actual OS restoration is unverified.",
            "Semantic budget tracks counts/references, not rule truth or upstream rule equivalence.",
        ],
        # 用例结果和来源 hash 方便父会话核对本次实际文件，避免混用旧日志。
        "passed_tests": result.passed,
        "failed_tests": [{"test": test.id(), "detail": text}
                         for test, text in result.failures + result.errors],
        "source_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                          for name in ("model.py", "test_protocol_model.py", "README.md")},
    }
    if args.write_results:
        # 只能写入授权的固定 JSON 路径；不接受任意输出目录或测试配置路径。
        destination = Path(__file__).resolve().parents[2] / RESULT_RELATIVE
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("RESULT_JSON=" + RESULT_RELATIVE)
    print("MODEL_ONLY=1 PRODUCTION_API_PROOF=0 OS_PROOF=0 IPC_PROOF=0")
    print("TESTS={} PASSED={} FAILURES={} ERRORS={}".format(
        result.testsRun, len(result.passed), len(result.failures), len(result.errors)))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
