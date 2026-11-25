"""有界协议状态模型：只验证示意约束，不导入产品代码、不调用系统控制接口。"""

from dataclasses import dataclass


# 所有对象身份、代次和逻辑时钟采用小型有限域；这些不是产品默认值。
MAX_ID = 255
MAX_COUNTER = 65535
THREADS = frozenset((0, 1))
REQUIRED_COVERAGE = frozenset(("api", "execution_probe"))


class ProhibitedTransition(Exception):
    """显式表达被禁止的转换；code 是可供测试逐项核对的拒绝原因。"""

    def __init__(self, code):
        """输入稳定原因码，构造异常；抛出异常不会被当成协议成功。"""
        self.code = code
        super().__init__(code)


def require(condition, code):
    """输入条件与原因码；条件不满足时抛出异常，满足时返回 None。"""
    if not condition:
        raise ProhibitedTransition(code)


def identifier(value):
    """检查输入是否为有限域内的整数身份；成功返回 None，否则显式拒绝。"""
    require(type(value) is int and 0 <= value <= MAX_ID, "IDENTIFIER_DOMAIN")


def increment(value):
    """输入当前诊断计数，返回加一值；到达上限后拒绝，禁止回绕或静默饱和。"""
    require(value < MAX_COUNTER, "COUNTER_EXHAUSTED")
    return value + 1


@dataclass(frozen=True)
class Faults:
    """预先声明的九种错误开关，只用于负控，不代表产品已发现的问题。"""

    ready_before_reader: bool = False
    omit_config_barrier: bool = False
    omit_coverage_barrier: bool = False
    accept_stale_ack: bool = False
    ack_while_frozen: bool = False
    ignore_stop_identity: bool = False
    forget_command_dedup: bool = False
    steal_control_reserve: bool = False
    discard_recovery_on_close: bool = False


@dataclass(frozen=True)
class Generation:
    """配置代次身份：session 为会话代次，generation 为本会话准备代次。"""

    session: int
    generation: int


@dataclass(frozen=True)
class ConfigAck:
    """目标已生成的配置回执：保留原始代次 token 与配置版本 revision。"""

    token: Generation
    revision: int


class Startup:
    """单个迁移发起者的准入屏障；不实现目标注入或真实管道。"""

    def __init__(self, session=1, faults=Faults()):
        """输入会话身份和可选负控开关，构造尚未准入的有限状态。"""
        identifier(session)
        self.faults = faults
        self.token = Generation(session, 1)
        # 准备状态分别保留读端、就绪、实际应用和收到回执，避免混为一项。
        self.phase = "preparing"
        self.reader = False
        self.ready = False
        self.applied = False
        self.ack = None
        self.coverage = frozenset()
        self.revision = 1
        # runnable 仅是目标调度的模型事实；外部控制器不属于目标线程集合。
        self.runnable = THREADS
        self.stale_acks = 0

    def start_reader(self):
        """无业务参数；先建立外部读端，返回明确的建立结果。"""
        require(self.phase == "preparing" and not self.reader, "READER_STATE")
        self.reader = True
        return "reader_started"

    def _target_executes(self):
        """无业务参数；检查目标控制线程可执行，返回 None 或显式拒绝。"""
        require(0 in self.runnable or self.faults.ack_while_frozen,
                "TARGET_CANNOT_EXECUTE")

    def agent_ready(self):
        """模拟目标发布就绪；读端及目标执行条件满足后返回就绪结果。"""
        require(self.phase == "preparing" and not self.ready, "READY_STATE")
        self._target_executes()
        require(self.reader or self.faults.ready_before_reader, "READER_NOT_STARTED")
        self.ready = True
        return "agent_ready"

    def apply_config(self):
        """模拟目标应用当前配置，返回应用结果；该步骤不等于收到 ACK。"""
        require(self.phase == "preparing" and self.ready, "CONFIG_BEFORE_READY")
        self._target_executes()
        self.applied = True
        return "config_applied"

    def produce_ack(self):
        """无业务参数；目标可运行且已应用配置时，返回带代次的不可变回执。"""
        require(self.phase == "preparing" and self.applied, "ACK_BEFORE_APPLY")
        self._target_executes()
        return ConfigAck(self.token, self.revision)

    def receive_ack(self, ack):
        """输入已生成的配置回执；返回接收或拒绝陈旧回执的明确结果。"""
        # 已在传输中的回执可由外部读端接收，不要求此时目标仍在运行。
        identifier(ack.token.session)
        identifier(ack.token.generation)
        identifier(ack.revision)
        if ack.token != self.token and not self.faults.accept_stale_ack:
            self.stale_acks = increment(self.stale_acks)
            return "stale_ack_rejected"
        require(self.phase == "preparing" and self.ready, "ACK_STATE")
        require(self.applied, "ACK_BEFORE_APPLY")
        require(ack.revision == self.revision, "CONFIG_REVISION_MISMATCH")
        self.ack = ack
        return "config_ack_received"

    def publish_coverage(self, coverage):
        """输入有限覆盖成员集合；模拟当前目标发布覆盖并返回接收结果。"""
        require(self.phase == "preparing" and self.ready, "COVERAGE_BEFORE_READY")
        self._target_executes()
        require(type(coverage) is frozenset and coverage <= REQUIRED_COVERAGE,
                "COVERAGE_DOMAIN")
        self.coverage = coverage
        return "coverage_received"

    def release_initiator(self):
        """无业务参数；只有配置和必要覆盖屏障均满足时才返回放行结果。"""
        require(self.phase == "preparing" and self.ready, "ADMISSION_STATE")
        require(self.ack is not None or self.faults.omit_config_barrier,
                "CONFIG_ACK_MISSING")
        require(REQUIRED_COVERAGE <= self.coverage or self.faults.omit_coverage_barrier,
                "REQUIRED_COVERAGE_MISSING")
        self.phase = "admitted"
        return "initiator_released"

    def cancel(self):
        """取消当前准备代次并清除其已接收回执；返回取消结果。"""
        require(self.phase == "preparing", "CANCEL_STATE")
        self.phase = "cancelled"
        self.ack = None
        return "generation_cancelled"

    def next_generation(self):
        """在取消后递增代次并重置准备状态；返回新代次结果或耗尽错误。"""
        require(self.phase == "cancelled", "GENERATION_STILL_LIVE")
        require(self.token.generation < MAX_ID, "GENERATION_EXHAUSTED")
        self.token = Generation(self.token.session, self.token.generation + 1)
        self.phase = "preparing"
        self.reader = self.ready = self.applied = False
        self.ack = None
        self.coverage = frozenset()
        return "generation_started"

    def suspend_all_target_user_threads(self):
        """将目标两个用户线程均标记为不可运行，返回模型状态变化说明。"""
        # 这里只改变模型中的调度事实，不调用 SuspendThread 或任何系统 API。
        self.runnable = frozenset()
        return "all_target_user_threads_suspended"

    def external_resume_selected_control_thread(self):
        """由外部控制恢复选定线程 0，返回结果；另一目标线程仍不可运行。"""
        require(not self.runnable, "TARGET_NOT_FULLY_SUSPENDED")
        self.runnable = frozenset((0,))
        return "external_control_resumed_thread_0"

    def split_pipe(self):
        """模拟拆分传输通道，返回说明；不改变目标线程的执行资格。"""
        # 通道独立并不能让被全部停止的目标执行配置、发出新的 ACK。
        return "split_pipe_only"

    def check(self):
        """无业务参数；断言当前状态满足准入不变式，违反时暴露断言异常。"""
        assert not self.ready or self.reader, "ready published before reader"
        assert self.ack is None or self.ack.token == self.token, "stale ACK accepted"
        if self.phase == "admitted":
            assert self.ready and self.applied and self.ack, "incomplete config barrier"
            assert self.ack.revision == self.revision, "wrong config revision"
            assert REQUIRED_COVERAGE <= self.coverage, "incomplete coverage barrier"


class Capacity:
    """八个逻辑记录槽位，其中两个仅供控制使用；不模拟载荷或真实传输。"""

    # 总容量和遥测上限分开，控制可以借用空闲遥测空间，反向借用被禁止。
    TOTAL = 8
    RESERVED_CONTROL = 2
    TELEMETRY_LIMIT = TOTAL - RESERVED_CONTROL

    def __init__(self, faults=Faults()):
        """输入可选负控开关，初始化占用、丢失和生命周期计数。"""
        self.faults = faults
        self.telemetry = 0
        self.control = 0
        # 拒收、迟到和控制耗尽分别计数，不把任意一种拒收记为交付成功。
        self.telemetry_dropped = 0
        self.control_rejected = 0
        self.late_events = 0
        self.draining = False
        self.closed = False

    def put_telemetry(self):
        """申请一个遥测槽位，返回入队或具体拒收结果；关闭后显式报错。"""
        require(not self.closed, "QUEUE_CLOSED")
        if self.draining:
            self.late_events = increment(self.late_events)
            return "late_telemetry_rejected"
        limit = self.TOTAL if self.faults.steal_control_reserve else self.TELEMETRY_LIMIT
        if self.telemetry >= limit or self.pending == self.TOTAL:
            self.telemetry_dropped = increment(self.telemetry_dropped)
            return "telemetry_capacity_rejected"
        self.telemetry += 1
        return "telemetry_queued"

    def put_control(self):
        """申请一个控制槽位；返回入队结果，总容量耗尽或关闭时抛出异常。"""
        require(not self.closed, "QUEUE_CLOSED")
        if self.pending == self.TOTAL:
            self.control_rejected = increment(self.control_rejected)
            raise ProhibitedTransition("CONTROL_CAPACITY_EXHAUSTED")
        self.control += 1
        return "control_queued"

    @property
    def pending(self):
        """无业务参数；返回两类记录合计占用，供排空与关闭检查使用。"""
        return self.telemetry + self.control

    def drain_one(self):
        """移出一个逻辑记录并返回类别；优先控制，空队列显式拒绝。"""
        require(self.pending > 0, "QUEUE_EMPTY")
        if self.control:
            self.control -= 1
            return "control_drained"
        self.telemetry -= 1
        return "telemetry_drained"

    def check(self):
        """断言队列总量、遥测专用上限和关闭状态，成功返回 None。"""
        assert 0 <= self.telemetry <= self.TELEMETRY_LIMIT, "control reserve stolen"
        assert 0 <= self.control and self.pending <= self.TOTAL, "queue overflow"
        assert not self.closed or self.pending == 0, "closed queue reopened"


@dataclass(frozen=True)
class StopToken:
    """停止责任身份：会话代次与本会话停点代次联合使用，防止复用误放行。"""

    session: int
    epoch: int


class StopControl:
    """外部控制所有者、固定双线程停止组和不可静默遗失的恢复责任。"""

    COMMAND_LIMIT = 4

    def __init__(self, session=1, faults=Faults(), foreign_holds=frozenset()):
        """输入会话、负控和外部持有集合；初始化独立控制状态，不接触系统。"""
        require(type(foreign_holds) is frozenset
                and all(type(thread) is int and thread in THREADS for thread in foreign_holds),
                "FOREIGN_HOLD_DOMAIN")
        identifier(session)
        self.session = session
        self.faults = faults
        self.phase = "active"
        self.queue = Capacity(faults)
        # stop 记录未解决的请求；即使尚无停止回执，也不能宣称责任已解除。
        self.epoch = 0
        self.stop = None
        self.holds = frozenset()
        self.foreign_holds = foreign_holds
        self._initial_foreign_holds = foreign_holds
        # selected/selected_outside/executable 表达选定推进与页面重设防次序。
        self.selected = None
        self.selected_outside = False
        self.executable = False
        self.rearmed = False
        # 缓存只保存最多四个命令及其原始结果；effects 统计实际执行次数。
        self.commands = {}
        self.effects = 0
        self.recovery_required = False

    def _command(self, command_id, payload):
        """输入命令 ID 和有限载荷，返回是否重试及缓存结果，冲突或耗尽则拒绝。"""
        identifier(command_id)
        if command_id in self.commands:
            saved_payload, result = self.commands[command_id]
            require(saved_payload == payload, "COMMAND_ID_CONFLICT")
            if not self.faults.forget_command_dedup:
                return True, result
        require(len(self.commands) < self.COMMAND_LIMIT, "COMMAND_LEDGER_EXHAUSTED")
        return False, None

    def _save(self, command_id, payload, result):
        """输入已执行命令及结果，更新有界缓存和执行计数，返回原始结果。"""
        self.effects = increment(self.effects)
        self.commands[command_id] = (payload, result)
        return result

    def _identity(self, token):
        """输入停点 token，确认属于当前停止责任；成功返回 None。"""
        identifier(token.session)
        identifier(token.epoch)
        require(self.stop is not None, "NO_STOP")
        require(token == self.stop or self.faults.ignore_stop_identity, "STALE_STOP")

    def request_stop(self, command_id):
        """输入命令 ID，建立新的待确认停止责任，或返回同命令的缓存 token。"""
        payload = ("stop", self.session)
        duplicate, result = self._command(command_id, payload)
        if duplicate:
            return result
        require(self.phase == "active" and self.stop is None, "STOP_STATE")
        require(self.epoch < MAX_ID, "STOP_EPOCH_EXHAUSTED")
        self.epoch += 1
        self.stop = StopToken(self.session, self.epoch)
        self.rearmed = False
        self.recovery_required = True  # 尚未收到目标停止 ACK 的请求也有恢复责任。
        return self._save(command_id, payload, self.stop)

    def confirm_stopped(self, token, thread):
        """输入停点和线程身份，登记真实停止回执，返回确认结果。"""
        self._identity(token)
        require(type(thread) is int and thread in THREADS, "THREAD_DOMAIN")
        require(not self.executable and self.selected is None, "STOP_ACK_AFTER_RELEASE")
        self.holds = self.holds | frozenset((thread,))
        return "thread_stop_confirmed"

    def external_run_selected(self, token, thread):
        """输入当前停点与选定线程；屏障完成且无外部持有时才放行并返回结果。"""
        require(self.phase == "active", "SELECTED_RUN_STATE")
        self._identity(token)
        require(type(thread) is int and thread in THREADS, "THREAD_DOMAIN")
        require(self.holds == THREADS and not self.executable, "STOP_BARRIER_INCOMPLETE")
        require(thread not in self.foreign_holds, "FOREIGN_HOLD_BLOCKS_EXECUTION")
        self.selected = thread
        self.selected_outside = False
        self.executable = True
        self.rearmed = False
        self.holds = self.holds - frozenset((thread,))
        return "selected_thread_released"

    def selected_left_page(self, token):
        """输入当前停点，接收选定线程离开页面的模型事实并返回结果。"""
        self._identity(token)
        require(self.executable and self.selected is not None, "NO_SELECTED_EXECUTION")
        self.selected_outside = True
        return "selected_thread_outside_page"

    def rearm(self, token):
        """输入当前停点，满足停止或离页条件后重设防，返回明确结果。"""
        self._identity(token)
        require((self.selected is None and self.holds == THREADS)
                or self.selected_outside, "SELECTED_STILL_INSIDE_OR_BARRIER_INCOMPLETE")
        self.executable = False
        self.rearmed = True
        return "page_rearmed"

    def continue_command(self, command_id, token):
        """输入继续命令及停点，验证所有权和重设防后仅归还本模型责任。"""
        payload = ("continue", token)
        duplicate, result = self._command(command_id, payload)
        if duplicate:
            return result
        require(self.phase in ("active", "draining"), "CONTINUE_OWNER_UNAVAILABLE")
        self._identity(token)
        require(self.rearmed and not self.executable, "PAGE_NOT_REARMED")
        self._clear_responsibility()
        return self._save(command_id, payload, "own_holds_released")

    def _clear_responsibility(self):
        """清理当前自身停止责任，返回 None；不写入其它所有者的持有集合。"""
        self.holds = frozenset()
        self.stop = None
        self.selected = None
        self.selected_outside = False
        self.recovery_required = False

    def begin_shutdown(self):
        """开始排空并禁止新遥测，返回状态；不会清除未解决的停止责任。"""
        require(self.phase == "active", "SHUTDOWN_STATE")
        self.phase = "draining"
        self.queue.draining = True
        return "shutdown_draining"

    def owner_lost(self):
        """模拟控制所有者失联，返回责任状态；失联本身不构成恢复成功证据。"""
        require(self.phase in ("active", "draining"), "OWNER_LOST_STATE")
        self.phase = "owner_lost"
        self.queue.draining = True
        # 保留原停点、已持有线程和待确认请求，供独立恢复路径接管。
        return "owner_lost_recovery_pending" if self.stop else "owner_lost_no_stop"

    def external_recovery_result(self, token, succeeded):
        """输入外部恢复结果；失败保留责任，成功确认才归还自身持有并返回结果。"""
        require(self.phase == "owner_lost", "RECOVERY_STATE")
        self._identity(token)
        require(type(succeeded) is bool, "RECOVERY_RESULT_DOMAIN")
        if not succeeded:
            return "recovery_failed_responsibility_retained"
        self.executable = False
        self.rearmed = True
        self._clear_responsibility()
        return "external_recovery_confirmed"

    def finish_shutdown(self):
        """排空且恢复责任清零后关闭；返回关闭结果，否则显式拒绝。"""
        require(self.phase in ("draining", "owner_lost"), "CLOSE_STATE")
        require(self.queue.pending == 0, "DRAIN_INCOMPLETE")
        require(not self.recovery_required or self.faults.discard_recovery_on_close,
                "RECOVERY_UNRESOLVED")
        self.phase = "closed"
        self.queue.closed = True
        return "shutdown_closed"

    def next_session(self):
        """清洁关闭后递增会话并初始化新状态，保留外部持有事实，返回结果。"""
        require(self.phase == "closed" and not self.recovery_required, "SESSION_UNRESOLVED")
        require(self.session < MAX_ID, "SESSION_EXHAUSTED")
        next_model = StopControl(self.session + 1, self.faults, self.foreign_holds)
        self.__dict__.update(next_model.__dict__)
        return "session_started"

    def check(self):
        """断言控制、队列、停止身份与所有权不变式，成功返回 None。"""
        self.queue.check()
        assert len(self.commands) <= self.COMMAND_LIMIT, "unbounded command ledger"
        assert self.holds <= THREADS, "unknown own hold"
        assert self.foreign_holds == self._initial_foreign_holds, "foreign hold changed"
        assert self.recovery_required == (self.stop is not None), "recovery debt lost"
        assert self.phase != "closed" or not self.recovery_required, "closed with recovery debt"
        assert (self.phase == "closed") == self.queue.closed, "queue/owner lifecycle mismatch"
        assert not self.executable or (self.selected is not None
                                       and self.holds == THREADS - {self.selected}), "unsafe release"


@dataclass(frozen=True)
class Partial:
    """部分匹配仅保留有限逻辑截止时间和事件 ID 引用，不复制原事件。"""

    deadline: int
    evidence: tuple


class SemanticBudget:
    """仅模拟对象、部分匹配和引用的预算生命周期，不产生行为语义结论。"""

    ENTITY_LIMIT = 3
    PARTIAL_LIMIT = 4
    PER_ENTITY_LIMIT = 2
    EVIDENCE_LIMIT = 2

    def __init__(self):
        """无业务参数；创建有界对象、匹配索引、逻辑时钟和分类计数。"""
        self.entities = set()
        self.partials = {}
        self.tick = 0
        # 预算拒绝与正常过期/退出分开，正常清理不自动标记为覆盖丢失。
        self.notices = {key: 0 for key in (
            "entity_limit", "partial_limit", "per_entity_limit", "evidence_limit",
            "expired", "entity_exit")}
        self.incomplete = False

    def _limit(self, name):
        """输入固定预算类别，记录覆盖不完整并返回具体拒绝说明。"""
        self.notices[name] = increment(self.notices[name])
        self.incomplete = True
        return name + "_rejected"

    def add_entity(self, entity):
        """输入有限对象身份，返回加入、重复或对象上限拒绝结果。"""
        identifier(entity)
        if entity in self.entities:
            return "entity_duplicate"
        if len(self.entities) == self.ENTITY_LIMIT:
            return self._limit("entity_limit")
        self.entities.add(entity)
        return "entity_added"

    def start_partial(self, entity, match_id, window=2):
        """输入对象、匹配 ID 和逻辑窗口，按总量及单对象预算创建空匹配。"""
        identifier(entity)
        identifier(match_id)
        require(entity in self.entities, "UNKNOWN_ENTITY")
        require(type(window) is int and window > 0 and self.tick + window <= MAX_ID,
                "WINDOW_DOMAIN")
        # 联合键保留对象归属；到期时间和引用数量不依赖真实时钟或休眠。
        key = (entity, match_id)
        require(key not in self.partials, "PARTIAL_ID_CONFLICT")
        if len(self.partials) == self.PARTIAL_LIMIT:
            return self._limit("partial_limit")
        if sum(k[0] == entity for k in self.partials) == self.PER_ENTITY_LIMIT:
            return self._limit("per_entity_limit")
        self.partials[key] = Partial(self.tick + window, ())
        return "partial_started"

    def add_evidence(self, entity, match_id, event_id):
        """输入对象、匹配和事件身份，去重后添加有限引用并返回处理结果。"""
        identifier(event_id)
        key = (entity, match_id)
        require(key in self.partials, "UNKNOWN_PARTIAL")
        partial = self.partials[key]
        if event_id in partial.evidence:
            return "evidence_duplicate"
        if len(partial.evidence) == self.EVIDENCE_LIMIT:
            return self._limit("evidence_limit")
        self.partials[key] = Partial(partial.deadline, partial.evidence + (event_id,))
        return "evidence_added"

    def advance_to(self, tick):
        """输入单调逻辑时刻，移除到期匹配并计数，返回推进结果。"""
        identifier(tick)
        require(tick >= self.tick, "CLOCK_REVERSED")
        expired = [key for key, value in self.partials.items() if value.deadline <= tick]
        require(self.notices["expired"] + len(expired) <= MAX_COUNTER, "COUNTER_EXHAUSTED")
        self.tick = tick
        for key in expired:
            del self.partials[key]
        self.notices["expired"] += len(expired)
        return "logical_time_advanced"

    def remove_entity(self, entity):
        """输入对象身份，清除对象与其部分匹配引用，返回正常退出结果。"""
        require(entity in self.entities, "UNKNOWN_ENTITY")
        count = sum(key[0] == entity for key in self.partials)
        require(self.notices["entity_exit"] + count <= MAX_COUNTER, "COUNTER_EXHAUSTED")
        self.partials = {key: value for key, value in self.partials.items() if key[0] != entity}
        self.entities.remove(entity)
        self.notices["entity_exit"] += count
        return "entity_and_partials_removed"

    def check(self):
        """核对对象、匹配、引用和到期状态的上限，成功返回 None。"""
        assert len(self.entities) <= self.ENTITY_LIMIT, "entity budget exceeded"
        assert len(self.partials) <= self.PARTIAL_LIMIT, "partial budget exceeded"
        for entity in self.entities:
            assert sum(key[0] == entity for key in self.partials) <= self.PER_ENTITY_LIMIT
        for (entity, _), partial in self.partials.items():
            assert entity in self.entities and self.tick < partial.deadline
            assert len(partial.evidence) <= self.EVIDENCE_LIMIT
