# ActionAnalyze 同步全局断点与性能复查

日期 2026-11-24。用户已确认同步下断采用**命中线程直接进入已登记停点，由目标外所有者接管**。R3 首个原生切片及各能力放行顺序见[工程开工基线](ActionAnalyze工程开工基线.md)。产品接口与性能测试待实施。

前置：[主规划](恶意行为单点追踪与调试能力规划.md)、[通信与控制](ActionAnalyze多通道通信与控制施工设计.md)、[双后端](ActionAnalyze双后端独立全流程设计.md)、[字段与方法](ActionAnalyze事件身份与协议契约.md)、[规则语言](ActionAnalyze筛选器与规则语言设计.md)、[施工任务](ActionAnalyze施工任务与契约落点.md)。Qt／Win32／CLI各自拥有业务、协调者及运行会话；不新增公共宿主、追踪DLL、统一runtime或跨端控制服务。

## 1. 复查结论与未关闭项

此前已经考虑有界队列、独立控制线程、停止账本、同步谓词白名单、内存和UI预算，并非完全没有性能设计。但是缺少同步命中的具体接管入口、原生机制与逻辑停止范围的对应、热路径总工作量约束，以及带可重复负载的端到端数据。`control.pause`／`requestPause`只有职责草案，不能等同于目标Hook可以安全调用的同步接口。

| 链路 | 尚未完善／关闭的内容 | 当前证据与下一门槛 |
| --- | --- | --- |
| 创建与早期来源 | 最小引导到完整Agent的覆盖交接、依赖DLL的TLS／DllMain | 双架构68项是独立最小IAT原型及生产入口暂停对照；完整Agent的早期安全子集仍待实现 |
| 同步断点 | Hook保留调用、直接通知外部owner、并发命中及继续令牌 | 本文定义接口与R3候选；现有API后置日志不能直接承担 |
| 全局停止 | 命中线程先停与组停止完成分离；跨进程停止偏差、新目标／新线程 | 固定集合局部机制有证据；完整门控仍未通过 |
| 写入到执行 | 写前布防、返回前布防与并发执行的区别；共享别名、原有RX覆盖 | 目标已有线程可并发，单拦写入方不自动封住执行方；普通store新落点未解决 |
| 线程与区域 | 临时恢复X期间的新线程、页内循环、并发改写与版本失效 | Explorer正常79项不覆盖新线程竞争；`creates_during_step=0` |
| R3／R0控制 | 两后端分别接管同步命中、容量、原生事件及恢复 | R0现有primary／恢复账／watchdog问题未修；不能把R3软断点直接交R0 |
| 规则 | 全库候选与启用闭包分开、每入口累计谓词成本、乱序与缺口 | 有白名单／三值／预算草案；解析器、机器契约和真实规则执行未实施 |
| 传输与归档 | 实际锁竞争、逐包系统对象、读端JSON／Base64／同步写盘 | 本轮找到具体源码成本；没有用吞吐或时延实测关闭 |
| 调查与步进 | 不执行目标代码的停态取证、快照一致性、耗时符号与目标保持时间 | 受控步进106断言不等于通用目标；调查不可依赖已停Agent返回ACK |
| 恢复与故障 | pending异常owner死亡、取消与继续竞争、部分恢复后仍可查询 | 已有owner死亡负控失败，不因本轮接口设计关闭 |
| 长程CLI／三端 | 真控制命令接通、慢stdout、状态查询、历史不触发控制 | REPL／JSONL及catalog尚未产品实现，三个端分别验收 |
| 长期／发行 | 多版本、目标CPU与私有提交、慢盘／满盘、长时退役代码与缓存增长 | 尚无产品长期数据；规则许可／正文／转换矩阵也仍未齐 |

这些内容按已有A0–A10施工，不借复查扩大为本轮产品实现。优先关闭同步控制及性能的准入条件，再开放严格“执行前停住”的声明。

## 2. 全局与同步的精确定义

**全局是本次会话的已授权对象范围，不是整台Windows。** 默认用户动作仍只作用于已关联线程，另可明确选择分支或实例集合。主程序把selector解析为请求时的不可变实例快照，记录`membershipRevision`及快照hash；Agent只能引用控制器预先绑定的`scopeBindingId`，不能凭一个布尔值暂停任意PID。Agent命中的实际组快照由控制器接纳时冻结，保存相应绑定修订；不能声称与较早的Hook入口时刻完全相同。

**同步只保证受支持边界上的命中调用不自行越过。** `call-enter`停住在原调用之前；`call-return`是原调用已返回、尚未返回给调用者；`execution-enter-attempt`是受支持的执行进入尝试。后台规则收到历史事件后发起的是异步暂停，不能倒称原操作尚未发生。一次原调用发生的副作用不能由返回前停点撤销。

| 状态 | 可以报告的事实 |
| --- | --- |
| `accepted` | 请求身份、范围、版本及资源已接纳，尚无停止保证 |
| `origin-held` | 命中线程已由真实机制持有，指定边界未被继续 |
| `group-building` | 正在停止其余冻结对象；它们在各自停住之前仍可能执行 |
| `held-complete` | 冻结集合内每项都已确认停止或真实退出，且至少一项仍持有，附逐项状态和停止区间 |
| `held-partial` | 已确认持有命中线程或一个组成员，且至少有一项停止未确认。保留逐项原因和已获得责任 |
| `not-held/ended` | 分别表示未建立停止且无未决责任，或冻结成员均真实退出且额外责任已清退 |
| `release-pending/released/recovery-required` | 对应每项真实释放结果，不把命令发送成功当线程已运行 |

`held-complete`还须携带`coverageBasis=frozen-members`及`futureThreadGate=verified/unsupported/unknown`。冻结集合已停不等于未来线程也受控，更不等于已满足临时恢复X所需的完整区域屏障；后者必须独立核对`regionReady`和内部必要执行者闭包。

**R3存在必须直说的停止范围放大。** Windows原生debug event在待处理期间暂停的是命中进程全部线程，包括Agent和未关联业务线程，不只命中TID，也不自动暂停其它进程。因此分别保存用户请求集合、原生附带暂停集合、内部区域屏障集合及其原因；临时暂停不增加恶意归因。要求“未关联线程绝不能短暂停止”的计划不得选择这种机制并假报精确范围。

若要从进程级native hold收缩到关联线程，必须先对需保留的线程登记并取得自己的显式hold，再由同一owner继续原生事件；事件继续前后都核对责任，命中线程不能在交接间返回原调用。这个转换会增加成本，并非现有夹具已证明的通用能力；转换不能完成时保留真实native hold并报告范围／限制。不同进程的停止保存各自单调时间，不承诺全组同一CPU时刻停住。

## 3. 两端接口：统一仲裁，区分同步与异步入口

下表是待实施的内部职责名，不是已存在的导出函数或新增CLI命令。正式机器契约唯一根仍为`schemas/action_analyze/`；R0/R3结构及IOCTL只在`shared/driver/`定义，本文不分配ABI值。

| 调用者／入口提案 | 输入 | 返回与责任 |
| --- | --- | --- |
| UI／CLI／后台：`ControlCoordinator.requestPause(BreakRequest)` | 请求ID、session/epoch、expected状态、冻结范围、原因、期限 | 立即返回ticket或接纳前拒绝；真实停止由目标外worker执行，UI不等待future |
| Agent非同步来源：`AgentBreakPort.tryRequestBreak(HitRecord)` | 预绑定scope、命中及修订、实际阶段 | 有界提交`queued/rejected`；提交成功只代表请求已排队，调用线程可以继续，不能称同步 |
| Agent同步Hook：`AgentBreakPort.breakAndPark(HitRecord, BoundStopRoute)` | 已准备路由／槽位、现场、operation及绑定修订 | 命中线程通过已验证原生机制停驻；只有外部owner明确释放本责任才正常返回，返回含继续处置与结果有效性 |
| 原生NX／TF／硬件命中：`Backend.adoptNativeStop(NativeStopRef, HitRef)` | 后端真实事件／线程／epoch、探针／版本及已有责任 | 导入同一停止账本；不能再给已native-held线程无故重复加Suspend |
| UI／CLI：`ControlCoordinator.query(ticketOrStopGroup)` | 原请求或停点身份 | 返回权威状态及逐项差异；历史通知可丢，当前责任不能丢 |
| UI／CLI：`ControlCoordinator.continue(ReleaseRequest)` | stop/group token、选定责任、expected版本 | 按机制精确释放；沿用公开`control.continue`，不接受Agent自行解全组 |

公开机器方法继续使用已有`control.pause/query/continue/recover`和`request.query/cancel`，不另注册`break.global`等同义方法。手动暂停和Agent命中在同一协调者汇合，保留`origin=manual/api-predicate/semantic/native-probe`；一个请求ID只产生一次副作用。

### 3.1 `BreakRequest`与结果至少包含什么

| 字段组 | 必需内容 |
| --- | --- |
| 身份 | controller/session/epoch、requestId、所选backendInstance；Agent路径另带agentInstance和sourceSequence |
| 触发 | breakpointId/revision或手动原因、operationId、apiId/probeId、实际phase、原始命中时间及clockId |
| 范围 | scopeBindingId／已解析实例快照、membershipRevision及hash；Agent绑定权限由控制器复核 |
| 前提 | 实际config/coverage/probe revision、所需sourceReady/regionReady、允许的原生附带停止范围 |
| 现场 | origin进程／线程强身份、原调用位置、有限预捕获字段、字段有效性及snapshotRef；不传裸指针当跨进程对象 |
| 策略 | 同步或异步、接纳／建组预算、失效和owner死亡策略引用；引用采样已冻结策略，Hook不临时弹窗选择 |
| 结果 | ticket/stopGroupId、每项stopId/token、originHeld与groupState、实际mechanism、附带暂停集合、时刻与未决责任 |

Agent自报字段来自受观测目标，外部核对真实事件PID/TID、对象句柄、模块及路由代次；目标已被攻陷时这些内容不能升级为防篡改证明。跨进程scope只能使用预授权绑定，解析／权限核验发生在副作用前。

全局状态修订不能成为高频命中的无休止失败源。手动命令使用显式expected状态；原生已发生的命中先导入其真实责任，再由唯一协调者按命中绑定修订裁决是否新建／合并组，不因UI刚刷新就丢弃一个已经停住的线程。过期配置拒绝新授权，但不封死旧责任的精确释放。

### 3.2 双端触发时序

```text
主程序手动暂停：
  UI/CLI → requestPause → 接纳ticket → 目标外worker执行所选后端
         → 逐项回读 → held-complete/held-partial → UI/CLI异步取得结果

Agent同步命中：
  Hook入口 → 读取不可变计划 → 按apiId/phase找候选 → 有界字段捕获与判断
           → 发布预分配HitRecord → 直接进入已绑定原生停驻点
           → 目标外owner取得真实停点 → 统一建组并回读 → 保持／调查
           → 显式continue → 释放自有责任 → 返回Hook → 原调用恰好执行一次
```

`call-return`版本最后一步是把真实原返回交还调用者，不能再次执行原API。原始返回位、LastError／NTSTATUS／适用WSA错误、入口参数及ABI易失状态按该入口契约保存和恢复；停驻函数的返回值不是被监控API返回值。异常／非局部展开和不返回API另有入口能力，未验证不公告支持。

## 4. 同步停驻的原生路线与尚未证明的条件

### 4.1 R3 首个实现验证登记过的直接停点

在既有 Agent 内增加独立登记的原生站点。命中线程把有限记录写到预分配槽，直接进入该站点的原生断点。目标外 debug owner 收到事件并持有，再按绑定范围建立停止组。Agent worker、sender 和 GUI 均可处于暂停状态。

调试附加／创建、事件接收和Continue由同一真实owner组织。只识别本会话登记的站点地址／模块实例、异常种类、实际线程、有效槽位序号及epoch；WOW64按实际异常码和上下文布局验收，不能只匹配所有`STATUS_BREAKPOINT`。未登记异常仍走原始异常策略，不吞掉目标自己的断点或保护异常。具体站点返回PC及寄存器恢复要有双架构原生测试，不能对所有异常统一做IP加减。

槽在Agent私有、固定且已提交的内存中，外部使用已有进程句柄有界读取；不是首版必须新增的共享内存运输。发布具有版本／长度／序号及先写内容再发布的顺序；槽位不稳定或被目标改坏时，原生停止事实仍保留，命中附加字段标损坏／未知。读取重试有界，不在被暂停的writer上忙等。槽地址是绑定时核验的内存范围，不接受每次由消息指定任意读取地址。

**有debug event时整个进程暂停，因此外部不能等待Agent生成“我停住了”的新ACK。** 原生事件本身提供origin hold；外部自行读取有限证据、停止其它已绑定对象并维护账本。已有pending事件时，事件owner仍处理自己的控制命令，不能阻塞GUI或等待磁盘。若进一步接收其它native event需要先移交当前hold，须先取得相应显式责任并验证无越界窗口；未证明前不假设可以无限囤积多个未Continue事件。

主程序手动触发仍提交同一协调者，但没有要求目标配合进入Hook。后端可按已验证能力使用原生中断或已绑定线程的外部挂起；报告实际机制。`DebugBreakProcess`不是全组停止函数，未建立调试所有权时更不能盲调；返回成功也须等真实事件。手动中断的目标端运行依赖与挂起兼容性另测，不能让它阻塞全部查询／恢复。

同步路由必须在启用断点前确认真实debug owner、站点、槽、预算、目标实例及恢复能力。只检查`IsDebuggerPresent`不构成路由绑定。owner在核验后死亡仍是现存故障边界，不能用心跳或预检查宣称该竞态消失；本轮不增加守护宿主，不把任意死亡后的正常续行写成已保证。没有可用路由时不授予严格同步能力，不能无owner仍执行INT3。

早期引导可以先记录，严格同步绑定须等原生接收路由确认就绪后再启用。正常关闭按顺序撤销接纳、保持事件所有权、清退已进入路由的调用和已有停点、确认不会再进入该站点，最后脱离。测试应把线程分别置于读到旧绑定、现场已经发布、原生事件待继续三个位置发起关闭，逐一确认交接结果。无法确认清退时保留 owner 与恢复账。

### 4.2 R0：统一语义，不能照搬R3软断点

已核对`kernel_noattach_events.c`：当前主分支消费自有TF／硬件断点及另行匹配的用户AV；非`STATUS_SINGLE_STEP`且无自有TF时返回原分发，不能因为存在STOP_BREAKPOINT枚举就认定可接Agent的INT3。它还受单primary／并发现场及恢复缺口约束。

因此`BoundStopRoute`由所选后端声明。R0需要单独证明适用异常现场接管，或外部可直接释放的预分配停驻原语；后者还须区分原Hook现场与等待现场、避免依赖已停Agent，并证明外部全组停止与恢复顺序。不分配新的IOCTL前就宣称已有完整实现，不为了接INT3私自附加Windows调试器而把R0会话变成R3会话。

无法满足时能力报告 `unsupported`／`blocked`，禁止安装要求严格同步的绑定。显式选择的后端贯穿活采样。R3 在本机独立验证受支持用户态全流程，R0 的实际停驻与恢复在指定来宾分别验证，结果待登记。[验收范围与运行环境](ActionAnalyze工程开工基线.md#验收范围与运行环境)

### 4.3 持锁、重入、并发命中与超时

- 同步Hook可能在业务锁或loader lock内发生。停驻前不能持Agent队列锁／配置锁；外部调查只读目标状态，不注入远程调用、初始化符号于目标或等Agent安装新Hook。业务锁仍可能被命中线程持有，其它线程等待属于本次真实扰动，不假称无死锁风险。
- 每个同步绑定先计算该API／phase全部候选谓词的累计最坏成本。禁止Hook里解析DSL、全库扫描、符号／签名查询、文件I/O、JSON／Base64、大块内存扫描、堆分配和无界自旋；不能只给单条规则限128节点，却允许同入口叠数千条突破总预算。
- 每线程首次进入、未知线程、嵌套Hook和异常重入都有预分配槽策略。有限CAS失败及容量耗尽有明确结果；不能用“lock-free”推导每调用必然固定时间，也不能在回调内临时扩容。嵌套消费同一operation按绑定策略合并，真实新命中不得被递归保护静默抹掉。
- 同一物理停止可被多个用户命中／内部屏障引用，分开保存逻辑hold。相同请求只加一次实际责任；取消一个命中或完成一次调查不能解掉其它hold。已held目标的新增理由可合并记录，不能反复Suspend增加计数。
- 建组超时按已取得的真实责任回读。存在已确认持有项时返回 `held-partial` 和未完成对象。只有确认无责任才返回 `not-held`，不明副作用继续查询和恢复。已持有的 origin 保留到本次策略明确处置。接纳前取消、已提交、已持有、正在释放分别仲裁，用户继续、配置变化、目标退出、新命中同时发生也可查询原结果。
- 运行中路由丢失但尚无真实hold时只能报告`interception-lost`，不能伪造“保持拦截”。故障处置受本采样已声明机制／策略约束，禁止自行杀目标、永久自旋或合成API失败来掩盖；任意owner死亡的强保证在问题关闭前仍不能公告。

## 5. 本轮找到的具体性能成本

下表是当前源码事实及应测项目，不是测得的瓶颈排名。复用需要局部改造和旧监控回归，不因此整套替换Hook引擎。

| 源码定位 | 当前事实 | 接入／性能要求 |
| --- | --- | --- |
| `APIMonitor_x64/core/MonitorPipe.cpp::QueueMonitorEventRaw` | 每条构造1000字节packet，复制名称／详情、写声明hash，调用StoreHookCallStack；用共享SRW排他锁入环，随后SetEvent | 分测标量、详情、可选栈、锁竞争及唤醒；有界容量不等于有界等待，更不等于同步控制通道 |
| 同文件ring／reserve | 4096槽，普通业务最多4032，Internal保留64但仍可满 | 同步stop及未释放责任独立预留；64个Internal槽不能充当每stop恢复槽 |
| `WritePendingPacketLocked` | 每包CreateEventW／CloseHandle，单包OVERLAPPED WriteFile；批次出队仍逐包发送 | 比较连接级复用事件／多包写入的收益、取消及断线语义；保留旧协议分帧回归，不能只改缓冲大小 |
| `HookTargets.cpp::HookedNtWriteVirtualMemory` | 原调用后计算耗时、格式化详情、再发包；输出指针读取也需安全审查 | enter／return分型和同步gate必须独立接入；API自身耗时与Hook附加开销分测 |
| `MonitorDock/WinAPIDiskArchive.h::append/flushLocked` | 调用append的线程上构造QJson／Base64，达到1 MiB或1秒阈值同步WriteFile | 新追踪归档用独立执行器；旧读端不能被误报为已经隔离慢盘 |
| `hook/HookCallStack.*`及配置路径 | 栈、元数据查找及配置快照各有实际执行成本 | 按开关分测；已有不可变快照不自动证明最后引用析构／分配器路径适合早期Hook |

容量算例：假设输入10万条／秒、1000字节原包且消费者短时完全停顿，4032个普通槽仅约**40.32毫秒**容忍窗口；仅原包流量约**95.37 MiB／秒**，不含额外字段、内核管道、拷贝和归档编码。这是算术，不是现有吞吐。逐包系统对象、锁和文本成本须测后再决定优化顺序；扩大ring不能解决持续消费不足。

不照搬历史性能诊断为当前代码缺陷：当前`HookEngine.cpp::AllocateNear`已委托`NearAllocation.h::AllocateNearAddress`并传安装取消检查；早期DWM记录中的旧逐64KiB扫描不能未经核对再写成当前实现。启动、安装／卸载与稳定采集成本仍须分别测量。

## 6. 性能验收：测什么、怎么分层、超限怎么办

### 6.1 分开计算调用开销与故意停止时间

每次测量保存原始QPC／频率／clockId及阶段有效性。跨进程时间只有确认同一时钟域后才比较，不跨机器相减；不能复用旧墙钟timestamp100ns冒充精确阶段耗时。

| 指标 | 起止与注意事项 |
| --- | --- |
| `hookAddedTime` | Hook进入到返回减去被包围原调用耗时，另扣明确停驻区间；无命中／命中分别报，不包含用户思考时间 |
| `originStopLatency` | 同步条件确定命中到原生origin-held被外部取得；记录发布／异常交付／调度分量及可观测边界 |
| `groupStopLatency` | 接纳范围快照到最后一项停止确认；部分失败也统计，不丢掉超时样本美化P99 |
| `stopSkew` | 各对象停止时间区间的差；状态读回不能反推精确同时停住，未知就报边界或unknown |
| `nativeAdvanceTime` | 从临时放行到安全边界、NX重设防确认；TF指令数／异常数／最坏页内停留单列 |
| `releaseLatency` | 显式继续提交到各项自有责任释放确认；“已可调度”与夹具后续标记证明“已运行”分开 |
| `disturbance` | 目标吞吐／耗时、CPU core-seconds、私有提交／工作集、上下文切换、故意停驻占比、最长不可运行区间 |
| `pipeline` | 源尝试／抑制／丢失、队列字节／年龄、入库水位／刷盘水位、规则候选数与扫描字节、UI输入延迟 |

冻结／恢复P50、P95、P99及max之外，还报样本数、失败／超时比例、负载和停止规模。P99不能用几十次成功样本支撑；先以至少10000次有限正常命中作为微基准候选样本量，大规模／长停驻样本另报n及局限，不为了凑数重复高扰动系统进程实验。暂停者与观察者都可能被调度延迟，不承诺硬实时上限。

### 6.2 最小可重复矩阵

仅在后续实现／试验范围内使用自有良性目标，固定Release／IntDir及HostX64，构建低于正常优先级；本轮不启动新试验。

| 维度 | 必须对照 |
| --- | --- |
| 功能层 | 未注入基线；已加载但不Hook；仅Hook旁路；标量遥测；加参数／栈；同步谓词不命中；单线程命中；全组命中；NX／TF重设防 |
| 架构／后端 | x64与x86/WOW64；R3无KSword驱动；R0指定环境独立结果，不能合并统计 |
| 并发／规模 | 1／4／16／64生产线程；1／2／8／32进程；停止规模1／16／128／1024作为负载点，超过实际capability则测明确拒绝，不强行假支持 |
| 频率 | 可控1千／1万／10万事件每秒及饱和曲线；未命中、稀疏命中、持续命中分别记录，实际未达速率仍保留 |
| 停态竞争 | 命中时持业务／loader锁、嵌套调用、并发命中、创建／退出线程、配置切代、continue撞上新命中 |
| 背压／故障 | 遥测满、控制洪峰、慢盘／满盘、stdout／stderr停读、通知丢失、坏命中槽、超时、断线、owner死亡 |
| 消费层 | 只归档；全部适用规则闭包；UI隐藏／可见／筛选滚动；调查开启；不同组合保持相同输入可比 |
| 时间 | 短基准及至少1小时稳定负载；退出／重开后内存回落，Hook退役代码与新目标数量分别计量 |

不要求做全笛卡尔积；固定基础负载后逐因素对照，再测已发现的相互作用，保留原始结果和实际启用闭包hash。大量规则候选仅目录浏览不等于全部安装或每事件全扫。

### 6.3 可执行的工程门槛与数值状态

先验硬门槛：无命中最小路径不等待IPC／磁盘／用户，不在Hook做无界分配／抢锁；stop与恢复资源不受遥测淘汰；暂停后恢复只依赖仍运行的外部owner；没有完整线程门控不开放严格区域重设防；未实现能力明确拒绝。

原有256 MiB逻辑数据预算、8 MiB恢复预留及各队列初值继续有效，不是RSS硬上限，也不是低扰动证明。目标端另公布每Agent固定提交、每线程槽、活动／退役Hook及内容缓存预算；三十二个Agent的固定开销不能只计控制器一次。使用`总固定开销 + 活动实例数×每实例成本 + 在途峰值`计算准入，槽容量与恢复记录以实际capability为准。

延迟／CPU阈值尚无基线，不能现在承诺“同步下断小于1ms”“监控只增加5%”或“120Hz无感”。首个最小路径原型应同时交付吞吐下降、每调用附加成本、目标与控制器CPU、建组规模曲线及故意停驻占比，才能冻结`PerformanceProfile`。profile按后端／架构／功能层保存测量环境、通过范围和饱和点；未测字段为null／unmeasured，不能填0。公开严格能力仍须通过正确性门槛，性能好不能弥补漏过原调用。

控制循环也需要测：同一个原生owner不能永久阻塞在`WaitForDebugEvent(INFINITE)`而不处理人工continue。首版比较有界等待1／5／10ms等候选的空闲唤醒成本与命令延迟；使用真实可唤醒机制时再验证所有权和取消，不把APC送给WaitForDebugEvent线程当通用唤醒方案。等待间隔是配置／测量项，不是响应SLO。

过载分层处理：先合并显示、停可选富化、限制新作业；遥测可丢必须记gap；必需来源不能持续则停止新增准入并撤销相关Ready。同步命中不能静默采样、合并掉原始责任或自动改异步；确需只停首次／每对象一次须是显式断点语义。控制容量耗尽前停止新武装并保留已有恢复槽；无法覆盖突发并发命中的路由不公告强保证。用户长时间保持全局停止造成的任务吞吐归停驻时间，不混成采集CPU开销。

## 7. 追加工作与独立验收

不重编号既有33项基础施工任务。以下SB项是它们的追加关闭条件，当前均未实施／未新增运行结果。

| 增量 | 归属 | 关闭判据 |
| --- | --- | --- |
| SB01 同步契约 | A0.1–A0.3／A3 | 唯一schema/catalog冻结请求、origin-held／group状态、scope binding、结果及过期／重复向量；不新增同义公开方法 |
| SB02 R3直接接管 | A4／A5 | x64／WOW64良性Hook入口命中后，原调用计数仍0；sender／worker不运行也能被外部接管；继续后恰好一次，错误／返回不变 |
| SB03 R0停驻路由 | A4／A5 | 所选后端真实路由、并发现场、容量及外部释放，指定环境独立验证；无路由明确拒绝，不能拿R3替代 |
| SB04 全局范围 | A4／A6／A7 | 两进程以上逐项停止时序、请求与附带范围、部分失败／退出／新线程、native→显式hold转换及完整门控分别证明 |
| SB05 热路径成本 | A2／A5／A10 | 每入口累计谓词上限、槽发布／重入、锁／分配／唤醒／系统对象成本、未命中基线及饱和曲线 |
| SB06 故障与竞争 | A4／A8 | 重复触发、多个逻辑hold、cancel／continue／close／新命中交错、路由失效、owner死亡；已知失败不删除 |
| SB07 控制与数据隔离 | A1／A3／A5 | 遥测／磁盘／stdout分别堵塞时外部仍能query和精确释放；不要求已停Agent产生新ACK |
| SB08 全链路性能 | A8／A9／A10 | 按§6交付原始时钟、n、分位／max／失败比例、扰动和内存；三端／双后端分别报告未测范围 |

原先完整门控、普通store发现、跨页与共享别名、pending异常owner死亡、完整Agent最早加载、TCP成功断连和GUI真实验证等门槛继续保留。两项目标处置默认仍在开工总表§13，本文不替用户决定。

## 8. 核对资料与交付边界

本轮读取的主要源码：`APIMonitor_x64/core/MonitorPipe.cpp`、`hook/HookTargets.cpp`、`hook/HookEngine.cpp`、`hook/NearAllocation.h`、`Ksword5.1/Ksword5.1/MonitorDock/WinAPIDiskArchive.h`及`KswordARKDriver/src/features/kernel_noattach/kernel_noattach_events.c`。历史量化证据保持各自范围，不累加成产品全链路检查数。

Windows机制边界核对官方文档：

- [Writing the Debugger's Main Loop](https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop)：debug event使被调试进程的所有线程暂停，Continue允许继续。
- [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)及[ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent)：事件接收／继续的线程所有权与实际异常处置。
- [DebugBreakProcess](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-debugbreakprocess)：作用于指定进程；未调试时可进入未处理异常，不是全组停止API。
- [SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)：挂起计数及持锁死锁风险，不作为任意同步原语。
- [DLL最佳实践](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)：loader lock内初始化／等待的限制。

本轮完成方案、相关规划和只读停点快照契约草案的静态核对。草案及向量随 A0 单独发布。产品实现和原生试验按工程开工基线推进。[工程开工基线](ActionAnalyze工程开工基线.md) · [已发布的 A0 基础契约](../schemas/action_analyze/base-contract-v1.md)
