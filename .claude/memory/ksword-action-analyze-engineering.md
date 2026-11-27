# ActionAnalyze 工程推进记录

## 持续推进与交接

- **2026-11-27 已有Ex2任务结束，失败保留。** sh_21bf01c6f001ZBf4KG8eDPYaTt自动回执已到，仅一次运行，目标stubRan/counter1/exit0、admission armed1/rejected0、entryObservation入口2251867357184及坐标段1/序号1/hash保留；CLI6，递归源37036 ready=true但failed=true/error31，process exited=true/cleanPipeEof=true/pipeError109/coverageStale=true，不能按26/27判通过。回执native-ex2-build/runtime-receipt.md、原日志scenario-ex2.log及完整project-root-9ba37cab-e046-4025-9cf0-b3c9c5442534保留。回执仅凭原包marker不能独立证明flags0有效位，源端exit1也不满足所有目标exit0，仍待正式闭合；禁止重跑和新增CodeBuddy。主协调沿失败路径发现finishPipeRead沿用pollReader读包前的exited快照，新增EOF时由保留的同一进程句柄即时重读，继续严格保留截断包/非EOF/覆盖接收器失效。只修已知快照时序，不承诺关闭EOF后才真正退出的全部竞态，源码待构建和运行。

- **2026-11-27 最新禁止调用CodeBuddy。** 用户原话「从现在开始不得调用codebudy，已有的不管，等新的通知下发。继续」。即刻禁止新增/续接/重试，已有sh_21bf01c6f001ZBf4KG8eDPYaTt/PID8608的Ex2定向运行按原范围继续，仅等待自动回执，不派后续。前Ex2构建已完成：native-ex2-build/receipt.md及三份日志，两Agent/CLI各一次Build成功，正式Release CLI49F3EA35…/x649AA8AA5C…/x860DD058BC…，只证明构建，不证明运行。主协调继续第6项产品：Observe在closing或cancel时只保存已持有事件，不再启动NX推进；提交Continue前再查cancel，关闭收到取消但Close尚未到达时自动放行的窗口。源码待构建实测，不自行替测、不启动GUI；持续推进要求与用户原有脏文件/证据保护保持。

- **2026-11-27 第4/5项直接NT Ex2入口开发。** 4c57b774e为NtQueueApcThreadEx2登记API994/独立special Hook，沿现有调用前PrepareTransferExecution与AAAP1保存Reserve、ULONG flags及三个参数、NTSTATUS；共享分类/outcome及NativeTransferAssociation接入，Qt/Light仅扩展原APC字段文档的API条件以显示flags/Reserve/参数2/3，未新增布局/文案/协议。CLI help notes及使用文档同步。参考phnt ntpsapi.h七参数签名；尚待构建和真实调用，不能借旧APC2/456通过。当前CodeBuddy唯一必要构建sh_21bec46130013Dh5kCaf4Em70G/PID4392，hy4flash，限定新目录native-ex2-build复制既有构建包装器、两Agent及CLI各一次，禁止目标/GUI/探针/重跑；等待自动回执，期间产品输入冻结。前APC2契约space-bunny任务19372/node10548运行约20分钟仅查询工具链，无构建/测试结果；主协调核对只有宿主/node/conhost后结束精确node10548，status最终failed/exit-1，不计通过。APC2驱动准备sh_21bd9dba8001Stll3ep4eTvPS1也900秒超时仅读取，无run_apc2.py，不重复同任务。保留apc2_stop源码及apc2_contract已有用户/任务文件，整体目标继续，GUI后置。

- **2026-11-27 新包链实际通过与入口回执构建。** sh_21bc1fa8d001gstwD5fz0PzRax一次chain真实运行已9/9/CLI0，CLI30313DBE…+Agent40372585…，样本5505df0a-91e2-4e04-a439-8ee0d3a0a553；A40296/B41104/C27760均exit0，B两个计数/C计数各1，三入口各5条raw-native，第二范围tid41928/create134402358157052790，清退leftOwned0。CodeBuddy后续在缺原项目根时重复replay并超时143；runtime-receipt仅覆盖链，不算CreateThread正式回读通过。下批sh_21bc72d09001wp44xoKPQ6RugW已一次CLI Build成功，entry-build.log明确EXIT_CODE0/BUILD_RESULT SUCCESS/hash4F1C01D071326D7FD1A95F8DB71FB86F08BE8E2716803906939861DFF4002339；仍超时，无离线/清单最终回执。其仅删除已核实replay-stage的junction与空目录，原26证据文件保留。当前短批sh_21bcdb6710011ny1zT3pU2kpIo两独立任务：直接离线AAIP1和只写APC2夹具，不构建运行、不重复链。主协调不自行验收。新entryObservation增量尚无运行结论；QueueUserAPC2/统一停止恢复待实证，GUI仍后置。

- **2026-11-27 第4/5项逐入口执行来源。** 产品提交5bde7e334在ApiTransferHandoff原Observe唯一writer成功写入并核验raw-native之后，为精确目标PID/create且实际instructionAddress等于请求入口的准入保存首个entryObservation（线程代次/段/序号/hash/观察阶段）；未见入口为null，不以范围列表冒充。原nativePageAdvance明确scope=target-owner-latest，避免B第二范围最终tid被误解为首范围的执行线程；共享Describe沿原三端终段使用，不改UI布局或协议。此批尚未构建，不借CLI30313DBE旧包覆盖。上次运行任务sh_21bba2127001dQowZaXEppOuXX超时143，只有旧档读取、无新运行回执；主协调实际核对无CLI/python/夹具残留。收窄任务sh_21bc1fa8d001gstwD5fz0PzRax第一命令只运行既有chain一次，独立local-thread输出，禁构建；APC2准备sh_21bbe954d001iL2OyE4S77YPYI也超时143，仅读取无夹具交付，不计完成。继续核心产品，GUI后置，不为等待伪造修复或追加大回归。

- **2026-11-27 第5项正式整合构建完成。** local-thread-integrated/receipt.md（在codebuddy-five-tests根下，不在apc-context-handoff下）：两Agent及CLI各一次Build成功、BelowNormal/HostX64/正式IntDir/统一Release；CLI30313DBE…、x6440372585…、x86106C6581…。源码0134a8303/318ae1a34覆盖，Qt/Light已有OfflineSegmentReader/StoredEvidence均直接调用共享ReadApiInjectionFields+ApiInjectionCallOutcome，不复制第二份解析。独立读侧专项sh_21bb4e6e10012Cjo5IB8rBjsHO超时143，无测试文件/回执/结果，不标通过，不续跑。唯一必要新包整合sh_21bba2127001dQowZaXEppOuXX只复用正式exe/Agent及既有夹具、一次chain且禁止构建重跑，核对本地CreateThread原包与raw-native的真实线程代次；旧样本保留pre-local-thread，失败直接回执。当前仍未形成新包运行结论，不借旧链PASS覆盖。

- **2026-11-27 第456项已有样本结构化核对通过。** CLI c1a3fc19…/Agent9f9318aa…最终样本1bd335c5-7490-4d72-b0bf-8fbe0b8b047a：三个admission error0、CLI0/completedInterval=true、三目标exit0、本地计数各1及清退成立。离线Stored文档顶层instructionAddress：B.block1段1/2/3/9/10，B.block2段11–15且tid2792/create134402347518934128，C段4–8；三者入口精确命中，各5条execution-enter-attempt，不把范围目录或25次字节命中当执行。CodeBuddy实际三次运行（原失败+修夹具后两次），已披露其追加重跑越界；以后先离线取证，不重跑已过链。回执tools/action_analyze_validation/api_handoff_chain/receipt.md及chain-456/receipt.md。新增本地CreateThread结构化源端/读侧不在旧Agent结论内，唯一正式整合构建sh_21bb65b49001dcDEKtV0oOJ374及读侧专项sh_21bb4e6e10012Cjo5IB8rBjsHO待自动回执，不轮询；GUI/R0/所有者死亡恢复/任意新分配传播未验。用户持续推进及shell期间继续独立开发要求有效。

- **2026-11-27 第5项本地线程证据读侧补齐。** shared/evidence/ApiMonitorClue.h登记CreateThread为thread-create，ApiInjectionCallOutcome沿原HANDLE/独立状态码一致性检查接纳该包装器；沿ArchivedEvidenceGraph保留AAIP1身份与实际返回结果。ApiTransferChain及ReadNativeExecutionRequest继续拒绝同进程跨进程候选，不扩大关系语义。0134a8303及本批共享头尚未构建/实测，不借当前chain旧Agent结论。用户再次要求shell执行时继续独立工作。chain首次三个admissions全部error0/armed3，8为管道请求数而非8个目标；原错误阶段判断已撤回。已定位夹具本地计数未发布到共享计数、duration0取消契约应为6两处问题，CodeBuddy唯一修正任务sh_21bb1e9f6001ld9rsBW4YnsRAG仅修夹具、复用CLI c1a3fc19…/旧Agent，一次有限期场景及回执，禁产品重建/GUI；主协调继续产品读侧开发。

- **2026-11-27 第8项单跳混采实证、转456。** etw-attach-fix/receipt.md已由CodeBuddy落盘：正式CLI hash3223ECB2…56371、两Agent新hash；B目标stubRan/counter1/exit0、CLI0、NX/Agent及自有清退成立，ETW5观察/2段/verified=true，真实普通段final=false及末段、duration45000/segmented计划和2检查点已在保留归档确认。强驱动仍14/18，4失败为删scratch后错路径及graph错误期待readback-verified，保留失败不再重跑B。唯一456任务sh_21ba2ba62001By3253KcjU9VdV复用两Agent，仅一次CLI增量及一次既有chain --execute，限12分钟，禁GUI/其他回归。主协调继续第5项：本地CreateThread沿原ApiInjectionObservation记录AAIP1入口/返回时钟、进程及真实返回线程身份，替代直接解引用调用者tid输出指针。此Agent增量不在当前456复用产物中，待后续适用验证，不借旧产物标通过。

- **2026-11-27 第4/6项成功准入与实际保护一致。** ApiTransferHandoff::Advance在Running及Agent Ready两处均用保留的真实目标句柄逐区VerifyArmedRange，临时开放返回Pending，实际错误保留失败；不再只靠owner范围登记先增加armed再等Hook重连才查NX。最终回包仍复核，不取消原保护/身份检查。源码待456定向实测。ETW CodeBuddy原宿主30分钟超时143：已有build-all.console.log确认两Agent/CLI成功，尚无运行回执；唯一原会话续接sh_21b9f6915001e7z5BlQJgNjpdb强制第一条业务命令运行原B一次，禁源码研究/重建/修驱动/追加场景，8分钟运行上限，测试与receipt仍由CodeBuddy完成。

- **2026-11-27 第4/5/6项追加范围暂停竞态。** ApiTransferHandoff在Pause实际回读前遇到NX命中时，不再因缺少手动暂停票据立即拒绝；真实可追加Held直接沿原AddRange，保存/继续仍归Observe；内部NX推进则保留Initial等待。只有真实Pending或已Held的手动暂停票据才登记ownPause，避免把已被NX抢先的暂停当作本请求债务。源码单独提交，456定向运行待CodeBuddy；不复用正在执行的ETW回执覆盖本次改动，GUI后置。

- **2026-11-27 第4/5项等待期间继续产品开发。** 用户明确「等待shell的时候写点别的」，解除本轮等待期间不改产品的工作安排。ApiTransferHandoff::Prepare现在无论原范围当前NX还是内部TF临时还X，均先按真实owner已登记目录解析入口；不把临时合并的VirtualQuery RegionSize作为新范围。新入口不在原目录且owner仍内部推进时，仅返回Pending，下一次Hook重连在回关NX后重新解析，避免冻结与原范围重叠的追加请求。最终成功ACK仍须VerifyArmedRange逐区确认真实NX。本批独立于正在运行的ETW构建实测，不能借该批产物或回执声称覆盖；待456定向实测。主协调只写产品，测试/记录仍交CodeBuddy，GUI后置。

- **2026-11-27 第8项显式附加遥测修正。** etw-stream最终回执已到：CLI正式Build成功，发布29条规则已接受；B目标stubRan/counter/exit0及清退成立，但配套ETW零观察、tailDeliveryUnconfirmed使CLI退出3。既有持续ETW9普通段+1终段及历史回读通过，不能替代混采。主协调定位MonitorAgent只在合作目录模式登记ETW，显式附加跳过；现统一为管道连接后的SessionEtw，合作/附加共用生命周期提供程序。EtwSessionController移除STOP前零回调即尾丢失的推断，仍保留消费者先退/ProcessTrace错误及丢包。CodeBuddy唯一任务sh_21b8358880012S8I4dF3IB4tso负责一次两Agent+CLI正式增量及一次原带ETW的B，回执etw-attach-fix/receipt.md；无GUI/持续ETW重跑/C。产品输入构建期间冻结，完成后继续456核心，不借源码修正声称已通过。全部测试落盘由CodeBuddy负责，原脏文件保留。

- **2026-11-27 凌晨主协调直接开发。** `98f018cb4`提前冻结异常CONTEXT，记录单步事件自己的EFLAGS/DR7并供Observe和临时页TF共同消费；仍严格要求BS，不按RIP移动吞单步。`3f41e3c2f`单来源递归Agent ETW及三端参数、计划/历史读取已接线；`dfa9d06ef`AAAP1追加queueFlags有效位/第16字段，兼容14/15字段旧包，原APC2 flags贯通三端；`e8769313e`统一ApiCaptureEtwJson并在API终段之前完成ETW封段，终段agentEtw保留独立阶段，不维护第二份桌面投影。`054bffda5`允许本轮已登记的递归来源在Ready前发送Pending下一跳，Advance仍等真实Ready后才推进。`c97eafb71`内部TF占用已核验空闲DR1、地址0须MEM_FREE，用活动调试槽维持状态回读，完成仍只认真实纯BS，退出/取消/错误沿原账归还DR1/TF；运行效果待验。`395040043`将已过严格Ready的自动接管HooksPartial非致命语义同步到根capture最终判定，仍保留partialHooks及硬错误。均本地提交未推送，原用户脏文件保留。

- **2026-11-27 最新方向及实际结果。** 用户明确「你把第八个弄完过后就去直接打通456」，第8项完成后集中第4/5/6项连续接管、脏页/新线程与统一停止恢复，暂不扩其他板块。integrated-status-slot已结束：两Agent及CLI正式Build成功；目标stubRan=true/counter=1/exit0，NX step-completed/nativeExit0/资源归还与自有清退成立；唯一强判据失败CLI6，C未运行。CodeBuddy回执在`.codex-build-logs/codebuddy-five-tests/apc-context-handoff/integrated-status-slot/receipt.md`，不是整链PASS。随包三条规则四处startsWith已改支持的Text.StartsWith并提交d2ac3532c，待规则目录复核，不重建Agent。用户明确CodeBuddy额度消耗可不计，旧数量限制不适用；所有测试/夹具/回执仍交CodeBuddy，主协调写产品，不自行替测。

- **第8项源码收尾。** 新ProjectEtwStream复用原单writer/ETW checkpoint，每段最多512条，原worker阈值256或约一秒排空，停止后循环封尾且只有最后段finalSegment；失败保留前缀且不跳段。CooperativeApiCapture三端共用入口及CLI原持续ETW已接同一游标，计划segmented=true保留请求durationMs，检查点及CLI历史读侧接受有限分段及实际报头PID目录，三端工程/filters登记。agentEtw增加segmentOrdinal/archivedObservations/finalSegment并沿原共享文档入API终段。当前仅源码，待CodeBuddy一次CLI构建和最小真实混采/历史回读；Qt/Light GUI后置。原用户脏文件保留，未推送。用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」继续有效。

- **第8项已提交7a355534b，4/5/6开始接续。** CodeBuddy唯一ETW验收宿主sh_21b65ed28001I0QJp8W3SLu13b/PID40492，续原会话；实际build-cli.console.log已记录CLI一次正式Build成功，hash C13E7EEBDD035CC6DEC03B15EBC7EC49F7071A081FB98C3DBFC5EF2DE3B3A1B5，Release规则hash与d2ac3532c源相同，两Agent复用旧已验版本。运行及最终receipt仍待自动通知，不借构建作ETW通过。后续053a33b仅改Agent Hook，新增CreateThread私有入口调用前接管，同进程Nt/APC/Context也可共用，模块入口本地快速跳过，不重装来源Agent；该增量不在旧Agent产物中。CLI构建已明确结束后主协调继续ApiTransferHandoff：NX内部推进时下一范围Pending而非Busy拒绝、主动暂停真正归还后才ACK、Close仅保存Held不再自动单步、清退成功不抹掉firstRecoveryFailure。源码待下一批456构建实测。

- **456夹具编写任务。** CodeBuddy宿主sh_21b671b36001dGZJzgK0FzsVoy/PID4872只在tools/action_analyze_validation/api_handoff_chain/写最小三目标两跳/第二范围夹具及独立receipt，禁构建运行和产品改动；不借此标运行通过。等待其自动完成后按新CreateThread同进程接续要求收齐，不提前Qt/Light GUI。下一执行：先读取ETW最终回执并修实际失败，再限定456一次整合构建与两跳/新范围实测；主协调持续写产品，全部测试记录仍由CodeBuddy承担。

- **2026-11-26 深夜核心继续。** 用户重申全流程目标，当前优先调用前同步自动接管。已提交`6468f5237`：NetworkTrafficSession单来源追加PID+创建时间窗口、原writer同采样归档、根退出后整链继续、独立追加失败、检查点及CLI回读范围，Qt/Light仅同步原网络说明和同源字段。两个网络作者并发增量已收齐，不覆盖用户文件。`20cd5b5c4`补原有QueueUserAPC2专用Hook，在原调用前执行APC交接；共享ApiApcCallOutcome及NativeTransferAssociation补QueueUserAPC2/NtQueueApcThreadEx准入，三端沿同源matcher，API原参数/返回/错误保留。源码均提交未推送；这两板块未有完整运行结论，GUI按用户要求后置。

- **NX定位当前交接。** `df5e9a971`和`6468f5237`保留内部NX推进的stage/error/原始DR6/continuation与目标退出码。最近完成B的真实回执见`.codex-build-logs/codebuddy-five-tests/apc-context-handoff/partial-hooks-fix/receipt.md`，B端到端仍失败。旧回执EFlags66054=0x10206，TF位实际为0，不能据该字段说已单步。一次性诊断任务首次宿主错误设120秒被结束，未构建/运行；确认无相关活进程后续接同会话，当前宿主`sh_21b1a4c0b001KF2rg1t1HlQza9`。只准一次当前正式CLI增量（BuildProjectReferences=false，复用旧Agent）、一次原B及一次i18n，失败不重跑、不扩探针、不找C、不GUI；所有脚本/回执由CodeBuddy写。下一步读取自动最终回执的nativePageAdvance，按实际异常归属修正续行，不吞未知STATUS_SINGLE_STEP。用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」仍有效；原11:54冻结是早前收工历史，不是当前停止指令。

- **2026-11-26 11:54停止状态。** 本轮最终产品源码`a0e5abe25`，恢复记忆另提交`b2700924c`。CodeBuddy第3项完成当前CLI正式增量Build exit0（SHA256 CBB7034F96693C6939EFD4C51520DF9164332F145E692AB30506CC508E42298A）及i18n 32875源串/exit0，日志在final-close；没有新场景。它又读旧日志、未在截止前写出receipt，主代理11:54按已核验进程树结束宿主3864/node41936及子bash/conhost，不再续接/重派；输出和原日志已保存，不能编造最终验收回执。11:54:12实际核对旧/新任务宿主与子进程、MSBuild/cl/link/python/CLI/入口夹具均无残留，自动收尾automation已删除；调度状态文件可能因强停仍标running，按实际PID及该记录判定已终止。用户原有两处tracked脏文件、两个untracked测试及runtime资料保留，无删改。按用户要求明天原分支原地恢复，不取消关机，不在12:00前再启动任何任务；整体目标未宣称完成。

- **2026-11-26 收工前最终修正与有限验收。** `bb1ebe216`解除固定上限、`52bb756d9`三端EXE/递归接管/同采样网络均已本地提交；`d4591fa80`修正Close先保存已持有NX事件、发Agent停止并Close原执行group解除debug冻结，再排空Agent尾包，避免Held事件冻结卸钩线程造成互等；同批定点补` · Win32 `及项目选择过滤器双语。总elapsedMs改到网络/ETW清退封段后冻结，intervalElapsedMs仍根Ready区间。CodeBuddy第1项sh_2186eb512001kWHvAfOrt7eumS于1800秒超时143，未产最终receipt；现有日志CLI及x64/x86 Agent增量构建成功（中间因共享源码未收齐曾失败，保留真实日志），入口场景A PASS，B/C无运行结果。第2项sh_21885fe7f001egNjsS0wqj18ol正常结束，theme PASS（14 token/1456文件）、i18n原4缺词条已修但尚未复查。新增额度用3/5，第3项sh_2188b3835001RPmN7PXTSBkZuA仅最终CLI增量/i18n及原日志收尾回执，禁止额外场景、11:54截止；主代理不自行实测或写验收回执。11:48核对原两宿主及子node、MSBuild、cl/link、CLI、python/夹具均已退出。代码已冻结，收尾只保存提交并确认最后任务退出，不推送、不GUI、不制作未验发行。用户要求不列剩余事项，明天保留原分支、脏文件、日志及项目证据；整体十一项仍未闭合，下一次仍从自动转移实证及当前源码继续，旧PASS不覆盖最后修正。

- **2026-11-26 第1/2/4/7项核心源码整合。** 根Ready调用OriginalSourceReady，根capture返回标OriginalSourceFinished；子来源经主worker的acceptPacket沿原raw/checkpoints单写者、全流连续sourceSequence归档，每包保存自己的PID/create/session。根自然退出后HasActiveAgents继续原Ready时长，不重置时钟，先Close排空子来源再终段。CreateRemoteThreadEx由生成后置包装改为独立调用前同步交接及AAIP1原包，读侧outcome与原生入口关联同步支持；原14字段/1000B ABI不变。LaunchedApiCapture接正式CLI launch/help与Qt/Light第四来源，三端工程/filters登记。NetworkTrafficSession由原网络服务拆Start/Poll/Close，API配置发布前启动、原worker轮询归档同sample raw-network，无第二writer；三端实时来源可选Off/raw-socket/existing-wfp，当前只根PID弱线索，HTTPS无。双语定点补15键及原流量68键；完整界面仍待后置实测。主代理据第1项CodeBuddy现有失败日志补winternl.h与ApiCallDuration{}；入口场景日志已有PASS，但完整Agent及递归接管不算通过。第2项仅双语/theme门禁，额度新增用2/5，宿主sh_21885fe7f001egNjsS0wqj18ol。用户要求12:00前收工且不需列剩余事项；收尾须确保本次任务/子进程退出，不取消系统关机。

- **2026-11-26 最新新增5项CodeBuddy额度。** 用户原话「按照先前的codebuddy任务量，你还可以布置5个新的。」覆盖旧3/3耗尽后禁止新派发的数量边界；新增已用1/5，主协调统一计数与派发。第1项核心接管实测宿主`sh_2186eb512001kWHvAfOrt7eumS`，独占正式CLI/APIMonitor构建，最多挂起入口/首次转移/追加范围三场景；产品失败不擅改产品或重复重建，测试/夹具/回执独立落盘，等自动完成。不恢复无限续接/重试，不提前Qt/Win32 GUI实测。

- **2026-11-26 最新用户核心方向。** 用户要求重点加强“发现跨进程行为→自动接管下一目标”，目标私有地址必须自动配置；入口须可选择EXE自动启动并挂起、再附加，同时保留已有进程入口。API Monitor的零窗口期待需要Hook调用前同步目标外owner准备屏障，不能拿返回后异步回传声称全接管。网络复用现有网络→流量监控强度，HTTPS解析后置。64页NX/16实例均现有代码上限，不是Windows硬限制；调整额度与补齐自动接管分开。用户询问十一项源码评估，已按源码口径分别估75/85/70/65/65/65/35/85/80/80/70%，仅粗估且不改原产品实证清单、不算整体均值。CodeBuddy测试额度3/3用完仍有效，不因goal重激活恢复。开发子代理【流量接入】只写独立网络后端/CLI源码，禁构建测试/GUI/CodeBuddy/提交推送；主代理处理启动与自动接管。

- **2026-11-26 第4/5/6项历史私有执行草稿源码。** shared ApiNativeExecutionProjection提供唯一PrepareNativeExecutionSiteDraft，核对原v3私有执行绑定、强实例、实际指令地址及来源摘要；NX仅原已纳入且包含指令的整页范围，不扩大。CLI analyze execution draft新增内置help及--sites-only输出完整v1站点文件；Qt/Light原归档树两动作送入原未启动集合目录、成功后导航，不覆盖表单，不自动Start/Append活集合；来源在原详情保留。复用ParameterWorkspace/None清单/FlowLayout/StructuredFieldView及原生等价结构，对照原候选准备与执行集合两页，不增加owner/轮询/文件工程项。双语6键定点，CLI及专项文档同步。仅源码本地提交，未构建/测试/i18n audit/GUI/验收回执/新派发测试/推送；自动接管仍无，不以此冒充完成。

- **2026-11-26 第6项CLI集合等待状态补齐。** 原StopToken为全部成员nativeSnapshot/sessionToken输出breakpoint.waitingForModule，ParseStopToken接新字段并兼容旧五/六字段绑定，精确字段计数不接纳未知键；不按零地址推定等待、不改变控制准入。上一批CLI帮助已承诺此字段，本批补真实集合输出。仅源码本地提交，未构建/测试/GUI/派发/验收回执/推送。

- **2026-11-26 第6/10项冻结定义条件源码。** BreakpointDefinition可选condition只存非空单行UTF-8 source/固定predicate-expr-v3，旧无条件五字段及原键序不变，新条件按键序进入原修订/hash/sample快照，编辑增量修订沿默认比较。ResolveSampleImageDefinition新增可选condition输出，带条件定义缺消费端口即拒绝；PrepareSampleImageCondition统一三端准备，保留CLI原生单目标Entry与OwnedDataWatchSession的Observation阶段。集合初始/追加在原目录副本准备全部继承条件，空手填继承，非空必须原文相同，冲突/类型/语法错误附加前整批拒绝，旧成员/writer不动。Qt/Light单目标原归档准备也接条件，Qt worker/Light原status回显实际继承文本；CLI --definition接原hello条件与求值器。Qt监控→行为分析→项目断点沿原ParameterWorkspace表单增加单行条件编辑/准备错误/草稿保护/清空/保存，Light原项目定义选择器只展示与激活，定义编辑仍为无；对照原DataWriteWatchPage/ExecutionGroupSiteEditor及ParameterWorkspace，未改主题/导航/布局所有权。双语4键定点source_translations，CLI help/元数据/schema/专项文档同步，无新源码/工程项。此批仅开发源码与本地提交，未构建/测试/GUI/i18n audit/验收回执/新派发/推送；测试额度3/3仍耗尽。延迟模块与条件均待运行，不能提升历史验收比例；全局自动激活/PDB/完整后代/死亡恢复仍为无。

- **2026-11-26 第6项集合延迟模块设点源码。** NativeBreakpointRequest新增默认false的waitForModule，仅显式普通映像执行准入；OwnedDataWatchSession::AttachImageExecution增加尾部默认参数，集合初始/追加Attach统一true，原单目标/合作默认不变。InstallBreakpoint仅ERROR_MOD_NOT_FOUND、且尚无目标副作用时保留Installing与waitingForModule，原LOAD_DLL事件中复用完整路径/PE位置/可选事件文件散列及全部线程登记后才Armed；不轮询模块、不新增owner/线程，不自动重绑卸载模块。关闭清除等待并沿原detach，等待不授Pause/Continue/Step资格或执行覆盖。CLI原ReportFields加waitingForModule/help/文档，Qt/Light原列表及同源详情明确“等待模块加载”、模块选择tooltip同步，双语2键定点source_translations。导航监控→行为分析→执行断点集合，原ParameterWorkspace+None管理表+StructuredFieldView/原生文本详情，参考既有单目标写入停点及执行集合两端；未改布局/主题/动作。仅源码，本批不构建/实测/GUI/派发/验收回执/推送；延迟DLL真实加载及清退待验，不能据此标全局自动定义或完整后代跟随完成。

- **2026-11-26 第6/10项集合Unknown保留实际路径。** 源码发现OwnedDataWatchSession仍默认假/未知自动Continue，导致集合文档/联停/自动归档的未知保留没有实际生效。构造新增默认false的holdUnknownCondition，集合Start与Append成员明确true，原ApplyCondition未知计数后直接保留同一事件；单目标默认旧策略不变。MatchesDisplayedStop与集合ReleaseEligible允许精确同事件/组/修订的真或未知，原完整令牌、恢复失败和原生动作准入不变；Unknown可显式Continue/Step/AddRange，自动归档仍只筛真实执行。三端均沿OwnedExecutionGroup获得修正，无新UI文本/协议/线程/owner。仅源码及专项说明，不构建/测试/GUI/验收落盘/派发/推送；不得把历史追加138检查或旧条件回执扩算这批通过。

- **2026-11-26 第6项Light归档启动草稿收尾。** ExecutionGroupPage在路径EN_CHANGE及自动保存/打开已有项目checkbox变化后沿原Refresh即时刷新资格；缺目录时禁用Start并说明原因，实际worker Prepare附加前拒绝仍保留，运行中参数仍禁改。不新增轮询/布局/页面/owner，修改范围为监控→行为分析→执行断点集合的原参数执行页；源码未构建/GUI/测试。专项CLI文档纠正旧“假或未知自动继续”为假自动继续、未知保留，与当前核心一致；不是新条件语义或运行回执。

- **2026-11-26 第4/9项无前置写入的入口关联源码。** NativeTransferAssociation原模块新增ReadNativeExecutionRequest/AssociateNativeExecutionRequest，独立解析成功AAIP1创建、接受AAAP1队列、接受AMD64 CONTROL AACT1请求，核对跨进程强实例/线程创建代次及instructionAddress精确等于请求入口；不需要写入，不按页/同PID弱匹配，不跨源QPC排序，不证明投递/上下文已生效/因果。CLI新增analyze execution entry，复用原Map双链读取及原API分页，help和CLI文档同步；旧correlate/map/memory-range语义保留。共享窗口范围/入口分别128，整段提交摘要，Qt/Light原四个读侧发布点接Requests，原三个一致性根显示空写入与完整entryRequest/native文档，同请求已有成功写入链时不重复加无写入副本；总结果512、独立历史保留。字段evictedMaps/sectionMapRequests为兼容命名，实际状态改“请求输入淘汰”；无写入说明改“不表示没有发生写入”，Light范围原请求不再误标全为节映射。导航监控→行为分析→项目与采样→归档关系，主树+共享StructuredFieldView/CodeEditorWidget原详情，参考既有原生历史根/范围树的两端实现，不改布局/主题/动作。无新增文件/工程项/线程/owner，双语2键定点source_translations。本批只源码与文档，不构建/测试/GUI/新派发/验收落盘/推送；3项额度耗尽的约束仍生效，整体目标继续。

- **2026-11-26 三项测试最终宿主状态及语言修正。** 追加任务自动回执：唯一正式CLI构建成功，产物SHA256=33f97540acee6fa3bbfbebe398741bb22491bae3b821ecb448da94ea739c6863；635626206及用户原KswordCLI.cpp范围，6组138检查PASS，测试脚本及receipt由CodeBuddy落盘.codex-build-logs/codebuddy-three-tests/append，构建不覆盖09:59–10:01后联停/范围/自动归档改动。原i18n实际448项FAIL（每语言224），主代理按这份既有失败清单定点补入source_translations，复用已有译文并补“新建项目/线程TID/需要恢复”英文；不整体重写、不删旧translations映射、不运行audit或GUI，不把修正称门禁通过。文本比较宿主sh_21812235f001qocCy95j8uXwn2于1800秒超时143、无最终stdout；rules目录只有构建文本及夹具源码，不能认定运行通过/清理完成。历史线程恢复仍以cancel通过、thread-exit FAIL为准。3/3已用完，三个宿主均结束；禁止新增派发/续接/重试，继续核心源码，测试/验收记录仍由CodeBuddy负责。

- **2026-11-26 第6/9项可选自动执行归档源码。** ExecutionGroupArchive::Prepare冻结autoSaveExecution，空目录在附加前拒绝；Observe只在原worker正常Query与Step/CancelStep结果后调用，NativeExecutionFromOwnedStop筛真实执行，沿原SaveEvent/journal/raw-native唯一writer去重写段。最近非空automatic批次最多16回执，verifiedExecutionSaves只计手动+自动唯一核验成功写段；手动saved/duplicate不被后台覆盖。首次自动失败/异常停止策略、独立automaticError，不抛成主会话Close或Continue，真实写失败仍保留原appendBlocked/firstFailure。CLI接--auto-save-execution/help及原Tick，Qt/Light原参数正文同名开关、Start冻结、运行禁改、原字段/文本详情，Capture/Memory/Close无隐式自动保存。导航监控→行为分析→执行断点集合，参数执行+None清单+同源详情；对照DataWriteWatchPage/ProcessGroupMemoryPane与ParameterWorkspace。双语4键正确放source_translations，无新增文件/线程/轮询/工程项。仅源码，不构建/测试/GUI/派发/推送。追加CodeBuddy自动返回正式CLI构建和6组138检查PASS，但i18n448项FAIL；该产物不覆盖后续联停/范围/自动保存，语言包分区修复另批进行。

- **2026-11-26 第4/9项内存实际范围→执行关联源码。** AssociateNativeMemoryRange在既有NativeSectionMapAssociation模块中独立核对AAIM1成功Allocate/Protect、源/目标创建身份、目标稳定位、实际输出及实际指令半开范围；Free/Unmap不匹配，不推定仍分配、MEM_PRIVATE、版本、先后或因果。CLI新增analyze execution memory-range及完整help，复用原Map分页/双链读取，旧execution map保持只节映射。共享ApiTransferCandidateWindow原Maps窗口扩为最近128条映射/分配/保护原包，事务CommitSegment填摘要；ApiNativeExecutionProjection调用共享核心，kind3沿原范围根，sourceDocument精确candidateType=memory-range并保留AAIM1实际/请求/有效位。Qt/Light仅换第四一致性根标签与空写入释义，旧节点编码、历史根、坐标/散列选区和原异步读任务不变；两条双语及CLI文档同步，无新增文件/工程项/owner/轮询。受影响导航为监控→行为分析→项目与采样→归档关系，主树+同源字段详情，参考原API/原生历史树与PrivateExecutionCandidatesPane。不构建/测试/GUI/验收落盘/新派发/推送；追加测试的结果不得覆盖这批新增关联。

- **2026-11-26 新3项测试额度已用完。** 第3项为635626206活集合追加的正式CLI本机focused验收，最多6组，只它构建完整CLI一次并做本次文本i18n门禁。前两项为条件文本比较和历史线程恢复。三个任务通过CodeBuddy skill直接派发，禁止新增派发/续接/外部重试，自动等回执。所有测试及记录由执行者落盘，主代理继续写功能；不得凭派发成功标运行通过。

- **2026-11-26 新授权最多3项测试。** 用户原话「我再批3个测试的额度，可继续调用codebuddy。」条件文本字段最多8组（sh_21812235f001qocCy95j8uXwn2）、历史线程恢复最多2场景（sh_21813eecb001fKXDq9hTcc2QML）、635626206集合追加正式CLI最多6组（sh_21816cae30014PdK8OQBHgJUIE）均已派出，已用3/3。只允许第三项构建完整CLI一次，前两项编译独立小夹具，固定IntDir/统一Release。禁止整批重跑、GUI、额外子派发、轮询和擅自续接；最新goal重激活不撤销本次数量边界。主代理仍写功能，测试及记录由CodeBuddy独立落盘。

- **2026-11-26 第6项显式命中联停源码。** OwnedExecutionGroup::Start新增默认false的holdPeersOnHit；正常Query先沿原session求条件，再对新保留断点向可暂停运行成员逐项Pause，未知条件保留、假条件继续。逐成员NativeEventKey去重，手动暂停/步进不触发，同一旧事件不撤销用户显式子集Continue。QueryWithoutCondition仍不产生联停副作用；peerHold独立保留触发owner/event和原始逐项暂停回执，不覆盖最近显式operation，后续Held仍看真实成员状态。CLI接--hold-peers-on-hit及帮助，Qt/Light原参数正文接同名开关、Start冻结、活集合禁改、原worker处理，字段详情复用原文档/文本。导航仍为监控→行为分析→执行断点集合，参数执行+None管理表+同源详情，参考DataWriteWatchPage/ProcessGroupMemoryPane与ParameterWorkspace/StructuredFieldView；无新后台任务、轮询、布局框架、驱动协议或源码文件。双语定点同步；仅源码，主代理未构建/测试/GUI/写验收回执，不推送，不增加第4项测试。

- **2026-11-26 第4/6项运行中追加实例源码。** OwnedExecutionGroup::AppendMembers按显式授权+原collectionId接收新站点，总计16个不同PID；先统一校验和分配，逐新成员独立Attach，原成员仅QueryWithoutCondition、不Continue/重建。Start无项目也只生成一个sample，后续沿用。ExecutionGroupArchive使用原sample冻结定义解析，追加失败独立memberSetupError，保留旧setup/writer。CLI新增members-append/control.members.append及原execution/N重放；Qt/Light原worker与固定动作栏接当前完整表单，Qt模型末尾insert不reset。导航为监控→行为分析→执行断点集合，参数执行+None管理清单+共享字段详情，复用ParameterWorkspace/FlowLayout/原生适配；对照DataWriteWatchPage与ProcessGroupMemoryPane及其共享实现。没有新增轮询、驱动协议、页面或源码文件；双语及CLI帮助文档同步。主代理未执行构建/测试/GUI，运行交第三项CodeBuddy，尚未通过；不自动后代或全系统激活。

- **2026-11-26 第10项文本字段等值源码。** 原FilterAst新增TextFieldComparison布尔叶，准备时绑定双方当前阶段Text目录，v3解析`left.field ==/!= right.field`，原常量/null/v1/v2路径保留。解释器左到右读取，完整Known按原UTF-8区分大小写比较，两个显式Null相等、Null/空文本不同；缺失/截断/读失败为Unknown，不因同字段折叠，原预算/UTF-8故障保留。Qt规则草稿说明、CLI catalog内置help、README/CLI文档及双语同步；Light预置回放复用同一核心，不新增字段或页面。仅源码，无构建/测试/GUI/派发/验收记录/推送。另已核对执行集合AddRange实际已有三端完整接线，不再重复实现。

- 文本字段间比较随后调整为先走原二元优先级再归并叶；不能在Atom中提前生成bool，避免`bool == textA == textB`被错误接受为`bool == (textA == textB)`。临时字段叶只在当前阶段两Text的==/!=归并，未归并交原类型准备拒绝；不修改原文本常量语法。仍仅源码未测。

- **2026-11-26 第9项独立历史失败发布补齐。** Qt保存本次原生失败摘要，即使首次无可发布快照或保留旧完整树仍显示真实段/阶段/Win32；取消沿原取消态。达到4096段的已核验独立原生窗口不再被旧Complete拦住。Light普通raw缺失、原生链坏时沿原失败回执显示raw-native段及项目错误，不清诊断或伪装空成功。只改原异步读侧及共享状态文案，无布局/计时器/所有者变动。CLI新增共享include的三级父路径已直接核对为仓库shared。源码未构建/测试/GUI/推送，无新增验收记录；原用户KswordCLI.cpp改动保留。

- **2026-11-26 第5/6项非CALL步过源码。** 原`NativeStepRuntime::Destination`对OverCall的非CALL分支改用既有TF路径，CALL继续DR1返回边界；请求模式不改写、无目的地表示单条TF，不预测跳转或RET后IP。`NativeStepUsesSingleInstructionTrap`统一证据及同时DR0/TF事件分类，完成的真实单条TF可形成instruction-completed，CALL返回/Out/内部NX推进仍不冒充。Qt、Light、CLI单目标及集合沿同一runtime，无新增owner、轮询或页面布局；CLI内置help/文档同步。历史“仅用户Into”边界由此源码扩为“用户Into或非CALL Over的真实单条TF”，不是运行通过。无构建/测试/GUI/验收记录/派发/推送，历史线程退出及取消失败仍待验。

- **2026-11-26 第9项独立原生历史源码。** 共享`ApiNativeExecutionProjection`新增最近512条独立观察及`NativeExecutionHistorySource`；不要求匹配API，完整来源含原生段号/序号/偏移/块/端点/SHA256及原文。Qt归档关系树第十根、Light原生历史状态根加入叶项，按原物理坐标和散列续持选择，共用原字段/文本详情；只有raw-native的采样沿原项目异步回放入口接入，不伪报API/ETW终段。CLI新增`analyze execution history --after N --limit N`共享同一读侧，摘要分页默认32/最大128、全链上限4096，完整原文沿execution read。导航为监控→行为分析→项目与采样→归档关系，类型主树+共享详情；对照原API关系树、原生候选字段视图和Light候选树，不新增布局/观察器。内置help、CLI文档及双语同步，CLI登记共享cpp。仅源码，无构建/测试/GUI/验收记录/推送；既有其他核心缺口继续推进，禁止新CodeBuddy派发仍有效。

- **2026-11-26 第1/2项启动展示源码归位。** 提交此前遗留的Qt条件块位置修正：先组合API启动阶段再判断状态文本是否变化，执行观察的if声明与其字段块保持同一作用域，避免阶段存在性错误门控状态刷新。Light将启动详情与原诊断按实际区块排列；语言包/CLI文档仅归位已有启动字段与同步采集说明，无新增采集行为。源码未构建/运行，正式Release未更新。

- **2026-11-26 第10项bool等值比较新增源码。** 复用BooleanBinary扩展Equal/NotEqual，v3 bool字段保留原null测试，其它比较交共享优先级解析器，支持bool字段/括号/函数/三元谓词之间==/!=。两侧左到右，任一未知即Unknown、两个未知不推断相等；大小比较和bool/u64混用仍拒绝，v1/v2仍走原解析。三端提示、CLI内置help、规则README及双语同步。此前回执中bool字段间==为无的边界已由这批源码扩展，但未构建、测试、GUI或派发，不能改为运行已通过。

- **2026-11-26 第10项布尔非短路源码闭合。** v3解析器按两侧静态输出选择BooleanBinary/u64 NumericBinary，解释器按左到右依次计算bool &/^/|，算术和预算故障仍使最终Unknown；同为bool或同为u64，混合拒绝，v1/v2不开放。Qt规则草稿、写入停点、Light说明与CLI内置help、两份文档及双语同步。CodeBuddy确认已有主体无新增行为缺口，仅修FilterAst契约注释，主代理补RuleExpression.h过时说明。只是有限C#风格谓词，不是完整C#执行环境；bool字段间==仍为无。无构建/运行/GUI/新增验收记录/推送。

- **2026-11-26 第5/6项线程恢复源码整合。** 接收CodeBuddy原限定任务的两处改动：`NativeStepRuntime::Restore`在上下文失败时仍逐真实线程对象结清已signaled退出对象的暂停债，存活债保留；`NativeDebugOwner::RestoreStep`在step资源为空的返回之前先处理仍开放的NX页。主代理只整理新增注释和代码排版，没有重复完整审查或执行验收。历史线程退出/取消后Continue异常保持待验，未构建/测试/GUI/推送。

- **2026-11-26 第5/6项执行集合成员内存源码。** 原`OwnedExecutionGroup::CaptureMemory`核对原owner/完整Held后复用该成员`OwnedDataWatchSession::CaptureMemory`；不求同伴条件、不Continue、不改为实时读取。`ExecutionGroupArchive`保留最新读取和独立保存来源，复用原writer/sample的`raw-memory`，独立段号/前序、同读取去重、真实写入失败阻止后续追加。CLI接`memory-read/control.memory.read`及`memory-save/control.memory.save`，原execution/N重放；保存按trackingEpoch指定当前原字节。Qt复用ProcessGroupMemoryPane参数及新AppendCapture字段入口，隐藏重复项目；Light沿原参数正文及唯一worker；两端Close置已有取消位、读取收尾后原集合清退。导航仍为监控→行为分析→执行断点集合，页面类型参数执行＋None清单＋共享字段详情，对照写入停点与原停止组内存页。本批无构建、测试、GUI、验收记录或推送，产物未更新。
- **2026-11-26 两项CodeBuddy恢复任务结束。** 长宿主自动回执两项ok，布尔245004ms、线程恢复170694ms；均只源码。布尔作者确认已有v3 &/^/|的bool/u64路径闭合，仅修正FilterAst.h契约注释，指出RuleExpression.h旧说明需同步。线程作者新增DischargeExitedHold，仅按真实线程对象signaled证明免除退出对象暂停债，存活债务保留；RestoreStep先回关NX再判断step资源。不得推断历史CountPeerTicks=0或取消后0xC0000005已运行修复。限定两次授权已结束，继续禁止新派发/续接/重试，自动回执位置仍在.codex-build-logs/codebuddy-two-dispatch。

- **2026-11-26 第4/6项集合同采样API源码。** 原`ExecutionGroupArchive`借本轮唯一writer/sample和`CaptureNativeBoundApi`采另一明确来源，拒绝来源为任一集合成员；前后`QueryWithoutCondition`不求条件、不Continue、不自动保存执行事件。Qt复用`NativeSessionApiPane`、原worker和200ms投影，Light复用`NativeSessionApiFields`和原250ms快照；两端关闭立即置原取消位，排空后才Close成员及writer。CLI `api-capture execution/N ... REPLSESSIONTOKEN [progress]`／`control.api.capture`用唯一完整sessionToken、原128回执流水；解析/完整报告复用单目标入口，stdout响应、stderr可选进度。CLI有限同步采集期间控制排队，不能声称在途取消。本批仅源码，未构建、测试、GUI、验收落盘或推送。
- **2026-11-26 两项CodeBuddy网络恢复授权。** 用户明确「网络环境炸了刚才，你可以继续跑那两个炸掉的」。原批次90秒首token超时退出1；首次恢复宿主误设后台120秒超时退出143，已确认无残留派发/CodeBuddy进程后，同两项改为30分钟宿主上限重跑，当前`sh_217ef3fbd001zM5SIntRv2cBgQ`。仍只允许条件布尔/线程恢复原限定源码，不测试/构建/GUI/验收/再派发，等自动最终通知，不轮询；本次恢复不开放其他CodeBuddy任务。

- **2026-11-26 第6项集合冻结定义源码。** `ExecutionGroupArchive::ResolveSites`在首个成员附加前以副本解析全部模块RVA站点的可选`definitionId`，复用`ResolveSampleImageDefinition`读取本轮sample冻结启用定义，核对模块名/RVA并继承映像散列；冲突、缺项目或不支持定位在附加前失败并释放未使用writer。Qt/Light/CLI同入口，结果保留实际解析后站点和期望散列；隐藏模式保留草稿但不发送。项目失败沿原空集合清退再启动恢复。只是显式实例站点引用，不是完整全局定义自动激活，不解析PDB。本批未构建、测试、GUI、派发或推送。

- **2026-11-26 执行集合显式保存三端源码。** `Project/ExecutionGroupArchive`在原worker准备可选新项目／打开项目及本轮新sample，全部原成员沿用真实sample；保存前`OwnedExecutionGroup::QueryWithoutCondition`回读原owner完整事件，不求同伴条件、不Continue。`native-execution-v3`原写入器保留18寄存器、事件绑定、NX范围及实测散列，backend/serial去重；真实追加失败阻止跳段，保留首次失败及written/flushed/verified。CLI `--project PATH [--open-project]`与`execution-save`／`control.execution.save`；Qt／Light原执行集合参数页、原worker、详情同步接入。导航为“监控→行为分析→执行断点集合”，类型为参数执行＋管理表（None）＋同源字段详情，沿用ParameterWorkspace；对照原DataWriteWatch及ProcessGroupMemoryPane。全部新增仅源码，无构建／测试／GUI／验收回执／推送。继续禁止新增CodeBuddy任务，已派两项仍等待自动最终消息，不轮询。

- **2026-11-26 进度口径纠正，交接保留。** 用户质疑“整体70%”是否为应付目标；主代理已明确收回整体70%及±10%说法。这些数值没有统一任务分母或权重，混合了历史实证与新源码接线，不能证明达到70%目标。以后按“历史正式产品已验范围／新增源码已接待验／明确未实现”报告，不以新增提交数量或主观平均数提高完成度，不为重新算百分比增加审查和验收任务。
- **2026-11-26 `278d1e4df` 同采样API在途启动源码。** 共享`NativeBoundApiProgress`携带原项目、采样、来源及native目标身份，沿原采集线程发布实际里程碑。Qt复用原200ms值刷新，Light复用原状态快照；CLI `api-capture ... confirm [progress]`或`params.startupProgress:true`向stderr输出带身份JSONL，stdout仍为原最终响应。完整采集/归档仍看最终回执。本批未构建、未测试、未GUI、未推送，不新增验收记录。

- **2026-11-26 当前开发批次，均仅源码且未推送。** `ff32000ba` 将真实Agent启动阶段接入CLI stderr与Qt/Light原快照；`353ccd441` 从已核验终段回放同一启动快照，旧档为null，归档详情不查询当前PID。`56b2dd4bf` 为执行集合各模块站点接可选SHA256，原owner验证装载事件文件，完整成员票据保留实测值，桌面保留期望值草稿。`c72a380f2` 聚合嵌套恢复责任，单成员Step/Cancel前置回读不自动释放其它成员。`234dddf40` 接Qt/Light同采样API关闭取消，原采集排空后再串行关闭native；启动前取消不装Agent、不创建API流。`ef27b3382` 新写`native-execution-v3`，保存同一事件原绑定、已纳入NX范围、实测文件散列；继续读旧v1/v2，不把历史绑定还原成控制。未执行构建、测试、GUI或新增验收记录，旧回执不覆盖这些变化。
- **CodeBuddy本轮唯一两次例外。** 用户仅批准直接派2项后等回执，再恢复静默；已一批直接派【条件布尔运算】与【线程恢复】，两项只做限定源码修正，不测试/构建/GUI/再派发/提交推送。最终文本在`.codex-build-logs/codebuddy-two-dispatch/`，批次宿主`sh_217a8b3fe001t52NhqCaDy67Ji`。等待自动最终通知，不轮询、不重试、不续接。布尔运算主体与三端提示尚未提交，等原直接任务回执后收整；历史线程退出/等待取消失败仍不得标修复通过。交接须保留这条限额，goal重激活不撤销限制。

用户2026-11-26最新明确「不需要测试」：当前阶段继续产品实现，不执行测试、不为测试构建、不新增CodeBuddy任务或验收回执。用户询问的五小时目标为第1、2、4、5、6、9、10项源码功能链路各推进到70%以上；这是开发目标，不能把新增代码当作运行通过。原生范围与TF推进、Light工具条及单页入口、AAIM1内存生命周期三位作者继续独立完整开发，主协调完成Qt/CLI及共享消费衔接。

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。进度答复后继续执行当前任务。该原话、未完成项目及下一可执行步骤须保留在压缩摘要和交接记录。按 [11 项产品验收清单](../../docs/ActionAnalyze产品验收清单.md) 更新状态，正式产品实证明确到入口、产物和测试范围，闭合批次仅推送 `ActionAnalyze`。

- **2026-11-26 验收纠偏补充。** 用户批准当前失败的CodeBuddy验收继续，要求核验必要性、削减约70%非必要门禁并明确边界。只恢复已有失败任务；同会话唯一续跑、CLI单次共享构建、失败仅复跑受影响场景。主协调已唯一续接旧CLI步进会话，先裁剪默认场景42→12（计划减少约71%），暂不授予构建/运行工具，等并行产品源码完成再明确允许实测；不扩验新增协议或GUI，不再并行续接相同会话。边界见[缩减批次](../../docs/action-analyze-planning/validation-reduced-batch.md)。
- 第4、5、6项本批新增源码：`CooperativeApiRequest::boundSampleId`复用原写租约和冻结采样，`RequireUnusedApiArchive`拒绝已有raw/checkpoints（含空目录或坏尾）；正式原生CLI的`control.api.capture`显式采另一来源实例，保留原native/memory控制。`BreakpointFollowProtocol`接`control.execution.follow`/`execution-follow`，独立128票据、原地址/完整当前停点核验、不Continue。原生作者已返回源码READY，新增`NativeWriteExecutionTransition.cpp`须由直接编译owner的自定义脚本一并链接。新功能、Qt/Light及新增协议仍未实测；旧失败续跑只按缩减范围，不自动扩大覆盖。
- 缩减源码续跑已结束，默认focused/full及skip-build已落盘。其回执仍有full空跑选择错误和内存两附加调用未计数，已在同一旧CodeBuddy会话下一次续跑要求修正（实际14/42约减67%）、禁止零场景PASS/异常不计失败、跳构建不伪报exit0，并授权产品READY后的四入口串行实测。当前唯一运行`sh_21715e4b1001abcgnDQDC1IVN3`，会话`01a216aa-73ca-7be7-8ebd-495384c02f91`；不再另派同会话副本，最终结果到达前不重试或轮询。

- **2026-11-26 最新限制优先于当前 goal，压缩与交接必留。** 用户原话：「从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你」「这个限制在goal之上，记得在上下文中保留。旧的继续。」已派发的旧任务继续运行；收到结果可登记，但用户明确恢复前不得新增派发、续接、失败重试或自动后续 CodeBuddy 任务。主协调与开发子代理继续写核心产品，未验部分保持待验，不自行替代原验收分工。
- **2026-11-26 双端集合源码接线收尾。** Light原作者任务033240及内存审查034938均已结束，前者未交付SOURCE报告，后者70项静态检查仍有共享writer／CLI的F2发现。原作者结束后Light集合已接原worker的Held范围读取、完整capture保存、新项目sample、clean后writer释放和显式下一集合；业务／状态／布局分文件并登记工程。Qt／Light写入页真实执行保存沿原OwnedDataWatchSession，普通Pause不构成执行证据。全部后续源码、双语、构建、GUI与退出取消时序仍待验，不新增派发或替代测试；详见[双端集合交付记录](../../docs/action-analyze-planning/process-group-desktop.md)。
- 最新优先级为「少在视图下功夫，多在全局调试和后端下功夫」。用户要求全部其他项完成前延后 Qt 和 Win32 GUI 桌面实测。现阶段允许相应正式构建、无窗口原生回归和正式 CLI 本机实测，历史桌面回执继续按各自范围记录。恢复 GUI 实测时复用 `tools/action_analyze_validation/isolated_desktop.py`，在独立非输入桌面执行。
- 用户最新要求「全面减少构建，只有当真的需要实测的时候才构建」。Qt／Light 后续源码改动累积至恢复桌面实测再整合构建；CLI 与无窗口验证只为实际待实测的批次构建。第 3、7、8 项保留后置顺序。
- 用户再次明确：主协调者优先写核心产品代码、整理职责；GUI 和 CLI 验收（包括夹具维护、实际执行、失败回执和落盘）交给子代理，由其用 CodeBuddy 在本机跑。复用已有效的回执，不为重复坐标和已覆盖行为追加轮次；改产品代码只做与实际变化相关的必要验收。
- 项目是默认工作单位。入口必须可新建和打开项目，并保留新一轮扫描入口。每次扫描生成独立采样和冻结配置。目录选择只进行只读分析，证据回查继续绑定该采样真实坐标。Qt 在独立桌面已验证同一项目两轮扫描及重启回放，记录见产品验收清单。
- 合作直连由 `Project/CooperativeApiCapture` 和 `Project/ProjectApiClueArchive` 复用采集与封段；CLI、Qt、Light 各保留本端会话、停止及项目租约。新桌面入口只编译合作控制分支（`KSWORD_APIMON_COOPERATIVE_ONLY`），不添加自动装载。合作流水号与 `raw` 坐标分列，规则在封段后回读；不得用已有同档回放、构建或静态门禁冒充桌面直连。[本批正式回执](../../docs/action-analyze-planning/validation-results.md#合作采集项目后端复验)

## 2026-11-24 首批工程启动

- 用户授权多 agent 并发编码、按功能分批提交和推送。主协调者负责分工、接口对齐、证据审查、集成排序、Git 和工程记录。逻辑闭合的工作包可先提交到 `ActionAnalyze`，适用构建可随后执行。分别记录源码、构建、原生和产品验收状态，产品验收项凭对应产品证据关闭。
- 新增或重构文件每文件上限 2000 行，沿用仓库建议的 1000 行组织目标。按职责拆 `.h`／`.cpp`，驱动用适用 `.h`／`.c`，禁止 `.inc` 堆叠。重构逐项登记受影响的旧功能与入口、行为、端／架构、复测判据、实际结果和待测范围。优先单独提交可验证的结构改动。
- R3 是正式后端，必须在 KSword 驱动未加载或不可访问时独立完成受支持用户态全流程。采样显式选择后端，活采样禁止静默切换。更换时原所有者先完成恢复并确认脱离，之后新建采样与会话代次，旧停点令牌和恢复责任留在原后端。
- 已确认同步下断使用命中线程直接进入已登记原生停点、目标外所有者接管。首个双架构夹具用自有合作目标验证调试所有权、进入／返回阶段和原调用语义。
- 用户指定 Qt 的唯一挂载点为「监控 → 行为分析」。总览、项目与采样、后续规则和断点等均是该工作台的子页。MonitorDock 管理根宿主，实际页签、全局搜索和 Taskbar 共用 `monitor.action_analyze` 导航树。
- 新增桌面工作包覆盖显示筛选、底部进程与线程右键和 Dump 导出、随采样自动归档网络流量元数据、出站 IP 和实际通信字节。网络写入沿用采样内 `raw`、`records`、BlobStore 和检查点。采样身份贯穿筛选、菜单与归档。[桌面交互计划](../../docs/ActionAnalyze总览交互与验收.md#显示筛选对象菜单与网络证据实施计划)
- 停止调试后的目标处置，以及单步时是否扩大依赖线程放行范围，仍由调用方显式决定。发现影响持久格式、恢复语义、采集范围或无驱动承诺的歧义时，先在依赖方之间对齐。产品需求变更写回共享基线并通知全部受影响 owner。

首批分工已启动，状态为开发进行中。A0 类型与 Stored 契约、CLI 离线外壳、Stored 归档与恢复、CLI 项目生命周期、离线规则回放、R3 停点夹具、被动环境入口目录、既有上游目录按行数拆分，各自独立编辑，统一审查提交。CLI `.vcxproj`／`.filters`、入口接线与内置帮助、文档同步在接口交付后统一分配，并串行运行共用构建工程。

## 当前验收决定

全范围完成验收后才能最终关闭。R3 在本机验证。普通 R0 在指定来宾 `E:\VMs\Windows11-24H2` 阻塞。普通 R0 入口要求 `RtlGetVersion` 报告 OS build `26300`，来宾 OS 为 `26100.9711`，SYS 就绪也无法通过。来宾已有 `TESTSIGNING`，KSwordARK 服务未注册、驱动未加载，现有产物来源与验证批次不匹配，配套签名候选产物未暂存。29 项普通 R0 外部判据尚未运行。历史夹具沿用各次授权和原始证据。环境详见本地计划 `docs/ActionAnalyze工程开工基线.md` 的「验收范围与运行环境」。

## 已接收批次与证据

| 提交 | 内容与证据 | 分支状态 |
| --- | --- | --- |
| `69f490db2` | 离线协议模型，本次无写入重跑 31/31 通过。 | 已推送 `origin/ActionAnalyze` |
| `f28f7fd5a` | 自有目标的 R3 原生步进夹具，本批沿用历史 106 项断言通过的证据。 | 已推送 `origin/ActionAnalyze` |
| `f04142e96` | 自有目标的传输夹具，保留历史 37 项 IPC 回归、7 项父进程终止后的子进程清理、TCP 权限负控。实际成功断连待验。 | 已推送 `origin/ActionAnalyze` |
| `f0efdde80` | 固定规则来源目录，共 24 个文件。11 个分片顺序拼接与原索引字节一致，批次内各文件最多 2000 行。 | 与 `10e0f370f` 同批推送至 `origin/ActionAnalyze` |
| `10e0f370f` | 自有目标页面执行探针夹具，沿用历史 21 项检查通过的证据。 | 与 `f0efdde80` 同批推送至 `origin/ActionAnalyze` |
| `055fef531` | SB02 自有目标同步停点夹具。Windows 10 19045，BelowNormal、HostX64 构建 x64 及 Win32 两个 Release，分别运行原生 x64 与 WOW64 目标。386 项断言通过，四个自有子进程，8 次真实停点、8 次旧代次或外来事件正确转交，四个正常退出事件，零测试配置、零残留夹具进程。[SB02 夹具说明](../../tools/action_analyze_sync_stop_validation/README.md) | 已推送 `origin/ActionAnalyze` |
| `6b459325e` | CLI 离线会话外壳和命令帮助。共用正式工程 HostX64 Release 构建退出 0，0 警告、0 错误，产物 `Ksword5.1/x64/Release/KswordCLI.exe`。旧 shell smoke 已独立运行并通过。本机构建日志 `.codex-build-logs/action-analyze-cli-shell-20261124-223330.log`。[旧 shell 回执](../../tools/action_analyze_validation/cli/README.md#first-shell-build-evidence) | 已推送 `origin/ActionAnalyze` |
| `5adc91d33` | A0 基础和 Stored v1 静态契约。66 项基础用例、35 项 Stored 用例及 CRC／UUID 检查通过。[基础契约](../../schemas/action_analyze/base-contract-v1.md) | 已推送 `origin/ActionAnalyze` |
| `a7d40bc27` | A0 离线 CLI 方法静态契约。62 项请求、传输及输出向量通过。[方法契约](../../schemas/action_analyze/method-contract-v1.md) | 已推送 `origin/ActionAnalyze` |
| `121ef3ea2` | Stored v1 分段读写与前缀扫描，覆盖封装范围与 CRC。记录语义解码另验。[归档验证范围](../../tools/action_analyze_validation/archive/README.md) | 已推送 `origin/ActionAnalyze` |
| `d2f246c8e` | 类型化离线规则回放与有界筛选。仓库夹具使用内存事件投影，完整 DSL、真实归档接线和实时策略继续按工单验收。[规则夹具范围](../../tools/action_analyze_validation/rules/README.md) | 已推送 `origin/ActionAnalyze` |
| `9a5449304` | 离线项目、配置修订和采样持久化。HostX64 Release 原生夹具 71 项以及 Python 文件与语义校验通过。最终可达代次链为 `6 → 4 → 3 → 2 → 1`，第 5 代保持未提交。[验证回执](../../tools/action_analyze_validation/project/ValidationReceipt.md) | 已推送 `origin/ActionAnalyze` |
| `96b9f38bd` | 被动环境证据来源索引归档。覆盖资料目录的静态清点，运行覆盖按独立判据验收。[来源索引](../../docs/action-analyze-planning/environment/README.md) | 已推送 `origin/ActionAnalyze` |
| `9c52f1847` | 原生停止责任账本与 C++ 夹具。账本处理单原生事件的释放责任。[账本范围](../../KswordCLI/ActionAnalyze/Control/README.md) | 已推送 `origin/ActionAnalyze` |
| `c0543c4dd` | Qt 普通 R0 回读解析器构建通过。R0 运行未执行。 | 已推送 `origin/ActionAnalyze` |
| `14509b8aa` | A0.2 离线项目／采样方法，62 项基础向量及 47 项项目方法向量通过。 | 已推送 `origin/ActionAnalyze` |
| `221cda4ba` | 正式 CLI 离线项目生命周期接线。HostX64 Release 构建退出 0，0 警告、0 错误。正式 CLI 的 `project_v1` 验证通过，临时验证目录已清理。 | 已推送 `origin/ActionAnalyze` |
| `923e36acc` | 保留 origin 的停止快照契约，96 项离线停止向量通过。 | 已推送 `origin/ActionAnalyze` |
| `59046a957` | 自有合作目标的原生停点与责任账本夹具。集成 495 项、基线 415 项、独立账本 124 项通过，范围限于各自夹具。 | 已推送 `origin/ActionAnalyze` |
| `345472b89` | Stored 格式分类与截断覆盖。469 项截断检查、35 项 A0 封装向量通过。 | 已推送 `origin/ActionAnalyze` |
| `a302d03cc` | 已提交采样的项目归档段解析器。28 项原生检查及 71 项项目生命周期夹具检查通过。 | 已推送 `origin/ActionAnalyze` |
| `a7f117606` | 正式 CLI 接通 `archive.inspect`。HostX64 Release 构建、12 方法的传输回归、项目及归档验收通过，测试目录已清理。[归档回执](../../tools/action_analyze_validation/cli/README.md#archive-v1-build-and-test-receipt) | 已提交 `ActionAnalyze` |

`221cda4ba` 的构建日志为 `.codex-build-logs/action-analyze-cli-project-20261124-224716.log`。受测正式产物 `Ksword5.1/x64/Release/KswordCLI.exe` 的 SHA-256 为 `54569FA5788D53160D1A6B2D37744A839E0B2A5D525E50BA834ECB9B0752710B`。`42c5977e6` 回执记录 `project-v1` smoke 通过 16 项请求、22 项传输向量及回执缓存条数和字节上限检查。[正式 CLI 验证回执](../../tools/action_analyze_validation/cli/README.md#unified-project-v1-build-and-test-receipt)

原 SB02 本机证据为 `.codex-build-logs/behavior-planning/action-analyze-sb02-20261125-022401-3067253-35208-metadata.json`。后续 `59046a957` 已验证自有目标夹具接线。并发命中、控制所有者死亡恢复与产品接入继续待验。

## CLI 接入与待验项

- 2026-11-25 正式 HostX64 CLI `b05abcd310b28515036802d70c5ab8cbbf7b74815ec35f63c7f70b1d8f74e37a` 复验自有 AMD64 子进程 131 次停点、130 次继续、128 条继续回执窗口和正常脱离。持续内存流通过 70 轮及精确 4 字节差异、四类输入收尾、stdout 断开和背压超时，以及退出后的计数对账。日志位于 `.codex-build-logs/action-analyze-cli-product-breakpoint-current.log` 和 `.codex-build-logs/action-analyze-cli-product-memory-current.log`。夹具已清理。全局停止组和故障恢复仍待验。
旧 `KswordCLI/KswordCLI.cpp` 已有 8398 行。ActionAnalyze 沿用它现有的委派入口，经 `KswordCLI/CommandRegistry.cpp` 接入，新增逻辑按职责拆分。上述 smoke 已覆盖实际帮助、旧入口查询及异常参数处理。其余回归按工单记录实际结果。

Qt 和 Win32 总览作者开工前均须读 `design-taste-frontend`。Qt 首版离线项目与采样通过正式 Release 构建，Win32 离线读取单个 Stored 段。实际窗口和旧入口回归另行验收。[当前离线切片](../../docs/ActionAnalyze总览交互与验收.md#当前离线切片)

Light 与独立 Stored 验证器的正式 Release 构建均以 BelowNormal 优先级使用 HostX64 工具链，两项构建均为 0 警告、0 错误。验证器通过 35 项 Stored 向量和 2 项 Win32 文件用例。正式产物为 `Ksword5.1/x64/Release/KswordARKLight.exe` 和 `Ksword5.1/x64/Release/KswordARKLightStoredEvidenceValidation.exe`。签名驱动镜像的 SHA-256 构建前后一致。[Light 构建与验证回执](../../docs/ActionAnalyze总览交互与验收.md#light-构建与验证回执)

## 网络证据的离线验收

网络草案通过 39 项静态向量。原生网络归档夹具在固定 `KswordCLI/x64/Release/ActionAnalyzeNetworkEvidenceValidation` 中构建并从统一 Release 运行，HostX64 `/W4 /WX` 的 539 项断言通过。包含 65,536 字节逐字节往返、队列回绕、源及队列丢失回执、实际截断文件后的已验证前缀。夹具段、对象文件和 EXE 已清理。投影夹具通过 112 项合成检查，包括八个 ETW 双栈收发描述符、IPv4 UDP／IPv6 TCP 原始内容及截断前缀。

旧 R3 `PacketRecord` 交付的实际字节最多 4,096，归档 writer 内联上限 65,536。ETW 计数按仅元数据处理。归档 writer 运行在样本单写者持有的串行通道，段刷新只产生文件前缀回执。实时接线、规范事件引用、BlobStore、检查点及跨端项目重开须单独验收。[网络草案](../../schemas/action_analyze/README.md#网络证据)

CLI `analyze network-capture` 已接入源码。冻结单一进程实例，依赖系统接受 ETW 载荷 PID 和事件 ID 筛选，保存回环端点及方向，关档后核对 `raw/1` 并返回记录坐标。采集字段只含元数据，ETW 窄筛选兼容性与正式回查见待验 AA-06。[验收交接](../../docs/action-analyze-planning/validation-handoff.md#aa-06-cli-实时回环网络元数据归档)

阶段依据保存在本地计划 `docs/ActionAnalyze工程开工基线.md`、`docs/ActionAnalyze施工任务与契约落点.md` 和 `docs/ActionAnalyze同步全局断点与性能复查.md`。首次启动时工作区有既有规划、验证夹具和资料目录尚未提交。集成须用限定路径提交，逐批核对来源、文档链接依赖、生成文件和行数。

## 被动 ETW 桌面回放

- 2026-11-25 正式 CLI 与 Light 共用 9 段持续 ETW 项目。CLI 记录 624 条 ETW 观察并查询 4,101 个不同 ID。Light 检查终段、624 条 ETW 筛选结果、跨段末观察的归档坐标和重读选择。移走第 2 段检查点后窗口报告该段尚未发布并只显示第 1 段的 14 条原始记录。截断第 3 段覆盖流后报告核验失败并显示前两段的 28 条。恢复后读回全部 642 条。旧 ETW 单段与五类 API 归档在同一 Light 产物复测通过。窗口正常退出，测试配置恢复，固定目录清理完成。日志 `.codex-build-logs/action-analyze-light-continuous-etw.log`，构建产物位于 `Ksword5.1/x64/Release/`。指定普通 R0 及 Light 实时采集仍待验。
- `3403fe3dc` 已推送至 `origin/ActionAnalyze`。Qt 项目入口重开冻结的项目及采样描述，再复用 CLI 校验 `raw/1` 与 `records/1`。只读句柄验证相同 raw 散列后，仅投影已提交前缀。标记缺失显示旧档回退，缺依赖或错采样保留原表和选择。独立段入口保留诊断式部分预览。
- 正式 Qt HostX64 构建、双语及主题门禁通过。真实 Qt 复验 14／12 行、同一详情、未提交尾部、缺 Coverage、错采样、旧档回退和恢复重读。窗口退出 `0`，测试项目和配置均已清理或恢复。浅色及右侧详情已验，Light 项目回放及完整桌面矩阵继续验收。[Qt 回执](../../tools/action_analyze_validation/qt/ETW-Readback.md#qt-项目检查点)

## 被动 API 检查点与离线规则

- 正式 CLI、Qt、Light 回放同一四段采样，验证缺标记仅读首段、第三段坏尾只保留前两段、修复恢复六条并定位 `raw/3 #9`。CLI 后续图页又通过 SHA-256 续页、候选原始坐标、检查点缺口拒绝和终段空页。来源诊断仅给出读端状态和历史声明，生产方连接和覆盖保持未知。[三端回执](../../tools/action_analyze_validation/qt/ETW-Readback.md#项目工作台与三端同采样)
- 正式 Qt 浅色独立桌面通过两组汇总、五类细分、原始坐标、坏尾重试和草稿保留。Qt 独立段网络读回通过双栈方向、实际 300 字节和 256 字节预览，完整／截断／坏 CRC 分别为 9／7／7 行。[规则回执](../../tools/action_analyze_validation/rules/README.md#协调登记与验收)
- AA-01 已通过 Qt／Light 候选与来源标签。AA-03 的 CLI 合作目标 Agent 就绪、线索回查及被动 API 跟随，AA-04 的 Qt／Light 同采样关系浏览，以及 AA-05 的 CLI 项目规则回放均已接入源码，独立验收会话负责构建和实测。Sysmon 正例、指定来宾普通 R0、条件停点与发行范围继续记录在 11 项清单。用户原话继续保留于本页首节。[验收交接](../../docs/action-analyze-planning/validation-handoff.md)
- 新版 `codebuddy-fast-dispatch` 已能用 `-Workspace` 和精确 `-AllowTools 'PowerShell(<命令>)'` 运行本机正式验收。命令不附加重定向、管道或其它语句；由派发宿主保存 JSON 回执。等 Release 链接完成后再启动对应产品测试，避免 Win32 32。AA-08 浅色隔离桌面和 AA-09 CLI 逐段命中已通过，[实测结果](../../docs/action-analyze-planning/validation-results.md#2026-11-25--codebuddy-本机-aa-08aa-09)。
- 合作采集和已结束 JSONL 共用封装，只有整段与尾记通过后才展示输入方式。`cooperative-pipe` 的源序号是普通包流水号，`closed-jsonl` 是行号，缺字段兼容旧档；不凭尾记认证历史生产者。Qt 的总览、采样摘要、规则报告及 Light 详情沿用同一回读值。
- 第 9 项跨段候选树在桌面既有归档扫描内消费共享 `ApiTransferChain`，每段暂存、整段检查点成功后提交；独立导入只在当前文件内串链。`shared/evidence/ApiTransferCandidateWindow.h` 保留 1024 写入行与 256 候选对，双方详情独立于 4096 主表窗口。恢复树选择需使用写入与创建双方坐标，不能只用创建包坐标（重叠写入可共用创建包）。来源声明不增加强对象或进程操作资格。[接口、CodeBuddy 回执及后置桌面范围](../../docs/action-analyze-planning/api-transfer-tree.md)；Qt／Light 构建和 GUI 仍后置，不能由源码接入推断通过。
- APC 桌面增量已接入源码：`ApiTransferCandidateWindow` 在同一 `Accept` 后调用 `AcceptApc`，共用 1024 写状态／详情，不另建写窗口；APC 独立保留 128 对 `write`／`queue`，两端快照公开 `apcTransferCandidates`／`apcTransferCandidateCount`。树选择恢复必须含类型＋双方坐标；Qt 第四组与 Light 第二根不混入线程创建组。单行 AAAP1 字段走 Qt 原规范文档／Light 原文本详情，接受入队不证明投递或执行。遵守最新禁令，本批未派发／续接 CodeBuddy、未构建、未测试、未 GUI；旧线程创建回执不覆盖本批，恢复验收须等用户明确授权。
- 上下文候选桌面后续源码已接入：共享窗口 `ContextCandidates()`／`ContextCandidateCount()` 独立 128 对 `write/context`，同一 `Accept` 后调用 `AcceptContext`，共用原 1024 写链和详情；Qt／Light 快照 `contextTransferCandidates`／`contextTransferCandidateCount`，独立树类型＋双方坐标恢复及 4096 外详情。活采从原 `contextCandidateCount/recentContext` 回执投影，Qt 本端 `contextTransferCandidates/latestContextTransfer` 及 `AppendApiContextProgress`，Light 原正文追加，无新 timer/query。不改布局，contextApplied/执行始终未知，不升级角色或控制权；七个双语键定点补齐，Detection/CLI/CooperativeApiCapture 未改。本批不构建、不测试、不 GUI、不 CodeBuddy，未提交暂存。
- AACT1／AASM1 桌面仅接入单行详情：行字段 `apiContext`／`contextOutcome`、`apiSectionMap`／`sectionMapOutcome` 消费源端独立结果函数，Qt 在原 `FieldDocument` 追加、Light 从原 `ApiTransferDetails` 分派。缺位未知，输入句柄不授身份；上下文 IP/SP/flags/ABI 仅请求；映射请求／实际返回范围分列，sectionOffset 原输入，sectionHandle 非别名身份。未建立新候选树。APC 活采 progress 复用已发布回执：Qt 本端 receipt 新增 `apcTransferCandidates`／`latestApcTransfer`，Light 原 `ApiTransferProgress` 追加，无新 timer/query。27 个双语源键和两端工程/filters 已定点登记。当前仅源码完成，不 CodeBuddy、不构建、不 GUI、不测试；详情及回执实际验收待用户恢复授权。范围见 [跨段候选树记录](../../docs/action-analyze-planning/api-transfer-tree.md)。
- 本批作者直接派发 CodeBuddy 后，候选树语言审计明确输出通过（32032 源文本），45 个相关双语键齐全、六份工程 XML／路径检查通过。专用无窗口工程首次 C4459 来自测试全局 `scope` 遮蔽，已改 `testScope`；唯一重试因真实 CLI 验收互斥占用退出 2，修正后工程未取得编译及运行通过。固定验证入口 `tools/action_analyze_validation/api_transfer_tree/run_validation.py`；后续由作者在空闲验收批次续接，不重复既有正式 CLI 整批。命名互斥的 `ERROR_ALREADY_EXISTS` 只证明对象存在，必须检查 `WaitForSingleObject(0)`，Python Win32 HANDLE 必须声明指针宽度。
- `memory track`／`memory stream --observe-threads` 复用被动线程记录。`previousThreadObservationRound` 指前一次实际枚举尝试的轮号；首次或本轮没尝试时为空，无字节轮不会更新基准。只读轮询不是实际断点；正式回执与清理情况见[验收回执](../../docs/action-analyze-planning/validation-results.md)。
- 本机 `python -B` 已通过 CodeBuddy 的精确命令授权，正式 CLI 流式观察三轮记录前序 `null / 1 / 2`；同一线程从首次可见到确认退出。该回执早于线程枚举失败的续持修补。修补后失败轮保留原线程句柄以确认其退出，但仍报告 `unknown`，不当作新线程的完整基准。
- 选中内存产品实现使用 `Memory/SelectedMemorySnapshot` 复用 `PassiveDirtyMemory::PollCapture`，成功页才交真实字节；项目独立 `raw-memory` 流通过 `ProjectMemorySnapshot` 写入。集合调查保存必须传完整 `ProcessMemorySnapshotResult` 到 `WriteProcessGroupMemorySnapshot`，不能只提取 `snapshot` 而丢失原读取模式和读前/读后停点。`completeRange` 与 `heldAtBothChecks` 是独立结论，历史上下文不授活控制权；格式见 [selected-memory-v1](../../schemas/action_analyze/selected-memory-v1.md)。各作者直接调用 CodeBuddy 负责适用测试及回执，未有回执不按源码推断运行通过。
- 原生执行证据入口为 `Control/NativeExecutionEvidence`，只从同一活原生所有者的当前精确事件提取 DR0 进入尝试或 Into 单指令完成。`Project/ProjectNativeExecution` 保存独立 `raw-native` 段，历史读取不构造活释放请求；格式见 [native-execution-v1](../../schemas/action_analyze/native-execution-v1.md)。`Detection/NativeTransferAssociation` 仅按已报告目标/线程代次与实际地址范围做一致性候选，两类档案尚无共同启动期时钟证明时不比较 QPC 先后，也不提升来源认证、区域版本或因果归因。
