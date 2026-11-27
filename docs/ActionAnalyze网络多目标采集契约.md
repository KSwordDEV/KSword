# ActionAnalyze 同采样网络成员契约

`NetworkTrafficSession` 在已有项目写租约中复用网络流量监控服务。根目标与后来明确接管的目标共用一个 `TrafficMonitorService` 或一个既有 WFP ring reader、同一邮箱、来源代次、游标和串行归档路径。追加成员不创建采样、抓包服务、采集线程或第二 writer。

## 接管入口

`NetworkTrafficTargetReceipt NetworkTrafficSession::AddTarget(std::uint32_t pid, std::uint64_t creationFileTime)` 由持有项目写租约的原 worker 同步调用。调用顺序为：启动网络会话；接管方核验目标；在对外宣告该目标 Ready 或发送 ACK 前调用 `AddTarget`；检查返回的 `status` 和 `accepted`；最后发布接管结果。不能把该调用放到独立 Agent 线程中直接访问项目所有者。

`AddTarget` 打开并持有具有查询及同步权限的进程对象，从同一句柄读取创建 FILETIME，核验请求身份及存活状态，再将对象纳入采集窗口。`accepted=true` 表示网络成员准入成功；来源是否真正就绪仍以 `Receipt().sourceReady` 表示，两者不可混用。

同一 PID 和创建时间的重复请求保留首次窗口，并以 `alreadyPresent` 表示复用。创建时间不符、对象已退出、打开或查询失败、会话未启动、已经停止或取消均返回本次请求的独立错误。失败不替换其它成员，不覆盖主会话归档错误。需要简易成功位的接管代码可使用 `AppendTarget`；它调用同一准入实现，并在原会话诊断中保留追加失败原因。

## 生命周期及边界

成员目录只追加，不按 PID 覆盖旧对象。原生报文入队时固定匹配窗口下标，写档前再次以该窗口核验；后来出现的同 PID 实例不会重新解释已经排队的包。每个成员保留准入创建身份、开始时刻、结束时刻及结束原因，直到来源排空后统一释放真实对象。

根退出只关闭根的窗口。已有其它成员存活时继续使用原来源和原时钟，不重新启动抓包。默认在全部成员退出后请求停止；`keepAliveForAppendedTargets=true` 允许协调者在暂时没有活动成员、但仍有在途接管时继续保留来源，由协调者在整链结束时显式 `Close`。取消、原有时长和来源错误仍对整会话生效。

WFP 使用原始 FILETIME；Raw Socket 保留来源毫秒精度。无法分辨准入或退出边界的同毫秒报文不补造精确时间；边界桶允许保守舍弃。对象退出从已持有句柄读回真实结束时刻；退出时间不可读或等待失败以成员结束原因明确区分，不把观察时刻说成已知真实退出时刻。

`Close` 冻结整会话截止，对各窗口取适用截止；Raw Socket 停止并 join 原服务后排空原邮箱，WFP 沿原固定水位进行有界排空。任何来源尾包仍必须落在当初匹配成员的窗口及整会话范围内。来源从未启动成功时不创建伪造网络段。

## 归档兼容与证据强度

正文继续使用既有 `ksword.actionAnalyze.network.v1`，写入原 sample 的 `raw-network`，由 `checkpoints-network` 发布检查点。旧单根 `requestedPid/requestedCreation` 保留为最初请求的目录身份；它们不再代表段内每条包必须属于该根，也不授予强实例归属。

`ProjectNetworkCheckpoint::targetWindows` 对应 v1 检查点的可选 `targetWindows` 数组，保存本段已经准入过的全部成员窗口快照。旧档缺少该字段仍可读，旧调用方省略 `CommitNetworkEvidence` 的末尾窗口参数仍可写。读端恢复并校验窗口声明，但不会凭该声明改写包的进程身份字段。

端口表补全仍为 `endpoint-table-hint`；WFP 原生 PID 仍为 `native-pid-hint`。即使成员准入时持有强身份对象，原包 `processCreatedUtc100ns` 仍不补填，`processObjectId` 仍为空。成员窗口证明采集器选择了哪个真实对象作为筛选范围，不能证明每条弱 PID 报文的事件时强归属；HTTPS 解密能力也未因此增加。

## 本次交付边界

网络层及三端共用采集入口已接线：`ApiTransferHandoff::Prepare` 核验目标强实例和私有范围后，在成功 ACK 前经 `TargetDiscovered` 回调调用原网络会话的 `AppendTarget`；重复准入复用窗口。`CaptureCooperativeApi` 在自动接管模式设置 `keepAliveForAppendedTargets`，根退出后由原 API 整链生命周期决定网络关闭。追加失败保留网络诊断，并使最终网络状态进入部分结果，不撤销原生接管及其恢复责任。

同一范围的先前命中处于内部 TF 推进、页暂时恢复执行时，后续交接请求继续获得 Pending，仍留在原 Hook 的同步屏障内；原 owner 重设 NX 后再回读保护并发出成功 ACK。仅有历史范围登记、已经完成的推进或无 owner 的可执行页仍不能取得成功 ACK；不为网络另开一套暂停或推进路径。

Qt／Light 原字段详情沿 `ApiCaptureNetworkJson` 展示同一 `targets` 快照，CLI `network-read` 返回该检查点的 `targetWindows`，原 CLI 帮助与双语说明同步。界面入口仍为“监控 → 行为分析 → 项目与采样”的原 API 参数执行页，复用 `ParameterWorkspace`／Win32 对应结构及原字段详情，仅更新网络范围说明；参考原 API 采集、写入停点及共享参数框架，不新增页面、布局或后台任务。构建、运行、抓包覆盖率、PID 复用、根先退出、成员尾包及跨端历史重开的实证尚未完成；GUI 实测按用户要求继续后置。本次源码作者不生成测试夹具或验收回执。
