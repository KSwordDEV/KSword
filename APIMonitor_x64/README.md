# API Monitor 共享采集与 x64 引擎

`api_monitor_definitions.json` 是强类型 API 定义的唯一来源。当前有 641 项；原有 614 项的 ID、模块和导出名保持稳定。
已发布的 ID 不得重编号或复用删除项的 ID。全部定义同时支持 x86/x64；独立32位工程与 ABI 说明见 `../APIMonitor_x86/README.md`。

| ID | 定义范围 | 数量 |
| --- | --- | --- |
| 1–614 | 原有 API | 614 |
| 615–623 | ALPC、线程查询、现代内存映射/分配、APC 和 CoGetObject | 9 |
| 624–634 | 异步结果查询、文件回调、IOCP 和取消 | 11 |
| 635–641 | Winsock 扩展函数 | 7 |

共有 417 个普通生成包装和 224 个具名 C++ 专用处理器。定义数量不代表安装数量；分类关闭、规则排除、导出缺失和入口拒绝安装均按实际结果报告。

## 定义与构建

每项包含 ID、模块、导出名、分类、架构、调用约定、完整参数/返回类型、采集方式、方向、编码、长度关系、成功条件、错误来源及绑定符号。

- 长度关系只引用参数名，指定 `bytes`/`elements` 和是否间接读取；复杂结构及表达式由具名 C++ 处理器负责。
- `wrapper.kind=generated` 生成普通包装并调用 `capture_handler`；`special` 引用专用 `handler`。处理器登记在 `hook/ApiHandlers.json`，正文位于 C++ 源码。定义中的 `handler` 条件表示由对应处理器解释。
- 新类型必须加入生成器 ABI 类型白名单；新处理器必须实现并登记。JSON 不接受 C++ 正文或任意执行表达式。
- `length=null` 不允许无界读取；结构化采集交给具名处理器。普通生成包装的格式化调用受 SEH 保护，不可读数据标记 `capture=unreadable`，并保持原返回值和错误码。
- Python 生成器只使用标准库，编译前校验并输出到 `$(IntDir)generated`，只更新内容变化的文件。重复 ID/导出/符号、未知类型/处理器、错误长度引用、间接读取类型不匹配和引用环使构建失败。
- 绑定表、函数指针声明、普通包装和扩展发现元数据均由 JSON 生成。Release 成功后原样复制到 `Ksword5.1/x64/Release/profiles/api_monitor_definitions.json`，不压缩。

在 x64 MSVC 开发环境中可先手动校验/生成：

```powershell
python tools/api_monitor/generate_definitions.py --definitions APIMonitor_x64/api_monitor_definitions.json --output APIMonitor_x64/APIMonitor_x64/x64/Release/generated
```

使用本机 64 位 MSBuild，`$msbuild` 必须指向 `Bin/amd64/MSBuild.exe`：

```powershell
& $msbuild APIMonitor_x64/APIMonitor_x64.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /m:1 /v:minimal
```

主程序通过非链接项目依赖构建 x64、x86 Agent，主程序检查使用 `tools/Invoke-KSwordBuildCheck.ps1`。可通过 `/p:ApiMonitorPython=...` 指定 Python。

发布 JSON 用于查看/核对，Agent 不从中动态加载 Hook；改定义必须重建。生成代码记录定义 SHA256，事件与快照携带该身份，UI 与发布副本核对并提示缺失/不匹配。更新时同时部署主程序、两个 Agent；已加载旧 DLL 的进程需要重启。

## 自研引擎与覆盖

指令描述及两遍布局支持已识别指令的 RIP 相对寻址、CALL/JMP rel32、短跳转、短/近条件跳转及覆盖区内部目标重定位，识别并保留 ENDBR64。优先邻近 relay 和 5 字节入口补丁；邻近分配失败时仅安全条件允许才用 14 字节。

未知指令、地址宽度覆盖、超范围位移、跳入指令中间、不可读/不可验证入口和跳转桩循环明确拒绝并报告地址/偏移/原因。同址同 detour 的兼容绑定共享入口，重叠或不兼容处理器拒绝覆盖。Raw 使用同一引擎，无法绕过入口失败。

x64 邻近分配优先用 `VirtualAlloc2` 的地址范围约束；不支持该接口时按内存区域跳过占用区，安装取消时停止搜索。`HighestEndingAddress` 为包含式上界，必须是分配粒度边界减一。安装先准备 trampoline，再批量提交入口补丁；一次暂停期间只读取一份线程上下文，恢复线程后不复用 RIP/EIP。短暂的上下文查询失败最多重试三次，已提交的入口不重复写入。移除同样批量恢复入口；失败的页保护保留原值并重试，未确认移除不能释放绑定。

入口检查按可读内存区域复制代码，不逐字节重复查询；活动入口使用有序区间索引，Strong 导出身份使用不可变索引，退役代码仍保留。线程对象可能已退出但仍被枚举：只有句柄已结束时才跳过，存活线程的暂停／上下文失败仍拒绝打补丁；按实际暂停的线程分别恢复。

x86代码按64KiB保留区逐4KiB页提交并独立封为RX，避免每个小stub单独保留导致32位地址空间碎片。已发布／退役代码仍保留；未发布准备页可单独释放。Agent工作线程和Hook补装中的C++异常请求停止并报告AgentFailure，清理成功才报告HooksRemoved；CLI将提前停止计为部分／失败，不虚构足时采集。

API 覆盖标签页按 PID 展示 Strong、Raw、Fake、Dynamic 的已安装、共享入口、分类关闭、等待模块、导出缺失、规则排除、可重试失败、不支持和已移除状态。完整快照带会话身份和修订号，由发送线程直接发送，不占普通事件队列；接收端只应用完整快照，中断/断线保留上次完整内容并标记过期。

共享协议版本 `0x20261003`，Windows 包为 1000 字节。根、子进程与剪贴板保护读端共同更新。会话身份、UI generation 和修订检查拒绝旧会话更新。

正常停止直接关闭服务端管道句柄，保留已经写入但尚未读取的字节；不调用会丢弃未读数据的 `DisconnectNamedPipe`。发送线程有积压时继续发送，不在每批快照后固定等待25ms。最终 `HooksRemoved.snapshotRevision` 表示应收齐的覆盖修订，CLI 排空到 EOF 后核对；旧 Agent 的0表示未知。该字段复用既有布局，不变更包大小。停止时仍未完整收到最终快照会如实标记过期。

## 可选诊断插桩

`core/MonitorDiagnostics` 的全部计数、计时、日志及参数求值受 `KSWORD_APIMON_DIAGNOSTICS` 控制。x64/x86 项目的 `ApiMonitorDiagnostics` 属性默认0；临时研究构建可追加 `/p:ApiMonitorDiagnostics=1`，向 `C:\Windows\Temp\KswordApiMon\profile_<PID>.jsonl` 记录安装、分配、线程上下文、移除及管道阶段。跨用户目标须预先授予该文件的写入权限。日志调用只在其他线程已恢复时执行，暂停窗口内只使用 QPC 和原子计数。

研究后用 `/p:ApiMonitorDiagnostics=0` 重建两个 Agent。源码保留插桩，关闭时不链接诊断函数、文件路径或日志字符串；不要把已经加载诊断 DLL 的旧目标当作最终二进制验证。系统进程试验应在隔离虚拟机中记录 PID、创建身份和恢复结果。

## 异步与扩展

操作以会话、资源身份和 OVERLAPPED 关联，生成唯一操作 ID，分别记录提交、等待、完成和取消请求。取消成功不表示完成；同步结果、IOCP 与后续查询去重。IOCP 关联检查完成键；句柄关闭/复用产生新身份，未完成 OVERLAPPED 重用标记歧义。

跟踪容量 8192。容量不足或 callback thunk 创建失败时报告未跟踪数量，保留原调用与回调。上下文 thunk 保持 x64 参数和 unwind 元数据；停止后继续执行应用回调，旧操作不向新会话发送事件。UDP 来源地址在完成时有界读取，待完成提交不读无效输出。

通过 WSAIoctl 的 SIO_GET_EXTENSION_FUNCTION_POINTER 发现 AcceptEx、ConnectEx、WSARecvMsg、WSASendMsg、TransmitFile、TransmitPackets、GetAcceptExSockaddrs；已知异步完成路径也触发发现。应用持有的指针不替换；重复发现幂等，不同 provider 地址分别保留原函数和上下文，冲突按失败报告。

## 回归与边界

主程序的“WinAPI → API 事件”使用 `QTableView` 和批量值模型，只绘制当前视口，不为每条记录创建六个单元格对象。保留最近最多100万条记录，并以约512 MiB的文本估算预算提前淘汰旧记录；这不是进程总内存上限。筛选在后台匹配，再按有界批次应用结果，普通追加不重置模型。“保持贴底”同时处理旧选中行淘汰和延迟布局，关闭后按事件身份保留阅读位置。导出仍以规范保留窗口及当前筛选条件为准，已移出的记录不在导出范围内。

前端专项回归：`python tools/api_monitor/test_ui_tail.py`、`python tools/api_monitor/test_ui_filter.py`。它们使用真实生产模型、排序代理、异步控制器和 Qt 离屏布局；不注入任何系统进程，也不能替代 DWM 实际场景复测。

在 x64 MSVC 开发环境运行：

```powershell
python tools/api_monitor/run_regressions.py
# 只运行 Agent、CLI 读端及协议测试，不运行 Qt 页面夹具
python tools/api_monitor/run_regressions.py --no-ui
```

回归脚本自动发现 `test_*.py`，覆盖原始 614 项冻结身份、确定性生成/非法定义、元数据/返回契约、可执行机器码重定位、共享/冲突/卸载失败/退役 trampoline、租约、管道分片、丢失计数、覆盖快照/会话切换、Qt 状态/筛选及真实自有文件、IOCP、APC、取消、TCP/UDP 与全部七个扩展路径。UI 使用 offscreen Qt。另在 HostX64/x86 环境执行 `python tools/api_monitor/run_regressions.py --architecture x86`。专项回归还覆盖批量提交/恢复、上下文瞬态失败重试、页保护失败恢复、近地址分配与取消、管道断开丢弃复现、最终修订缺失、半包 EOF 及诊断关闭后的无参数求值/无日志字符串。

可选元数据审计只读本机 SDK 头文件，允许追加原生声明目录：

```powershell
python tools/api_monitor/audit_definition_metadata.py --headers <SDK-Include-directory> --headers <optional-native-declarations-directory>
```

本轮核对 2592 个带方向注解的参数，差异为0；定义含217项简单长度关系。原生 ABI 参考 [phnt 声明](https://github.com/winsiderss/phnt)，构建不下载/依赖该目录；没有引入第三方 Hook 或解码实现。

仍有以下边界：

- 任意 COM 方法、直接系统调用、启动前的调用及无法识别的原生异步完成路径不保证覆盖。
- 未经过本会话 WSAIoctl 发现的扩展地址可能没有 Hook；缺失导出或保守解码器拒绝入口按实际失败显示。
- 启动前建立的 IOCP 关联无法补推；同键同 OVERLAPPED 的手动投递无法与真实内核完成完全区分。
- 已公布的 trampoline、stub、回调上下文与模块保留到进程退出，避免在途调用访问释放内存。8192 限制跟踪槽位，重复会话/回调仍累计退役代码内存，当前没有安全回收算法。
- 本机回归不替代多 Windows 版本、长期压力、严格 CFG/CET、受保护进程和实际界面注入验证。
