# Explorer 复杂环境页面执行探针验证

日期：2026-11-24。用户明确允许本机 Explorer 实验、结束及重启，明确排除 DWM。本轮仅新增独立测试夹具、构建并运行它；不实施产品追踪引擎、不加载 R0、不改变安全策略，也不加载目标 DLL。

**结果：正常执行／主动中止五类场景、79项检查通过；持有 NX 异常时杀控制器的恢复测试失败，并造成旧 Explorer 桌面功能失效，已按授权重启恢复。不能声明整体故障恢复通过或目标绝不受影响。**

前序固定两个自有线程的21项断言见[页面执行探针机制验证](非虚拟化页面执行探针验证-20261124.md)。两份记录的测试环境、异常 owner、通过数分别保存，不相加作为产品验收。

## 1. 谁接收异常

本轮是 Windows 原生调试附加路线：

```text
Explorer 线程执行到临时 NX 页
  → CPU 执行访问异常
  → Windows 暂停目标并把现场作为原生调试事件交给外部控制器
  → ExplorerProbeValidation.exe --child 决定保护恢复、TF 推进及继续方式
  → ContinueDebugEvent 后目标才继续相应流程
```

异常不是在父监护进程中自然执行，也不要求 Explorer 安装我们的 VEH。父进程负责刺激／独立结果回读／监护，子进程是唯一 Wait/Continue 所有者。未知异常按原分发语义转交，不能把任意 AV 当成自有探针。

前序夹具则用自有目标内 VEH；未来默认普通 R0 后端需要独立实现并验证异常接入、线程门控和恢复责任。三者不能混为已经接通的一条产品链。

## 2. 真实目标与构建

- 系统：Windows 10 专业工作站版，10.0.19045，x64。
- 原目标：Explorer PID 4000，创建时间 FILETIME `134400375726811023`，起始目录有209–211线程；用户会话1。
- 恢复后目标：Explorer PID 8120，创建时间 FILETIME `134400399703068732`；最终运行附加时165线程，新建计算线程时峰值169。
- 真实入口：`USER32.dll!DispatchMessageW`，RVA `0xe1e0`，远程地址 `0x7ffefe58e1e0`。定位所属模块后比较本地／远程32字节，不靠跨进程绝对地址相同作假设。
- 历史本地夹具工程为 `tools/explorer_probe_validation/ExplorerProbeValidation.vcxproj`，本地说明为 `tools/explorer_probe_validation/README.md`。当时源码均登记在工程及 filters 中。这两个路径用于定位原测试资料，夹具源码随原本地环境保存。
- 固定 IntDir：`tools/explorer_probe_validation/x64/Release/`；正式 OutDir：`Ksword5.1/x64/Release/`。
- 使用 BelowNormal 构建宿主、amd64 MSBuild、MSVC 14.44.35207 HostX64、Release x64、`/W4 /WX`，构建通过。主程序／驱动未改，未构建它们。
- 最终测试 EXE SHA-256：`720120047E05B432D09B995060A5829F1618F32C757E8A67B7DF27AFC9F9D608`。

## 3. 最终正常路径的实测结果

最终日志前缀 `.codex-build-logs/behavior-planning/explorer-probe-20261124-202734-`，分别保留 `build.log`、`run.log`、`metadata.json`。运行退出码0、79行 PASS、0行 FAIL、五项 CASE_RESULT=PASS，最后 `RESULT=PASS failures=0`。该次明确输出 NOT_RUN guardian-at-nx，不包括已知失败项。

| 场景 | 操作与独立证据 | 实测结果 |
| --- | --- | --- |
| 既有线程／真实系统映像页 | 向 Explorer 任务栏投递 WM_NULL；NX 覆盖 DispatchMessageW 所在共享用途映像页，不改系统代码字节 | 既有 TID 12884 命中8次；多个真实页内入口，510次 TF、8次页外重设防；字节前后完全相同 |
| 私有代码版本1 | 分配目标内自有两页、真实写入29字节无害计算函数、读回、恢复 RX、FlushInstructionCache；四个新线程执行 | 4个真实 CREATE_THREAD，4个不同 TID 各1次 NX、各自计算返回 `0x13570001`；48次 TF、4次重设防 |
| 同映射版本2 | 同一分配更改立即数；完整字节比较证明版本确实变化，再运行四线程 | 4个新线程各1次 NX，全部返回 `0x24680002`；48次 TF、4次重设防 |
| 跨页取指 | 只给第二页设置 NX；10字节指令从第一页末尾开始 | 4次均为 RIP `0x15d0ffd`、fault VA `0x15d1000`；12次 TF、4次重设防，4个返回值正确 |
| 页内主动中止 | 首次 TF 后 RIP 仍在区域内，主动撤探针而非完成页外推进 | 1次 NX、1次 TF；恢复原 RX、清除并读回自有 TF、归还本次挂起计数后，线程返回 `0x24680002` |

版本指纹是诊断 FNV-1a64，不作为密码学身份：完整两页版本1 `9da87938f7ee0ceb`、版本2 `f683017113e4b16e`；测试还直接比较完整字节而非仅比较指纹。已知写入者是测试父进程，写入与执行串行安排，不代表自动发现任意未知写入者或传播。

每例均核对原保护恢复、自己的TF／挂起责任清退、调试脱离、同一目标创建时间不变、目标存活和 WM_NULL 响应。TF 在停点中清除后读回；每次 Resume 的返回计数必须等于对应 Suspend 之前的计数加1。不是仅看“程序没有退出”。

最长一次受控推进周期分别为39.807、26.559、36.400、39.260、28.449毫秒。该计时从命中事件开始建立显式停止账，到检测推进结束／中止为止，不覆盖所有释放／继续／消息延迟；不能当成完整冻结时长、P99或性能承诺。它已显示逐线程控制和 TF 有可见扰动，不声称120Hz无感。

## 4. 失败和修正分别保留

### 4.1 线程快照不是活线程屏障

日志 `explorer-probe-20261124-201450-run.log` 在首个命中后因线程集合不匹配拒绝恢复 X；`202424` 版本进一步记录快照中缺失目录的线程，Suspend 返回5。随后用真实 EXIT_THREAD 及创建时间核对，确认 Toolhelp 仍可列出已经交付退出事件的对象。

修正保留退出身份墓碑，以真实退出事件排除同一对象的迟留条目；新的同TID对象不能沿用。最终 `image-natural` 中实际出现一次 `SNAPSHOT_AFTER_EXIT_EVENT tid=24632`，其余快照新增／步进中新增分支计数均为0。未收到创建事件的真活线程不能仅凭快照当作已通过执行门控。

### 4.2 事件句柄错误

`201559` 版本的前五类通过，监护例在读取线程现场时报无效句柄6，脱离时报5。检查发现控制器提前关闭 Windows 管理的原始调试事件线程／进程句柄，系统后续自动关闭可能命中已复用的句柄值。

修正为仅关闭自有 DuplicateHandle 副本；原始事件句柄由 Windows 按事件生命周期关闭。后续正常回归通过，不抹去旧日志。

### 4.3 尚未解决：异常未继续时杀控制器

日志 `.codex-build-logs/behavior-planning/explorer-probe-20261124-202540-run.log`：修正句柄后，前五类再次通过，最后运行 `guardian-at-nx`。

1. 目标线程 TID 16952 已命中 NX，控制器仍持有原生异常事件。
2. 父监护先恢复原 RX；此时尚无自有 TF 或显式线程挂起。
3. `DebugSetProcessKillOnExit(FALSE)` 已成功设置；父进程以退出码77结束子控制器。
4. 独立线程句柄读回 `0x5bb`，与应得 `0x24680002` 不同；原任务栏 HWND 失效，SendMessageTimeout 返回错误1400。
5. 进程身份查询当时仍能看到旧 PID，不等于桌面功能正常。没有转储，不把返回值擅解成特定NTSTATUS或声称已证明Explorer自行进程崩溃。

**页权限恢复不等于待处理异常已完成。** 关闭 kill-on-exit 也不能替代实际 Continue／Detach。父监护不拥有该原生会话的 Wait/Continue，不能假定子进程死后可直接接管。将“先正常继续并脱离，再杀已空闲控制器”改成通过，是更换测试条件，不能关闭此失败。

G05／A4／A8需要独立的异常完成责任：保护恢复、TF／计数归还、待处理事件继续结果、调试脱离分别记账；owner先死亡时仍须证明相应后端可以完成，否则能力保持不可用／有明确限制。普通R0的file cleanup／owner-death恢复也必须实测，不从原生模式结果推定可用。

该负控默认禁用，只有显式 `-IncludeControllerDeathProbe` 才会运行，并在夹具文档说明已知破坏结果。本轮不再次触发。

## 5. 桌面恢复与清理

- 在用户既有授权内，先核对旧 PID 4000 与创建时间，再结束该唯一 Explorer，启动系统 Explorer；新 PID 8120。
- 恢复核对：Shell_TrayWnd HWND `132140`，实际 owner PID 8120，WM_NULL 成功响应。最终正常回归后仍为同一个新 Explorer，正常响应。
- DWM PID 3040／会话1及22256／会话2与开始时一致；代码不对DWM打开控制句柄、结束、重启、设防或附加。
- `201559` 失败后保留的8 KiB已在独立确认所有测试线程退出后，按精确进程／映射／字节校验释放。`202540` 的8 KiB随旧 Explorer 结束释放。
- 最终正常回归的8 KiB显式 `VirtualFreeEx` 成功；无残留 ExplorerProbeValidation 进程，无测试配置、临时运行副本或Qt复制。保留固定 IntDir、正式测试EXE/PDB和文本证据，未删除其它工作成果。
- 诊断恢复记录：`.codex-build-logs/behavior-planning/explorer-probe-recovery-20261124.json`。

## 6. 覆盖边界

这次宿主确实是本机多线程 Explorer，原有系统代码路径、页内多入口、真实写入、四线程执行及跨页现场均已运行；新写入的计算函数仍是受控短函数，不等于真实复杂载荷。

尚未覆盖普通R0、新线程在恢复X期间的实际创建竞争（本轮 `creates_during_step=0`）、目标／外部DR混合、未知异常中断、长循环／锁依赖、共享映射别名、JIT、自修改并发、自动下一跳、新区域发现、完整来源归因、多OS、长程稳定性及异常任意时刻控制器死亡。异常恢复失败明确存在，不把这份记录称为完整脏内存追踪产品验收。

资料：[WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)、[ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent)。前者说明事件句柄生命周期，后者说明异常继续语义；实测结果仍以各版本日志为准。
