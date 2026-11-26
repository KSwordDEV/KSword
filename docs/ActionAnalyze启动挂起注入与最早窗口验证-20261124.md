# ActionAnalyze 启动挂起注入与最早窗口验证

日期：2026-11-24。范围：按用户要求验证“刚创建挂起后能否注入，能否覆盖最早窗口”，同时核对既有 API Monitor 复用边界。只创建并操作自有良性 x64／x86 测试进程；未运行样本、未加载驱动、未接触 Explorer／DWM、未改变系统策略。新增独立夹具和设计记录，未实现产品启动期接入。

## 1. 实测结论

**创建期布置可行，不必等到样本 main／业务代码运行后再注入；但现有 API Monitor 注入器不能原样满足最早窗口。** 必须区分“挂起期间布置加载”“目标开始执行引导”“Hook 生效”三个时点。挂起时只是修改自有目标的启动安排；引导 DLL 的 DllMain 和 Hook 安装在首次恢复后由加载器执行，不能说目标从未执行任何用户态指令时 DLL 已完成初始化。

| 路径 | x64 | x86／WOW64 | 真实覆盖 |
| --- | --- | --- | --- |
| CREATE_SUSPENDED 刚返回，不恢复主线程，直接调用生产 injectAgentNative | 失败，299，目标模块枚举未就绪 | 失败，299，该路径诊断字符串为空 | 未加载 Agent；TLS／构造／main 均未执行，随后无监控正常运行证明目标有效 |
| 调试推进到 EXE AddressOfEntryPoint，再显式挂起主线程并完成调试事件／脱离，注入真实 Release Agent | 加载、HooksInstalled、首调采集、HooksRemoved、正常退出通过 | 同左，兼容 WOW64 断点码 0x4000001f | 真实捕获全局构造和 main 首次 CreateFileW；EXE TLS 已执行，不能补采 |
| 原始 CREATE_SUSPENDED 内存中安排首个导入，然后首次恢复，加载最小测试引导 DLL | 引导先于 EXE TLS 安装自有 IAT Hook | 同左 | TLS、全局构造、main 三处首次文件打开均捕获；原文件写入及正常退出保留 |

最终六个场景共 **68 项检查、0 失败、退出0**。其中包含“当前注入器不能用于此时点”的预期负控，不能解释为六种方式全部注入成功。初版夹具错误及中途构建失败的原始日志均保留，见§5。

“最早窗口”本次精确证明到**自有 EXE 的进程附加 TLS 回调之前**。尚未证明先于所有依赖 DLL 的 TLS／DllMain、任意保护目标、不同 Windows 版本，或直接系统调用与任意内存 store 全覆盖。最小测试 Hook 只改自有 EXE 的 CreateFileW IAT，不能推出 inline 引擎或全部 API 已在同一时点可用。

## 2. 夹具、时序与独立判据

历史夹具源码位于本地目录 `tools/api_monitor_startup_validation/`，本地说明为 `tools/api_monitor_startup_validation/README.md`。当时两个 vcxproj 及 filters 登记全部源码，夹具随原本地环境保存。目标包含三个真实标记：EXE DLL_PROCESS_ATTACH TLS、CRT 全局构造、main。各自先递增共享计数，再调用 CreateFileW／WriteFile 写入不同文件。TLS 标记不使用尚未初始化的 CRT 分配。

### 2.1 原始挂起负控

CreateProcess(CREATE_SUSPENDED) 返回后，三阶段计数全0。控制器直接复用 `shared/ApiMonitorInjection.h::injectAgentNative`，不自行替换本地地址绕过模块核验。两架构返回299，此时计数仍全0。生产路径依赖目标系统模块和导出解析；这只是当前路径的时序限制，不是“R3不可能提前布置”的证明。

负控随后只归还原始一次挂起，三阶段及文件写入各执行一次、退出0。没有以坏目标、崩溃或永远挂起制造“无早期行为”。

### 2.2 EXE 入口对照

本端独占 Windows 原生调试事件；在 CREATE_PROCESS 事件读实际映像入口并放一个自有断点。命中后恢复原字节、权限和IP，对主线程持有一个显式 Suspend，完成 ContinueDebugEvent 并确认 detach，再使用生产注入器加载实际 Release Agent。这样没有把 pending debug 事件误当成允许 Agent worker 运行的状态。

入口时共享计数为 `tls=1, constructor=0, main=0`。等待真实 `SessionReady → HooksInstalled`，且构造与 main 仍0，才归还该次显式挂起。真实 Agent 包逐包核对大小、协议版本、PID及会话；收到构造和main文件调用，再请求停止并等 HooksRemoved，最后让自有目标正常退出。未强制卸载 Agent，驻留代码随目标退出释放。

生产 Agent 两架构报告相同定义 SHA256：`67aa8a6476434d7af2564b1a2dc1a8f12aa16fd792cfe55e2ee2b6489cd049d1`，与当前898项源定义一致。每架构观测1000个 coverage item 包不等于1000项 API 全部 Installed；本次只对指定文件调用和安装／停止顺序给出运行结论。

### 2.3 创建期首导入原型

控制器在目标原始主线程仍挂起、三阶段计数均0时，仅修改该自有目标内存中的导入目录，安排匹配位数的测试 DLL 为首导入。目标磁盘 EXE 不变；无 R0 和运行时复制。首导入安排成功时，引导 `DllMain` 也尚未运行。

首次 Resume 后，由加载器加载 CRT-free 小型测试 DLL；其 DllMain 只设置有界的自有 EXE CreateFileW IAT 拦截及共享计数，不在加载器锁内启动完整 Agent、建工作线程、等待管道或调用 LoadLibrary。每次记录后把原参数交给原函数，保留进入调用前 LastError。不会拦截其它进程或其它模块的 IAT。

最终两架构都观察到：

```text
loaded=1 installed=1 beforeTls=1
tls=1 ctor=1 main=1
capturedTls=1 capturedCtor=1 capturedMain=1
tlsWrite=1 ctorWrite=1 mainWrite=1
```

引导 DLL 身份从真实模块列表回读；目标正常退出0。该 DLL 是独立机制夹具，**不是新产品追踪DLL、公共宿主或完整 API Monitor**，未链接生产 HookEngine，未将极小 IAT 成功算成898项 Hook 的早期兼容性验收。

## 3. 现有 API Monitor 复用判断

| 既有部分 | 本轮核对结果 | ActionAnalyze 需要追加的工作 |
| --- | --- | --- |
| 898项定义、生成包装、专用处理器及x86/x64入口身份 | 可继续作为唯一既有采集定义源；本次真实 Agent hash 与源一致 | 逐规则核对实际需要的输入／输出／阶段和字段，不以定义数代表实时覆盖 |
| HookEngine、保守指令重定位、批量安装／恢复、退役代码保留 | 适用于现有安装时点和支持入口，可复用底层 | 早期加载器环境不能直接整套搬入DllMain；需证明可用子集、线程／锁条件及原语义保持 |
| 生产R3注入、位数选择、PID创建身份、租约、broker、管道及覆盖快照 | 入口暂停对照已真实复用；并非只有规划接口 | 新增刚创建挂起时的部署路径、失败恢复和 earlyReady；不是给现有注入器延长超时即可解决 |
| R0辅助注入 | `shared/ApiMonitorR0Injection.h` 已有显式调用；当前同样先找目标LoadLibraryW、驱动等待后回读模块 | 当次授权未覆盖 R0 实测，早于 TLS 或 HookReady 均待验证。[当前验收范围](ActionAnalyze工程开工基线.md#验收范围与运行环境) |
| 子进程自动注入 | HookedCreateProcessW保持原创建flags，原函数返回后再AutoInjectChildIfRequested；broker成功不是子Agent HooksInstalled | 必须补启动前准入和调用者CREATE_SUSPENDED语义；原有快速子进程存在先执行后安装的窗口 |
| 内存写／映射／线程／APC处理器 | NtWriteVirtualMemory等已有参数、原返回和文本详情，当前主要在原调用返回后发包 | 补强类型前／后阶段、请求ID、冻结目标身份、成功范围、regionReady门控和内容版本；不能解析文本就视为完整事实协议 |
| 生命周期与暂停 | Agent worker先发SessionReady，再InstallConfiguredHooks，最后HooksInstalled；Hook撤销与目标调试暂停不是同义 | earlyReady／sourceReady／regionReady分开；目标停止时不能依赖Agent继续运行来ACK或恢复 |

因此是**大量复用、局部改造**，不能回答为“全部原样复用”。本轮没有改动产品 API Monitor、CLI 命令或语言包，也没有把现有 capture 命令称为已实现长程分析会话。

## 4. 产品接入增量与验收门槛

按[双后端设计](ActionAnalyze双后端独立全流程设计.md)追加启动任务，不新增公共TraceHost／追踪DLL／统一runtime。优先审查把早期安全子集放入既有Agent和本端启动协调器的可行性；测试bootstrap不直接打包成产品组件。若既有Agent的CRT／依赖／HookEngine不能满足早期约束，相关计划保持blocked，不能通过启动全功能worker再等待它来掩盖TLS缺口。

1. **创建期布置及身份。** 根目标与获授权子目标在原始挂起内冻结进程／主线程身份、配置、来源与原flags；可回读启动安排。已有目标的附加模式明确记录早期窗口不可追补。R3不以驱动在线作为前置。
2. **早期安全采集。** 限定可在加载器环境运行的接口子集、内存预算、原语义和取消路径。不能用“DLL已映射／DllMain已调用”代替这些接口已经生效。依赖DLL TLS／DllMain、动态导出和绕过IAT分别扩展验证。
3. **覆盖交接。** earlyReady后保留早期记录，完整worker运行后再以真实覆盖表生成sourceReady；指定区域另等regionReady。交接不能卸掉早期Hook再留空窗，也不重算同一次调用；完整Agent部分失败仍保留早期事实和缺口。
4. **调用者挂起语义与恢复。** 调用者原本请求CREATE_SUSPENDED时，准备完成也不擅自运行其主线程。原本未请求挂起的调用，只有满足明确计划的准入条件才归还本会话增加的一次责任；失败／超时按显式策略报告，不暗中扩大放行、不默认结束用户目标。
5. **独立验收。** EXE TLS、初始依赖DLL TLS／DllMain、构造、main、快速子孙、不同架构、缺失导出、模块加载失败、失联与输出背压逐项留证。当前68项只关闭本报告的局部机制条件，不关闭完整启动链或任意死亡恢复。

初始导入、早期安全子集与全功能交接适用于R3／R0各自后端，部署机制不改变Hook运行权限。通过R0加载的用户态Agent仍是R3代码；驱动线程创建成功不等于早期来源Ready。

微软原始资料用于限定机制，而非替代本机证据：

- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)：进程启动／DLL初始化／新线程入口的序列化限制。
- [DLL最佳实践](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)：DllMain加载器锁与最小初始化边界。
- [Microsoft Detours创建期导入](https://github.com/microsoft/Detours/wiki/DetourCreateProcessWithDlls)：公开的挂起创建、内存首导入、恢复后由加载器加载机制。本夹具未引入Detours源码或其rundll32助手。

## 5. 最终证据、纠错及产出

最终运行：`.codex-build-logs/behavior-planning/apimon-startup-20261124-212423-run.log`；元数据同前缀`-metadata.json`；四份构建日志同前缀。OS为Windows10 19045。六个测试PID为25376、23520、28352、21224、5900、24632，均只代表该次已退出测试实例，不作为后续操作目标。

| 文件 | 最终SHA256 |
| --- | --- |
| ApiMonitorStartupValidation.exe | 87B48722EDA138869E2B72CAE5E07AA5374C3DEFE4D2E06D15635C9BE9F4F306 |
| ApiMonitorStartupTarget_x86.exe | B85ADBDC2CCB01B502DD166D3795EBF22436AB3A4EB36C5CE86C36F65BDFD0DB |
| StartupProbeBootstrap_x64.dll | E85A2683BFA3C285C00A08FBB6D7CE217D198FF193B074264E204A143F41EA55 |
| StartupProbeBootstrap_x86.dll | F144D43AA3ED8DA5611FC6913499F997C0B1BEEF3E5A006EB9848F87AE2200F6 |
| 原有 APIMonitor_x64.dll | E5A6A1E8BA34A73AC029F309984F251ECF5079C7B7829A2728279EF85A171A62 |
| 原有 APIMonitor_x86.dll | 11D1CA85B6471F538C627405F605054EF0F856BF94777C7A09F297E79B4749CA |

初版测试的TLS标记错误使用初始化前CRT，造成自有进程0xC0000005；修为纯Win32标记后无监控负控正常。初版漏认WOW64 0x4000001f入口断点，导致自有32位目标未被留在入口；修正后两架构原生对照完成。两者是夹具缺陷，不能归因于产品Agent。初次新增工程编译名称／窄化转换错误、一次后台宿主时限中止以及最终修正记录保留；未对失败日志做通过替换。

正式EXE／测试DLL／PDB位于`Ksword5.1/x64/Release/`，IntDir在`tools/api_monitor_startup_validation/`按项目／平台划分；未复制Qt或Agent运行副本。最终固定`test-artifacts/`目录已移除，无残留测试进程；本次PID配置／stop与标记文件已清理，原有Agent及正式构建产物保留。未构建主程序、未构建／加载驱动、未做GUI或真实样本验收，未提交／推送／发行。
