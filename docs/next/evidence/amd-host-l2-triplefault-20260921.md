# 实体宿主 general 模式下 VMware 来宾三重故障

结论：完整 L2 操作系统启动测试失败，根因尚未确定。2026-09-21 18:50:41.422（UTC+8），VMware 明确报告来宾 `vcpu-0 Triple fault`。宿主 Windows、VMware VMX 进程及 KSword 32 核常驻在随后采集时仍存活。不能将驱动自身无故障标志解读为嵌套执行正确。

## 拓扑和时间线

- 本轮为实体机 KSword L0 → 宿主 Windows / VMware Workstation 16.2.5 L1 → KSword-AMD-Lab L2。
- 克隆配置：EFI、硬件版本19、单插槽8 vCPU、8 GiB、`vhv.enable=TRUE`。额外暴露 SVM 是配置事实，并非已证实的故障原因。
- 18:50:23：VMware 使用 CPL0 monitor 启动。
- 18:50:26.476–477：8 个 vCPU 均记录 `AMD-V enabled`。
- 18:50:26.629：来宾输出 EFI ROM 版本。
- 18:50:41.422：vcpu-0 三重故障，显示重启/关闭提示。
- 本次日志未出现 Windows Boot Manager 或 firmware transitioned to runtime 标记。较早的 `vmware-0.log` 两者均存在。因此仅能确认本次到达 EFI，不能确认进入 Windows；缺少标记本身不能精确定位故障指令。
- 18:53:14：只读 `status` / `metrics` 均成功。generation=11、powerGeneration=0，32/32 CPU 常驻，state=0x00404013，lastStatus=0，累计退出850089。逐核 stage=4、failureStatus=0。

## 保存的现场

原始文件保存在仓库忽略目录 `artifacts/vmware-triplefault-20260921-185309/`，其中 `manifest.json` 记录采集文件的 SHA256 和大小。采集时仓库 HEAD 为 `39c683fb75633fd6a90b46bf15dd4d63187dd693`；此值不等于运行映像身份绑定。

| 文件 | 大小（字节） | SHA256 |
|---|---:|---|
| vmware.log | 183962 | 15854F4FE1EB962FBB2CD97E31F3DA5B5B23F96585A3AB28D649106B5AD7AB4B |
| status.json | 11698 | 154C13FEDD35FA730F7E51D98A943849EB3201DBF7EC8C63E5C109BA1FB0626D |
| metrics.json | 52440 | 7B8ECD6F1E3908629D1249BA34515DE8F430DE65EF5449E19FD55573FB758A2F |
| vmware-vmx-current.dmp | 307952 | ECE1D200749D980C24D37C9D2F64FBDF4D8718D93777FCCBC85B105A327BECD8 |
| guest-memory.vmem | 8589934592 | 8CFD0F57C1330A6A1BB41FBBF08126F0AC3C94BAB8A53BFD21705E1BCAD3F754 |

另保存 VMX 配置、历史正常启动日志、mksSandbox 日志、SCM/宿主信息、采集脚本、命令前后日志及转储分析。原 VM 目录中的9月18日转储属于旧事故，不用于本次归因。

VMX PID23184 的新转储通过 CDB 非侵入附加 `-pv`、`.dump /m`、`qd` 取得，采集成功且离线可打开。它是18:56:10的用户态进程快照，只含寄存器、线程栈和部分内存；显示的 `80000007 Wake debugger` 是采集事件，不是来宾三重故障。主线程位于消息等待路径，无法据此恢复 L2 第一条异常。没有 VMware 私有符号，VMX 帧仅能定位到模块偏移。

8 GiB VMEM 通过共享只读流复制，保存的是后续时点的内存文件，不是包含 CPU/设备上下文的原子虚拟机快照。不能把它当成 Windows 内核转储或独立完整恢复点。所有原始内存/转储只保留本地，不纳入 Git。

## 尚缺的定位证据

当前 metrics 的 `general.exitCode` 来自 `GeneralLastHardwareExit`，是最新一次退出；普通 ring 已存在大量覆盖。当前查询无法还原18:50:41对应的完整异常链，也没有故障时的 VMCB12/VMCB02 配对快照。后续正常 CPUID/MSR 退出和32核 ACTIVE 状态不能否定先前 L2 错误。

下次定位需要保留首次异常/SHUTDOWN 的 RIP、CR2/CR3、段和描述符表、EXITCODE/EXITINFO、EVENTINJ/EXITINTINFO，以及对应 VMCB12/VMCB02 和事件反射决策；这些记录应在后续普通退出后仍可读取。应先补故障现场保留，再在受控环境做最小复测，不能仅凭三重故障猜测并修改中断/NPT 语义。

本轮没有执行重启、VM reset/power-off、驱动 stop/teardown、重新加载或重新激活；未修改运行中配置或签名。此前签名验证结果与本次崩溃归因相互独立。完整 L2 OS / 内层多核并发均未通过，原有 general 常驻启停 smoke 结果仍仅覆盖原测试范围。
