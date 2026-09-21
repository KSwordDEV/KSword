# AMD SVM/NPT 实验工具

当前是待硬件验收的实验实现。编译、模拟测试和克隆完成不等于 SVM 已跑通。
逐项进度与缺失硬件证据见 [状态记录](../../docs/next/ksword-amd-lab-status.md)。
宿主固定 Windows 10 / VMware Workstation 16.2.5，不升级系统或更换硬件。

宿主 CET 候选支持用户态 `XSS.CET_U`，使用 XSAVES/XRSTORS 保存当前线程状态；非零 `S_CET`（内核 CET 控制）仍明确拒绝，未实现内核影子栈返回链。构建后先用 `Test-HostSvmAdmission.ps1` 仅装载/查询/卸载核验准入；`backendStatus=0` 仅表示准入成功，不是 VMRUN 或常驻通过。该候选保持 HVM v6，不能把新 CLI 与旧 v5 来宾驱动混用。

实体机准入通过后，管理员运行 `Test-HostSvmSelfTest.ps1`，其固定流程是装载→prepare→逐CPU串行self-test→status/metrics核验→teardown→卸载。SYS/CLI须匹配已归档准入哈希；每条命令执行前落盘日志，核对逐核集合、代次、CPUID退出和资源释放。不执行resident或内层VM；物理宿主32逻辑处理器即检查32个串行往返，不是32核并发常驻。若执行不完整或无法证明释放，保留驱动与资源并报告证据目录，不将CLI终止当作回滚成功。`Test-HostSelfTestEvidence.ps1`只运行证据验证器的模拟测试。

逐核自检通过后，可显式加 `-ResidentSeconds 5`：自检之后新增全核同时resident→等待5秒→stop，再释放/卸载；省略参数仍只执行短自检。核对活动与停止的每核集合/阶段、卸载保护及等待期间代次不变；一旦尝试resident，异常路径也请求stop，无法证实完整退出时保留资源。此短测不等于负载或内层VM兼容测试。运行在实体机，请先保存工作。

执行宿主装载/卸载测试前须完全退出主程序（含托盘），避免设备句柄阻止卸载。SCM的`STOP_PENDING`不是停止完成；自检脚本在入口与卸载后最多等待30秒，仍未停止就报告失败，不重新启动、不强制卸载。`Running`不会被自动停止。
进入实验前保存工作；两份宿主脚本均需要**管理员 Windows PowerShell 5.1**。

## 两个宿主入口

```powershell
powershell.exe -NoProfile -File tools/hvm_lab/Enter-AmdLab.ps1 -Check
powershell.exe -NoProfile -File tools/hvm_lab/Enter-AmdLab.ps1 -NoRestart
# 核对 PendingReboot 后自行正常重启；省略 -NoRestart 会请求正常重启，不强制关闭应用。

powershell.exe -NoProfile -File tools/hvm_lab/Restore-NormalBoot.ps1 -NoRestart
# 再次正常重启，随后检查：
powershell.exe -NoProfile -File tools/hvm_lab/Restore-NormalBoot.ps1 -Check
```

首次基线、BCD 导出、实验启动项所有权、待执行事务和核验结果保存在
`%ProgramData%/KSwordARK/amd-lab/`。只有管理员/SYSTEM 可写；不接受普通用户预置的状态目录。
默认启动项及原 loader 的元素不改动，只为复制出的实验项设置 Hypervisor/VSM Off，使用一次性 bootsequence。
恢复按保存的原始 GUID 安排下次启动，不导入整份 BCD。
BitLocker 保护开启、UEFI 锁/策略导致 VBS 继续运行、外部启动配置变化或核验失败均明确拒绝。
不会卸载宿主 Windows 功能、修改宿主 Secure Boot 或移除加密保护器。

`PendingReboot` 只代表待重启；`LabHostReady` 还必须补上 VMware 日志的原生模式及来宾 SVM 自检证据。
启动任务仅核验并写结果，不修改启动配置。若任务未执行，手工 `-Check` 仍可查询实际状态。
脚本无法保证策略、固件或硬件始终允许实验；Blocked/VerificationFailed 必须先处理，不能当成功。

## 独立虚拟机

本次已创建完整克隆，实际位置记录在 `host.local.json`，VM 目录内有 `lab-ownership.json`。
该本机配置文件不入库。工具按参数支持其他磁盘位置：

```powershell
Import-Module ./tools/hvm_lab/VmwareLab.psm1
New-KswordAmdLabVM -SourceVmx $sourceVmx -DestinationDirectory $newLabDirectory
Set-KswordAmdLabCpu -Vmx $labVmx -CpuCount 1
Get-KswordVmwareEvidence -Vmx $labVmx | ConvertTo-Json -Depth 8
```

固定硬件版本 19、单插槽、8 GiB、`vhv.enable=TRUE`、COM1 命名管道
`\\.\pipe\KSword-AMD-Lab`。1 → 2 → 4 → 8 vCPU，每次正常关机后改核数。
克隆清除了 suspend checkpoint 引用，不会恢复源 VM 的挂起内存。
首次冷启动仍需检查文件系统与实际 Windows 版本，再正常关机建立 `clean-win10-kd` 快照。
未完成这些检查前，`guestOsVerified` 和 `cleanShutdownSnapshot` 保持 false。
不要把 VMX 的 `guestOS=windows9-64` 当作来宾 OS 实测。

来宾内运行 `Prepare-Guest.ps1 -CloneManifest <复制来的 lab-ownership.json>` 先检查，
再加 `-Configure` 设置来宾测试签名、COM1 KD、Hypervisor/VSM Off、VBS 本地配置和内核转储。
该脚本不自动重启，不导入证书；Secure Boot 开启时先停下，在关闭的**克隆 VM**上调整虚拟固件设置。
存在来宾组策略/UEFI 锁时仍以重启后实际 VBS 状态为准。

已挂载 `KSwordLab` 共享目录时，可在克隆的**管理员 Windows PowerShell**运行：

```powershell
$share='\\vmware-host\Shared Folders\KSwordLab'
& "$share\Bootstrap-GuestLab.ps1" -Mode Inspect
# 只有 Inspect 显示 secureBoot=false 后：
& "$share\Bootstrap-GuestLab.ps1" -Mode Configure
```

`Configure` 将匹配的候选文件复制到克隆的 `C:\KSwordLab\candidate`，仅在克隆中导入实验公钥，
然后配置 KD、测试签名、VBS/Hyper-V Off 和转储。它不重启，也不作用于宿主或源 VM。

克隆重启并确认 KD 已连接后，在同一管理员 PowerShell 运行 `Load-GuestCandidate.ps1`。
它复核候选哈希及来宾证书信任，并用与主程序相同的 SCM 需求启动方式加载 `KswordARK`；
成功时才运行一次只读 `hvm_ctl --json status`。加载失败时保留服务与证据，不自动卸载或继续 HVM 命令。

## 调试闭环

隔离候选使用 `Sign-LabCandidate.ps1 -CandidateDirectory <候选目录>` 签名。
只在克隆中导入随候选提供的 `AMD-Lab-TestSigning.cer` 到 LocalMachine Root/TrustedPublisher；
不要给宿主导入该信任，也不要复制私钥。签名写入、证书信任、内核加载是三个独立状态。
`python tools/hvm_lab/collect_identity.py --candidate <候选目录> --vmx <克隆VMX>`
会核对 SYS/PDB GUID/Age 并生成带源码/产物/日志哈希的 identity.json；硬件结果保持 NotRun，需另行附上实测证据。

1. 宿主确认 LabHostReady，再冷启动克隆。保存当次 `vmware.log`，要求 `Monitor Mode: CPL0`，不能是 ULM/WHP。
2. 宿主连接：`windbg.exe -k com:pipe,port=\\.\pipe\KSword-AMD-Lab,resets=0,reconnect`。
3. 在来宾安装本次测试签名 SYS；把对应 PDB 放入宿主符号目录。记录 `lmvm KswordARK` 与 SYS/PDB SHA256。
4. 先证明普通驱动断点可命中、来宾转储链可用，再执行 SVM。不要直接在 SVM host 退出循环打普通来宾 KD 断点。
5. `hvm_ctl --json status` 检查 backend=2、SVM/NPT/NRIP、有效 MSR 证据与外层 VMware；然后 `prepare → self-test → resident → stop → teardown`。
6. 首次 VMRUN 失败，查 VMCB 字段/对齐/保留位/ASID/EFER/CR；首次退出崩溃，查 GPR/RAX、GS、host 栈、XSTATE 与返回链。
7. 多核卡死，比较每 CPU Stage、独立 VMCB/HSAVE/stack、group:number、IPI 参与集合；检查 GIF/IF 与 NMI 边界。
8. 内存错误查完整 NPT 覆盖、AMD PAT/MTRR 合成与 TLB；停止后延迟故障查残留 Active、提前释放和 MSR/CR3 恢复。
9. 卡死先 break-in，保存 `~* k`、`!irql`、`!analyze -v`（有转储时）、`lmvm KswordARK`。无法 break-in 时保留 VMware 日志与磁盘日志；不要补造缺失 CPU 栈。

逐核 ring 位于 `KSW_SVM_STATE.Cpus[n].Trace`，用 `dt` 按匹配 PDB 解析。
每条记录有 sequence，奇数/变化中的记录不可信。`metrics` 输出最新一致记录与覆盖数；完整最近 64 条应从 KD/转储读取。
稀疏 AMD EXITCODE 保留 64 位，不能用 Intel 的 96 项数组解释。
未知退出采用保留 ring 后 bugcheck 的故障路径；尚无真实转储证明 host 故障时 KD 一定可达。

### 可控失败点

默认全部未启用。仅在 KD 中设置，且只能在停止/准备边界配置：

```text
ed KswordARK!g_KswSvmFaultCpu 0
ed KswordARK!g_KswSvmFaultStage 3
ed KswordARK!g_KswSvmFaultArmed 1
```

stage 1：该核完整资源分配后失败；2：该核进入前失败；3：该核 guest continuation 返回后失败。
arm 匹配时原子清零，每次只触发一次。对每个目标 CPU 轮流测试。
stage 3 不清除 Active，必须由真实全核 stop 收回已进入 CPU。
记录原失败、逐核停止、卸载保护与资源释放；超时不是回滚完成。

## 采集与压力

先把 hvm_ctl、驱动及符号身份清单放到来宾。直接在来宾执行：

```powershell
./Invoke-GuestAcceptance.ps1 -Ctl C:/KSwordLab/hvm_ctl.exe -EvidenceDirectory C:/KSwordLab/run-1cpu -Vcpu 1 -Cycles 20
# 2 核 20 次；4/8 核分别 100 次。最终 8 核另执行：
./Invoke-GuestAcceptance.ps1 -Ctl C:/KSwordLab/hvm_ctl.exe -EvidenceDirectory C:/KSwordLab/run-8cpu -Vcpu 8 -Cycles 100 -SoakSeconds 7200
```

每条控制调用前先落盘。超时保留 CLI 进程与 RollbackUnproven，停止继续下发命令。
首轮常驻额外等待 `-IdleSeconds`（默认 10 秒），记录等待前后状态并重新核验全核集合，覆盖中断被屏蔽后空闲无法唤醒的问题；持续负载不能代替此项。该等待只证明计时器唤醒与常驻状态连续，不能证明每个 CPU 都实际执行了 HLT。
压力工作线程逐核固定亲和性，每轮验证内存、定期文件读回及本机 UDP，要求每核持续前进。
本机 UDP 不替代虚拟网卡到另一端的网络 I/O 测试；还需单独保存这项证据。
接受外层 VMware 身份并不等于 KSword 支持内层 SVM。

`VmwareLab.psm1` 的 `Invoke-KswordLabGuest` 接受已认证的网络 PSSession，复制脚本及其伴随负载，再收回证据。
凭据只通过 `Get-Credential`/`New-PSSession -Credential` 传递；不使用 vmrun 的明文用户名/密码参数，也不依赖 PowerShell Direct。
来宾 WinRM 初始配置与连接尚需在该克隆中验证。

## 无硬件测试与实现边界

宿主只读准入诊断：管理员执行 `Test-HostSvmAdmission.ps1`，默认使用仓库 Release SYS 和匹配的 hvm_ctl。
该脚本仅装载→status→卸载，将启动 ID、文件哈希、SCM 输出和原始查询保存到 artifacts/host-admission-*；不执行 prepare/self-test/resident。
HVM v6 输出明确拒绝原因及带有效位的 CR4/XCR0/XSS；即使驱动装载成功，准入失败也不得记为 SVM 执行通过。

嵌套 SVM 第二阶段候选使用独立 `guest-bootstrap/nested-probe` 目录，保留上一阶段候选。
来宾冷启动、旧驱动 STOPPED 后，管理员运行该目录的 `Start-GuestNestedProbe.ps1`（默认 1 vCPU/1 次）。
脚本复制匹配 SYS/PDB/CLI 到独立目录，加载并执行 `prepare-svm-probe → self-test-svm-nested → metrics → teardown`，自动回传证据。
`-Vcpu 2/4/8 -Cycles N` 只应在前一阶段硬件结果已确认后使用。
metrics v4 的逐核 `nestedProbe` 是固定内层指令探针，不能当作任意内层操作系统或持续多核运行的验收。
实现范围见 `docs/next/amd-nested-svm-implementation.md`。

```powershell
cmd /c tools/hvm_lab/build-tests.cmd
powershell.exe -NoProfile -File tools/hvm_lab/Test-BootPolicy.ps1
powershell.exe -NoProfile -File tools/hvm_lab/Test-BootTransactions.ps1
powershell.exe -NoProfile -File tools/hvm_lab/Test-BcdBinding.ps1
cmd /c tools/hvm_ctl/build.cmd
python tools/hvm_ctl/test_command_parity.py
cmd /c tools/hvm_ctl/build-tests.cmd
powershell.exe -NoProfile -File tools/hvm_lab/Test-GuestLoader.ps1
powershell.exe -NoProfile -File tools/hvm_lab/Test-AcceptanceCapture.ps1
```

`Load-GuestCandidate.ps1` 可在同一候选已经运行时重试，只查询该服务；活动的其它驱动路径仍拒绝修改。
从共享目录运行时，脚本先核对本地 SYS/PDB 与共享清单相同，再更新本地 hvm_ctl/identity（不替换 SYS/PDB）。
证据目录包含之前的身份清单、SCM 查询和分离的 status JSON/stderr。JSON 文本统一使用 ASCII Unicode escape，
防止 Windows PowerShell 5.1 的 OEM/ANSI 解码损坏 UTF-8 及相邻引号；上述测试使用实际 query 格式化代码的模拟响应，不能替代 SVM 硬件验证。

首版要求 NRIP，未实现安全的任意来宾指令读取/长度回退；不支持 >48 位物理地址、活动 CET/LA57/PKS/UINTR 或非零 XSS。
BCD 绑定回归使用真实 System.Management 嵌入对象及本机 WMI 类元数据，不调用 BCD 读写方法；不能替代管理员环境的启动往返。
XSAVE/XRSTOR 使用 XCR0 的标准格式；启动前重新核对，XSETBV 和相关 MSR 写入受控。
NPT 使用 AMD 页表位，完整覆盖 CPUID 地址范围；同一遍历先精确计算包含 RAM 边界拆分的页表成本，超过 64 MiB 拒绝。
RAM 选择现有 host PAT 的 WB 项、空洞/MMIO 选择 UC 项；最终类型仍按 AMD guest PAT、nested PAT、物理地址 MTRR 合成，未修改全局 PAT。
尚未完成缓存边界的硬件测例，因此不能据此宣称物理机常驻可用。
每次 VMRUN 全量 flush，ASID=1 按处理器独立使用；未开启 clean-bit/选择性失效优化。
Intel 保留原执行路径，新增调度边界目前由 AMD 接入；共享 phase、电源/拓扑回调与 unload 互锁继续共用。

来源：[AMD APM Volume 2](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf)、
[AMD Hyper-V 嵌套宿主版本限制](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization)、
[一次性启动](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootsequence)、
[BitLocker 的 BCD 检查](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bcd-settings-and-bitlocker)、
[KeIpiGenericCall](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keipigenericcall)。

静态候选现使用 metrics v5，CLI和当前验收脚本须与驱动同批构建；历史v4导出仍可由只读验证器解释其不变的nestedProbe子集。`general`诊断不复用探针完成位。`build-tests.cmd --build-only`只编译链接宿主测试目标，打印TEST_EXECUTION=NOT_RUN；不执行测试或装载驱动。
