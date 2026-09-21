# AMD 实验后端与重启续接

2026-09-21静态interrupt：控制overlay按实际L1IF处理V_INTR_MASKING、GIF0抑制IRQ/VIRQ并拦NMI，退出恢复原controls再route，真实CR8/mask输出分开。NMI叶已改同CS/IST0近返回保留硬件NMIblock，由guest真正完成IRET解除；未验证，不能沿用前段IRETQ说明。全局资源释放门保留NMIcount/窗口。继续平台队列/TPR/停止接线。

2026-09-21静态物理事件入口：hvm_svm_nmi.{c,h,asm}可信IDT副本/临时vector2计数、IF0有限STGI/CLGI窗口、描述符复核与计数保留；普通路径没有调用点。HostInterruptsAllowed138汇编桥、VMEXIT立即CLI；默认零。未验证，继续注入/IRET/平台接线，不能称完整静态完成。

2026-09-21静态pending：固定token事件账本区分Queued/Armed/完成，NMI优先与owner隔离；执行器Deferred已接，L2未交接事件阻止反射，未验证。继续物理NMI确认与窗口平台桥，不能声称通用入口完成。

2026-09-21静态执行器：nested_execute接一般事务/状态/NPF/异常，物理事件与GIF动作留给平台，未挂普通resident。修正fc5阶段INVLPGA退出码错误86→7a（86是SKINIT，拒绝并隐藏CPUID）；未验证。继续事件桥，不阶段停止。

2026-09-21静态CPUID：nested_cpuid过滤不支持的状态/控制扩展，动态guest OSXSAVE/leafD，显式ExposeSvm+NPT/NRIP/ASID门，SVMfeatures仅0xc9；L2更深SVM不暴露。probe leafD已接，普通resident仍隐藏SVM。代码未验证，继续通用执行分派与事件桥接。

2026-09-21静态寄存器层：nested_register已接受限probe，EFER虚拟SVME/当前模式/LMA与PG门、L1HSAVE/VMCR隔离、XSS软件值、L2G_PAT更新与L1缓存契约拒绝、S_CET门。未编译测试。接下来重点完整通用分派、GIF/IRQ/NMI及平台桥接，仍不开放普通resident SVM能力或宣称完整L2完成。

2026-09-21静态TLB：SessionInvalidate实现L1 INVLPGA→当前vCPU全部NPT02缓存重置/epoch推进，输入ASID只记诊断、不发真实INVLPGA；probe真实inner反射后新增一条并要求Invalidations1。跨CPU仍需L1逐核shootdown，不能把本地失效称全局完成；外层NPT01保持不可变。未构建未执行，继续写通用执行与物理事件桥接。

2026-09-21静态transfer：新增nested_transfer，VMLOAD/VMSAVE共用session/translated-HPA lease，捕获后持有再重读，仅架构字段复制/白名单写回，partial保留；生产probe已改调用，不再有旧固定地址读取适配内部实现（harness限制仍在）。未编译未测试。继续一般状态MSR/指令及事件控制，不阶段停下。

2026-09-21静态多核增量：nested_owner共享4096永久HPA键/唯一CAS token无等待锁；session获取后重读、完整INVALID/VMEXIT写回后释放、故障保留，probe等原生读回后释放；teardown要求全部token空。记录group:number。解决monitor并行VMRUN同页互斥，不阻止来宾普通内存写表；跨核NPT失效仍待做。测试源码已补未运行，未构建，按用户要求继续静态实现并本地逐块commit。

2026-09-21静态异常增量：nested_event实现原异常L1截获优先、contributory/PF合成DF、DF/shutdown二次截获；IRQ/NMI已确认事件Deferred必须保留才注入，guestCR2与RIP规则明确。普通GP/UD已接，普通路径尚无异步队列故保留故障。新增测试源码/工程清单，未构建未执行。继续写物理事件/GIF、通用指令与多核所有权；不可说静态全完成。

2026-09-21静态续写：XSS Host/Guest128/130汇编切换，CET_U子集写门；CPUID.D几何固定/当前guest大小计算已接受限probe，汇编x87-only检查EBX576。原生核验比较guest当前mask，probe要求原mask；补用例未运行。此阶段用户明确不验证，未编译/测试/签名/装载，不复用977725df的通过结果。后续继续静态写事件仲裁与跨核所有权等；每阶段本地commit，不阶段性结束。

2026-09-21续接XCR0：新增分配边界/依赖检查与HostXcr0/GuestXcr0汇编切换（118/120偏移断言），root恢复原掩码后固定全mask XSAVE，guest restore后安装子集；XSS仍固定。探针x87-only跨INVALID/真实内层再恢复，并由L1/L2 XGETBV读回。policy590326/生产分派390及既有回归、WDK/API/CAT零警告通过，硬件NOT_RUN，未签名/未暂存。用户新指令：一直把剩余静态实现写完，不阶段性停下；每块本地commit、不推送、暂不运行验证，后续新代码必须明确未验证。不加载驱动/启动VM/复现冻结；不使用旧关机授权。

2026-09-21冻结后继续离线：nested_route已接生产probe，按原VMCB+权限图判退出归属（双重拦截先反射L1；NPF走MMU；物理INTR/NMI/SMI/INIT走专门仲裁，禁止盲目重入）。NPF重入恢复EXITINTINFO事件或清旧EVENTINJ；软件INT无有效NRIP则拒绝，不宣称异常合成/GIF完成。route1925/nested4551/分派241及entry8765/session65/8线程100模拟/其它回归通过；标准WDK/API/CAT零警告。Release输出是新未签名构建；共享nested-entry-20260921仍为4ec4d724/age5已签名但NOT_RUN候选，未覆盖未加载。当前不启动VM、不进行宿主虚拟化动态测试。继续实现XSTATE/IRQ/NMI等前保留故障原因UNKNOWN，不能推断VMware安全漏洞。

2026-09-21 10:11宿主整机冻结：用户确认硬挂后重启，LastBoot10:13:20，Kernel-Power41/BugcheckCode0、6008异常关闭；无本次新dump。八核前次10:08:33正常VMXexit0；新单核10:10:02 CPL0/NumVCPUs1启动，Tools运行，日志截止10:11:10。新候选4ec4d724仅构建/签名/暂存nested-entry-20260921（SYS/PDB age5），未执行来宾加载/探针，也未在物理宿主发出驱动装载或常驻。KD重连等待，旧会话失效；所有测试进程随宿主重启终止。宿主现HypervisorPresent=true、Ksword服务Stopped；暂不再启动VM或硬件试验，只读取证和离线实现继续。故障根因未知，不能称CPU锁/漏洞，也不能凭重启后Stopped排除冻结时全部驱动状态。证据artifacts/host-freeze-20260921-101828，报告docs/next/evidence/amd-host-freeze-20260921.md。旧00:31dump访问拒绝，不改ACL提权，不归因本次。

2026-09-21通用入口提交4ec4d724：新增nested_entry/writeback/commit/session；生产probe先ASID0→INVALID正常返回L1，修正同一VMCB再真实内层CPUID。NPT01写权限/HPA绑定，VMEXIT/INVALID/VMSAVE字段白名单，部分写进度，实际L1续执行。普通常驻仍不开放SVM，IRQ/NMI/GIF、XSTATE、通用退出/跨核失效未完成，完整L2 OS/内层并发未通过。entry8765/writeback622/session65（另8宿主线程×100模拟）/分派240及既有回归通过，标准WDK/API/CAT零警告。硬件新候选NOT_RUN；用户目标仍是完整OS+内层多核，不推送、不用旧关机授权。

2026-09-21 09:28八核新候选PASS：nested-operand-20260921同一ec61b3df/age3候选。导出nested-probe-20260921-092817-a6830b52ca494d5dabe7af1efd99fad6共624文件，verify_nested_probe独立核验全部哈希、控制/CPU集合/完成序列及最终释放。8vCPU各100轮，共800次逐核串行嵌套往返，CPU0:0..7最终sequence200、每轮NPF5、released=true。报告docs/next/evidence/amd-nested-operand-8cpu.json。不宣称并发内层vCPU或完整L2 OS运行；权限图读取/合并新路径已完成1核1轮和8核100轮硬件回归，下一步是通用VMCB准入、L1续执行/异常反射和IRQ/NMI/GIF，不必继续重复本探针轮次。用户要求通过即commit，不推送。

2026-09-21 08:52单核新候选PASS：ec61b3df对应nested-operand-20260921、SYS/PDB e4cc4cb2-c439-411a-b14d-0a1a0f78fedc age3。导出nested-probe-20260921-085216-7af421ad03814e60a8e1a6067ff5d346共30文件，verify_nested_probe独立核验哈希、控制顺序、逐核状态及最终释放通过；CPU0:0完成sequence2、NPF5、VMEXIT18、failed0。KD52376实际query断点命中并解析匹配私有PDB。仅固定探针往返，不是L2 OS或并发内层vCPU通过。按用户偏好立即提交证据后正常关闭克隆、保存单核冷态快照并直接改8vCPU；同一候选无需重编译。宿主不重启、不关机、不推送。

2026-09-21续接：已先按用户要求fetch并快进到f7779802，保留本地工作。宿主HypervisorPresent=False，32LP，克隆起始关机/8vCPU。新增hvm_svm_nested_operand.c/.h：L1物理页经可信NPT01遍历、只接受WB叶缓存属性、每个物理字通过RAM窗口回调读取，复制后重验页表结构（忽略硬件A/D）；失败清零目标并返回明确状态。权限图捕获已改用此路径，取消CPU原有map地址白名单，固定VMRUN操作数/标记限制仍保留。此读取不提供对L1并发数据写入的原子快照、跨核失效或通用VMRUN准入。MSVC/WDK Release/API/CAT零警告、hvm_ctl构建通过；operand1049/分派180/权限917803/AMD74056/nested449/Intel85逻辑检查通过。新候选尚未加载/硬件验证；旧probe候选保留，本次另建共享子目录nested-operand-20260921，计划1vCPU冷启动+KD后用户运行Start-GuestNestedProbe，再按偏好跳8核。旧关机命令不再适用，本轮不关机、不推送。

2026-09-19晚间收尾：按用户授权已推送一次，远端前进导致首次拒绝后fetch/merge，保留hvm_internal.h双方字段（BackendContext及NativeVmcsFields），合并提交02655653已推送；真实32核5秒证据提交4c9295bc。远端提示新地址KSwordDEV/KSword，origin未擅改。随后实现hvm_svm_nested_permissions：私有权限图捕获/失效、完整地址范围、启用位感知OR、MSR/IOIO逐位归属（包括IOPM尾部不回绕、隐式MSR拦截）。每核新增20KiB连续合并图，生产固定探针在VMRUN前实际捕获/合并并替换硬件指针，反射恢复L1原指针；只接受原有固定map地址。917803项权限图断言、158生产分派模拟、AMD74056/nested449/Intel85通过，标准WDK/API/CAT零警告。通用L1物理快照适配、跨核失效、VMCB合法性、一般IRQ/NMI/GIF与真实L2 OS仍未完成；正常CPUID继续隐藏SVM。Release SYS已被新未签名构建替换，旧通过候选仍在artifacts/amd-host-cet-user-v6；现有host测试哈希锁会拒绝新SYS，不可直接让用户跑旧脚本当成新验证。用户明确今晚不再动态验证，当前代码本地commit后执行shutdown -s -t 0；不再推送、不再额外审计。

实体机32核完整短常驻PASS（2026-09-19）：host-self-test-20260919-000749-f718b7a6f2e548dc9146617747f6547d原始证据经生产验证器独立回放：32核串行自检、并发进入、两次Active查询间隔5.0321852秒且代次不变、全核stop、teardown归零、SCM STOPPED。报告docs/next/evidence/amd-host-resident-32cpu-5seconds.json；仍是7004a13c/age13候选，不是L2操作系统通过。随后用户手动常驻32核，VMware报AMD-V/RVI不可用、MonitorMode失败；当前普通CPUID隐藏SVM且不提供通用SVM转发，与此现象相符。此次VMware失败仅有用户报告，未取得对应vmware.log。用户明确授权本次提交后推送一次，再继续实现；后续不自动再推送。当前SCM独立查询已Stopped。

STOP_PENDING续接（2026-09-19）：用户完成teardown/sc stop后立刻重跑，脚本因尚未STOPPED拒绝。独立观察STOP_PENDING持续超过额外30秒，发现宿主Ksword5.1 PID32092自00:01:40运行；用户完全退出主程序后SCM即确认STOPPED/exit0，未重启。符合主程序设备句柄延迟卸载，但未取得句柄级归因。Test-HostSvmSelfTest现用SCM ServiceController：仅StopPending等待最多30秒、Running仍拒绝；stop后等待完成再发布结果，超时不当成功；入口要求主程序退出。PS5显式加载System.ServiceProcess，37项回归及实际STOPPED查询通过。驱动不改，下一步直接重跑-ResidentSeconds5，无需再次teardown/sc stop。

实体机首轮并发常驻（2026-09-19 00:00）：真实32核已全部进入(stage4/flags103/common404013/gen4)，finally stop也全部成功(stage6/flags403/common13/gen5/resident0、逐核VMMCALL exit81、failure0)。此次报错是脚本把ENTERED错写成3（实际3是ENTERING、4才ENTERED），模拟测试也复制了错误常量；已修正stage4，测试从共享协议取常量、增加ENTERING拒绝及本次真实32核快照回放。docs/next/evidence/amd-host-resident-enter-stop.json记录准确通过范围。5秒等待尚未执行，资源未teardown、驱动仍RUNNING；这不是退出失败，也不是完整5秒验收PASS。下一步管理员先核对status全核已stop，再teardown/sc stop，重跑同一-ResidentSeconds5脚本。驱动/SYS无需改动或重编译。新错误输出含group:number/期望实际stage/flags/status，避免再次只报笼统异常。

实体机短常驻入口：Test-HostSvmSelfTest.ps1 新增显式 -ResidentSeconds 5（默认0仍只串行自检，最大30）。同一已通过32LP自检的7004a13c/age13候选，无驱动改动；自检后全32LP并发resident、5秒前后核对Active完整CPU集合/代次/卸载保护，finally请求stop核验逐核Stopped，然后teardown/卸载。执行/回滚证据不足时保留driver/resources，不从CLI结束推断停止。PS5证据验证器29项通过；本轮全核常驻尚未执行。32核串行自检里程碑已提交f1e4d60d，未推送。

实体机32LP串行SVM自检已PASS（2026-09-18 23:45）：同一7004a13c/age13候选，a155d211脚本运行。原始host-self-test-20260918-234529-87219d5d131f46bd8a9649c57fdac932共23文件，独立检查SYS/CLI哈希、CPU0:0..31精确集合、每核CPUID EXITCODE72/VMEXIT1/TLB1/有效偶数序列、32个独立VMCB和HSAVE页。prepared/selfTest32，failed/resident0，generation2→3→4、power0，teardown后INITIALIZED/processor0/slat0，SCM STOPPED。报告docs/next/evidence/amd-host-self-test-32cpu.json。本机第一次真实VMRUN往返和原生状态返回验证已通过；不是全核同时常驻、内层OS或压力通过。下一阶段可做实体机全核短时resident→stop→release，不需再跑准入。

下一步入口已准备：tools/hvm_lab/Test-HostSvmSelfTest.ps1，管理员一条命令装载→prepare→全部32LP串行self-test→核验逐核集合/状态/代次/EXITCODE72/TLB1→teardown→SCM STOPPED。锁定已通过准入的SYS/CLI哈希，不重编译，不resident，不修改虚拟机CPU配置。所有命令前落盘日志，失败/不完整证据保留driver/resources，不盲目卸载。PS5解析与21项生产证据验证器模拟测试通过，非管理员前置拒绝已实测；真实prepare/VMRUN尚待用户执行。准入里程碑commit d4c873e3，未推送。

宿主准入已实际PASS（2026-09-18 23:38）：用户Test-HostSvmAdmission输出backendStatus0/rejectReason0/NONE，CR4仍B50EF8、XSS仍800、HSAVE0，未关闭CET。独立核对原始status、SYS/CLI哈希与7004a13c的age13候选匹配，SCM STOPPED。证据docs/next/evidence/amd-host-admission-pass.json，原始artifacts/host-admission-20260918-233852-d2206581cff943a19cf380b31dc01fe3。此范围仅初始查询CPU准入及驱动装载/查询/卸载；prepared/selftest/resident/vmExit均0，不是实体机VMRUN通过。下一步prepare→逐CPU串行self-test→metrics→teardown，不直接resident；物理宿主32LP，自检是每CPU短往返，不能说并发32核常驻通过。

CET_U 候选归档：tools/hvm_lab/artifacts/amd-host-cet-user-v6，SYS/PDB匹配f0725672-1a1e-4104-890a-1b5744c5c7a9 age13；docs/next/evidence/amd-host-cet-user-build.json保存哈希与测试/签名边界。Release SYS仓库签名者00797B09...，签名最终信任检查仍失败（不受信任根）；此候选装载、准入及SVM硬件执行均NOT_RUN。现有管理员Test-HostSvmAdmission脚本默认路径已指新Release SYS与新hvm_ctl，用户无需重新编译。

CET_U 修复候选（2026-09-18）：已实现 CR4.CET/XSS=800 且 S_CET=0 的窄范围支持，尚无新硬件结果。Caps逐核读CPUID7.CET_SS、S_CET/ISST/U_CET/PL3_SSP；其它XSS、非零S_CET、XCR0管理的CET仍拒绝，新增v6枚举reason13 CET_STATE_UNSUPPORTED，不改协议尺寸。CPU固定前缀追加110h XstateCompacted/114h CetPresent并C_ASSERT；XSS=800用D.1EBX大小、XCR0|XSS掩码、XSAVES64/XRSTORS64，原XSS0保持standard路径。VM入口重探测状态；MSRPM阻止改变XSS/启用S_CET；VMCB 5E0/5E8/5F0与nested CopyVmrun/Reflect一起处理，native恢复当前ISST/S_CET。自检返回检查原线程UCET/PL3及XCR0/XSS/SCET/当前ISST，stop仅核对当前状态，不回滚用户线程。驱动WDK/API/CAT零警告，主程序/KswordCLI/hvm_ctl通过（GUI4既有警告）；AMD74056/nested449/生产分派124/Intel85、JSON/命令/i18n/IOCTL通过。下一步管理员对新Release候选再跑现有Test-HostSvmAdmission.ps1；它不执行SVM。不要把编译测试记录成实体机准入或CET硬件通过，也不替换旧guest-bootstrap已验收候选。

宿主准入原因已实测确定（2026-09-18 23:14）：HVM v6 诊断版成功装载/status/卸载，独立核对原始文件、SYS/CLI SHA256及SCM STOPPED/exit0；报告 docs/next/evidence/amd-host-cet-admission.json。rejectReason=8 CR4_UNSUPPORTED_STATE，CR4=B50EF8 与现有拒绝掩码相交仅 bit23/CET；XSS=800 即 bit11/CET_U，stateValidMask=31。HSAVE=0、SVME=0、SVMDIS=0，先前所有权阻塞已消失；当前是实现不支持的状态保存/恢复组合。XSS.CET_U 不等于内核影子栈已启用，尚未采集 S_CET，不能据此推断 supervisor CET 开关。AMD APM 24593 §18.13 确认 CET_U 为 U_CET/PL3_SSP，XSAVES/XRSTORS 由 XSS 管理；普通 VMCB 的 S_CET/SSP/ISST_ADDR 在 5E0/5E8/5F0。后续须明确支持范围，补 XSTATE 路径、VMCB/原生返回及逐核进入时重验证，不能只删 CR4/XSS 门或清零系统配置。此次 prepared/selftest/resident/vmExit 均0；物理机 SVM 执行仍未测。现有候选无需重复装载，也无需重启。

宿主重启后诊断（2026-09-18 23:01启动）：用户遵循实验项重启、未开VMware，宿主仅装载查询卸载成功；HSAVE归零，拒绝从STATUS_DEVICE_BUSY变为STATUS_NOT_SUPPORTED(C00000BB)，EFER4D01/VM_CR8/PA48/MSR有效15。尚不能确定CR4或XSS等具体原因，不可据此放宽门。已增加HVM v6准入诊断：rejectReason/Name、stateValidMask、CPUID.1 ECX/CPUID.D.1 EAX、CR4/XCR0/XSS，原准入限制保留。驱动/主程序/KswordCLI/hvm_ctl同步构建；驱动WDK/x64ApiValidator/CAT零警告，主程序4条既有警告；AMD73907/嵌套441/分派124/Intel85、JSON/CP936、命令目录/i18n/IOCTL检查通过。Release SYS按仓库原签名链签名，签名者00797B09...与用户此前成功加载产物一致；工具链验证仍报不受信任根，不能称签名验证通过。诊断候选副本artifacts/amd-host-admission-v6；新增Test-HostSvmAdmission.ps1仅装载/status/卸载并保存文件哈希及日志，PS5解析通过，待用户管理员执行。未实际执行本机SVM。旧guest-bootstrap/nested-probe及age9/协议v5候选保持原样，勿与新v6 CLI混用；宿主重启已使旧KD会话失效，后续需重建。

宿主装载里程碑（2026-09-18）：用户对Release/KswordARK.sys执行仅装载→status→卸载。用户原始CLI证明IOCTL响应，SCM独立查询STOPPED/exit0且ImagePath指Release；此范围PASS，需按要求提交。HVM本身未启动：queryStatus1/backendStatus=0x80000011 STATUS_DEVICE_BUSY，prepared/resident/vmExit=0。svmProbe有效位15，VM_CR8（SVMDIS=0）、EFER4D01（SVME=0）、HSAVE=0x803656000非零，ASID32768/PA48；触发hvm_svm_resources.c的非零HSAVE保守拒绝条件。不能据非零HSAVE断言仍有活动VMware所有者（残留/来源未确认），也不能当作物理机SVM执行失败或通过。报告docs/next/evidence/amd-host-load-query-unload.json明确查询来自用户stdout、未核对已加载映像调试身份。不得自动清零HSAVE或跳过能力门；后续若推进物理机常驻，需要独立所有权诊断。

最新测试偏好（2026-09-18）：用户要求提速，后续新候选单核通过后直接跳8核，取消常规2/4核中间验收；仅8核失败且定位需要时才缩小拓扑。每个真实通过点仍独立核验并commit，不推送。当前八核探针通过点已提交47d404b4，克隆正常关机并保存AMD-NestedProbe-8CPU-100Cycles-PASS-20260918冷态快照；用户无需重复旧探针或在实体宿主加载候选。下一步是通用嵌套SVM代码实现，不能把既有固定探针当作VMware内层OS兼容测试入口。

最新硬件里程碑（2026-09-18 22:40）：8vCPU/100轮受控嵌套探针PASS。回传nested-probe-20260918-224000-3121a1707dfe4fb7998257c004a2397c共624文件，verify_nested_probe.py独立核验全部哈希/大小、控制顺序、逐核状态/代次及最终释放。CPU0:0..7各100轮，共800次往返，完成序列均200，每轮每核NPF5、entries/reflections1、exit72/marker4B534E31、failure0，资源归零。报告docs/next/evidence/amd-nested-probe-8cpu.json。由此固定探针1核1次、2核20次、4/8核100次均已通过；不重复同类轮数来冒充通用内层VMM兼容。下一实现重点：任意VMCB快照/合法性检查、MSRPM/IOPM合并、IRQ/NMI/GIF、CLGI/INVLPGA与异常反射、一般L1 continuation和非身份NPT硬件覆盖，再测试内层OS。物理机常驻及并发内层多核均未验证；原2h压力仍是用户中止，不补记通过。

八核探针准备（2026-09-18 22:39）：四核100轮已提交b4c5dc05，未推送；正常关机保存AMD-NestedProbe-4CPU-100Cycles-PASS-20260918冷态快照。克隆改单插槽8vCPU冷启动，VMware日志CPL0/NumVCPUs8，KD78911重连，同一nested-probe age9候选。下一步来宾共享Start-GuestNestedProbe.ps1 -Vcpu 8 -Cycles 100；尚无八核探针通过证据。

最新硬件里程碑（2026-09-18 22:37）：4vCPU/100轮受控嵌套探针PASS。用户仅回贴命令，但宿主已收到nested-probe-20260918-223710-9e5e89f87bac4713aa6a96526ef296ce完整导出，verify_nested_probe.py独立核验624文件哈希/大小及所有控制/逐核结果。CPU0:0..3各100轮，共400次往返，完成序列均200，每轮NPF5、entries/reflections1、exit72/marker4B534E31、failure0，最终资源归零；同一age9候选。报告docs/next/evidence/amd-nested-probe-4cpu.json。仅逐核串行自检，不是并发内层OS；按要求立即commit，下一步8核100轮。

四核探针准备（2026-09-18 22:36）：双核20轮已提交5dabd644，未推送；正常关机保存AMD-NestedProbe-2CPU-20Cycles-PASS-20260918冷态快照。克隆改单插槽4vCPU并启动GUI，VMware确认CPL0/NumVCPUs4，Tools running、KD78911重新连接，源/结果共享已恢复。沿用age9候选，等待来宾Start-GuestNestedProbe.ps1 -Vcpu 4 -Cycles 100。尚无四核嵌套探针结果；上一阶段四核常驻100轮是另一项验收。

最新硬件里程碑（2026-09-18 22:33）：2vCPU/20轮受控嵌套探针PASS。回传nested-probe-20260918-223305-8a32023c694c43178321d1b125402751共144文件SHA256/大小核验；生产CLI控制日志顺序完整，CPU0:0/0:1各20轮，completion sequence均到40，每轮每核entries/reflections=1、NPF=5、exit72/marker4B534E31、failure0，电源代次一致；teardown后资源归零。源候选仍age9，与单核同一SYS/PDB/CLI。新增verify_nested_probe.py独立验证器，处理PS5 Tee-Object UTF16与CLI UTF8；报告docs/next/evidence/amd-nested-probe-2cpu.json。自检是逐核串行，不宣称并发多核内层OS。按用户要求通过即本地commit，不推送；下一阶段4核。

双核探针准备（2026-09-18 22:31）：单核通过点已提交d9413087，未推送。正常关机后保存冷态快照AMD-NestedProbe-1CPU-PASS-20260918，克隆改为单插槽2vCPU并冷启动；VMware日志CPL0/NumVCPUs2，KD78911已重连，映像/PDB仍为nested-probe候选age9。沿用已验证的候选，不替换SYS；下一步来宾管理员执行共享nested-probe/Start-GuestNestedProbe.ps1 -Vcpu 2 -Cycles 20，脚本加载独立候选并自动回传。尚无双核嵌套探针结果。

用户工作方式（2026-09-18）：今后每个验证阶段实际通过并核验原始证据后，立即创建本地 commit，不推送。固定探针通过、逐核多CPU探针通过、并发内层OS通过和物理机常驻通过必须分别记账；不得把VMware来宾验证外推为物理宿主已可运行。当前单核探针通过点准备提交，克隆已正常关机，双核配置/启动尚未执行。

最新硬件里程碑（2026-09-18 22:24）：受控嵌套SVM探针1vCPU/1轮真实PASS。回传nested-probe-20260918-222442-acf9b8d1cbe1476f9edeffb5604cf904，30文件SHA256/大小独立核验，SYS/PDB/CLI匹配nested-probe候选（PDB age9），来宾signature Valid、KD实际命中新驱动query并加载private PDB。CPU0:0 nestedProbe valid1/sequence2/status0/entries1/reflections1/faults5/exit72/marker4B534E31，18次TLB请求；teardown后INITIALIZED、prepared/resident/slatReady=0。独立报告artifacts/guest-results/verified-nested-probe-one-cpu.json。仅固定内层指令序列，不是内层OS启动。下一步正常关机保存单核探针通过快照，2vCPU/20轮逐核探针；这类self-test逐核串行，不得声称并发多核内层VM通过。

交付续接（2026-09-18 22:22）：新候选 `artifacts/amd-candidate-nested-probe` 使用原实验证书15B8036D...签名（宿主不信任根为预期，来宾加载尚待验证），共享子目录 `guest-bootstrap/nested-probe`，旧根目录irqfix保留。主程序与KswordCLI Release也构建成功；主程序4条既有宏重定义/部署警告、自动GUI签名校验0x80096019，不能说整个GUI零警告或签名验证通过。8核克隆已正常关机并保存冷态快照 `AMD-8CPU-Stopped-BeforeNestedProbe-20260918`（不是PASS快照），改1vCPU冷启动，VMware日志CPL0/NumVCPUs1。重新启动KD会话78911，日志host-20260918/kd-nested-probe.log，符号和映像路径指新候选；实际break-in后g，设置一次性query断点自动输出模块身份再g。下一步用户在来宾管理员PowerShell运行共享子目录Start-GuestNestedProbe.ps1；脚本负责复制/加载/1核1轮自检/回传。不再手工覆盖旧candidate。无密码Tools远程执行仍不可用，不能声称已运行探针。

最新续接（2026-09-18，受控嵌套探针接线）：生产 VMEXIT、资源与汇编已接通固定内层 VMRUN→稀疏影子 NPT 缺页→CPUID 反射→原生返回；仅 driver-owned operand，正常常驻仍隐藏 SVM。新增 prepare-svm-probe/self-test-svm-nested，metrics v4 nestedProbe 完成序列在原生 EFER/HSAVE 回读后才发布。MSVC/WDK Release x64、ApiValidator/CAT 通过；AMD73907/嵌套441/生产退出分派模拟124/Intel85通过。PS5验收谓词16项、实际子进程采集300次等、CLI JSON/CP936、62命令目录、i18n、IOCTL门禁通过。Start-GuestNestedProbe.ps1 一条命令从冷启动STOPPED服务复制独立候选、加载、执行并回传原始证据；首次1vCPU/1轮。新探针尚无硬件结果，不得当作任意内层VM可运行；一般VMCB校验/权限图合并/IRQ-NMI-GIF/CLGI-INVLPGA及非身份映射硬件仍待完成。旧irqfix候选保留，不等待2h压测。

最新续接（2026-09-18，第二阶段代码）：用户已手动stop八核压力，OK，generation304→305、prepared/selfTestPassed=8、failed/resident=0、VMEXIT12496。记用户中止，不能补记2h PASS；8核100轮尚未取回原始报告。上一阶段提交4c6cd6a0，未推送。新增hvm_svm_nested_npt/mmu/shadow/state：NPT12页表页本身经NPT01转译、故障归属、CAS A/D、只读叶首次写捕获、WB/UC叶合成、每CPU最多256页影子池/epoch/flush请求、分离VMRUN与VMLOAD状态搬运。新增427断言及AMD73907/Intel85通过；标准WDK Release x64编译链接/x64ApiValidator/目录生成通过。新代码尚未接入退出分派或资源准备，真实nested-SVM/Windows物理回调/虚拟MSR/GIF/权限图合并均未完成，不得发布嵌套支持。新SYS未签名/加载，guest-bootstrap和KD候选仍irqfix版本。精确约束和下一步见docs/next/amd-nested-svm-implementation.md。用户要求继续写，晚上再跑压力，不要等待2h测试、不重启或关宿主。

最新硬件里程碑（2026-09-18 21:03）：4 vCPU/100轮/10秒idle PASS，prepared/resident均归零。回传export-20260918-210303-7c68ccf223e44b51873c71a07e308344共1876文件全部SHA256独立核验；单/双/四核原始controls与逐核status/metrics再次独立解析通过：20/20/100次resident、40/40/200次含幂等stop，CPU集合及电源代次一致，最终各核stage6/exit0x81/failure0。报告artifacts/guest-results/verified-through-four-cpu.json，复现脚本artifacts/host-20260918/verify-through-four-cpu.py。四核目录four-cpu-20260918-210224，用户附件e76f7ac7-077a-4e36-8350-ba3f201a7837。仍未完成8核/2小时压力/故障回滚/电源验收。当前正常关机后准备四核冷态快照和8核；runner新增每25轮和每5分钟压力进度，压力线程停止后再检查最终错误。GuestWorkload在宿主原生2线程3秒smoke通过，只证明负载工具可运行，不计入SVM硬件压力证据。

最新硬件里程碑（2026-09-18 20:56）：2 vCPU/20轮/10秒idle PASS，结束prepared=0/resident=0，未执行soak。来宾日志C:\KSwordLab\two-cpu-20260918-205615；用户附件ece07e58-a376-4c89-b269-24acc23edb4a原文已存artifacts/host-20260918/two-20cycles-pass-user-output.txt。已有真实双核常驻/停止往返证据；4/8核、压力与故障回滚未通过。当前准备正常关机保存双核冷态快照后改4核100轮。

最新硬件里程碑（2026-09-18 20:50）：用户附件3edd679a-2a77-4a17-b273-050fba969221给出irqfix重测最终PASS，1 vCPU/20 cycles/idleSeconds10/soakSeconds0，结束prepared=0/resident=0。来宾原始证据C:\KSwordLab\irqfix-retry-20260918-205003，用户摘要已保存artifacts/host-20260918/single-20cycles-pass-user-output.txt。这证明单核重复常驻启停与计时唤醒，尚不证明压力、多核、故障注入和电源路径。当前按计划正常关机克隆，准备冷态快照及单插槽2 vCPU；不要重跑旧1核任务或把“CAPABILITY_ONLY”（释放状态）误判为本轮没进入。

最新续接（2026-09-18，20:44运行）：用户附件0c03bd1e-32c9-4b08-b9f6-f87c42c403b3证明irqfix驱动加载PASS/signature Valid；KD query断点解析新私有PDB（timestamp6AAD2E04）。测试目录C:\KSwordLab\irqfix-20260918-204421，第34条stop读取输出文件失败，未报告CPU禁用。按生产runner顺序已通过10秒idle等待、前4轮完整启停及第5轮resident/status；第5轮stop真实结果需查询，不能记为20轮通过。原始附件保存在artifacts/host-20260918/irqfix-first-attempt.txt。共享目录重启后曾不可读，宿主vmrun enableSharedFolders+setSharedFolderState readonly后用户列目录通过；粘贴内容会转义斜杠，不能仅据显示认定输入错误。

采集修复：移除Start-Process的重定向文件回调依赖，用ProcessStartInfo和并发ReadToEndAsync显式等待两个EOF再写UTF8文件；超时不Kill/不继续控制。具体旧文件缺失原因尚未独立复现，不把回调竞态当作已证实唯一根因。Test-AcceptanceCapture在真实PS5子进程验证300次快速退出、双流各128KiB、exit7、空输出拒绝、超时进程保留并自然结束。无需改驱动；新版runner已同步共享，待stop/status/teardown后重跑1核20轮，保留原失败目录。

最新故障与修复候选（2026-09-18 20:29）：一次手动 resident/stop 成功后，自动测试重新 prepare/self-test，在首轮 resident（generation=9）停止响应。VMware 12:14:02Z 记录 CLIHLT/CPU disabled；已保存 8 GiB backing RAM、日志、旧 SYS/PDB，目录 `tools/hvm_lab/artifacts/halt-20260918-201502`。可复现解析脚本及 `halt-memory-summary.json` 确认 resident=1、ring 仅1条自检、VMCB INTCTL=0x01000000、Windows BugCheck 数据全零。VMCB RIP/RFLAGS 是首次进入状态，不能当作停止时 CPU 寄存器。APM 15.21.1-2 证明 V_INTR_MASKING=1 时物理 IRQ 使用 host IF，而本入口 CLI 后 IF=0；已改 INTCTL=0，保持真实 IRQ/CR8 直通。硬件根因仍须重测闭环。关闭提示后12:16:45Z VMware renderer 独立崩溃退出；此前 RAM 已保存，快照尝试失败，不存在成功快照。

修复候选 `artifacts/amd-candidate-irqfix`：标准 Release x64 编译链接、x64 ApiValidator Universal 通过；自动发行签名的宿主信任校验仍失败，随后以原来宾已信任的实验证书15B8036D...重新签名隔离候选。SYS/PDB GUID f0725672-1a1e-4104-890a-1b5744c5c7a9，age=5（旧age=4）；SYS SHA256 fb3b054dc9f91656abb4af04bc063898d63c969bfff8a959ec7717e54456deb9。AMD73907/Intel85逻辑检查通过，PS5 runner解析通过，不代表硬件修复。共享目录已更新，旧候选保留。克隆已冷启动，KD实际重连并g；新KD exec session29168，日志 `artifacts/host-20260918/kd-irqfix.log`，符号路径指向irqfix；一次性query断点会记录模块身份并自动g。待用户在克隆确认服务STOPPED后复制新SYS/PDB/CLI/identity，再Load-GuestCandidate并运行1核20轮；runner首轮新增默认10秒idle等待/唤醒检查。空密码Tools仍不能从宿主执行来宾命令，无需等待桌面登录确认。未通过20轮、多核或压力，未推送。

最新硬件证据（2026-09-18）：单核首次 resident/stop 往返 PASS。用户附件 b634785c-5ac7-414a-9a11-dfbd10b118ef/pasted-text.txt 已包含原始五条输出：进入 generation=4/ACTIVE/resident=1/UNLOAD_GUARD_ARMED，停止 generation=5/resident=0/DEVIRTUALIZED/stage=6，末次 exit=0x81 VMMCALL、failureStatus=0、无 FAULTED/ROLLBACK_REQUIRED。此轮常驻退出15次，累计 ring/TLB=16（含前一自检）。准备和自检仍保留，需 teardown 后运行 Invoke-GuestAcceptance 的1核20轮；尚未完成20轮/多核/压力。运行器修复 PS5 Start-Process 未缓存 Handle 导致 WaitForExit 后 ExitCode=null（真实 CLI 已复现并验证缓存 Handle 后恢复0），加入最终 PASS 摘要。

2026-09-18 首次真实单核 SVM 自检 PASS（最新状态，覆盖下文尚未 VMRUN 的历史）：用户 self-test 返回 OK，generation=3，selfTestPassed=1、failed=0、resident=0；CPU 0:0 stage=TESTED，VMEXIT=1，原始 EXITCODE=0x72/CPUID，NRIP-RIP=2，TLB requests=1，ring valid=1/sequence=2/position=1，failureStatus=0。Guest VMCB PA=0x239C66000，HSAVE PA=0x239831000，NPT root=0x239815000。自检成功路径已核对原 EFER/HSAVE 恢复。尚未 resident/stop、多核或负载；下一步单核常驻启停。通用 metrics command/transition 仍滞留 prepare，AMD 看 svmProcessors；此观测缺陷需后续修复，不能拿通用字段推断自检未执行。宿主 query 断点已命中；受控 mini kernel dump 331436 字节已落盘且离线打开成功，只有寄存器/有限栈，不能替代来宾崩溃后完整内核转储的落盘验证。

2026-09-18 单核 prepare 实测通过：generation=2、RESOURCES_READY、prepared=1、slatReady=1，CPU 0:0 stage=PREPARED，NPT 根非零，failureStatus=0，无 VMRUN。failedProcessorCount=1 来自 hvm_runtime.c 固定计算 ProcessorCount-SelfTestPassedProcessorCount（未测也记入），不能解读成 prepare 失败；通用 metrics.processorCount=0 对应 Intel 数组，AMD 看 svmProcessors；HsavePa 到 BuildVmcb 才缓存，因此 prepare 后为零。待完善诊断命名/准备期 HSAVE 发布，暂不为显示字段更换运行中驱动。

调试接管：原 WinDbg PID3492 已换为 kd.exe PID23012，exec 会话8364（若会话失效可用 npipe 调试服务器 KSword-AMD-KD 接入），串口仍为 KSword-AMD-Lab。kd-svm-preflight.log 已证明真实 break-in、候选 SYS 路径与 private PDB 加载、KswordSvmSelfTest 符号解析。已设置 /1 KswordARKHvmQuery 断点，命中后自动输出 KSW_QUERY_BREAKPOINT_VERIFIED、k 6、g；目标已 g 恢复。等待用户执行 status 触发这个普通驱动断点。首次 self-test 前仍需受控转储证据；不得据 prepare 宣称 VMRUN 成功。

最新实测（2026-09-18）：用户重跑加载器已返回 PASS，signature=0（Valid），中文 JSON 完整。来宾证据目录 `C:\KSwordLab\candidate\driver-load-20260918-111425-db464b7394514425838c859184b49ac2`。generation=1、仅 INITIALIZED、prepared/selfTest/resident=0；SVM 探针保持 ASID=64、PA=45、msrValidMask=15。加载/编码阻塞解除；下一步单核 prepare 及 status/metrics 回读，不跳过真实 VMRUN 自检。宿主仍有原 WinDbg 进程且日志记录 KD 连接，Tools=running；尚未验证普通驱动断点、精确符号实际加载、受控转储。

2026-09-18 加载入口补充：PS5.1 `powershell.exe -File` 下 param 默认表达式的 `$PSScriptRoot` 为空，正文中才有值；同一文件用 `-Command &` 则默认值正常，已用最小文件复现。Load-GuestCandidate 改为正文初始化来源目录；测试新增 3 项真实 PS5 进程入口（默认 -File、显式目录、调用运算符），另 7 项模拟 SCM 全通过。重试时 CLI 哈希相同不重复覆盖，避免刚退出的进程仍短暂持有文件时 Copy-Item 失败。当前仍等待来宾新版加载脚本实测，不能记作 VMRUN 通过。

最新进度（2026-09-18，优先于下方逐次历史）：宿主 LabHostReady；克隆 Win10 Home 19042/1 vCPU，初始化并重启，KD 已连接（普通驱动断点/匹配符号加载/受控转储尚未验证）。用户的加载输出已证明签名信任、SCM RUNNING 和 AMD status IOCTL 成功：backend=2、SVM/NPT/NRIP、ASID=64、PA=45、msrValidMask=15。未 prepare 或 VMRUN。当前阻塞是 UTF-8 中文 `没有拒绝过` 经 PS 5.1 代码页 936 解码吞掉后面的引号，已复现；不是驱动或原始 printf 丢引号。共享 JSON 打印器现在输出 ASCII Unicode escape；真实 query 格式化 + PS5/936 回归通过。加载脚本现在可重试同路径运行中候选，更新 CLI/identity 前比较 SYS/PDB 哈希，拒绝其它活动路径；7 项模拟 SCM/更新测试通过。PS5 Get-Content 的字符串 provider 属性会被 ConvertTo-Json 深度遍历，证据字符串改用 File.ReadAllText。新 CLI/加载脚本待共享目录来宾实测；不需要重启/卸载现有候选。用户已授权切回 Astra 修改代码并继续；保留 Win10、不换电脑、不推送。不得重复执行昨晚已经完成的关机授权。

2026-09-17 增加待硬件验收的 SVM/NPT 实验实现。**第一次真实 VMRUN 尚未运行，不能宣称 AMD 或多核已支持成功。**

- 用户底线：Windows 10、不换电脑、现有 Workstation 16.2.5。只验 VMware 暴露 SVM 环境下的 KSword 常驻，不提供内层 SVM。
- 实现入口 `hvm_backend.*`，AMD 模块 `hvm_svm_*`、`hvm_npt.c`；Intel 原执行路径保留。主协议 v5、metrics v3，定义只在 `shared/driver/`。
- 能力位不代表运行证据；MSR 有独立有效位。VMware 必须显式 ALLOW_NESTED；未知外层拒绝。NRIP 强制要求。
- 准备、自检与启动绑定 power generation、group:number/全局 CPU index 集合；共享 phase/unload 保护。NativeReturnSeen 防止恢复校验失败后在已退出 CPU 再发 VMMCALL。
- Intel ASM 已依赖 runtime/CPU 前缀偏移，新增字段置于尾部，不改变既有 offsets。SVM ASM 前缀字段逐项 C_ASSERT。
- root 路径预分配、每核 ring；metrics 只导出最新一致记录，完整 ring 从 KD 读取。64 位 AMD exit 不进入 Intel 96 项数组。
- NPT 完整 CPUID 范围，RAM WB/空洞 UC，先遍历精确计费，64 MiB 上限；>48 位明确拒绝。缓存合成与 native-return 仍需硬件验证。
- 两个宿主公开入口在 `tools/hvm_lab/`。首次基线/BCD 导出/所有权在 ProgramData；默认启动项不改，只设置一次性实验启动。-Check/-NoRestart，必须管理员。PendingReboot 不等于 LabHostReady，更不等于来宾 SVM 可用。
- 独立冷启动克隆已建立，路径在忽略的 `host.local.json`；尚未启动，guestOS 与干净关机快照未核验。不得恢复源 VM 挂起内存或修改源 VM。
- 仓库原自动证书出现 0x80096019 basic constraints。AMD 隔离候选使用 Sign-LabCandidate.ps1 的独立代码签名证书；仅签名写入已验证，克隆信任/驱动加载未验证，不给宿主导入该信任。
- 构建/逻辑检查与硬件进度见 `docs/next/ksword-amd-lab-status.md`。本机日志、SYS/PDB/CLI 与 identity.json 在 tools/hvm_lab 忽略目录，identity 脚本独立匹配 RSDS/PDB GUID/Age。
- 下一步：用户管理员运行 Enter-AmdLab -NoRestart，PendingReboot 后正常重启，-Check 确认 LabHostReady，再验证 VMware CPL0、来宾 Win10/SVM、KD/转储、单核、2/4/8 核与回滚。当前 agent 令牌未提升，不能自己改 BCD。
- 用户最新决定：今天不验证、不切换启动环境；收尾必要构建后创建本地 commit，不推送，然后执行 `shutdown -s -t 0`。明天再测试；没有安排自动启动实验或定时任务。
- 2026-09-18 首次管理员执行 Enter 报 `ManagementBaseObject` 无 `OpenObject`，发生在首次环境读取、任何 BCD 写入之前；本机尚无基线目录。已修复 OpenStore/OpenObject 的嵌入输出：按 FilePath 或 Id+StoreFilePath 键重新绑定 root/WMI ManagementObject，不依赖可能为空的 __PATH。Test-BcdBinding 用真实嵌入类型及 WMI schema 通过 8 项检查；策略 12/事务 21 项继续通过。实际管理员执行仍需用户重试，尚未进入 LabHostReady；不要重新关机，昨晚关机授权已执行完毕。
- 2026-09-18 后续：用户重试成功并重启，-Check=LabHostReady；agent 独立读取 HypervisorPresent=false/VBS=0，boot ID 2026-09-18T10:57:28.5000000Z。证据保存 tools/hvm_lab/artifacts/host-20260918。日常恢复方向尚未测试。
- 克隆已冷启动，按首轮测试设为 1 vCPU/8 GiB，原 VM 未动。vmware.log 明确 CPL0，加载 hv-svm.vmm/gphys-npt.vmm；Tools running，IP 192.168.172.130。Tools runtime guestInfo 报 Windows 10 Home 19042.631，尚需来宾内核实。
- 用户已确认克隆进入桌面、没有密码，后续不必等待登录确认。vmrun 匿名 captureScreen 被拒绝（需要 LoginInGuest），未尝试凭据登录；不得绕过登录或把凭据放命令行。可用 VIX SDK 在进程内安全登录已知账户，用户名还未获取。网络 PSSession 尚未建立。
- 克隆已挂只读 VMware 共享目录 KSwordLab -> tools/hvm_lab/artifacts/guest-bootstrap，包含 Prepare-Guest.ps1 与 lab-ownership.json；来宾路径 \\vmware-host\Shared Folders\KSwordLab。还没执行初始化、加载驱动、连接 KD 或 VMRUN。Get-KswordVmwareEvidence 的 $matches 与 PowerShell 自动变量冲突已修复为 $logLines，JSON 导出通过。
- 用户希望改用 GPT-5.6-Terra 继续测试以节省 token；只做必要检查。继续原测试目标，绝不将 CPL0 或 Tools 报告当成 KSword 硬件常驻通过。
- 2026-09-18 当前：hvm_lab/artifacts/guest-bootstrap 已包含签名候选、PDB、hvm_ctl、验收/负载脚本、manifest，以及新增 Bootstrap-GuestLab.ps1。后者 Inspect 只读核验克隆；Configure 必须来宾管理员且 Secure Boot=false，复制到 C:\KSwordLab\candidate，hash 核验、只导入克隆证书，再调用 Prepare-Guest Configure。Tools 对空密码 VIX 远程操作返回“不支持空密码”，故不能从宿主自动执行。用户需在已登录克隆的管理员 PowerShell 运行 \\vmware-host\Shared Folders\KSwordLab\Bootstrap-GuestLab.ps1 -Mode Inspect 并报告输出；不要直接 Configure，先确认 secureBoot。

双核阶段准备已完成：克隆正常关机后建立冷态快照 AMD-1CPU-20Cycles-PASS-20260918（listSnapshots确认1项），只修改克隆numvcpus=2/cpuid.coresPerSocket=2，内存仍8192MiB。重新冷启动，VMware日志NumVCPUs=2/MonitorMode=CPL0，KD初始断点已g，Tools running；共享已enable并重新设置readonly。KD在系统引导早期显示1 procs不代表最终拓扑，来宾runner会核验2逻辑处理器。下一步来宾Load-GuestCandidate后Invoke-GuestAcceptance -Vcpu 2 -Cycles 20；当前双核尚未运行KSword自检/常驻。

四核准备完成：正常关机后建立AMD-2CPU-20Cycles-PASS-20260918冷态快照（共2项），只改克隆numvcpus=4/coresPerSocket=4。已启动、KD初始断点g、Tools running。源共享KSwordLab只读；新增KSwordResults可写，仅指向仓库忽略的artifacts/guest-results。新增Export-GuestEvidence.ps1（PS5解析通过）选择实验运行/驱动加载日志逐文件SHA256核对后回传；不用密码。下一步用户运行export/load/四核100轮/export，四核硬件测试尚未执行。

八核准备完成：克隆四核正常关机后建立AMD-4CPU-100Cycles-PASS-20260918冷态快照（共3个）；numvcpus=8/coresPerSocket=8，内存8192MiB，VMware确认NumVCPUs8/CPL0。已冷启动，KD初始断点g，Tools running，两个共享保持源只读/结果可写。待用户运行Load后8核100轮加SoakSeconds7200；runner每25轮/每5分钟报告进度，结束再Export。当前尚未开始8核验收，不要把两小时列为已通过。

2026-09-18 用户调整优先级：不再把两小时压测作为当前阻塞项，要求立即推进AMD功能向Intel对齐，先提交当前进度且不推送。下一阶段授权实现嵌套SVM（含内层VM运行所需的VMCB/退出反射/NPT合成），不再受首期“不实现嵌套SVM”的范围约束。Win10、不换电脑、不推送仍有效。已确认硬件验收仍只记1/2核20轮、4核100轮；8核及压力未获结果，不补记成功。正在询问压力是否已启动，以便单独收尾，代码工作继续。
