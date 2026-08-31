# 第二规划：Windows 内核知识板块与 Ksword 研究补全图

## 1. 目标与判断方法

本规划面向几乎没有 Windows 内核基础的中文读者。目标不是把私有结构字段堆成名词表，而是让读者能回答四个问题：这个对象是什么；谁创建、谁拥有、何时销毁；它如何与相邻对象连接；Ksword 的某个只读结果究竟证明了什么、又不能证明什么。

仓库已经有大量内核能力：进程/线程 Cross-View、`PspCidTable`、句柄与对象摘要、页表和物理内存、回调/Minifilter、驱动对象、WFP/NDIS、ALPC、Win32k、存储、设备栈、代码完整性等，主要落在 `KswordARKDriver/src/features/`、`shared/driver/` 和 `ArkDriverClient/`。这不等于对应知识已经被讲清。本规划把“功能已存在但概念链缺失”列为必讲，而不是只列尚未有 IOCTL 的功能。

每一专题统一采用以下写法：

1. 用对象关系图开始，先画出输入、核心对象、所有权和结果。
2. 解释首次出现的缩写、结构、句柄、地址、引用与运行上下文。
3. 给出只读、受限、可复现的观察路径；区分公开 API、文档化内核 API、PDB/DynData 证据和运行时推断。
4. 说明版本差异、权限、IRQL、锁、引用计数、并发和失败状态。
5. 先给正确处理，再给最小错误处理；不把危险写操作作为常规教学路径。

状态标记：`[已有]` 表示仓库原先已有相应只读能力；`[已有但必须重讲]`、`[已有但需重讲]` 表示底层能力已存在且知识解释已补齐；`[已实现]` 表示本轮已经补成共享协议、R0 证据编排、R3 严格解析、知识正文与可达业务页面组成的完整观察链。运行机器缺少符号、权限、硬件或对应子系统时，界面必须如实显示 unsupported、partial、budget 或 unavailable，不得伪造完整结果。

---

## 2. 先修基础：所有内核专题共享的前置知识

### 2.1 Windows 的层次、地址和执行权

- `[已实现] 用户态、内核态、系统调用、ntdll、Win32 子系统、服务进程、驱动的完整调用链`：解释“谁能调用谁”，不能把 Ring 0 简化成“权限更高”。
- `[已实现] 虚拟地址、物理地址、内核地址、用户地址、RVA、文件偏移`：同一个数值在不同坐标系中的含义，指针不等于可安全读取的内存。
- `[已实现] HANDLE、对象指针、伪句柄、内核句柄、引用计数、所有权转移`：所有后续 API/IOCTL 的共同语法。
- `[已实现] NTSTATUS、Win32 错误码、HRESULT、最后错误码`：错误码来源、成功族、何时可读取 `GetLastError`。
- `[已实现] IRQL、线程上下文、PASSIVE_LEVEL、APC_LEVEL、DISPATCH_LEVEL`：为何某些查询能睡眠、哪些不能，为什么“在任意地方调用 API”是错误前提。
- `[已实现] 同步原语全景`：自旋锁、互斥体、快速互斥、ERESOURCE、推锁、事件、信号量、等待、内存屏障和原子操作的职责边界。

### 2.2 驱动怎样活着

- `[已实现] 驱动加载到卸载`：PE 映像、`DriverEntry`、`DRIVER_OBJECT`、`DEVICE_OBJECT`、符号链接、服务项、PnP 与非 PnP 驱动的不同生命周期。
- `[已实现] WDM 与 KMDF`：IRP 分发、队列、请求对象、回调、引用和清理机制；解释为什么 Ksword 使用 WDF 控制设备仍需理解 I/O 管理器。
- `[已实现] IOCTL 完整链`：`CTL_CODE`、设备类型、功能号、METHOD_BUFFERED/DIRECT/NEITHER、访问掩码、输入输出长度、`DeviceIoControl` 到 WDF request 的边界。
- `[已实现] 调试与崩溃转储基础`：KD、WinDbg、符号、PDB、断点、BugCheck、dump 类型、不要在生产机上做破坏性调试。

---

## 3. 对象管理器：最应优先补齐的板块

### 3.1 对象、名称和命名空间

- `[已实现] Object Manager 总图`：对象类型、对象头、类型对象、对象目录、命名对象、无名对象、引用计数、句柄表之间的关系。
- `[已实现] 目录对象专题`：`\`、`\Device`、`\Driver`、`\FileSystem`、`\KnownDlls`、`\RPC Control`、`\BaseNamedObjects`、会话命名空间分别由谁使用；目录枚举结果的权限与瞬时性。
- `[已实现] 符号链接专题`：内核符号链接、`\DosDevices`、盘符、卷 GUID、对象管理器路径、Win32 路径转换；避免把 reparse point 与对象符号链接混为一谈。
- `[已实现] _OBJECT_HEADER 深解析`：PointerCount、HandleCount、TypeIndex、NameInfo、CreatorInfo、SecurityDescriptor 等可选头的版本差异；必须使用 PDB/DynData 标示证据来源。
- `[已实现] 安全描述符与对象访问检查`：SID、DACL、SACL、GenericMapping、特权、令牌、`SeAccessCheck` 的概念流程。

### 3.2 句柄表与 CidTable：独立重点专题

`PspCidTable` 已在进程 Cross-View 和内核对象审计中使用，必须从“PID 表”这种错误俗称中解救出来。

1. `[已有但必须重讲] PspCidTable 是什么`：它是内核维护的一个句柄表根，CID（client ID）空间把进程 ID、线程 ID 映射到进程/线程对象；它不是进程链表，也不是用户态进程列表。
2. `[已实现] PID、TID、HANDLE、CLIENT_ID、EPROCESS、ETHREAD 的五对象关系`：同一个数字何时是 ID，何时是句柄值，何时需要引用对象。
3. `[已有但必须重讲] HANDLE_TABLE / TableCode`：编码根指针、层级、页状表项、表项如何指向对象；只解释读取和校验，不教授修改表项。
4. `[已实现] 三视图交叉验证`：`PsActiveProcessHead`、`PspCidTable`、公开进程快照、线程所有者之间的差异；退出竞争、PID 复用、权限限制、损坏与隐藏各自留下什么证据。
5. `[已实现] 进程句柄表与全局 CID 表的区别`：每进程 `ObjectTable`、继承/复制/关闭句柄、内核句柄标志、`ExHandleTable` 不能与 `PspCidTable` 混写。
6. `[已实现] 可视化设计`：表中必须展示来源、对象类型校验、是否成功引用、创建时间、差异分类、预算截断和 DynData 版本；不把“CID 可见”直接标成恶意。

---

## 4. 进程、线程、调度与执行

- `[已有但必须重讲] EPROCESS / KPROCESS / ETHREAD / KTHREAD`：公开指针类型与私有布局的边界；进程地址空间、令牌、对象表、活动链、线程链分别属于谁。
- `[已实现] 创建与退出链`：`CreateProcess` 到 `PsSetCreateProcessNotifyRoutineEx`、映像加载、首线程、退出、对象最后释放的顺序；为什么回调不能代替进程快照。
- `[已实现] 调度器基础`：优先级、量子、就绪队列、处理器组、CPU 亲和性、理想处理器、上下文切换；区分统计信息与调度决策。
- `[已实现] Dispatcher objects`：事件、互斥体、信号量、定时器、等待块、`KeWaitFor*` 的对象模型。
- `[已实现] APC / DPC / Work Item`：用户 APC、内核 APC、特殊 APC、DPC、工作线程的执行时机和 IRQL；它们不是可互换的“异步函数”。
- `[已实现] 进程附加与地址空间切换`：`KeStackAttachProcess`、`KAPC_STATE`、引用、异常路径、禁止在附加期间做什么。
- `[已实现] Session、Silo、AppContainer、Pico/WSL`：会话隔离、作业、容器、Silo、Pico provider 与普通进程的关系。

---

## 5. 内存管理：从页表到真实证据

- `[已有] 四级页表与大页`：CR3、PML4E/PDPTE/PDE/PTE、NX、RW、US、Global、PFN、2 MB/1 GB 页；补充 LA57 为何不能假定所有机器均是四级。
- `[已实现] 页错误与工作集`：软/硬页错误、working set、standby/modified/zeroed/free 页面、内存压缩、trim，不把“物理内存占用”误读为私有内存。
- `[已实现] VAD 树`：Virtual Address Descriptor、`MEM_PRIVATE/MEM_IMAGE/MEM_MAPPED`、保护位、提交/保留、`VirtualQuery` 与内核 VAD 的证据边界。
- `[已实现] PFN 数据库`：物理页帧、引用/共享计数、页位置、反向映射；只读观测的版本风险。
- `[已实现] Section / ControlArea / Subsection / Prototype PTE`：文件映射、映像映射、写时复制、删除后映像、缓存与页面回收的对象关系。
- `[已实现] MDL 与 DMA`：MDL 不是内存本身；锁页、映射、散布/聚集、DMA adapter、IOMMU/DMA protection。
- `[已有但需重讲] Pool`：paged/nonpaged pool、pool tag、quota、Special Pool、pool overrun、释放与泄漏证据；不要从 tag 名直接推断归属。
- `[已有] 内核可执行内存证据`：模块节、RWX/RX private、Big Pool、System PTE、MDL 类证据、预算/partial；另设“证据强度而非判定恶意”专题。

---

## 6. I/O 管理器、文件系统与存储

- `[已实现] IRP 全生命周期`：创建、栈位置、Major/Minor function、向下传递、completion routine、pending、cancel routine、MDL、缓冲方式和完成顺序。
- `[已实现] DRIVER_OBJECT / DEVICE_OBJECT / FILE_OBJECT`：设备栈、AttachedDevice、StackSize、MajorFunction、Fast I/O、FileObject 与用户 HANDLE 的关系。
- `[已有] Filter Manager / Minifilter`：Filter、Instance、Volume、Altitude、pre/post callback、context、communication port、bypass 的安全边界。
- `[已实现] Cache Manager 与 Memory Manager 协作`：cached/non-cached I/O、lazy writer、section object pointers、oplock、lease、文件删除挂起。
- `[已有但需重讲] NTFS/FAT/exFAT`：卷、分区、MFT、attribute、runlist、USN journal、reparse point、ADS、bitmap；明确原始卷读取和文件系统逻辑视图不同。
- `[已实现] 存储栈`：卷管理器、MountMgr、磁盘、分区、类/端口/miniport、Storport、NVMe、BitLocker filter、FVE 元数据与密钥材料绝对隔离。
- `[已实现] 网络文件系统与重定向器`：MUP、RDBSS、MRxSmb、WebDAV、UNC 路径、缓存一致性；SMB 专题不应被文件句柄专题替代。

---

## 7. 注册表与配置管理器

- `[已有] 键和值的安全查询、枚举和只读/受控修改`；配套讲 `HKLM/HKCU` 与实际 hive、配置单元、控制集、WOW64 视图。
- `[已实现] Configuration Manager 内部模型`：Hive、bin、cell、key node、value cell、索引、缓存、脏页和 flush；区分注册表路径与 hive 文件偏移。
- `[已实现] 注册表回调`：`CmRegisterCallbackEx`、pre/post 通知、操作类、对象名解析、回调上下文、重入与 IRQL 边界。
- `[已实现] 注册表事务与恢复`：KTM、CLFS、日志、延迟写、崩溃恢复；不要把 RegSetValue 成功等同于已永久写入介质。

---

## 8. 安全、身份和可信执行

- `[已实现] Token 全图`：用户 SID、组、特权、完整性级别、限制 SID、AppContainer capability、会话、默认 DACL、Primary/Impersonation token。
- `[已实现] LSA、LSASS、SAM、Kerberos、NTLM`：认证、授权、凭据存储和安全包的边界；不把“读取令牌”与“读取凭据”混为一谈。
- `[已有但需重讲] PPL/PP、保护签名等级`：保护等级、签名、访问检查、可观察与可修改的边界、版本差异。
- `[已有] Code Integrity / Secure Boot / ELAM / WDAC / AppLocker`：启动信任链、签名验证、策略、审计/强制模式。
- `[已有] VBS / HVCI / Secure Kernel / Hyper-V`：VTL、Hypervisor、IOMMU、Credential Guard、KVA shadow；“检测已开启”与“读取私有安全内存”是两件事。
- `[已实现] PatchGuard 专题`：保护对象类别、触发的不确定性、为何检测页必须只读、禁止把规避作为工程目标。

---

## 9. 网络、IPC 与图形子系统

- `[已实现] Windows 网络层图`：NDIS miniport/filter、TCPIP、WFP、ALE、AFD、NSI、Winsock、RPC；每层看到的对象、时间点和归属不同。
- `[已有] WFP/NDIS`：callout、filter、sublayer、layer、net buffer list、adapter/filter chain；补充事务与卸载顺序。
- `[已实现] AFD/NSI`：endpoint、连接状态、owner PID、控制块和版本风险；R0 研究证据、TCP/UDP endpoint 与 NDIS 链并列呈现，任何 fallback 都明确标注来源，不能冒充 R0 私有结构深审计。
- `[已有但需重讲] LPC/ALPC`：port、connection port、communication port、消息、section view、句柄传递、server 生命周期。
- `[已实现] Pipe、RPC、COM、共享内存`：Named Pipe、mailslot、RPC endpoint、COM server、section mapping 的命名空间和安全模型。
- `[已实现] Win32k / GUI 内核边界`：window station、desktop、session、GUI thread、USER/GDI handle、hook/hotkey；把公开窗口枚举与 win32k 内部证据并排解释。

---

## 10. PnP、硬件、固件与电源

- `[已实现] PnP 状态机`：devnode、PDO/FDO/filter、IRP_MN_START_DEVICE/REMOVE_DEVICE、资源仲裁、重平衡、设备接口和 SetupAPI 视图。
- `[已有但需重讲] 设备栈审计`：Upper/Lower Filter、driver service、设备对象链、功能/总线过滤器的来源与风险解释。
- `[已实现] ACPI/PCI`：ACPI namespace、AML、PCI config space、BAR、MSI/MSI-X、IOMMU；只读硬件枚举的权限边界。
- `[已有] USB/HID/输入栈`：hub topology、composite device、kbdclass/mouclass/HID、filter；明确不采集键盘鼠标内容。
- `[已实现] GPU/display/TDR`：dxgkrnl、WDDM、显存管理、watchdog/TDR、display path；与普通设备栈的不同。
- `[已实现] 电源管理`：PoFx、device power state、system sleep、modern standby、wake source；设备“消失”的时序解释。

---

## 11. 可观测性、回调、Hook 与取证边界

- `[已有] 进程、线程、映像、注册表、对象回调`：注册接口、回调时机、上下文、移除安全和模块归属；区分已注册回调与实际触发记录。
- `[已有] Minifilter/WFP/NDIS 外部回调`：拥有者、卸载顺序、enumeration source、不可用状态。
- `[已有] SSDT、Shadow SSDT、inline、IAT/EAT、DriverObject dispatch`：地址归属、原始字节、合法热补丁/第三方防护的假阳性、只读证据优先。
- `[已实现] IDT/GDT/MSR 与 CPU 控制状态`：每核状态、虚拟化影响、固件/Hypervisor 证据；避免用单核快照宣布全系统结论。
- `[已实现] ETW、WPP、DbgPrint、Event Log`：provider、session、buffer、lost events、实时消费者、格式化元数据和隐私。
- `[已实现] 时间与证据链`：QPC、system time、FILETIME、boot time、PID reuse、snapshot time、hash、source confidence、partial/budget 标记。

---

## 12. 建议实施顺序

### P0：先让读者看懂现有 Ksword 输出

1. 基础执行模型、地址、IRQL、引用与错误码。
2. Object Manager、句柄表、`PspCidTable`、进程/线程 Cross-View。
3. 页表、VAD、Section/ControlArea、Pool、MDL。
4. IRP、设备栈、DriverObject、FileObject、Minifilter。
5. Token、对象访问检查、PPL、CI/VBS。

### P1：把已有审计能力变成完整证据链

1. 注册表 Configuration Manager、回调和事务。
2. WFP/NDIS/AFD/NSI、ALPC/Pipe/RPC/COM。
3. PnP/ACPI/PCI、USB/HID、GPU/TDR、电源。
4. 回调、ETW/WPP、Hook 检测的来源/置信度/假阳性。
5. `MmUnloadedDrivers`、PiDDB、对象头深字段、ControlArea 和 SMB 专项的 PDB schema。

### P2：研究型专题

1. PFN、working set、内存压缩、DMA/IOMMU。
2. Secure Kernel、VTL、VMBus/vSwitch/vPCI/HvSocket。
3. dxgkrnl/dxgmms2 私有对象、网络 AFD/NSI 私有结构、SMB redirector。
4. 崩溃转储、KD 扩展、内核时间线与跨来源证据关联。

## 13. 完成定义

一个板块只有同时具备“概念关系图、对象生命周期、公开与私有边界、只读观察路径、版本/权限/IRQL限制、错误示范、Ksword 结果字段解释、证据不能证明什么”才可标为完成。仅能枚举一个结构或已有一个 IOCTL，不算知识板块完成。

## 14. 实施状态（2026-08-23）

- 主程序 `KernelDock` 已新增“内核知识”页，按本规划顺序收录 12 类、71 个专题；中文与英文语言包均提供标题、摘要和完整正文。
- 71 篇正文都具备完成定义要求的八个固定板块，并以关系图开篇；`tools/validate_kernel_knowledge.py` 会校验目录、双语键、板块顺序、关系图和只读路由，防止后续遗漏。
- 页面支持全文检索、按底层能力覆盖度筛选、上一篇/下一篇、复制全文、Microsoft Learn 官方参考，以及跳转到当前 `KernelDock` 已有观察页。
- 站内跳转只负责切换页签和完成既有页面的惰性初始化，不模拟刷新或动作按钮，也不触发修复、摘除、写入或其它修改；目标页仍可按自身生命周期执行首次只读加载。
- 原规划的 15 个摘要覆盖专题与 37 个缺口专题现均已接入版本化的 `IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC`：共享头固定 71 个专题 ID，R0 返回请求上下文、处理器、精确系统时间、QPC、WDF/WDM 对象链和已注册业务 IOCTL 映射，R3 对协议版本、长度、保留字段、行类型及 NUL 终止进行严格校验，知识页可异步采集当前专题的实时证据并跳转到实际业务页面。
- “已实现”表示专题从共享协议、R0 handler、中央注册表、R3 wrapper 到 UI 已形成真实可调用链，并且每个专题至少关联一个已注册业务 IOCTL；它不表示任意 Windows 版本、硬件与权限环境都必然返回全部私有证据。运行时的 unsupported、partial、truncated、budget 和来源限制属于协议结果，必须原样保留。
- macOS 静态校验负责验证 71 个 ID/映射同序、180 个 IOCTL 定义与注册闭环、工程文件、双语正文及路由；Windows MSVC/Qt/WDK 构建由推送后的 CI 验证。未签名驱动的实际加载和逐机运行态仍需在隔离 Windows 测试机完成，不能由编译成功替代。
