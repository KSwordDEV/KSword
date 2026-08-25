# SKT64 旧版功能对照

> 参考边界：仅使用公开仓库 `PspExitThread/SKT64` 的旧版内容，对照提交为 `461e41a278d93b8fb0f1f6cc4ea36453a0c783e7`。  
> 未访问、未反编译、未推断非公开 NextGen 仓库或二进制。  
> 判定方法：公开源码阅读 + 公开旧版 Release 二进制的静态菜单/字符串清单；不执行参考二进制。

## 结论

KSword 现有代码已覆盖公开 SKT64 旧版的大多数常规系统诊断、取证与管理功能面。本轮已独立实现并确认的增量是：

1. `IoTimer` 枚举，并超越旧版增加受控的启动/停止。
2. “结束进程并删除映像文件”，且使用 PID 创建时间与文件 ID 防止路径/PID 竞态。
3. 任意 `DriverObject.MajorFunction[]` 的查询、修改、事务恢复与放弃恢复记录，包括 KSword 自身、PnP、文件系统和安全关键驱动；保留对象身份、当前值、代次和 CAS 并发校验。
4. 任意 `DriverObject.DriverStart/DriverSize/DriverSection` 与对应 `KLDR_DATA_TABLE_ENTRY.DllBase/SizeOfImage` 的查询、事务修改和恢复，以及加载器链摘除、重新插入或放弃恢复；保留对象身份、事务代次、期望当前值、链邻居和真实加载器资源同步。
5. Intel EPT / AMD NPT 来宾可见交叉视图与 IOMMU 取证：CPUID/MSR、物理别名哈希、ACPI DMAR/IVRS、公开 IOMMU 接口及可选只读 MMIO。

仍不得写成“全部完成”的关键缺口包括：HVM 任意目标执行、完整 Nested VMX/eVMCS、PatchGuard/DSE 控制、驱动加载/卸载拦截、引导扇区保护、固件刷写/锁定，以及产品特定的安全软件禁用工作流。常驻 HVM 已提供 Intel-only 生命周期保护实现，但仍属于高风险实验能力。

## 功能面对照

| SKT64 旧版功能面 | KSword 对应实现 | 状态 |
|---|---|---|
| 进程枚举、树、结束/强制结束、挂起/恢复、关键进程、PPL、隐藏 | `ProcessDock/`、`ArkDriverClient/`、`KswordARKDriver/src/features/process/` | 已覆盖并扩展 |
| 结束进程后删除映像 | `ProcessDock/ProcessDock.cpp`、`ksword/process/ProcessImageDeleteGuard.*` | 本次补齐；精确文件句柄删除 |
| 线程、Token、句柄、模块、内存、注入 | `ProcessDock/`、`HandleDock/`、`MemoryDock/`、R0 thread/process features | 已覆盖并扩展 |
| 窗口、热键、KCT/窗口扩展信息 | `WindowDock/`、`KernelDock` 的 win32k 枚举页 | 已覆盖并扩展 |
| 驱动枚举/卸载、DriverObject、DeviceObject、MajorFunction、FastIo、完整性 | `DriverDock/`、`KernelDeviceDriverObjectsTab`、`KernelDriverDispatchEditorDialog`、driver integrity/unload/blind/dispatch features | MajorFunction 本轮补齐事务修改/恢复；其余已覆盖并扩展 |
| `IoTimer` | `KernelIoTimerTab.*`、`driver_object_query.c`、`io_timer_ioctl.c` | 本次补齐并超越 |
| SSDT / Shadow SSDT / Inline / IAT / EAT | `KernelDock/`、kernel hook/SSDT features | 已覆盖并扩展 |
| Timer/DPC、IDT/GDT、MSR/HAL/CPU 完整性 | `KernelTimerDpcTab`、`KernelDescriptorTableTab`、CPU/platform audit | 已覆盖并扩展 |
| EPT/NPT Hook 与 IOMMU 隐藏取证 | `KernelSlatIommuAuditTab`、`slat_iommu_audit.c` | 本轮补齐来宾可见只读取证；外层 SLAT 仍不可证明 |
| VT-x/EPT HVM 沙箱与目标执行 | `KernelHvmTab`、`features/hvm/` | 已有真实一次性 VMLAUNCH/VMCALL 自检与 Intel-only 受保护常驻 VMM；任意目标执行及完整 Nested VMX/eVMCS 未完成 |
| 驱动映像基址/大小修改与加载器链隐藏 | `KernelDriverImageEditorDialog`、`ArkDriverImage.cpp`、`driver_image_editor*.c`、共享协议 | 本轮补齐并超越；五字段事务、链摘除/恢复/放弃恢复 |
| 驱动加载/卸载拦截、引导扇区保护 | 现有卸载、storage forensics 仅覆盖相邻能力 | 未完成 |
| PatchGuard/DSE、固件刷写/锁定、产品特定禁用 | 现有平台/安全审计仅覆盖只读取证 | 未完成 |
| 进程/线程/镜像/注册表/Ob/ExCallback/文件系统回调 | `KernelDock` callback enumeration/interception 与 R0 callback features | 已覆盖并扩展 |
| Minifilter、标准过滤、WFP function/callout | callback/filter/network audit pages 与 R0 filter/network features | 已覆盖并扩展 |
| MmUnloadedDrivers、PiDDB、内核对象类型、系统线程 | unloaded-driver/PiDDB/object-type/thread audit pages | 已覆盖并扩展 |
| 内核/物理内存读写、页表、反汇编诊断 | `MemoryDock/`、R0 memory features、kernel executable-memory scan | 已覆盖并扩展 |
| 物理磁盘查看/镜像/恢复/编辑 | `HardwareDock/`、`FileDock/`、storage forensics 协议 | 诊断/取证/可回滚路径已覆盖 |
| 文件删除、强制解锁、占用查找、恢复 | `FileDock/`、R0 file feature | 已覆盖并扩展 |
| 服务、网络、注册表、启动项、PE/签名分析 | `ServerDock/`、`NetworkDock/`、`RegistryDock/`、`AutoStartDock/`、文件详情 | 已覆盖并扩展 |

## IoTimer 超越项

旧版公开 SKT64 的 IoTimer 菜单只能看到地址/对象并复制。KSword 的新实现增加了：

- 枚举全部公开 DriverObject 命名空间，通过 `DEVICE_OBJECT.Timer` 公开字段组建清单。
- 通过带引用的 `IoEnumerateDeviceObjectList` 快照核验设备，不直接解引用 R3 地址。
- 操作前同时比较 DriverObject、DeviceObject 和 PIO_TIMER 三重身份；任一变化都拒绝并要求刷新。
- 只调用 WDM 公开 `IoStartTimer` / `IoStopTimer`，不读写未公开 `_IO_TIMER` 布局。
- IOCTL 要求 `FILE_WRITE_ACCESS` 和 UI 确认令牌，但不因高级模式或风险等级拒绝修改。
- UI 有不可跳过的风险确认，以及包含精确 PIO_TIMER 地址的输入短语二次确认。
- 明确告知 WDM API 返回 `VOID`；成功仅表示 API 已调用，不伪造不存在的“已验证运行态”。

## 修改能力与风险准则

KSword 对修改能力采用“告知风险、用户决定”的准则：风险等级本身不构成功能封锁条件。用户确认后，操作不会再被高级模式或产品策略拒绝。

协议版本、缓冲区长度、调用方访问权限、目标存在性、对象归属、PID 创建时间、文件 ID 和修改前快照等校验仍然保留。这些校验用于确保修改落在用户实际选择的对象上，防止 PID/地址复用或竞态误伤，不属于基于风险的功能限制。

## MajorFunction 事务编辑器

- R3 只能通过 `ArkDriverClient` 使用共享协议；Dock 不直接调用 `DeviceIoControl`。
- R0 重新解析规范化 DriverObject 名称，返回当前 28 个 MajorFunction 指针、对象身份和事务代次。
- 修改要求用户明确确认，并比较期望 DriverObject、期望旧指针与期望代次；并发变化返回冲突，不会静默覆盖新值。
- 成功修改后保留原始值，可按事务恢复；恢复同样检查当前值，避免把第三方后续修改覆盖掉。
- 不根据驱动类别限制目标，因此错误地址可立即蓝屏、破坏 I/O、切断恢复通道或留下悬空指针；UI 对此持续告知风险。

## DriverObject / KLDR 镜像与加载链事务编辑器

- R3 只能通过 `ArkDriverClient` 使用共享协议；Dock 不直接调用 `DeviceIoControl`。
- 同一事务可选择修改 `DriverStart`、`DriverSize`、`DriverSection`、`DllBase` 和 `SizeOfImage`；两个大小字段按其原生 32 位宽度解析，其余指针值不设类别或数值策略限制。
- 首次绑定同时核验精确 DriverObject/名称、`DriverStart == DllBase` 或 `DriverSection == KLDR` 条目地址，并冻结对象引用、规范名称和原始模块基址；因此改写 `DriverStart` 后仍可通过对象身份重新打开记录。
- 加载链操作使用实时导出的 `PsLoadedModuleList` 与 `PsLoadedModuleResource`，并用 DynData 的加载链 RVA 交叉核验；修改链表时获取真实 `ERESOURCE` 排他锁。
- 字段修改先对全部所选字段执行期望当前值与代次 CAS，再整体写入；中途失败按逆序回滚，并分别保留原始值和本次应用值。
- 摘链前核验前后节点互相指回目标及请求携带的期望邻居，随后将条目自环；恢复只在当前值仍等于事务应用值时回写字段，链邻居仍相邻时回原位，否则插入当前链尾，第三方冲突会被保留并返回证据。
- 记录持有 DriverObject 引用；存在活动记录时阻止强制卸载，驱动卸载阶段执行尽力恢复并释放引用。放弃记录会明确保留已应用字段或隐藏状态。
- 不因 KSword 自身、PnP、文件系统、安全关键驱动或值风险拒绝操作；UI 始终告知蓝屏、PatchGuard、I/O/符号/崩溃转储失效和不可恢复悬空链风险，并要求逐次显式确认。

实现的对象与同步语义按公开一手资料核对：

- [Microsoft DRIVER_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object)
- [Microsoft ExAcquireResourceExclusiveLite](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquireresourceexclusivelite)
- [Microsoft RemoveEntryList](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-removeentrylist)

## EPT/NPT 与 IOMMU 只读取证

- 同时识别 Intel VMX/EPT 与 AMD SVM/NPT，并记录 Hypervisor CPUID 厂商与 CPUID 时延分布。
- 对多组已导出内核例程执行两次虚拟读取、两次物理别名读取和哈希比较，区分不一致与读取不稳定。
- 校验并有界解析 ACPI `DMAR` / `IVRS`，列出 DRHD/RMRR/ATSR/RHSA/IVHD/IVMD、保留内存和畸形结构。
- 动态查询公开 `IoGetIommuInterface` / `IoGetIommuInterfaceEx`；用户可选择额外只读采样 Intel VT-d 或 AMD IOMMU MMIO 状态。
- 明确边界：外层 Hypervisor 控制的 EPT/NPT 对来宾不可见。哈希一致只能说明来宾当前可观察视图一致，不能证明不存在 execute-only 或按访问类型切换的 Hook。

实现按公开一手资料核对寄存器和 API 语义：

- [Intel VT-d Architecture Specification](https://www.intel.com/content/www/us/en/content-details/868911/intel-virtualization-technology-for-directed-i-o-architecture-specification.html)
- [AMD I/O Virtualization Technology (IOMMU) Specification](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/specifications/48882_IOMMU.pdf)
- [Microsoft IoGetIommuInterfaceEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetiommuinterfaceex)
- [Microsoft MmCopyMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory)

## 验证

- 新增共享协议仅位于 `shared/driver/`，驱动分发仅通过 `ioctl_registry.c` 注册；镜像事务 IOCTL 为 `METHOD_BUFFERED + FILE_WRITE_ACCESS`，SLAT/IOMMU 查询仍为 `METHOD_BUFFERED + FILE_ANY_ACCESS` 的只读固定响应。
- IOCTL 审计确认 153/153 个共享定义均已注册、0 个遗漏；风险启发式报告 14 条高风险和 2 条中风险项。
- 中英语言包审计通过（18,497 条源码字符串）。
- `KswordARKDriver` `Release|x64` 编译/链接通过；未安装或加载驱动。
- `Ksword5.1` `Release|x64` 编译/链接通过。
