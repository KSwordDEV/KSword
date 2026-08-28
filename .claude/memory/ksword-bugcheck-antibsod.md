# Anti-BSOD 参考实现（KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED）

按 Anti-BSOD 报告的反编译在 KSword 里加了一份算法级参考实现。**这不是可
上线的能力**：默认编译开关关闭，即使打开也依赖空签名表 fail-closed。用于
研究、教学、以及作为其它蓝屏模块对照的稻草人。

## 落点

- 协议：`shared/driver/KswordArkBugcheckIoctl.h`
  - `IOCTL_KSWORD_ARK_CONFIGURE_ANTIBSOD`（function code `0x8FF`）
  - 协议版本 `KSWORD_ARK_ANTIBSOD_PROTOCOL_VERSION = 1`
  - 确认令牌 `KSWORD_ARK_ANTIBSOD_CONFIRMATION_TOKEN = 'KAKB' = 0x424B414B`
  - 请求 `KSWORD_ARK_ANTIBSOD_REQUEST` / 响应 `KSWORD_ARK_ANTIBSOD_RESPONSE`
- 头声明：`KswordARKDriver/include/ark/ark_bugcheck.h`
  - `KswordARKAntiBsodInitialize/Uninitialize/IoctlConfigure`
- 实现：`KswordARKDriver/src/features/bugcheck/bugcheck_antibsod.c`
- 注册：`KswordARKDriver/src/dispatch/ioctl_registry.c`
- 生命周期：`KswordARKDriver/src/framework/driver_entry.c`
  - Initialize 在 Shield 之后调用；只准备同步原语和空签名表。
  - Uninitialize 在 Shield 之后、Control 之前调用；调用 UninstallLocked。
- 工程注册：`KswordARKDriver.vcxproj` 与 `.vcxproj.filters`
  已同步加入 `Source Files\Features\Bugcheck`。

## 编译开关

`KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED`：

- `0`（默认）：`Initialize/Uninitialize` 空操作，`IoctlConfigure` 返回
  `STATUS_NOT_SUPPORTED`。整个模块除三个符号外不引入任何行为。
- `1`：编译进完整实现。仍需 IOCTL 明确 INSTALL；未提供签名字节的情况下
  Install 走 fail-closed 分支返回 `STATUS_OBJECT_NAME_NOT_FOUND`。

Release 发行包默认使用 `0`。切换到 `1` 只用于研究环境。

## 与报告的对照

| 报告函数（Sample） | 参考实现 | 备注 |
|---|---|---|
| `FindWildcardBytePattern` | `KswordARKAntiBsodFindWildcardBytePattern` | 保留 0x00 通配符语义，额外校验 RangeEnd < RangeStart |
| `ResolveRipRelativeTarget` | `KswordARKAntiBsodResolveRipRelativeTarget` | signed 32-bit 位移 |
| `ReadUint32AtOffset` | `KswordARKAntiBsodReadUint32AtOffset` | Base=0 返回 0 |
| `AddOffsetIfNonNull` | `KswordARKAntiBsodAddOffsetIfNonNull` | 同上 |
| `SelectWindowsBuildProfile` | `KswordARKAntiBsodSelectWindowsBuildProfile` | 报告 5 段 build 区间；> 28000 时**拒绝**（样本继续） |
| `FindLoadedModuleTextRange` | `KswordARKAntiBsodFindNtoskrnlTextRange` | ZwQuerySystemInformation 类 11，296 字节步长，PE 头 + section 遍历 |
| `ClassifyBugcheckStackOrigin` | `KswordARKAntiBsodClassifyBugcheckStackOrigin` | RtlCaptureStackBackTrace 最多 64 帧，值 0/1/2 |
| `CapturePerCpuBugcheckState` | `KswordARKAntiBsodCapturePerCpuBugcheckState` | KeGetPcr()->NtTib.FiberData (KPCR+0x20)、KPCR+SecondaryOffset |
| `InstallBugcheckSuppressionHooks` | `KswordARKAntiBsodInstallLocked` | 9 级链式扫描 + fail-closed 校验 + IPI + 事件初始化 + SEH 写槽 |
| `SuppressBugcheckAllProcessorsHook` | `KswordARKAntiBsodSuppressAllProcessorsHook` | 分类=0 转原函数；分类>0 改私有状态、遍历 CPU、legacy 分支 100ms 后再写、CR8=0、终态调 KTHREAD 私有槽或永久等待 |
| `SuppressBugcheckCurrentProcessorHook` | `KswordARKAntiBsodSuppressCurrentProcessorHook` | 同上但只处理当前 CPU |
| `KeWaitForSingleObject(&event, ..., NULL)` | `KswordARKAntiBsodWaitForever` | 无限循环 KeWaitForSingleObject |
| DriverEntry-triggered install | 分离到 IOCTL | DriverEntry 只 Initialize；INSTALL 必须走 IOCTL |
| （样本无 Unload） | `KswordARKAntiBsodUninstallLocked` | 恢复原槽 + 释放 per-CPU 数组，SEH 包住写回 |

**参考实现相对样本增加的安全检查**（报告点名为样本"关键缺陷"）：

- Install 结束前对 8 个解析结果统一非零校验，任一为 0 直接返回失败；
- ZwQuerySystemInformation 双次调用之间校验 requiredBytes；
- PE 头解析前分别校验 MZ 与 PE 签名；
- OffsetToFileName 越界防御；
- ActiveProcessorCount 越界防御（> 2048 拒绝）；
- SEH 包住两个 hook 槽的写入并做失败回滚；
- HookExecutions 计数器让 Uninstall 遇到"有 CPU 仍在 hook 里"时返回 BUSY；
- 事件在 Install 完成后才 initialize，避免部分安装状态下被信号；
- Legacy stall 参数 100000µs = 100ms，与样本一致。

## 签名字节策略

参考实现**不带**下面这些数据：

- 五套 profile 的私有内核签名字节（每 slot 128 字节 × 9 slot × 5 profile）。
- ntoskrnl 私有全局的精确写入值（`BugcheckStateFlagPtr` = 0、
  `BugcheckInProgressFlagPtr` = 1、per-CPU 状态 = 0/1/5/34 这些常量已经
  按报告保留，但对应的 offset 需要签名解析出来）。

原因：报告作者也没有导出这些字节，KSword 也不导出。空签名 → `Length=0`
→ 每级扫描返回 0 → fail-closed。要让它真跑起来的两个前置条件都必须由
使用者自己完成：

1. 在同一台目标机上（或结构完全一致的 PDB 匹配环境）反编译 `ntoskrnl`
   得到 9 slot 的字节序列 + offset 参数；
2. 通过外部工具填入 `g_KswordArkAntiBsodProfiles[N]`；这一步既不通过
   IOCTL，也不通过磁盘文件——参考实现没有提供加载入口，任何"塞进去"
   都要在源码里显式修改。

## PatchGuard / HVCI 现实

即便有人补齐了签名并成功装上 hook：

- HVCI 打开时，`*(PVOID*)slot = ...` 走的是内核数据页，如果该私有槽本身
  被 hypervisor 强制只读则 SEH 会捕获访问违例，Install 失败回滚。
- PG 覆盖清单会周期扫描 `KiBugCheckOwner` 系列私有全局。虽然本模块没有
  改这些字段的地址、而是改它们里面的 DWORD 值，但值改动同样会被 PG 的
  内容抽样发现，触发 `0x109 CRITICAL_STRUCTURE_CORRUPTION`。
- 抑制路径命中后 CPU 永远停在 `KeWaitForSingleObject`，机器实际上死机；
  存储/DPC watchdog 后续会二次触发别的 bug check。

上述失败模式**是设计而非缺陷**：这份实现只用来复现报告里的算法结构，
不用来在生产内核上稳定运行。

## R3 交互摘要

- QUERY：无副作用，返回当前已发布的 state / mask / summary / lastStatus。
- PROBE：只读跑一遍完整扫描管线（选 profile → 找 ntoskrnl `.text` →
  9 级扫描），不装 hook、不分配 per-CPU。填充 `slotExpectedMask`、
  `slotHitMask`、`supportSummary`。不需要确认令牌。
- INSTALL：必须携带 `KAKB` 令牌 + `UI_CONFIRMED` flag，否则返回
  `CONFIRMATION_NEEDED`。走完扫描后仍会发布 mask/summary，然后依赖
  fail-closed 校验决定是否写槽。空签名下返回 `SIGNATURE_NOT_FOUND`。
- UNINSTALL：正常时返回 `INACTIVE`；仍有 hook 在跑时返回 `BUSY`。

## 透明化字段

响应固定长度，永不返回原始内核指针。字段：

- `stateFlags`：粗粒度状态位（`INSTALLED`、`HOOKS_ACTIVE`、
  `LEGACY_BUILD`、`PROFILE_SELECTED`、`MODULE_RANGE_RESOLVED`、
  `TARGETS_RESOLVED`、`PER_CPU_STATE_CAPTURED`、`SIGNATURES_EMPTY`）。
- `windowsBuildNumber`、`selectedProfileIndex`、`kthreadRoutineOffset`：
  当前系统身份与被选中的 build profile。
- `slotExpectedMask`：9 位，第 N 位=1 表示 profile 第 N slot 的 `Length`
  非零（即操作者已在源码里填入签名字节）。默认发行包全 0。
- `slotHitMask`：9 位，第 N 位=1 表示第 N slot 扫描后解析到非零地址。
- `supportSummary`：
  - `UNKNOWN` 未跑过 PROBE/INSTALL；
  - `UNSUPPORTED_BUILD` 当前 build 不在 5 段区间内；
  - `SIGNATURES_EMPTY` build 支持但签名全空（默认发行包状态）；
  - `PARTIAL_MATCH` 有签名但扫描漏掉部分；
  - `FULL_MATCH` 每条 expected 规则都命中。

Slot 索引（见 `KSWORD_ARK_ANTIBSOD_SLOT_*`）：

| Bit | 名称 | 用途 | 类型 |
|---|---|---|---|
| 0 | `BUGCHECK_ANCHOR` | KeBugCheckEx 附近锚点 | ADD |
| 1 | `BUGCHECK_CODE_START` | Bugcheck 私有代码区起点 | RIP |
| 2 | `BUGCHECK_CODE_END` | Bugcheck 私有代码区终点 | ADD |
| 3 | `STATE_FLAG_PTR` | 私有状态 DWORD 指针 | RIP |
| 4 | `KPCR_STATE_OFFSET` | KPCR→PRCB state 偏移 | READ |
| 5 | `KPCR_SECONDARY_OFFSET` | 二级 flag 偏移（可空） | READ |
| 6 | `INPROGRESS_FLAG_PTR` | in-progress byte 指针 | RIP |
| 7 | `ALL_HOOK_SLOT` | 全 CPU hook 槽 | RIP |
| 8 | `CURRENT_HOOK_SLOT` | 当前 CPU hook 槽 | RIP |

Slot 5 特殊：报告显示该字段在部分 build 上合法为 0；本实现在
`Length == 0` 的情况下不把它标为 miss，避免整体报 PARTIAL_MATCH。

## 与已有蓝屏模块的关系

| 模块 | 用途 | 是否改私有内核 | 是否需要签名 |
|---|---|---|---|
| `bugcheck` (BGP) | 绘制蓝屏诊断页 | 否 | 否 |
| `bugcheck_guard` | 一次性 KeBugCheckEx 延迟 | HVCI 关时补丁；开时用 callback | 否 |
| `bugcheck_shield` | 多阶段有界缓冲窗口 | 否 | 否 |
| `bugcheck_antibsod`（本条） | 私有槽 hook + 抑制 | **是**（当前模块唯一） | 是（外部提供） |

只有 Anti-BSOD 参考属于"改私有内核 + 依赖签名"路径；生产发行包不启用。
研究复现请在一次性 VM + 外部内核调试器 + 快照回滚的环境里操作，参考
`.claude/memory/ksword-bugcheck-bgp.md` 里对目标机复测的说明。

## 复测清单

编译开关关闭时（默认）：
- 加载驱动 → `IOCTL_KSWORD_ARK_CONFIGURE_ANTIBSOD` 任何 action 返回
  `STATUS_NOT_SUPPORTED`；registry 中该 IOCTL 存在但 handler 无副作用。

编译开关开启但签名为空：
- QUERY → `INACTIVE`，`SIGNATURES_EMPTY` 置位；
- INSTALL（带令牌）→ `SIGNATURE_NOT_FOUND`；state 里 `PROFILE_SELECTED`
  + `MODULE_RANGE_RESOLVED` 可置，`TARGETS_RESOLVED` 不置；
- UNINSTALL → `INACTIVE`。

编译开关开启并已由使用者补齐签名（不由 KSword 团队完成）：
- 后果不在本模块承诺范围内；请参照报告和 PG/HVCI 部分的现实说明。
