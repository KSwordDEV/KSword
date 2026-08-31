# 蓝屏缓冲 Shield（PatchGuard-safe）

Bugcheck Shield 是 `bugcheck_guard.c` 之外的第二种缓冲后端。灵感来自公开逆向报告
（例如 `Disable-PatchGuard-BSOD.sys`）：这些样本通过签名扫描私有 ntoskrnl 函数
指针槽、写入自制 hook 并永久等待未置位事件来吞掉 bugcheck。该做法会触发
PatchGuard/HVCI/WHQL 拒绝，且失败后系统处于不可恢复内核状态。Shield 只保留
"扩大蓝屏与重启之间可观测窗口" 这个动机，实现仅使用公开 API。

## 落点

- 协议：`shared/driver/KswordArkBugcheckIoctl.h`
  - `IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD`（function code `0x8FE`）
  - 协议版本 `KSWORD_ARK_BUGCHECK_SHIELD_PROTOCOL_VERSION = 1`
  - 确认令牌 `KSWORD_ARK_BUGCHECK_SHIELD_CONFIRMATION_TOKEN = 'KSHL' = 0x4C48534B`
  - 请求 `KSWORD_ARK_BUGCHECK_SHIELD_REQUEST`、响应 `KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE`
  - 时间轴条目 `KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRY`，环容量 16
- 头声明：`KswordARKDriver/include/ark/ark_bugcheck.h`
  - `KswordARKBugcheckShieldInitialize/Uninitialize/IoctlConfigure`
- 实现：`KswordARKDriver/src/features/bugcheck/bugcheck_shield.c`
- 注册：`KswordARKDriver/src/dispatch/ioctl_registry.c`（前向声明 + 表项）
- 生命周期：`KswordARKDriver/src/framework/driver_entry.c`
  - Initialize：`KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED` 分支内，`Guard` 之后
  - Uninitialize：卸载路径，`Guard` 之后，`Control` 之前
- 工程注册：`KswordARKDriver.vcxproj` 与 `.vcxproj.filters`
  已同步加入 `Source Files\Features\Bugcheck`。

## 安全边界

- 仅使用公开 API：`KeRegisterBugCheckCallback` 与 `KeRegisterBugCheckReasonCallback`
  （`KbCallbackSecondaryDumpData`、`KbCallbackDumpIo`、`KbCallbackAddPages`）。
- 绝不修改 ntoskrnl 代码、私有函数指针槽、SSDT/IDT/GDT、CR0/CR4/CR8、MSR、
  KPCR/KPRCB/KTHREAD 私有偏移，也不解析未文档化的 build-specific 结构。
- 绝不永久等待任何事件；每个回调仅执行有界 `KeStallExecutionProcessor` 循环。
- DriverEntry 只初始化同步原语；未收到 R3 IOCTL 前没有任何回调被注册。
- 卸载与 DISABLE 都会先撤销 `Enabled` 再逐个 `KeDeregisterBugCheckCallback`/
  `KeDeregisterBugCheckReasonCallback`，通过 `Executions` 计数器排空回调，
  未排空则返回 `STATUS_DEVICE_BUSY`（`KSWORD_ARK_BUGCHECK_SHIELD_STATUS_BUSY`）。

## 缓冲预算

- 每回调阶段最大 `KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS = 8` 秒。
- 单次 ENABLE 全局总额最大 `KSWORD_ARK_BUGCHECK_SHIELD_TOTAL_MAX_SECONDS = 16` 秒。
- 默认 stage 3 秒、total 10 秒。
- 全局剩余毫秒由 `RemainingBudgetMs`（CAS 循环）跨回调共享，防止不同回调总
  时长超过 total；无余额时该阶段直接跳过 stall，仍写入 timeline。
- Stall 循环粒度 50µs，用 `KeQueryInterruptTime` 判定截止时间。

## 时间轴

- 环形数组 `Timeline[16]`，条目 `{reason, bugcheckCode, cpu, stalledMilliseconds}`。
- `TimelineNextIndex` 由 `InterlockedIncrement` 分槽；超出容量的回调被丢弃但
  仍完成 stall（防止 R3 观察到不匹配的分配）。
- `TimelineCommittedCount` 只在字段写入完成后递增，读端据此确定可读前缀。
- `bugcheckCode` 字段目前恒为 0：公共回调没有直接暴露 bug check code。字段保留
  以便未来 kernel 暴露该值时可以扩展。

## 请求校验

- 版本、size 精确匹配当前协议。
- 保留字段必须为 0；未来版本可安全扩展。
- flags 只允许 `KSWORD_ARK_BUGCHECK_SHIELD_FLAG_UI_CONFIRMED`。
- action：QUERY / ENABLE / DISABLE。
- ENABLE 必须同时携带 `KSHL` 令牌与 UI_CONFIRMED 标志；否则返回
  `CONFIRMATION_NEEDED`。
- `reasonMask` 必须非零且不含 `~KSWORD_ARK_BUGCHECK_SHIELD_REASON_ALL`。
- stage/total seconds：0 视为使用默认值；超过上限时钳制；stage > total 时
  钳到 total。

## 时间轴 reason 编码

- `0x1` CLASSIC — `KeRegisterBugCheckCallback` 触发
- `0x2` SECONDARY_DUMP_DATA — `KbCallbackSecondaryDumpData`
- `0x4` DUMP_IO — `KbCallbackDumpIo`
- `0x8` ADD_PAGES — `KbCallbackAddPages`
- `0x0` 表示 kernel 触发了未订阅的 reason（记录进 timeline 用于诊断，不 stall）。

## 与已有蓝屏模块的关系

| 模块 | 用途 | 是否改私有内核 | 触发次数 |
|---|---|---|---|
| `bugcheck` (BGP/panel) | 绘制蓝屏诊断页 | 否，仅公开 BGP 加载期解析 | 每次崩溃 |
| `bugcheck_guard` | 一次性 KeBugCheckEx 延迟 | HVCI 关时可直接补丁，HVCI 开时用 callback | 一次 |
| `bugcheck_shield`（本条） | 多阶段有界缓冲窗口 | 否，仅公开 reason 回调 | 每次崩溃 |

Guard 与 Shield 可以并存：Guard 关注 "延迟 KeBugCheckEx 本身"，Shield 关注
"在标准 bugcheck 流程的多个阶段各留一段可观察窗口"。ENABLE 冲突由各自的
`STATUS_ALREADY_REGISTERED` 语义保证。

## 复测清单

- `IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD` QUERY → 应返回 INACTIVE，
  state=0，timeline 空。
- ENABLE 缺 UI 确认或错误令牌 → `CONFIRMATION_NEEDED`，不注册任何回调。
- ENABLE 合法 → `ACTIVE`，state 包含请求的 `*_REGISTERED` 位。
- ENABLE 重复 → `STATUS_ALREADY_REGISTERED` 映射为 `ACTIVE`。
- DISABLE → `INACTIVE`；如同一 CPU 上仍有回调在执行 → `BUSY`（应仅在人为
  实验下出现，正常崩溃路径系统已不返回）。
- 人为在测试机触发一次可控 bugcheck（例如 NotMyFault），返回 R3 后 QUERY 应
  显示 `fireCount > 0`、`FIRED` 位为真，`timelineCount > 0`，条目 `reason`
  值属于订阅集，`stalledMilliseconds` 各阶段和 ≤ totalSeconds*1000。

## 边界与不做的事

- 不承担蓝屏抑制：Shield 从不改变 bug check code、参数或返回路径，Windows
  仍按正常流程写转储并重启。
- 不承担 dump 数据写入：SecondaryDumpData/DumpIo/AddPages 回调不填充 OutBuffer；
  如需向 dump 追加数据，另行走 `bugcheck` 模块的 SecondaryDumpData 通道。
- 不做栈来源分类：报告样本用 `RtlCaptureStackBackTrace` 判断是否位于私有
  bugcheck 代码区间以选择性抑制。这依赖未文档化的内核代码范围解析，Shield
  故意不复刻。
- 不做 IPI 采集每 CPU 状态：Shield 只关心当前回调 CPU，不去枚举其它 CPU 的
  私有 KPCR/KPRCB 布局。
