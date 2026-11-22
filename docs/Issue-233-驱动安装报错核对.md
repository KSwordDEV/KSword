# Issue #233：驱动安装报错逐项核对

核对日期：2026-11-22。范围为 Qt 主程序的真实 SCM 驱动加载失败入口；不代表 Launcher、Light 或任意第三方安装器均已覆盖。源码、测试、完整构建、实际系统修改和官网上线分别记录，不以文档替代产品实现。

本轮纠正：上一版错误地将 577/1275/1260 合并到新弹窗，反而遗漏 issue 截图中的 **4551（ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION）**。上一版 168 项测试不能证明错误码分流正确。本次仅将 4551 接入新弹窗，577/1275 的主窗口签名弹窗及驱动页原有报错处理均恢复原样；1260 也不接入新弹窗。

## 原始要求与变更前证据

| 原始要求 | 变更前核对 | 本次源码处理 |
| --- | --- | --- |
| 安装失败弹窗针对相关错误码给出专门指导 | 截图为 4551，旧代码未对其提供专门指导 | 两个真实入口仅对 4551 使用 `UI/DriverLoadFailureDialog`；正文只讲原因及处理方法，不显示预检清单、GUID、命令或实现要求 |
| 根据指定更新决定是否提供自动处理按钮 | 无指定更新检测，无 CiTool 移除按钮 | 后台读取真实 build、同分支 UBR 及产品类型；确认更新后显示“禁用策略”，执行前重新核查完整资格 |
| 不满足条件时只提供帮助链接，不自动修改 | 无此明确的受限分支 | 旧更新、未知更新或查询失败显示“查看帮助”，暂时链接 issue 指定博客；与“禁用策略”在初始弹窗互斥 |
| 摘要到 ksword.dev | 不作为本轮交付条件 | 按用户指示暂缓；撤回上一版写入 `使用与兼容性.md` 的本地摘要，不提交、推送或操作网站 |

## 操作模型与 UI 接入

- 导航入口一：标题栏 R0 启用 → 后台 `StartServiceW` 返回 4551 → `MainWindow::startR0DriverService` 的独立策略分支。577/1275 仍调用原 `showUnsignedDriverFailureDialog`。
- 导航入口二：驱动 Dock → 驱动操作 → 挂载服务 → `DriverDock::loadSelectedDriverService` 失败。
- 页面类型：消息框/风险确认框；共享布局和主题为原生 `QMessageBox` + 全局 `ThemedMessageBox`，显式不透明底面。对照 CKS 的后台 CiTool 事务与内存工作台的风险确认消息框，不重排业务页面。
- 用户任务 → 4551 加载失败 → 原因及处理方法 → 按更新状态显示“禁用策略”或“查看帮助” → 显式点击禁用及简短风险确认 → 执行前重新检查 → 简短结果及手动重启指引；默认动作及 Escape 均为不修改。原始命令回执不展示到 UI。
- 系统进程只在共享 `AsyncOperation::submitTransaction` 中运行，有超时和子进程回收；UI 线程不等待进程。查询只负责读，确认前无系统策略写入。
- 所有按钮有双语文字及 tooltip；禁用操作涉及系统级保护，保留可理解的文字，不改成含义不明的图标。没有表格，Full/Compact/None、列组、快照复制及专业编辑器规则不适用。

## 更新及策略判定

不能用当前日期、更新安装日期、`DisplayVersion` 或“更大 build 应该支持”代替累计更新检测。生产实现以已核实的 2026-07-14 安全累计更新为基线，26H2 单列已核实的后续累计更新；同分支后续累计更新可满足，未知分支仅帮助：

| 产品服务分支 | 最低 UBR | 官方基线 |
| --- | ---: | --- |
| Windows 11 build 22631 | 7376 | KB5099414 |
| Windows 11 build 26100 / 26200 | 8875 | KB5101650 |
| Windows 11 26H2 build 26300 | 9550 | KB5124010，2026-09-22 的已核实后续累计更新 |
| Windows 11 build 28000 | 2525 | KB5101649 |
| Windows Server 2025 build 26100 | 33158 | KB5099536 |

读取 `RtlGetVersion` 后只接受同分支 `CurrentBuildNumber` 的 UBR；CBS/WU 待重启键存在或读取失败时不提供自动操作。Server 单独判定，不能将它较大的 UBR 套进客户端阈值。26300 低于 9550 的版本因未核实而返回未知，不把它称为“七月以前”；以上并非所有 Insider/未来系统的支持承诺。

策略列表来自系统目录的 `CiTool --list-policies -json`。按钮可见性只由已确认的更新状态决定；实际执行时，仍要求固定强制 GUID 同时满足 `IsEnforced` 和 `IsAuthorized`、当前提升权限、无待重启标记且工具可用。审核 GUID、空列表、缺字段、重复目标或解析失败均不执行移除。4551 不等于已核实具体的策略 GUID，不能宣称已经查到此驱动对应的 3077 事件。

确认后后台再次读取全部资格，只允许执行：

```powershell
CiTool.exe --remove-policy "{8F9CB695-5D48-48D6-A329-7202B44607E3}"
```

没有旧系统删除文件、挂载 EFI、修改 BCD、关闭安全启动或移除其他策略的后备流程。命令退出 0 仅报告请求已提交并提示保存工作、手动重启，不宣称当前会话已修复。失败只给简短的重试或帮助指引，不向 UI 展示原始命令回执，不自动重试或重启。

## 验收记录

- `tools/Invoke-DriverPolicyTests.ps1`：HostX64 MSVC，真实生产后端纯函数、弹窗、翻译器及共享异步控制器参与编译链接；系统策略 I/O 使用注入回执，不运行真实移除命令。
- 上一版回归为 168 项，但错误地把 577/1275/1260 作为新弹窗入口。本轮 **219 项断言通过**（`DRIVER_POLICY_CHECKS=219 FAILURES=0`），覆盖 4551 分流、旧错误零查询/零新弹窗、按更新选择互斥按钮、博客地址、原因/处理方法正文、确认取消与执行回执，以及不向 UI 暴露 GUID、预检清单和原始命令回执。
- 固定产出目录：`Ksword5.1/x64/Release/driver-policy-tests/`。复用既有 Qt 运行时，未复制 Qt 或主程序，没有创建测试配置；离屏流程验证不代表实际主程序 GUI 或系统策略移除成功。
- 本轮双语检查通过（31,288 个源字符串）；修正后的正式 Release/x64 构建通过：`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`、`ARTIFACT_UPDATED=True`，HostX64 工具链、BelowNormal 优先级，耗时 236 秒。日志 `.codex-build-logs/ksword-build-check-20261122-103422.raw.log`；上一版日志仅保留为历史记录。
- 主程序产物为 `Ksword5.1/x64/Release/Ksword5.1.exe`，34,369,432 字节，SHA256 `FC08E7086E315691B426E0D109DBE09E148EE2AFADEEB5CFE4BBE2DBD1A6713B`。未复制运行副本、未创建测试配置；固定 Release 产物与诊断日志保留，无本轮测试配置需要清理。
- 源码核对：主窗口的 `isR0DriverSignatureFailure` 和 `showUnsignedDriverFailureDialog` 与修改前 HEAD 逐段一致，`DriverDock.cpp` 全文与 HEAD 一致；两个实际失败入口仅新增 4551 独立分支。固定目标移除命令、关闭/取消不执行、异步回执及模态返回后的生命周期检查已复核；新增源码/头文件在 `.vcxproj` 与 `.filters` 各登记一次，定点 `git diff --check` 通过。
- 尚待实际主程序验证：两个真实失败入口、深浅主题、长服务/路径、中英文、小屏及 DPI、背景模式下的首帧和按钮可达性。
- 尚待隔离环境端到端验证：真实旧/新补丁系统的策略读回、命令接受/拒绝、执行时资格变化、重启后状态。不得为了本轮验收关闭开发宿主的安全策略。
- 官网：按用户后续指示暂缓。上一版的本地摘要已撤回，未提交、推送或发布；本轮不执行官网工作，也不报告 `ksword.dev` 已上线。

## 来源

- [原始 Issue #233](https://github.com/KSwordDEV/KSword/issues/233)
- [微软 Windows Driver Policy](https://support.microsoft.com/en-us/windows/hardware/drivers/the-windows-driver-policy)：两个 GUID、3076/3077、实际生效/授权检查、七月更新前后处理差异及风险。
- [Windows 11 KB5101650](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875)
- [Windows 11 KB5101649](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/july-14-2026-kb5101649-os-build-28000-2525)
- [Windows 11 KB5099414](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/july-14-2026-kb5099414-os-build-22631-7376)
- [Windows Server 2025 KB5099536](https://support.microsoft.com/en-us/servicing/os/windows-server/2026/07/july-14-2026-kb5099536-os-build-26100-33158)
- [Windows 11 26H2 KB5124010](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update)：明确列出 26300.9550，作为该分支的保守已核实下界。
