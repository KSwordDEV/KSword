# 系统时间控制

`system time speed query [--backend r0] [--json]` 读取驱动的系统全局计数器变速状态，包括协议、代次、实际倍率、计时后端、解析方案、状态位和原始诊断。该状态是性能计数器映射，不是墙上时钟或 NTP 同步证明。`system time query` 仍是已有的 R3 墙上时间、时区及 W32Time 配置查询。

`system time speed set --mode up|down --factor N [--timer-backend hyperv|hal] [--resolution compat|guarded] [--generation N] --confirm [--backend r0] [--json]` 应用加速 N 倍或减速到 1/N，倍率范围 2–64。默认 Hyper-V 共享 QPC 后端和兼容解析；HAL 是显式可选后端。调用先读取驱动状态并将当前代次传回驱动；指定 `--generation` 时必须与查询值一致。传输成功、驱动业务状态和后置查询分别保留；驱动接受但回读无法确认时退出 6。驱动仍执行原有 KERNEL_PATCH 安全策略，CLI 不绕过。

`system time speed reset --confirm [--backend r0] [--json]` 请求恢复连续 1x；即使前置状态查询失败也尝试调用恢复，再做后置查询。驱动的 reset 忽略期望代次；为避免计数器回退，恢复 1x 后可能保留钩子。变速影响全系统性能计数器并在 CLI 退出后持续，实际可用性由驱动、系统版本和平台决定。

`system time resync --confirm [--timeout-ms N] [--backend r3] [--json]` 从系统目录执行 `w32tm.exe /resync /rediscover`，与 GUI 的时间服务器同步动作一致。默认超时 15000 毫秒，可设 1000–60000；输出保留至多 16 KiB 并按当前 OEM 代码页解码。进程正常退出且退出码为零只证明命令成功返回，不能证明长期同步。超时时只结束 CLI 创建的子进程并返回 6，已经提交给系统服务的请求结果未知，不自动重试。

所有动作必须显式 `--confirm`。时间控制在生产环境可能影响系统稳定性；测试使用模拟驱动回执及自有子进程，未主动变更真实系统计数器或时间服务器设置。
