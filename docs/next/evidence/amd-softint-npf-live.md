# softint-npf-v7 实体机复测进度

2026-09-24。源码修复提交 `6d4825f5`，用户签名 SYS，匹配 PDB GUID `610cc2ba-167e-46b9-968b-c558e3386a99` / age 1。证据目录：`artifacts/softint-npf-v7-live-20260924-094511`。

- 重启后 `LabHostReady`，boot ID `2026-09-24T01:42:30.5000000Z`，Hypervisor=false。
- 新候选由正常 SCM 加载；准入、prepare、逐核 self-test、并发 general resident 和 5 秒稳态复核通过，32/32 CPU；generation=4，卸载保护已启用。
- 01:46:13Z 请求启动原 8 vCPU/8GiB EFI 克隆 KSword-AMD-Lab，01:46:18Z vmrun 返回 0。未重新配置或恢复快照。
- a 至 f 六次采样均 32 resident、lastStatus=0，32 个热点快照有效。未观察到此次宿主蓝屏重现；不据此宣称已完成长期稳定性验证。
- 用户确认看到了 Windows logo，正在“准备自动修复”，画面没有卡死，主观执行速度不足原来的 30%。这不是经过基准测试得到的性能比例，也不是正常桌面开机验收。
- 日志在 01:47:03Z 报 firmware transitioned to runtime；Tools 状态曾为 running，随后 heartbeat timeout。短暂 Tools 心跳不能作为桌面或全部来宾核心正常运行证明。

e→f（QPC 频率 10MHz，间隔 10.7660379 秒）L1 退出增加 4,882,497，L2 退出增加 2,950,230，其中 NPF 增加 2,871,252，约 26.7 万次 NPF/秒。说明仍存在大量嵌套页表退出成本，但单凭计数无法确定全部性能损失的原因。原始退出字段和逐核热点保存在各采样 metrics.json 中。

一致的 flight 快照未发现终止锁存；部分活跃 CPU 的 flight/general 快照无法取得一致性，已明确标记，不能把这些 CPU 的零填充字段当作真实状态。a–d 为 CPU6，e 为 CPU6/8，f 为 CPU3/4/8/10/12/14/16/18。

当前保留驱动和虚拟机运行，让 Windows 自动修复继续。没有强制停止、卸载或重置。**本阶段通过的是新版 32 核宿主常驻；8 核完整内层 OS 正常启动仍待验收。** 用户看到正常开机会告知，后续先只读采集，避免覆盖本轮现场。
