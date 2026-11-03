# 进程网络监控与 QoS

## 入口

| 入口 | 用途 | 共享布局 |
| --- | --- | --- |
| 进程 → 进程详情 → 网络监控 | 当前进程实例的速率、报文、连接、阻断及限速 | `ParameterWorkspace`、共享结果表、`CodeEditorWidget` |
| 网络 → 流量监控 | 左侧组合筛选、固定监控动作，右侧时间轴与报文表 | `ParameterWorkspace`、原 `PacketMonitorTable` 与时间轴 |
| 网络 → QoS 管理 | 策略列举、创建、编辑、启停、删除、导入草稿与导出 | `ParameterWorkspace`、Compact 结果操作条 |

进程详情可一键打开完整流量监控并启动捕获，临时 PID 范围独立于保存的规则组；返回规则组筛选或明确应用规则时恢复原配置。组合筛选保留组内 AND、组间 OR；地址字段支持 IPv4 单地址/CIDR/范围和 IPv6 单地址/CIDR。

## 数据与身份

进程速率由两个有效 ETW 累计字节快照做差，使用网络快照自身的单调时间；进程枚举耗时不改变该区间。未开始、没有有效事件、基线刚建立、计数器重置或发生丢失时显示 N/A，健康空闲区间才显示零。网络列表头提供状态及“重启网络统计”。意外消费线程退出可有界恢复，失败清理不逐帧重试；暂停/恢复重新建立基线。

详情报文由应用级共享 R3 捕获服务按进程实例分流，每个订阅持有 PID＋创建时间对应的进程句柄。单窗口停止不停止其他订阅。连接枚举、断开和策略写入前重新校验目标；断开同时重新核对端点所有者。Windows 原生 DELETE_TCB 用于可关闭的 IPv4 TCP；其他连接可通过阻断策略控制。

详情待消费队列最多1024条，展示历史最多2000条；队列丢弃和历史淘汰分别计数。PCAP 使用 DLT_RAW，保存真实 IP 字节、原长度、捕获长度及时间；截断记录保留截断语义，没有 IP 字节的元数据记录不伪造成报文。JSONL dump 保留元数据与原始十六进制。导出使用对话框打开前冻结的记录集合。

## 阻断后端

- Windows Firewall：按程序路径匹配同映像的所有实例，或显式全局主机范围。入站/出站规则组成一个托管策略 ID，可以列举、启停和移除。
- KswordARK WFP：独立于旧规则表，最多64条托管策略，每条最多32个 IPv4/IPv6 CIDR。按当前 PID＋创建时间实例或全局主机匹配；退出通知、进程引用和 rundown 维护生命周期。四个 ALE 授权层未命中时继续原决策，策略变化通过过滤器事务请求重新授权。
- 主机名按当前 DNS 解析地址生成规则；地址记录变化时需重新解析。列表展示实际地址范围。后端能力或操作失败如实返回，不自动改用另一个作用范围。

只管理 KSword 自己创建的规则，不替换其他防火墙规则或旧驱动规则表。驱动客户端位于 `ArkDriverClient`，协议唯一来源为 `shared/driver/KswordArkManagedNetworkIoctl.h`；分发入口登记在 `ioctl_registry.c`。

## QoS

Windows Policy QoS 按应用映像（所有实例）或显式全局条件匹配，上行整形不挂起进程。可配置协议、源/目标 IP 前缀、端口范围、DSCP、802.1p、策略优先级和上行字节上限。没有带宽上限时仍可配置标记动作。KiB/s 表单保留精确字节值，导入字段先校验，不自动应用草稿。

使用 IP/端口条件时必须明确选择 TCP、UDP 或两者；提供者的默认协议会忽略这些条件。创建不限端口的策略时省略端口参数，修改策略时使用提供者的清空值；回读的全端口范围会统一为“不限”，便于再次编辑或恢复。新建后失败会清理新策略，已有策略失败保留 ID 并报告实际状态，重试不另造身份。

QoS 使用 ActiveStore；已保存定义用于移除活动策略后的恢复，页面区分实际活动状态与保存定义。系统/组策略来源可查看和导出，在本页只读。矩形图比较已启用策略的配置上限，不代表实际吞吐，匹配范围可能重叠。

## 构建与回归

```powershell
python tools/test_process_network_rate.py
python tools/test_network_policy.py
python tools/managed_network_core_tests.py
python tools/test_network_monitor_filter.py --qt .deps/Qt/6.9.3/msvc2022_64
python tools/test_process_network_exports.py --qt .deps/Qt/6.9.3/msvc2022_64
python tools/test_network_qos_draft.py --qt .deps/Qt/6.9.3/msvc2022_64
python tools/driver_functional_ci/plan_gate.py --repo-root .
```

回归使用实际算法、编解码及有界适配器，不在主机上创建策略或执行真实阻断。主程序使用仓库 HostX64 构建脚本；驱动使用标准 WDK，并单独报告编译链接、API 校验与目录生成。CLI 提供 `network managed-policies` 查询，并同步内置帮助及功能矩阵。

2026-11-01：主程序 Release/x64 构建成功，标准 EXE 为32,556,544字节；驱动构建退出0，API校验返回 `Driver is 'Universal'.`，目录生成无错误和警告；CLI Release 为4,030,976字节。网络速率/会话/载荷、策略与响应编解码、QoS参数构造、IPv6筛选、真实报文导出和草稿解析回归均通过；R0匹配/事务/引用生命周期107项通过。IOCTL审计225项全部登记、无高风险项，功能矩阵计划保持完整覆盖且未增加CLI缺口预算。
