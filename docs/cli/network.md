# 网络 R3 命令

使用 `help network` 查看直属命令，`help network connections` 查看连接操作，
`help network connections close` 查看精确语法。以下命令默认为 R3，不需要驱动；
`--backend r3` 可以显式指定，`--backend r0` 不适用于这些新增命令。

## TCP/UDP 连接（迁移项 01）

```powershell
KswordCLI.exe network connections enum [--pid PID] [--protocol all|tcp4|tcp6|udp4|udp6] [--limit N] [--backend r3] [--json]
KswordCLI.exe network connections close --pid PID --local-address IP --local-port N --remote-address IP --remote-port N --confirm [--backend r3] [--json]
```

枚举通过 IP Helper 读取四种端点表。默认协议 `all`，显示上限 100；`--limit 0`
只显示统计，不影响采集。每行包含协议、PID、进程名、本地／远程地址和端口、
原始 TCP 状态编号与 `canClose`。UDP 的状态为 `null`，远端地址为空、端口为 0。
JSON data 包含 `matchedCount`、`returnedCount`、`truncated`、`entries`。
表读取失败时保留已采集的数据并返回部分完成 6；全部失败返回 3。

关闭要求管理员权限，仅支持 IPv4 TCP 的活动 TCB，不支持监听端点、IPv6 或 UDP。
参数指定的是枚举输出中的 PID 和完整地址／端口元组；执行前重新枚举并匹配所有者，
使用后端保存的原始网络字节序元组调用 SetTcpEntry。成功后重新枚举：连接消失返回 0，
回读不完整或仍存在返回 6。目标已消失返回 3，监听等不支持状态返回 5。
JSON data 包含目标、`requestSucceeded`、`postcheckPresent`、`postcheckComplete`；
系统调用失败时含 `win32Error`。目标的消失不能证明应用程序不会建立新的连接。

自动测试使用本机回环 TCP／UDP 夹具，与独立 Get-NetTCPConnection 结果核对；
关闭后通过对端 socket 验证实际断开，不以退出码作为唯一证据。
