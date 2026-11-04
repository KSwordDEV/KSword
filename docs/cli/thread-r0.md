# R0 线程控制

普通进程线程控制使用 `thread r0 suspend|resume|terminate`：

```text
KswordCLI.exe thread r0 suspend --pid PID --creation-time FILETIME --tid TID --thread-creation-time FILETIME --confirm [--json]
KswordCLI.exe thread r0 resume --pid PID --creation-time FILETIME --tid TID --thread-creation-time FILETIME --confirm [--json]
KswordCLI.exe thread r0 terminate --pid PID --creation-time FILETIME --tid TID --thread-creation-time FILETIME [--exit-status N] --confirm [--json]
```

先运行 `thread r0 identity --pid PID --tid TID --json` 获取进程和线程创建时间。新命令通过独立的 `CONTROL_THREAD_VERIFIED` IOCTL 在驱动持有线程对象及其所有者时核对两个创建时间；即使 R3 无法打开目标也可使用。旧驱动不支持该协议时返回 5，不退回 PID/TID 旧请求。R3 查询句柄仅用于可选的动作前后回读；成功发起后，如果挂起计数或终止状态无法回读确认，返回 6。R0 不能打开设备返回 2，不会回退为 R3 写操作。

System/PID 4 的驱动线程使用单独命令：

```text
KswordCLI.exe thread driver suspend --tid TID --start-address VA --thread-creation-time FILETIME --confirm [--json]
KswordCLI.exe thread driver resume --tid TID --start-address VA --thread-creation-time FILETIME --confirm [--json]
KswordCLI.exe thread driver terminate --tid TID --start-address VA --thread-creation-time FILETIME --method psp|zw|normal-apc|special-apc --confirm [--json]
```

该驱动协议重新验证 TID、启动地址及创建时间，并执行现有保护检查。它没有动作效果回执，已受理请求返回 6；APC 方法只代表已排队，不能推断线程已经结束。以实际回执及后续独立查询确认效果。
