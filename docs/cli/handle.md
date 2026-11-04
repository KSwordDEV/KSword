# 句柄关闭

`handle close --pid PID --handle HANDLE --creation-time FILETIME --object ADDRESS --confirm [--backend r3|r0] [--json]` 关闭一条已枚举行的真实远程用户句柄。默认 R3；R0 使用驱动独立的 CLOSE_HANDLE IOCTL，不回退 R3。PID 创建时间、句柄值和对象地址必须非零且来自同一行；对象地址只作身份比较，不解引用。可以先用 `handle enum` 或 `system file-holders query` 取得对应行。文件映射不是文件句柄，不能使用此命令解除。

操作前验证目标进程创建时间，暂停目标并复核句柄对象，随后关闭和恢复；两个阶段的回执分别输出。`DUPLICATE_CLOSE_SOURCE` 即使失败也可能关闭源句柄，尝试后无法确认或恢复失败返回 6，调用方应重新查询而不是盲目重试。用户态或内核并发修改句柄表的窗口不能完全消除。禁止关闭系统、调用者自身及高位内核句柄；缺少身份时拒绝。
