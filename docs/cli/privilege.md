# 当前 CLI 进程权限（R3）

迁移项 13。使用 `help privilege` 查找叶子命令；本组不打开驱动。

```powershell
KswordCLI.exe privilege query [--name NAME] [--limit N] [--backend r3] [--json]
KswordCLI.exe privilege run [--enable NAME[,NAME...]] [--disable NAME[,NAME...]] [--backend r3] [--json] -- <CLI command>
```

query 读取当前 CLI 进程令牌。name 精确匹配权限名，limit 为显示行数（0 或省略表示全部）。
输出 source、pid、token、totalCount、matchedCount、returnedCount、privileges、win32Error、queryErrors。
每项权限含 name、displayName、十六进制 luid、enabled、enabledByDefault、removed、description、risk。
token 包括用户 SID、账户、完整性级别、令牌类型、提升状态、UIAccess 和已启用组；未知字段为 null。
附属令牌信息读取失败返回 6；令牌或权限数组读取失败返回 3；有效空筛选返回 0。

run 至少指定 enable 或 disable；逗号列表不能包含空项、重复名或相互冲突的权限。
`--` 后是完整 CLI 命令路径和参数，直接在同一 CLI 进程内执行；不会启动外部程序。
权限只调整本进程已被授予的权限，不能授予缺失权限（ERROR_NOT_ALL_ASSIGNED=1300）。
调整逐项回读，全部确认后才执行目标命令；失败时恢复此前涉及的权限，目标命令不执行。
目标命令结束后按逆序恢复原 enabled 状态并回读。异常离开作用域时也尝试恢复。

```powershell
KswordCLI.exe privilege run --disable SeChangeNotifyPrivilege --json -- privilege query --name SeChangeNotifyPrivilege --json
KswordCLI.exe privilege run --enable SeDebugPrivilege -- process enum --backend r3
KswordCLI.exe privilege run --enable SeDebugPrivilege -- help process
```

作用域输出 pid、adjustments、commandArguments、executed、exitCode、stdout、stderr、restorations、restored。
调整／恢复分别记录 requestedEnabled、requestSucceeded、observedEnabled、verified、win32Error。
目标输出作为文本字段保留；即使目标使用 JSON，外层 stdout 仍仅有一个 JSON 文档。
外层 `--json` 必须在分隔符之前；目标的 `--json` 不改变外层格式。目标 help 只查询目标帮助。
调用失败返回 3；请求完成但回读或恢复未确认返回 6；目标失败退出码原样保留。
独立 CLI 调用不继承本次权限调整。后续命令若自行调整权限，其行为仍由该命令定义。
