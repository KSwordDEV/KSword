# 启动项 R3 命令

## 枚举（迁移项 11）

```powershell
KswordCLI.exe startup enum [--kind all|run|run-once|folder|service|driver|registry-only-service|task] [--scope all|user|machine|all-users|unknown] [--name NAME] [--limit N] [--backend r3] [--json]
```

默认展示上限 100，0 仅返回统计。kind、scope 默认 all，name 精确匹配区分大小写的显示名称。
筛选和显示上限不改变后端采集范围。无需 KswordARK 驱动。

来源包含 HKCU Run/RunOnce、HKLM 32/64 位视图、后端保留的禁用存储、用户／公共启动目录、
SCM 服务及驱动、Services 注册表与 SCM 的来源差异、Task Scheduler 文件存储。
不存在的可选启动键／目录视为有效空来源；读取拒绝、枚举错误等保留已采集行，并在 sourceErrors 中报告。
code 为实际 Win32/HRESULT；原布尔接口未提供具体错误时为 null，不猜测错误码。

数据包含 userSid、identityWin32Error、complete、sourceErrors、匹配／显示数、displayTruncated 和 entries。
每项保留 kind、scope、state、名称、命令、位置、注册表根／视图／值名、禁用存储、文件／服务／任务路径以及原始属性列表。
未知状态明确显示 unknown。驱动及 registry-only-service 是只读观察；来源差异不等于隐藏服务判定。
任务项来自文件存储，state 为 unknown，不把存在的任务文件解释为已启用或正在运行。

id 是调用者 SID 与不可变来源字段的稳定标识，排除 active/disabled 状态；后续操作会重新枚举并要求唯一匹配。
该标识只用于定位当前来源，不是可跨用户复用的授权令牌；SID 获取失败时 id 为 null。
采集完整返回 0；来源查询部分失败或身份上下文不可用返回 6，已采集的内容继续输出。
