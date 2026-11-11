# 启动项 R3 命令

## 枚举（迁移项 11）

```powershell
KswordCLI.exe startup enum [--category all|logon|services|drivers|tasks|image-hijack|registry|wmi|hidden] [--scope all|user|machine|all-users|unknown] [--name NAME] [--limit N] [--backend r3] [--json]
```

默认展示上限 100，0 仅返回统计。category、scope 默认 all，name 精确匹配区分大小写的显示名称。
筛选和显示上限不改变后端采集范围。无需 KswordARK 驱动。

来源按主程序同一顺序包含登录项、SCM 服务、驱动、计划任务、映像劫持、高级注册表、Winsock、WMI 和隐藏项交叉检查。
登录项继续覆盖 HKCU Run/RunOnce、HKLM 32/64 位视图、后端保留的禁用存储、用户／公共启动目录及脚本文件。
不存在的可选启动键／目录视为有效空来源；读取拒绝、枚举错误等保留已采集行，并在 sourceErrors 中报告。
code 为实际 Win32/HRESULT；原布尔接口未提供具体错误时为 null，不猜测错误码。

数据包含 userSid、identityWin32Error、complete、sourceErrors、匹配／显示数、displayTruncated 和 entries。
每项保留 category、stage、scope、state、name、command、location、sourceType、publisher、imagePath、risk、
canEnable/canDisable/canDelete、actionKind 及结构化 registry/service/task/file 定位字段。
未知或不可证明的值为 null/unknown；驱动、隐藏项和来源差异观察保持只读，不从差异推导隐藏服务判定。

每项也直接提供 GUI 详情所用的 `sourceUniqueId`、`categoryDisplay`、`displayRegistryValueName`、
`sourceEnabled`、`deleteRegistryTree` 和 `serviceStartMode`。`sourceEnabled` 是共享后端返回的原始布尔值，
不是额外实时验证；`state` 仍保留各来源的可证明状态。`registryValueName` 是动作定位器中的值名，
`displayRegistryValueName` 是原始记录的显示值名，两者可能不同。共享后端没有 WOW64 注册表视图、
禁用备份子键或通用 properties 的可靠字段，`registryView`、`disabledRegistrySubKey`、`properties`
因此返回 null；不使用 0、原键名或空列表伪装已有证据。`serviceStartType` 对可确认的 Boot=0 保留零值。

id 是调用者 SID 与不可变来源字段的稳定标识，排除 active/disabled 状态；后续操作会重新枚举并要求唯一匹配。
该标识只用于定位当前来源，不是可跨用户复用的授权令牌；SID 获取失败时 id 为 null。
采集完整返回 0；来源查询部分失败或身份上下文不可用返回 6，已采集的内容继续输出。

## 控制和位置查询（迁移项 12）

```powershell
KswordCLI.exe startup enable --id ID --confirm [--backend r3] [--json]
KswordCLI.exe startup disable --id ID --confirm [--backend r3] [--json]
KswordCLI.exe startup delete --id ID --confirm [--backend r3] [--json]
KswordCLI.exe startup location query --id ID [--backend r3] [--json]
```

从 startup enum 取得 id。操作前重新枚举并要求同一调用者 SID 下唯一匹配；缺失或歧义返回 3，未执行修改。
驱动和 registry-only-service 仍为只读观察，控制请求返回 5。
位置查询返回来源字段，不启动 Regedit/Explorer/Services GUI；它也可用于只读观察项。
其数据就是重新枚举后唯一匹配的完整 entry，与 `startup enum` 共用同一个字段投影。

Run/RunOnce 使用 shared 后端的 KSword 恢复元数据，移动时保留原始 SZ/EXPAND_SZ 类型和字节。
启动目录项在原目录与 shared 后端恢复目录之间移动；删除实际选中的活动／禁用文件。
服务禁用保存原启动类型，启用恢复；删除是 SCM 删除请求，服务仍存在时报告未确认而不声称已消失。
计划任务通过 Task Scheduler/PowerShell 读取并由 COM/PowerShell 控制，启停后重新枚举验证 Enabled。

结果保留 target、observed、requestSucceeded、changed、status、errorCode、verified、sourceErrors；
请求完成并验证目标状态返回 0，部分来源或回读未确认返回 6，实际调用失败返回 3，后端不支持返回 5。
删除后缺失只有在来源枚举完整时才算已确认。同名 active/disabled 副本会造成标识歧义并如实报告。
