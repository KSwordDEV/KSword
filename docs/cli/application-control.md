# 应用控制、AppLocker 和 Defender

这些命令调用当前系统的 Windows PowerShell AppLocker / Defender cmdlet；仅 R3，按当前令牌权限执行，不自动提权，也不改变域或组织策略。Windows 版本或模块不具备相应 cmdlet 时返回不可用及原始错误。辅助进程有超时和输出上限；长时间无回应或写后未能验证会返回部分结果。

## AppLocker

```text
security applocker rules enum [--scope local|effective] [--id GUID] [--limit N] [--json]
security applocker policy export --output PATH [--scope local|effective] --confirm [--json]
security applocker policy import --input PATH --expected-hash SHA256 --confirm [--json]
security applocker rule add --collection TYPE --name NAME --sid SID --action allow|deny --path PATH [--description TEXT] --expected-hash SHA256 --confirm [--json]
security applocker rule update --id GUID --name NAME --sid SID --action allow|deny --path PATH [--description TEXT] --expected-hash SHA256 --confirm [--json]
security applocker rule delete --id GUID --expected-hash SHA256 --confirm [--json]
```

`rules enum` 展示每条规则的 ID、集合、模式、类型、名称、SID、动作、路径及原始规则 XML；可按 ID 筛选。`policyHash` 是所查策略原始 XML 的 UTF-8 SHA-256；`--limit` 为 1..128，并有输出字节预算，`displayTruncated` 标明限制。先用 `--scope local` 查询获取当前 `policyHash`，将其作为后续本地写操作的 `--expected-hash`。`effective` 允许只读枚举／导出，包括可能由组策略提供的规则；新增、修改、删除和 XML 导入只操作本地策略。路径规则集合为 exe、msi、script、dll、appx；新增/修改仅针对路径规则，删除可按唯一 ID 选中任意本地规则。规则定义的权限和作用由 Windows 执行，不从枚举结果推断程序必然能否运行。

导出使用新建文件语义，已有目标不会覆盖；`verified` 表示导出文件内容的回读校验。导入读取不超过 2 MiB 的 XML，验证根节点后替换本地策略；它可能改变整个本地策略，请先导出并仔细审阅文件。规则写入与导入均先核对当前策略哈希，再调用系统 cmdlet 并重新读取；哈希检查和系统提交不是原子操作。提交后读取失败、超时或结果不一致返回 6，须先重新查询再决定是否重试。

## Defender 和 ASR

```text
security defender settings query [--json]
security defender setting set --setting controlled-folder|pua|network|realtime --value N --expected-hash SHA256 --confirm [--json]
security defender asr add --id GUID --value 0|1|2|6 --expected-hash SHA256 --confirm [--json]
security defender asr set --id GUID --value 0|1|2|6 --expected-hash SHA256 --confirm [--json]
security defender asr delete --id GUID --expected-hash SHA256 --confirm [--json]
```

`settings query` 返回受控文件夹访问、PUA、网络保护、实时保护和 ASR ID／动作数组及 `snapshotHash`。写入时传入该哈希；ASR 数组长度不一致或 ID 重复时拒绝修改，避免覆盖不明配置。ASR 值为 0 关闭、1 阻止、2 审核、6 警告；前三种普通设置值为 0、1、2，`realtime` 值为 0 或 1（禁用或启用）。所有变更通过 `Set-MpPreference`，保留系统错误，并再次读取所选值确认；篡改防护、权限或组织策略可能拒绝或覆盖设置。

写命令使用 `--confirm`；返回 0 表示调用和所请求的回读一致，6 表示快照过期、写入状态未知或回读未能确认，3 表示可定位的辅助进程／操作错误，5 表示系统模块不可用。哈希只用于发现已知的快照变化，不能阻止检查与写入之间发生并发更改。参数在脚本中以 Base64 编码数据传递，调用方文本不会作为 PowerShell 语句执行。

这组命令没有涵盖 GUI 的 WDAC 源策略编辑／编译／部署或文件拦截诊断；不要将 AppLocker／Defender 的配置读取当作 WDAC 等效能力。
