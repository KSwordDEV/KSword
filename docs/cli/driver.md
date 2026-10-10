# 驱动 R3 命令

迁移项 30。通过 Windows NT / Psapi 查询已加载的内核映像，不要求 KswordARK 驱动。原有 `driver detail --driver NAME` 继续查询 R0 DriverObject。

```powershell
KswordCLI.exe help driver
KswordCLI.exe driver modules help
KswordCLI.exe help driver modules enum
KswordCLI.exe driver modules query --help
KswordCLI.exe driver modules enum --json
KswordCLI.exe driver modules query --name ntoskrnl.exe --signature off --json
KswordCLI.exe driver modules query --base 0xFFFFF80012340000 --json
KswordCLI.exe privilege run --enable SeDebugPrivilege --json -- driver modules enum --source psapi --json
```

`enum` 无必填参数；`query` 必须提供恰好一个 `--name`（不区分大小写的完整叶文件名）或非零 `--base`。两者支持 `--source auto|nt|psapi`（默认 auto）、`--signature on|off`（enum 默认 off，query 默认 on）、`--limit 1..100000`（默认 1000）、`--backend r3`、`--json`。显式选择来源仅调用该来源；auto 在 NT 调用失败时尝试 Psapi，保留两次调用的证据，NT 格式异常不会被回退掩盖。不会切换 R0。

统一外壳下的 `data` 包含 `requestedSource`、`selectedSource`、`sources`（各自 complete/malformed/redacted/unsupported、原始 NTSTATUS/Win32 错误、系统报告数量）、`enumeratedCount`、`matchedCount`、`returnedCount`、`truncated`、`modules`。每个模块包含 name、baseAddress、imageSize、endAddressExclusive、path、source；NT 还提供 flags、loadOrder、initOrder、loadCount。地址用十六进制字符串，大小和计数用十进制字符串，不可见字段为 null。列表是瞬时系统快照，不保证后续操作时模块仍然加载。

Psapi 不提供映像大小，非空结果返回部分完成 6；NT 的地址／路径等字段不可见也返回 6。Windows 11 24H2 起，Psapi 需要当前进程启用 SeDebugPrivilege 才返回有效基址；它可能成功却返回全 NULL。全部身份不可见返回 5，不伪造零地址模块或成功空结果。允许真实的有效空枚举返回 0。信息长度／模块数量／地址范围异常返回 4；调用失败返回 3（导出不可用为 5）；输出截断为 6。query 无匹配且快照身份完整时返回 3，身份隐藏不能证明目标不存在，返回 5。

`signature` 包含 requested、available、status、trustStatus、localPath、fileWin32Error、catalogVerification。启用时只检查返回模块对应的可访问磁盘文件，使用 WinVerifyTrust 缓存模式，不查询网络、不验证已加载内存、不查询目录签名。status 可为 trusted、no-embedded-signature、bad-digest、expired、revoked、untrusted；无法评价时 null 并返回 6。`no-embedded-signature` **不能证明驱动未签名**，驱动可能使用目录签名。不同来源／文件签名不构成 R0 完整性结论。

共享后端以 8 次重试、128 MiB 缓冲上限校验枚举长度；Psapi 字符串容量为名称 512、路径 1024 个字符，截断保留错误且字段不可用。权限提升由显式 `privilege run` 在同一 CLI 进程内完成并恢复。help 查询不触发任何枚举、签名检查或设备访问。
