# 文件命令（R3）

通过 `help file`、`help file directory`、`help file directory enum` 逐层查看。
已有文件 R0 命令的默认后端和输出保持兼容；本页新增命令默认 R3，不打开驱动。

## 目录浏览（迁移项 14）

```powershell
KswordCLI.exe file directory enum --path PATH [--kind all|directory|file] [--limit N] [--backend r3] [--json]
KswordCLI.exe file directory drives enum [--limit N] [--backend r3] [--json]
KswordCLI.exe file directory enum --path "%TEMP%" --kind file --limit 10 --json
```

目录命令只枚举直接子项，保留后端“目录在前、名称不区分大小写”的顺序。
路径去除外层引号、展开环境变量、统一分隔符，并把相对路径转换为绝对路径。
目录路径不接受通配符；不会递归或跟随子项重解析点。UI 的返回／前进导航历史不单独成为 CLI 功能。
drives 只读取逻辑驱动器名称，不探测容量、介质是否就绪或硬件身份。

输出 source、path、virtualDriveRoot、complete、win32Error、totalCount、matchedCount、returnedCount、entries。
每项含 kind、name、path、十六进制 attributes、attributeText、sizeBytes、lastWriteFileTime、lastWriteLocalTime、reparsePoint。
sizeBytes 和 FILETIME 使用十进制字符串；目录／驱动器的文件大小、没有取得的时间为 null。
时间包含原始 UTC FILETIME 与后端本地时间展示。kind、limit 只筛选显示，不改变实际枚举范围。
有效空目录返回 0；失败且无结果返回 3；枚举中断但有部分结果返回 6，保留实际 Win32 错误。
