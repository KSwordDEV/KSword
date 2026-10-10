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

## 创建、传输和删除（迁移项 15）

```powershell
KswordCLI.exe file create --directory PATH --confirm [--backend r3] [--json]
KswordCLI.exe file directory create --directory PATH --confirm [--backend r3] [--json]
KswordCLI.exe file copy --path PATH --to-directory PATH --confirm [--backend r3] [--json]
KswordCLI.exe file move --path PATH --to-directory PATH --confirm [--backend r3] [--json]
KswordCLI.exe file rename --path PATH --target PATH --confirm [--backend r3] [--json]
KswordCLI.exe file delete --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe file directory delete --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe file delete-path --path PATH --confirm --backend r3 [--json]
KswordCLI.exe file path short query --path PATH [--backend r3] [--json]
KswordCLI.exe file shortcut query --path PATH [--backend r3] [--json]
```

create 复用后端的自动命名（新建文件.txt／新建文件夹，有冲突则编号），返回实际 target。
创建空文件或空目录；指定最终名称可随后调用 rename。创建成功不保留前一次名称碰撞错误。
copy／move 目标为目录，目标名称取源路径最后一段。复制按后端行为递归并覆盖已有文件；
移动先尝试重命名，失败后复制并删除源。rename 使用 MoveFileExW，可覆盖目标并允许跨卷文件移动。
文件删除使用 DeleteFileW；目录删除仅删除空目录。delete-path 只有显式 R3 时调用本实现，默认 R0 不变。

修改输出 source、target、action、requestSucceeded、errorCode、errorCategory、partial、verified、
copyCompleted、sourceRemoved、before、sourceAfter、targetAfter。原生操作错误类别为 win32；
标准文件系统错误保留原始类别和值，不把通用类别的 errno 标成 Win32 错误。
回读证据含 known、present、win32Error、attributes、sizeBytes；不能确认是否存在时 present 为 null。
verified 检查最终路径存在／消失、类型和文件大小，不表示对目录所有子项完成了额外内容校验。
API 成功并有相符证据返回 0；调用失败返回 3；部分复制／源删除失败、目标存在但复制完整性未知，
或成功请求未取得相符回读返回 6。没有事务回滚；部分失败后的路径状态直接保留供检查。

short query 返回 GetShortPathNameW 结果。系统关闭 8.3 名称生成时，结果可能仍是长路径。
shortcut query 仅加载 .lnk 并读取文件系统目标，不启动目标、不执行 Shell 解析修复。
输出 path、result、win32Error／hresult；无文件系统目标返回 5，读取失败返回 3。

## 所有权与占用者（迁移项 16）

```powershell
KswordCLI.exe file ownership take --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe file locks query --path PATH [--pid PID] [--limit N] [--backend r3] [--json]
```

ownership take 把单个文件／目录的所有者设为当前令牌用户，不修改 DACL、不递归修改子项。
按后端行为在本进程尝试启用 SeTakeOwnershipPrivilege；没有该权限时仍保留原生操作的真实结果。
输出 path、callerSid、privilegeEnabled、requestSucceeded、win32Error、before、after、verified。
前后所有者 SID 查询各保留独立错误；请求成功且后续 SID 等于调用者 SID 返回 0，读取未确认返回 6，原生失败返回 3。

locks query 使用 Restart Manager，只枚举可见占用者，不关闭句柄、不强制解锁。
输出 path、source、target 文件存在证据、win32Error、rebootReason、totalCount、matchedCount、returnedCount、processes。
进程包含 pid、十进制 creationTime FILETIME、application、service、applicationType、十六进制 status、sessionId、restartable。
pid／limit 只筛选显示；成功的空结果返回 0，原生失败返回 3。Restart Manager 并不保证发现全部占用者，
也不验证目标路径是否存在；target 的独立存在证据用于说明该限制。空结果不能证明文件可被删除或没有内核句柄。
