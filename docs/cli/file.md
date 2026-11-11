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
KswordCLI.exe file create (--path PATH [--text TEXT | --hex HEX | --data-file PATH] | --directory PATH) --confirm [--backend r3] [--json]
KswordCLI.exe file directory create (--path PATH | --directory PATH) --confirm [--backend r3] [--json]
KswordCLI.exe file copy --path PATH --to-directory PATH --confirm [--backend r3] [--json]
KswordCLI.exe file move --path PATH --to-directory PATH --confirm [--backend r3] [--json]
KswordCLI.exe file rename --path PATH --target PATH --confirm [--backend r3] [--json]
KswordCLI.exe file delete --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe file directory delete --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe file delete-path --path PATH --confirm --backend r3 [--json]
KswordCLI.exe file path short query --path PATH [--backend r3] [--json]
KswordCLI.exe file shortcut query --path PATH [--backend r3] [--json]
```

create 的 `--directory` 使用自动命名（新建文件.txt／新建文件夹，有冲突则编号）；`--path` 指定最终名称，存在时失败，不覆盖。返回实际 target。
文件内容可选 `--text`（UTF-8，无 BOM）、`--hex` 或 `--data-file` 原始字节，互斥且最多 64 MiB；省略时创建空文件。目录不接受内容。指定路径的文件会回读并比较全部字节；写入失败可能留下部分文件并返回 6。
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

## 哈希、签名与熵（迁移项 17）

```powershell
KswordCLI.exe file hash query --path PATH [--backend r3] [--json]
KswordCLI.exe file signature query --path PATH [--backend r3] [--json]
KswordCLI.exe file entropy query --path PATH [--max-bytes N] [--backend r3] [--json]
```

hash 为整个文件计算 SHA256，输出 algorithm、digest、bytesRead、complete、win32Error。
任意读取／CryptoAPI 失败返回 3 且 digest 为 null，不把已读取前缀的摘要冒充完整摘要。
entropy 默认最多读取 16777216 字节，max-bytes 必须为正数。输出 bitsPerByte（JSON 数值）、
sampledBytes、sizeBytes、maxBytes、complete、limited、win32Error。空文件熵为 0。
完成整个文件读取返回 0；受预算限制或已经读到部分内容后失败返回 6；完全无法读取返回 3。
部分熵只描述实际读到的前缀，所有字节数使用十进制字符串。共享写入文件不构成原子快照。

signature 使用 WinVerifyTrust 通用 Authenticode 策略，无 UI，仅允许缓存 URL 数据，不检查吊销。
`embedded` 保留嵌入式签名状态和原始 trustStatus；`catalog` 独立报告已安装驱动子系统目录中
SHA256/SHA1 哈希对应的签名验证、目录路径、算法、枚举数量、搜索是否完成和原生错误。
任一来源通过时 trusted=true；已检查证据不足以判断时 trusted=null 且退出码 6。如果没有通过的来源，
嵌入式签名或已找到的目录中存在明确不可信结果，且查询完整，则 trusted=false。未找到已安装目录不能证明没有其他脱机目录或无签名。
策略／主体格式不可用返回 5，其他验证调用错误返回 3；受限或部分查询返回 6。
文件在两次检查之间可能变化，两者不是原子快照，在线吊销和其他目录数据库不在检查范围。

## 十六进制与 PE（迁移项 18）

```powershell
KswordCLI.exe file hex query --path PATH [--max-bytes N] [--backend r3] [--json]
KswordCLI.exe file pe query --path PATH [--backend r3] [--json]
KswordCLI.exe file pe header query --path PATH [--backend r3] [--json]
```

hex 默认读取前 256 字节，max-bytes 范围 1..1048576；输出 dataHex、preview、returnedBytes、sizeBytes、limited、complete、displayTruncated、win32Error。
preview 保留后端每行 16 字节的偏移／十六进制／ASCII 展示，JSON 中作为字符串。有效空文件返回 0，
complete 表示请求的前缀已完整读取，displayTruncated 表示文件超出请求预览；完整的受限预览返回 0。文件大小未知或读取短于预期返回 6，读取失败返回 3。

pe query 复用 16 MiB 上限的后端磁盘快照和共享 PE 解析器，展示最多 32 个区段及 64 个导入模块。
输出 deepAvailable、fallbackReason、snapshotSize、bytesRead、machine／machineName、subsystem／subsystemName、
format、imageBase、entryPointRva、entryPointFileOffset、sectionCount、importModuleCount、sections、imports、exportEntries、notes。
地址／RVA／文件偏移与标志为十六进制字符串；大小为十进制字符串。区段保留原名、布局、属性和熵；
导入模块保留名称、描述符、thunk RVA、已解析条目数、函数名或序号、hint、thunk/name RVA 和独立诊断；最多显示 4096 个导入函数，计数和截断状态单独列出。
exportEntries 原样保留旧版导出报告字段、备注和层级；结构化 exportSymbols 按非零 EAT 槽返回序号、RVA、全部已解码名称及转发目标，包含仅按序号导出。名称表不完整时 ordinalOnly 为 null，不把未知名称判为仅序号。exportEvidenceState 区分 unavailable、absent、partial、complete；exportNamesComplete、exportTruncated、exportMalformed 和目录中的函数／名称计数单独报告。解析上限为 4096 个 EAT 槽和 4096 个名称，零槽不计作导出；损坏或受限返回 6。
显示截断通过 sectionsTruncated／importsTruncated／importFunctionsTruncated 明确说明，截断、导出诊断或导入解析不完整返回 6。

fallbackReason 区分 none／unsupported-path／read-failure／size-limit／invalid-pe，不解析 UI 文本判断状态。
超过大小上限而还能取得轻量 header 时返回 6，仅剩路径限制且没有证据时返回 5；读取失败返回 3，
非 PE 或无效深度布局返回 4。Light 为展示而生成的 fallback 文本不能替代有效结构化证据。
header query 只读取 DOS／NT／COFF／OptionalHeader 魔数，包含 machine、sectionCount、timestamp、characteristics、optionalMagic、win32Error；
适用于超过完整快照上限的文件，不验证所有数据目录与区段内容。pe query 的 header 字段仅用于回退证据。
