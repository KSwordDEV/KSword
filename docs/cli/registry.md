# 注册表 R3 命令

## 浏览和读取（迁移项 08）

```powershell
KswordCLI.exe registry key enum --path PATH [--kind all|keys|values] [--limit N] [--max-value-data-bytes N] [--backend r3] [--json]
KswordCLI.exe registry value read --path PATH [--name NAME] [--max-data-bytes N] [--backend r3] [--json]
KswordCLI.exe registry enum-key --key KEY --backend r3 [--kind all|keys|values] [--limit N] [--max-value-data-bytes N] [--json]
KswordCLI.exe registry read-value --key KEY --backend r3 [--value NAME] [--max-data-bytes N] [--json]
```

业务树通过 `help registry` → `help registry key`／`help registry value` → 叶子帮助查询。
新增树默认为 R3；既有 enum-key/read-value 省略 backend 保留原 R0 输出，显式 `--backend r0` 同样走原路径。
显式 R3 不打开驱动，不接受 R0 专用 flags/hexdump/协议采集上限参数。每个叶子帮助同时说明两种语法。

path/key 支持 HKLM、HKCU、HKCR、HKU、HKCC 和完整根名称，也支持后端已实现的 `\REGISTRY\MACHINE`／`\REGISTRY\USER` 路径。
采用 CLI 进程的原生 x64 注册表视图，不增加后端未实现的 WOW64 视图选项。非法路径返回用法错误 1。
读取 name/value 省略或为空表示默认值；包含空格的路径和值名称应加引号。

枚举提供键／值区分、原始类型、类型名称、字节数、原始 dataHex、显示文本及截断标志。
显示 limit 默认 100；kind 默认 all，可筛选 keys/values。每值原始数据预览默认 256 字节，可调整 max-value-data-bytes。
单值读取的 max-data-bytes 同样默认 256，0 只输出统计。文本预览最多 256 字符。
显示／数据预览截断独立于采集完成状态，不导致操作失败；需要完整原始数据时增大字节预览参数。

枚举输出 complete、win32Error、匹配／显示数和 entries。完整结果返回 0；原生枚举中有读取失败时保留已采集行并返回 6。
单值读取输出 path、name、type、typeName、dataBytes、returnedBytes、dataTruncated、dataHex、dataText、win32Error。
缺失键／值和权限失败返回 3，并保留 Win32 状态；有效空键、空值均为成功。

## 搜索（迁移项 09）

```powershell
KswordCLI.exe registry search query --path PATH --query TEXT [--max-keys N] [--max-values N] [--max-results N] [--max-depth N] [--max-preview-bytes N] [--backend r3] [--json]
```

按不区分大小写的子串搜索键路径、值名称／类型及有界数据预览。空查询或非法路径返回 1。
复用后端固定预算：键、值、结果默认／上限各 2000，深度 32，数据预览 16384 字节。
0 使用后端默认值，超过上限会归一化；effectiveBudgets 明确输出实际预算。

输出路径、查询、完整性、stopReason、firstWin32Error、各项计数及 hits。
每个命中含 kind、path、name、typeName、dataPreview、原始数据字节数、深度及 previewTruncated。
预览被截断或根本未读取的大值仍保留标记，结果不声称已经搜索了未读取的完整数据。
预算边界、深度截断、部分读取失败或 Ctrl+C 取消返回 6；完全读取失败返回 3；完成且无读取失败返回 0。
没有命中的完整搜索是成功。Win32 错误来自实际系统调用，不解析显示文本来决定退出码。

## 修改（迁移项 10）

```powershell
KswordCLI.exe registry key create --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe registry key delete --path PATH --confirm [--backend r3] [--json]
KswordCLI.exe registry value set --path PATH [--name NAME] --type sz|expand-sz|multi-sz|dword|qword|binary|none|N (--text TEXT | --hex HEX | --data-file PATH) --confirm [--backend r3] [--json]
KswordCLI.exe registry value delete --path PATH [--name NAME] --confirm [--backend r3] [--json]
KswordCLI.exe registry value rename --path PATH --old-name NAME --new-name NAME --confirm [--backend r3] [--json]
```

所有修改都要求 confirm；创建可打开已有键，created 区分新建与已有。删除键递归删除非根键树，不支持删除预定义根。
value set 三种载荷互斥。text 支持 SZ/EXPAND_SZ 字符串、分号分隔 MULTI_SZ、十进制／0x 前缀 DWORD 和 QWORD。
hex 接受完整字节、可选单个 0x 前缀和空格；data-file 提供不转换的原始字节，沿用 CLI 64MiB 载荷上限。
数字 type 保留原始 REG 类型。Binary/None 等原始类型使用 hex 或 data-file；空载荷可写入有效空值。
省略 name 或指定空名称表示默认值。原始字符串字节以 UTF-16LE 提供，text 形式自动补充字符串终止符。

结果含 requestSucceeded、win32Error、partial、unchanged、verified 和 result。
每个修改后调用共享 R3 读取后端验证实际字节／类型、键存在或值缺失。系统调用成功但回读未确认返回 6；
完整确认返回 0；实际操作失败返回 3／不支持返回 5。载荷文件读取失败保留 dataFileWin32Error，并不进行注册表写入。

值重命名复用“读取、写新名称、删除旧名称”的现有实现，可能覆盖新名称已有值，且不是原子事务。
写新值成功、删除旧值失败标记 partial 并返回 6。大小写不敏感的同名重命名为 unchanged，保留原值。
R3 键重命名尚未实现，本轮不发布跳过式命令；原 R0 rename-key 命令仍保留。

原有 create-key/delete-key/set-value/delete-value/rename-value 可用 `--backend r3` 选择同一实现：
路径参数为 key，值参数为 value，重命名参数为 old-value/new-value，其他 R3 参数同上。
省略 backend 或指定 r0 保留原语法、行为和输出；具体 help 同时列出两种语法。
