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
