# PFN 查询（只读）

`memory pfn ranges` 查询物理页范围，`memory pfn owners` 查询进程类型的私有源证据，`memory pfn pages --first PFN --count N` 查询连续 PFN，`memory pfn identities --pfns LIST` 查询离散 PFN，`memory pfn identity --pfn PFN` 查看单个 PFN 的原始身份。以上默认 R3，可用 `--backend r3|r0` 指定实际后端。范围查询在 R3 使用 Superfetch，在 R0 使用 `MmGetPhysicalMemoryRanges`。拥有者和页身份查询在两端都使用 Superfetch。运行需要本机 x64、4 KiB 原生页和相应权限。

`memory pfn mappings --pid PID --creation-time FILETIME --addresses LIST` 经 R0 查询进程虚拟地址的驻留页 PFN，默认且仅支持 `--backend r0`。创建时间为进程创建时刻的 100 ns FILETIME 整数，驱动验证 PID 与创建时间匹配；只查询驻留的用户页，不触发缺页。每个地址分别返回 NTSTATUS，不能用失败项的 PFN。PID、虚拟地址和 PFN 都是瞬时观察。

所有命令支持 `--json`，列表可用 `--limit` 控制显示条数。范围查询从 512 条开始按需增大缓冲，最多返回 65536 条。超过上限会报告状态码和空结果。拥有者最多 16384 条，单次 PFN 最多 4096 个，地址映射最多 256 个。`displayTruncated` 表示显示已截短，`complete` 表示底层查询是否完整。拥有者查询会过滤非进程源，完整性为未知。部分结果或完整性未知以退出码 6 报告。`trace` 保留后端实际调用与状态，原始 `frame`/`backing` 的解释取决于系统版本。

```powershell
KswordCLI.exe memory pfn ranges --backend r3 --json
KswordCLI.exe memory pfn identity --pfn 0x123 --backend r0 --json
KswordCLI.exe memory pfn pages --first 0x100 --count 16 --json
KswordCLI.exe memory pfn mappings --pid 1234 --creation-time 133000000000000000 --addresses 0x10000,0x20000 --json
```
