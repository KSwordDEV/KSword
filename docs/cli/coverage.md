# Light R3 的 66 项 CLI 覆盖

清单顺序来自 `shared/usermode/backend/MIGRATION.jsonl`；每项随实现、内置帮助、业务文档和可复现测试独立提交。`coverage.json` 保存可自动核对的命令树路径。

| 项 | 原始迁移功能 | CLI 路径／文档 |
| --- | --- | --- |
| 01 | TCP/UDP connections | `network connections`；[network](network.md) |
| 02 | Ping | `network ping`；[network](network.md) |
| 03 | route tracing | `network trace-route`；[network](network.md) |
| 04 | DNS lookup | `network dns`；[network](network.md) |
| 05 | firewall rules | `network firewall`；[network](network.md) |
| 06 | network R3 endpoint audit | `network endpoint-audit`；[network](network.md) |
| 07 | service enumeration and control | `service`；[service](service.md) |
| 08 | registry browsing and reads | `registry`；[registry](registry.md) |
| 09 | registry search | `registry search`；[registry](registry.md) |
| 10 | registry mutations | `registry`；[registry](registry.md) |
| 11 | startup enumeration | `startup`；[startup](startup.md) |
| 12 | startup enable disable and deletion | `startup`；[startup](startup.md) |
| 13 | current process token and privilege control | `privilege`；[privilege](privilege.md) |
| 14 | directory browsing and path navigation | `file directory`；[file](file.md) |
| 15 | file creation transfer rename and deletion | `file`；[file](file.md) |
| 16 | file ownership and lock inspection | `file ownership`；[file](file.md) |
| 17 | file hash signature and entropy analysis | `file hash`；[file](file.md) |
| 18 | file hex and PE snapshot analysis | `file pe`；[file](file.md) |
| 19 | process base enumeration | `process enum`；[process](process.md) |
| 20 | process extended field collection | `process detail fields`；[process](process.md) |
| 21 | process dynamic and network telemetry | `process telemetry`；[process](process.md) |
| 22 | native process controls | `process`；[process](process.md) |
| 23 | process detail basic collection | `process detail basic`；[process](process.md) |
| 24 | process thread queries and controls | `process thread`；[process](process.md) |
| 25 | process module queries and controls | `process module`；[process](process.md) |
| 26 | process token details and editing | `process token`；[process](process.md) |
| 27 | process token switches | `process token switches`；[process](process.md) |
| 28 | process PEB and memory queries | `process peb`；[process](process.md) |
| 29 | process usermode hotkey collection | `process hotkeys`；[process](process.md) |
| 30 | driver R3 enumeration and metadata | `driver modules`；[driver](driver.md) |
| 31 | hardware device enumeration | `hardware devices`；[hardware](hardware.md) |
| 32 | hardware system performance sampling | `hardware performance`；[hardware](hardware.md) |
| 33 | hardware disk activity sampling | `hardware disk`；[hardware](hardware.md) |
| 34 | hardware USB topology | `hardware usb`；[hardware](hardware.md) |
| 35 | hardware system bus topology | `hardware bus`；[hardware](hardware.md) |
| 36 | window enumeration and management | `window`；[window](window.md) |
| 37 | window clipboard reading | `clipboard`；[window](window.md) |
| 38 | window capture protection | `window capture`；[window](window.md) |
| 39 | window hierarchy diagnostics | `window hierarchy`；[window](window.md) |
| 40 | global hotkey occupancy probing | `window hotkeys`；[window](window.md) |
| 41 | ETW sessions event capture and filtering | `monitor etw`；[monitor](monitor.md) |
| 42 | system file holder scanning | `system file-holders`；[system](system.md) |
| 43 | system event log reading | `system event-log`；[system](system.md) |
| 44 | system context menu scanning and recovery | `system context-menu`；[system](system.md) |
| 45 | system time and timezone | `system time`；[system](system.md) |
| 46 | IOCTL decoding | `system ioctl`；[system](system.md) |
| 47 | kernel object namespace overview | `kernel namespace`；[kernel](kernel.md) |
| 48 | kernel recursive object directories | `kernel directory`；[kernel](kernel.md) |
| 49 | kernel symbolic links | `kernel symlink`；[kernel](kernel.md) |
| 50 | kernel Device and Driver objects | `kernel objects`；[kernel](kernel.md) |
| 51 | kernel BaseNamedObjects | `kernel base-named-objects`；[kernel](kernel.md) |
| 52 | kernel communication endpoints | `kernel endpoints`；[kernel](kernel.md) |
| 53 | kernel object type matrix | `kernel object-types`；[kernel](kernel.md) |
| 54 | kernel named pipes | `kernel pipes`；[kernel](kernel.md) |
| 55 | kernel Atom tables | `kernel atoms`；[kernel](kernel.md) |
| 56 | kernel NtQuery queries | `kernel nt-query`；[kernel](kernel.md) |
| 57 | kernel Hook disk image baseline | `kernel hook-baseline`；[kernel](kernel.md) |
| 58 | security Code Integrity and WDAC | `security ci`；[security](security.md) |
| 59 | security VBS HVCI and SKCI | `security vbs`；[security](security.md) |
| 60 | security Hyper-V | `security hyperv`；[security](security.md) |
| 61 | security AppLocker | `security applocker`；[security](security.md) |
| 62 | security BAM and ahcache | `security bam`、`security ahcache`；[security](security.md) |
| 63 | security Bugcheck VMware R3 evidence | `security bugcheck`；[security](security.md) |
| 64 | window list capture protection | `window capture`；[window](window.md) |
| 65 | clipboard clearing and live owner queries | `clipboard`；[window](window.md) |
| 66 | process identity sampling adapters | `process identity`；[process](process.md) |

PEB 的远程字段写入仍未发布；UI 导航、绘制、复制等辅助方法复用在输出／适配层，不成为独立操作。窗口列表捕获保护复用已有 capture 入口，Bugcheck 的 R3 项只有系统环境查询。部分硬件／系统能力按真实不可用语义验收，不能据此宣称成功实测。

核对全部迁移顺序、命令路径、业务文档和所有帮助层级：

```powershell
tools\Test-KSwordCliR3Coverage.ps1 -Cli Ksword5.1\x64\Release\KswordCLI.exe -ReportPath "$env:TEMP\KswordCLI-R3-coverage.json"
```

后端独立头文件边界检查可使用 `tools/Test-KSwordR3BackendBoundary.ps1 -EvidenceDirectory` 指定仓库之外的证据目录。运行报告、构建日志和原生夹具产物不提交；测试脚本／源码随各功能提交。
