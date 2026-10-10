# 安全证据 R3 命令

## VBS／HVCI／SKCI（迁移项 59）

```powershell
KswordCLI.exe security vbs help
KswordCLI.exe help security vbs hvci query
KswordCLI.exe security vbs device-guard query --json
KswordCLI.exe security vbs hvci query --json
KswordCLI.exe security vbs registry query --json
KswordCLI.exe security vbs files enum --json
KswordCLI.exe security vbs query --json
```

参数、统一 data/evidence/capture 字段和退出码同 CI。`query` 汇总八个来源：DeviceGuard CIM、三个系统文件状态、三项 HVCI 注册数据、三项 VBS／平台／LSA 注册数据。CIM payload 提供 virtualizationBasedSecurityStatus/requiredSecurityProperties/availableSecurityProperties/securityServicesRunning/securityServicesConfigured。`hvci query` 读取 HypervisorEnforcedCodeIntegrity 的 Enabled/WasEnabledBy/Locked；`registry query` 读取 EnableVirtualizationBasedSecurity/RequirePlatformSecurityFeatures/LsaCfgFlags，保留 HKLM64 视图、原始类型／值／错误及关闭证据。注册配置不等于当前已生效的 HVCI／VBS 状态。

`files enum` 只报告 System32 的 securekernel.exe/skci.dll/ci.dll 的 name/path/known/present，错误与真实缺失分开。旧 UI 的“Secure Kernel modules”条目实际检查磁盘文件，CLI 据实命名，不推断安全内核已启动、SKCI 在运行或模块已加载。CIM 缺失保留不可用／结构化错误，真实关闭或未知值为 null，不自动回退 R0、不修改配置或启停安全功能。help 不采集，VM／宿主分别用 CIM、64 位注册视图和磁盘查询核对。

## Code Integrity／WDAC（迁移项 58）

```powershell
KswordCLI.exe help security
KswordCLI.exe security ci help
KswordCLI.exe help security ci device-guard query
KswordCLI.exe security ci device-guard query --json
KswordCLI.exe security ci policy-files enum --json
KswordCLI.exe security ci registry query --json
KswordCLI.exe security ci service query --json
KswordCLI.exe security ci query --json
```

`security ci query` 汇总六个共享后端已有来源；其他叶子分别查询 CIM DeviceGuard 的 CI 属性、两个磁盘策略目录文件数、HKLM64 的 UpgradedSystem／Enabled／UEFISecureBootEnabled 注册值、CI 驱动服务状态。所有叶子支持 `--duration-ms 500..60000`（整体 30000）、`--timeout-ms 500..30000`（每辅助进程 12000，受剩余整体预算限制）、`--max-data-bytes 1..65536`（注册数据预览 256）、`--backend r3`、`--json`。

data 提供 source/requestedCount/returnedCount/successCount/partialCount/unavailableCount/failedCount/limited/cancelled 和 evidence。每条有 id/source/kind/status/exitCode/data/capture。CIM data 保留 availableSecurityProperties/securityServicesConfigured/securityServicesRunning、codeIntegrityPolicyEnforcementStatus/usermodeCodeIntegrityPolicyEnforcementStatus，缺失属性为 null。策略目录 data 保留 path/known/present/fileCount（十进制字符串），错误与有效缺失分开；使用实际 Windows 目录，修复旧辅助脚本把 `$env:windir` 作为单引号字面量路径的问题。文件存在／文件数不证明策略已激活或强制执行。

注册 data 包括 HKLM64 路径／名称、打开／查询／关闭状态、available/absent/type/reportedBytes/value/dataHex/dataTruncated/limited/malformed。DWORD 为数值，QWORD 为十进制字符串，其他类型保留原始字节；未得到的数据为 null，已证实不存在也不解释成策略禁用。64 KiB 读取边界、实际 DWORD／QWORD 字节长度和关闭失败均可见。服务 data 保留 SCM／服务打开、available/absent、原始错误、state/serviceType/pid 和两个自有句柄的关闭证据；CI 服务登记不是活动模块证明。

辅助进程使用隐藏的系统 PowerShell、UTF-16 编码脚本和 UTF-8 JSON 输出。capture 记录实际 started/exitCodeKnown/exitCode/win32Error/waitCompleted、timedOut/cancelled/terminated/terminationWin32Error/terminationWait、outputTruncated/outputWin32Error/decodeMalformed/closeWin32Error/diagnostic。单个输出最多 128 KiB；达到预览上限后继续排空管道，避免辅助进程堵塞。超时／取消只停止本次创建的辅助进程并回收自有句柄。JSON 用已有无损解析器校验深度、大小、重复键、UTF-8 和整数，不解析 UI 的“成功／失败”文字，不把进程结束当作安全证据已取得。

完整来源／有效缺失为 0；混合结果、关闭、预算／取消或预览截断为 6；全部查询失败为 3；来源不可用为 5；无合法结构化数据或格式错误为 4。CIM／系统版本／权限可能限制来源，按来源报告，不能用缓存值推断当前内核 CI 状态。没有策略、注册表或服务修改，不打开驱动或回退 R0。help 不执行查询或启动辅助进程。
