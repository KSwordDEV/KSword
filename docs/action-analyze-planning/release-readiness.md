# ActionAnalyze 发布准备与指定来宾准入

截至 2026-11-26，正式回执覆盖离线回放、部分被动采样及 CLI 自有目标停点与清退。全范围产品与 7z 成品待验。普通 R0 的指定来宾缓存版本为 `26100.9711`，源码要求 OS build 精确等于 `26300`，专项运行 `0/29`。[11 项产品验收](../ActionAnalyze产品验收清单.md) · [A0–A10 的 33 项施工表](../ActionAnalyze施工任务与契约落点.md) · [普通 R0 准入回执](../../tools/action_analyze_validation/ordinary-r0-readiness-audit.md)

## 产品回执与未闭合能力

| 产品项 | 有回执的范围 | 待验的正式产品范围 |
| --- | --- | --- |
| 1 选择起点后注入 | 自动注入为无。正式本机 CLI 通过自有 AMD64 目标自行启用 Agent 后的就绪验收；不是远程装载。 | 自动注入、启动早期覆盖和双架构。 |
| 2 样本 WinAPI 回传 | 三端自有合作直连、部分 Hook。正式 CLI 缺终段检查点时独立读者退出 `0`、写端退出 `4`，均保留 4 段、526 包、132 条线索。[回执](validation-results.md#2026-11-26--正式-cli-定向回执) | Qt／Light 活水位、真实混采、来源异常及持续全量归档。 |
| 3 归类与展示 | 三端同一合成项目核对访问拒绝的规则 ID、证据级别、坐标和缺字段负例。正式 CLI 补验真实合作档的拒绝及成功负例。Light 合成活跟随补验释义清除。 | Qt 新释义字段窗口实测、同一活采样的混合来源；注册表判断沙箱不凭普通查询归因。 |
| 4 跨进程转移 | 正式 CLI 已验被动 API 候选；三端同一 KSword 自有合成回调归档核对 `raw/1 #2`、源序号 `107`、完整空批和冲突拒绝。 | 真实回调采集、强实例关联和后续执行证据。候选不是传播结论。 |
| 5 脏内存断点及新线程 | 正式 CLI 在自有 AMD64 数据导出实测 `1 / 2 / 4 / 8 B` 写入停点；范围外和同值写放行，首次停点后新建线程写末字节再次命中，旧令牌拒绝并正常脱离。[原始日志](../../.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-014523-393596-36020.log) | 任意私有页、跨区范围、执行时区域版本、异常终止恢复及桌面写入停点。 |
| 6 全局下断及恢复 | 正式 CLI 自有 AMD64 单绑定 131 次停点；合作双目标验证组继续、主动关闭两成员脱离且存活、自然退出两成员继续退出事件。故障重试仅由原生夹具验证（1,072 项）。[回执](validation-results.md#2026-11-26--正式-cli-定向回执) | WOW64 产品停点、非合作或更大目标组、正式 CLI 故障注入和桌面控制；所有者死亡恢复为无。 |
| 7 流量抓取及归档 | 三端通过合成归档回读；CLI 核对完整 `300 B`，Light 对账 `0 / 7 / 300 B` 与原始文件位置。CLI 本机回环 ETW 启用报 Win32 `5`，已清退且未建样。 | 实时归档正例、出站 IP 实证、实捕通信字节、桌面活网络入口。 |
| 8 ETW 遥测及归档 | 正式三端回读同一至少 180 秒的自有 ETW 档，`68` 段、`13,200` 条 ETW，终态原生丢失和队列丢弃均为 `0`；Qt、Light 另外各自验证活采与项目重开。 | 饱和负载、小时级运行、异常清退及 API 混采。 |
| 9 底部树状图 | 正式 Qt 和 Light 已验关系分组、定位被筛掉的 `raw/3 #9`、保留筛选和清筛恢复选中。Qt 支持 Enter 和双击，Light 已验键盘。 | 传播树、跨事件强关系和实时更新。 |
| 10 C# 复杂条件断点 | 正式 Qt 已验离线表达式及 UTF-8 错误位置。正式 CLI 在自有 AMD64 子进程验证真、假、未知三种条件及正常脱离。 | 桌面真实条件停点、多目标绑定及更完整的 C# 语法。 |
| 11 行为规则预置 | 正式 CLI 自有合作采样封段与离线规则同版本、累计 198 条。外置规则缺失、坏 JSON、共享冲突均使目录退出 `4`；恢复退出 `0`、`2 / 5 / 1`。[回执](validation-results.md#2026-11-26--正式-cli-定向回执) | Qt／Light 外置规则实测、扩展规则包的许可、字段依赖与正负例。 |

正式入口为 Qt「监控 → 行为分析 → 总览／项目与采样」、Light「监控 → ActionAnalyze → 打开归档」，CLI 按内置帮助公布实际方法及后端。9 段 ETW、五类 API 和旧单段的回执各有对应产物哈希与样本身份。[发布 ToDo](../ActionAnalyze发布ToDo.md) · [CLI 被动 ETW](../../tools/action_analyze_validation/cli/README.md#passive-etw-session-receipt) · [Qt 回读](../../tools/action_analyze_validation/qt/ETW-Readback.md) · [Light 窗口](../ActionAnalyze总览交互与验收.md#light-普通权限打开归档)

机制回执包括 A0 停止组静态向量 96 项、SB02 自有 x64／WOW64 目标 386 项、R3 步进 106 项和页面执行探针 21 项。IPC 杀父 7 项证明自有冻结子进程被清理，目标正常运行恢复仍待证。Explorer 在途 NX 所有者死亡负控曾失败，成功断连也缺实证。R3 受支持流程以本机且 KSword 驱动不可用时的实测为准。每次采样显式选后端，变更后端时原所有者完成恢复并确认脱离后另开采样。[工程推进记录](../../.claude/memory/ksword-action-analyze-engineering.md#已接收批次与证据) · [R3 补充验证](../ActionAnalyzeR3机制补充验证-20261124.md) · [双后端规则](../ActionAnalyze双后端独立全流程设计.md#4-选择独占与资料身份)

| 工单 | 发布前尚需的证据 |
| --- | --- |
| A0.1–A0.3、A1.1–A1.3 | 三端身份、方法与 Stored 格式一致，项目配置修订、提交水位、重开、写入故障、搬运和索引恢复。 |
| A2.1–A2.3、A3.1–A3.3 | 六域及字段阶段、缺失与真实水位，帮助／REPL／JSONL 一致、背压及原生故障清退。 |
| A4.1–A4.3、A5.1–A5.3 | 双后端分别核对恢复与权限。每来源按实际架构、入口和阶段公告覆盖。 |
| A6.1–A6.3、A7.1–A7.3 | 强实例、来源及区域就绪、快速下一跳、映射代次、执行与归因。 |
| A8.1–A8.3、A9.1–A9.3 | 范围内 12 项动作、调查与字节导出、断连及非目标存续、三端同样本、桌面真实窗口。T12 外部操作回滚、T13 热重载和跨采样自动比较按已确认范围延期。 |
| A10.1–A10.3 | 长跑、故障与实测预算，回归旧 API／ETW、调试器、CLI、桌面导航，冻结依赖、许可证、产物身份、支持矩阵和清理记录。 |

## 正式路径和依赖

- `Ksword5.1/x64/Release/` 是统一正式输出。本轮实际回读的中间目录：Qt `Ksword5.1/Ksword5.1/Ksword5.1/x64/Release/`、CLI `KswordCLI/x64/Release/`、Light `KswordARKLight/x64/Release/obj/`。各端在编译前回读绝对 `IntDir`、`OutDir` 和 HostX64，使用 BelowNormal 和 AMD64 MSBuild。登记实选 `Release|x64`、工具集及退出码；Qt 另记双语和主题结果。Win32 Agent 单列目标架构。驱动的编译链接、API 校验、INF/CAT、签名及来宾运行不随 Light 宿主构建通过，分别留存结果。[统一输出属性](../../Ksword.ReleaseOutput.props) · [Qt 构建](../../tools/Invoke-KSwordBuildCheck.ps1) · [CLI／Light 构建](../../tools/Invoke-KSwordNativeBuildCheck.ps1) · [仓库规范](../../AGENTS.md#发行版制作流程)
- 暂存目录为 `dist/KswordARK-release-work/Release/`，成品位于 `dist/`，归档唯一顶层为 `Release/`。按冻结清单取件。统一输出中的测试 EXE、bootstrap、历史备份、`.obj`／`.ilk`、本机 `config/` 和诊断材料排除在清单外。正式默认配置及获准随包发布的 PDB 逐文件登记。[暂存规范](../../AGENTS.md#2-搭建发行目录)

| 分组 | 清单与核对内容 |
| --- | --- |
| 三端 | `Ksword5.1.exe`、`KswordCLI.exe`、`KswordARKLight.exe`。Light 静态 CRT、系统 DLL 依赖。CLI 按实际导入和延迟导入核对运行库。 |
| 配套 | `Launcher.exe`、`Taskbar.exe`、`KswordHUD.exe`、`KSwordSecureDesk.exe`、`KswordDwmZOrder.dll`。内核转储 GUI 与同目录 CLI 配套。API Monitor 按架构纳入 `APIMonitor_x64.dll`／`APIMonitor_x86.dll`、`profiles/api_monitor_definitions.json` 及适用 PDB。 |
| Qt／CRT | Qt 6.9.3 的 Core、Gui、Network、Widgets、Svg、OpenGL、OpenGLWidgets，另含 `qtadvanceddocking.dll`。Taskbar 依赖 Multimedia 等模块。按实际部署及导入表核对 MSVC CRT、图形及媒体运行库、`platforms/qwindows.dll`、styles、imageformats、iconengines、generic、networkinformation、tls、translations 及适用多媒体插件。 |
| 配置／资产 | `languages/{zh-CN,en-US}.json`、`Style/{StartupLandscape.png,StartupWindows.png,KswordLogo.png}`、`profiles/ark_dyndata_pack_v4.json.qz`、`profiles/launcher_support_manifest.json`、注册表优化清单和 `profiles/registry_optimization_assets/Config/Data.zip`。本次目录可见 `registry_optimization_items.json.qz`，交付名按实际生成链核对。本次目录缺 `profiles/thread_layouts/` 和 `profiles/process_layouts/`，内核结构查看发行范围需补齐。 |
| 驱动 | 根 `KswordARK.sys`、`KswordARK.pdb`、`KswordARKDriver.inf` 及 `KswordARKDriver/` 下的 SYS／INF。签名安装套件登记 CAT，并核对其覆盖的实际文件及签名信任。获准发布的未签名评估包标明状态。 |
| 存储、许可及规则 | Stored codec 0 为基础，按端公布 zstd，系统 SQLite 仅作可选缓存。7z 用于发行包。核对 `LICENSE`、`COMMUNITY_COVENANT.md`、`licenses/third_party/` 下实际随包组件的 LICENSE／NOTICE 及源码条款。包括 Qt／ADS、System Informer、Easy HWID Spoofer、FLTK、zstd、zlib、Zydis／Zycore 等适用组件。随包核对 `profiles/action_analyze_api_rules.json`。规划目录登记本地 601 候选和 9 个固定上游；可发行规则计数取通过字段、许可及真实回放的条目。 |

[主程序工程](../../Ksword5.1/Ksword5.1/Ksword5.1.vcxproj) · [Light 工程](../../KswordARKLight/KswordARKLight.vcxproj) · [CLI 工程](../../KswordCLI/KswordCLI.vcxproj) · [Taskbar 工程](../../Taskbar/Taskbar.vcxproj) · [存储契约](../ActionAnalyze项目存储格式与恢复设计.md) · [规则来源资料](README.md)

## 现有产物 SHA-256 与配置

以下为 2026-11-25 统一 Release 的历史静态抽样，不是当前候选清单。抽样时 `ActionAnalyze` HEAD 为 `23f253146871938589f28fec62bdcee8425135d4`，工作区处于并行开发。后续各端的实际产物身份见[验收回执](validation-results.md)。候选须绑定各组件实际构建提交和源补丁。

| 相对 Release 的文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `Ksword5.1.exe` | 35,056,536 | `84081B13CC7C12F5A7C55ABEA0469716204776C1992328850682A89D692F958E` |
| `KswordCLI.exe` | 6,551,040 | `B05ABCD310B28515036802D70C5AB8CBBF7B74815EC35F63C7F70B1D8F74E37A` |
| `KswordARKLight.exe` | 12,118,016 | `5D054981D1C1C019CA81F14FCD6979B56CFE20F15189F96564BADD02740C3412` |
| `APIMonitor_x64.dll` | 6,213,120 | `E5A6A1E8BA34A73AC029F309984F251ECF5079C7B7829A2728279EF85A171A62` |
| `APIMonitor_x86.dll` | 8,106,496 | `11D1CA85B6471F538C627405F605054EF0F856BF94777C7A09F297E79B4749CA` |
| `Launcher.exe` | 486,400 | `EC414D4203B31D6C5C3308D5C636C352ED0061ED4D7FAD8107A46B2C58725FB7` |
| `Taskbar.exe` | 529,920 | `F63FF5AC3A86C413BB2A399FE8E0DBC5FD59807C0296F3273BFCD34C06D3F0EE` |
| `KswordHUD.exe` | 475,648 | `6EF864FA218FB3CA8EDE88D5DFB984733689F96E3FF30FE1A796AFDF2588B314` |
| `KSwordSecureDesk.exe` | 272,896 | `DDDAF393B304109C4637F448C5FF3516CF9D4DFD74B7503FD3E61589BA65E63D` |
| `KswordDwmZOrder.dll` | 1,103,360 | `317A83EE1437602BA615DD4C4D1AB49FAC18124D7643E8D2DBC7A51298BD7CC4` |
| `KswordARK.sys`、`KswordARKDriver/KswordARK.sys` | 3,665,008（各） | `AB896E94F6B5E5C9CAE01F73C25DEA0CA705A7F3E333B96884100E1AEB7851E3` |
| `KswordARK.pdb` | 14,602,240 | `BB1649600343AFE98B5195DCE866C02CC3318153FD45AC1A0026E68FFF81A9BD` |
| `KswordARKDriver.inf`、`KswordARKDriver/KswordARKDriver.inf` | 2,400（各） | `FEB9700A61DD44CDA556D4B019A3863C750356429798A930A56583748F3BF70C` |
| `KswordARKDriver/kswordarkdriver.cat` | 1,344 | `F6149CECE7482DF2A666A17800411C3D7B185D49C3B739392EFCD90F224F2D63` |
| `languages/zh-CN.json` | 4,417,059 | `38AA180DBF0BBB4A0D823F8BCDAC62A96D4C7A781F94A34CBC7ED79F32074EF3` |
| `languages/en-US.json` | 4,661,434 | `DB7964BFF4C35FA71F5D059579B11492CBBF47D107099C6C0EB80D098F4C067D` |
| `profiles/api_monitor_definitions.json` | 1,454,745 | `67AA8A6476434D7AF2564B1A2DC1A8F12AA16FD792CFE55E2EE2B6489CD049D1` |
| `profiles/ark_dyndata_pack_v4.json.qz` | 7,422,819 | `5285DC30D7BC505D3556611A873F84223AAF12C2C635915943B630067485E187` |
| `profiles/launcher_support_manifest.json` | 1,109,449 | `6841AAD1B6B6AB6246FFF58BFC15261492AE41F03E33DEB175218EA98ED87FCD` |
| `profiles/registry_optimization_items.json.qz` | 116,594 | `9AE707FA6A1AB79EFAB9A7E44C7BC474BF2F95ABAAC5E9079675EBFC19C1163F` |
| `profiles/action_analyze_api_rules.json` | 2,336 | `45A1438F3ECB31467A5D780502D38F423DBEB2C0865AB5D38B58C78CBE2D27F4`（`ksword.api.behavior-presets.v1`，已核对 Release 散列） |
| `profiles/registry_optimization_assets/Config/Data.zip` | 95,849 | `93DBE35AE3796136EB5B5B6B81E57819E9A1EB46C16B5E7229CEB7C95BBC7695` |
| `platforms/qwindows.dll` | 925,920 | `133983755958A0F4D955B4A6F3712A014AC62351EC5EDD3C32B802094F66AC96` |
| `qtadvanceddocking.dll` | 553,472 | `A6625EF523A10F3AF34E6EC751FC05B8077446872F4171FD110A63D924B9EF61` |

抽样时两份语言包分别与源码字节一致。本机 `.codex-build-logs/` 的 `action-analyze-qt-toolbar.log` 绑定上表 Qt／CLI，记录两段收尾、窗口退出 `0`、配置恢复及夹具清理。`action-analyze-cli-product-{breakpoint,memory}-current.log` 绑定上表 CLI。`action-analyze-light-legacy-filter-retest.log` 绑定上表 Light 及旧单段 14／12 行。9 段回执 `action-analyze-light-continuous-etw.log` 与五类同档回执 `action-analyze-three-product-api.log` 使用 CLI 哈希 `6ADAA75FE50969B8406E685DE9744AFE205EC5139120C6842D494EAFF139D04F`。

发布候选逐文件记录相对路径、字节数、SHA-256、版本、架构、构建提交及签名状态。产品回执绑定实际入口、OS／权限、后端、目标实例、来源版本、`projectId`／`sampleId`、冻结配置 `revisionId`／`snapshotId`／`configSemanticHash`、规则或断点包、原始段及检查点哈希、退出、未决责任和清退。旧回执缺失字段记 `未记录`。测试配置恢复或删除、固定路径的夹具清理按各批实录填写。

## 7z 成品核对

有授权且成品就绪时，使用实际 7z 程序和包路径运行以下只读校验。本轮结果为命令静态语法审查，成品完整性和成品 SHA-256 待验。

```powershell
$seven = (Resolve-Path -LiteralPath $env:KSWORD_RELEASE_7Z -ErrorAction Stop).Path
$archive = (Resolve-Path -LiteralPath $env:KSWORD_RELEASE_ARCHIVE -ErrorAction Stop).Path

& $seven t $archive
if ($LASTEXITCODE -ne 0) { throw '7z integrity test failed' }

$listing = @(& $seven l -slt $archive)
if ($LASTEXITCODE -ne 0) { throw '7z inventory failed' }
$separator = [Array]::IndexOf([string[]]$listing, '----------')
if ($separator -lt 0) { throw '7z entry list missing' }
$paths = @($listing | Select-Object -Skip ($separator + 1) | ForEach-Object {
    if ($_ -match '^Path = (.+)$') { $Matches[1].Replace('\', '/') }
})
if (!$paths.Count -or ($paths | Where-Object { $_ -notmatch '^Release(?:/[^/]+)*$' })) {
    throw 'Expected Release as the sole package root'
}
$paths | Where-Object { $_ -ne 'Release' }
Get-FileHash -Algorithm SHA256 -LiteralPath $archive
```

回执保存 `Everything is Ok` 和退出 `0`，依冻结清单对照全部条目。至少核对三端、配套 EXE／DLL、所选驱动及配置、语言、Qt 平台插件、资产与许可证。核对包内文件的 SHA-256 后，将回执和清单绑定到成品包 SHA-256。项目原始段和检查点由产品格式验收独立记录。[仓库成品校验](../../AGENTS.md#4-校验发行包)

## 普通 R0 来宾的无侵入前置检查

| 检查 | 现有证据及可准备材料 |
| --- | --- |
| 指定来宾与 OS | 只读查看 `E:/VMs/Windows11-24H2/Windows 10 x64.vmx` 的 VMware Tools 缓存，得到 `bitness=64`、`buildNumber=26100`、`kernelVersion=26100.9711`。旧回执另有挂起日志和宿主状态。准入谓词为 `RtlGetVersion().dwBuildNumber == 26300`，目前版本条件不满足。驱动身份表中的 `26100.9711` 是 PE 映像版本。T01–T29 均未执行。[准入源码](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach_hook.c#L86) · [宿主回执](../../tools/action_analyze_validation/ordinary-r0-readiness-audit.md#指定来宾及证据时效) |
| 产物身份与签名 | 准备同批 SYS／INF／CAT／PDB、消费者版本、PE 机器类型、精确内核映像和 RSDS GUID/Age 所需比对项。旧准入回执 SYS 哈希为 `96F6310DC74C72ECA4FA3FDD7EDC35F8E0CEE1F394A7BC10FDA2D8E9892CEC39`，宿主验签为 `UnknownError`。本次 SYS 哈希为上表 `AB896E94…`。同哈希的既有 `.codex-build-logs/action-analyze-light-source-filter-build.log` 中 SignTool 核验退出 `1`，原因为证书链终止于不受信任的根。CAT 覆盖、来宾信任与运行绑定待核验。 |
| 来宾预检字段 | 从已存在的证据或授权只读报告取实际 OS build／修订、AMD64、处理器组、代码完整性状态、服务注册及实际加载、证据时间与来源。工程基线曾记录已有 `TESTSIGNING`、服务未注册、驱动未加载，来宾实时状态未核验。前置不符或缺失时保持阻塞，维持现有系统策略。[工程基线](../ActionAnalyze工程开工基线.md#验收范围与运行环境) |
| 能力与专项证据 | 历史正式 CLI 的 `offline` 公告 12 项方法，`r0`／`r0-noattach` 返回不支持，静态停止组向量通过 96 项。历史准入审计指出驱动 Query 有内部状态或租约副作用。T01 的实际驱动回读属于单独授权的运行验收。可先准备 A4／A7 的 29 项回执字段，包括前置、端、候选哈希、结果、原始错误和未决恢复，当前各项均为 `未执行`。[能力回执](../../tools/action_analyze_validation/ordinary-r0-readiness-audit.md#实际运行的只读核验) · [专项判据](../ActionAnalyze多通道通信与控制施工设计.md#74-普通-r0-后端的静态审计门槛) |

## 交接

用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。本轮对齐已验能力与待验范围。下一可执行步骤为按产物哈希核对当批回执和候选清单，继续三端复读同一长程样本及 R3 产品验收。正式 7z、完整产品和普通 R0 运行待验。候选就绪后绑定版本、签名、配置及成品完整性回执，普通 R0 保留有效准入和单独运行授权条件。仅验收闭合批次推送 `ActionAnalyze`。
