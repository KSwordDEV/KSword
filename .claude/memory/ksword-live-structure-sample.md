# 实时结构采样与回执验收

状态日期：2026-11-23。完整进度与证据范围见
[验收记录](../../docs/validation/实时结构采样与在线内核栈验收-20261122.md)。
代码已在 `b2927455d` 提交；该提交没有包含被忽略的结构布局数据，不能等同于可独立重建的完整交付。
下面历史段落中的“未提交”指当时状态；不要把已提交或已编译等同于已发布能力。

## 2026-11-23：精确布局不使用邻版风险底色

- 用户纠正颜色规则：精确 PE/RSDS 命中后，即使当前版是目录端点或缺少严格前后邻版，
  EPROCESS/ETHREAD 根项和全部成员也应使用正常主题背景。双侧版本判断仅用于未命中精确布局的参考。
- 共享 `AppendLayout` 不再按 `bracketed` 染黄；EPROCESS 页及两个线程入口的正文、仅布局、
  固定字段回退路径均遵守同一规则。读取失败、未采样、union 和暂不支持解码继续显示真实文字状态。
- 页面仍属于专业结构树：复用 `KernelStructureTree::Configure`、`TablePresentation` 及现有五列模型；
  无新增布局或用户文案。按用户限制仅做源码和正式 Release 构建/包校验，不进行 GUI 或离屏 GUI 验收。
- 本次修正的 HostX64 Release 增量构建通过，`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`、语言审计通过；
  日志 `.codex-build-logs/ksword-build-check-20261123-224744.raw.log`，产物仍为正式
  `Ksword5.1/x64/Release/Ksword5.1.exe`。实际深浅主题、选择态和各回退分支由用户手动验收。

## 2026-11-23：完整结构与版本索引统一并入 v4

- 用户明确要求单一 v4 发布。`ark_dyndata_pack_v4.json.qz` 顶层新增 `structureLayouts`
  用户态扩展：`formatVersion=1`，`fieldSets` 保存按 SHA256 去重的完整 TSV 字段正文；
  `thread_layouts` / `process_layouts` 分别保存原始 `catalog` 文本及文件名到 `[rootSize, fieldSetKey]`
  的 `profiles` 映射。两个索引及每类 1,946 个精确身份全部内嵌，184 份共享正文不丢任何字段。
- `shared/usermode/ThreadLayoutPack.cpp` 是 GUI/CLI 共用的生产消费者：有界 qCompress 解压、
  选择性 JSON DOM、字段正文/目录完整性校验，按路径/大小/时间缓存已验证扩展。只在精确
  PE 三元组加非空 RSDS GUID/Age 全匹配时返回布局；参考仍由原邻版选择器处理，不增加 R0 授权。
  完整字段继续由 `ThreadLayoutProfile::Parse` 核验。CLI 不引入 Qt 运行时依赖，使用静态 zlib，
  原许可证及修改说明在 `third_party/zlib/`，随包部署 `zlib-LICENSE.txt`、`zlib-NOTICE.md`。
- GUI `LoadLayout`、CLI 两条 `layout query` 与两条 `layout sample` 均已切换到单一 v4。
  不再读取外置 TSV 或 `.neighbors`；五列树、内嵌结构、两个线程入口和独立进程子页没有重排。
   无精确布局时仍显示包内邻版参考，参考缺严格前后邻版继续黄色，参考不能授权现场采样。
- 发布同步器、规范化器、压缩器及 GUI/CLI 构建链均保留/生成该扩展；源码 TSV 与索引作为
  已入 Git 的可审计输入继续保留，正式 Release 不再复制独立布局目录。原 Release 两目录
  的 3,894 个文件已逐字节对照源码、确认未被 Git 跟踪且无占用后删除，源码没有删除。
- 对原两包中的旧 v4 比较：2,932 个业务 profiles / 591,302 个 items 对象完全不变。
  新 v4 为 7,422,819 字节，SHA256 `5285dc30d7bc505d3556611a873f84223aaf12c2c635915943b630067485e187`。
  该文件不能与旧单纯业务 v4 互换后声称仍有完整结构布局。
- `Invoke-StructureSampleTests.ps1 -IncludeExactProfiles` 通过原生全量对照：ETHREAD 1,507,365 行、
  EPROCESS 1,294,309 行，全部身份、版本、根大小和每个字段属性一致。新增
  `test_v4_structure_layouts.py` 的四组测试含原生损坏包拒绝；旧投影、客户端、wire 回归通过。
  生产 Qt 业务消费者仍接受全部 2,932 个 profiles 和四个拒绝用例，发布器八项单测通过。
- 删除 Release 外置目录后，正式 CLI 的磁盘布局回归通过（本机线程 766 / 进程 672 行），
  现场采样前置拒绝也通过并明确 `deviceAccessAttempted=false`；没有加载宿主驱动或做 GUI 自动化。
- 最终主程序 HostX64 / BelowNormal 整合 Build 通过，日志
  `ksword-build-check-20261123-033040.raw.log`：`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，
  语言审计通过；EXE 34,416,536 字节，SHA256
  `93C0700E65B8346F371AB7F26C2A3B9EC9DD7CB33CAF3C5AB87A5C41E4C18BAC`。
  CLI、Launcher 同步构建成功；本轮源码修改尚未提交/推送。
- 最终只同名更新 `Ksword5.1/x64/KswordARK-5.2.1.1Pre.7z`（48,459,865 字节，121 文件）
  和 `KswordARK-5.2.1.1Pre-PDB.7z`（30,475,151 字节，8 文件）。两包精确白名单、7z 完整性、
  逐文件 CRC/冻结输入 SHA256、全部八对 PE/PDB GUID/Age 及包内两类各 1,946 身份均通过。
  没有新建日期版、ZIP 或校验交付文件；历史其它版本包未动。原生/CLI 测试配置目录已清理。
  最终包摘要及冻结输入保存在 `.codex-build-logs/package-v4-layouts-20261123-inputs.json`：
  程序包 `339F48A89BC5757FBADC4285D307B6E2AD1FC39358B21FD0D46B124B3BE2BF92`，
  PDB 包 `13F320BE85D80CEE8C6E88842B8D08B7530024764729A7201EBDF42D7C9CA824`。

## 2026-11-22 偏移数据交付补查

- 数据及修复已在 `483caa7c4` 实际提交，远端合并为 `f5680a23e`。对该干净合并源码再次正式 Build 通过，
  日志 `ksword-build-check-20261122-203913.raw.log`，主 EXE 34,378,240 字节，SHA256
  `686D5CEF94282607503B6ED2AC8028E355D2800FF63823385FB93A85AE150C89`，版本字面量为 `5.2.1.1Pre`。
  先前双 VM 验收冻结的驱动/CLI 哈希只对应当时产物；本次 CLI 仅重建/磁盘布局回归，不冒充重新完成 VM 栈验收。
- `.gitignore` 原先整体忽略 `profiles/`，两类各 1,946 份 TSV 和各自 `_versions.index` 全部漏交。
  现只为 `thread_layouts`、`process_layouts` 的 TSV/参考分片/版本索引开放例外，其它生成资产仍忽略。
  两类数据共 3,894 个文件；已核对 Git 暂存 blob、源文件和正式 Release 逐字节一致。
- `.gitattributes` 对两个目录强制 LF。生产加载器是二进制 LF TSV 读取，Windows 的 CRLF checkout
  不能再让新克隆上的精确布局和版本目录同时失效。GUI/CLI 单独构建都复制版本索引，缺分片/索引直接报错。
- 本机磁盘内核 `10.0.19041.7844` 可由正式 CLI 读取 ETHREAD 766、EPROCESS 672 行；它恰好是
  当前 19041 分支最高版本，仍按用户规则黄色。黄色不等于字段必须消失，也不代表快照读数都是失败。
- 参考来源选择与风险判定拆开：双侧无歧义才算 bracketed；没有精确布局时，单侧、同版异 RSDS、
  最近版本多 PE 来源仍保留完整参考字段，逐来源注明版本/RSDS，绝不拿参考偏移授权采样。不同分支不冒充可比。
- `Invoke-StructureSampleTests.ps1 -IncludeExactProfiles` 已使用生产加载器全量读取两类各 1,946 份布局，
  分别 1,507,365 / 1,294,309 个字段，通过全部身份与格式核验。新增参考选择回归、原有投影/客户端/wire 回归通过。
  这次没有加载宿主 R0，也没有重新声称 GUI 或 SYSTEM/UIAccess 实机验收通过。

## 最新结论：保存上下文原始内核链已双机实测（10:14–10:16 UTC）

- 下方APC零帧/完整栈未完成等表述是08:40前历史。独立新端点 `0x8D7`、版本1、48/792字节，
  仅支持精确Win10 19041.631和Win11 26100.9711，单处理器组、64KiB副本、16个在途上限。
  协议只在 `shared/driver/KswordArkThreadStackSnapshotIoctl.h`；实现为
  `features/thread/thread_stack_snapshot*.c/.h`，不能把旧 `0x8D6` 680字节响应混用。
- 实际全处理器DPC会合确认目标不运行且保存栈驻留，再复制私有栈到PASSIVE_LEVEL原生展开。
  不投递目标APC，不挂起/唤醒目标，不扫描返回地址。真实机器帧提供用户CS、原生恢复RIP/RSP，
  有界检查和原生上下文一致才能 `complete=true`；只表示内核段到用户边界，不含R3链。
- Win10 saved5：2026-11-22 10:14:47.6318709–10:14:51.0687753 UTC；Win11 saved6：
  10:16:20.3886105–10:16:24.2305017 UTC。每台20个CLI事件，全部退出码符合预期。
  等待各7帧、忙碌分别5/4帧，均完整到CS=0x33用户机器帧；四路并发各7帧；limit1明确部分退出6。
  采样严格分子仍为Win10进程442/641、线程447/766，Win11进程525/772、线程513/851。
- 两台等待链均为 `KiSwapContext → KiSwapThread → KiCommitThreadWait → KeWaitForSingleObject
  → ObWaitForSingleObject → NtWaitForSingleObject → KiSystemServiceCopyEnd`，精确本地PDB注释。
  忙线程是调度/中断保存上下文；没有本驱动采集或APC分发帧，不读正在执行的变化栈。
- 原始目录 `.codex-tmp/live-stack-win10-saved5/receipts-final-saved` 与
  `.codex-tmp/live-stack-win11-saved6/receipts-final-saved`。新独立验证器
  `tools/verify_live_saved_thread_stack.py` 经原入口分流，每台11份raw响应核验通过；报告
  `.codex-build-logs/saved-stack-{win10,win11}-final-wire-review.json`。文件自洽仍不是独立采集证明，
  必须与实际来宾命令、夹具身份、签名/部署哈希一起保留。
- 保存上下文GUI/CLI共用持句柄会话，默认Auto首选saved，只有新端点明确不支持才回退旧APC；
  失败/部分不重发采集、不拼接来源。CLI `--method auto|saved|apc`，完整退出0、部分6、不支持5。
  GUI来源、完整/部分状态、tooltip及双语已同步；没有GUI/窗口/离屏自动化。
- 挂起的从未执行用户代码线程实际已有内核等待栈，可正常取得10帧；不能强求零帧。
  正常退出后旧实例raw请求拒绝。SCM普通停止45/55ms，复制均在停止前完成；新后端的
  `inFlightDrainCovered=false`、`acquisitionOverlappedExit=false`，不冒充在途退出/卸载实测。
- saved4先错误假设挂起线程无栈，再因dot-source污染父夹具变量导致清理异常；已改独立子作用域，
  失败回执/恢复报告保留于 `receipts-scope-failure`，独立服务正常停止删除、无遗留自有进程。
  saved1的0x40/0x48切换序言前缀错误已按两份PE修正。Win11 saved5仅连接超时、未执行；
  之后正常nogui启动再验saved6，没有回滚或改变安全/信任策略。
- 驱动/CLI冻结清单 `.codex-build-logs/saved-stack-artifacts2-20261122.json`，驱动SHA256
  `A26093C60FB92906BF816C422DAAFC6CDAF12FAA43590E25721EE791BBB5606D`，CLI为
  `6132B978D65663785A211F14AC2C81388C39B09ABAFE3729E08DEF622D271D0D`；当前实测没有改动这两者。
  驱动 `/WX`、Universal、Inf2Cat和CLI HostX64构建通过；最终主程序日志
  `ksword-build-check-20261122-061851.raw.log`，HostX64/BelowNormal、退出0、语言审计通过，
  34,361,344字节，SHA256 `03E4AE3FA668CEF1D76B06FE08691AD57ACA9D57F60F521D29B8767B1FC0C4FA`。
  最终冻结清单 `.codex-build-logs/saved-stack-final-artifacts-20261122.json`；不要复用08:40旧哈希。
- 最终原生回归日志 `saved-stack-native-final-20261122.log`：六份精确布局、采样验证、旧wire29、
  新wire24、生产范围检查器16、符号投影、会话12项全部通过。独立Python10测试和CLI前置拒绝10项通过。
  功能矩阵234个IOCTL全部登记/显式排除。所有正式产物在 `Ksword5.1/x64/Release/`，无运行副本。
- 双机最终stage已清理，服务删除、夹具正常退出、原安装exe/sys哈希不变。多组CPU、未允许版本、
  非NT驱动元数据完整链、新后端在途停止/退出未验收；禁止把这些范围说成已全平台支持。

## 实现边界

- 唯一协议位于 `shared/driver/KswordArkStructureSampleIoctl.h`，函数号 `0x941`。
  请求 48 字节、响应 9,344 字节；输入只有根类型、PID/TID、两个创建时间及零保留字段。
- `features/process/structure_sample*.c/.h` 独立校验加载中内核完整 PE/RSDS，选择编译内置的
  EPROCESS/ETHREAD 精确根大小，再引用并核对真实对象。不接受地址、偏移、长度或指针跟随。
- 当前内置配置只有精确的宿主 `19041.7844`、Win10 `19041.631` 和 Win11 `26100.9711`。
  发布目录拥有 1,946 份布局分片不代表后端允许读 1,946 个内核。
- `DriverClient::queryStructureSample` 为 GUI/CLI 共同入口；
  `shared/usermode/StructureSampleProjection` 是共同投影器。
- `valid` 精确到每字节；一次失败的 MmCopyMemory 可能已写入部分目标缓冲，必须先清零
  再回退读取。一个字段的所有字节有效才允许显示；不能把不可读区域的填充零解释成实采零。
- 所有快照均为非原子读取区间。对象引用只保证对象生命周期，不冻结字段或调度器。

## 覆盖口径与回归

分母必须是精确分片的全部符号行，包含父结构、未知类型和 union 分支。严格分子只含成功
读取并解码的非 union 行，按 `(absoluteOffset,width,bitOffset,bitWidth)` 去重。
union 可以显示原始共同存储，但不能猜活动分支、冒充额外采样或增加严格分子。

`tools/Invoke-StructureSampleTests.ps1 -IncludeExactProfiles` 在既有固定 IntDir 与正式
Release 中以 HostX64 `/MD /W4 /WX` 构建合成投影/协议测试。六份静态分片的严格计数为：
宿主线程 448/766、进程 468/672；Win10 线程 447/766、进程 442/641；
Win11 线程 513/851、进程 525/772。它们不是 VM 现场覆盖率。

`tools/verify_live_structure_sample.py` 独立读取 TSV 和 CLI JSON，核对全部元数据、有效位、
原始位域与重叠存储、计数去重及过半条件，还把实采 PID/TID/CreateTime 字段与独立夹具身份
对照。它只证明给定文件的自洽性，不证明采集来源；部署哈希、真实 guest 命令和退出码必须
另行保留。`tools/test_verify_live_structure_sample.py` 是合成变异拒绝及六分片静态回归。

CLI 命令为 `process layout sample` 和 `process thread layout sample`，原磁盘 `layout query`
与离线 `stack dump` 不变。CLI 正式构建及设备访问前拒绝测试通过；采样页保留五列、内嵌
展开、两个线程入口和独立 EPROCESS 子页，正文成功不与固定字段回退混成一份快照。

## 已经实测的结果与剩余门槛

- 用户停用宿主 R0 并退出程序后，正式驱动 `/WX`、Universal、Inf2Cat 和采样版 GUI 构建
  均成功。最新在线栈 CLI 再次链接成功；后续 GUI 整合曾被并行 UI 的未同步词条拦截，
  自己的诊断字符串已定点补齐双语，未覆盖别人改动。随后 31,246 条语言审计和最新正式
  整合均通过：`.codex-build-logs/ksword-build-check-20261122-022600.raw.log`，
  `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`；为当前产物的增量验证，`ARTIFACT_UPDATED=False`。
- 双 VM 真正加载 lab 签名的采样版驱动，EPROCESS/ETHREAD 严格覆盖率分别为：
  Win10 `442/641`、`447/766`；Win11 `525/772`、`513/851`。等待/忙碌线程分别取样，
  对象字段 PID/TID/CreateTime 与夹具身份一致；错误身份、退出、卸载后不可用均通过。
  原始采样证据在 `.codex-tmp/live-structure-win10/receipts-attempt3` 和
  `.codex-tmp/live-structure-win11/receipts-final`。不能再将这些实测写成尚未执行。
- 在线栈第二版 `0x8D6` 已登记工程、生命周期、注册表、唯一客户端、独立 CLI/help 及 CI
  排除项。Win11 的自有等待/忙碌线程实得 8/3 个真实目标 APC 时态帧；精确内核及驱动 PDB
  解析出 `KswStackApcKernel`、`KiDeliverApc` 和真实等待系统调用链；四路并发各取得 8 帧，
  limit=1 得 1 帧并标记截断。真实回调退休、随后卸载/删除成功。
- Win10 普通请求、limit=1 和四路并发都在入队前 `LIFETIME_UNAVAILABLE`、零帧。
  精确 19041.631 的 `KeRemoveQueueApc` 不导出且不在 GFIDS；不调用私有地址，不弱化 CFG，
  不改用永久 pin/无界挂队列绕过。完整双平台在线内核回溯仍未完成；Win11 后续生命周期
  覆盖见下方最新增量，不能把 Win10 的安全拒绝记成该平台在线栈通过。
- 在线诊断最终原始证据在 `.codex-tmp/live-stack-{win10,win11}/receipts-final`，
  完整字节/冻结身份独立一致性复核在 `.codex-tmp/live-stack-independent-final.json`，
  符号证据在 `.codex-tmp/live-stack-win11/final-symbols.json`。
  文件自洽性不等于脚本独立观察到采集，部署哈希和真实 guest 命令必须一并保留。
- 两机只使用既有 lab 信任，无证书库或安全策略修改，不加载宿主驱动、不回滚 VM。
  验收仍是 CLI only，不做 GUI/窗口或离屏 GUI 自动化；所有改动未提交、未推送。

## 本轮构建经验

构建包装脚本若把 `TEMP/TMP` 直接设为项目 IntDir，MSBuild 自己会报 MSB8029。
`tools/Invoke-KSwordBuildCheck.ps1` 现改用固定 `IntDir/CompilerTemp`，临时文件仍在正式
中间目录内，既不隐藏警告，也不建立第二套编译工程或运行副本。最新主程序构建已无该警告，
此前最终链接因用户 exe 占用失败，随后用户关闭程序的正式重建已成功；不能继续引用旧阻塞。

## 验收脚本已复现并修复的陷阱

- Windows PowerShell 的原生管道必须显式 UTF-8；否则中文嵌套 `privilege run` JSON 会被
  旧代码页损坏。只设置独立验收进程的 OutputEncoding，不改系统代码页。
- WinPS `Start-Process -PassThru` 会对快速退出的进程丢失 ExitCode；并发验收改为直接持有
  `Diagnostics.Process.Start()` 的原始句柄，同时 ReadToEndAsync 排空 stdout/stderr。
- 模块命令的真实入口是 `driver modules enum` 或有 `--name/--base` 的 `query`，不是
  `list`；帧符号只需查询内核和本测试驱动，避免无关的全模块输出。
- 夹具仅用线程级 `SetThreadExecutionState` 短租约阻止测试期间空闲 S1，退出时恢复；
  不更改来宾电源计划。传输超时先读 VM 日志/原请求，不盲目重发。
- Win10 各次脚本失败回执均按 advanced1–5 独立留存，没有抹去失败仅保留最终成功。

## 08:20 UTC 以后最新增量

- Win11 `.codex-tmp/live-stack-win11-gui6/receipts-exit-and-drain1` 的51项命令全部符合
  各自预期，suite成功但 `completeLiveKernelUnwindAccepted=false`。真实排队超时取消、
  24路饱和（16超时取消、8未入队busy）、正常采集恢复均通过。
- 自有夹具正常退出时APC实际执行并取得6帧、随后退休；这是退出期间执行分支，
  `stackExitUndeliveredRundownCovered=false`，不得写成未投递rundown已实测。
- 真实在途请求与普通SCM stop重叠，SCM等待5秒请求有界超时排空，stop后观察4,048ms；
  `stackInFlightUnloadDrainCovered=true`，但 `stackInFlightUnloadCovered=false`，
  模式是 `scm_waited_for_bounded_timeout_drain`，不是停止通知取消。原安装哈希未变，
  夹具/测试服务正常退出，stage清理成功；没有强制卸载或终止原生请求。
- `gui3` 在08:05:05 UTC已失败并清理服务，08:05:21 VMware记录来宾ACPI S1，
  Kernel-Power 42原因为System Idle，不是已证明的驱动崩溃。后续各次传输失败独立留证，
  不一概归因S1；`gui6`最终以限速legacy SCP补齐原stage并逐文件核验，未改OpenSSH配置。
- `.codex-build-logs/live-stack-ui4-artifacts.json`冻结了上述实测身份；后续会话异常修复
  会重建GUI/CLI，不能把旧实测哈希冒充新二进制。最新已确认的早期GUI构建为
  `ksword-build-check-20261122-040407.raw.log`：成功、退出0、34,352,640字节，SHA256
  `926045B47824EB16A70E10CD8656708BBB9AA45AFF8433EAA6087CF10C079A5F`。
- 独立原始栈核验器通过Win11 gui6的35份和Win10 gui2的8份响应；5项合成变异测试、
  7项直接链接生产会话的合成异常/身份/存活回归通过。它们不证明完整在线回溯。
- 共用会话已加模块/符号标准异常降级，保留同次真实裸地址，不重发采集；GUI工作线程
  异常走原提交入口结束在途状态，R3失败不再显示成功。对应最终GUI/CLI整合构建仍待回执。
- 压缩测量已完成：同生产运行文件清单下，全部结构TSV让7z增加209,129字节（0.1482%），
  两个版本索引再增加12,542字节（0.0089%）；原始增量分别170,316,755及293,222字节。
  报告`.codex-build-logs/layout-package-size-20261122.json`。这是受控功能增量而非历史包
  对比，也不是后续重建产物的固定成品体积；测量包及列表已清理，Release未被测量修改。
- 两类源码/Release索引各1,946条、146,611字节且逐字节一致，SHA256为
  `38c508dc98889558b6dc62b45f4b977e81176c47522b841222c363540796a741`；复制入口及
  再生成说明已核对。索引为忽略生成资产，不表示已发布或已提交。

## 最终会话版 gui7 复测（08:39–08:40 UTC）

- 最终主程序构建日志 `ksword-build-check-20261122-043443.raw.log`：HostX64、BelowNormal、
  `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`、实际重新链接、34,356,224字节、语言审计通过。
  主程序SHA256为`2DE164BA12BBD5753BF759B648B7E64F21AE72DE6D49D899AD461154A1AB1E3C`。
  CLI同步构建退出0，日志`live-stack-session-cli-final-20261122.log`，SHA256为
  `D701D9DDF69A26F0680579C2C9DE13B4DE82D487EB2E00A0C5CFBAF632035E59`。
  上节“构建仍待回执”和7项会话测试是早期阶段；最终会话测试已扩至9项并通过。
- 最终冻结清单`.codex-build-logs/live-stack-session-final-artifacts-20261122.json`。
  驱动、驱动PDB和夹具与ui4保持相同哈希，gui7两台部署清单包含最终CLI身份。
- `.codex-tmp/live-stack-win10-gui7/receipts-session-final`共24项，Win11同路径前缀共51项，
  实际退出码均符合各自预期。严格采样覆盖保持Win10进程442/641、线程447/766，
  Win11进程525/772、线程513/851；错误身份和资源回收条件继续通过。
- 独立报告`.codex-build-logs/live-stack-{win10,win11}-gui7-wire-review.json`分别核验
  8和35个原始栈响应通过。Win10仍是入队前生命周期不可用、零帧；Win11仍是等待8帧、
  忙碌3帧的目标普通APC诊断。二者`completeLiveKernelUnwindAccepted=false`，不得将
  套件success=true或本次会话异常修复说成完整R0回溯完成。
- Win11再次覆盖饱和16取消/8未入队busy、退出期间执行6帧；SCM有界排空本轮4,063ms，
  仍不是停止通知取消，未投递退出rundown也仍未覆盖。两机自有夹具正常退出、测试服务
  停止删除、stage清理成功，原安装exe/sys哈希未变。没有GUI/窗口或离屏自动化。
- 最终会话处理还拒绝返回false后的半份模块列表；符号失败保留同批裸地址、不重发采集。
  以上改动仍未提交/推送，不能把本地Release或忽略生成索引说成已发布。
