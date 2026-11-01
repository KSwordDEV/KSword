# DynData v4 读取、提取与分模块回执

- 2026-10-11：协议/配置包含可选 `PspTerminateProcess`（1401），旧 GUI 的手写 ID switch 漏项，导致整份 NTOS profile 无效，EX/V4 都不下发。包格式合规不等于实际消费者能接受；回归必须执行生产 `loadV4ItemsFromJson`。
- 支持的特殊 ID 统一登记于 `shared/driver/KswordArkDynDataIoctl.h` 的 `KSW_DYN_V4_SUPPORTED_SPECIAL_ITEMS`；GUI 使用该头的 `KswordArkDynDataV4ItemIdSupported`，Python 发布器读取同一目录和数值宏。1004/1006 仍保留协议编号，但不进入接受目录。不要恢复独立的 GUI 数字名单。
- 原汇总会把 FLTMGR 成功的 7 项计入 NTOS 的已应用/状态，掩盖 NTOS 读取失败。现有兼容汇总只代表 NTOS；`profileModules` 分别记录 EX/V4 是否尝试、状态、本次接受及最终缓存接受，界面和复制报告共用。缓存接受不能覆盖本轮格式失败。
- 新增 21 个结构字段映射和 2 个句柄位域 shift 映射。`_SECTION.u1.ControlArea`、`_ALPC_PORT.u1.State` 必须按成员的确切 CodeView type ID 追踪匿名 union，不能按重复的 `<anonymous-tag>` 类型名匹配。
- `ObDecodeShift`/`ObAttributesShift` 是位位置，不是成员字节偏移；只从 `_HANDLE_TABLE_ENTRY` 的真实 LF_BITFIELD 元数据产生，并校验 64 位存储及对象指针位域终点。零偏移的 ALPC 成员合法，不能用真假值过滤。
- 当前内核 GUID `63950D24-7362-0017-E1FC-214544590A77`：profile 从 225 项增至 248 项，原有值及 PE/PDB 身份不变；EX 投影 209 项。其余 profile 没有本次补提取，完整 Release 矩阵仍为 2856 项、580004 items。
- `tools/test_dyndata_profile_loader.py` 从生产源码抽取实际 Qt 解析和 EX 投影，离线遍历 Release 包并验证未知/重复 ID、非法 uint32 和错误组计数；生成的源码登记在独立 vcxproj/filters 中，不调用驱动。`--source-ref` 可复现旧消费者拒绝合法包。
- 本次 Python 回归 8 项、Qt 全包 2856 profiles 加 4 个拒绝用例通过；主程序用仓库 HostX64 构建脚本。最初因运行中的 exe 锁定报 LNK1104，用户正常退出后构建成功。
- 没有停用 Runtime pattern，没有更改 R0 ABI 或驱动活动状态提交规则。EX 精确身份/条目校验失败时保留原活动状态；PDB 接受会覆盖候选中的对应字段来源。离线校验和构建不替代用户的实际下发与业务验证。

## 2026-10-24：发行资源覆盖与 Launcher 完整性判定核查

- 已从公开 `5.2.1.0Pre` 应用包选择性提取 profiles 并校验文件 CRC；其中 v4 qz 与本地 Release 逐字节相同，SHA256 为 `2783851fd312f73c318e83840a0ffd372e51cd3567d57ee5a8688055997be56b`。Launcher 清单也逐字节相同，SHA256 为 `a8c3d0dca382d7240b7a09a983431211fb2ba43484becf5fa11360793531cb1f`。此结论只覆盖所提取文件，不是整个发行包完整性测试。
- 源 JSON 与 Release qz 解压后的 JSON 对象相同：2856 profiles、580004 items，分为 NTOS 1906、NTKRLA57 814、FLTMGR 136。含 70 个 NTOS 28000 系列身份（28000.1–28000.3181）；版本标签存在不代表每个更新的精确 PE/PDB 身份都已覆盖。
- 当前生产 `loadV4ItemsFromJson` 的独立 Qt 回归再次通过全部 2856 profiles 与 4 个非法输入用例。不能据“缺偏移”提示直接断言当前包无法解析；此测试不替代驱动实际下发。
- `Launcher/tools/generate_support_manifest.py::profile_is_complete` 根据旧 `missingFields`/`missingGlobals` 判完整。全部 2720 个 NTOS/NTKRLA57 档案都缺 `_PIDDB_CACHE_ENTRY` 的 DriverName/TimeDateStamp/LoadStatus 三字段，公共 PDB 不提供该私有类型；这三项不在可选字段列表，导致清单所有 2856 项均为 `complete=false`。`Launcher/Compatibility.cpp::ScanCompatibility` 将命中但不完整与无身份一起计入 missing，故已有身份也可弹缺偏移提示。仅在内存中排除这三项后，1490 个 NTOS、813 个 NTKRLA57 满足其余旧完整性条件；其余缺项不能一并宣称误报。
- 包只有上述三个模块类别；CI、WIN32K 等其它类别和独立 deep offset 库须分别核查，不能以 NTOS 覆盖推导全模块覆盖。核查机器当时磁盘 NTOS RSDS `91A0697C-BDF1-F6C1-B8D2-82E109E671E6/1` 在包中无身份，仍有真实覆盖缺口。
- 自动发行脚本从最新手工应用包继承 profiles，CI 不发布占位偏移包；普通拉取/构建不会补齐精确身份。此次仅核查与独立读取测试，未修改生产逻辑、生成偏移、下载 PDB 或加载驱动。
- 用户随后提供主程序实际 DynData 报告，明确绕过 Launcher。该现场 `profiles=2856 / 扫描=2856 / 无效命中=0`，NTOS 的 `0x8664 / 0xAEEE138F / 0x01045000` 与本机磁盘内核完全相同，包按这四个 PE 身份字段命中为 0，RSDS GUID/Age 命中也为 0。磁盘内核版本为 `10.0.19041.7802`，包内 175 个 NTOS 19041 系列档案最高为 `19041.7725`。报告 231 个字段中 51 个来自 Runtime pattern、180 个 Unavailable，EX/V4 均未下发。此现场根因是精确身份未覆盖，不能套用前述 Launcher 完整性问题；未命中时 `valid` 保持默认 false，报告“格式有效=否”不代表匹配档案被格式校验拒绝。

## 2026-10-30：矩阵来源与全量研究库刷新

- 原始模块/PDB 矩阵位于独立语料库的 `matrix/`，PE 与 PDB 分别在 `pe-store/amd64/`、`pdb-cache/amd64/`。项目脚本中的旧默认盘符不能证明资产不存在；先查看本地发布 manifest 的来源路径或询问当前语料库位置。历史矩阵有 24294 条引用、24179 个标记可用的 PDB 身份、127 个实际模块文件名，旧 README 的 126 是过期口径。
- 本轮源为 Winbindex stable/Insider、System Informer 上游 `kphlib/kphdyn.xml`，文件来自微软公开符号服务器。253 份源快照均成功取得；候选按模块与 PE 头键去重，保留同键多 SHA 的索引别名，不能把元数据引用、PE 文件、PDB 身份、偏移配置和字段条目混计。用户要求跳过 NTKRLA57，既有数据保留。
- 最终 7272 个候选全部处理，5468 配对成功、1804 未找到（PE 404 为 1622、PDB 404 为 182），瞬态错误经重试后为 0。模块/PDB 矩阵从 24294 增至 29832 条，标记可用 PDB 从 24179 增至 29647。实际新增 PE 5537、PDB 5468：采集缓存有 5538 个 PE，其中 NTOS 28000.1812 的一个文件在原语料库已经存在但旧矩阵未收录，故“新增记录 5538”与“新增文件 5537”不同。旧 NTKRLA57 的 817 条矩阵记录与 814 个发布配置精确保留。
- 发布 v4 新增 NTOS 45、FLTMGR 31，共 76 profiles / 11298 items；总计 2932 profiles / 591302 items。旧 2856 个对象逐项保留，含此前补齐的 248-item 当前配置。`10.0.19041.7802` 的 `91A0697CBDF1F6C1B8D282E109E671E6/1` 已补齐。121 份新增 CI 源档案仅有可提取全局，缺少必需组字段，未发布为 CI 运行时支持。
- 26H2 的 OS build 是 26300，但其内核 PE 文件版本可仍是 26100，不能按 profileName 是否包含 26300 判断覆盖。仓库记录的 26300.9022 现场实际 NTOS 为 26100.9022，`0x8664 / 0x3ABC2041 / 0x01450000 / 9DAAB2015E4CABF698009DBD0548B669 / age1` 在更新包中精确命中，含 224 items；包内也有 26100.9818 档案。此为身份/离线数据覆盖，不代表所有 26H2 机器及功能的实机通过；28000 是 26H1，29695 是 Future Platforms，不能按 build 数值大小推断对应零售版本。官方对应关系见 [Windows release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) 与 [Flight Hub](https://learn.microsoft.com/en-us/windows-insider/flight-hub/)。
- 按 `26***` 汇总会混入服务器与其它实验构建，不能将该组最高值当作 Windows 11 26H2 最新内核：`26534.1000` 属于 [Windows Server vNext LTSC Preview](https://techcommunity.microsoft.com/discussions/windowsserverinsiders/announcing-windows-server-vnext-preview-build-26534/4475333)，公告说明预览品牌仍为 Windows Server 2025；`29695.1001` 是 Windows 11 Experimental (Future Platforms)，官方未将其对应到一个零售 H1/H2 版本；`28000.3364` 属于 Windows 11 26H1 内核分支。
- 再次回读 `Ksword5.1/x64/Release/profiles/ark_dyndata_pack_v4.json.qz`，解压后的对象与源码 JSON 完全相同，2932 profiles / 591302 items，qz SHA256 为 `dc9f19f9d03c348f769faecad0ff8a8b05234a0c40a9fd93cd379a90855d3ed3`；Release 的 Launcher 清单也与源码相同。完整研究库归档到独立语料库，并未把其 12GB 全量数据接入 Release 的运行时加载。
- 生产 Qt loader 全部 2932 profiles 与 4 个拒绝用例通过，8 项发布器单测通过，Launcher x64 Release Build 通过；未测试驱动实际下发。既有 runtime catalog guard 仍缺 21 个 FIELD_MAP 映射，此问题与静态包可解析是两回事，本轮未修改运行时解析逻辑。Launcher 原完整性策略仍把全部身份标为 `complete=false`，不能把新配置数说成完整功能支持数。
- NTOS/Win32k 研究库按精确 PDB 身份生成 4234 份（3915 个既有可用身份 + 319 个新增身份）：2079 份提取到字段/类型，2155 份仅提取到符号，空结果 0。它是研究语料，不是把这些字段任意下发 R0 的接口；原仓库三份研究库保留。完整研究索引位于语料库的 `profiles/pdb_deep_offsets/index.json`，数据及支持文件由同目录 `publish-manifest.json` 列出。
- 每份研究库的 GUID 与 PE/矩阵身份、RSDS/cache-key Age 对齐；PDB 内部 summary Age 可为 2/3/5，只作诊断。不可把“GUID 校验 + RSDS Age 作缓存键”描述成 PDB 内部 Age 也相同。
- 外置语料库逐文件随机 stat / 多轮 llvm dump 很慢。先把每个 PDB 顺序暂存本地，再多轮解析，实测吞吐明显改善；保留检查点、按不可变文件 SHA256 归档，数据完成后才发布索引。网络高并发发生集中 SSL/连接中止时降并发并只重试瞬态错误，不删除成功数据或把 404 当成永久不存在的证明。
