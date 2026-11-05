# 磁盘队列、I/O 日志与 MFT 索引

- 文件 → 快速文件搜索（`file.tab.ntfs_index`）由 `FileDock/NtfsSearchPage` 承载；空间分布已拆为独立入口 `file.tab.disk_space` / `FileDock/DiskSpacePage`。两者使用 `ParameterWorkspace`，搜索保留 MFT/USN，空间页默认普通文件遍历，也可选 MFT。选择文件夹/修改路径与扫描方式只修改参数，必须显式点击开始扫描；不在构造时扫描磁盘。空间页两种来源复用同一不可变快照、目录投影、扩展名统计及面积图；MFT 先读取所在卷，再按所选目录身份裁剪，并从范围内硬链接名称选择一次计量。
- `DirectorySpaceScanner` 使用 Win32 目录枚举与只读元数据句柄，不读文件内容；跳过重解析点/脱机召回项，硬链接按卷与文件身份去重，未计量与跳过项必须警示。持有被遍历目录的祖先锁链，拒绝写/删除共享，防止待处理子目录路径因祖先被替换为联接点而越界。取消不发布部分新树，失败保留旧结果且注明来源。切换计量方式后取消/失败必须恢复 `displayedMetric`，旧图不能误标为新口径。
- 扫描范围使用 `DirectoryScopePicker` 可视化目录树，路径仅作为选中摘要；`ParameterWorkspace::setParameterViewport` 给树完整伸缩空间，避免外层表单再次包滚动。QFileSystemModel 只按展开加载目录，不预展开盘根、不把选择动作连到扫描。扫描方式与计量口径使用分段控件，结果树鼠标/键盘选择和地图进入/上级/取消的目录身份一致。用户禁止窗口自动化测试后，此版本仅源码核对和编译，视觉留给用户。
- 查询/卷探测/汇总/排序在后台，表格使用共享 ResultTableHost（扩展名 Compact、目录树 None），定位走 FileDock 原异步导航并显示隐藏/系统项。相关控件按用途区分：整卷MFT搜索/误删源仍选卷，Scanner仍选单文件但选择不再自动扫描，FileDock手动单目录模型禁用无真实层级的树形选项。独立页修改的范围与验收记录见 [空间分布独立页面](../../docs/空间分布独立页面.md)。
- `NtfsIndexRecord` 是 Qt/Windows 无关的 FILE/USA/属性和 MFT 映射解析器；raw 记录严格验证 USA，FSCTL 返回格式有显式入口。默认 DATA 的逻辑/分配大小与实际卷已用空间不同；硬链接以完整文件引用去重，扩展名称按基础记录身份合并，无法计量的大小显式报告。
- FILE 的 USA 格式步长固定512字节，不能用卷的逻辑扇区大小计算 count、tail 或首块边界。4096B FILE 在4Kn卷上仍有9个 USA 项；raw I/O 长度、偏移和缓冲对齐继续按真实卷几何处理。
- `FSCTL_GET_NTFS_FILE_RECORD` 返回 NTFS 已恢复的逻辑记录；缓存修改后 sector tail 可与旧 USA 数组不同，甚至恰好等于保护标记。`FileSystemControl` 入口保留逻辑字节，不再依赖旧 USA 判断一致性或二次恢复；`RawDisk` 才严格验证并恢复 USA。`ParseMftStreamParts` 必须遵守同一格式边界，受控 FSCTL 夹具也必须返回真实的已恢复表示。
- 索引只读，不创建/删除 Journal。扫描前取 USN 游标，扫描后核对 MFT 布局并重放；日志身份/保留范围变化须重建，失败保留旧快照。活动卷不是 VSS 原子快照；不支持的 MFT 映射/属性列表明确失败，不能以部分结果冒充完整成功。
- `$MFT` 自身的非驻留 `$ATTRIBUTE_LIST` 按完整有界映射读取（最多16MiB）并核对扩展记录身份；不能因属性列表非驻留而直接拒绝普通卷。扫描前后只比较真实 runlist、记录身份和有效长度，不能把整条 FILE 的 LSN/USA/时间变化误报为映射变化。raw 卷句柄可能隐式 noncached，MFT/属性列表读取须对齐缓冲；碎片化 extent 的后续目标地址也要经对齐 scratch 再拼接。
- 硬件 → 硬盘监控复用卷性能 lease，区分瞬时 QueueDepth、平均队列、IOPS 与进程文件 I/O；不可将多卷相加当物理磁盘队列。Kernel-File 日志采用私有会话，显示头 PID 和请求/完成阶段，不把请求字节当落盘字节。待消费 2048/显示 10000 条，覆盖/淘汰/ETW 丢失分开。
- 磁盘监控用“活动 / 文件 I/O 日志 / 卷队列”同级结果Tab；标题是共享中性工具面与独立28px折叠图标，不用整行checked按钮。独立搜索/空间页使用实际 PrimaryToolbar 与 TableActionTableView 槽，避免裸表操作条形成黑块；搜索页不再保留只有一项的结果Tab。索引失败时需显示详细失败、重试与禁用原因；取消空间请求须恢复已提交目录身份，不能让旧图按新路径或新快照解释。
- CI 的 `test_ntfs_volume_integration.ps1` 只初始化、格式化它新建并核验的临时VHD，测试生产的真实 FSCTL/raw MFT/USN；生产索引器仍不修改Journal。`test_ntfs_backend_io.py` 的完整受控I/O另覆盖真实临时卷不易构造的非驻留列表、LSN正常变动和真正映射变动负例。两者不等于用户现场ETW或完整GUI验收。
- 回归与 Windows 验收清单见 `docs/磁盘监控与MFT索引.md`。Linux 解析/数值/QtCore 检查和语法检查不等于 HostX64 MSVC 构建、原生 NTFS/ETW 或真实 GUI 验收。

- 磁盘编辑 GPT 名称：`PARTITION_INFORMATION_GPT::Name[36]` 是 NUL 填充的固定 UTF-16 字段；`fromWCharArray(Name,36).trimmed()` 会保留尾部 U+0000，导致地图和表格名称末尾出现方框。`gptPartitionName` 用有界 `std::find` 截断首个 NUL，无终止符时保留全部 36 单元；与 DiskStructureParser 原始 GPT 路径保持一致。不要用全局字体或 provider 编码猜测处理此问题。
