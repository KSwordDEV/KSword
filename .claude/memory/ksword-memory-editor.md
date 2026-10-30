# 统一内存编辑器与汇编

- **生产对象复用回归的 ABI 门禁**：独立 Qt 回归从主程序 link tlog 复用对象时，公开 context/request 布局变化后须先更新所有生产宿主对象；仅替换新页面及 moc 仍可能链接旧 inline 默认构造 COMDAT，产生错误架构等假失败。`Invoke-WorkbenchPseudocodeUiTests.ps1` 检查生产链接记录和复用测试对象不早于公开分析接口头；`-RelinkOnly` 只复用已检查的新对象。

- **RAW 反编译按需规划（2026-10-30）**：`UI/Decompiler/RawCodePlanner` 是 std+Zydis 的可恢复有界 CFG 规划器，入口与所选字节分离，不依赖模块/PE/`.pdata`；通过已有 bytes provider 的 1/0/2 掩码冻结真实区段，直接分支/顺序流和静态读取引用补页，普通 call 不递归，未知间接 jump/缺失代码/预算截断不接受完整结果。`WorkbenchPseudocodeView.Raw.cpp` 每个事件推进128项，单次读取与总1MiB预算分开；Source+Content 撤销票据，实时缓存淘汰保留冻结证据，快照不能经重载窗口假装同轮增量。实时读取使用 `WorkbenchHexPane::requestAnalysisWindow`，不能复用会改浏览/基线锚点的 requestBrowseWindow。新冻结JSON把入口/选点/地址/字节/body一起哈希；后端映射全部区段后创建 Disassembler，避免补页后复用其已缓存的旧 executable set。详见 `docs/反编译后端.md`；原型实测不代替产品集成回归。

- 区域原始 Dump（Issue #216）由 `MemoryDock.RegionDump.cpp` 实现，菜单按 UserRole 的基址/长度冻结区域、PID/创建时间和独立 QUERY_INFORMATION/SYNCHRONIZE 租约。R3/R0 固定读取、完整读门禁、QSaveFile 原子发布；取消与提交用 atomic 阶段仲裁，后台控制器与带轮次的独立进度收口。附加句柄没有 SYNCHRONIZE，不能复用其等待权限；kPro.addReusable 仅按 owner/taskName 去重，步骤名不同并不能隔离进度。范围和验证边界见 [区域 Dump 核对](../../docs/Issue-216-内存区域Dump核对.md)。

- `UI/MemoryEditorWidget` 是后端无关的快照编辑器，主程序的普通/R0/R-1/DDMA 内存、影子页、Hook 补丁、内核证据与转储内存入口共用。内部 Hex/反汇编/文本/对比视图使用同一份字节缓存；控件不调用任何内存写入接口。用户修改后须通过所属页面显式应用（影子页/Hook 由安装动作提交）。完整组件核查与保留边界见 `docs/内存编辑器组件清单.md`；独立 ARKLight Win32 客户端仍使用自身组件，不声称全仓已移除旧 Hex 工具。
- `MemoryEditorWidget::hexEditor()` 仅用于保留书签、断点等既有 Hex 集成。程序直接调用 Hex 的 `setByteArray` / `setByteAtAbsoluteAddress` 后，须调用 `refreshFromHexEditor()`；新读取应使用 `setSnapshot` 建立基线。成功写回必须以实际回读数据创建新快照，不能把暂存字节直接当作已成功写入。
- `MemoryEditHistory.Core` 只存 before/after 差异块，限制 32 MiB/256 步；一次 `refreshFromHexEditor` 聚合为一步（汇编、模板、粘贴与字符串修改）。Ctrl+Z 撤销，Ctrl+Y/Ctrl+Shift+Z 重做；新编辑切断 redo 分支。新快照、实际写回后接受及放弃修改均清空历史，不能借历史撤销真实写入。单次操作超出容量保留当前缓存但清除不可跨越的历史；回放前核对相关字节，失配拒绝整步回放。
- `setSnapshot` 的末尾 `sourceIdentity` 必须涵盖目标/后端/会话代次等身份。只有身份、基址和长度均一致才保留上一读取；物理地址、CR3 和 PID 不可跨目标混比较。Hex/反汇编/文本的橙色表示当前缓存相对读取基线的待提交修改，青色表示两次实际读取的变化；选区/搜索高亮优先。`HexEditorWidget::setChangeReferences` 为统一的 palette-aware 高亮入口，保留旧值 tooltip。
- 对比页可选读取基线或上次读取，默认仅列差异，每页最多 256 行；并列基线/当前 Hex 和文本，统计变化字节，双击定位，右键可复制两侧字节。快照文本页从当前地址选择有界窗口，64 KiB 起始窗口可连续向前后浏览，避免大快照生成无限格式对象。KernelDisassemblyDialog 的菜单扩展与两次模态确认绑定捕获证据代次、架构和指令值快照，不在菜单结束时重取行号。
- 反汇编按明确的起点解码，默认对应请求地址，避免从前置读取缓存或指令中间开始；WorkbenchDisasmView 以 4 KiB + 15 字节前瞻、最多 4096 指令的窗口连续浏览。可手选 x86/x64，物理地址和 CR3 不能自动判定代码位数。指令行保持地址顺序；上下文菜单在模态循环前保存地址与文本，快照改变后拒绝编辑旧行。
- `MemoryAssembly.Core` 使用仓库现有 Zydis 4.1.1 编码器；Qt 包装为 `InstructionAssembler`。支持常用 Intel 指令、多行、局部标签、寄存器/索引/位移、显式内存大小、实际地址分支与 RIP 相对寻址。裸数字默认十六进制；`0x`/`h` 为十六进制，`0d` 为十进制。它不实现 CE Auto Assembler 的 alloc/registersymbol 等脚本指令或外部模块符号解析；不支持的语法明确拒绝，失败不返回部分机器码。
- 汇编编辑对话框先编译和预览旧/新字节；变长补丁须由用户明确扩大覆盖长度；必须覆盖完整且可解码的旧指令，剩余空间可用 NOP 填充。关闭填充时新字节长度须与覆盖长度相等。填入缓存前复核快照代次、基址、架构与内容。
- Tab4 写回绑定附加进程代次与读取后端；DDMA 在 Tab4 保持只读。Tab6 保留标准 R0 内核事务，其他后端使用 `MemoryAccessBackend`，写回绑定快照后端及 DDMA 会话代次。最终回读逐个比对授权差异块，任一失败不报告整体成功；未知回读清空编辑快照。
- R-1 页写回绑定成功读取的物理/虚拟模式、地址和 CR3；待应用修改期间锁定请求参数。IOCTL 仍在后台运行，写权限与原有危险动作确认保留。所有新线程用的翻译模板在 UI 线程先解析。关闭窗口取消后续步骤，`QPointer` 和操作序号抑制陈旧回调；接口不提供原子的比较后写入，不能宣称防止所有并发修改。
- KvmViewDialog 加载完整目标页后暂存影子修改，显式安装前重查映射及整页原字节；KvmHookWizard 使用 VA 作为显示/汇编地址，PA 仅用于 IOCTL 和计划，模板与整页导入不重建快照。DDMA 独立页绑定全局会话代次，确认框后复核上下文、写前核对原字节；成功/失败/partial 均以真实回读更新显示，不完整回读清空禁用。
- DumpMemoryView 与 TRIAGE 中带 VA 的 raw 块为只读共享组件，保留已捕获范围、文件身份和预览限额；Secondary Dump Data 等无 VA 的文件辅助数据继续作为文件偏移报告。KvmWatchPanel 采样、DMA 操作备份日志等仍为证据报告；磁盘/文件/网络工具不属于内存编辑器迁移。
- 汇编核心独立回归入口：`tools/Invoke-MemoryAssemblyTests.ps1`（gcc/g++ + 仓库 Zydis，无 Qt）。覆盖实际编码/解码往返、x86 高地址、x64 RIP、标签、错误输入和无部分输出。2026-10-02 本机核心回归通过；指定 Qt/MSBuild 缺失，主程序编译、真实 GUI 和 R-1 驱动写入未验证。
- 历史回归 `tools/Invoke-MemoryEditHistoryTests.ps1` 420 项通过；汇编核心 217 项通过。`tools/hvm_unit_tests/test_ddma_editor.py` 用生产读写方法与 facade 类型、替代后端/Qt shell 检查 13 个提交/冲突/回读/会话/取消分支，不能代替 Qt GUI 或硬件实写。2026-10-02 主程序构建检查仍因指定 Qt 路径不存在停止。

- **2026-10-07 共享行画布迁移**：快照编辑器的反汇编/文本页复用 `WorkbenchDisasmView` / `WorkbenchTextView` 与 `MemoryRowCanvas`，已退役 `instructionTable()`；宿主只取 `selectedInstruction()` 值快照并在 `instructionContextMenuAboutToShow` 追加动作。`MemorySnapshotBytesProvider` 将原有 HEX 缓存、原始基线和上次读取映射为同一只读窗口；超出已捕获范围返回不可用或真实前缀，不能以补零尾部冒充证据。data/diffBlocks/accept/discard/undo/redo 与宿主显式应用事务保持原义。accept/discard/历史回放调用 `invalidateEditContext`，保留导航但取消旧汇编输入。析构时必须先让两子视图 `setBytesProvider(nullptr)`，因为 C++ provider 成员先于 QWidget 子树销毁。进程VA快照在加载时通过 `setProcessContext` 冻结PID/创建时间；kernel/physical/DDMA/dump 不传目标，不能从 `sourceIdentity` 字符串推断PID。
- **中断恢复后对抗审查**：同步快照 provider 时，文本也须接收捕获范围和位数，不能只限制反汇编；否则从非零基址后退会改到捕获区外并清空画布。真实完整 Qt 宿主隔离回归 148 项及完整内核窗口探针 27 项通过；删除文本边界或完整读取门禁两种私有变异均被抓住。KernelDisassemblyDialog 读取入口去掉 ZERO_FILL_UNREADABLE，只有 readStatus 完整、copyStatus 成功、bytesRead 与 data 覆盖请求才建立全有效快照；不得把补零当已捕获指令。模态编辑器/提示框使用堆对象与 QPointer，父窗口销毁后探活再读成员，所选原始字节值拷贝；保留既有确认、expected-before、dry-run、回读及回滚。此验证用 DriverClient/HVM 外部桩，未进行内核写入或真实驱动加载。
- **文件查看共享（2026-10-08）**：FileDock 的文件分页查看直接复用 `MemoryEditorWidget`、`WorkbenchDisasmView` 和 `WorkbenchTextView`，由 `SnapshotAddressKind::FileOffset` 隔离文件偏移与内存地址。x86/x64 只决定指令解码，文件文本定位始终保留 64 位偏移；文件模式拒绝进程导航上下文。文件页只读，分页 I/O 和稳定文件身份由宿主负责；跨读取对比的身份不包含修改时间，否则真实内容变化永远无法比较。读前后大小/写入时间核验、失败清空、请求代次和主线程生命周期核验仍属宿主责任。`openFindPanel()` 搜索当前 HEX/反汇编/文本页；对比页切到 HEX。文件反汇编以原始偏移展示，不进行 PE RVA/VA 映射。标准 MSVC/Qt 依赖缺失时，便携 Qt 组件验证不能等同完整 Release 构建。
- **零偏移定位**：`WorkbenchDisasmView::anchorAddress()==0` 不代表已定位；`reset()` 后必须先检查 `hasAnchor()`，再决定跳转还是刷新。磁盘文件通常从偏移 0 加载，只用数字相等判断会让文件开头反汇编空白；内存快照的地址 0 也须覆盖该回归。
