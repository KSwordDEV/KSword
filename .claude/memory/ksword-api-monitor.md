# API Monitor 定义、x86/x64 引擎、覆盖与异步采集

## GUI 分类与第三轮强类型扩充（2026-11-08）

- 用户反馈关闭窗口类仍刷大量GDI，并要求继续Raw转强类型。新增 `EventCategory::Gui=15`，原值/包布局不变；`enable_gui` 和界面“GUI API”缺省关闭，旧INI缺省也关闭，独立于 `enable_process` / `enable_window`。主程序写出/启停、CLI分类/help/业务白名单、剪贴板专用会话、子进程继承、事件标签和密度轨道同步。
- 原因是多数GDI Raw落入旧名称推断的Process兜底。现在明确的GDI/GDI+/DWM/DirectX/OpenGL/主题/字体整形模块先归Gui，精确列出的User32绘图/DC导出及win32u的NtGdi导出也归Gui，其他旧猜测规则保留。关闭类别时Raw发现阶段直接记录CategoryDisabled，不占导出批次配额，也不创建安装绑定；底层安装门禁仍复核类别。Fake发送和原始槽位采集未改。
- 原窗口类13项（Gdi32的6项，以及GetDC/ReleaseDC/InvalidateRect/ValidateRect/RedrawWindow/UpdateWindow/PrintWindow）迁Gui。追加77项：900–932对象/字体33项，950–993绘图/DC/路径/坐标44项。总898项，673生成包装、225专用处理器；Gui共90项。原ID/导出身份稳定，没有合入第三方声明。
- 新接口仅采具名值/地址、返回位及耗时，不解引用结构/文本/图像。生成器 `error_source=none` 扩到bool/handle/dword_nonzero/uint_nonzero/int_positive：已知失败标StatusUnknown、保留真实返回和LastError，不把残留错误码当有效原因。GetCurrentObject、GetObjectType和LineTo的成功/失败两路径在双架构各15组逐项匹配。
- 原生签名77项均经x86/x64 SDK static_assert核对；生产Raw分类和CategoryEnabled门禁双架构通过。定义生成/确定性/原614身份、配置继承/往返、CLI密度、14个选择项的24组主题/字号/栏宽回归和语言/主题门禁通过。入口仍为“监控→WinAPI→API事件/API覆盖”，沿用ParameterWorkspace和FlowLayout，对照SystemTime/VirtualLocation；未新增布局或例外，真实主程序视觉仍依此前用户不使用computer use的要求待人工查看。
- 恢复用户指定 `Codex-DwmApiMonitor-PreAttach-20261101-01` 后，在20H2来宾两架构各实际调用257/257项（原180+新77）。x64逐项匹配248、入口不可用9；x86匹配255、不可用2；契约不符0、丢包/无效包0。新77中x64匹配76、x86匹配77；x64唯一新增不可用为CreateHatchBrush，入口offset3指令被现有解码器拒绝，本轮未扩改Hook引擎。不能把定义数/尝试数称全部安装成功。
- 逐项证据 `.codex-build-logs/gui-per-api-vm-20261108/per-api-summary.json`；原始trace/capture位于同目录results。GUI隔离另测8个会话：x64/x86的process+Raw和window+Raw均0条GDI/GUI事件，且强类型/Raw覆盖行均分类关闭；GUI+Raw有187/176条，GUI强类型模式各48条，返回/耗时边界正确，70项断言通过。证据 `.codex-build-logs/gui-category-vm-20261108/results/summary.json`。这只证明受控输入和单一系统，不等于多版本/长期压力验收。
- 最终主程序/双Agent/CLI HostX64 Release构建通过。声明SHA256=`67aa8a6476434d7af2564b1a2dc1a8f12aa16fd792cfe55e2ee2b6489cd049d1`，主程序SHA256=`0FB3E0CA80E338C08DDD86FC3B542BEDCCF08889463CB843108E4AA0FBBC31BA`；日志 `apimon-gui-main-build.log` / `apimon-gui-cli-build.log` 均在 `.codex-build-logs/`。旧x64 DLL被宿主目标映射，改名保留为 `APIMonitor_x64.before-gui-category-20261108.dll` 后重链，未结束用户进程。主程序与已加载旧Agent的目标均须重启，再开新会话才使用新分类；Agent仍PIN常驻。

## 分类复选框消失与采集方式说明（2026-11-08）

- 用户截图中的13个分类控件仍存在；`ParameterChoiceWrap` 将其水平策略设为 `Ignored` 后，`QWidgetItem::sizeHint()` 宽度变为0，原 `FlowLayout` 据此分配零宽。共享流布局现对这类非扩展、非隐藏控件使用控件本身的自然宽度，并限制在可用行宽内。
- “采集强类型调用栈”右侧新增主题圆圈问号，悬停以中英文解释项目内的强类型/Raw约定、参数/返回/耗时差异及仅强类型提供最多8帧调用栈的边界；实际安装仍以API覆盖为准。入口、页面类型和共享框架沿用下节记录，无新增页面或例外。
- `tools/api_monitor/test_flow_parameter_choices.py` 使用生产 `ParameterChoiceWrap` 和 `FlowLayout`；旧源码负控稳定复现13项零宽，新源码在深浅配色、10/14pt字体、200/340/700px栏宽的12种组合中显示、换行及标签点击均通过。图片仅为共享组件离屏回归，不代表真实主程序的背景、首帧或整页视觉验收；此前用户禁止computer use，真实窗口仍待人工查看。
- 主程序HostX64 Release构建、语言与主题门禁通过；产物SHA256=`BF9901745ED2B1B41FB709091E659BF8D693E4210681EA70152B3115C9EB43F9`。运行中的旧EXE因占用导致首次链接LNK1104，已原目录改名为 `Ksword5.1.running-before-category-help-20261108.exe` 后重建成功，未结束用户窗口；重启主程序才会使用新布局。
- 用户随后截图指出短标签全部把 `API` 的 `I` 换到下一行。上述12组回归只覆盖原生样式和配色，没有加载主程序的QSS，也未断言短标签必须单行；通过不能作为主题下文字尺寸正确的证据。根因是 `ParameterChoiceWrap::labelRect()` 硬编码指示器间距7px，而主程序规则为6px，造成自然宽度恰好少1px。
- 标签区域现统一通过 `SE_CheckBoxContents` / `SE_RadioButtonContents` 取得，与原生 `sizeHint()` 同源。回归直接提取主程序的复选框主题规则，增加短API标签单行断言；修复前13项在12种主题组合均失败（156项），修复后含原生样式的24组通过。参数选择项既有首帧、鼠标、键盘与生命周期回归245项通过；组件截图已核对，仍不等于真实主程序视觉验收。
- 断行修复后的HostX64主程序Release、语言/主题门禁通过，最终EXE SHA256=`50D44300345933D2E6B27FB99266B0D16E67BA2EDB846418CEC161530015E8D3`；构建日志 `.codex-build-logs/apimon-choice-text-build.log`。已有测试签名的本机信任校验警告仍存在，未改变证书配置。

## 第二轮扩充与逐 API 实测审计（2026-11-08）

- 用户追问“能否新增更多强类型，实测数量足够吗”。复核上一轮最终原始事件：新增115项中仅x64的10项、x86的9项曾出现事件，逐项强制断言各7项；426是断言数，不能称426个API实测或115项全部可靠。
- 本轮再新增65项（801–823菜单23、830–851内存/线程/进程22、860–879 COM/安全描述符20），总数821；596个生成包装、225个专用处理器。原有ID/导出身份不变，Raw推断和Raw/Fake发送入口保持既有行为，没有合入第三方候选。补21项方向/长度元数据（16长度、6方向，836合并在一项）；输入地址数组不能因SDK SAL简写为out而丢失inout语义。
- `ReclaimVirtualMemory` 的 `ERROR_BUSY=170` 是成功回收但内容丢弃，不是普通非零失败；831使用专用处理器，状态归成功，保留调用方返回170及 `reclaimed_discarded=1`。生产函数提取夹具在x86/x64验证0/170/87及旁路、LastError和返回位。
- 三组 `runtime_probe_*.inc` 实际调用两轮全部180个新增接口，先未注入基线，再受控注入循环。`runtime_probe_fixture.cpp` 限定明确授权来宾 `DESKTOP-D2161R7`，本轮用户允许虚拟机状态丢失；光标调用仅在这个授权分支允许，服务仅只读打开RpcSs查询，不修改服务。每轮清理自有窗口、句柄、内存、COM/CNG资源。
- `analyze_per_api_capture.py` 根据调用线程、FILETIME时间窗、真实返回位、LastError/状态契约与事件一对一匹配，并核对类别、函数、声明SHA及返回/耗时标志。一个事件不能验证多个调用，额外清理调用不能误报为返回不符。HooksRemoved在物理恢复和覆盖发布后才发出，不能把确认之前的全部调用都视为仍在采集；按HooksInstalled与requestedDurationMs限定稳定区间，避开20ms边界桶。
- 最终在用户指定 `Codex-DwmApiMonitor-PreAttach-20261101-01` 快照中，x64/x86均实际调用180/180项。x64逐项匹配172、入口不可用8（前轮115中107、新65全部）；x86匹配178、入口不可用2（前轮115中113、新65全部）。契约不符0，丢包/无效包0，部署二进制哈希与本机最终产物一致。成功/失败两条路径均匹配的接口分别53/54项；部分接口只验证安全失败，不能说全部业务成功或全部旧641项已逐项实测。
- x64不可用：GetPhysicalCursorPos/SetPhysicalCursorPos为共享入口冲突，SetProcessWorkingSetSize为保守指令拒绝，CoResumeClassObjects、CopySid、InitializeSid、InitializeSecurityDescriptor、GetSecurityDescriptorControl为RIP相对位移超范围。x86仅两个物理光标接口入口冲突。本轮没有扩改Hook引擎，不把尝试调用或覆盖行存在算已验证。
- 结果 `.codex-build-logs/per-api-vm-20261108-final/per-api-summary.json`，原始trace/capture在同目录results；采集日志 `.codex-build-logs/apimon-per-api-vm-final.log`。重跑入口 `tools/api_monitor/Build-PerApiProbe.cmd`、`Invoke-CliParityVm.ps1 -Mode perapi`、`analyze_per_api_capture.py REPORT_ROOT`。新增65项双架构SDK ABI、定义生成、目录元数据、特殊返回和匹配器回归通过，主程序/双Agent Release与语言/主题门禁通过。当前声明SHA256=`59ee7581c3e71a467f3d19474ea998b8a36fd4f927a425ce2872047f9a931ee8`。
- 本轮未改GUI布局；此前GUI实机视觉验收仍未完成。单一20H2快照的受控调用不代替多系统版本、长时压力、复杂输出结构解码或任意宿主进程验证。

## 分类细化与自有强类型扩充（2026-11-08）

- 用户要求将内存、线程、服务、权限、加密、COM、窗口从进程分类拆出；Raw 按函数名推断分类的逻辑保持原样。协议仅追加 `Memory=8/Thread=9/Service=10/Security=11/Crypto=12/Com=13/Window=14`，原枚举值和包布局不变；原 641 项导出身份与 ID 不变，其中 229 项重分类。分类数为 13 个业务类，时间轴另有其他轨道。
- 自有 SDK 定义新增 115 项，总数 756；532 个生成包装、224 个专用处理器。新 ID 段 642–683（窗口 42）、700–731（内存/线程 32）、760–800（服务/权限/加密/COM 41）。没有合入此前第三方候选。当前分类数量：文件95、注册表86、网络111、进程83、加载器27、剪贴板10、内存42、线程70、服务33、权限54、加密58、COM26、窗口61。
- 七个 `enable_*` INI 开关缺省继承 `enable_process`，保留旧配置覆盖；主程序显式保存、子进程显式继承，剪贴板保护专用会话显式关闭全部七类。CLI `--categories`、业务选项导入、help、文档、事件文本和密度桶同步。加载器可为补装继续安装，但强类型业务事件按用户分类选择抑制；网络完成观察入口也不冒出未启用分类事件。
- 新包装先采具名数值/指针地址、返回值和耗时，不读取新结构/缓冲区内容。21 项 SDK SAL 长度关系表示容量或输入长度，不能推断实际输出字节。16 项未有完整 `GetLastError` 契约的 BOOL 接口使用 `error_source=none`，失败保留真实 FALSE 并上报 `StatusUnknown`、`call_failed=1 error=unavailable`；不得把旧 LastError 当有效错误。
- 源码 UI 核对入口为“监控 → WinAPI → API 事件/API 覆盖”，类型为参数/执行与列表/时间轴混合页，沿用 `ParameterWorkspace`、既有结果表/详情与共享 `FlowLayout`；对照 `SystemTimePage`、`VirtualLocationPage` 和共享布局实现。新增分类自然换行，时间轴为14轨；普通控件继续由标准主题接入。剪贴板保护仅配置写入受影响，不改布局。真实主程序的窄窗、DPI/长文本、深浅主题、背景与首帧视觉尚未验收，不能由编译/离屏测试认定合规。
- 本机 HostX64 构建主程序 Release、CLI 和双位数 Agent 通过；CLI 工程原漏登记的 `ArkDriverModule.cpp` 已在工程/filters 补齐，避免 `enumerateProcessModules` 链接缺失。主程序语言与主题门禁、配置隔离/子继承、覆盖快照、CLI 时间桶、定义确定性、Raw 身份索引通过；115 项 SDK 签名均在 x86/x64 编译核对，窗口/权限/加密/COM 的隔离包装夹具通过。主程序自动测试签名仍有原有 `0x80096019` 验证警告，构建成功不等于证书受信任。
- 按用户授权丢弃 VM 当前状态，恢复 `Codex-DwmApiMonitor-PreAttach-20261101-01` 后，最终双位数 DLL/CLI 在 `DESKTOP-D2161R7` 完成16组、426项检查，覆盖18个自有进程实例、七分类独立启用、新旧代表接口、返回值、声明SHA、子进程混合开关继承、完整覆盖快照和停钩；丢包/无效包为0。部署产物哈希与本机最终产物一致。所有会话均为partial（退出6），不能据代表调用通过宣称756项全部安装。日志 `.codex-build-logs/apimon-category-vm-release.log`，结构化结果 `.codex-build-logs/category-vm-20261108-release/summary.json`；复现用 `tools/api_monitor/Invoke-CliParityVm.ps1 -Mode category` 与 `Invoke-CategoryGuest.ps1`。只操作自有夹具，不操作宿主 DWM。
- 初轮 x64 权限代表 `OpenProcessToken`、`InitializeSecurityDescriptor` 被现有引擎以 `RIP-relative operand exceeds disp32 range` 拒绝（覆盖Unsupported），未修改引擎或伪称已覆盖；改用该快照确实可安装的 `GetTokenInformation`、`GetSecurityDescriptorDacl` 验证权限分类。初轮失败原始数据保留 `.codex-build-logs/category-vm-20261108/results/x64-security/capture.json`。Raw/Fake发送与入口实现、Raw分类推断按源码与原版逐段核对未变；分类关闭的业务事件抑制仅在强类型metrics路径。

## 2026-11-02 P0 增强与 CLI（仍需最终验收）

- 2026-11-03 用户确认此前版本的时间轴显示和交互正常。随后按其反馈压缩时间轴、移除可见状态/图例行，将分配长度和撤销放到模式旁，调整三栏比例，A/B 时间只显示时分秒毫秒，B 隐藏序号及相对时间；属性字段从事件列投影补齐。新布局已构建，用户禁止 computer use，修改后的真实 GUI 尚待人工查看。
- 主程序 `ksword-build-check-20261102-222645.raw.log` 构建成功，但 EXE 测试签名的 `signtool verify /pa` 返回 `0x80096019`（basic constraint extension），签名状态 `UnknownError`；不能将编译通过说成签名已被信任。
- 生产声明文件及 Release 副本 SHA-256 为 `F963FFD995036E2070D37811E3D0239C9DCD8EC461CC54418144CE46F25A4BEB`，仅包含 641 条自有定义。遵照用户“候选暂不合入”的要求，第三方参考数据保存在 `.codex-build-logs/api-monitor-user32-batch-candidate.json`（SHA-256 `2F8283CA5C8C9BEF2C5A2783ACC5721AFA7255D9342D55FD8A22BCA406DEF14C`），其中 227 项通过 SDK 原型核对，方向和运行时语义未由该核对证明。
- 较早 x64 Agent 在来宾 DWM/Explorer 各短测三秒，进程创建身份保持、停钩完成、未见对应应用崩溃事件；均为 partial，Agent 报告丢失为 0，CLI 20000 条缓冲分别淘汰 10341/10357 条。见 `.codex-build-logs/api-p0-current-system-vm-20261102/results/summary.json`；该 Agent 包含候选哈希，不能冒充最终 Agent 的系统进程实测。停钩后 Agent 仍驻留来宾进程，不能删除其 DLL 或称完全卸载。
- 异步等待语义修复前的自有声明版本 x64 Agent 在来宾 DWM/Explorer 各短测三秒，进程身份保持且停钩完成，未见对应应用崩溃事件，均为 partial；Agent 报告丢失为 0，CLI 各保留 20000 条并淘汰 19146/20972 条，见 `.codex-build-logs/api-p0-owned-system-vm-20261102/results/summary.json`。各保留记录中的 19999 条有效业务事件重放到密度模型后分别落入 37/35 个像素列，计数守恒；不能证明当前 Agent 系统进程行为、GUI 视觉或长期稳定。
- 异步 IoWait 的零错误是未完成观察，不能显示为成功：生产跟踪器对这种等待发送 `StatusUnknown`，等待观察的非零错误仍使用 `StatusCode`。x86/x64 跟踪器回归及当前双位数 Agent 的来宾 ReadFileEx 提交/等待/完成实际对照通过，等待字节数未知、完成字节数与目标回调一致，见 `.codex-build-logs/semantic-pending-vm-20261102/results/summary.json`。
- 异步等待语义修复前的 CLI 和双位数 Agent 在来宾自有目标完成 142 项检查，覆盖前后置筛选及例外、调用栈开关及来源、有界时间桶计数、声明哈希与停钩；各会话均为 partial，结果见 `.codex-build-logs/cli-parity-owned-catalog-vm-20261102/results/`。
- 当前双位数 Agent 在来宾自有语义夹具中对照验证 `VirtualProtect` 和 `DuplicateHandle` 的成功/失败返回值、成功输出参数及失败错误码，各项匹配，均 partial，Agent/CLI 缓冲丢失为 0 且已停钩。见 `tools/api_monitor/Invoke-SemanticGuest.ps1` 和 `.codex-build-logs/semantic-owned-catalog-vm-20261102/results/summary.json`；该结果不代表全部 API 均有输出参数支持。
- 自有目标双位数复测新增调用栈来源核对：校验目标 PID 的可执行文件与预期夹具一致，以运行时主映像基址和大小验证 WriteFile 事件中至少一帧落在目标映像内；142 项通过且每轮仍为 partial，原始采集见 `.codex-build-logs/cli-stack-provenance-vm-20261102/results/`。这不是完整展开、符号或任意调用场景的证明。
- `test_timeline_density.py` 可用 CLI 采集 JSON 重放真实 API 时间戳，优先仓库 Qt、回退本机 Qt；当前来宾 x64/x86 的 baseline 分别为 594/700 条，1200 列投影落在 54/51 个不同位置且计数守恒。该模型证据不代替真实 GUI 验收。
- 当前来宾 DWM/Explorer 短测保留的 19998/19999 条有效业务事件重放主程序密度模型后分别落入 31/33 个像素列，计数守恒。`QueryNow100ns` 使用 `GetSystemTimeAsFileTime`，不同类别可能具有相同时间戳而纵向对齐，不能将时间戳当成高精度调用顺序；CLI 已淘汰的事件未进入重放。
- `GetProcAddress` 的隔离候选对一个实测系统映像版本验证了 `KernelBase!GetProcAddressForCaller`，它是未公开内部接口，不能代替对其他版本及调用者敏感行为的兼容证明；基于稳定性要求未合入生产。原 `Kernel32!GetProcAddress` 的覆盖仍按实际 Unsupported 报告。
- API Monitor 提供默认关闭的 R0 注入选项，CLI 为 `--r0-inject 1`；沿用既有 v1 注入 IOCTL，不新增驱动能力或协议，目标位数与远端入口在用户态核对，子进程通过 broker 使用相同后端，失败不回退 R3。驱动 v1 仍有 PID 查找竞态及远端路径分配保留到目标退出的限制。异步等待语义修复前的版本在来宾现有驱动和自有 x64/x86 目标实测安装、停止通过且未报告丢包，覆盖为 partial；测试后服务恢复停止，见 `.codex-build-logs/api-p0-r0-owned-catalog-vm-20261102/results/summary.json`。
- 异步等待语义修复后的当前双位数 Agent 也在来宾自有目标完成 R0 注入、采集与停钩，Agent/CLI 缓冲未报告丢失，两次为 partial；测试前后驱动均为停止状态，见 `.codex-build-logs/api-p0-r0-pending-vm-20261102/results/summary.json`。
- 时间轴密度桶起始宽度由 1 秒调整为 10 毫秒，每个类别保留桶内首末时间并按中点投影；最长时间范围仍自适应合并到最多 2048 桶。百万事件模型回归通过，但真实 GUI 的轨道呈现及缩放拖选尚未验收。
- 生产 `api_monitor_definitions.json` 保留 641 条可执行强类型定义；第三方参考声明和接口元数据仅在隔离候选中。来源与未核验状态须保留，不将 COM 元数据视为已安装 Hook；未知声明不推断参数。第三方转换后发行授权尚需确认。
- `KernelBase` 与 `KernelBase.dll` 等无路径、无扩展名模块使用一致的筛选和声明键；显式其他扩展名及路径保持独立。CLI 支持前后置排除、导入 GUI v1/v2 筛选文件、调用栈选项、Raw 槽位、声明和有界分类时间桶；显式 CLI 排除叠加导入规则，控制及覆盖包不受过滤。
- 强类型返回值和耗时有显式有效标记；可选有界调用栈在事件时采集，地址归属/最近导出只能称查询时快照。异步 I/O 的未观察字节以 unknown 表示，不能把失败、未完成或不安全晚到观察当作已知零；跨版本协议和真实失败路径仍需继续验收。
- 重启后已重连 Windows10-20H2 来宾 `DESKTOP-D2161R7`。原 Release 主程序和双位数 Agent 构建通过；来宾自有目标高频 9600 次逐项对照通过，见 `.codex-build-logs/api-p0-vm-metrics-reconnect-20261102/`。CLI 对等功能来宾重试 130 项通过但均为 partial，见 `.codex-build-logs/cli-parity-vm-20261102-retry/`；首次 x86 一轮异常的输出未保存，原因未知。上述非全部 P0、真实 GUI 或长期系统进程稳定性的证明。

## WinAPI 列、类别密度时间轴与调用者快照（2026-11-02）

- 列表和 TSV 通过同一列投影展示时间、相对时间、PID/TID、模块及已明确采集的值；时间筛选与其他条件共用分批/后台过滤。Raw 事件只采入口返回位置，强类型 CreateFileA/W/2 通过固定包普通事件标记传递真实返回 HANDLE；其余未采返回值或耗时不得推断。原协议包大小不变，原始 packetBase64 仍归档；仅对验证管道 PID 与创建时间的事件附加进程身份。
- 时间轴按主程序已接收事件、类别及自适应时间桶聚合，最多 2048 桶，不保留逐事件引用；包含后置隐藏事件，排除前置拒收、传输或队列丢失和内部/异步阶段事件，淘汰列表行不倒扣。原 ETW 时间轴的缩放、范围及拖选保留，选区以防抖方式并入异步列表/导出筛选；桶宽和时间缺失数可见。值基准不代表真实 GUI 和长时间性能验收。
- 调用者归属只在选中事件后对验证过创建身份的当前进程异步查询，明确标记查询时快照，不把地址当前归属当作调用发生时的历史事实。旧/无身份、已退出、不可访问均未知；Raw 返回位置经跳板/尾调用不保证是最初调用者。
- 项目自有声明异步加载，用于选中详情的签名和保守 Raw 槽位展示，不读指针内存。外部 API Monitor XML 不自动导入；审计脚本按 SHA-256 精确识别并隔离修复 esent.xml 首部多余字符，其他声明差异作为待审线索。WinVerifyTrust 的 HRESULT 返回声明与微软文档 LONG 不符，按原文件哈希在隔离副本中仅修正返回类型，GetLastError 与零成功判定仍标为待核验，不能称整项已核准。外部 XML 清洗副本和报告不纳入仓库。

## WinAPI 事件解码与前后置筛选（2026-11-01）

- “显示详情”默认关闭，控制事件表的详情列；事件详情面板复用 `DetailLayoutHost` 的全局显示方案；Raw 参数规则按模块名（不区分大小写）与函数名（区分大小写）保存在程序目录 `config/winapi-param.cfg`。参数槽位/连续小端字节两种解码均只使用已采集值，不读取指针指向的内存，也不能凭原始槽位推断实际参数数量；x86 fastcall 的寄存器参数不能由默认堆栈槽位准确识别。
- 事件下方与表格右侧详情使用一份 `StructuredFieldView` 规范文档：属性、参数分别投影为只读树，未分配字节由共享 `HexView` 展示；详情源工具行保留复制/导出，隐藏搜索且限制高度。行内和独立窗口沿用共享字段镜像，不是三栏。
- 参数类型可按固定宽度的有符号/无符号整数、bool/Win32 BOOL、wchar_t、float/double、指针与字节数组分配；指针宽度跟随目标 ABI。x64 参数模式中浮点参数走 XMM，而当前 Raw 数据没有采集 XMM，必须显示未采集，不能把整数寄存器或栈槽解释成该浮点参数；连续字节模式则明确按已采集字节的位模式解码。
- 参数条按可用视口宽度缩放，两种模式均按类型实际字节宽度绘制色块，数组长度翻倍时宽度按比例增加；参数模式解码仍按 ABI 槽位对齐；色块之间留间隔、剩余字节单独显示。无默认选中色，使用主题中性色块及悬停状态；数据不足的分配按所需宽度标出但不消耗未采集字节，并可通过“撤销末尾分配”移除。类型按钮使用短名，并根据目标位数及数组长度按宽度升序排列。数组长度默认 1，所有类型可分配数组；数组按已采集的连续字节解码，参数模式整段按 ABI 槽位对齐，不解引用目标指针。
- API 覆盖页维护 `config/winapi-filter.cfg`：前置筛选在管道读取后、写入档案前拒收业务事件；后置筛选保留事件档案和内存源，只异步改变表格可见行及可见事件导出。两者均不影响 Agent 控制事件与覆盖快照，也不改变 Hook 安装。规则在管道线程和 UI 之间以不可变快照共享，修改立即生效；前置丢弃的历史事件无法恢复，后置移除规则后只能恢复仍在内存窗口内的事件。
- 筛选区以模块 → API 分类 → 函数树预加载发布定义，并增量合并覆盖快照中的运行时函数和已保存规则；无分类的 Raw 函数按名称首字母分组。前置/后置左右并列，勾选表示接收或显示，分类仅用于导航。共享搜索支持模块、分类与函数，树节点和状态按 UI 时间预算分批更新，清空搜索恢复先前展开状态；批量全选/反选只修改搜索结果，模块排除下的单函数允许例外保存在版本 2 配置中，版本 1 排除规则继续兼容。

## CLI 监控接入（2026-11-01）

- 新命令 `monitor api capture --pid PID --confirm [--json]`，注册元数据在 `KswordCLI/R3MonitorApi.cpp`，文档在 `docs/CLI使用文档.md`、`docs/cli/monitor.md`。x64 CLI 使用 Qt-free `shared/ApiMonitorCapture.{h,cpp}`，复用主程序的 Agent 位数选择、原生注入、SessionLease、InjectionBroker 和 CoverageSnapshotReceiver；没有新增 R0 注入路径。CLI 工程非链接依赖两个 Agent，x86 CLI 对本命令明确返回5。
- 支持限时／取消、分类、Raw 模块／排除规则、跨位数自动子进程、导入主程序 INI 的业务选项及 Fake Success／剪贴板规则、文本和 JSON 事件／完整覆盖输出。控制端 SID、会话、broker、管道、停止路径始终由新会话生成，导入不能覆盖。Raw EntryOnly 的结果为 null。
- 每个目标保留进程创建身份，管道连接复核服务端 PID。只有 HooksInstalled 后开始计时；停止时通知根和全部已受理后代，继续读取到 HooksRemoved 和管道关闭（或确认原目标退出）。停止标记保留给迟到加载／常驻 Agent；DLL 和退役代码仍按原策略留到目标退出。目标已退出可确认清理，但不得虚构 stopWritten=true。
- Win10 常驻 Agent 的 GetPrivateProfileString 可能短暂阻止原子替换 INI，MoveFileEx 返回5／32；对原子 rename 有界重试2秒，不能退回截断原文件。虚拟机首次验收实际遇到并修复；重复 x86／x64 会话随后通过。
- `tools/Test-KSwordCliApiMonitor.ps1` 与自有 `tools/api_monitor/cli_capture_fixture.cpp` 覆盖77项：非法输入、双位数真实 WriteFile、常驻复用、缓冲截断、INI 控制字段隔离、真实 Raw 未知结果、隔离控制台 CTRL_BREAK、同 PID 租约冲突、x64→x86 子进程、目标提前正常退出及所有自有进程正常退出。Windows10-20H2 真实 WinRM 验收通过，完整轮次 Agent 丢包为0，无遗留测试进程；缺失导出／未加载模块等原有覆盖边界如实为 partial，不宣称所有641项均可用。
- CLI 与两套 Agent Release 构建成功，0 warnings／0 errors；新增 C++ 通过 HostX64 `/W4 /WX`，x86 capture stub 编译通过。覆盖快照、跨线程租约、管道分片三个生产协议回归通过。构建日志在 `.codex-build-logs/cli-apimon/`；运行 JSON 留在虚拟机隔离验收目录及本聊天产物中，不纳入提交。
- 两个已有通用测试入口存在本次改动前的失效假设：`tools/test_ksword_cli.py` 在旧夹具直接调用未限定命名空间的 configureConsole，编译报 C3861；`tools/Test-KSwordCliR3Coverage.ps1` 固定要求66条迁移记录，当前已有67条。专项回归和生产构建通过，不将这两个旧入口描述为通过，也未顺带改动其框架。

## 虚拟机 DWM 附加实验（2026-11-01）

- 用户要求只测试虚拟机，禁止操作宿主机 dwm。目标为 Windows10-20H2 来宾 `DESKTOP-D2161R7` 的 System32/dwm.exe，PID904、创建身份134379816769715121、Session1、x64、Window Manager/DWM-1，PPL=None、CFG开启、硬件栈保护关闭。所有附加经 WinRM 且强制校验计算机名；通过 CLI `privilege run --enable SeDebugPrivilege` 暂时启用已分配权限并在结束恢复，不改进程保护。
- 建立实验前快照 `Codex-DwmApiMonitor-PreAttach-20261101-01`。约4.6GiB的带内存快照造成宿主机严重卡顿，用户叫停后结束快照请求客户端并暂停指定 VM；快照最终正常完成。用户随后明确允许继续，恢复 VM，未再创建内存快照。恢复实验不能把这一卡顿归因于 DWM 注入，快照阶段尚未注入。
- 默认分类、Raw=0、3秒采集：elapsed5844ms，HooksInstalled/Removed=true，原DWM实例存活，无Application 1000/1001错误。仅5条Agent控制事件，无业务调用；返回6/partial，pipeWin32Error=233，coverageStale=true，不能描述为完整监控通过。
- 默认Raw全模块、5秒采集：30秒启动+15秒停止等待，elapsed45016ms、退出3，只收到SessionReady；当时HooksInstalled/Removed=false且cleanupComplete=false。稍后真实转储显示Agent已回到WaitForNextSessionConfig，不能据超时就认定永久死锁或崩溃。
- 将启动等待延至120秒、停止等待延至60秒复核同一常驻Agent：elapsed161578ms、退出3，启动仍超时；HooksInstalled/Removed在清理阶段才收到，cleanupComplete=true，但coverageStale仍为true，无实际业务调用。DWM始终是同一个PID/创建身份，没有崩溃/重启或WER自动转储；这种结果不能宣称Raw可用或所有Hook都覆盖成功。
- 安装期间抓到的线程栈：MonitorWorkerThread → InstallConfiguredHooks → InstallRawFallbackHooks → TryInstallRawHookBinding → InstallInlineHookAtAddress → AllocateNear → VirtualQuery/HookedNtQueryVirtualMemory。`hook/HookEngine.cpp:371` 的AllocateNear按64KiB步进重复扫描±2GiB，为明确耗时点；注释说跳过占用区域，代码实际没有按RegionSize跳过。一次栈不能证明唯一原因。停止标记也不会中断整个Raw安装过程，导致超时后继续安装、再撤销。
- 最后确认HooksRemoved、所有实验CLI退出、原DWM实例存活、临时dwm专用WER配置恢复为不存在，清理后线程栈回到WaitForNextSessionConfig。按既有策略Agent DLL/退役代码仍驻留，没有强制卸载。生产源码未修改；三轮JSON、一个手工完整转储及两份约3MiB线程转储保存在本聊天产物 `dwm-apimon/`。该空闲场景未验证图形交互负载、实际恶意载荷或长时间稳定性。

## DWM稳定性修复与宏控插桩（2026-11-01）

- 后续用户要求保留全部插桩源码并用宏包裹，最终二进制关闭宏；不进行git回滚。`KSWORD_APIMON_DIAGNOSTICS`／工程属性 `ApiMonitorDiagnostics` 默认0，两个位数工程及filters登记诊断源。临时1记录JSONL，最终0不求值参数、不链接日志／计数实现。研究报告见 `docs/API-Monitor-DWM稳定性诊断-20261101.md`。
- 原版同一默认Raw配置首轮8097绑定安装71704ms，晚补装9909绑定87704ms；近地址查询42979700次、47278.701ms，上下文读取20999.206ms，移除22297ms，最终覆盖排空2秒超时。修复后插桩首轮3093ms，9909绑定补装4187ms；近地址查询0（VirtualAlloc2）、分配累计1205.101ms、上下文4.817ms、移除93ms、最终修订3约610ms排空。不是仅AllocateNear一个问题，没有证据证明APC杀死worker。
- 邻近分配用VirtualAlloc2范围约束，最高包含地址必须是粒度边界减一；不支持接口时才按VAD区域跳跃。入口按区域读取；Strong键和活动补丁区间索引避免重复构造／扫描退役记录。准备后批量提交及批量恢复，在同一暂停区间复用上下文，恢复线程后绝不复用。页保护失败保留原值并重试；已公布代码／上下文仍保留到进程结束。
- 扩展Explorer测试发现已结束但仍可枚举的线程对象：原生NtSuspendThread返回0xC000004B、WaitForSingleObject=0，被Win32映射为错误5。现只跳过确已结束线程，仍存活线程失败保持拒绝；用逐线程held标记恢复，避免跳过线程后恢复错位。重启来宾加载新DLL后Explorer首次／重复监控成功，再次探测仍有4个结束对象，证明覆盖真实边界。
- 安装循环及兼容扫描可取消；取消后直接清理并发HooksRemoved。正常管道close保留已写未读字节，快照有积压不每64包睡25ms。HooksRemoved.snapshotRevision复用字段声明最终修订，CLI读到EOF后确认；新JSON字段finalCoverageRevision。未生效记录不再冒充Removed。旧Agent字段0表示未知，不改变1000字节布局。
- 32位记事本第二次Raw会话发现真实崩溃：C++ bad_alloc从PublishConfiguredCoverage逃出worker，转储虽有约1.86GB空闲但最大连续段只有64KiB。新增CodePageAllocator为x86 trampoline／Raw/Fake／回调代码按64KiB保留区逐4KiB页提交／封RX，避免单独保留导致碎片；只释放未发布页，退役代码仍保留。worker与Hook补装增加异常边界并发AgentFailure，CLI不再把提前停止算足时采集。同一32位记事本6轮Raw后正常退出0，最大连续空闲仍1403518976字节，无丢包／新崩溃；已提交内存约515.9MB，保留代码仍线性增长。
- HostX64构建0警告／0错误；最新`--no-ui`核心回归x64/x86各37项通过，主程序Release构建和双语审计通过。此前虚拟机CLI77项通过；最后的代码页修复后完整CLI／CMD／所有系统目标重跑未完成，用户停用VM并要求立即收尾提交，不能宣传为全部实机复验完成。带Qt的旧coverage夹具字段失配，完整UI入口未通过；本次未改版／验收图形页面。版本按用户最新要求保持5.2.1.0。
- 用户询问完整DLL卸载后，明确以稳定性为先，本轮保持常驻。当前Agent使用PIN，HooksRemoved只代表恢复入口／停止采集；不要宣传成FreeLibrary完成。完整卸载需另做准入及在途／异步回调回收，不能仅删除PIN或扫描当前IP。来宾为更新已固定DLL曾有计划地重启，与测试期间崩溃区分；宿主机DWM始终未附加。

## 分层和会话

- `APIMonitor_x64/hook/HookEngine.cpp` 负责入口补丁与 trampoline；HookTargets 负责强类型包装、Raw 入口和 Fake Success。MonitorAgent 管理配置与安装，MonitorPipe 负责有界队列和发送。主程序的 MonitorDock/WinAPIDock 与 MiscDock/ClipboardGuard 共用 Agent。
- 同一个 PID 只允许一个监控会话。`shared/WinApiMonitorProtocol.h` 的 SessionLease 用命名内核对象协调主程序实例、API Monitor 与剪贴板保护，必须在写配置之前获取。
- UI 的后台回调带 sessionGeneration；开始、停止都会换代，旧回调不能修改新会话状态。
- 管道为字节流，读端必须累计一个完整包；不要把一次 ReadFile 当成包边界。共享 readEventPacket 轮询可用字节并检查停止信号。

## Hook 安全约束

- 当前解码器是保守子集，指令描述与两遍布局支持已识别 RIP 相对寻址、CALL/JMP rel32、短跳转、短/近条件跳转和覆盖区内部目标重定位；跳入指令中间拒绝。识别并保留 ENDBR64。未知指令、地址宽度覆盖、超范围位移、不可读/不可验证入口、跳转桩循环和过早 RET/INT3 明确拒绝并报告地址/偏移/原因，不猜长度。
- 优先邻近 relay + 5 字节入口补丁，邻近分配失败后仅安全条件允许才用14字节；代码 RW 写入后转 RX。全局补丁区间登记防重叠，同址同 detour 的兼容绑定共享，不同处理器拒绝覆盖。Raw 与 Strong 使用同一引擎，Strong 表中存在但安装失败不能算已覆盖。
- 安装和恢复必须检查补丁区线程 RIP；挂起线程前准备容器，恢复线程之后才分配错误字符串，避免暂停持有堆锁的线程后死锁。
- 线程枚举使用 NtGetNextThread 检查当前进程线程，避免每个 API 全系统 Toolhelp 扫描。PE 导出遍历用 `hook/ExportCatalog.h` 的固定模块、安全读、范围和数量限制，拒绝畸形/不可读数据。
- 恢复失败必须保留 installed 和原始指针，允许重试。
- 入口恢复不证明 detour 或 trampoline 已无人执行。已公布的 trampoline、Raw/Fake stub 及绑定上下文保留到进程退出；目标模块与 Agent 固定驻留，配置快照不可变。重复会话会增加内存占用，这是当前保守回收策略的代价，后续替换引擎需单独设计安全回收。

## 子进程与就绪状态

- 自动子进程支持 CreateProcess A/W、CreateProcessAsUser A/W、CreateProcessWithTokenW、CreateProcessWithLogonW；关闭进程分类时自动注入入口仍可安装。根及子管道继续解析 AutoInjectChild，以发现后代。
- 子配置以 UTF-16 临时文件原子替换，继承剪贴板策略、Raw/Fake 配置与根停止路径；停止根会话可通知尚未被 UI 发现的后代。
- 管道连接不代表 Hook 已安装；UI 分别显示安装中、部分生效、安装失败、监控中与已移除。

## 有界记录与协议

- 2026-11-01：WinAPI 页面可输入16–65536 MiB文本估算预算并保存，立即淘汰超预算的显示窗口；100万条上限仍存在。新会话在注入前创建 AppLocalDataLocation 下 `api_monitor_archive/<session>/events.jsonl`，每个通过协议／会话校验的原始包在读管道线程内、UI有界队列之前落入单线程序列化的归档缓冲；JSONL保留机器字段和完整1000字节Base64原包，覆盖包也保留。每1MiB／有新包且经过1秒写盘，停止时FlushFileBuffers；写失败标红并请求停止。已接收与已写包数分开显示；已写不等于每包都已物理刷盘。只保证实际收到并成功写入的数据，不覆盖Agent丢包、停机前未读管道、启动前行为或本次改动之前已淘汰的记录。已有的表格TSV导出仍仅限当前保留窗口，完整记录直接从归档JSONL读取。
- Raw入口桩额外传递保存帧：x64显示RCX/RDX/R8/R9和最多四个原始栈槽，x86显示ECX/EDX和最多四个栈槽；读取限定在线程StackLimit/StackBase且用SEH保护，不解引用槽内指针。未经签名无法确定参数个数、类型或有效位，x64栈槽高32位可能保留垃圾；XMM未解码，结果仍为EntryOnly。自建x64/x86六参数函数回归验证寄存器、栈槽及原函数返回；禁止将本机DWM作为测试目标。

- Agent 环形队列 4096 个包，其中 64 个容量预留内部通知。队列拒收及取出后无法发送的包计入累计 EventsDropped 通知，通知由发送线程直接发送，不进入满队列。内部通知洪峰仍可能溢出，进程突然退出前的最后统计也不能保证送达。
- UI 待显示队列仍为24000；2026-11-01前端由QTableWidget迁为TableActionTableView＋WinAPIEventTableModel＋WinAPIEventFilterModel。规范保留窗口上限100万条／约512 MiB文本估算预算，先到者淘汰；估算不是总RSS硬限制。Agent丢失、UI队列丢失、窗口移出分别计数。导出读取同一规范窗口及当前筛选／排序条件，包含尚未物化的保留记录，已移出记录不在内；它不是无限完整调用轨迹。
- 不再为每行创建六个item、长期persistent index及独立过滤字段副本。普通增量批量beginInsert/RemoveRows，不reset；默认2048条一批。筛选快照按2048／4ms捕获纯值，AsyncOperation后台匹配，按512／4ms发布AcceptedRole，代理只处理变化范围；代次拒绝旧条件、已淘汰ordinal及clear之前的结果。隐藏页不提交筛选投影，菜单复用共享屏障。
- “保持贴底”时关闭Qt的currentChanged自动定位，避免旧选中行淘汰／筛掉后跳到替代的首行；rangeChanged和批次结尾合并一次排队scrollToBottom，勾选、可见性和菜单屏障都在执行时复核。取消贴底恢复原生导航，删除旧行后按事件身份及像素偏移恢复阅读点。不要只在append返回前滚一次，也不要每次菜单屏障后clear模型。前端实现与验收边界见`docs/API-Monitor前端长列表-20261101.md`。
- 协议版本 `0x20261003`，Windows 包大小1000字节。包包含 EventKind、API ID、操作 ID、会话身份、快照修订/状态/种类/地址及定义 SHA256。resultKind 为 StatusCode 或 EntryOnly，Raw 结果显示“未采集”，不能因 resultCode=0 标成 OK 或错误。剪贴板分类码为7。
- 升级必须同时部署新主程序、APIMonitor_x64.dll、APIMonitor_x86.dll；旧协议组合不兼容。已加载旧 Agent 的目标进程需要重启后再监控。剪贴板保护的读端也使用共享包布局与版本检查。

## 回归验证与边界

在 x64 MSVC 开发环境运行 `python tools/api_monitor/run_regressions.py` 顺序执行33个脚本（包括5项 offscreen Qt）；`--architecture x86` 执行29项。原始614项冻结身份、确定性生成/非法定义、元数据/返回契约、可执行机器码重定位、共享冲突/卸载失败/退役 trampoline、租约、管道分片、覆盖快照/中断/会话切换、晚加载、丢失统计、Qt状态/筛选和真实自有 x64 文件/IOCP/APC/取消/TCP/UDP/七个扩展路径均已通过。全选分类/默认 Raw、TLS 生命周期、加载器标记参数及256 KiB小栈另有回归。

这些测试编译生产代码或生产函数，覆盖指令边界、恢复失败、在途 detour、跨线程租约、字节管道分片、子配置继承、溢出计数与 Qt 状态/增量筛选。UI 测试使用 offscreen Qt Widgets，不替代实际目标程序的注入、长期压力、多系统版本、CFG/CET 或受保护进程验证。主程序构建使用 `tools/Invoke-KSwordBuildCheck.ps1`；两个 Agent 使用 x64 MSBuild 和 HostX64，分别编译 x64/Win32 目标。修改用户可见字符串时定点更新双语包，并通过 i18n 审计。

## JSON 定义与构建（2026-10-02）

- `APIMonitor_x64/api_monitor_definitions.json` 是唯一强类型定义源，641项：原有614项 ID 不变，615–623普通补缺，624–634异步观察，635–641 Winsock扩展。417个普通生成包装、224个具名专用处理器。项目说明见 `APIMonitor_x64/README.md`。
- `tools/api_monitor/generate_definitions.py` 仅用 Python 标准库，编译前校验/生成至 `$(IntDir)generated`，只更新变化内容。绑定表、原函数指针声明、普通包装、扩展发现元数据由 JSON 生成，专用正文保留 C++ 并在 `hook/ApiHandlers.json` 注册。禁止 JSON 函数正文和任意表达式。
- 定义包括 ABI/方向/编码/采集方式/长度/成功条件/错误来源；复杂行为以具名 handler 解释。重复身份/符号、未知类型/处理器、错误长度引用/间接类型/引用环都会失败。
- Release 成功后原样复制至 `Ksword5.1/x64/Release/profiles/api_monitor_definitions.json`，不压缩。主程序有 Agent 非链接依赖；发布副本仅查看/核对，不运行时加载。源定义改后必须重建。
- 生成的定义 SHA256 出现在 Agent 事件/覆盖快照，UI 比较发布 JSON 并提示缺失/不匹配。已验证源与发布副本字节一致，SHA256=`7ce4774f1fd93dc2fd723024ed5e89675407bbc94719fa66d625a9eac5565b10`。
- 基于 SDK 10.0.26100.0 与可选 phnt 原生声明只读核对2592个带方向注解的参数，差异0，定义有217项简单长度关系。`tools/api_monitor/audit_definition_metadata.py --headers ...` 可重复审计；原生声明不作为构建依赖，没有第三方 Hook/解码实现接入。
- Agent x64 Release 增量/干净 Rebuild 均通过。主程序最后检查日志 `.codex-build-logs/ksword-build-check-20261002-134416.raw.log`：BUILD_RESULT=SUCCESS、EXIT_CODE=0、exe=20259840字节、I18N_AUDIT_PASSED=True。每阶段回归和 Release 编译后分别提交。

## 完整覆盖快照

- EventKind：ApiCall=0，IoSubmit/IoWait/IoComplete/IoCancel=1/2/3/4，CoverageBegin/Item/End=16/17/18。Strong/Raw/Fake/Dynamic=0/1/2/3，运行时 Raw/Fake ID 从 `0x80000000` 起。
- 状态：Installed=0、SharedEntry=1、CategoryDisabled=2、WaitingModule=3、ExportMissing=4、RuleExcluded=5、RetryableFailure=6、Unsupported=7、Removed=8。普通、剪贴板 Win32u Fake、已发现扩展均报告实际结果。新会话分类关闭不得继承旧会话 Removed。
- `MonitorCoverage` 产生不可变完整快照，内容不变不升修订；发送线程直接发送，不占普通队列。`shared/ApiMonitorCoverage.h` 验证顺序/完整性、拒绝旧会话/旧修订。断线/中断保留上次完整快照并标记过期。
- UI API事件/API覆盖按 PID 筛选；异步事件标注提交/等待/完成/取消与操作 ID。根/子读端各自维护覆盖接收状态，ClipboardGuard 跳过控制/异步包。会话身份与 UI generation 联合拒绝旧更新。停止使用有界 Drain 发送最新快照/事件后关闭管道。

## 异步 I/O 与 Winsock 扩展

- `core/MonitorAsyncIo` 容量8192，按会话/资源身份/OVERLAPPED 关联单调唯一操作 ID；原调用前登记，提交先于竞态完成，重复完成去重。同步完成与 IOCP 消费分别记录预期，完成键参与关联。
- ReadFile/WriteFile/DeviceIoControl、WSASend/Recv/SendTo/RecvFrom、Ex/结果查询/IOCP/取消入口参与关联；取消请求不表示完成，CancelIo 只针对发起线程。处理 FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 与 hEvent 低位。
- CloseHandle/closesocket 退役身份，句柄复用产生新身份；未完成 OVERLAPPED 重用标记歧义，结果查询/IOCP 不强行关联。满容量报告 IoUntracked 并保留原调用/回调。
- `hook/ContextThunk.h` 保持 x64 寄存器/栈参数并登记 unwind 元数据。停止后应用回调仍执行，保留 error/bytes/OVERLAPPED/flags，旧操作不向新会话发事件。UDP 来源地址完成时有界读取，待完成提交不读无效输出。
- WSAIoctl 的 SIO_GET_EXTENSION_FUNCTION_POINTER 发现 AcceptEx、ConnectEx、WSARecvMsg、WSASendMsg、TransmitFile、TransmitPackets、GetAcceptExSockaddrs，已知异步完成也触发发现。
- 每个扩展地址保留独立原函数/上下文，重复幂等，不替换应用指针；覆盖按实际地址报告冲突/不支持。File 分类关闭但 Network 开启时仍安装必要 IOCP 观察入口，抑制 File 事件并保留 Network 完成关联。

## 需要保留的边界

- 任意 COM 方法、直接系统调用、启动前调用、无法识别的原生异步完成路径、本会话没有通过 WSAIoctl 发现的扩展地址不保证覆盖。
- 启动前 IOCP 关联无法补推；同键同 OVERLAPPED 的手动投递无法完全区分真实内核完成。不同键手动通知不会错误完成操作，已通过回归。
- 系统缺失导出、保守解码器拒绝入口按不可用/失败报告，Raw 不绕过同一入口失败。
- 保留到进程退出的退役代码/回调上下文随重复会话/回调增长。8192限制跟踪槽位，不限制所有退役内存；当前没有安全回收算法。

## 独立 x86 工程与跨位数安装（2026-10-02）

- `APIMonitor_x86/APIMonitor_x86.vcxproj` 仅提供 Debug/Release Win32，链接共享采集源码及唯一 JSON，641项定义与 x64 一致。生成器 `--architecture x86` 输出至本工程 `obj/$(Configuration)/generated`，不能复用64位生成目录。32位项目详情见 `APIMonitor_x86/README.md`。
- `hook/HookEngineX86.cpp` 包含共享引擎 x86 分支；`InstructionDecoder.inc` 是32位保守解码器，支持绝对地址、相对调用/分支、内部目标、ENDBR32、FF25绝对跳转桩。rel32使用32位回绕，线程检查使用EIP；区间冲突、退役原始指针和恢复失败策略保持一致。
- `ContextThunk.h` 的32位实现保持 stdcall 参数和清栈，现有异步回调及全部七个 Winsock 扩展复用；停止后保留回调语义。`EntryStubs.h` 的 Raw 保存标志/寄存器/x87/MMX/XMM 后尾跳原调用，Fake 使用 ret N 与 EAX/EDX:EAX；已知 API 清栈值由目标 `sizeof` 生成，未知 Fake 必须显式提供第七字段 `x86StackBytes`，不猜 ABI。
- WinAPIDock 增加32位栈清理输入/表列，序列化保留空字段并兼容旧六字段配置。32位未知 Fake 仅支持 cdecl/stdcall 的标量/整数返回；不支持 fastcall、浮点/结构返回，不填 out 参数。Native剪贴板阻止桩按真实 HANDLE/BOOL 契约返回NULL/FALSE并设置拒绝错误，32位清栈分别为8/12/0。
- `shared/ApiMonitorPlatform.h` 查询进程/PE架构。WinAPI和剪贴板保护安装时自动切换同目录的标准 Agent 文件名；自定义 DLL 先校验位数。`ApiMonitorInjection.h` 原生注入按远程目标模块基址解析LoadLibraryW，按模块列表确认加载成功，避免64位HMODULE被DWORD截断；主程序直接解析目标PE导出处理32位注入，子进程通过会话管道请求主程序处理并验证目标创建时间，超时不释放仍可能使用的远程路径。
- 独立Injector工程、源码、解决方案项和Agent依赖已删除。主程序以非链接依赖构建两套Agent，显式映射 x86 为Win32；统一发布到 `Ksword5.1/x64/Release`，打包时携带主程序、两个DLL及profiles JSON。
- x86 DLL使用静态CRT，避免32位运行库覆盖64位主程序目录。x64 DLL仍使用64位动态CRT。自动子进程按实际位数重新选择Agent，子配置记录选择结果，继承会话/根停止路径，32→64和64→32均已验证。
- x86 Release干净Rebuild及25项回归通过，证据 `.codex-build-logs/apimon-integrated-x86-regressions.log`。包括真实异步文件/IOCP/APC/取消、TCP/UDP、全部7扩展、Raw/Fake与本机双向注入、跨位数子进程根停止。x64完整回归29项（含Qt规则与生产解析器往返）证据 `.codex-build-logs/apimon-integrated-x64-regressions.log`。
- 主程序Release检查 `.codex-build-logs/ksword-build-check-20261002-163225.raw.log`：BUILD_RESULT=SUCCESS、EXIT_CODE=0、exe=20301824字节、I18N_AUDIT_PASSED=True。每阶段先编译/测试后分别中文提交；其他工作区修改未纳入。
- 所有已有覆盖边界继续适用，尤其未知入口拒绝、任意COM/直接系统调用、未发现扩展、跨用户TEMP目录、退役代码内存增长。多Windows版本、严格CFG/CET、长期压力与受保护进程不属于本机回归的证明范围。


## 主程序集中注入与助手移除（2026-10-02）

- `shared/ApiMonitorInjectionBroker.cpp` 仅编译进64位主程序，不生成新EXE或DLL；事件协议保持不变，控制请求采用独立固定布局的InjectionProtocol v1（请求288字节、响应528字节），两个位数静态断言一致。
- 主程序直接注入x64及x86。`ApiMonitorRemoteExports.h` 在目标进程读取PE32/PE64导出表，验证范围、数量、机器类型和可执行映像页；具名/序号及转发导出有界解析，转发深度最多8。不能把本地64位 LoadLibraryW RVA直接用于32位目标。
- WinAPIDock在启用自动子进程时创建会话专用服务，独立于普通事件队列。INI新增 `injection_broker_pipe/token/pid/creation`，子配置继承。Agent只发请求，主程序选择已注册父进程对应DLL；不接受请求者提供任意DLL路径。校验内核提供的管道客户端PID、创建时间、根令牌、真实父子关系、子配置所属会话及根停止路径；成功子进程登记后可继续请求后代，容量8192。
- 管道拒绝远程客户端，ACL限当前用户及SYSTEM，首实例防抢占，客户端复核服务PID/创建时间。请求读取、发送和远程加载有界等待；停止会话取消在途管道和加载等待，仍可能被远程线程使用的路径内存保留到目标退出。未完成读取的客户端不能阻塞主程序退出；旧会话或主程序退出时明确失败，不启动任何注入助手。
- API监控与剪贴板保护的Qt配置写入改为UTF-16LE带BOM，与Win32 INI读取一致；已验证中文/空格路径、broker字段、剪贴板策略、原子提交后撤销旧停止标记。
- Release中的两套旧助手EXE/PDB/ILK共6文件已移出到本地忽略目录 `.codex-build-logs/retired-apimon-helpers`。重新构建不会生成；源工程和项目依赖均无助手引用。Agent DLL/PDB和profiles JSON保留。
- 主程序Release构建证据 `.codex-build-logs/ksword-build-check-20261002-180835.raw.log`：BUILD_RESULT=SUCCESS、EXIT_CODE=0、exe=20337152字节、I18N_AUDIT_PASSED=True。会话服务、无助手双位数注入、32→64/64→32真实子进程及根停止回归通过；完整回归证据见上述25/29项日志。
- 跨用户TEMP目录与ACL、受保护进程、严格CFG/CET及多系统矩阵仍需单独验收；显式改写父进程属性的CreateProcess请求若父子身份不匹配，会拒绝自动注入。更新已驻留旧Agent的进程仍需要重启。

## 全选监控崩溃排查与修复（2026-10-02晚）

- 用户导出的 TSV 是排队后送达 UI 的事件，无法证明最后一个 Hook 或采集动作没有异常。JC 自有崩溃日志显示 x86 Agent +0x6b7fb / +0x2be47，原版 PDB 对应 `AppendWideText` / `HookedLdrLoadDll`；搜索参数为 `0x1`。直接 `LdrLoadDll` 标记参数的对照调用在未监控时成功、旧采集路径崩溃。
- 加载器低地址搜索参数记录为 `search=tagged:0x1`，不解引用；保留原 NTSTATUS 和 LastError。宽/窄字符串采集按详情容量和源长度限制，逐页检查可读性，不读取 guard/no-access 页；UNICODE_STRING 结构有安全读取及长度校验，无法采集标记 `<unreadable>`。此修复不表示所有专用处理器已完成任意输入/系统版本审计。
- 自有全分类/默认 Raw 并发进程第一次访问冲突落在 `RawHookEnter` 的静态 TLS 读取：`gdi32!EngAcquireSemaphore` 实际进入 ntdll 同步函数，线程清理时 TLS 向量已空。Raw 安全策略必须同时检查解析转发及跳转后的实际模块；不能仅检查配置模块和导出名黑名单。排除的别名在覆盖快照标为 RuleExcluded。
- HookEngine 在读取静态 TLS 前直接检查 TEB 的 TLS 向量及本模块槽位（x86 FS:0x2C、x64 GS:0x58），不调用监控 API。TLS 未初始化/已清理时直接旁路，强类型重入检查先判断引擎旁路再访问自身 TLS。测试主动移除向量和模块槽位，复原后验证嵌套保护仍正常。
- 新启动的 SysWOW64 记事本暴露另一项 `0xC00000FD`：发送线程内联了256×1000字节的栈批次，但宿主默认栈只有256 KiB。批次移为静态缓冲；`g_pipeLock` 从取队列之前持有至发送结束，防止并发 flush 复用缓冲。保留批次上限、队列溢出统计与独立覆盖快照。`test_small_stack.py` 以 `/STACK:262144,4096` 运行真实 Release DLL 验证。
- 完整回归证据：`.codex-build-logs/apimon-crash-final-x86-regressions.log`（29项）、`apimon-crash-final-x64-regressions.log`（33项）。每处修改分别编译两个 Release Agent 后提交；新增全分类真实并发回归 `test_live_all_targets.py`。
- 通过生产64位注入器与会话 broker 对新启动的三个 x86 应用全选分类+默认 Raw+自动子进程测试，最终均正常安装、持续记录并收到 HooksRemoved：JC PID59824，Raw7992、189824事件、3043条标记搜索参数加载；SysWOW64 notepad PID34064，Raw6397、12194事件；SysWOW64 cmd PID8392，Raw4756、307事件。证据 `.codex-build-logs/x86-real-app-probe.log`、`x86-real-app-results.json`；每次活动观察15秒，退出本轮自有进程，不代表长期压力证明。
- 另查到较早的 x64 notepad 转储，加载的是 `Ksword-nice` 目录中的9月23日旧 DLL，不应与当前 Release 产物混同。当前 DLL 定义641项及发布 JSON SHA256保持一致；未重新引入注入助手。工作区其他功能修改保持原样。
- 用户追加要求后，用当前 Release 对新启动的原生 x64 System32 notepad（PID41880）和 cmd（PID47748）再次全选注入，IsWow64Process2 确认机器类型；六分类、默认 Raw 模块/排除规则与自动子进程开关均启用。各观察30秒，记事本 Raw5893、43959事件，cmd Raw4357、409事件，均取得完整覆盖快照、HooksInstalled 和 HooksRemoved，未出现崩溃，随后仅关闭本轮自有实例。证据 `.codex-build-logs/x64-real-app-probe.log`、`x64-real-app-results.json`。x64 四线程全分类/默认 Raw 回归另采集290080事件并正常停止（`apimon-x64-all-selection-recheck.log`）；x64 Release 增量编译成功（`apimon-x64-all-selection-build.log`），发布 JSON/两套 DLL 架构校验通过。本轮无代码修复，不代表每个 API 已安装或完成长期压力验证。

## WinAPI 暂停与详情 HEX

- 会话操作区的“暂停”默认关闭，可在会话期间切换；接收线程在校验包之后、前置筛选和归档之前丢弃普通 API 事件，单独统计暂停丢弃数。覆盖率及内部控制包仍需处理，以维持会话状态和子进程管道；暂停前已接收的事件可以继续入队。
- WinAPI 事件详情的 HEX 视图初始化为每行 8 字节，仍可通过视图工具栏手动更改行宽，不影响其他 HEX 视图。

## WinAPI 列、筛选与导出

- 事件表禁用全局内容采样列宽适配，使用可手工调整的初始列宽；缺失字段显示 `-`。耗时使用当前主题强调色，按毫秒的十进制数量级调整透明度，不对未采集数据着色。
- 筛选进度延迟 350ms 接入 KProgress：采集与结果应用阶段按实际进度更新，后台匹配阶段不伪造百分比。事件专用 CSV/TSV 导出从保留窗口及筛选条件生成，包含 A/B 的所有列。
- 调用者模块与内存归属为当前进程映射的异步快照，不能当作历史时刻证据；表格对有调用地址且进程身份可验证的事件分批后台查询，结果随表格记录淘汰。2026-11-03 自有进程单地址 10 万行真实表格模型和代理自动填充约 3988ms；进程权限、地址分布和系统负载会影响实际用时。

## 暂停、刷新和退出（2026-11-03）

- 自动调用者解析器的关闭登记曾在 `beginShutdown` 只停止 worker、直到页面销毁才释放 lease，而主窗口等 lease 归还后才销毁页面，造成退出死锁。现由关闭回调通过 `AsyncUiDispatcher` 回到模型线程移交停止与后台 join；回归在模型仍存活时验证 pending 清零。
- ETW 使用 50ms/32 行的有界 UI 提交；WinAPI 原先可能一次接收 24000 行并以零间隔持续投影。现 UI inbox 最多每批接收、投影 512 行，积压以 16ms 间隔继续；后台 inbox 按剩余容量转移，丢弃继续计数，完整原包仍以现有语义先入磁盘归档。调用者快照投影间隔由 10ms 调整为 40ms；自有离屏回归的 12000 行最大批次 2ms、10 万相同地址快照约 18.4s，仅是本机样本。
- 主程序使用会话唯一的全局命名事件通知新 Agent 暂停，Agent 持有只读等待权限，子进程配置继承同一名称。暂停先阻止业务事件，再批量恢复 Hook 入口，确认后发 `HooksPaused`；恢复时重新安装并发 `HooksResumed`。根进程确认恢复前主程序继续丢弃暂停期数据；旧常驻 Agent 不支持此控制，需重启目标进程。x64/x86 自有目标回归验证原始入口字节、暂停时无事件、恢复重新安装及暂停中停止，并验证两个独立 Agent 监听同一事件；未以实际自动注入子进程路径实测此功能。反复停装按现有安全策略保留已退役代码，不能称为完全卸载。
- 启动失败时即使清理已经开始也显示真实失败原因，未发布配置不再声称已发送停止标记；只剩停止事件的历史现象无法单凭空归档确定原始错误。本机非提升测试重现了会话目录 ACL 错误 5，提升的自有目标后端启动/暂停/恢复/清理通过，不能推断用户目标当时的具体错误。
- 原 Release 的旧 Agent 被用户记事本映射时，先在自有进程验证映像重命名与替换可行，再将旧 DLL 移至工作区忽略目录并原子放入已测试新 DLL；未结束用户进程。已加载旧 Agent 的目标仍须重启才会使用新代码，旧版不支持暂停控制时 UI 会提示。
