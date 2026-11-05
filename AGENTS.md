# KSword Agent Notes

## 共享记忆

跨 agent / 开发者共享的项目知识放在 `.claude/memory/`，索引见 `.claude/memory/MEMORY.md`。
任何 Codex、Claude 或其他 agent 开始处理本仓库任务前，必须同时读取两类记忆：

1. 该 agent 在当前平台可用的自身记忆、用户记忆或历史摘要（如果有）；
2. 仓库共享记忆索引 `.claude/memory/MEMORY.md`，并按任务关键词继续读取其中链接的相关主题文件。

`.claude/memory/` 是跨 agent 共享的项目记忆，不是 Claude 专用目录；即使 agent 不是 Claude，也不得因目录名而跳过。某一类自身记忆不可用时，应继续读取另一类可用记忆，不得将“没有自身记忆”作为跳过仓库共享记忆的理由。

改动主程序 UI、主题或窗口背景前，先读 `.claude/memory/ksword-ui-architecture.md`：其中记录了主题 token 体系、
全局样式块链路、透明背景与毛玻璃的平台约束，以及已经踩过的坑。新增可复用经验时请一并更新该目录。

## 主程序 UI 强制接入规则

新增页面、重排页面或修改控件外观前，必须读取 `.claude/memory/ksword-ui-architecture.md`，并检查至少两个功能形态相近的现有页面及其共享组件实现。参数操作页优先对照 `MiscDock/SystemTime/SystemTimePage.cpp`、`MiscDock/VirtualLocation/VirtualLocationPage.cpp`；路径均相对 `Ksword5.1/Ksword5.1/`。

- 参数与执行页必须复用 `UI/ParameterWorkspace`：参数正文独立滚动、执行动作固定、状态与结果保留可用高度；长说明放入参数区或共享折叠分区。结果列表复用现有结果容器，字段详情和日志分别使用共享字段视图、`CodeEditorWidget`。
- 页根、内容面、Tab关系与工具行通过适用共享入口接入；普通按钮和独立输入由标准主题自动绑定，页面显式声明主动作、风险等业务角色。Tab 使用 `PageControlStyle` 的适用入口；工具行使用 `NormalizeToolbarRow`；纯图标按钮使用 `theme.h` 的统一尺寸并配置释义。间距、圆角、颜色、字体和交互状态以共享组件为准。
- 页面只组合共享组件与业务内容；共享组件已有的两栏、滚动、动作栏、主题或详情结构不得在页面中另写一套。确有共享能力缺口时，先扩展共享组件，再接入页面。
- 完成前逐项核对同类页面的分区、留白、Tab 层级、动作位置、窄窗滚动和深浅主题。编译成功不能作为 UI 合规或实机视觉验收的结论；在可编译环境中使用真实主程序验收，并明确报告尚未完成的视觉验证。

以上要求适用于所有 agent；新增页不得以“先做功能”省略 UI 接入。

## 全页面 UI 设计规范（强制）

### 适用范围与交付门槛

本节是全项目页面设计的统一强制标准，适用于新页和既有页、所有导航层级、惰性/动态生成页、空态/加载态/错误态，以及主程序、设置、属性详情、工具弹窗、Taskbar、HUD、Launcher和自有插件的图形界面。所有页面必须同时符合通用规则与对应页面类型规则；不能因为“不是参数页”“使用原生控件”或“旧页一直如此”而跳过。

- **每个页面必须至少归属一种下表布局规范。** 开工时记录“导航入口 → 页面类型 → 共享布局入口”，交付时按此记录验收。混合页可组合多种规范，但每块内容必须有明确职责；未分类、只改颜色或只排列原生控件的页面不得交付。
- **新页首次交付就必须合规。** 完成业务功能或编译通过，不代表页面完成；不得先交付传统控件堆叠的大页，再把共享框架、主题、布局和窄窗适配留给用户指出后补做。
- 修改现有页时，必须把受影响页面按本节逐项核对；不合规项必须修复或如实列为未完成。未检查的旧页不得标记为已覆盖，新增规范也不代表存量页面已经完成整改。
- 本节规定设计目标与适用边界；共享组件实现提供具体样式，`.claude/memory/ksword-ui-architecture.md` 记录实现约束与历史经验。历史截图、旧页面、旧记忆与本节不一致时，以本节及用户最新明确要求为准。
- 开工先按实际用途分类，再选择共享入口；必须检查至少两个功能形态相近的现有页面及其共享实现，不能只抄一个旧页的控件摆放。共享能力缺失时先补共享组件，不在业务页复制第二套布局、主题、导航或详情框架。
- 专业控件保留自身结构，只是局部结构规则的例外，仍必须符合配色、信息密度、交互状态、可读性和性能规则。其它例外只能来自本节明确范围或用户明确要求，交付时写清范围与理由。

### 1. 共同目标与页面组织

- **先设计操作心智模型，再选择组件。** 新增或修改交互前，记录真实导航入口，以及“用户任务 → 对象/范围 → 参数/草稿 → 显式执行 → 结果归属 → 失败恢复”。按对象结构选控件：层级目录范围用可视化目录树，单文件目标用文件选择器，整卷数据源用卷选择；共享布局和主题承载这些控件，不代替用途判断。相关流程审查及实例见 [操作心智模型审查](docs/操作心智模型审查.md)。
- **动作时机与目标必须可预测。** 参数编辑形成待执行草稿；即时只读预览可随选择更新，但耗时扫描、系统策略和写操作应有明确执行入口。批量操作说明对全部所选执行的动作，不由首行状态代表整个集合；动作使用请求时冻结的真实对象身份，复制已有数据与执行资格分别判断。
- **结果与草稿分别保留身份。** 页面显示本次结果实际对应的对象、范围、来源和采样时间；修改参数、切换列表选择或刷新不能静默改写旧结果来源或丢弃未保存草稿。读失败、部分结果、成功空结果分别呈现，并提供原位重试、刷新、重新选择或载入原任务参数的恢复入口。
- **按流程验收全部受影响入口。** 检查鼠标与键盘选择、批量/混合状态、运行中改条件、取消、失败、重新执行及旧结果/草稿保留。报告已检查页面和未覆盖范围；源码与编译不能替代实机验证。用户禁止窗口自动化时，不启动、操作窗口或运行离屏 GUI 测试，继续完成源码和构建检查，并列出手动验收项。
- 保持有用信息密度，降低视觉负担。允许换布局、增加分类Tab或参数列，但必须保留业务信息、关键状态、动作入口及可比较关系。
- 操作按“对象/范围 → 参数或筛选 → 执行 → 状态/结果”组织。共同作用于多个结果页的操作放在共同页头；只作用于某个结果的操作留在该结果区。
- 需要同时观察的参数和结果同屏呈现。宽屏根据内容采用双列参数或合理左右比例；日志少时不让日志区吞掉大部分空间，常用参数不为折叠而折叠。
- 参数行和分组使用自然高度，宽屏利用分栏、双列参数或有宽度上限的表单；伸缩空间交给结果、预览、图表或正文。禁止把小弹窗的纵向控件堆叠拉满大窗口，禁止把剩余高度平均分配给字段行、把输入框无意义拉到全屏宽或留出无职责的大空白。
- 分区之间的留白必须大于区内行距。标题、字重、留白和轻量分隔线承担层级；色块、边框、箭头、高亮只承担明确功能，不叠套无用途容器。
- 显示真实状态：空结果、未加载、加载中、失败、不可用/无权限必须可区分，提供对应的重试或恢复入口；不能用空表冒充查询成功。

### 2. 各类页面必须使用的结构

以下组件路径均相对 `Ksword5.1/Ksword5.1/`；非Qt子项目使用本节语义相同的原生适配，不能因工具链不同跳过设计要求。

| 页面类型 | 强制结构与共享入口 |
| --- | --- |
| 主列表、树、现场清单、审计结果 | 公共操作/筛选在上，结果占主要空间；使用 `TablePresentation`、适用的 `ResultTableHost` 和表格操作条；详情通过共享 `DetailLayoutHost`/`DetailLayoutRegistry` 接入。 |
| 参数、执行、请求构造、编辑工具 | 使用 `ParameterWorkspace`。参数正文独立滚动，执行动作固定，状态/结果可见；分区通过 `StyleParameterSection` 等共享入口组织，长说明与低频参数按需要折叠。 |
| 设置和非属性类二级工具窗 | 使用 `SecondaryPageLayout`。分类Tab、自然高度表单、分区及固定底栏分工明确；设置预览与实际应用状态区分，取消/应用语义保持一致。 |
| 属性、对象详情、字段详情及详情弹窗 | 使用 `InstallDetailWindowFramework`、`DetailDialogChrome`、`DetailPresentation`。对象摘要全宽，分组导航与无描边内容卡片分层；字段来自同一 `StructuredFieldView`/规范文档，不能每个窗口手工复制一套。 |
| 日志、命令返回、文本详情、代码输出 | 使用 `CodeEditorWidget` 等项目共享文本外壳，保留搜索、复制、导出和完整文档语义；字段型内容使用共享字段视图，不堆重复只读输入框。 |
| 监控、时间线、图表、仪表盘 | 指标分组和图表尺度明确，图表复用共享主题/历史组件，状态与采样时间可辨；图表、表格、快照选择有一致的数据身份。 |
| 生命周期、状态诊断、专业操作页 | 保留步骤、状态、依赖及恢复动作；使用共享页根、工具带、输入和内容面。此类页不强制套参数/日志两栏，也不得沿用无层级的巨大空白页。 |
| HEX、内存工作台、反汇编、调试器、专业编辑器 | 保留专业布局、模型、内部滚动及控件身份，按需使用 `ksword_detail_keep_layout` 等明确保护；外围导航、工具行、搜索和主题仍接入共享规范，不让通用框架进入其内部重排。 |
| 消息框、确认框、菜单及系统选择器 | 普通消息使用共享 `ThemedMessageBox`；菜单显式提供不透明背景及各状态文字色。Qt/系统文件、颜色、字体等选择器保留原生结构，不套详情卡片框架。 |
| Taskbar、HUD、Launcher、独立辅助窗、自有插件 | 按职责保持紧凑、可读、可操作的独立布局，复用本项目可用主题/控件或等价适配。Taskbar页面总览保持真实页面目录、搜索和逐层直达；RGB仅作辅助强调，模糊可调且有不可用回退。 |
| 外部第三方原生窗口 | 统一可控宿主与边界，不接管不可控内部布局；明确内部视觉验收边界，不将其算作已完成改造的自有页面。 |

### 3. 底色、文字和主题状态

- 主程序在首个业务窗口创建前安装 `InstallStandardWidgetTheme`，以应用级标准主题提供普通Qt控件的默认外观、度量和生命周期接入。新增普通按钮、输入、数值框、下拉框、滑块及Tab不再要求逐个手工适配；页面只声明业务语义和选择布局框架，不能另写一套基础皮肤。
- 主窗口与ADS浮动窗口使用 `MainSurfaceStyle` 的固定表面层级：底板、内容、工具带、表头、输入。各层直接由主题种子派生，不能随父容器嵌套逐层抬亮，造成正文与背景失去对比。
- 使用 `theme.h` 动态token及 `ThemeBinding`；同一控件的QSS/palette由一个明确拥有者管理，热换肤更新已有内容。业务数据的风险色、热度色、语法色保留原语义。
- 文本、图标必须在正常、悬停、按下、选中、选中悬停、禁用和焦点状态均可辨。正文按共享对比校准保持至少4.5:1，主要图形按共享校准保持至少3:1；不能让蓝色图标与蓝色悬停底融合。
- 输入、下拉、数值框、菜单及弹窗必须有符合其用途的实际底色，不能依赖透明继承让控件隐形。背景图、透明/毛玻璃模式保留既有策略，失效时仍须保证文字和操作可读。
- 使用应用字体及共享字号，不用更换字体掩盖字号/字重错误。参数和详情正文沿用共享14px/10pt下限，已有更大字号保留；高密度数据表按所属组件指标处理，不全局硬放大。
- 标题、说明、正文、禁用态用清楚而克制的字重和前景层级；标签和右侧控件垂直对齐，避免一侧偏高。数值/地址/代码可使用适合阅读的等宽字体，不把整页统一改为代码字体。

### 4. 留白、尺寸、圆角与外框

- 每个页根的四边留白等宽，且只由一层负责。主内容框默认6px；明确页面类型的4/8px或欢迎页16px沿用其共享入口，不能同页混杂或父子重复累加。
- 参数/详情卡片沿用16px内边距；设置分区通常24px、区内行距8px。表单行使用自然高度，剩余高度交给结果/滚动区，不能把空白平均拉进各参数行。
- 独立内容面/工具带使用8px圆角，独立按钮/输入使用5px；同一组件的内部接缝可为0。只有确认是独立一块的控件才修改外围圆角，不对复合控件内部、冻结辅助窗格或编辑器部件硬替换。
- 普通 `QGroupBox` 必须采用新版分区/卡片：参数框架内为标题与细分隔线，独立卡片为卡片内部标题＋正文留白；默认由标准主题接入。标题不得嵌在线框上，页面不得再定义原生图例式GroupBox皮肤。进度使用细轨道与独立数值，不将其拉成亮色矩形块。
- 参数/详情等参考色块采用无描边卡片；结构靠底色和留白区分。只在明确输入边界、焦点或数据结构需要时保留轻量边界，不另套一圈高亮线框。
- **外层凹圆过渡只适用于“方角外框包着圆角内容”。** 过渡画在最外框，外半径=内部半径+留白（通常14=8+6），内外同心。外面没有方框、已有圆角面板或只是内部结果Tab时不画外圆；不能把角片盖到内部圆角上，也不能新增贯穿全高的侧翼/描边。
- QSS `border-radius` 不代表子视口已裁剪；表格/树实际圆角使用 `RoundedViewSurface` 等共享实现。非置顶主窗口不绘大蓝边框，同时保留原缩放命中区；其它原生窗口外沿由共享 `WindowChrome` 与系统策略处理。

### 5. Tab 必须按关系选择入口

| 实际关系 | 必须采用的行为 |
| --- | --- |
| 普通页签、属性/详情自身导航 | `StylePageTabs` 或对应详情/二级共享导航；保留原Tab对象、标题、索引、键盘和鼠标语义。 |
| 内部内容区只需等边留白 | `StylePageTabsContentFrame`；有留白不代表有外框，不因此绘外圆。 |
| 主导航直接承接方形工作区 | `StyleSquarePageTabsFrame`；纯单子Tab/明确惰性壳可转交外框资格，工具条、splitter或并列内容会终止继承。 |
| 整页同时有页头、内容与页尾 | 在真正页根使用 `StyleWorkspaceContentFrame`；嵌入已有框架时让出角片，不能在中间Tab另造外框。 |
| 父Tab直接连接子Tab | 保留清楚的父子层级和共享方向切换动画，留白只计一次，不把整块内容随标签缩进。 |
| 上方工具/状态区后接结果Tab | 使用 `StyleJoinedResultTabs`：工具区与Tab同底色、局部零间隔连成一组；**此组与下方“表格操作条+表格”相隔6px**。表格与整条Tab栏同宽，左右不再重复内缩。 |

- 结果Tab连体只重组明确相邻的组件，保留详情splitter、比例和其它页脚间隔。专业子页只对齐其外边界，不能清掉专业控件内部布局。
- Tab选择及下划线使用共享 `PageTabMotion`/ADS动画；父级切换带动子栏时按父项位置关系确定方向。遵守系统关闭动画设置，保留图标可读性，不能重复绘静态与动态选中标记。

### 6. 按钮、输入和选择控件

- 工具行使用 `NormalizeToolbarRow`/`ToolbarMetrics`，同排控件等高并对齐；普通动作间距8px，明确的A/B/C分段内部紧贴。文字按钮按内容适配宽度，只有真实图标动作锁为方形。
- 焦点提示必须区分输入来源：鼠标点击或切换Tab时不显示键盘焦点矩形；Tab键、方向键等键盘导航仍保留可辨焦点与原有快捷操作。该行为由共享组件实现，不通过禁用键盘焦点规避。
- 普通动作使用共享中性实底，主动作使用强调色，危险动作用危险语义。文字链接/轻导航按其明确角色处理；刷新时不能重写旧局部QSS，导致底色丢失或共享状态失效。
- 图标动作使用真实主题SVG/QIcon和可理解的悬停释义；复杂或易误解操作保留文字。禁用动作须有可理解的状态/依赖说明，不能只留一个看不清的空按钮。
- 普通独立输入与下拉框由标准主题自动接入；需要搜索语义或明确工具行尺寸时使用 `StyleSearchField`、`StyleStandaloneInput` 等角色入口。已有显式绑定继续拥有自身角色；组合框/数值框内部QLineEdit、表格单元格编辑器和专业视口不按独立控件重复接入。
- 所有同类下拉Popup统一底色、文字、箭头、状态及共享展开动画，不能只覆盖部分页面。保持原选项、滚轮规则和键盘操作，不为动画提前创建全部隐藏Popup。
- A/B/C、主题模式、搜索范围等离散选项使用共享 `SegmentedControl`，独立分段组必须有可辨底板；连续数值使用 `ThemedSlider` 等共享滑块，保留轨道、滑块、数值及单位，禁用态仍能读出值。

### 7. 表格、详情和数据语义

- **逐张表显式选择 Full/Compact/None 操作条。** 需要现场快照比较的表保留完整操作；静态结果按用途精简；属性、选择器或已有业务操作区隐藏重复控件。不能以全局开关或批量替换代替逐表判断。
- 列多时使用互补的A/B，必要时A/B/C精简列组；保留表头右键逐列选择，自定义后分段不假装仍匹配预设。不能把B做成A加所有扩展列。
- 快照对比复用源表操作条，避免第二套复制/导出/冻结宿主；按钮可用性根据真实数据和模式更新。复制全部、导出范围、排序、筛选、选择及模型身份在视觉重排后保持正确。
- 字段详情只保留一个规范文档源；搜索、复制和导出使用同一份完整数据。卡片投影不得另造过期副本或在后台继续维护已淘汰的隐藏字段树。
- 点击图表快照保持原X轴位置，只暂停该历史视窗的自动推进；用户明确恢复实时后再跟随最新数据，不能自动把选中点居中。

### 8. 自适应、交互与运行性能

- 窄窗、缩放和长中文/英文文本下，参数/设置栏必须通过换行、改列或内部滚动适配，不能靠水平滚动或隐藏横向滚动条掩盖溢出。数据表、HEX等确需横向内容的专业视口保留横向滚动。
- 每个内容区只有明确的滚动责任；标题/动作区按用途固定，避免外层滚动再包专业视口。滚轮是否调整数值/切Tab遵守全局选项，键盘焦点、Tab遍历及原有快捷操作保持可用。
- 首次显示、惰性页打开和切换主题必须通过共享准备入口在首帧前完成当前可见分支的主题/布局；不能先闪旧样式，再补底色、侧栏宽度和角片。
- UI线程不执行耗时查询/全模型重建；使用共享异步、进度与取消机制。颜色、字体或窗口大小变化不得重做业务枚举，重复状态更新不得无变化重写QSS或重建图标。
- 隐藏页可延后绘制，但不得误停承担采样/归档的业务。动画按屏幕刷新率和经过时间推进，静止时停止，保留系统动画开关；声明“120Hz流畅”必须有实际测量，不能以定时器间隔代替证据。
- 新增通用观察器只监听明确宿主并合并更新，保留销毁/换页保护；不得为视觉效果逐帧扫描全页、截图整个内容区或循环polish整树。

### 9. 必须完成的交付核对

对每个新增/修改页面及所有共享改动影响的页面类型，提交前必须给出可核对结果：

1. 列出真实导航入口、页面类型、共享组件和适用例外；惰性/动态工厂也要覆盖，不能只数helper调用次数。
2. 核对底色层级、文字/图标各状态、输入底色、控件尺寸、标签对齐、分区密度、四边留白、外圆适用性和Tab关系。
3. 核对表格操作条模式、列组、复制/导出、详情来源、快照语义，以及窄窗、DPI/字体缩放、长文本、深浅主题、背景模式与首帧表现。
4. 代码变更完成适用构建与语言包/主题门禁；新增用户文本同步zh-CN/en-US，新增源码登记工程。纯规范文档修改校验文档、路径和差异，不为此构建产品或运行业务。
5. 可编译环境下使用真实主程序验证UI；只有主程序无法正常编译时才使用伪窗口/离屏替代，并说明边界。用户明确自行测试时停止自动UI测试，完成已授权构建并列出待用户查看项。
6. 分别报告源码核对、构建和实际GUI验证结果。编译成功不能宣称全部页面视觉合规；存在未解决的规范项时不得宣称任务全部完成。当前任务的用户授权决定是否执行运行验收、提交或推送。

## 发行版制作流程

本流程用于在仓库根目录 `C:\Users\Felix\CLionProjects\KSword` 生成包含完整 `Release\` 目录的 7z 发行包。默认参考旧包布局：`C:\Users\Felix\Downloads\KswordARK评估版本-260427-未签名R0-进程内存监控增强.7z`。

### 1. Release 构建

构建宿主统一使用 64 位 MSBuild、编译器与链接器。优先使用仓库随附依赖 `.deps\Qt\6.9.3\msvc2022_64` 与 `.deps\QtVsTools\msbuild`，MSBuild 使用 `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe`。若该套不可用，再回退到 `D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe` 和 `D:\Software\Qt\6.9.3\msvc2022_64`。没有 64 位 MSBuild 时停止，不得降级到 32 位入口。所有构建命令同时传入 `/p:PreferredToolArchitecture=x64`、`/p:PROCESSOR_ARCHITECTURE=AMD64` 和 `/p:PROCESSOR_ARCHITEW6432=AMD64`；MSVC 导入规则将工具偏好当作局部属性，只传工具偏好仍可能被覆盖为 x86。主程序构建检查使用仓库脚本 `tools/Invoke-KSwordBuildCheck.ps1`，它在构建前读回并检查 HostX64 路径。

先设置 Qt 路径和 QtMsBuild 路径，再依次构建用户态项目。主程序必须重新构建；Taskbar、KswordHUD、APIMonitor_x64 也要构建后覆盖进包。

```powershell
$msbuild='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path $msbuild)) { $msbuild='D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (!(Test-Path $msbuild)) { throw '64-bit MSBuild is required.' }
$env:KSWORD_QT_DIR=(Resolve-Path '.deps\Qt\6.9.3\msvc2022_64' -ErrorAction SilentlyContinue).Path
if (!$env:KSWORD_QT_DIR) { $env:KSWORD_QT_DIR='D:\Software\Qt\6.9.3\msvc2022_64' }
$qtMsBuild=(Resolve-Path '.deps\QtVsTools\msbuild').Path

$hostToolArgs=@('/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
& $msbuild 'Ksword5.1\Ksword5.1\Ksword5.1.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostToolArgs /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'Launcher\Launcher.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostToolArgs /m:1 /v:minimal
& $msbuild 'Taskbar\Taskbar.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostToolArgs /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'KswordHUD\KswordHUD.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostToolArgs /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'APIMonitor_x64\APIMonitor_x64.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostToolArgs /m:1 /v:minimal
```

#### 主程序 `LNK1000` / `IMAGE::BuildImage` 恢复

如果主程序的 MSVC 链接日志包含 `LNK1000`、`IMAGE::BuildImage` 或 `.iobj`，保持上述 64 位 MSVC 工具链，不要改用 LLVM、替代 TargetName，也不要自动升级或降级 MSVC。先且仅执行一次干净重建，并仅对这次构建禁用 Whole Program Optimization：

```powershell
& tools\Invoke-KSwordBuildCheck.ps1 `
  -RepositoryRoot (Get-Location).Path `
  -Action Rebuild `
  -DisableWholeProgramOptimization
```

该兼容开关只在本次构建使用的临时 props 中关闭 WPO/LTCG，不改动工程文件。成功必须同时满足 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，且 `Ksword5.1\x64\Release\Ksword5.1.exe` 非零；随后不要为了“复查”立刻再跑普通 Build（WPO 禁用会使常规增量缓存失效），需要时只用 `-VerifyArtifactOnly`。只有该恢复路径也复现失败后，才考虑安装 VS servicing update 或并列 v143 工具集。

#### 驱动 WDK x64 `ApiValidator` 后置校验

驱动仍由标准 MSVC/WDK 构建。若 `KswordARK.sys` 已在链接阶段更新、但 WDK 后置阶段因错误选择 ARM64 `ApiValidator`/`aitstatic` 或无子进程的静默卡住，不得把被中止的 `/t:Build` 说成整体成功：先确认实际报错发生在链接之后，记录精确 MSBuild PID/命令行，并确认没有活跃的 `cl.exe`、`link.exe` 或验证器子进程，才可以停止该**唯一**卡住的 MSBuild。

随后以 x64 验证器单独校验刚链接的 `.sys`：

```powershell
$solutionDir=(Resolve-Path 'Ksword5.1').Path + '\'
$apiValidatorX64='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild 'KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir `
  /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

`Driver is 'Universal'.` 是该独立验证的通过标志。它只证明已链接驱动的 API/体系结构合规，不替代完整 Build、INF/CAT、签名或实际加载验证；这些状态必须单独报告。`10.0.26100.0` 应替换为本机已安装的 WDK 版本。若链接前已经失败，修复原始编译/链接错误，而不是使用此后置校验路径。

驱动项目依赖 WDK。如果当前机器无法构建驱动，不要阻塞发行包制作；沿用统一 Release 目录中的已有未签名 R0 产物：`Ksword5.1\x64\Release\KswordARK.sys`、`Ksword5.1\x64\Release\KswordARK.pdb`、`Ksword5.1\x64\Release\KswordARKDriver.inf`。

### 2. 搭建发行目录

推荐从参考包提取完整 Qt 依赖与插件目录，再覆盖最新构建产物。这样能保持 `platforms`、`styles`、`imageformats`、`iconengines`、`generic`、`networkinformation`、`tls`、`translations`、`qtadvanceddocking.dll` 等布局一致。

```powershell
$ref='C:\Users\Felix\Downloads\KswordARK评估版本-260427-未签名R0-进程内存监控增强.7z'
$stageRoot=Join-Path (Get-Location) 'dist\KswordARK-release-work'
$stage=Join-Path $stageRoot 'Release'

if (Test-Path $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
New-Item -ItemType Directory -Path $stageRoot | Out-Null
tar -xf $ref -C $stageRoot

Copy-Item 'Ksword5.1\x64\Release\Ksword5.1.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\Launcher.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARKLight.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\Taskbar.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordHUD.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\APIMonitor_x64.dll' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordDwmZOrder.dll' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\APIMonitor_x64.pdb' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARK.sys' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARK.pdb' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARKDriver.inf' $stage -Force
$styleDir=Join-Path $stage 'Style'
New-Item -ItemType Directory -Path $styleDir -Force | Out-Null
Copy-Item 'Ksword5.1\x64\Release\Style\StartupLandscape.png' $styleDir -Force
Copy-Item 'Ksword5.1\x64\Release\Style\StartupWindows.png' $styleDir -Force
Copy-Item 'Ksword5.1\x64\Release\Style\KswordLogo.png' $styleDir -Force
Copy-Item 'LICENSE' (Join-Path $stage 'LICENSE') -Force
Copy-Item 'COMMUNITY_COVENANT.md' (Join-Path $stage 'COMMUNITY_COVENANT.md') -Force

$licenseDir=Join-Path $stage 'licenses\third_party'
New-Item -ItemType Directory -Path $licenseDir -Force | Out-Null
Copy-Item 'third_party\systeminformer_dyn\LICENSE.txt' (Join-Path $licenseDir 'systeminformer-LICENSE.txt') -Force
Copy-Item 'third_party\systeminformer_dyn\NOTICE.md' (Join-Path $licenseDir 'systeminformer-NOTICE.md') -Force
Copy-Item 'third_party\easy_hwid_spoofer\LICENSE.txt' (Join-Path $licenseDir 'easy-hwid-spoofer-LICENSE.txt') -Force
Copy-Item 'third_party\easy_hwid_spoofer\NOTICE.md' (Join-Path $licenseDir 'easy-hwid-spoofer-NOTICE.md') -Force
Copy-Item 'third_party\fltk\LICENSE.txt' (Join-Path $licenseDir 'fltk-LICENSE.txt') -Force
Copy-Item 'third_party\qt_advanced_docking_system\LICENSE.txt' (Join-Path $licenseDir 'qt-advanced-docking-system-LICENSE.txt') -Force
Copy-Item 'third_party\zstd\LICENSE.txt' (Join-Path $licenseDir 'zstd-LICENSE.txt') -Force

$profileDir=Join-Path $stage 'profiles'
if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir | Out-Null }
Copy-Item 'Ksword5.1\x64\Release\profiles\ark_dyndata_pack_v4.json.qz' $profileDir -Force
Copy-Item 'Ksword5.1\x64\Release\profiles\launcher_support_manifest.json' $profileDir -Force
Copy-Item 'Ksword5.1\x64\Release\profiles\registry_optimization_items.json' $profileDir -Force
Copy-Item 'Ksword5.1\x64\Release\profiles\registry_optimization_assets' $profileDir -Recurse -Force

$languageDir=Join-Path $stage 'languages'
if (Test-Path $languageDir) { Remove-Item -LiteralPath $languageDir -Recurse -Force }
Copy-Item 'Ksword5.1\x64\Release\languages' $stage -Recurse -Force

$driverDir=Join-Path $stage 'KswordARKDriver'
if (!(Test-Path $driverDir)) { New-Item -ItemType Directory -Path $driverDir | Out-Null }
Copy-Item 'Ksword5.1\x64\Release\KswordARK.sys' $driverDir -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARKDriver.inf' $driverDir -Force
```

### 3. 生成 7z 包

本机可能没有 `7z.exe` 在 PATH 中；已验证可用工具路径：`C:\Users\Felix\CLionProjects\Wisdom-Weasel\7z.exe`。压缩包建议放在 `dist\` 下，文件名带日期和本次功能描述。

```powershell
$seven='C:\Users\Felix\CLionProjects\Wisdom-Weasel\7z.exe'
$date=Get-Date -Format 'yyMMdd'
$archive=Join-Path (Get-Location) ("dist\KswordARK评估版本-$date-未签名R0-功能描述.7z")

if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
Push-Location 'dist\KswordARK-release-work'
& $seven a -t7z -mx=9 -mmt=on $archive 'Release'
$exit=$LASTEXITCODE
Pop-Location
if ($exit -ne 0) { exit $exit }
```

### 4. 校验发行包

生成后必须测试压缩包完整性，并列出关键文件确认最新 exe/dll/sys 已进入 `Release\`。

```powershell
$seven='C:\Users\Felix\CLionProjects\Wisdom-Weasel\7z.exe'
& $seven t $archive
& $seven l $archive 'Release\Launcher.exe' 'Release\Ksword5.1.exe' 'Release\KswordARKLight.exe' 'Release\Taskbar.exe' 'Release\KswordHUD.exe' 'Release\APIMonitor_x64.dll' 'Release\KswordARK.sys' 'Release\KswordARKDriver\KswordARK.sys' 'Release\Style\StartupLandscape.png' 'Release\Style\StartupWindows.png' 'Release\Style\KswordLogo.png' 'Release\LICENSE' 'Release\COMMUNITY_COVENANT.md' 'Release\licenses\third_party\systeminformer-LICENSE.txt' 'Release\licenses\third_party\easy-hwid-spoofer-LICENSE.txt' 'Release\licenses\third_party\fltk-LICENSE.txt' 'Release\licenses\third_party\qt-advanced-docking-system-LICENSE.txt' 'Release\licenses\third_party\zstd-LICENSE.txt' 'Release\profiles\launcher_support_manifest.json' 'Release\profiles\ark_dyndata_pack_v4.json.qz' 'Release\profiles\registry_optimization_items.json.qz' 'Release\profiles\registry_optimization_assets\Config\Data.zip' 'Release\languages\zh-CN.json' 'Release\languages\en-US.json' 'Release\platforms\qwindows.dll'
```

校验通过时，`7z t` 输出应包含 `Everything is Ok`；另需确认主程序项目引用生成的 `Release\KswordDwmZOrder.dll` 已入包，窗口 DWM 排序功能从 exe 同目录加载该 DLL。主程序顶部“许可证”页面从 exe 同目录读取根 `LICENSE`。本流程生成的包根目录必须是 `Release\`，不要把 `dist\KswordARK-release-work\` 或其它临时目录打进包里。

## Launcher 用户报告接入

收到解压后的 Launcher 报告目录时，先只读校验，确认 `valid=true` 后再写入语料库：

```powershell
py -3.12 tools\pdb_offset_generator\launcher_report_intake.py $reportDir
py -3.12 tools\pdb_offset_generator\launcher_report_intake.py $reportDir --corpus-root $corpusRoot --commit
```

工具会校验 SHA256 和 PE/RSDS 身份、下载精确 PDB，并生成 NTOS/NTKRLA57 偏移配置；collection-only 模块只保存 PE/PDB。Wine、非 amd64、无 RSDS 或校验和不匹配的报告不得进入正式矩阵。

导入后运行 `ksword_profile_release_sync.py` 重新生成唯一发布矩阵 `ark_dyndata_pack_v4.json`，再运行 `Launcher/tools/generate_support_manifest.py` 更新支持清单。最后确认新 PDB GUID/Age 在清单中唯一且 `complete=true`，并构建 Launcher Release。重复导入应显示 `existing`。


## Phase -1 协作规范

- 仓库相对根目录为 `H:/Project/Ksword5.1`；文档与规则使用相对路径，不写个人机器路径作为开发落点。
- R0/R3 协议只在 `shared/driver/` 定义。
- 驱动 IOCTL 分发只通过 `KswordARKDriver/src/dispatch/ioctl_registry.c` 注册 handler，`ioctl_dispatch.c` 不再承载业务 switch。
- 用户态 KswordARK 设备访问只通过 `Ksword5.1/Ksword5.1/ArkDriverClient/`，Dock UI 不直接调用 KswordARK `DeviceIoControl`。
- `KswordCLI` 每新增、删除或调整一个命令/别名/参数时，必须同步更新 `KswordCLI` 内置 `help` 命令元数据，并同步更新 `docs/CLI使用文档.md`。
- 新增源码必须同步更新对应 `.vcxproj` 和 `.vcxproj.filters`。
- 语言包（`languages/*.json`）只能定点编辑；禁止用脚本 `json.load`/`json.dump` 整体重写，那会重排键序与缩进并产生数万行无意义 diff。
- 第三方代码接入必须保留原有许可证文本。
- 新增、删除或修改主程序用户可见文本时，必须同步 `Ksword5.1/Ksword5.1/languages/zh-CN.json` 与 `Ksword5.1/Ksword5.1/languages/en-US.json`，并通过 `python tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json`。
