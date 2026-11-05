# KSword 标题栏全局搜索 / 双模式与四节点循环输入

主程序标题栏中间输入框是“搜索 / CMD”双模式（默认搜索），实现分三层：

- 操作心智模型审查后，搜索模式按钮持续显示当前范围（长表名省略并保留完整提示），输入框提示具体用途；范围选项与“仅显示搜索结果”分两行，宿主缩放时单独重新计算弹层尺寸，不重新搜索或重写主题。命中激活前再次核对表格持久索引、模型及业务过滤；失效目标显示原因和重新搜索入口，撤销旧过滤并作废旧搜索代次。当前范围没有可搜索表格与真正无命中分别提示。这些变化只经源码核对和构建，用户禁止窗口自动化后的版本未做GUI验收。

- `Framework/CustomTitleBar`：输入组 `ksTitleInputGroup`（QToolButton 模式按钮 + QLineEdit 一体外观）。
  模式按钮 InstantPopup 菜单切换；搜索模式发 `searchTextEdited`，CMD 模式回车发 `commandSubmitted`
  （cmd /K 新控制台，MainWindow::executeCommandInNewConsole）。模式切换发 `inputModeChanged`。
  顶部输入框的普通 Tab/Shift+Tab 按 Global ↔ CurrentPage ↔ CurrentTable ↔ CMD 四节点循环；
  范围边界由 `requestCommandInputActivation -> activateCommandInput` 切 CMD，CMD 返回搜索仍走
  `requestSearchInputActivation -> activateSearchInput`。复用 `inputModeChanged` 同步搜索/CMD 配置弹层。
  CMD 的 Enter/Esc 透传给 `CommandExecutionPopup`；popup 内字段与 Ctrl/Alt/Meta+Tab 不被四节点逻辑接管。
  返回搜索要同步当前文本，包括空串，否则会恢复 CMD 模式前的旧查询。
- `UI/GlobalUiSearch`（ks::ui::GlobalUiSearchController，Q_OBJECT/QtMoc）：防抖 220ms 后**异步分片**扫描——
  控件树只能在 UI 线程碰，所以按“每个事件循环周期扫一个 Dock”切片（singleShot(0) 链），
  分片间让出事件循环保持 UI 响应；`m_searchGeneration` 代数自增实现取消（新输入/Esc/切模式/收起弹层
  都会作废在途分片）。扫描中弹层显示进度行（ksGlobalUiSearchProgressRow：QLabel“正在搜索：%1（%2/%3）”
  + 6px QProgressBar，chunk 用 PrimaryAccent），完成后 stable_sort 命中并切回结果列表。
  索引 QLabel/按钮/GroupBox 标题/QTabWidget 页签/下拉项/占位符/表头和表格可见列单元格。
  进度模板文本用 ks::i18n::sourceText 先翻模板再 .arg 拼接（整串运行时组合查不到词条）。
  结果弹层是 MainWindow 子控件（非顶层窗口，避免无边框窗口焦点问题），每条显示“匹配文本 + 页面路径
  （Dock › 内部页签 › 分组框，› 分隔）”。激活结果：ensureDockContentInitialized → withTemporaryNonTopMost
  raise → 逐层 QTabWidget/QStackedWidget setCurrent + QScrollArea ensureWidgetVisible → 140ms 后
  SearchHitFlashOverlay（目标控件子 overlay，主题强调色脉冲 3 次自毁）。
- MainWindow：`initGlobalUiSearchController`（initCustomTitleBar 末尾）注入 dock 列表
  （collectSearchableDockWidgets：18 主 Dock + 日志/监视/任务辅助 Dock）与激活回调
  （activateDockForSearchNavigation：isClosed 先 toggleView(true) 再 raise）。

通用表格搜索入口只保留图标按钮；空间足够时显示，点击后切换到“当前表格”范围并激活标题栏搜索框。
命中仍展示在搜索结果弹层中；默认不改变行可见状态。开启“仅显示搜索结果”后会附加通用行过滤，切离搜索、清空查询或撤销过滤时恢复此前的隐藏行快照，不能把原本隐藏的行一并显示。

可揭示性判定：向上遍历到 CDockWidget，途中显式隐藏且父不是 QStackedWidget 的控件视为不可揭示（不收录）。
非当前 Tab 页被 QStackedWidget 显式 hide 属于导航性隐藏，必须放行，否则搜不到其他页签内容。

## i18n 审计的隐藏约定（tools/i18n_language_pack.py audit）

- setObjectName 的 `ksXxxYyy` 标识符、`#include "无路径分隔的头文件名.h"` 都会被提取，
  必须在两个语言包 source_translations 里加“恒等词条”（"ksTitleInputGroup": "ksTitleInputGroup"）。
- 组合文本按整串查词条：按钮文本 "搜索 ▾"/"CMD ▾" 是完整键，不能只登记 "搜索"。
- 审计器会同时提取 C++ 相邻字符串字面量的编译后完整值；拆开的每段都有词条但完整值缺失时，`audit` 必须失败。
- `text/contextText/translated/bind*` 等调用点引用的语义键必须真实存在于两份语言包；审计器会从源码反向校验，不能再依赖中文 fallback 蒙混通过。
- LanguageManager 的非中文兼容翻译按实际对象接入：普通 UpdateRequest/LayoutRequest 不再调度子树；Paint/help 与普通 Show 只处理接收对象及明确所属控件。Qt 6.9.3 的 `show_helper/showChildren` 向可见子控件先分别发送 Show，再发父 Show，不能在每个 Show 重扫其后代。QAction 没有 Show，须在暴露它的 QWidget 首显时补处理实际 actions，并保留其 managed/preserve 边界。
- 动态 setText/setPlaceholderText 仍经绘制前兼容翻译；模型保留原通知/root 代次。ChildAdded/Polish、显式 dirty 和受管 dirty 的首帧准备仍有效；局部 Paint 不得清掉已排队的子树 dirty。真正换语言前必须用旧语言包完整捕获隐藏控件规范源文，再广播 LanguageChange，不能只为减少遍历删掉此步骤。上述性能改动完成源码/QtCore 检查，实际主程序首帧、菜单与语言组合仍须用户 GUI 验收。
- source template 的 `%1` 等捕获值会再做一次源文本翻译，使外层英文模板不会夹带“安全模式”等稳定中文枚举；动态多行报告仍应逐行翻译后再 join，不能对最终整块只调用一次 sourceText。
- 语言包两文件键序逐行对齐（同键同行号），插入词条必须两包同锚点成对插入；
  用“整行内容锚点 + 行插入”脚本定点编辑，禁止 json.load/dump 重写。

## 四节点循环的实际回归入口（2026-10-04）

`tools/Invoke-SearchHistoryUiTests.ps1` 在既有构建日志目录编译真实 CustomTitleBar、GlobalUiSearch、TableSearchSupport、CommandExecutionPopup 和 LanguageManager，CMD执行请求只接记录槽。当前128条离屏断言覆盖双向四节点、菜单/修饰键/弹层字段Tab、Enter/Esc、真实防抖后过滤快照恢复、空查询和未提交分片的取消；不运行真实命令或驱动。

修饰键Tab按Qt正常焦点顺序移动时，当前表格上下文和名称可合法变化；范围不变应断言popup QTabBar索引，不能冻结包含动态表名的searchScopeDisplayText。切回搜索须同步空字符串，否则旧pending query可能重新启动；取消必须同时停止debounce、增加扫描代数并恢复原隐藏行快照。

## 当前页面搜索的惰性范围（2026-10-21）

- 当前页只搜索实际可见分支，不应为它构造所有隐藏的Memory/Misc子页。NestedDockPreparer传实际UiSearchScope，MainWindow将CurrentPage映射到prepareNavigationPages(true)，只保证当前根及其工作台/调试视图已准备。此路径不置全局prepared，之后全范围搜索仍完整准备全部原分支；Taskbar兼容路由及旧调用默认false。
- 现有DockSearchCursor仍按64节点/4ms目标和完整表格游标恢复，保留当前可见性、字段、索引和查询代次；本步未改匹配/排序/过滤/高亮导航。全范围冷正文仍缺完整值索引，不能据此将searchComplete置true或关闭GN-009/FP-003。
- 133项QtCore检查抽取真实Memory/Misc/MainWindow方法、原MainWindow搜索lambda与冻结旧路径；验证全范围调用等价、当前页0个无关工厂及构造中销毁/换页保护。实际产品GUI、语言/主题与可见正文仍由用户验收；未运行窗口、业务或驱动。

- 2026-10-21 全范围搜索的Memory/Misc嵌套准备按既有工厂逐次推进，返回未完成时由原搜索generation排下一轮；取消停止后续构造，已完成游标可续用。当前页保持所选分支；真实目标激活和Taskbar兼容fallback仍请求完整准备。每页内部构造仍原子、冷正文仍需构造，不能据此宣称全文零实例化或整项关闭。

- 2026-10-21 冷搜索的嵌套准备只在每个查询/同一实际内容根首次读取目录、检查正文覆盖及准备Dock根；后续singleStep只推进原嵌套工厂。取消、换范围、新查询清空临时身份，内容根替换重新准备；扫描完成仍读取最新目录，未缓存动态可见/禁用结果。3099项QtCore实际准备块检查及真实GlobalUiSearch TU通过；单页构造/冷正文实例化仍未消除，不能关闭B03。

- 2026-10-21 B03冷正文首个完整生产者为MinidumpDock初始9条。PageSearchBodyText与真实UI共用文案/稳定objectName，挂于真实导航descriptor的coldBodyTexts/coldBodyComplete，不生成伪页面；完整性仅指冷初始状态，已有实例不挂冷值。Misc仅在搜索具备有效schema+真实navigator时跳过该factory，显式完整准备仍补齐；值遍历完成不能置全部UIprepared。DockSearchCursor在原host遍历位置投影正文，保留每Dock24命中预算和原顺序；实际构造清除host标记，结构失效后重扫真实控件。激活走原目标页路由，再按稳定objectName定位真实控件及原高亮。schema中途失效先撤销跳过资格，再按原分片补工厂，防漏正文。其余冷页仍需逐源迁移，不能将整个B03或全DocksearchComplete置true。

- 2026-10-21 ThemeCheck冷源24条（22原文案+2Tab标题）也按真实host位置参与正文扫描；20个实际target复用旧objectName，其余仅增加无视觉身份。已有实例、动态样本、状态及表格仍真实扫描。正文命中属于真实目标，去重时应压掉相同Dock/path/text的目录别名，但保留不同真实目标的同文命中。StripUiSearchMnemonicMarkers从原私有算法移到已有catalog值头，控件与冷值共用；Dock路径归一但不剥助记符，其后真实Tab祖先剥助记符，分组保留原语义；内部Tab的冷path段同样剥助记符。不得为索引改变UI原文字/助记符。禁用签名页冷构造updateStateDisplay→evaluateBlockReason→driverAvailable实际open设备，影响阻断原因和方案摘要；尚无同身份值输入，不能以默认离线/两个互斥文本同时入索引冒充coldBodyComplete。

- 2026-10-22 DSE冷搜索的原始evaluateBlockReason({}, {})通过既有AsyncOperation读取，默认姿态/定位和DriverClient::open的权限/通知保持。PageSearchPreparation以Complete/MorePages/Waiting区分工厂续片与实际值等待；Waiting仅由一次ready回调续作，不用0ms轮询。新搜索只替换弱控制器/generation回调，已完成初态供真实构造消费一次；直接激活在途时取消旧值发布并走原构造查询，允许已有只读open完成，不能覆盖活页。失败/拒绝回退原工厂，Misc析构先close门禁。DSE共享编辑器的标题省略/子项显隐仍依赖实际宽度和字体，所以整页正文保持真实控件扫描；未把17条不完整草稿投入产品，也未标coldBodyComplete。后续真实refresh/show/动作/主题更新继续原权威查询，未改DSE/KSec业务。

- 2026-10-22 StructuredFieldView空初态的搜索占位、两格式项、复制按钮与两表头由coldSearchBody(targetPrefix)复用updateTranslations的同一六条定义；页面显式setSearchTargetPrefix才命名已有四个目标，未接入的实例不改objectName。此接口只代表空初态，不替代非空规范文档/已有真实控件扫描；无新模型、控件、定时器或主题观察器。真实方法与冻结旧翻译方法在原文、实际英文及助记符扰动下162项QtCore/QObject替身对照通过，真实GUI/布局/polish由用户验收。

- 2026-10-22 SystemTime/VirtualLocation冷初态分别25/42条、25/26目标接入真实Misc host。两页UI与冷源共用原文案/键/预设/纯格式化，Virtual复用StructuredFieldView六条；warm页仍扫描实时控件，激活原工厂后清host标记，完整兼容准备仍补齐。系统时间是目录读取时的新鲜墙钟快照，沿原默认1x格式；它不承诺等于独立稍后构造/250ms刷新的时间，且不回填旧搜索时钟到实际页，不缓存/改变系统或R0计时。原构造/show/query/风险确认/修改动作与布局保持。717项实际纯值/原坐标数学/冻结旧格式对照、181项实际prepare/AsyncOperation受控QtCore及60项原业务源码边界通过；真实GUI另验，不据两个新源关闭整个B03。

- 2026-10-22 Compact表格冷正文复用原TableActionBar的复制全表/导出两条文案。显式SetCompactTableSearchTargetPrefix只给已有或后续创建的原按钮命名，不创建操作条；未opt-in表格不改名。Full/Compact/None、原动作、列/快照/导出/主题逻辑保持。69项实际方法QtCore与真实TableInteractionSupport TU通过，GUI仍由用户验收。

- 2026-10-22 SoundSource全局初始页冷正文31条/11真实目标：原8控件文案、21全部表头和共享Compact两动作，顺序与原QObject遍历一致；表头包括初始A组隐藏列。Misc完整冷正文生产者4→5/20，搜索才跳过未构造声音页；已有实例、当前页、真正激活及完整兼容准备仍走原工厂，构造清host标记。原Core Audio/R0采样、历史、列预设/自定义、复制导出、状态/主题/布局与show触发完全保持。381值检查、175实际准备检查、30源码保持及两实际TU通过；未执行GUI/音频/驱动，未关闭整批B03。

- 2026-10-22 CodeEditorWidget仅保留原空的更多菜单，23个QAction和语法子菜单延至首次aboutToShow；顺序/动作/只读导出/当前语言及原按钮状态保持。父菜单本轮新连接不会接到当前发射，工具动作创建后显式执行原首次show状态更新；语法子菜单仍用自己首次show更新。空白显示QAction仍提前存在，State.cpp保存/恢复不需展开菜单。17521项实际方法/冻结旧动作代码+真实QtCore QObject信号对照通过，真实TU通过；没有运行QWidget/菜单GUI，实际首开位置/主题/键盘仍交用户。此步减少冷页构造开销，不等于已完成CodeEditor冷正文或整个B03。

- 2026-10-22 ClipboardGuard未激活初态28条/12真实目标：策略控件5条、规则表7表头、事件标题/A/B3条、事件11表头及Compact2动作。规则表None、事件表Compact不变，隐藏列照原完整索引；无初始数据行。Misc完整冷正文5→6/20，冷搜索不创建Runtime/UI；激活沿原notifyPageActivated加载/扫描，已存在页仍真实扫描。构造、规则/注入/监控/会话/管道/驱动/列组/布局主题源码不变；345实际值、173实际prepare/AsyncOperation、42静态保持及2真实TU通过，未执行剪贴板/GUI/native业务。

- 2026-10-22 DesktopDrawing冷正文使用原PhysicalPixels/EnumDisplayMonitors只读枚举的实际值，经既有AsyncOperation一次完成回调续作；无空转轮询、UI/native过滤器/绘制器创建。20+N条、17目标（空或超60项按原combo规则），空结果沿原DisplayChanged，失败/拒绝沿原工厂。真实激活取消晚到发布、清cold标记并保留原新鲜refreshDisplays；兼容完整准备仍构造页面。Misc完整源6→7/20。225项实际prepare/activation+真实AsyncOperation受控QtCore及882项实际值与冻结旧双语来源对照通过；显示器原生查询和GUI未运行，后续由用户手测。

- 2026-10-22 BugcheckGuard未显示初态11条/11目标共享原key/source：风险说明、控制分组/选项、固定动作、状态标题及原waiting文案。原构造不查询R0，Show查询、所有开关/截图/驱动函数保持。Misc未构造页冷源7→8/20，目录仍服从原实验入口visible；真正激活清标记并执行原Show。51项静态检查证明10条既有bind文本/两语言key和14个非布局方法保持；未运行GUI或危险业务，不能关闭整个B03。

- 2026-10-22 ContextMenuCleaner冷页的原IE查询结果在隐藏时只存pendingSnapshot，不会填表；此前把它视作冷正文必须等待真实行的阻塞不准确。现将只读首查移至真实首显一次（已有query/hasLoaded保护），随后保留原分类切换、查询/投影、备份/删除/恢复/测量链。七类确定空初态从同源文案提供123条，Right详情方案165条；其它三方案的显式隐藏字段仍不入索引。Misc冷源8→9/20，真实激活原查询，兼容准备和warm页仍扫描真实内容。4343项纯值/首显QObject替身、269项实际prepare/AsyncOperation受控检查及完整业务尾部保持通过，GUI/native未运行；不关闭整个B03。

- 2026-10-22 DWM/Win32k注入页冷初态15+N条正文复用原EnumWindows/Capture真实快照（>60项按旧Combo扫描规则跳过，枚举失败沿原三段状态）。只读取Win32窗口/进程身份，未触发DWM、R0或输入控制；原Refresh worker复用相同枚举，Control、AgentPanel Start、Injection Select保持。Misc既有AsyncOperation后台读一次/完成续作，不轮询；共享不可变值回GUI无整表复制，激活取消晚到发布并走原新鲜工厂查询，不给动作回填旧HWND身份。Misc冷源9→10/20。4343纯值/首显与269实际prepare/AsyncOperation受控检查通过；native及GUI未运行，业务/性能仍待用户验收。

- 2026-10-22 Memory首个完整冷正文接入PTE / VA翻译：原7控件文案与12表头同源，Compact两动作；默认/Embedded/Floating共21条10目标，Right加共享字段6条为27条14目标。全范围useColdBodies仅跳过未建PTE，真正激活、当前页及默认完整兼容仍用原工厂；冷遍历完成不冒充所有UI已建，兼容请求重置游标补齐。原refresh至文件尾逐字相同，无原生查询/附加/数据语义变化。1109项实际prepare与冻结旧方法QtCore对照、574项实际纯值双语/四详情方案检查通过；没有运行产品GUI/native，不据单页关闭整个B03。

- 2026-10-22 内存搜索冷初态50条/28真实目标与原UI同源：9类型、2范围、8比较项、原参数/固定动作、4表头、Compact两动作和状态；显式隐藏值B不索引，禁用但可揭示输入/动作保留。后端提示读取既有进程级DDMA会话，复用原纯isDdmaUsable及同一提示格式化，不查询native、不改回退索引/颜色/通知。全范围冷准备同时跳过未建search与process_pte；已有实例、当前页、实际激活及兼容完整准备保留原工厂。搜索结果只由已构造页的原扫描流程产生，冷初态不虚构单元格。QtCore实际值1226项、实际准备与冻结旧路径1112项通过；真实页面/主题/语言/高亮由用户手测。其它冷页仍未覆盖，B03不因此关闭。

- 2026-10-22 Memory/Misc的`navigationCatalog(existing, includeColdSearchBody=true)`默认保持完整冷正文，供原全文搜索/注册目录调用；Taskbar目录及两类实际路由权限核对传false，只省掉与导航无关的正文生产。MainWindow复用同一寿命/准入/已有根映射及冷Bugcheck门禁，按实际请求分别取值；其余注册provider继续原路径，无新缓存、观察器或队列。冷/暖/嵌入/可见禁用/语言的实际新旧方法QtCore对照及实际MainWindow取值闭包12028项通过；导航ID、父链、标题、searchTexts、顺序和状态保持，false无正文生产，true与旧完整目录相同。此步不把正文省略伪装成searchComplete，不改变旧宽度/省略匹配规则；真实Taskbar/GUI和其它冷正文仍待用户及后续实施。

- 2026-10-22 引导页实际使用CodeTextEdit及None操作条，不依赖CodeEditorWidget宽度；完整冷正文复用初态文本/表头和真实权限判据，保留两处折叠隐藏规则。仅全文搜索且目录/navigator有效时，MiscDock可省略默认引导页及0ms补建；首次真实Show在原主题准备入口补建所选页。普通创建、当前页/实际激活与兼容完整准备保留原流程。冷页命中稳定目标名映射回原控件；不执行BCD枚举或写入。
