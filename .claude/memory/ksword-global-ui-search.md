# KSword 标题栏全局搜索 / 双模式输入

主程序标题栏中间输入框是“搜索 / CMD”双模式（默认搜索），实现分三层：

- `Framework/CustomTitleBar`：输入组 `ksTitleInputGroup`（QToolButton 模式按钮 + QLineEdit 一体外观）。
  模式按钮 InstantPopup 菜单切换；搜索模式发 `searchTextEdited`，CMD 模式回车发 `commandSubmitted`
  （cmd /K 新控制台，MainWindow::executeCommandInNewConsole）。模式切换发 `inputModeChanged`。
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
命中仍展示在搜索结果弹层中；搜索过程不修改表格原有行可见状态。

可揭示性判定：向上遍历到 CDockWidget，途中显式隐藏且父不是 QStackedWidget 的控件视为不可揭示（不收录）。
非当前 Tab 页被 QStackedWidget 显式 hide 属于导航性隐藏，必须放行，否则搜不到其他页签内容。

## i18n 审计的隐藏约定（tools/i18n_language_pack.py audit）

- setObjectName 的 `ksXxxYyy` 标识符、`#include "无路径分隔的头文件名.h"` 都会被提取，
  必须在两个语言包 source_translations 里加“恒等词条”（"ksTitleInputGroup": "ksTitleInputGroup"）。
- 组合文本按整串查词条：按钮文本 "搜索 ▾"/"CMD ▾" 是完整键，不能只登记 "搜索"。
- 审计器会同时提取 C++ 相邻字符串字面量的编译后完整值；拆开的每段都有词条但完整值缺失时，`audit` 必须失败。
- `text/contextText/translated/bind*` 等调用点引用的语义键必须真实存在于两份语言包；审计器会从源码反向校验，不能再依赖中文 fallback 蒙混通过。
- LanguageManager 有运行时全树翻译（app eventFilter 监听 ChildAdded/Show/UpdateRequest 等），
  代码里直接写中文字面量即可，动态 setText/setPlaceholderText 后也会被自动重翻。
- source template 的 `%1` 等捕获值会再做一次源文本翻译，使外层英文模板不会夹带“安全模式”等稳定中文枚举；动态多行报告仍应逐行翻译后再 join，不能对最终整块只调用一次 sourceText。
- 语言包两文件键序逐行对齐（同键同行号），插入词条必须两包同锚点成对插入；
  用“整行内容锚点 + 行插入”脚本定点编辑，禁止 json.load/dump 重写。
