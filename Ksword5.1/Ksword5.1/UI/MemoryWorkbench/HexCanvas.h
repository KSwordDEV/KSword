#pragma once

// ============================================================
// HexCanvas.h
// 作用：
// - 自绘、虚拟化的十六进制/ASCII 视图，取代旧 HexEditorWidget 那种"每字节一个表格单元格、
//   每次变更整表重建"的做法。绘制对象数 O(可见行数)，与地址空间大小、选区大小无关。
// - 只负责"显示 + 手势转发"：本类**不读也不写任何目标内存**（不变式 1）。
//   读由外部的页提供者（IHexPageProvider）完成并经 deliverPage 回填；
//   写只落到 MemoryDiffOverlay::Stage 暂存，真正写入由宿主的写事务负责。
//
// ------------------------------------------------------------
// 冻结接口摘要（Phase 3 WP-0 新增；基线喂入器等后续工作包依赖，改签名或语义须同步依赖方）
// ------------------------------------------------------------
// - struct HexCanvas::CachedRangeCopy { std::vector<std::uint8_t> bytes; std::vector<std::uint8_t> validMask; }
//     等长；validMask 1 = 真实读到，0 = 所在页已读完但该字节读不到（此时 bytes 恒为 0）。
// - std::optional<std::vector<std::uint8_t>> copyCachedRange(std::uint64_t firstAddress, std::uint64_t lastAddress) const
//     严格版：闭区间内每个字节都"已缓存且读到了"才返回字节；任一字节未加载/在途/不可读、区间越出地址空间、
//     first > last、区间比缓存容量长，一律整体 nullopt（不补零、不返回一半）。
// - std::optional<CachedRangeCopy> copyCachedRangeWithMask(std::uint64_t firstAddress, std::uint64_t lastAddress) const
//     掩码版：已读完但读不到的字节以 0 + 掩码 0 返回，直接可喂 MemoryDiffOverlay::RefreshBaseline；
//     只有"未落定"（未加载/在途）与非法区间才 nullopt。
//     两者共同点：返回页缓存里的原始值（不叠加暂存补丁）、不刷新 LRU、不发信号、UI 线程调用。
// - std::set<std::uint64_t> settledPageStartsInRange(std::uint64_t firstAddress, std::uint64_t lastAddress) const
//     （Phase 3 WP-J 新增，装配接口文档 §8 缺口 G1）：按页对齐枚举 [firstAddress, lastAddress]
//     覆盖的整页，只返回"已经落定"（缓存里已经有结果，不区分 Valid/部分有效/整页不可读）的页
//     起始地址集合；不含 NotLoaded/Pending 的页。详见"四之三"节与本函数自己的声明处注释。
//
// ------------------------------------------------------------
// 一、模型分工（全部复用 Phase 0 的 Qt-free 类，不重写其逻辑）
// ------------------------------------------------------------
// - ksword::memwb::HexViewport（值成员）：地址空间、行列互转、页缓存、选区、PlanFetch。
// - ksword::memwb::MemoryDiffOverlay（非拥有指针，可为空）：暂存补丁与 ChangeKind。
//   为空时画布是纯只读查看器，只显示页缓存里的字节。
// - 暂存叠加层的"基线"由宿主载入（LoadBaseline/RefreshBaseline）。画布不替宿主载入基线。
//
// ------------------------------------------------------------
// 二、字节的显示规则（绝不伪造数据）
// ------------------------------------------------------------
// - 读到了：两位大写十六进制；ASCII 面板可见字符照画，其余画点号。
// - 未加载 / 在途：十六进制画 "··"、ASCII 画 "·"（U+00B7 中点），用禁用色。
// - 不可读：十六进制画 "??"、ASCII 画 "×"（U+00D7 乘号），用禁用色。
//   ASCII 面板不再用 "?" 表示不可读：那会与真实的 0x3F 字节混淆。中点与乘号都不在可见 ASCII
//   （0x20..0x7E）范围内，所以 ASCII 面板里看到的每个可见字符都一定是真实读到的字节；
//   Consolas 与微软雅黑都有这两个字形（本机已逐一核对）。字符常量在 HexCanvasFormat.h。
// - 有暂存补丁的字节显示补丁值（暂存必然针对读到过的字节，所以一定有值）。
// - 首行开头与末行结尾的"补空位"不画任何东西。
// - 着色优先级：选区 > 通用高亮层（layerId 大者在上）> ChangeKind
//   （Pending 暖色、ExternalChange 冷色、SelfWritten 淡色，Unchanged 无底色）。
//   所有颜色在每次 paintEvent 里现取主题静态颜色，主题切换后无需任何通知。
// - 选区在 Hex 与 ASCII 两个面板同时镜像高亮，活动面板更醒目；当前字节有外框。
//
// ------------------------------------------------------------
// 三、滚动
// ------------------------------------------------------------
// - 竖向滚动条映射"首行行号"。最大首行不超过 2^31-1 时精确映射（滑块值 == 首行行号）；
//   超过时（地址空间大到 2^47 乃至接近 2^64）按比例映射：拖滑块按比例跳转，
//   滚轮、方向键、PgUp/PgDn 仍按精确行数移动，随后把滑块同步到最接近的位置。
// - 每行宽度超过视口时出现横向滚动条（像素滚动）。
// - 视口变化时发 visibleRangeChanged，并用 HexViewport::PlanFetch（前后各预取 2 页）
//   规划需要读取的页，先 MarkInFlight 再交给页提供者。
//
// ------------------------------------------------------------
// 四、页提供者协议
// ------------------------------------------------------------
// - 画布调用 provider->RequestPages(ranges, sourceRevision)，范围已经被登记为在途。
// - 提供者可以同步或异步回填，必须在 UI 线程调用：
//     deliverPage(pageStart, bytes(4096), validMask(4096), sourceRevision)
//     deliverUnreadable(range, sourceRevision)
//   sourceRevision 必须原样带回请求时拿到的值；换目标后旧代次的结果会被 HexViewport 拒收。
// - 提供者放弃某个范围又不想标不可读时，调用 cancelPages(range) 撤销在途登记以便重试。
// - setStaticData(base, data) 装一个内置的按需供页提供者：2 MiB 数据超过页缓存容量，
//   必须按需供页，不能一次性塞满缓存。
//
// ------------------------------------------------------------
// 四之二、数据变化信号 contentChanged()（订阅它，不要轮询）
// ------------------------------------------------------------
// - 凡是"画布上某个地址显示的值可能变了"都会发 contentChanged()，订阅者（解释器面板、宿主状态栏等）
//   据此重读自己关心的字节，不需要定时器轮询。触发点：
//     deliverPage / deliverUnreadable 被接受、setAddressSpace / setStaticData / clearAddressSpace、
//     refresh（换代次清缓存）、setPageProvider（会 refresh）、setOverlay、
//     stageBytes 成功（键盘编辑、粘贴、填充、解释器行内编辑都走它）、Backspace 丢弃暂存、
//     宿主调用 notifyOverlayChanged()。
// - 合并：信号是排队发出的，同一轮事件循环内发生的任意多次变化只发一次（异步供页时一次回填几十页、
//   setStaticData 同步供满可见页，都只产生一个信号）。因此信号发出时变化已经全部落地，
//   但调用返回后、事件循环处理之前读不到信号（测试里要 processEvents 一次）。
// - 信号发出之后若槽里又改了内容，会再排一次，不会丢也不会递归。
// - 它不携带范围：订阅者自己比较关心的字节。不发的情形：选区/插入点/滚动/行宽/分组/高亮层变化
//   （没有改任何地址的值，各有自己的信号或不需要信号）。
// - 宿主若绕过画布直接改了叠加层（AcceptWrite / DiscardAll / LoadBaseline），画布无从知道，
//   请在改完后调用 notifyOverlayChanged()。
//
// ------------------------------------------------------------
// 四之三、页缓存只读导出 copyCachedRange / copyCachedRangeWithMask（Phase 3 WP-0，基线喂入器使用）
// ------------------------------------------------------------
// - 把页缓存里一段闭区间的字节拷出来，让宿主用它装叠加层基线（RefreshBaseline），不必再读一次目标。
// - 严格版 copyCachedRange：区间内每个字节都"已缓存且读到了"才返回，否则整体 nullopt，不补零、不返回一半。
// - 掩码版 copyCachedRangeWithMask：已读完但读不到的字节以"0 + 掩码 0"返回，只有未落定的（未加载/在途）才 nullopt。
// - 两者返回的都是页缓存里的原始值，不叠加暂存补丁；与 cellStateAt 的"所见值"只在有补丁的地址上不同。
// - 都不刷新 LRU、不改状态、不发信号；区间长度上限是缓存容量，更长的直接 nullopt。
//
// ------------------------------------------------------------
// 四之四、页级落定查询 settledPageStartsInRange（Phase 3 WP-J 新增，供基线喂入器使用）
// ------------------------------------------------------------
// - 装配接口文档 §8 缺口 G1：WorkbenchBaselineFeeder 要围绕插入点选"已落定页"组成的连续
//   跨度（ksword::memwb::SelectBaselineSpan/DecideBaselineRefeed），需要一个"某范围内已
//   落定的页起始地址集合"的查询，画布之前没有公开这个粒度（只有逐字节的 cellStateAt /
//   逐字节且要求整段都落定的 copyCachedRange 系列）。
// - "已落定"＝该页已经在缓存里有结果（无论整页是 Valid、部分字节 Unreadable，还是整页被
//   deliverUnreadable 标成不可读），不区分这三种细分状态；不含 NotLoaded（从没请求过）
//   与 Pending（已登记在途，结果还没回来）。
// - 实现上不是"从页对齐起点逐页加页大小枚举到页对齐终点"，而是对"已缓存页列表"
//   （数量恒不超过缓存容量，默认 256）按起始地址是否落在查询区间过滤，两种写法结果
//   等价，但开销只随已缓存页数变化，与查询区间本身多大无关——即使传入整个地址空间
//   也不会逐页遍历到溢出。不刷新 LRU、不改变任何缓存状态，UI 线程调用。
//
// ------------------------------------------------------------
// 五、编辑（setEditable(true) 且 overlay 非空时才生效）
// ------------------------------------------------------------
// - Hex 面板输入十六进制数字：第一个半字节只显示预览（"A_"）不暂存（但先做预检，字节没读到就当场拒绝）；
//   输入第二个半字节才调用 stageBytes(address, {value}) 并自动前进到下一字节。移动插入点、切换面板、
//   Esc 都会取消尚未完成的半字节；Backspace 取消半字节，否则回退一字节并丢弃该字节的暂存。
// - ASCII 面板：可见字符（0x20..0x7E）直接写入当前字节并前进。
// - Ctrl+V：Hex 面板按十六进制文本解析（容忍空格/0x/换行/逗号/花括号，失败整体拒绝），
//   ASCII 面板把剪贴板文本按 UTF-8 字节原样写入，起点为选区起点。
// - 填充 00 / 填充 FF / NOP 填充(0x90) 作用于选区，公开槽 fillSelection(quint8)，不弹对话框。
// - Stage 返回非 Ok 或预检失败时发 editRejected(原因)；成功发 editStaged(address, length)。
// - 只读模式下按键输入一律静默忽略；填充/粘贴这类显式命令发 editRejected("当前为只读视图…")。
//
// 公开的暂存入口 stageBytes(address, bytes, reasonOut)：
// - 键盘编辑（两个半字节 / ASCII 字符）、粘贴、填充、解释器面板的行内编辑全部走这一个入口，
//   宿主要的"暂存成功"信号因此只有画布的 editStaged 一处（面板不再有自己的 editStaged，
//   避免宿主同时连两处导致写事务被触发两次）。宿主自己要暂存（例如汇编、从文件导入）也调它。
// - 检查顺序（与键盘编辑的预检同一套）：只读（未 setEditable 或没有 overlay）-> 空字节 ->
//   64 位溢出 -> 范围是否在地址空间内 -> 每个字节是否"屏幕上看得到值"（读到了，或已有暂存补丁；
//   未加载 / 在途 / 不可读都不行，早退，所以最坏耗时只与页缓存容量成正比）-> overlay->Stage
//   （窗口、基线未读到字节、总量上限由叠加层判定）。
// - 失败：发 editRejected(原因)，把同一原因写进 reasonOut（可传空指针），返回 false，叠加层不变。
//   成功：重绘、排队 contentChanged、发 editStaged(address, length)，返回 true。
//   Stage 对"与现值相同"的写入是空操作，仍算成功（editStaged 照发，宿主的写事务看到空补丁自会跳过）。
// - 与旧行为的差异：填充与粘贴现在也要求目标字节"屏幕上看得到值"（此前只靠叠加层的基线判断）。
//   理由与复制一致：不覆盖从没看到过的数据；代价是跨越已被页缓存淘汰的区域（超过约 1 MiB）时被拒，
//   原因文本会告诉用户"尚未加载"。
//
// ------------------------------------------------------------
// 六、剪贴板与右键菜单
// ------------------------------------------------------------
// - Ctrl+C：Hex 面板复制大写空格分隔的十六进制，ASCII 面板复制文本（不可见字节为点号）；
//   Ctrl+Shift+C 复制另一个面板的格式。复制的是"屏幕上看到的值"（含暂存补丁）；
//   选区内只要有未加载/不可读字节就整体拒绝并发 copyRejected，绝不拿 ?? 或 00 充数。
// - 右键菜单：复制十六进制/ASCII/C 数组/Python bytes/转义字符串/地址、粘贴、三种填充。
//   菜单显式使用不透明主题静态色样式，每项有图标与悬停提示。
// - 右键落在未选中字节上先把选区设为该字节；菜单弹出前发
//   contextMenuAboutToShow(menu, address, hasByte)，宿主可追加书签/补丁等项。
//
// ------------------------------------------------------------
// 七、其它
// ------------------------------------------------------------
// - 所有 UI 线程限定：包括 deliverPage/deliverUnreadable。
// - IME：inputMethodQuery 对 ImHints 返回 ImhNoPredictiveText | ImhPreferLatin | ImhLatinOnly；
//   输入法的预编辑内容被丢弃，仅把提交的拉丁字符当作按键处理。
// - Tab 切换面板（重写 focusNextPrevChild，使 Tab 不再移动焦点）；为避免键盘陷阱，
//   Ctrl+Tab / Ctrl+Shift+Tab 仍把焦点交给后一个/前一个控件。
// - 诊断访问器（cellStateAt/cellRect/cellToolTip/lastPaintedRowCount）供离屏测试使用，不影响行为。
// - 视口坐标命中查询 addressForViewportPos / paneAtViewportPos 是公开接口，供宿主做悬停提示、拖放落点等定位
//   （与鼠标点击、悬停提示用同一个命中函数；空白处不吸附成最近字节）。
// - 图标使用 Ksword5.qrc 里已有的别名（:/Icon/codeeditor_copy.svg、codeeditor_paste.svg 用于复制/粘贴，
//   :/Icon/settings_background_reset.svg 即斜线填充图案用于三种填充）；没有 qrc 时图标为空，不影响功能。
//   填充曾借用循环箭头 codeeditor_replace.svg（语义是刷新/替换），已换掉。更贴切的油漆桶
//   Resource/Icon/editor/paint_line.svg 在主 qrc 里尚无别名，加了别名后只需改 HexCanvas.Menu.cpp 的 fillIcon 常量。
//
// ------------------------------------------------------------
// 七之二、自适应行宽与字号缩放（"内存编辑器太小"反馈的修复）
// ------------------------------------------------------------
// - 根因：内容宽度只取决于（每行字节数、分组、字符宽度、地址位数），与视口宽度无关；
//   固定 16 字节时内容宽度约 600 px，窗口再宽右边也是大片空白，窗口窄了又出横向滚动条。
// - setAutoBytesPerRow(true) 打开"自适应行宽"：每当视口宽度、分组、字体（含缩放）、地址位数变化，
//   用纯函数 hexcanvas_format::ChooseAutoBytesPerRow 在 {64,48,32,16,8} 里选"放得下的最大一档"，
//   一档都放不下退 8（横向滚动条兜底）。判据只用视口宽度（竖向滚动条常驻，不影响它），
//   选择是宽度的确定性纯函数，因此没有"选 n -> 滚动条变化 -> 视口变化 -> 再选 n"的反馈环；
//   m_inAutoFit 只是防重入的保险。不用定时器：跨过阈值才重排，一次拖动最多重排 4 次，
//   定时器只会让布局滞后一帧、闪出横向滚动条。
// - **默认关闭**：HexView 的各个宿主（文件/网络/磁盘/内存编辑器）每次载入数据都显式 setBytesPerRow(16)，
//   默认打开会让它们的行为全变；只有内存工作台在自己的 loadSettings 路径里打开它。
// - 手动 setBytesPerRow(n) 会关闭自适应（手动选择优先）；非法值返回 false 且不改变自适应标志。
// - 改行宽（手动与自动共用 applyBytesPerRow）的锚点：插入点在当前屏幕上完整可见时，以插入点为锚点，
//   让它停在同一屏幕行；否则沿用旧行为——以首行起始地址为锚点。改行宽只改行列映射与布局：
//   选区、半字节预览、高亮层、暂存补丁都按地址存放，页缓存也按绝对地址存放，所以不 refresh()、
//   不换来源代次、不发 contentChanged（HexFindBar 据 contentChanged 取消在途搜索，误发会丢搜索结果）。
// - rowWidthModeChanged(n, automatic)：行宽或模式任一变化就发（首次显示前后可能多发一次，订阅者须幂等）。
// - 字号缩放：setZoomLevel/zoomBy/zoomReset，级别 [-4, +12]，每档 1pt，基准字体取构造时的等宽字体。
//   Ctrl+滚轮（按 120 累计成整档，触摸板的小增量也不会丢）与 Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0 触发，
//   不滚动内容。解释器面板等别的控件用自己的字体，不跟随缩放。缩放走 setFont -> changeEvent(FontChange)，
//   那里会重量度、夹取首行并重新自适应行宽。
// - minimumSizeHint：高度至少表头 + 4 行 + 横向滚动条（宽度沿用基类，绝不抬高，否则宿主窗口会被钉在
//   一个拖不动的宽度上）；sizeHint 不变（HexView 宿主的对话框尺寸依赖它）。
//
// ------------------------------------------------------------
// 八、文件分工、自包含与验证
// ------------------------------------------------------------
// - 组件自包含：不包含 Framework.h，只依赖 Qt Core/Gui/Widgets、theme.h 与 shared/evidence/memory_workbench。
//   主程序接入时需要把下列文件登记进 Ksword5.1.vcxproj 与 .filters（本阶段不登记）：
//     HexCanvas.h（Q_OBJECT，需 moc）  HexCanvas.cpp（数据源/页回填/模式/选区）
//     HexCanvas.Scroll.cpp（滚动与页请求规划）  HexCanvas.Layout.cpp（度量/布局/高亮层）
//     HexCanvas.Paint.cpp（绘制/单元格状态/悬停提示）  HexCanvas.Input.cpp（鼠标/键盘/滚轮/输入法）
//     HexCanvas.Edit.cpp（编辑手势）  HexCanvas.Menu.cpp（复制/右键菜单）
//     HexCanvasFormat.h/.cpp（字节<->文本纯函数）
// - 用户可见中文文案（约 52 条，含 stageBytes 的多字节拒绝原因）与审计要求补恒等词条的头文件名，
//   均已写入语言包，由 tools/i18n_language_pack.py audit 校验。
// - 离屏验证：tools/memwb_ui/build-memwb-ui-tests.cmd（QTest 离屏驱动真实画布，含截图与基准）。
//   本机 MSVC 14.44 不识别 /std:c++23（会静默退回 C++14），构建必须用 /std:c++latest。
// - 数字量级（1200x800、2 MiB 静态数据、offscreen）：首屏 6~15 ms，单帧 3 ms 级，
//   对照旧 QTableWidget 方案 2 MiB 整表重建约 1 s（基准由 tools/memwb_ui 夹具的 --bench 参数产出）。
//   第二轮复测（同机，三次）：首屏中位数 5.8~6.3 ms、100 次滚动+整视口抓图平均 2.57~2.67 ms，与第一轮同量级
//   （第一轮 5.7 / 2.4，机器负载不同，差值在波动范围内；绘制路径没有改动）。
// - 第二轮验证读数：全夹具 2173 条断言 0 失败（第一轮 1889 条一条不少，新增 284 条），MSVC /W4 /WX 零警告。
//   27 个人为缺陷全部被抓到，未变异对照组全绿；画布侧 21 个：contentChanged 不合并 / 同步发 / 回填不发 / 换叠加层不发 /
//   refresh 不发 / 丢弃不发，editableChanged 重复设为可编辑也发，stageBytes 的只读检查、未加载检查、末字节范围检查、
//   editStaged、editRejected、reasonOut 各去掉一项，视口命中的"末行之下"/"行尾右侧"/"补空位"吸附，
//   不可读占位符在绘制路径或状态里改回问号，填充图标改回旧别名，notifyOverlayChanged 误取消半字节，
//   预检不早退（64 MiB 选区实测 1011 ms 对 300 ms 的界线）。
// - 已知限制：ASCII 面板里"不可见字节"仍画点号（与真实的 0x2E 字节同形，这是十六进制编辑器的惯例，
//   本轮只处理了"没有值"的两种状态）；十六进制面板的不可读仍画 "??"（那里只可能出现十六进制数字，没有歧义）。
// ============================================================

#include "../../../../shared/evidence/memory_workbench/HexViewport.h"
#include "../../../../shared/evidence/memory_workbench/MemoryDiffOverlay.h"

#include <QAbstractScrollArea>
#include <QByteArray>
#include <QColor>
#include <QFont>
#include <QPoint>
#include <QRect>
#include <QStaticText>
#include <QString>
#include <QTimer>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

class QContextMenuEvent;
class QHelpEvent;
class QInputMethodEvent;
class QKeyEvent;
class QMenu;
class QMouseEvent;
class QPainter;
class QResizeEvent;
class QWheelEvent;

namespace ks::ui
{
    // HexFetchRange：页提供者收到的一段连续页，类型直接取自 HexViewport。
    using HexFetchRange = ksword::memwb::HexViewport::FetchRange;

    // IHexPageProvider：页提供者接口。画布只依赖它，不关心数据来自文件、字节数组还是进程内存。
    class IHexPageProvider
    {
    public:
        virtual ~IHexPageProvider() = default;

        // RequestPages：请求读取一批页范围。
        // 传入：ranges 已被画布 MarkInFlight 的页范围（按距离由近到远）；
        //       sourceRevision 请求时的来源代次，回填时必须原样带回。
        // 传出：无。实现可同步或异步回填，但必须在 UI 线程调用 deliverPage/deliverUnreadable。
        virtual void RequestPages(
            const std::vector<HexFetchRange>& ranges,
            std::uint64_t sourceRevision) = 0;
    };

    // HexCanvas：自绘虚拟化十六进制视图，详见文件头说明。
    class HexCanvas : public QAbstractScrollArea
    {
        Q_OBJECT

    public:
        // 下面几个别名只是让调用方少写命名空间。
        using AddressRange = ksword::memwb::HexViewport::AddressRange;
        using ActivePane = ksword::memwb::HexViewport::ActivePane;
        using ScrollAlign = ksword::memwb::HexViewport::ScrollAlign;
        using ByteState = ksword::memwb::HexViewport::ByteState;
        using PageResult = ksword::memwb::HexViewport::PageResult;
        using ChangeKind = ksword::memwb::ByteChangeKind;

        // CopyFormat：复制出去的格式。
        enum class CopyFormat : int
        {
            HexText = 0,    // 大写空格分隔的十六进制
            AsciiText,      // 所见即所得的 ASCII 文本
            CArray,         // C 数组初始化列表
            PythonBytes,    // Python bytes 字面量
            EscapedString,  // C 转义字符串
            AddressOnly     // 选区起点地址
        };

        // CellState：单个地址的显示状态，供测试与宿主查询，所见即所绘。
        struct CellState
        {
            bool inSpace = false;                       // 地址是否属于地址空间
            ByteState byteState = ByteState::NotLoaded; // 页缓存里的状态
            bool hasValue = false;                      // 是否有可显示的值（读到了或有暂存补丁）
            std::uint8_t value = 0;                     // 显示值，hasValue 为假时无意义
            ChangeKind change = ChangeKind::Unchanged;  // 变化种类（没有值时恒为 Unchanged）
            bool selected = false;                      // 是否在选区内
            bool isCaret = false;                       // 是否是插入点
            bool highlighted = false;                   // 是否落在某个通用高亮层
            int highlightLayerId = 0;                   // 命中的高亮层号（highlighted 为真时有意义）
            bool nibblePreview = false;                 // 是否正显示半字节预览
            QString hexText;                            // 十六进制面板文字："4A"/"··"/"??"/"A_"
            QChar asciiChar;                            // ASCII 面板字符：可见字符/'.'(不可见字节)/'·'(未加载)/'×'(不可读)
        };

        // 构造：parent 为父控件。默认空地址空间（不画任何字节），只读，每行 16 字节。
        explicit HexCanvas(QWidget* parent = nullptr);

        // 析构：内置静态提供者随之释放。
        ~HexCanvas() override;

        // ---------------- 数据源 ----------------

        // setAddressSpace：设置地址空间闭区间 [firstAddress, lastAddress]。
        // 作用：重建视图、清空缓存并换新的来源代次，选区回到起点，滚动回到顶部。
        // 传出：false 表示区间非法（first > last），此时保持原状。
        bool setAddressSpace(std::uint64_t firstAddress, std::uint64_t lastAddress);

        // clearAddressSpace：回到"无数据"状态，不画任何字节。
        void clearAddressSpace();

        // setPageProvider：设置外部页提供者（非拥有）。传空表示不再请求任何页。
        void setPageProvider(IHexPageProvider* provider);

        // setStaticData：便捷接口，用一块字节数组当数据源。
        // 作用：地址空间设为 [base, base+size-1]，内置提供者按需供页（不会一次塞满缓存）。
        // 传入：起始地址与字节；空数据等价于 clearAddressSpace；base+size 溢出 64 位时按可容纳的部分截断。
        void setStaticData(std::uint64_t base, const QByteArray& content);

        // setOverlay：设置暂存叠加层（非拥有）。传空表示纯只读显示。
        void setOverlay(ksword::memwb::MemoryDiffOverlay* overlay);

        // overlay：当前叠加层指针，可为空。
        ksword::memwb::MemoryDiffOverlay* overlay() const;

        // deliverPage：提供者回填一页。传入页起点、4096 字节数据、4096 字节有效掩码、请求时的代次。
        // 传出：HexViewport 的接收结果；代次不符会被拒收（陈旧异步结果）。只接受 UI 线程调用。
        PageResult deliverPage(
            std::uint64_t pageStart,
            const QByteArray& bytes,
            const QByteArray& validMask,
            std::uint64_t sourceRevision);

        // deliverUnreadable：提供者声明某范围整页不可读。传入范围与请求时的代次；传出接收结果。
        PageResult deliverUnreadable(const HexFetchRange& range, std::uint64_t sourceRevision);

        // cancelPages：撤销某范围的在途登记（提供者放弃读取，允许之后重试）。
        void cancelPages(const HexFetchRange& range);

        // sourceRevision：当前来源代次，提供者在 RequestPages 里也能拿到同一个值。
        std::uint64_t sourceRevision() const;

        // CachedRangeCopy：copyCachedRangeWithMask 的结果，bytes 与 validMask 等长，按地址从低到高排列。
        struct CachedRangeCopy
        {
            std::vector<std::uint8_t> bytes;        // 页缓存里的字节；validMask 为 0 的位置恒为 0（不是真实数据）
            std::vector<std::uint8_t> validMask;    // 1 = 真实读到了；0 = 所在页已读完但这个字节读不到
        };

        // copyCachedRange：把页缓存里 [firstAddress, lastAddress]（闭区间）的字节拷出来，供基线喂入器使用。
        // 传入：闭区间两端（含）。
        // 传出：区间内每个字节都"已缓存且读到了"才返回它们（长度 = last - first + 1）；
        //       只要有一个字节未加载、在途、不可读，或区间不在地址空间内 / first > last / 比缓存容量还长，
        //       就整体返回 nullopt——绝不补零，也不返回一半。
        // 返回的是页缓存里读自目标的原始值，**不叠加暂存补丁**（基线要的是目标的真实内容，补丁叠进去
        // 就把"待写入"和"基线"混为一谈了）；因此对有补丁的地址它与 cellStateAt().value 不同，
        // 其余地址逐字节相同。不刷新 LRU、不改任何状态；只在 UI 线程调用。
        // 耗时与区间长度成正比（逐字节查缓存），上限是缓存容量（默认 1 MiB）。
        std::optional<std::vector<std::uint8_t>> copyCachedRange(
            std::uint64_t firstAddress,
            std::uint64_t lastAddress) const;

        // copyCachedRangeWithMask：copyCachedRange 的"带有效掩码"版本，给 MemoryDiffOverlay 的基线用
        // （它的 LoadBaseline/RefreshBaseline 接受 bytes + validMask，掩码为 0 的字节表示没读到）。
        // 与上一个的唯一区别：**已读完但读不到**的字节（整页不可读，或部分读里没读到的字节）不再让整体失败，
        // 而是以 0 字节 + 掩码 0 返回；仍然返回 nullopt 的只有"还没落定"的情形——未加载、在途、
        // 区间不在地址空间内、first > last、比缓存容量还长。同样不叠加暂存补丁、不刷新 LRU。
        std::optional<CachedRangeCopy> copyCachedRangeWithMask(
            std::uint64_t firstAddress,
            std::uint64_t lastAddress) const;

        // settledPageStartsInRange：按页对齐枚举 [firstAddress, lastAddress]（闭区间，不要求
        // 调用方预先页对齐）覆盖的整页，只返回"已经落定"（缓存里已经有结果：Valid、部分
        // 字节 Unreadable、或整页被标成不可读，三者统称见文件头"四之四"）的页起始地址
        // 集合；不含 NotLoaded（从没请求过）与 Pending（已登记在途、结果还没回来）的页。
        // Phase 3 WP-J 的 WorkbenchBaselineFeeder 用它核对"插入点所在页是否已经落定"，
        // 以及"上次喂过的窗口里有没有页被淘汰出缓存"（装配接口文档 §8 缺口 G1）。
        // 传入：闭区间两端（含）。
        // 传出：命中页的起始地址集合（已页对齐）；下列情形返回空集，不抛异常也不崩溃：
        //       没有地址空间；firstAddress > lastAddress；页对齐后首尾颠倒（防御性校验，
        //       当前页大小 4096 字节整除 2^64，正常输入不会触发，仍保留这道防线，不让
        //       未来改动页大小时在不知情的情况下按反序区间枚举）。
        // 不刷新 LRU、不改变任何缓存状态；实际开销只随"当前已缓存的页数"（上限
        // kMaxCachedPages，默认 256）变化，与查询区间本身有多大无关——传入覆盖整个 64
        // 位地址空间的区间也不会逐页遍历，只在 UI 线程调用。
        std::set<std::uint64_t> settledPageStartsInRange(
            std::uint64_t firstAddress,
            std::uint64_t lastAddress) const;

        // ---------------- 模式与外观 ----------------

        // setEditable：是否允许编辑手势（还需要 overlay 非空）。
        // 值真的变了才发 editableChanged；设为只读会取消未完成的半字节。
        void setEditable(bool editable);

        // isEditable：当前是否允许编辑。
        bool isEditable() const;

        // ---------------- 编辑 ----------------

        // stageBytes：公开的暂存入口（键盘编辑、粘贴、填充、解释器行内编辑与宿主自己的暂存都走这里）。
        // 传入：起始地址、要写入的字节、原因输出（可为空指针）。
        // 传出：true 表示已暂存（已发 editStaged）；false 表示被拒绝（已发 editRejected，reasonOut 是同一原因，
        //       叠加层不变）。检查顺序与"与现值相同也算成功"等细节见文件头"五、编辑"。
        // 只接受 UI 线程调用。本函数只落到 MemoryDiffOverlay::Stage，从不读写目标内存。
        bool stageBytes(std::uint64_t address, const QByteArray& bytes, QString* reasonOut = nullptr);

        // setBytesPerRow：改每行字节数，只接受 8/16/32/48/64；返回 false 表示被拒绝。
        // 作用：插入点在屏幕上完整可见时以插入点为锚点（它停在同一屏幕行），否则以首行首地址所在行为锚点；
        //       选区与缓存不受影响，不重读、不发 contentChanged。
        // 手动选择优先：合法值会同时关闭自适应行宽（isAutoBytesPerRow() 变假）；非法值返回 false，
        // 不改行宽也不改自适应标志。行宽或自适应标志变了会发 rowWidthModeChanged(n, false)。
        bool setBytesPerRow(int bytesPerRow);

        // bytesPerRow：当前每行字节数（自适应模式下是自适应选出的那一档）。
        int bytesPerRow() const;

        // setAutoBytesPerRow：开关"自适应行宽"（默认关，详见文件头"七之二"）。
        // 传入：on 为真时按当前视口宽度立即重选一档并此后随宽度/分组/字体/地址位数自动重选；
        //       为假时停在当前这一档不再自动变（等价于"把自适应结果固定为手动"）。
        // 还没有地址空间时只记下标志，installSpace 时生效。值真的变了会发 rowWidthModeChanged。
        void setAutoBytesPerRow(bool on);

        // isAutoBytesPerRow：是否处于自适应行宽模式。
        bool isAutoBytesPerRow() const;

        // setGroupSize：十六进制列分组，只接受 1/2/4/8；返回 false 表示被拒绝。
        // 自适应模式下分组变化会让每行内容宽度变化，行宽随之重选。
        bool setGroupSize(int groupSize);

        // groupSize：当前分组字节数。
        int groupSize() const;

        // ---------------- 字号缩放 ----------------

        // kMinZoomLevel / kMaxZoomLevel：字号缩放级别的下限与上限（含），0 是默认字号，每档 1pt。
        static constexpr int kMinZoomLevel = -4;
        static constexpr int kMaxZoomLevel = 12;

        // setZoomLevel：设置字号缩放级别，超出 [kMinZoomLevel, kMaxZoomLevel] 的值夹取到边界。
        // 级别真的变了才重建字体（重量度、重建缓存文字、重选自适应行宽）并发 zoomLevelChanged。
        void setZoomLevel(int level);

        // zoomLevel：当前缩放级别。
        int zoomLevel() const;

        // zoomBy：在当前级别上加 delta 档（正数放大、负数缩小），夹取到边界。
        void zoomBy(int delta);

        // zoomReset：恢复默认字号（级别 0）。
        void zoomReset();

        // ---------------- 选区与插入点 ----------------

        // selectedRange：选区闭区间；无数据时为空。
        std::optional<AddressRange> selectedRange() const;

        // caretAddress：插入点地址；无数据时为 0。
        std::uint64_t caretAddress() const;

        // activePane：当前活动面板。
        ActivePane activePane() const;

        // setActivePane：切换活动面板（会取消未完成的半字节）。
        void setActivePane(ActivePane pane);

        // setCaretAddress：设置插入点。extend 为真时锚点不动；ensureVisible 为真时滚动到可见。
        // 传出：true 表示插入点正好落在该地址。
        bool setCaretAddress(std::uint64_t address, bool extend = false, bool ensureVisible = true);

        // selectedBytes：取选区的"所见值"（含暂存补丁）。
        // 传出：false 表示选区过大、含未加载/不可读字节或无选区，reasonOut 给出原因。
        bool selectedBytes(QByteArray* bytesOut, QString* reasonOut) const;

        // selectionText：按格式取选区文本，失败返回空串并在 reasonOut 写原因。
        QString selectionText(CopyFormat format, QString* reasonOut) const;

        // ---------------- 滚动 ----------------

        // scrollToAddress：滚动让地址可见（不改选区）。传出：false 表示地址不在空间内。
        bool scrollToAddress(std::uint64_t address, ScrollAlign align = ScrollAlign::Center);
        // revealCaret：按明确纵向对齐揭示当前插入点，同时保证活动面板的单元格水平可见。
        // 传出：false 表示无地址空间，或同步通知中本画布被销毁；不修改选区。
        bool revealCaret(ScrollAlign align = ScrollAlign::Nearest);
        // visibleAddressRange：实际正在绘制的字节闭区间，供切页后重喂当前视口，
        // 不使用仍停在旧地址的 caret，也不使用子页临时扩展的读取窗口。
        std::optional<AddressRange> visibleAddressRange() const;
        // Other address-backed views use the same cache/read pool without moving the HEX viewport.
        void requestAddressRange(std::uint64_t first, std::uint64_t last);
        void setViewportReadEnabled(bool enabled);
        std::optional<AddressRange> addressSpaceRange() const;

        // firstVisibleRow：当前首行行号。
        std::uint64_t firstVisibleRow() const;

        // setFirstVisibleRow：直接设置首行行号，超过最大首行时夹取。
        void setFirstVisibleRow(std::uint64_t row);

        // visibleRowCount：当前能完整显示的行数（至少为 1）。
        std::uint64_t visibleRowCount() const;

        // ---------------- 通用高亮层 ----------------

        // setHighlightRanges：设置/替换一个高亮层（搜索命中、书签等复用）。
        // 传入：层号（大者在上）、闭区间列表、颜色、悬停提示；区间会被排序合并。
        void setHighlightRanges(
            int layerId,
            const std::vector<AddressRange>& ranges,
            const QColor& color,
            const QString& tip);

        // clearHighlightRanges：按层号清除；层号不存在时什么也不做。
        void clearHighlightRanges(int layerId);

        // clearAllHighlightRanges：清除全部高亮层。
        void clearAllHighlightRanges();

        // ---------------- 诊断与几何查询（供测试与宿主定位） ----------------

        // cellStateAt：查询地址的显示状态（不刷新缓存的 LRU）。
        CellState cellStateAt(std::uint64_t address) const;

        // cellRect：地址在指定面板里的单元格矩形（视口坐标）；不可见或不在空间内返回空矩形。
        QRect cellRect(std::uint64_t address, ActivePane pane) const;

        // cellToolTip：悬停提示文本；地址不在空间内返回空串。
        QString cellToolTip(std::uint64_t address) const;

        // addressForViewportPos：视口坐标命中的真实字节地址，供宿主做悬停提示、拖放落点等定位。
        // 传入：视口坐标（与 QMouseEvent::pos()、QDropEvent::position() 在视口里的坐标同一坐标系；
        //       从画布本身的坐标要先 viewport()->mapFrom(this, pos)）。
        // 传出：命中十六进制或 ASCII 面板里的某个真实字节时返回其地址；命中表头、地址列、
        //       首尾行的补空位、末行之下的空白、越过末列右缘的空白、无数据时返回 nullopt
        //       （不会吸附成最近字节，因为拖放落到空白处不应被当成落在某个字节上）。会考虑横向滚动量。
        //       十六进制单元格之间的空隙与鼠标点击同一规则，归属左边那一格。
        std::optional<std::uint64_t> addressForViewportPos(const QPoint& viewportPos) const;

        // paneAtViewportPos：视口坐标落在哪个面板。
        // 传出：落在数据行的十六进制区返回 Hex，ASCII 区返回 Ascii（含补空位与行尾空白，
        //       这时 addressForViewportPos 为空但面板是明确的）；表头、地址列、末行之下的空白、
        //       无数据返回 nullopt。
        std::optional<ActivePane> paneAtViewportPos(const QPoint& viewportPos) const;

        // lastPaintedRowCount：最近一次绘制实际遍历的行数，用来验证 O(可见行数)。
        std::uint64_t lastPaintedRowCount() const;

        // buildContextMenu：构造右键菜单（含内置项）并发 contextMenuAboutToShow，调用方负责 exec 与释放。
        // 传入：地址、该处是否有字节。传出：新建菜单，父对象为本控件。
        QMenu* buildContextMenu(std::uint64_t address, bool hasByte);

        // copySelection：按格式把选区复制到剪贴板。传出：false 表示被拒绝（已发 copyRejected）。
        bool copySelection(CopyFormat format);

        // sizeHint：按当前每行宽度给出建议尺寸（首选尺寸，不是最小尺寸）。
        QSize sizeHint() const override;

        // minimumSizeHint：宽度沿用基类（两个滚动条的宽度，绝不抬高——否则宿主窗口会被钉在一个拖不动的宽度上），
        // 高度至少"表头 + 4 行 + 横向滚动条"，让画布在被压扁时仍能看到几行数据。
        QSize minimumSizeHint() const override;

        // inputMethodQuery：对 ImHints 返回禁用预测的拉丁输入提示。
        QVariant inputMethodQuery(Qt::InputMethodQuery query) const override;

    public slots:
        // fillSelection：用同一个字节值填充选区（填充 00/FF、NOP 0x90）。不弹对话框。
        void fillSelection(quint8 value);

        // selectAll：全选地址空间。
        void selectAll();

        // copyCurrentPane：复制活动面板格式（Ctrl+C）。
        void copyCurrentPane();

        // copyOtherPane：复制另一个面板的格式（Ctrl+Shift+C）。
        void copyOtherPane();

        // pasteFromClipboard：把剪贴板内容粘贴到选区起点（Ctrl+V）。
        void pasteFromClipboard();

        // refresh：换新的来源代次、清缓存并重新请求可见页（宿主重读目标后调用）。
        void refresh();

        // notifyOverlayChanged：宿主绕过画布直接改了叠加层（AcceptWrite / DiscardAll / LoadBaseline /
        // RefreshBaseline）之后调用：重绘并排队 contentChanged。画布自己的暂存/丢弃已经会发信号，不需要调它。
        void notifyOverlayChanged();

        // autoScrollTick：拖选出视口时的自动滚动一拍（定时器调用，测试也可直接调用）。
        void autoScrollTick();

    signals:
        // caretMoved：插入点地址变化。
        void caretMoved(quint64 address);

        // selectionChanged：选区变化。valid 为假表示无数据。
        void selectionChanged(bool valid, quint64 first, quint64 last);

        // contentChanged：画布上某些地址显示的值可能变了（页回填、换代次、换空间/叠加层、暂存/丢弃）。
        // 排队发出、同一轮事件循环内合并为一次；不携带范围。详见文件头"四之二"。
        void contentChanged();

        // editableChanged：setEditable 让可编辑状态真的变了才发，参数是新状态。
        void editableChanged(bool editable);

        // editStaged：一次编辑已成功暂存（唯一的"暂存成功"信号，所有编辑入口都经 stageBytes 发出）。
        void editStaged(quint64 address, quint64 length);

        // editRejected：编辑被拒绝，reason 是可直接给用户看的原因。
        void editRejected(const QString& reason);

        // editDiscarded：Backspace 回退时丢弃了某字节的暂存补丁。
        void editDiscarded(quint64 address, quint64 length);

        // copyRejected：复制被拒绝（选区过大或含未加载/不可读字节）。
        void copyRejected(const QString& reason);

        // visibleRangeChanged：可见地址范围变化，first/last 为首尾可见字节地址。
        void visibleRangeChanged(quint64 first, quint64 last);

        // rowWidthModeChanged：每行字节数或"自适应/手动"模式任一变化就发。
        // bytesPerRow 是变化后的每行字节数，automatic 为真表示处于自适应模式。
        // 首次显示前后窗口尺寸还没定下来时可能多发一次，订阅者必须幂等。
        void rowWidthModeChanged(int bytesPerRow, bool automatic);

        // zoomLevelChanged：字号缩放级别变化，参数是新级别。
        void zoomLevelChanged(int level);

        // contextMenuAboutToShow：菜单弹出前发出，宿主可追加书签/补丁等项。
        void contextMenuAboutToShow(QMenu* menu, quint64 address, bool hasByte);

    protected:
        void paintEvent(QPaintEvent* event) override;
        void resizeEvent(QResizeEvent* event) override;
        void changeEvent(QEvent* event) override;
        void mousePressEvent(QMouseEvent* event) override;
        void mouseMoveEvent(QMouseEvent* event) override;
        void mouseReleaseEvent(QMouseEvent* event) override;
        void wheelEvent(QWheelEvent* event) override;
        void keyPressEvent(QKeyEvent* event) override;
        void contextMenuEvent(QContextMenuEvent* event) override;
        void inputMethodEvent(QInputMethodEvent* event) override;
        bool viewportEvent(QEvent* event) override;
        bool focusNextPrevChild(bool next) override;
        void focusInEvent(QFocusEvent* event) override;
        void focusOutEvent(QFocusEvent* event) override;

    private:
        // CellCore：绘制用的轻量单元格状态（不含字符串，避免逐格分配）。
        struct CellCore
        {
            bool inSpace = false;                       // 是否在地址空间内
            ByteState state = ByteState::NotLoaded;     // 缓存状态（有暂存补丁时已提升为 Valid）
            bool hasValue = false;                      // 是否有可显示的值
            std::uint8_t value = 0;                     // 显示值
            ChangeKind change = ChangeKind::Unchanged;  // 变化种类
            int layerIndex = -1;                        // 命中的高亮层在快照里的下标，-1 表示无
        };

        // Layout：由字体、行宽、分组决定的横向几何，单位像素（内容坐标，未减去横向滚动量）。
        struct Layout
        {
            int charWidth = 8;                  // 单个等宽字符的宽度
            int rowHeight = 18;                 // 行高
            int ascent = 12;                    // 字体上升高度，文字基线 = 行顶 + 1 + ascent
            int headerHeight = 22;              // 顶部列偏移表头的高度
            int addrDigits = 8;                 // 地址列位数（8 或 16）
            int addrX = 0;                      // 地址列左边界
            int addrWidth = 0;                  // 地址列宽度
            int hexX = 0;                       // 十六进制区左边界
            int hexWidth = 0;                   // 十六进制区宽度
            int asciiX = 0;                     // ASCII 区左边界
            int asciiWidth = 0;                 // ASCII 区宽度
            int contentWidth = 0;               // 内容总宽度
            int cellX[64] = {};                 // 各列十六进制单元格相对 hexX 的左边界
        };

        // HighlightLayer：一个通用高亮层。
        struct HighlightLayer
        {
            std::vector<AddressRange> ranges;   // 已排序合并的闭区间
            QColor color;                       // 调用方给的颜色
            QString tip;                        // 悬停提示
        };

        // Hit：一次鼠标命中测试的结果。
        struct Hit
        {
            bool valid = false;                 // 是否命中了数据行（表头之外且有数据）
            bool exact = false;                 // 命中的是真实字节（补空位吸附过来的为假）
            std::uint64_t address = 0;          // 命中的地址（补空位已吸附到最近有效地址）
            std::uint64_t row = 0;              // 命中的行号
            ActivePane pane = ActivePane::Hex;  // 命中的面板
            bool inGutter = false;              // 是否落在地址列
            bool pastLastRow = false;           // 点位在最后一行之下的空白（row 已夹取到末行；点击选区仍吸附到末行，公开查询视为未命中）
            bool pastRowEnd = false;            // 点位越过本面板最后一列的右缘（地址已吸附到末列；公开的字节查询视为未命中）
        };

        // PaintPalette：一次绘制用到的全部颜色，定义在 HexCanvas.Paint.cpp。
        struct PaintPalette;

        // ---------- HexCanvas.cpp：数据、滚动、布局 ----------
        void rebuildMetrics();
        void recomputeLayout();
        void rebuildStaticTexts();
        void syncScrollBars();
        void onVerticalBarChanged(int value);
        void onHorizontalBarChanged(int value);
        std::uint64_t maxFirstRow() const;
        std::uint64_t fullVisibleRows() const;
        std::uint64_t paintRowCount() const;
        void scrollRowsBy(std::int64_t deltaRows);
        void ensureCaretVisible();
        void requestVisiblePages();
        void notifyVisibleRange();
        bool installSpace(std::uint64_t firstAddress, std::uint64_t lastAddress);

        // applyBytesPerRow：改行宽并按锚点策略（插入点可见取插入点，否则取首行）重排，不动自适应标志、不发信号。
        // 传入：已校验合法的行宽；传出：true 表示行宽真的变了并已重排，false 表示与当前相同（什么都没做）。
        bool applyBytesPerRow(int bytesPerRow);

        // applyAutoBytesPerRow：自适应模式下按视口宽度/字符宽度/分组/地址位数重选行宽（定义在 HexCanvas.Layout.cpp）。
        // 传出：true 表示行宽真的变了（已发 rowWidthModeChanged）；非自适应、无地址空间、视口宽度尚未布局、
        //       正在自适应中（防重入）或选出的档与当前相同都返回 false。
        bool applyAutoBytesPerRow();

        // applyZoomFont：按基准字体与缩放级别算出字体并 setFont（定义在 HexCanvas.Layout.cpp）。
        void applyZoomFont();

        // handleZoomKey：Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0 缩放键（定义在 HexCanvas.Input.cpp）。
        // 传出：true 表示按键已处理（已 accept）。与有没有地址空间无关，Alt 同时按下（AltGr 文字输入）不处理。
        bool handleZoomKey(QKeyEvent* event);

        void setFirstRowInternal(std::uint64_t row, bool syncBar);
        void applySelectionChange(const ksword::memwb::HexViewport::Selection& before);
        // 跨同步通知后核对实际选区；同一来源内重入导航也会使旧通知作废。
        bool selectionStillMatches(const ksword::memwb::HexViewport::Selection& expected) const;
        void scheduleContentChanged();
        bool collectCachedRange(
            std::uint64_t firstAddress,
            std::uint64_t lastAddress,
            bool allowUnreadable,
            std::vector<std::uint8_t>* bytesOut,
            std::vector<std::uint8_t>* maskOut) const;
        static std::uint64_t rowFromSlider(int value, std::uint64_t maxRow);
        static int sliderFromRow(std::uint64_t row, std::uint64_t maxRow);

        // ---------- HexCanvas.Paint.cpp：绘制与单元格状态 ----------
        PaintPalette makePalette() const;
        CellCore resolveCore(std::uint64_t address) const;
        int findLayerIndex(std::uint64_t address) const;
        void rebuildLayerSnapshot();
        void touchVisiblePages(std::uint64_t firstAddress, std::uint64_t lastAddress);
        void paintHeader(QPainter& painter, const PaintPalette& palette, int viewWidth, std::uint64_t caretColumn) const;
        void paintRow(
            QPainter& painter,
            const PaintPalette& palette,
            std::uint64_t row,
            int rowTop,
            const std::optional<AddressRange>& selection) const;
        void paintCaretFrames(QPainter& painter, const PaintPalette& palette) const;

        // ---------- HexCanvas.Input.cpp：鼠标、键盘、滚轮 ----------
        Hit hitTest(const QPoint& viewportPos) const;
        void extendSelectionTo(const Hit& hit);
        bool handleCaretKey(QKeyEvent* event);

        // ---------- HexCanvas.Edit.cpp：编辑 ----------
        bool handleTextInput(QChar ch);
        void cancelNibble();
        bool precheckStage(std::uint64_t address, std::uint64_t length, QString* reasonOut) const;
        void rejectEdit(const QString& reason);
        void backspaceStep();
        void advanceAfterEdit();

        // ---------- HexCanvas.Menu.cpp：复制与菜单 ----------
        QString menuStyleSheet() const;
        int addressDigits() const;

        // 暂定常量。
        static constexpr int kProportionalRange = 0x7FFFFFFF;       // 比例映射时滚动条量程
        static constexpr std::uint64_t kPrefetchPages = 2;          // 前后各预取的页数
        static constexpr std::uint64_t kMaxCopyBytes = 16ULL * 1024ULL * 1024ULL; // 单次复制上限
        static constexpr int kAutoScrollIntervalMs = 40;            // 拖选自动滚动间隔

        // ---- 模型 ----
        ksword::memwb::HexViewport m_viewport;                      // 地址空间/缓存/选区模型
        bool m_hasSpace = false;                                    // 是否有地址空间
        bool m_viewportReadEnabled = true;
        ksword::memwb::MemoryDiffOverlay* m_overlay = nullptr;      // 暂存叠加层（非拥有）
        IHexPageProvider* m_provider = nullptr;                     // 外部页提供者（非拥有）
        std::unique_ptr<IHexPageProvider> m_staticProvider;         // setStaticData 装的内置提供者
        std::uint64_t m_revisionCounter = 1;                        // 来源代次发生器，只增不减
        bool m_editable = false;                                    // 是否允许编辑
        int m_groupSize = 1;                                        // 十六进制分组字节数
        bool m_autoBytesPerRow = false;                             // 是否处于自适应行宽模式（默认关，见文件头"七之二"）
        bool m_inAutoFit = false;                                   // 正在自适应重排中（防重入的保险）

        // ---- 滚动 ----
        std::uint64_t m_firstRow = 0;                               // 首个可见行的行号（权威值）
        bool m_proportionalScroll = false;                          // 竖向滚动条是否处于比例映射
        bool m_updatingBars = false;                                // 程序同步滚动条时屏蔽回调
        int m_hOffset = 0;                                          // 横向滚动像素量
        std::uint64_t m_lastNotifiedFirst = 0;                      // 上次发出的可见首地址
        std::uint64_t m_lastNotifiedLast = 0;                       // 上次发出的可见末地址
        bool m_notifiedOnce = false;                                // 是否发过 visibleRangeChanged

        // ---- 度量与缓存文字 ----
        Layout m_layout;                                            // 横向几何
        QStaticText m_hexTexts[256];                                // 每个字节值的两位十六进制文字
        QStaticText m_asciiTexts[256];                              // 每个字节值的 ASCII 文字
        QStaticText m_loadingHexText;                               // "··"
        QStaticText m_unreadableHexText;                            // "??"
        QStaticText m_loadingAsciiText;                             // "·"（U+00B7）
        QStaticText m_unreadableAsciiText;                          // "×"（U+00D7），不再用 "?"，避免与真实的 0x3F 混淆

        // ---- 编辑状态 ----
        bool m_nibbleActive = false;                                // 是否有未完成的高半字节
        int m_nibbleHigh = 0;                                       // 已输入的高半字节
        std::uint64_t m_nibbleAddress = 0;                          // 半字节所属字节地址

        // ---- 拖选 ----
        bool m_dragging = false;                                    // 是否正在拖选
        QPoint m_lastMousePos;                                      // 最近一次鼠标位置（视口坐标）
        QTimer m_autoScrollTimer;                                   // 拖出视口时的自动滚动定时器
        int m_wheelRemainder = 0;                                   // 滚轮角度累积余量

        // ---- 字号缩放 ----
        QFont m_baseFont;                                           // 基准字体（构造时的等宽字体，缩放级别 0 对应它）
        int m_zoomLevel = 0;                                        // 当前缩放级别，范围 [kMinZoomLevel, kMaxZoomLevel]
        int m_zoomWheelRemainder = 0;                               // Ctrl+滚轮的角度累积余量（按 120 凑成整档）

        // ---- 高亮与诊断 ----
        std::map<int, HighlightLayer> m_layers;                     // 通用高亮层，键为层号
        std::vector<std::pair<int, const HighlightLayer*>> m_layerSnapshot; // 层快照（层号降序，高层优先匹配）
        std::uint64_t m_lastPaintedRows = 0;                        // 最近一次绘制的行数
        bool m_refetchQueued = false;                               // 是否已排队一次补读（可见页被淘汰时）
        bool m_contentChangedQueued = false;                        // 是否已排队一次 contentChanged（用于同一轮事件循环内合并）
    };
}
