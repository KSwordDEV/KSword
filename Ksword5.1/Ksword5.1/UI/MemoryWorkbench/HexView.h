#pragma once

// ============================================================
// HexView.h
// 作用：
// - 通用十六进制组件（复合控件），服务内存、文件、网络、磁盘及捕获证据宿主。
//   布局自上而下：
//     工具栏 | 查找条（默认隐藏）| 跳转条（默认隐藏）| QSplitter{ HexCanvas | HexInspectorPanel（默认隐藏）} | 状态条
// - 画布、解释器面板、查找引擎、地址表达式、暂存叠加层全部复用已验证的组件，本类只做组合与"旧缓冲模型兼容层"。
//
// ------------------------------------------------------------
// 一、工具栏（全部图标化，全部有悬停提示）
// ------------------------------------------------------------
// - 行宽（8/16/32/48/64，下拉）、分组（1/2/4/8，下拉）：图标右侧带当前值徽标；
// - 查找（Ctrl+F）、跳转（Ctrl+G）、导出（下拉：导出二进制 / 导出十六进制文本 / 导出选中字节为十六进制文本）、
//   解释器面板开关（可勾选）。
// - setToolbarVisible / setStatusBarVisible 可分别隐藏工具栏与状态条（嵌入式宿主要极简外观）；
//   隐藏工具栏后快捷键仍然有效。
// - 状态条显示：插入点地址 | 选区长度 | 数据范围与总字节数；跳转失败、导出结果、编辑被拒绝等瞬时消息会
//   替换这三段显示，下一次选区变化（或换数据）后恢复。
//
// ------------------------------------------------------------
// 二、快捷键（全部 Qt::WidgetWithChildrenShortcut 上下文）
// ------------------------------------------------------------
// - Ctrl+F 查找、Ctrl+G 跳转、F3 / Shift+F3 下一个 / 上一个、Esc 关闭当前面板。
// - 旧控件用窗口级上下文：同一窗口嵌入多个十六进制控件时，快捷键会二义冲突。现在只在焦点位于本控件
//   或其子控件内时才触发，两个 HexView 并存时 Ctrl+F 只作用于有焦点的那个。
// - Esc 的规则："先查找/跳转条，再无则不处理"：焦点在跳转条内先关跳转条，否则先关查找条，再关跳转条；
//   两个条都没开时这个快捷键处于禁用状态，Esc 落到画布自己的处理（取消半字节 / 折叠选区）。
// - F3 在查找条未打开时会先打开它，并在输入框已有文字时直接开始搜索。
//
// ------------------------------------------------------------
// 三、解释器面板
// ------------------------------------------------------------
// - 默认隐藏，工具栏图标切换；宽度由分割条拖动。面板在第一次需要时才创建（嵌入式宿主不用就没有开销）。
// - 显隐状态持久化到 QSettings 键 memwb/hexview/inspectorVisible，读失败退回 false。
//   只有"用户点工具栏按钮"才写入；宿主用代码调用 setInspectorVisible 不写入——
//   否则一个嵌入式宿主强制 false 会覆盖内存工作台里用户的偏好（两个宿主共用同一个键）。
//
// ------------------------------------------------------------
// 四、旧缓冲模型兼容层（接口承诺，夹具逐个函数测试）
// ------------------------------------------------------------
// 模型：HexView 自己持有缓冲 m_buffer（当前内容）与基线 m_baseline（参照）。画布的数据源是基线
// （BufferProvider 切页回填），用户编辑落在暂存叠加层 MemoryDiffOverlay 里，所以恒有不变式：
//     叠加层补丁集合 == { 地址 : 缓冲[地址] != 基线[地址] }，补丁的 before = 基线字节，after = 缓冲字节。
// 画布显示 = 补丁值（有补丁）或基线字节（无补丁），也就恒等于缓冲；橙色"待提交"着色 = 补丁。
// 这样编辑、回滚、撤销都不必让页缓存失效，也没有第二份需要同步的副本。
//
// - setBuffer(base, bytes)：整块替换内容。清选区与暂存，滚动回顶，基线 = bytes（暂存全部消失），查找状态清空。
//   base + 长度超过 2^64 时截断到放得下的部分。空数据等价 clearBuffer。
// - buffer()：当前缓冲（含已应用的编辑）。clearBuffer()：清空内容（基址保留）。
// - baseAddress() / bufferSize()：基址与字节数。
// - 编辑（setEditable(true) 后）：画布键盘 / 粘贴 / 填充 / 解释器行内编辑产生的暂存，在 editStaged 时立刻同步进缓冲，
//   并对每个真正变化的字节发 byteEdited(绝对地址, 旧值, 新值) 恰好一次（暂存了与缓冲相同的值不发）。
//   Backspace 丢弃暂存使字节回到基线值时，缓冲同步回退，同样对每个变化字节发 byteEdited
//   （宿主若按 byteEdited 立即写目标，回退也会被写下去，缓冲与目标始终一致）。
//   信号在缓冲、叠加层都已落地之后才发出；槽里可以安全地调用 setByteQuiet 回滚。
// - setByteQuiet(addr, value)：改一个字节，不发 byteEdited（旧控件 setByteAtAbsoluteAddress 的语义，回滚路径依赖）；
//   缓冲与画面立即更新，橙色着色按"是否不同于基线"重算（回到基线值 = 橙色消失）。
//   地址不在缓冲内返回 false；暂存总量超限时返回 false 且不改任何东西。
// - setReference(original, previousRead)：设置变更着色参照。
//   original 成为基线（长度必须等于缓冲，否则按旧控件规则"不着色"：参照被清除，返回 false）；
//   缓冲与基线不同的字节以补丁体现为橙色；previousRead 非空且与 original 等长时作为"上次读取"，
//   previousRead 与 original 不同的字节显示冷色"外部变化"（已有补丁的字节橙色优先）；尺寸不符的 previousRead 被忽略。
//   clearReference()：基线回到"当前缓冲"，橙色与冷色全部消失（待提交的修改被接受为基线）。hasReference()：是否设置过有效参照。
// - jumpToAddress(addr)：地址在缓冲范围内则选中该字节并滚动到视口中央，返回 true；
//   范围外返回 false，并在状态条显示"跳转失败：…超出数据范围 [起点, 终点]"——不静默。
// - openFind() / openGoto()：打开查找条 / 跳转条并聚焦输入框。
// - setBytesPerRow / bytesPerRow、setGroupSize / groupSize：只接受画布支持的取值（行宽 8/16/32/48/64，分组 1/2/4/8），
//   非法值返回 false 且不改（旧控件是夹取；画布的取值集合更窄，宿主传 16/32 照常）。
// - caretAddress()：插入点绝对地址；selectedBytes()：选区字节（来自缓冲，不依赖画布页是否已加载）；
//   selectionRange(startOut, endOut)：选区在缓冲内的半开偏移区间 [start, end)（相对基址，旧控件语义），无数据返回 false。
//   注意：新画布恒有插入点，所以有数据时"无选区"不会出现——刚载入时 selectedBytes() 是第 0 个字节。
// - 信号：byteEdited、caretMoved(绝对地址)、selectionChanged(起偏移, 止偏移(开), 是否有选区)、
//   aboutToShowContextMenu(菜单, 地址, 该处是否有字节)（转发画布的 contextMenuAboutToShow）、
//   editRejected(原因)（转发画布的编辑拒绝并显示在状态条）、exportFinished(是否成功, 说明)。
// - panel() 访问器与 setInspectorVisible(bool)：见第三节。
//
// ------------------------------------------------------------
// 五、查找 / 跳转 / 导出的接线
// ------------------------------------------------------------
// - 查找：HexFindBar 取缓冲快照（QByteArray 隐式共享）在后台线程搜索；命中后选中命中范围（插入点在命中起点）并滚动到可见；
//   当前视口内全部命中用画布高亮层（层号 kFindHighlightLayer）标出，颜色在每次主题变化后重新取；
//   缓冲内容任何变化（setBuffer / 编辑 / setByteQuiet）都会清除高亮并让在途搜索作废（只改参照不改内容的 setReference 不会）。
//   起点规则：下一个 = 上次命中起点 + 1（允许重叠命中）；选区不是"同一个模式的上次命中"时，从选区起点（含）开始；到尽头一律回绕并在结果文字里明示（"已从头继续" / "已从末尾继续"），不会静默回绕。
// - 跳转：HexGotoBar 地址 / 偏移 / 行号三模式，输入按十六进制默认解析，错误行内提示，历史持久化。
// - 导出：二进制、十六进制转储文本（每行 16 字节）、选中字节十六进制文本；
//   exportXxxTo(path) 是不弹对话框的版本（返回是否成功并发 exportFinished），exportXxx() 先弹保存对话框，失败再弹错误框。
//
// ------------------------------------------------------------
// 六、边界与已知限制
// ------------------------------------------------------------
// - 目前是"缓冲模式"：数据整块在内存里。内存宿主若要稀疏大地址空间 + 异步页读取，需要另加页提供者模式
//   （画布本身支持，canvas() 已公开；但缓冲兼容层、查找、导出都以缓冲为前提，本类未做外部提供者模式）。
// - 叠加层要求基线窗口的终点能用 uint64 表示：缓冲正好贴着 0xFFFFFFFFFFFFFFFF 末端时叠加层载入基线失败，
//   此时视图可看但不可编辑（画布会给出"超出当前已读取的数据窗口"的原因）。
// - 暂存总量上限 64 MiB（叠加层上限）：缓冲与基线相差字节超过它时 setReference 返回 false。
// - 画布的通用高亮层把调用方给的颜色存下来、不随主题自动更新：HexView 靠 changeEvent 在调色板变化后重新设置查找高亮；
//   宿主自己往画布加的高亮层（书签等）需要自己做同样的事，或由画布改成按需取色。
// - aboutToShowContextMenu 的 QMenu* 参数在本头文件里只有前置声明：QSignalSpy 拿不到它的元类型，
//   接线要用 lambda / 槽函数（夹具里就是这么测的）。
// - 原生保存对话框（QFileDialog）与导出错误框只有用户手势才会走到，夹具只验证样式与不弹窗的部分。
//
// ------------------------------------------------------------
// 七、文件分工（均已登记进 Ksword5.1.vcxproj 与 .filters）
// ------------------------------------------------------------
//   HexView.h               （Q_OBJECT，需 moc）本文件
//   HexView.cpp             构造、界面搭建、画布信号接线、状态条刷新、可见性
//   HexView.Toolbar.cpp     工具栏、下拉菜单
//   HexView.Compat.cpp      缓冲模型：BufferProvider、setBuffer/setReference/setByteQuiet、编辑同步
//   HexView.Panels.cpp      查找 / 跳转 / 解释器 / 快捷键 / 导出 / 主题刷新
//   HexViewWidgets.h/.cpp/.Text.cpp  五个自绘小控件（HexViewSegmented 含 Q_OBJECT，需 moc）
//   HexFindBar.h/.cpp、HexFindSearch.h/.cpp   查找条（Q_OBJECT，需 moc）与纯逻辑
//   HexGotoBar.h/.cpp       跳转条（Q_OBJECT，需 moc）
//   HexExport.h/.cpp        导出格式化 / 写文件 / 对话框
//   HexViewFormat.h/.cpp、HexViewSettings.h/.cpp   共用纯函数与偏好读写
// - 依赖：Qt Core/Gui/Widgets、theme.h、HexCanvas、HexInspectorPanel、shared/evidence/memory_workbench/*。
//   不包含 Framework.h，自包含，可被离屏夹具单独编译。
//
// ------------------------------------------------------------
// 八、验证读数（Phase 2 本组实测，tools/memwb_ui/build-memwb-ui-tests.cmd）
// ------------------------------------------------------------
// - 离屏夹具（MSVC /std:c++latest /W4 /WX，Qt 6.9.3 offscreen，/MP 并行编译约 30 秒）：HexView 部分 1100 条断言 0 失败，
//   全夹具 3273 条 0 失败，零编译警告；tools/theme_token_audit.py 通过；本组每个源文件不超过 800 行。
//   截图 14 张（深/浅 x 窄/宽，含查找命中、回绕提示、无效模式、跳转错误、历史菜单、解释器展开、极简嵌入、行宽/导出菜单），
//   由夹具的 --shots 参数落盘，逐张目视核对过。
// - 覆盖：工具栏图标按主题现取（像素实测）与悬停提示（真实 ToolTip 事件）、三个下拉菜单（内容、选中态、不透明像素、深浅主题重新取色）、
//   解释器面板（按需创建、跟随画布、真实拖动分割条、偏好持久化含乱写值与读失败）、两个 HexView 同窗口的快捷键隔离与 Esc 优先级、
//   兼容层每个函数（byteEdited 恰好一次、五条编辑入口、槽内回滚、setByteQuiet、setReference 橙/冷色与像素、64 位末端、16/65 MiB 规模）、
//   查找（三种模式、通配、回绕明示、起点规则、可见高亮含跨边界/重叠/主题重取、后台取消、陈旧结果两种时序、销毁安全、
//   对朴素实现的差分测试：RunSearch 600 组、HitsInRange 800 组随机用例）、跳转（三种模式、十六进制默认、范围外与错误提示、
//   历史上限/去重/持久化/Up-Down/菜单）、导出（转储格式逐行精确、写文件成功与失败路径）。
// - 变异验证：30 个人为缺陷全部被抓到（未变异对照组全绿；"编辑不同步进缓冲"一条让夹具后续流程中断、没有汇总行，
//   但已打出多条 FAIL，按"被抓到"计）：同值写入也发 byteEdited、setByteQuiet 不丢补丁、参照尺寸不符不清参照、
//   previousRead 被忽略、回绕不提示、起点忽略选区、陈旧结果不丢弃、数据变化不清高亮、可见命中不向前/向后多看、偏移忘了加起点、
//   历史上限 20 / 不持久化、转储补 00、快捷键改窗口级、代码调用写偏好、主题变化不重取高亮色、setBuffer 不清查找、末字节跳转越界、
//   Esc 常驻启用、用户切换不写偏好、行号按十六进制、selectionChanged 止偏移变含、搜索忽略取消标志、编辑不同步进缓冲、
//   乱写偏好当 true、换模式跳过同一起点命中、查找按钮无提示、偏移模式放过一字节越界、选中字节导出小写。
//   第一轮曾有一个幸存者："陈旧结果不丢弃"——只测了"搜索还在途时被取代"，引擎的取消检查点兜住了它；
//   补了"搜索已完整跑完、结果回调已入队再作废"这一档（只剩票据判断）后被抓到。
//   审视测试时还发现一个真实缺陷：改了查找模式再回车，选区仍是旧模式的命中时会从命中起点 + 1 开始，
//   跳过同一起点上的新命中（"4D 5A" 补成 "4D 5A 90 00"）；已修复（上次命中记住模式），并补了用例与变异体。
// - 读数（本机，与其它会话并行时有波动）：16 MiB 缓冲 setBuffer 约 11~13 ms、第一次编辑 2~4 ms（缓冲与基线分离的一次整块拷贝）、
//   之后每次编辑 2~3 ms、setByteQuiet 不足 1 ms；64 MiB 全零缓冲上的慢模式搜索：findNext() 立即返回（0 ms），
//   后台整个搜索约 545 ms，中途取消在 2 ms 内生效，搜索进行中销毁控件 9~10 ms。
// ============================================================

#include "HexCanvas.h"
#include "HexExport.h"
#include "HexFindBar.h"
#include "HexGotoBar.h"
#include "HexViewWidgets.h"

#include "../../../../shared/evidence/memory_workbench/MemoryDiffOverlay.h"

#include <QByteArray>
#include <QString>
#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

class QMenu;
class QShortcut;
class QSplitter;
class QVBoxLayout;

namespace ks::ui
{
    class HexInspectorPanel;

    // HexView：通用十六进制复合控件，详见文件头。
    class HexView : public QWidget
    {
        Q_OBJECT

    public:
        // kFindHighlightLayer：查找命中使用的画布高亮层号（大者在上；宿主的书签层应取更小的号）。
        static constexpr int kFindHighlightLayer = 100;

        // 构造：parent 为父控件。默认空数据、只读、每行 16 字节、工具栏与状态条显示、解释器面板按偏好。
        explicit HexView(QWidget* parent = nullptr);

        // 析构：先让画布放开叠加层与页提供者（它们是本类的成员，先于子控件销毁）。
        ~HexView() override;

        // ---------------- 缓冲模型（旧控件兼容层，见文件头第四节） ----------------

        // setBuffer：整块替换内容。传入：起始地址、字节。
        void setBuffer(std::uint64_t baseAddress, const QByteArray& bytes);

        // buffer：当前缓冲（含已应用的编辑）。
        QByteArray buffer() const;

        // clearBuffer：清空内容，基址保留。
        void clearBuffer();

        // baseAddress / bufferSize：基址与字节数。
        std::uint64_t baseAddress() const;
        std::uint64_t bufferSize() const;

        // setByteQuiet：静默改一个字节（不发 byteEdited）。传出：false 表示地址越界或暂存超限。
        bool setByteQuiet(std::uint64_t absoluteAddress, std::uint8_t value);

        // setReference：设置变更着色参照。传出：false 表示 original 与缓冲等长不成立（参照已被清除）。
        bool setReference(const QByteArray& original, const QByteArray& previousRead = QByteArray());

        // clearReference：基线回到当前缓冲，着色全部消失。hasReference：是否设置过有效参照。
        void clearReference();
        bool hasReference() const;

        // setEditable / isEditable：是否允许编辑。
        void setEditable(bool editable);
        bool isEditable() const;

        // jumpToAddress：选中并滚动到某地址。传出：false 表示范围外（状态条已提示）。
        bool jumpToAddress(std::uint64_t absoluteAddress);

        // openFind / openGoto：打开查找条 / 跳转条。
        void openFind();
        void openGoto();

        // setBytesPerRow / bytesPerRow：每行字节数（8/16/32/48/64）。非法值返回 false。
        bool setBytesPerRow(int bytesPerRow);
        int bytesPerRow() const;

        // setGroupSize / groupSize：十六进制列分组字节数（1/2/4/8）。非法值返回 false。
        bool setGroupSize(int groupSize);
        int groupSize() const;

        // caretAddress：插入点绝对地址；无数据为 0。
        std::uint64_t caretAddress() const;

        // selectedBytes：选区字节（来自缓冲）；无数据返回空数组。
        QByteArray selectedBytes() const;

        // selectionRange：选区的半开偏移区间 [start, end)（相对基址）。无数据返回 false，两个出参保持原值。
        bool selectionRange(std::uint64_t& startOffsetOut, std::uint64_t& endOffsetOut) const;

        // ---------------- 外观 ----------------

        // setToolbarVisible / toolbarVisible、setStatusBarVisible / statusBarVisible：工具栏与状态条显隐。
        void setToolbarVisible(bool visible);
        bool toolbarVisible() const;
        void setStatusBarVisible(bool visible);
        bool statusBarVisible() const;

        // setInspectorVisible / inspectorVisible：解释器面板显隐。代码调用不写偏好（见文件头第三节）。
        void setInspectorVisible(bool visible);
        bool inspectorVisible() const;

        // panel：解释器面板；首次调用时创建（初始隐藏）。
        HexInspectorPanel* panel();

        // ---------------- 内部控件访问器（供宿主微调与离屏测试，不改变行为） ----------------
        HexCanvas* canvas() const;
        HexFindBar* findBar() const;
        HexGotoBar* gotoBar() const;
        HexViewStatusBar* statusBar() const;
        QWidget* toolbar() const;
        HexViewGlyphButton* rowWidthButton() const;
        HexViewGlyphButton* groupButton() const;
        HexViewGlyphButton* findButton() const;
        HexViewGlyphButton* gotoButton() const;
        HexViewGlyphButton* exportButton() const;
        HexViewGlyphButton* inspectorButton() const;
        QSplitter* splitter() const;
        QMenu* rowWidthMenu() const;
        QMenu* groupMenu() const;
        QMenu* exportMenu() const;

        // closeFindBar / closeGotoBar：关闭对应的条（取消搜索、清高亮、焦点回画布）。
        void closeFindBar();
        void closeGotoBar();

        // ---------------- 导出 ----------------

        // exportBinaryTo / exportHexTextTo / exportSelectedHexTo：不弹对话框的导出，直接写 path。
        // 传出：是否成功；结果同时显示在状态条并发 exportFinished。数据为空（或选区为空）返回 false。
        bool exportBinaryTo(const QString& path);
        bool exportHexTextTo(const QString& path);
        bool exportSelectedHexTo(const QString& path);

    public slots:
        // exportBinary / exportHexText / exportSelectedHex：先弹保存对话框，用户取消什么也不做，写失败再弹错误框。
        void exportBinary();
        void exportHexText();
        void exportSelectedHex();

    signals:
        // byteEdited：用户编辑使缓冲里的字节真的变了。
        void byteEdited(quint64 absoluteAddress, quint8 oldValue, quint8 newValue);

        // caretMoved：插入点（绝对地址）变化。
        void caretMoved(quint64 absoluteAddress);

        // selectionChanged：选区变化。起止偏移相对基址，止偏移不含；hasSelection 为假表示无数据（两个偏移为 0）。
        void selectionChanged(quint64 startOffset, quint64 endOffset, bool hasSelection);

        // aboutToShowContextMenu：右键菜单弹出前发出，宿主可追加动作（转发画布的 contextMenuAboutToShow）。
        void aboutToShowContextMenu(QMenu* menu, quint64 absoluteAddress, bool hasByte);

        // editRejected：编辑被拒绝（只读、未加载、超限等），reason 可直接给用户看。
        void editRejected(const QString& reason);

        // exportFinished：一次导出结束，ok 表示是否成功，message 是状态条上显示的同一段文字。
        void exportFinished(bool ok, const QString& message);

    protected:
        // changeEvent：主题（调色板）变化后重新取查找高亮色。
        void changeEvent(QEvent* event) override;

    private:
        // BufferProvider：画布的页提供者，从基线切页回填（定义在 HexView.Compat.cpp）。
        class BufferProvider;

        // ---------- HexView.cpp ----------
        void buildUi();
        void connectCanvas();
        void refreshStatus();
        void onCanvasSelectionChanged(bool valid, quint64 first, quint64 last);

        // ---------- HexView.Toolbar.cpp ----------
        void buildToolbar();
        void updateToolbarBadges();
        QString menuStyleSheet() const;
        void rebuildRowWidthMenu();
        void rebuildGroupMenu();
        void rebuildExportMenu();

        // ---------- HexView.Compat.cpp ----------
        void attachBufferModel();
        void installBaseline(const QByteArray& previousRead = QByteArray());
        bool applyDiffPatches();
        void syncBufferFromOverlay(std::uint64_t address, std::uint64_t length);
        void onEditStaged(quint64 address, quint64 length);
        void onEditDiscarded(quint64 address, quint64 length);
        void onDataReplaced();
        std::uint64_t lastAddress() const;

        // ---------- HexView.Panels.cpp ----------
        void buildPanels();
        void ensureInspector();
        void onInspectorToggled(bool checked);
        void applyInspectorVisible(bool visible);
        void updateEscapeShortcut();
        void onEscape();
        void onFindNextShortcut(bool forward);
        void applyFindHighlights();
        void onFindMatch(quint64 first, quint64 length, bool wrapped);
        void onGotoRequested(quint64 address);
        void showStatusMessage(HexViewStatusBar::Kind kind, const QString& text);
        bool runExport(hexexport::Kind kind, const QString& path, QString* messageOut = nullptr);
        void runExportWithDialog(hexexport::Kind kind);

        // ---- 数据 ----
        std::uint64_t m_baseAddress = 0;                            // 缓冲起始地址
        QByteArray m_buffer;                                        // 当前缓冲（含已应用的编辑）
        QByteArray m_baseline;                                      // 基线（画布的数据源，叠加层的基线）
        bool m_hasReference = false;                                // 是否设置过有效参照
        ksword::memwb::MemoryDiffOverlay m_overlay;                 // 暂存叠加层（补丁 == 缓冲与基线的差异）
        BufferProvider* m_provider = nullptr;                       // 画布的页提供者（裸指针：类定义在 Compat.cpp，由 attachBufferModel 创建、析构里释放）

        // ---- 子控件 ----
        QVBoxLayout* m_root = nullptr;                              // 根布局
        HexViewBarFrame* m_toolbar = nullptr;                       // 工具栏
        HexFindBar* m_findBar = nullptr;                            // 查找条
        HexGotoBar* m_gotoBar = nullptr;                            // 跳转条
        QSplitter* m_splitter = nullptr;                            // 画布 | 解释器
        HexCanvas* m_canvas = nullptr;                              // 画布
        HexInspectorPanel* m_inspector = nullptr;                   // 解释器面板（按需创建）
        HexViewStatusBar* m_status = nullptr;                       // 状态条
        HexViewGlyphButton* m_rowWidthButton = nullptr;             // 行宽
        HexViewGlyphButton* m_groupButton = nullptr;                // 分组
        HexViewGlyphButton* m_findButton = nullptr;                 // 查找
        HexViewGlyphButton* m_gotoButton = nullptr;                 // 跳转
        HexViewGlyphButton* m_exportButton = nullptr;               // 导出
        HexViewGlyphButton* m_inspectorButton = nullptr;            // 解释器面板开关
        QMenu* m_rowWidthMenu = nullptr;                            // 行宽菜单
        QMenu* m_groupMenu = nullptr;                               // 分组菜单
        QMenu* m_exportMenu = nullptr;                              // 导出菜单
        QShortcut* m_escapeShortcut = nullptr;                      // Esc 快捷键（仅有条打开时启用）

        // ---- 状态 ----
        bool m_inspectorShown = false;                              // 解释器面板是否显示
        std::vector<HexCanvas::AddressRange> m_findRanges;          // 当前查找高亮区间（主题变化后重新着色用）
        bool m_visibleValid = false;                                // 是否收到过画布的可见范围
        std::uint64_t m_visibleFirst = 0;                           // 画布最近一次报告的可见起点
        std::uint64_t m_visibleLast = 0;                            // 画布最近一次报告的可见终点
    };
}
