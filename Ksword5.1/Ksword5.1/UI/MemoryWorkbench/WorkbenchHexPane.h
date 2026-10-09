#pragma once

// ============================================================
// WorkbenchHexPane.h
// 作用：
// - 十六进制子页的容器（见 ux.md §1/§4.1）：组合 HexCanvas + HexInspectorPanel +
//   HexFindBar（不复用 HexView 复合控件——ux.md §0 已拍板：HexView 是"缓冲模式"，
//   没有外部页提供者，状态条单行省略，这正是旧版缺陷的根因，HexView 继续冻结给
//   文件/网络/磁盘等缓冲型宿主用）。
// - 本类是 MemoryDiffOverlay **唯一一份**的持有者（值成员，见下）：
//   WorkbenchBaselineFeeder / WorkbenchWriteController / 反汇编·文本·对比三个子页
//   （经 IWorkbenchBytesProvider 适配）全部只拿本类转交出去的非拥有指针，谁都不
//   另建一份。画布本身不拥有叠加层（HexCanvas::setOverlay 只接受非拥有指针），
//   所以这份唯一性完全靠"本类是谁都不把 overlay 的所有权转出去"来保证。
// - 本类同时是 WorkbenchPageProvider / WorkbenchBaselineFeeder / WriteController
//   三者的接线点：它们由上层（MemoryWorkbenchView）创建并注入（非拥有指针），本类
//   负责把画布的信号（visibleRangeChanged/caretMoved/contentChanged/editStaged）
//   转发给它们各自对应的入口方法，以及把它们的结果信号（baselineRefreshed 等）
//   转发回画布（notifyOverlayChanged）。
// - "窗口跟随"：画布视口变化（visibleRangeChanged）与插入点变化（caretMoved）都会
//   调用 baselineFeeder_->noteDirty(...)；画布请求页（通过 IHexPageProvider 协议）
//   则完全由 pageProvider_ 自己接住，本类不转发 RequestPages（画布直接持有
//   pageProvider_ 的 IHexPageProvider* 基类指针，setPageProvider 时一次性接好）。
// ============================================================

#include "HexCanvas.h"
#include "HexFindBar.h"
#include "HexInspectorPanel.h"

#include "../../../../shared/evidence/memory_workbench/MemoryDiffOverlay.h"

#include <QPointer>
#include <QSize>
#include <QString>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

class QMenu;
class QResizeEvent;
class QShowEvent;
class QSplitter;
class QVBoxLayout;

namespace ks::ui
{
    class WorkbenchBaselineFeeder;
    class WorkbenchPageProvider;
    class WorkbenchWriteController;

    // WorkbenchHexPane：十六进制子页容器，详见文件头。全部公开函数只在 UI 线程调用。
    class WorkbenchHexPane final : public QWidget
    {
        Q_OBJECT

    public:
        explicit WorkbenchHexPane(QWidget* parent = nullptr);
        ~WorkbenchHexPane() override;

        // overlay：唯一一份暂存叠加层的引用，本类拥有其生命周期（值成员）。
        // 调用方（装配层）在换目标时先对它调用 LoadBaseline（本类不代为载入首个
        // 基线——"谁先读到字节谁载入"更自然地落在换目标流程本身，不是子页容器的
        // 职责），之后的"跟随与重喂"交给 setBaselineFeeder 注入的 WorkbenchBaselineFeeder。
        ksword::memwb::MemoryDiffOverlay& overlay() noexcept;

        // canvas / inspector / findBar：内部控件访问器，供装配层微调、接线与离屏
        // 测试，不转移所有权。
        HexCanvas* canvas() const noexcept;
        HexInspectorPanel* inspector() const noexcept;
        HexFindBar* findBar() const noexcept;

        // setPageProvider / setBaselineFeeder / setWriteController：三个非拥有依赖
        // 的装配点。必须在 setAddressSpace 第一次被调用之前设置好 PageProvider（否则
        // 画布请求页时 provider 为空，只会静默什么都不回填）。
        void setPageProvider(WorkbenchPageProvider* provider);
        void setBaselineFeeder(WorkbenchBaselineFeeder* feeder);
        void setWriteController(WorkbenchWriteController* controller);

        // setSourceRevisionProvider（Wave 3 wpJ5 新增，任务书允许的增量②）：注入
        // "取当前**目标轴**来源代次"的回调。装配层（MemoryWorkbenchView）在接好
        // target.session() 之后，用 target.capture().rev.source 实现这个回调并
        // 传进来；本类调用 baselineFeeder_->noteDirty(...) 时，第二个参数
        // （currentSourceRevision）就取自这里，而不是画布自己的 sourceRevision()
        // ——两条数轴是独立的（见 WorkbenchPageProvider.h"两条数轴"一节），基线
        // 喂入器要的是**目标轴**。未设置（默认空）时退回常量 0，不崩溃、仍能正常
        // 构造与显示，只是基线喂入器看到的目标轴代次恒为 0（等价于"看不到目标轴
        // 变化"，装配尚未完成时的安全占位，调用方应尽快补上真实实现）。
        void setSourceRevisionProvider(std::function<std::uint64_t()> provider);

        // setAddressSpace：换目标/换范围时调用。作用：canvas_->setAddressSpace(...)
        // （清缓存、换新来源代次）、overlay_.LoadBaseline(新 identityKey, 空窗口占位)
        //（真正的基线内容由随后的页回填触发 BaselineFeeder 喂入，这里只是清空旧补丁、
        // 换新身份串，避免旧目标的补丁被错配进新目标）、通知 pageProvider_/
        // baselineFeeder_ 重置内部状态（resetScratchLatch/setIdentityKey 等）。
        // 本函数末尾还会无条件更新 lastAnchor_ 并调一次 baselineFeeder_->noteDirty
        // （独立审核 wave3 review-wpJ5.md §1.1 修复）：换目标但地址空间边界与
        // 插入点都恰好与旧目标相同时，HexCanvas 的 visibleRangeChanged/caretMoved
        // 去重逻辑可能一个信号都不发，不能依赖画布重发信号来唤醒基线喂入器。
        void setAddressSpace(
            std::uint64_t firstAddress,
            std::uint64_t lastAddress,
            const std::string& identityKey);

        // clearAddressSpace：回到"无目标"状态（未附加/未钉住时）。
        void clearAddressSpace();

        // setEditable：随"写入忙/只读通道"切换，转发给 canvas_->setEditable；
        // WriteController 的 CanvasReadOnlyHook 正是接到这个方法。
        void setEditable(bool editable);

        // insertionAddress：当前插入点地址，转发 canvas_->caretAddress()。
        std::uint64_t insertionAddress() const;
        void requestBrowseWindow(std::uint64_t address, std::uint64_t length);
        void setExternalBrowseMode(bool enabled);

        // selectionStart：选区的起点（闭区间的 first）；没有选区时退回插入点。
        // 与 insertionAddress 的区别：向前拖选时插入点在选区末端，而用户要看的是选中区域的开头——
        // 三个只读子页（反汇编/文本/对比）的自动跳转用它，而不是插入点。
        std::uint64_t selectionStart() const;

        // jumpTo：跳转入口（地址条回车、模块表双击等最终都落到这里）。
        // 传出：false 表示地址不在当前地址空间内（调用方应先走 setAddressSpace 或
        //       NavStatus::NeedsScopeSwitch 的处理，不会在这里静默失败后一无所知）。
        // align：显式打开范围用 Top；历史/查找等内部导航默认保留 Nearest，
        // 不把键盘就近移动与打开模块起点的首屏政策混成同一种滚动行为。
        bool jumpTo(std::uint64_t address, std::uint64_t selectLength = 1,
            HexCanvas::ScrollAlign align = HexCanvas::ScrollAlign::Nearest);

        // openFind / closeFindBar：查找条显隐，Esc/F3 规则照抄 HexView.Panels.cpp
        // （ux.md §0 第 2 条），本类自行实现，不经由 HexView。
        void openFind();
        void closeFindBar();

        // rereadWindow（Wave 3 wpJ5 新增，任务书允许的增量③）：对"基线窗口 ∪
        // 可见页"这一段地址范围调用 pageProvider_->rereadByteRange 做一次原位
        // 重读——不走 HexCanvas::refresh()（那会清空整个页缓存、丢掉 previous
        // 使青色高亮失效，只应该用在真正"换目标"的场合，见 HexCanvas.h 对
        // refresh() 的说明与 WorkbenchPageProvider.h 对 rereadByteRange 的
        // 说明）。供装配层（MemoryWorkbenchView）在 F5/实时刷新定时器/写事务
        // 提交后的局部重读三个场景统一调用，不需要调用方自己算范围。
        // 三条管线任一缺失（尤其 pageProvider_ 为空）或当前没有任何可重读的
        // 范围（既没有基线窗口、也从未收到过画布的可见范围通知）时是空操作，
        // 不崩溃。
        void rereadWindow();

        // ------------------------------------------------------------
        // 行宽偏好与"视图"菜单（十六进制画布自适应）
        // ------------------------------------------------------------
        // 画布默认**不是**自适应（HexCanvas::isAutoBytesPerRow() 初值为假），本类构造时也不打开它：
        // 只有装配层在 loadSettings 路径里经 setRowWidthPreference 打开，所以不走 loadSettings 的
        // 宿主/夹具仍是固定 16 字节行宽。

        // setRowWidthPreference：应用一份行宽偏好。
        // 传入：automatic 为真 -> 打开画布的自适应行宽，manualBytes 只作为"用户上次手选的值"记下来
        //       （manualBytesPerRow() 读回，不立即应用）；为假 -> 把画布固定为 manualBytes（8/16/32/48/64，
        //       非法值忽略并沿用已记下的手选值）。
        void setRowWidthPreference(bool automatic, int manualBytes);

        // rowWidthAutomatic：画布当前是否处于自适应行宽。
        bool rowWidthAutomatic() const;

        // manualBytesPerRow：用户上次手动选的行宽（默认 16）。自适应期间画布的实际行宽会随窗口变化，
        // 但这个值不变——保存设置时用它判断"自动状态不得覆盖用户上次手选值"。
        int manualBytesPerRow() const;

        // rebuildViewMenu：把"视图"菜单（行宽 自动/8/16/32/48/64、分组 1/2/4/8、字号 放大/缩小/恢复）
        // 的内容重建进 menu（先清空），并显式设置不透明的主题静态色样式、开启悬停提示。
        // 用法：装配层把一个 QMenu 设给工具按钮，并在它的 aboutToShow 里调用本函数（每次弹出都按当前
        //       状态与主题重建）。选中某项直接作用于画布，不经任何确认。定义在 WorkbenchHexPane.ViewMenu.cpp。
        void rebuildViewMenu(QMenu* menu);

        // viewButtonBadgeText / viewButtonToolTip：视图菜单按钮上的徽标文字与悬停说明。
        // 徽标：自适应时是"自动"，否则是当前每行字节数（如 "32"）；悬停说明写明含义与当前值。
        // 文字都已经过 ks::i18n::sourceText 翻译（按钮是自绘控件，运行期整树扫描够不到，必须在源头翻译）。
        // 画布行宽模式变化（rowWidthModeChanged）后装配层应重新取一次。
        QString viewButtonBadgeText() const;
        QString viewButtonToolTip() const;

        // minimumSizeHint（Wave 3 分割比例修复新增，任务书增量④的配套修复）：
        // 不把分割条内部各面板的最小尺寸要求（尤其是解释器面板约 260px 的
        // 硬性最小宽度，见 HexInspectorPanel::minimumSizeHint）向上传播成本类、
        // 进而是宿主顶层窗口的"硬性最小窗口尺寸"。QWidget 默认行为是把
        // minimumSizeHint 委托给自己的 layout()（这里是 root_），而 root_ 里的
        // splitter_ 的 minimumSizeHint 恒等于"两个面板各自最小宽度之和"——这与
        // 调用 splitter_->setSizes(...) 是否发生过无关，是 QSplitter 的固有
        // 行为，只是在本类从未显式 setSizes 之前这条尺寸链路可能从未被
        // Qt 真正查询/缓存过。画布本身支持横向滚动，宿主窗口理应可以被用户
        // 拖得比"解释器硬下限+画布半行下限"还窄，由画布自己承担内容裁切/
        // 滚动——不应该让整个宿主窗口因为本类内部某个面板的尺寸偏好而被钉在
        // 一个较大的下限上拖不动（夹具 wpJ6 的会话条换行回归测试实测抓到过
        // 这条链路：装上 WorkbenchHexPane 之后宿主视图再也拖不进很窄的宽度）。
        QSize minimumSizeHint() const override;

    protected:
        // showEvent / resizeEvent（Wave 3 分割比例修复新增，任务书允许的增量
        // ④）：只在"用户还没手动拖过分割条"时，重算一次解释器面板的初始
        // 宽度——首次显示（construct 之后分割条真实宽度此刻才第一次非零）
        // 与窗口随后被缩放（宿主/测试调用 resize）都要能让面板宽度跟着重新
        // 收敛到合理比例，而不是停留在构造期算出的旧值。具体算法见
        // applyInitialSplitterSizes() 的实现处注释（WorkbenchHexPane.Panels.cpp）。
        // 不使用定时器猜测"布局何时稳定"：showEvent/resizeEvent 触发时分割条
        // 的 width() 已经是 Qt 事件分发前一刻算好的真实布局结果，可以直接读。
        void showEvent(QShowEvent* event) override;
        void resizeEvent(QResizeEvent* event) override;

    signals:
        // insertionPointChanged：插入点变化（转发画布 caretMoved），装配层据此刷新
        // 侧栏/状态条/Ctrl+D 的目标地址等。
        void insertionPointChanged(quint64 address);
        // editRejected：转发画布的编辑拒绝原因，装配层显示在状态条。
        void editRejected(const QString& reason);
        // contextMenuAboutToShow：转发画布的右键菜单扩展点（添加到地址簿、写入字符串
        // 等菜单项由装配层在这里追加，见 ux.md §4.1）。
        void contextMenuAboutToShow(QMenu* menu, quint64 address, bool hasByte);
        // rowWidthModeChanged：转发画布同名信号（行宽或自适应/手动模式任一变化就发）。
        // 装配层据此刷新"视图"菜单按钮的徽标与悬停说明；可能多发（首次显示前后），订阅者须幂等。
        void rowWidthModeChanged(int bytesPerRow, bool automatic);

    private slots:
        // onCanvasVisibleRangeChanged / onCanvasCaretMoved：驱动 baselineFeeder_->noteDirty。
        void onCanvasVisibleRangeChanged(quint64 first, quint64 last);
        void onCanvasCaretMoved(quint64 address);
        // onCanvasContentChanged：转发给 inspector_（inspector 自己订阅画布信号，这里
        // 只是本类自己也需要知道"内容可能变了"去驱动 WriteController::notifyWindowMayCover）。
        void onCanvasContentChanged();
        // onBaselineRefreshed：WorkbenchBaselineFeeder::baselineRefreshed 的槛，调用
        // canvas_->notifyOverlayChanged()（见 HexCanvas.h"四之二"）。
        void onBaselineRefreshed(quint64 baseAddress, quint64 length);

        // onSplitterMoved（支撑增量④）：用户真的拖动了分割条（QSplitter::
        // splitterMoved 只在手柄被拖拽时发出，代码调用 setSizes 不会触发它），
        // 之后 applyInitialSplitterSizes() 永久不再改写用户已经摆好的比例。
        void onSplitterMoved(int pos, int index);

    private:
        // buildUi：构造分割条、画布、解释器面板、查找条的布局；构造函数里调用一次。
        void buildUi();

        // applyInitialSplitterSizes（支撑增量④）：给解释器面板一块合理的初始
        // 宽度，画布占其余；splitterSizesUserAdjusted_ 为真或分割条宽度此刻仍是
        // 0（尚未真正布局）时什么都不做。算法与各项边界见 .Panels.cpp 实现处
        // 的详细注释。
        void applyInitialSplitterSizes();

        // overlay_：唯一一份暂存叠加层，值成员（见文件头）。
        ksword::memwb::MemoryDiffOverlay overlay_;
        // canvas_ / inspector_ / findBar_：子控件，均拥有（parent 关系释放）。
        HexCanvas* canvas_ = nullptr;
        HexInspectorPanel* inspector_ = nullptr;
        HexFindBar* findBar_ = nullptr;
        QSplitter* splitter_ = nullptr;
        QVBoxLayout* root_ = nullptr;
        // pageProvider_ / baselineFeeder_ / writeController_：均非拥有，由
        // MemoryWorkbenchView 创建并注入；QPointer 自动探活，防止装配顺序问题导致
        // 的悬空指针解引用。
        QPointer<WorkbenchPageProvider> pageProvider_;
        QPointer<WorkbenchBaselineFeeder> baselineFeeder_;
        QPointer<WorkbenchWriteController> writeController_;
        // hasAddressSpace_：当前是否已经 setAddressSpace 过（供 jumpTo/insertionAddress
        // 在无目标时给出一致的"无数据"行为）。
        bool hasAddressSpace_ = false;
        // 空间操作与导航分别领票据：新空间使旧导航失效，但允许新空间里同步导航，
        // 安装空间外层仍可为同一来源完成身份/基线收尾，不覆盖最新选区或视口。
        std::uint64_t spaceRevision_ = 0;
        std::uint64_t navigationRevision_ = 0;

        // sourceRevisionProvider_（支撑增量②）：setSourceRevisionProvider 注入的
        // 回调；未设置时为空，调用处一律判空后退回 0，不解引用空 std::function。
        std::function<std::uint64_t()> sourceRevisionProvider_;

        // lastVisibleFirst_ / lastVisibleLast_ / hasVisibleRange_（支撑增量③）：
        // 画布最近一次 visibleRangeChanged 报告的可见地址闭区间缓存，供
        // rereadWindow() 计算"基线窗口 ∪ 可见页"时使用，避免新增一个只为了这一
        // 个用途的 HexCanvas 公开查询。setAddressSpace/clearAddressSpace 会把
        // hasVisibleRange_ 重置为 false（旧目标的可见范围对新目标没有意义）；
        // 画布随后会在 setAddressSpace 内部同步重新发一次 visibleRangeChanged
        // （只要新地址空间非空），这三个成员会在那一刻被重新填入新目标的值。
        std::uint64_t lastVisibleFirst_ = 0;
        std::uint64_t lastVisibleLast_ = 0;
        bool hasVisibleRange_ = false;

        // lastAnchor_（支撑增量①的 jobLanded 接线）：最近一次真正驱动过
        // baselineFeeder_->noteDirty 的锚点（插入点或视口中心，取决于触发它的
        // 是 caretMoved 还是 visibleRangeChanged）。页请求落地（jobLanded）时
        // 必须复用这个值重新 noteDirty，不能改用 insertionAddress()——纯滚动
        // （插入点没动）场景下 insertionAddress() 还是旧值，会把"刚刚滚动到的
        // 视口中心"这个锚点在页落地的那一刻覆盖回旧插入点，窗口因此跟不上
        // 纯滚动（已用 wpJ5_tests.Baseline.cpp 的 TestScrollOnlyFollowsViaVisibleRangeAnchor
        // 实测抓到）。
        std::uint64_t lastAnchor_ = 0;

        // splitterSizesUserAdjusted_（支撑增量④）：用户是否已经手动拖动过分割
        // 条。一旦为真，showEvent/resizeEvent 驱动的 applyInitialSplitterSizes()
        // 永久跳过——"用户摆好的比例"优先于"程序认为合理的默认比例"，不能在
        // 用户拖完之后下一次 resize 又被程序悄悄改回去。
        bool splitterSizesUserAdjusted_ = false;

        // manualBytesPerRow_：用户上次手动选的行宽（默认 16）。由画布的 rowWidthModeChanged（automatic 为假）
        // 与 setRowWidthPreference 更新；自适应期间画布实际行宽随窗口变化，本值不变。
        int manualBytesPerRow_ = 16;
        bool externalBrowseMode_ = false;
    };
}
