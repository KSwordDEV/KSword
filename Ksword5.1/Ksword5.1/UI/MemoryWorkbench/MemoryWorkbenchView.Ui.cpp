// ============================================================
// MemoryWorkbenchView.Ui.cpp
// 作用：
// - buildUi()：搭建会话条｜地址条｜子页签｜主体（QStackedWidget）｜侧栏（地址簿+
//   int3 补丁，QSplitter）｜状态条的完整布局（ux.md §1），并把三条管线
//   （pageProvider_/baselineFeeder_/writeController_）注入 hexPane_。
// - connectPipelineSignals()：管线信号 → 状态条/会话条的收尾反应。
// - connectPanelSignals()：会话条/地址簿/int3/十六进制子页/三个只读子页的信号
//   接到对应处理函数（处理函数本体在 .Session.cpp/.Nav.cpp）。
// - 窄窗口（Wave 3 复核修复，第二轮复核更正）：
//   ① root 的 QLayout::SetNoConstraint（见下方 buildUi）防止 mainSplitter_ 内部
//      子控件的尺寸偏好被 Qt 自动回灌成本类的硬性 QWidget::minimumSize()——没有它，
//      窗口会被钉在约 628px 的最小宽度上，根本缩不窄。早先"会话条高度恒为 36"的
//      读数正是这个原因（窗口没有变窄，会话条当然不换行），而不是 Qt 的
//      heightForWidth 委托链失效——这条归因已被第二轮复核推翻：把
//      updateSessionBarHeightForWidth 与 sessionBar_ 的 setHeightForWidth(true) 一起
//      撤掉，完整夹具套件仍然全绿，即这两处当前没有可观测效果。
//   ② 侧栏可见性由 maybeAutoCollapseSidebar 统一裁决，偏好宽度由
//      applySidebarWidthIfPossible 在分割条有真实宽度之后落地。
//   ③ 窄宽度（< kSidebarAutoCollapseWidth）下由 updateSidebarWidthCap 给主体留底：用户手动展开
//      侧栏时，侧栏的 minimumSizeHint（约 244px）不再把十六进制画布挤到 1px
//      （wpJ6_tests.Narrow.cpp）。注意这里不是 SetDefaultConstraint 回灌：它只作用于顶层窗口，
//      侧栏容器是子控件（变异实测：对它再加 SetNoConstraint 没有任何差别，所以没加）。
//      仍然存在、但低于任何实际使用宽度的下限：分段钮 HexViewSegmented 是固定宽度（约 170px），
//      文本子页的工具钮在 ≤240px 时越界几个像素。
//   WorkbenchSessionBar 内部用 FlowLayout 作自己的顶层布局，FlowLayout 正确实现了
//   hasHeightForWidth()/heightForWidth()（见 FlowLayout.cpp 文件头）；保留
//   heightForWidth 相关两处是为了让"遵守该协议"的宿主在会话条换行时拿到正确高度。
// ============================================================

#include "MemoryWorkbenchView.h"
#include "MemoryWorkbenchView.Internal.h"

#include "AddressBookPanel.h"
#include "HexViewWidgets.h"
#include "Int3PatchPanel.h"
#include "WorkbenchBaselineFeeder.h"
#include "WorkbenchCompareView.h"
#include "WorkbenchConfirmations.h"
#include "WorkbenchDiagnosticsHost.h"
#include "WorkbenchPageProvider.h"
#include "WorkbenchSessionBar.h"
#include "WorkbenchShared.h"
#include "WorkbenchStatusBar.h"
#include "WorkbenchStringWriteDialog.h"
#include "WorkbenchTextView.h"
#include "WorkbenchWriteController.h"
#include "WriteModeSwitch.h"

#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLineEdit>
#include <QResizeEvent>
#include <QShowEvent>
#include <QSizePolicy>
#include <QSplitter>
#include <QStackedWidget>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>

namespace ks::ui
{
    // buildUi：构造函数内唯一调用一次。创建顺序对应文件头"创建/销毁顺序"一节：
    // hexPane_（随后注入前四条管线）→ 三个只读子页 → 会话条/地址条/侧栏/状态条。
    void MemoryWorkbenchView::buildUi()
    {
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(6, 6, 6, 6);
        root->setSpacing(4);
        // 修复缺陷 1（根因，见文件头）：SetNoConstraint 关掉 Qt 对"子控件聚合出的
        // 最小尺寸"自动回灌成本类 QWidget::minimumSize() 的默认行为
        // （QLayout::SetDefaultConstraint）。没有这一步，mainSplitter_ 两个子控件
        // minimumSizeHint 之和（侍栏≈244 + 只读子页≈368，审核报告实测约 628）会被
        // Qt 自动写回本类的硬性最小宽度，第一次 resize() 到更窄的宽度就会被直接
        // 钉死——窄窗口夹具断言根本等不到任何后续逻辑执行。关闭后本类仍然正常
        // 参与布局（子控件的几何分配不受影响），只是不再被子控件的尺寸偏好
        // 反向锁死；窄到内容显示不全时由画布自身的横向滚动与侧栏自动折叠承担
        // （见 minimumSizeHint() 的覆盖与 maybeAutoCollapseSidebar）。
        root->setSizeConstraint(QLayout::SetNoConstraint);

        // ---- 会话条 ----
        sessionBar_ = new WorkbenchSessionBar(this);
        {
            // 见文件头：显式声明 heightForWidth，供遵守该协议的宿主在会话条换行后
            // 取到正确高度（第二轮复核：当前夹具里撤掉它没有可观测差别）。
            QSizePolicy policy = sessionBar_->sizePolicy();
            policy.setHeightForWidth(true);
            policy.setVerticalPolicy(QSizePolicy::Preferred);
            sessionBar_->setSizePolicy(policy);
        }
        root->addWidget(sessionBar_);

        // ---- 地址条 ----
        auto* addressRow = new QHBoxLayout();
        addressRow->setSpacing(4);
        backButton_ = new QToolButton(this);
        backButton_->setIcon(QIcon(QStringLiteral(":/Icon/file_nav_back.svg")));
        // 本项目不使用 Qt 的 tr()：标准控件文本直接写中文源文本，运行期全局
        // 扫描会翻译（见 AGENTS.md / .claude/memory 的 i18n 审计规则）。
        backButton_->setToolTip(QStringLiteral("回到上一个地址（Alt+Left）"));
        KswordTheme::ApplyCompactIconButtonMetrics(backButton_);
        forwardButton_ = new QToolButton(this);
        forwardButton_->setIcon(QIcon(QStringLiteral(":/Icon/file_nav_forward.svg")));
        forwardButton_->setToolTip(QStringLiteral("前进到下一个地址（Alt+Right）"));
        KswordTheme::ApplyCompactIconButtonMetrics(forwardButton_);
        addressEdit_ = new QLineEdit(this);
        addressEdit_->setPlaceholderText(QStringLiteral("地址或表达式：0x7FF6…、client.dll+1A40、[ptr]"));
        rerouteButton_ = new QToolButton(this);
        // 第二轮复核 B6：状态条提示写的是「切换并跳转」，按钮必须真的显示这几个字
        // （图标+文字），图标也不能与"前进"钮相同（旧实现两者同为 file_nav_forward，
        // 且 IconOnly 样式下文字不显示、悬停说明为空）。
        rerouteButton_->setIcon(QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")));
        rerouteButton_->setText(QStringLiteral("切换并跳转"));
        rerouteButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        rerouteButton_->setToolTip(QStringLiteral("该地址位于其它范围：点击后切换到对应范围并跳转（不会自动切换）"));
        rerouteButton_->setVisible(false);
        rereadButton_ = new QToolButton(this);
        rereadButton_->setObjectName(QStringLiteral("ksMemwbRereadButton"));
        rereadButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        rereadButton_->setToolTip(QStringLiteral("用「当前通道」重读窗口（F5）；与上次读取不同的字节标青色"));
        // 真机反馈"右边几个图标钮意义不明"：重读/实时刷新/侧栏都带上文字标签（图标 + 文字），
        // 只有窗口很窄时才退成纯图标（见 updateAddressRowLabels）。固定高度、宽度随文字。
        rereadButton_->setText(QStringLiteral("重读"));
        rereadButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        rereadButton_->setIconSize(KswordTheme::CompactIconSize());
        rereadButton_->setFixedHeight(KswordTheme::CompactIconButtonSize().height());
        liveRefreshCheckBox_ = new QCheckBox(this);
        liveRefreshCheckBox_->setIcon(QIcon(QStringLiteral(":/Icon/process_resume.svg")));
        liveRefreshCheckBox_->setText(ks::i18n::sourceText(QStringLiteral("实时刷新")));
        liveRefreshCheckBox_->setToolTip(QStringLiteral("每秒重读一次；磁盘传输（DDMA）通道不可用"));
        liveRefreshTimer_ = new QTimer(this);
        liveRefreshTimer_->setInterval(1000);

        // sidebarExpandButton_（修复缺陷 1）：侧栏被自动或手动折叠后唯一的展开
        // 入口；复用 ToggleSidebar 动作已登记的 memwb_bookmarks 图标，初始侧栏
        // 展开，按钮不显示（见 toggleSidebarByUser/maybeAutoCollapseSidebar）。
        sidebarExpandButton_ = new QToolButton(this);
        sidebarExpandButton_->setIcon(QIcon(QStringLiteral(":/Icon/memwb_bookmarks.svg")));
        sidebarExpandButton_->setToolTip(QStringLiteral("展开侧栏：地址簿、书签、监视、搜索结果（Ctrl+Shift+B）"));
        sidebarExpandButton_->setVisible(false);
        sidebarExpandButton_->setText(QStringLiteral("侧栏"));
        sidebarExpandButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        sidebarExpandButton_->setIconSize(KswordTheme::CompactIconSize());
        sidebarExpandButton_->setFixedHeight(KswordTheme::CompactIconButtonSize().height());

        addressRow->addWidget(backButton_);
        addressRow->addWidget(forwardButton_);
        addressRow->addWidget(addressEdit_, 1);
        addressRow->addWidget(rerouteButton_);
        addressRow->addWidget(rereadButton_);
        addressRow->addWidget(liveRefreshCheckBox_);
        addressRow->addWidget(sidebarExpandButton_);
        root->addLayout(addressRow);

        // ---- 子页签 ----
        // 四个段名经 ks::i18n::sourceText 翻译：HexViewSegmented 在 paintEvent 里
        // 自己用 QPainter 画文字（自绘控件），运行期整树扫描够不到它的私有
        // QStringList 成员，必须在源头就翻译好（AGENTS.md i18n 规则）。
        subTabSegmented_ = new HexViewSegmented(
            QStringList{
                ks::i18n::sourceText(QStringLiteral("十六进制")),
                ks::i18n::sourceText(QStringLiteral("反汇编")),
                ks::i18n::sourceText(QStringLiteral("文本")),
                ks::i18n::sourceText(QStringLiteral("对比"))},
            this);

        // 子页签那一行：左边分段钮，右边"视图"菜单钮（行宽/分组/字号，只在十六进制子页显示，
        // 不增加这一行的高度）。菜单钮是自绘图标钮，徽标显示"自动"或当前行宽；它的菜单内容、
        // 徽标刷新与显隐在 connectHexViewMenu 里接上（那时 hexPane_/subTabStack_ 才存在）。
        auto* subTabRow = new QHBoxLayout();
        subTabRow->setContentsMargins(0, 0, 0, 0);
        subTabRow->setSpacing(4);
        subTabRow->addWidget(subTabSegmented_);
        subTabRow->addStretch(1);
        hexViewMenuButton_ = new HexViewGlyphButton(HexViewGlyphButton::Glyph::RowWidth, this);
        hexViewMenuButton_->setPopupMode(QToolButton::InstantPopup);
        subTabRow->addWidget(hexViewMenuButton_);
        root->addLayout(subTabRow);

        // ---- 主体：hexPane_（随后注入三条管线）+ 三个只读子页 ----
        hexPane_ = new WorkbenchHexPane(this);
        hexPane_->setPageProvider(pageProvider_.get());
        hexPane_->setBaselineFeeder(baselineFeeder_.get());
        hexPane_->setWriteController(writeController_.get());
        hexPane_->setSourceRevisionProvider([this]() -> std::uint64_t {
            return target_ ? target_->revisions().Source() : 0ULL;
        });
        connect(hexPane_->canvas(), &HexCanvas::editStaged, writeController_.get(), &WorkbenchWriteController::onEditCompleted);

        // DisasmBytesProviderAdapter 的完整类定义只在 MemoryWorkbenchView.cpp
        // 里（头文件只前置声明），本文件（.Ui.cpp）看不到它继承
        // IWorkbenchBytesProvider 这件事，不能直接传 bytesProviderAdapter_.get()
        // 给三个子页的 setBytesProvider——改用 currentBytesProvider()，这个
        // 成员函数的*定义*在能看到完整类型的 MemoryWorkbenchView.cpp 里，返回
        // 类型本身是已经上转型好的 IWorkbenchBytesProvider*，跨 TU 调用只需要
        // 函数声明（头文件已有），不需要在这里看到派生类的完整定义。
        ensureBytesProviderAdapter();
        disasmView_ = new WorkbenchDisasmView(this);
        disasmView_->setBytesProvider(currentBytesProvider());
        textView_ = new WorkbenchTextView(this);
        textView_->setBytesProvider(currentBytesProvider());
        compareView_ = new WorkbenchCompareView(this);
        compareView_->setBytesProvider(currentBytesProvider());

        subTabStack_ = new QStackedWidget(this);
        subTabStack_->addWidget(hexPane_);
        subTabStack_->addWidget(disasmView_);
        subTabStack_->addWidget(textView_);
        subTabStack_->addWidget(compareView_);

        // ---- 侧栏：地址簿面板 + int3 补丁面板（绑定 WorkbenchShared 的共享对象） ----
        auto& shared = WorkbenchShared::Instance();
        addressBookPanel_ = new AddressBookPanel(&shared.AddressBookTable(), this);
        int3Panel_ = new Int3PatchPanel(&shared.Int3(), this);
        sidebarContainer_ = new QWidget(this);
        auto* sidebarLayout = new QVBoxLayout(sidebarContainer_);
        sidebarLayout->setContentsMargins(0, 0, 0, 0);
        sidebarLayout->setSpacing(4);
        // 窄宽度硬下限（侧栏版）：这里**不需要**像 root 那样关 SetDefaultConstraint 回灌——默认约束
        // 只会给顶层窗口写最小尺寸，侧栏容器是子控件，变异实测去掉/保留该行结果一致。真正把画布
        // 挤到 1px 的是容器的 minimumSizeHint（约 244px，含 FlowLayout/分段钮的固定宽度）：
        // QSplitter 不会把子控件压到它的 minimumSizeHint 以下。解法见 updateSidebarWidthCap
        // （窄宽度下给侧栏设宽度上限并显式落尺寸，上限会把 minimumSizeHint 一并压下来）。
        sidebarLayout->addWidget(addressBookPanel_, 1);
        sidebarLayout->addWidget(int3Panel_);

        mainSplitter_ = new QSplitter(Qt::Horizontal, this);
        mainSplitter_->addWidget(subTabStack_);
        mainSplitter_->addWidget(sidebarContainer_);
        mainSplitter_->setStretchFactor(0, 1);
        mainSplitter_->setStretchFactor(1, 0);
        mainSplitter_->setSizes(QList<int>{600, 300});
        root->addWidget(mainSplitter_, 1);

        // ---- 状态条：诊断抽屉宿主包一层 CodeEditorWidget（接口缺口 G3）----
        statusBar_ = new WorkbenchStatusBar(std::make_unique<WorkbenchDiagnosticsHost>(), this);
        root->addWidget(statusBar_);
    }

    // connectPipelineSignals：管线信号（读/基线/写）接到状态条与自身收尾逻辑。
    void MemoryWorkbenchView::connectPipelineSignals()
    {
        connect(pageProvider_.get(), &WorkbenchPageProvider::channelUnavailable, this,
            &MemoryWorkbenchView::onProviderChannelUnavailable);
        connect(pageProvider_.get(), &WorkbenchPageProvider::readFailed, this,
            [this](quint64 rev, QString text, int count) { onProviderReadFailed(rev, text, count); });
        connect(pageProvider_.get(), &WorkbenchPageProvider::scratchAreaDirtyLatched, this,
            &MemoryWorkbenchView::onProviderScratchAreaDirtyLatched);
        connect(pageProvider_.get(), &WorkbenchPageProvider::retryBlockedByLatch, this,
            &MemoryWorkbenchView::onProviderRetryBlockedByLatch);
        connect(pageProvider_.get(), &WorkbenchPageProvider::jobLanded, this,
            &MemoryWorkbenchView::onProviderJobLanded);

        // baselineRefreshed → notifyWindowMayCover（零覆盖路径，审核报告 P4
        // 探针并入后新发现的真实缺陷）：WorkbenchWriteController.PendingStage.cpp
        // 的文件头明确写着"移动窗口使之覆盖该地址是装配层（订阅
        // WorkbenchBaselineFeeder::baselineRefreshed...后调用
        // notifyWindowMayCover）的职责"——装配代码此前从未接这一条，
        // beginPendingStage 对任何真正落在窗口外的地址都只会立即尝试一次
        // （必然失败）、挂 2 秒超时后放弃，PendingStage 票据端到端链路对
        // 窗口外地址恒不可用。地址簿面板远不在可见范围之外时才会用到这条
        // 票据机制，恰好是最容易被忽略的场景。
        connect(baselineFeeder_.get(), &WorkbenchBaselineFeeder::baselineRefreshed, this,
            [this](quint64 baseAddress, quint64 length) {
                Q_UNUSED(baseAddress);
                Q_UNUSED(length);
                if (writeController_)
                {
                    writeController_->notifyWindowMayCover();
                }
            });

        connect(baselineFeeder_.get(), &WorkbenchBaselineFeeder::baselineUnavailable, this, [this](ksword::memwb::BaselineSpanStatus status) {
            Q_UNUSED(status);
            if (statusBar_ != nullptr)
            {
                // setWindowRangeText 把文本存进私有成员再和其它几段一起拼成状态
                // 条最终显示的整串文字（见 WorkbenchStatusBar::rebuildSummary），
                // 运行期整树扫描只按控件"当前整串文字"做精确匹配，拼接后的整串
                // 永远不会出现在词条表里，必须在源头就经 ks::i18n::sourceText
                // 翻译好（与 WorkbenchStatusBar.cpp 里 setReadResultText 的注释
                // 同一惯例，本项目不使用 tr()）。
                statusBar_->setWindowRangeText(ks::i18n::sourceText(QStringLiteral("该处尚未读取")));
            }
        });

        // commitFinished 携带完整 CommitReport，但 onWriteControllerCommitFinished
        // 这个槛在头文件冻结时已经定成无参（见 lastCommitReport_ 成员注释）——先把
        // 参数存一份，再调用无参槛，槛函数体从该成员读完整数据，不丢字段。
        connect(writeController_.get(), &WorkbenchWriteController::commitFinished, this,
            [this](const ksword::memwb::CommitReport& report) {
                lastCommitReport_ = report;
                onWriteControllerCommitFinished();
            });
        connect(writeController_.get(), &WorkbenchWriteController::commitFailed, this,
            [this](ksword::memwb::CommitReport report) { onWriteControllerCommitFailed(report); });
        connect(writeController_.get(), &WorkbenchWriteController::scratchAreaDirtyReported, this,
            &MemoryWorkbenchView::onWriteControllerScratchAreaDirtyReported);
        connect(writeController_.get(), &WorkbenchWriteController::pendingPatchesChanged, this,
            &MemoryWorkbenchView::onWriteControllerPendingPatchesChanged);
        connect(writeController_.get(), &WorkbenchWriteController::commitRejectedBusy, this,
            &MemoryWorkbenchView::onWriteControllerCommitRejectedBusy);
        connect(writeController_.get(), &WorkbenchWriteController::undoRedoAvailabilityChanged, this,
            &MemoryWorkbenchView::updateUndoRedoActionsEnabled);
        connect(writeController_.get(), &WorkbenchWriteController::pendingStageResolved, this,
            [this](WorkbenchWriteController::PendingStageTicket ticket, bool ok, QString reason) {
                Q_UNUSED(ticket);
                // ok 只证明补丁进入暂存层；真实写入或拒绝结果已由提交信号展示，不再覆盖为成功。
                if (!ok && statusBar_ != nullptr)
                {
                    // 同上：setWriteResultText 走私有成员+拼接，必须源头翻译；
                    // reason 是通道给的原始失败文本（用户数据），只用单个 %1，
                    // 不链式 .arg()，避免 reason 里恰好出现 "%2" 被二次替换。
                    statusBar_->setWriteResultText(
                        ks::i18n::sourceText(QStringLiteral("地址簿编辑未能写入：%1")).arg(reason));
                }
            });
    }

    // connectPanelSignals：会话条/地址簿/int3/十六进制子页/三个只读子页 → 处理函数。
    void MemoryWorkbenchView::connectPanelSignals()
    {
        connect(sessionBar_, &WorkbenchSessionBar::scopeRequested, this, &MemoryWorkbenchView::onSessionBarScopeRequested);
        connect(sessionBar_, &WorkbenchSessionBar::channelRequested, this, &MemoryWorkbenchView::onSessionBarChannelRequested);
        connect(sessionBar_, &WorkbenchSessionBar::modeRequested, this, &MemoryWorkbenchView::onSessionBarModeRequested);
        connect(sessionBar_, &WorkbenchSessionBar::applyRequested, this, &MemoryWorkbenchView::onSessionBarApplyRequested);
        connect(sessionBar_, &WorkbenchSessionBar::discardRequested, this, &MemoryWorkbenchView::onSessionBarDiscardRequested);
        connect(sessionBar_, &WorkbenchSessionBar::pickTargetRequested, this, &MemoryWorkbenchView::onSessionBarPickTargetRequested);
        connect(target_.get(), &WorkbenchTarget::livenessChanged, this, [this](const int state) {
            if (!memoryDebugMode_ || state != static_cast<int>(LivenessState::Exited))
            {
                return;
            }
            // 退出身份的在途回调变旧并取消，已有显示内容保留而不再触发新 I/O。
            pageProvider_->cancelAllInFlight();
            cancelPointerChainResolution();
            hexPane_->setEditable(false);
            disasmView_->setEditable(false);
            liveRefreshTimer_->stop();
            liveRefreshCheckBox_->setChecked(false);
            refreshChannelGateDisplay();
            statusBar_->setReadResultText(ks::i18n::sourceText(
                QStringLiteral("目标进程已退出，当前内容为过期快照")), true);
        });

        connect(addressBookPanel_, &AddressBookPanel::jumpRequested, this, &MemoryWorkbenchView::onAddressBookJumpRequested);
        connect(addressBookPanel_, &AddressBookPanel::pointerChainCreateRequested, this, &MemoryWorkbenchView::onPointerChainCreateRequested);
        connect(addressBookPanel_, &AddressBookPanel::pointerChainEditRequested, this, &MemoryWorkbenchView::onPointerChainEditRequested);
        connect(addressBookPanel_, &AddressBookPanel::pointerChainResolveRequested, this, &MemoryWorkbenchView::onPointerChainResolveRequested);
        connect(addressBookPanel_, &AddressBookPanel::pointerChainCancelRequested, this, &MemoryWorkbenchView::cancelPointerChainResolution);
        connect(addressBookPanel_, &AddressBookPanel::openDisassemblyRequested, this,
            &MemoryWorkbenchView::onAddressBookOpenDisassemblyRequested);
        connect(addressBookPanel_, &AddressBookPanel::valueEditRequested, this,
            [this](quint64 id, ksword::memwb::ValueType type, QString text) {
                onAddressBookValueEditRequested(id, type, text);
            });
        connect(addressBookPanel_, &AddressBookPanel::promoteRequested, this,
            &MemoryWorkbenchView::onAddressBookPromoteRequested);
        connect(addressBookPanel_, &AddressBookPanel::removeRequested, this, &MemoryWorkbenchView::onAddressBookRemoveRequested);
        // clearSearchResultsRequested：地址簿自身的记录操作（不涉及目标内存读写，
        // 见 AddressBookPanel.h 文件头"唯二的例外"一节之外的第三个例外——清空搜索
        // 结果同样只动地址簿自己的存档），直接调用共享 Store，不必像写内存那样
        // 经过写事务。
        connect(addressBookPanel_, &AddressBookPanel::clearSearchResultsRequested, this, []() {
            WorkbenchShared::Instance().AddressBook().clearSearchResults();
        });

        connect(int3Panel_, &Int3PatchPanel::resultMessage, this, &MemoryWorkbenchView::onInt3ResultMessage);
        // 面板操作账本"当前目标"之前先把本视图的会话声明为当前目标（直接连接，同步执行）。
        connect(int3Panel_, &Int3PatchPanel::aboutToAct, this, &MemoryWorkbenchView::syncInt3Context,
            Qt::DirectConnection);
        const QPointer<MemoryWorkbenchView> pointerView(this);
        int3Panel_->SetInstallValidationCallback([pointerView](std::uint64_t address, QString& reason) {
            if (!pointerView || !pointerView->target_) return false;
            const auto session = pointerView->target_->session();
            if (!pointerView) return false;
            std::string failure;
            const bool allowed = pointerView->validatePointerChainWrite(session, address, 1, failure);
            reason = QString::fromUtf8(failure.c_str());
            return allowed;
        });

        connect(hexPane_, &WorkbenchHexPane::insertionPointChanged, this, &MemoryWorkbenchView::onHexPaneInsertionPointChanged);
        connect(hexPane_, &WorkbenchHexPane::editRejected, this, &MemoryWorkbenchView::onHexPaneEditRejected);
        connect(hexPane_, &WorkbenchHexPane::contextMenuAboutToShow, this, &MemoryWorkbenchView::onHexPaneContextMenuAboutToShow);

        // 子页自动跳转：切到反汇编/文本/对比页时跟随十六进制的选区起点（或起始模块）；画布内容变化
        // （页回填/暂存/换代次/基线喂入）时刷新当前可见的那一页。规则见 MemoryWorkbenchView.SubPages.cpp。
        connect(subTabStack_, &QStackedWidget::currentChanged, this, &MemoryWorkbenchView::onSubTabChanged);
        connect(hexPane_->canvas(), &HexCanvas::contentChanged, this, &MemoryWorkbenchView::onSubPageDataChanged);

        connect(disasmView_, &WorkbenchDisasmView::stageRequested, this, &MemoryWorkbenchView::onDisasmStageRequested);
        connect(disasmView_, &WorkbenchDisasmView::requestHexLocate, this, &MemoryWorkbenchView::onDisasmRequestHexLocate);

        connect(subTabSegmented_, &HexViewSegmented::currentIndexChanged, subTabStack_, &QStackedWidget::setCurrentIndex);
        connect(subTabStack_, &QStackedWidget::currentChanged, subTabSegmented_, &HexViewSegmented::setCurrentIndex);
        connectHexViewMenu();
        connectRowCanvasSignals();

        connect(addressEdit_, &QLineEdit::returnPressed, this, &MemoryWorkbenchView::onAddressBarReturnPressed);
        connect(backButton_, &QToolButton::clicked, this, &MemoryWorkbenchView::onGoBackRequested);
        connect(forwardButton_, &QToolButton::clicked, this, &MemoryWorkbenchView::onGoForwardRequested);
        connect(rerouteButton_, &QToolButton::clicked, this, &MemoryWorkbenchView::onRerouteButtonClicked);
        connect(rereadButton_, &QToolButton::clicked, this, [this]() { if (hexPane_) hexPane_->rereadWindow(); });
        connect(liveRefreshTimer_, &QTimer::timeout, this, [this]() {
            if (hexPane_ != nullptr)
            {
                hexPane_->rereadWindow();
            }
        });
        connect(liveRefreshCheckBox_, &QCheckBox::toggled, this, [this](bool checked) {
            if (checked && target_ && target_->session().channel != ksword::memwb::Channel::Ddma)
            {
                liveRefreshTimer_->start();
            }
            else
            {
                liveRefreshTimer_->stop();
            }
        });
        connect(statusBar_, &WorkbenchStatusBar::rereadRequested, this, [this]() { if (hexPane_) hexPane_->rereadWindow(); });
        connect(statusBar_, &WorkbenchStatusBar::scratchDirtyAcknowledged, this, [this]() {
            // 常驻红 chip 只能用户点 × 才消，本类不需要额外动作——点击本身已经
            // 在 WorkbenchStatusBar 内部完成（不变式 14），这里留空占位，方便
            // 日后需要同步清理别处状态时有现成的接线点。
        });

        // sidebarExpandButton_（修复缺陷 1）：与 Ctrl+Shift+B 共用同一个切换入口。
        connect(sidebarExpandButton_, &QToolButton::clicked, this, &MemoryWorkbenchView::toggleSidebarByUser);
    }

    // ------------------------------------------------------------
    // 修复缺陷 1：窄窗口 heightForWidth 真正生效 + 侧栏自动折叠
    // ------------------------------------------------------------

    // resizeEvent：见头文件声明处的注释。几件事都是"主动量一次、手动应用结果"，
    // 不依赖 Qt 内部的 heightForWidth 委托链或自动最小尺寸回灌。
    // 顺序有讲究：先裁决侧栏可见性，再落偏好宽度（隐藏的侧栏不落宽度）。
    // Qt 在把 Resize 事件交给本类之前，已经让本类的布局给子控件设好了新几何，所以
    // 这里读到的 mainSplitter_->width() 是新宽度。
    void MemoryWorkbenchView::resizeEvent(QResizeEvent* event)
    {
        QWidget::resizeEvent(event);
        updateSessionBarHeightForWidth();
        maybeAutoCollapseSidebar();
        applySidebarWidthIfPossible();
        maybeAutoCollapseInspector();
        updateAddressRowLabels();
    }

    // updateAddressRowLabels：见头文件声明处的注释。
    void MemoryWorkbenchView::updateAddressRowLabels()
    {
        const bool compact = width() < kAddressRowLabelsMinWidth;
        const Qt::ToolButtonStyle wantedStyle =
            compact ? Qt::ToolButtonIconOnly : Qt::ToolButtonTextBesideIcon;
        for (QToolButton* const button : {rereadButton_, sidebarExpandButton_})
        {
            if (button == nullptr)
            {
                continue;
            }
            if (button->toolButtonStyle() != wantedStyle)
            {
                button->setToolButtonStyle(wantedStyle);
            }
            // 纯图标时回到紧凑方块的宽度；带文字时宽度交给文字（取消固定宽度）。
            if (compact)
            {
                button->setFixedWidth(KswordTheme::CompactIconButtonSize().width());
            }
            else
            {
                button->setMinimumWidth(0);
                button->setMaximumWidth(QWIDGETSIZE_MAX);
            }
        }
        if (liveRefreshCheckBox_ != nullptr)
        {
            // 文字走 sourceText：运行期切语言后这里重设的文字也是当前语言的。
            const QString wantedText = compact ? QString() : ks::i18n::sourceText(QStringLiteral("实时刷新"));
            if (liveRefreshCheckBox_->text() != wantedText)
            {
                liveRefreshCheckBox_->setText(wantedText);
            }
        }
    }

    // showEvent：视图被显示（页签切到前台、窗口首次弹出）时，把本视图的会话重新声明为
    // int3 账本的当前目标，见头文件声明处的注释。
    void MemoryWorkbenchView::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        syncInt3Context();
    }

    // changeEvent：窗口激活变化时重新声明一次。内嵌进程详情窗口与主窗口同时可见时，
    // 用户点到哪个窗口，面板上的 int3 操作就应该作用在哪个窗口的目标上。
    void MemoryWorkbenchView::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event != nullptr && event->type() == QEvent::ActivationChange && isActiveWindow())
        {
            syncInt3Context();
        }
    }

    // updateSessionBarHeightForWidth：见头文件声明处的注释。直接问会话条自己的
    // 顶层布局（FlowLayout）在当前宽度下要多高，显式 setMinimumHeight 上去；
    // root（外层 QVBoxLayout）下一次 setGeometry 会按"至少给这么高"分配空间，
    // 换行多出来的那一行不会再被压扁/裁掉。
    void MemoryWorkbenchView::updateSessionBarHeightForWidth()
    {
        if (sessionBar_ == nullptr || sessionBar_->layout() == nullptr)
        {
            return;
        }
        QLayout* const flow = sessionBar_->layout();
        if (!flow->hasHeightForWidth())
        {
            return;
        }
        const int width = sessionBar_->width();
        if (width <= 0)
        {
            return;
        }
        const int hfw = flow->totalHeightForWidth(width);
        if (hfw > 0 && sessionBar_->minimumHeight() != hfw)
        {
            sessionBar_->setMinimumHeight(hfw);
        }
    }

    // maybeAutoCollapseSidebar：见头文件声明处的注释——侧栏可见性的唯一裁决入口。
    // 显示 = 想要可见 且 (用户手动决定过 或 窗口够宽)；内嵌模式恒隐藏且不给展开钮。
    // 展开钮可见 = 侧栏隐藏 且 非内嵌（它是隐藏时唯一的展开入口）。
    void MemoryWorkbenchView::maybeAutoCollapseSidebar()
    {
        if (sidebarContainer_ == nullptr)
        {
            return;
        }
        const bool show = !embedded_ && sidebarWantedVisible_
            && (sidebarUserOverride_ || width() >= kSidebarAutoCollapseWidth);
        // 用 isHidden() 而不是 isVisible()：顶层窗口还没 show() 过时 isVisible()
        // 恒为 false，与"此刻应不应该显示"这件事无关（仓库已知坑）。
        if (show == sidebarContainer_->isHidden())
        {
            sidebarContainer_->setVisible(show);
            if (show)
            {
                // 刚从隐藏变回可见：分割条要把偏好宽度重新落一次（宽度可能从未落过，
                // 或隐藏期间窗口尺寸变了）。
                sidebarWidthApplied_ = false;
            }
        }
        if (sidebarExpandButton_ != nullptr)
        {
            sidebarExpandButton_->setVisible(!embedded_ && sidebarContainer_->isHidden());
        }
        // 可见性定下来之后再裁决侧栏的宽度上限：上限只在"窄宽度且侧栏可见"时存在。
        updateSidebarWidthCap();
    }

    // updateSidebarWidthCap：见头文件声明处的注释。
    // 窄宽度（< kSidebarAutoCollapseWidth）下侧栏只会因为用户手动展开而可见；此时给主体留底：
    // 主体至少拿到 min(kMinMainBodyWidth, 可用宽度的一半)，侧栏被限制在剩下的宽度内（它的内容
    // 放不下就被裁掉，比把画布压成 1px 更可用）。宽屏（>= 760）不加任何上限——用户拖分割条的
    // 自由保持原样。窗口重新变宽、上限解除时，侧栏要回到偏好宽度，所以把 sidebarWidthApplied_
    // 复位让 applySidebarWidthIfPossible 再落一次。
    void MemoryWorkbenchView::updateSidebarWidthCap()
    {
        if (sidebarContainer_ == nullptr || mainSplitter_ == nullptr || layout() == nullptr)
        {
            return;
        }
        const bool narrow = width() < kSidebarAutoCollapseWidth;
        int cap = QWIDGETSIZE_MAX;
        if (narrow && !sidebarContainer_->isHidden())
        {
            const QMargins margins = layout()->contentsMargins();
            const int total = width() - margins.left() - margins.right();
            const int floor = std::min(kMinMainBodyWidth, total / 2);
            cap = std::max(1, total - mainSplitter_->handleWidth() - floor);
        }
        const bool wasCapped = sidebarContainer_->maximumWidth() != QWIDGETSIZE_MAX;
        if (sidebarContainer_->maximumWidth() != cap)
        {
            sidebarContainer_->setMaximumWidth(cap);
        }
        if (cap != QWIDGETSIZE_MAX)
        {
            // 只改最大宽度不够：QSplitter 重新布局时沿用它已记住的各子控件尺寸（实测侧栏仍保持 300，
            // 超出上限，主体照样被挤到 1px；刚从隐藏变可见时它记的尺寸还是旧值/0，同样不会自己收回），
            // 必须显式落一次尺寸：侧栏取"已有宽度（在上限内且非 0）"，否则取 min(上限, 偏好宽度)，
            // 剩下的全部还给主体。
            const QList<int> sizes = mainSplitter_->sizes();
            const int current = sizes.size() == 2 ? sizes.at(1) : 0;
            const int target = (current > 0 && current <= cap) ? current : std::min(cap, sidebarPreferredWidth_);
            const int mainWidth = std::max(0, mainSplitter_->width() - mainSplitter_->handleWidth() - target);
            if (sizes.size() != 2 || sizes.at(0) != mainWidth || current != target)
            {
                mainSplitter_->setSizes(QList<int>{mainWidth, target});
            }
        }
        if (wasCapped && cap == QWIDGETSIZE_MAX)
        {
            sidebarWidthApplied_ = false;
        }
    }

    // applySidebarWidthIfPossible：见头文件声明处的注释。
    void MemoryWorkbenchView::applySidebarWidthIfPossible()
    {
        if (mainSplitter_ == nullptr || sidebarContainer_ == nullptr
            || sidebarContainer_->isHidden() || sidebarWidthApplied_)
        {
            return;
        }
        const int total = mainSplitter_->width();
        const int sidebarWidth = sidebarPreferredWidth_;
        const int handle = mainSplitter_->handleWidth();
        // 分割条还没有真实宽度（show 之前）或放不下"偏好宽度 + 最小主体"：本次放弃，
        // 等后面的 resizeEvent 再试；绝不用未布局的宽度做减法（会出负数，Qt 把负数
        // 当 0，结果是侧栏占满、主体 0px）。
        if (total < sidebarWidth + handle + kMinMainBodyWidth)
        {
            return;
        }
        mainSplitter_->setSizes(QList<int>{total - sidebarWidth - handle, sidebarWidth});
        sidebarWidthApplied_ = true;
    }

    // toggleSidebarByUser：见头文件声明处的注释。用户手动切换 = "想要可见"翻转，
    // 并从此不再受窗口宽度影响；落地交给统一裁决入口。
    void MemoryWorkbenchView::toggleSidebarByUser()
    {
        if (sidebarContainer_ == nullptr || embedded_)
        {
            return;
        }
        sidebarUserOverride_ = true;
        sidebarWantedVisible_ = sidebarContainer_->isHidden();
        maybeAutoCollapseSidebar();
        applySidebarWidthIfPossible();
    }

    // refreshPendingPatchesDisplay：见头文件声明处的注释。
    void MemoryWorkbenchView::refreshPendingPatchesDisplay()
    {
        if (sessionBar_ == nullptr || hexPane_ == nullptr)
        {
            return;
        }
        sessionBar_->setPendingPatches(
            hexPane_->overlay().PendingByteCount(),
            static_cast<quint64>(hexPane_->overlay().DiffBlocks().size()));
    }

    // clearScopeSwitchPrompt：见头文件声明处的注释。
    void MemoryWorkbenchView::clearScopeSwitchPrompt()
    {
        pendingScopeSwitchRequest_.reset();
        if (rerouteButton_ != nullptr)
        {
            rerouteButton_->setVisible(false);
        }
    }

    // maybeAutoCollapseInspector：见头文件声明处的注释。
    void MemoryWorkbenchView::maybeAutoCollapseInspector()
    {
        if (hexPane_ == nullptr || hexPane_->inspector() == nullptr || inspectorUserOverride_)
        {
            return;
        }
        const bool shouldCollapse = width() < kSidebarAutoCollapseWidth;
        if (shouldCollapse == hexPane_->inspector()->isHidden())
        {
            return;
        }
        hexPane_->inspector()->setVisible(!shouldCollapse);
    }

    // minimumSizeHint：见头文件声明处的注释——与 WorkbenchHexPane::minimumSizeHint
    // 同一处理方式，故意返回一个很小的固定值，不把 mainSplitter_ 内部两个子
    // 控件此刻的尺寸偏好向外传播成宿主的硬性下限。
    QSize MemoryWorkbenchView::minimumSizeHint() const
    {
        return QSize(1, 1);
    }
}
