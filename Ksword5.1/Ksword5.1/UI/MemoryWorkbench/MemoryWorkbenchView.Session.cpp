// ============================================================
// MemoryWorkbenchView.Session.cpp
// 作用：
// - 会话变化的两条分支（handleIdentityChange/handleReloadOnly）、离开写路径的
//   安全网（onTargetAboutToDetach）、写入反馈 W4（commitFinished/commitFailed/
//   scratchAreaDirtyReported/pendingPatchesChanged/commitRejectedBusy）、会话条
//   请求→裁决→回写（scope/channel/mode/apply/discard）、地址簿与 int3 面板的
//   转发、Gate/读反馈（provider 的四个信号）、以及它们共用的几个刷新函数
//   （refreshChannelGateDisplay/refreshStatusBarChannelScopeText/
//   refreshProtectionDisplay/refreshConfirmationsAndSuppression/
//   refreshTargetDisplays）与地址簿去重新增（G4）。
// ============================================================

#include "MemoryWorkbenchView.h"
#include "MemoryWorkbenchView.Internal.h"

#include "AddressBookPanel.h"
#include "Int3PatchPanel.h"
#include "WorkbenchBaselineFeeder.h"
#include "WorkbenchCompareView.h"
#include "WorkbenchConfirmations.h"
#include "WorkbenchMessages.h"
#include "WorkbenchPageProvider.h"
#include "WorkbenchSessionBar.h"
#include "WorkbenchShared.h"
#include "WorkbenchStatusBar.h"
#include "WorkbenchTextView.h"
#include "WorkbenchWriteController.h"

#include "../../Internationalization/LanguageManager.h"

#include "../../../../shared/evidence/memory_workbench/MemoryValueDecode.h"
#include "../../../../shared/evidence/memory_workbench/SessionAddressResolver.h"

#include <QCheckBox>
#include <QStackedWidget>

#include <array>

namespace ks::ui
{
    namespace
    {
        // NoModuleLookup：传给 MemoryAddressBook::ResolveAddress 的"永远查不到
        // 模块"回调。本文件需要一个**非空**的 ModuleBaseLookup——传一个默认构造
        // 的空 std::function 在遇到模块+RVA 条目时会被内部直接调用，对空
        // std::function 调用是 std::bad_function_call（未定义行为的后果比崩溃更
        // 隐蔽）；本类目前没有接到模块目录的公开查询入口（见文件头接口缺口
        // 说明），因此只能如实返回"找不到"，不能假装成功。
        ksword::memwb::ModuleBaseLookup NoModuleLookup()
        {
            return [](const std::string&, std::uint64_t&) { return false; };
        }
    }

    // onTargetSessionChanged：按 IsIdentityChange 分派到两条分支；纯 Policy 位
    // 变化（钉住/回到跟随，身份未变）只刷新展示文字，不清补丁、不触碰画布。
    void MemoryWorkbenchView::onTargetSessionChanged(quint32 changeMask)
    {
        const auto mask = static_cast<ksword::memwb::TargetChange>(changeMask);
        if (ksword::memwb::IsIdentityChange(mask))
        {
            handleIdentityChange(changeMask);
        }
        else if (mask == ksword::memwb::TargetChange::Reload)
        {
            handleReloadOnly();
        }
        else
        {
            refreshStatusBarChannelScopeText();
            refreshTargetDisplays();
        }
    }

    // handleIdentityChange：身份类变更的完整收尾。多数"清旧目标状态"的工作已经
    // 由 hexPane_->setAddressSpace/clearAddressSpace 内部完成（见该函数注释：
    // 它会先 resetScratchLatch/cancelAllInFlight 再换地址空间，LoadBaseline 清
    // 补丁，并把新身份串/边界转给 baselineFeeder_）；WorkbenchWriteController
    // 也已经在 setTarget 里自己订阅了 sessionChanged 来清撤销历史（见该函数
    // 注释）。本函数要做的是：①算出新地址空间与身份串、决定"有没有可用目标"；
    // ②清本类自己持有的导航历史与"切换并跳转"挂起请求（旧目标的地址对新目标
    // 没有意义）；③把新目标同步给 Int3Controller；④刷新会话条可用性/目标
    // chip/确认策略/状态条/保护段/撤销可用性/实时刷新开关。
    void MemoryWorkbenchView::handleIdentityChange(quint32 changeMask)
    {
        cancelPointerChainResolution();
        pointerBindings_->Clear();
        pointerClearAfterPending_ = false;
        pointerTraces_.clear();
        Q_UNUSED(changeMask);
        if (target_ == nullptr)
        {
            return;
        }
        // 先记一笔：openAt 靠前后差值判断"身份是否真的变了"（第二轮复核 B2）。
        ++identityChangeCount_;
        const auto& session = target_->session();
        const bool hasUsableTarget =
            (session.scope != ksword::memwb::Scope::ProcessVirtual) || (session.pid != 0);

        if (hexPane_ != nullptr)
        {
            if (hasUsableTarget)
            {
                const auto space = ksword::memwb::ScopeAddressSpace(session);
                hexPane_->setAddressSpace(space.first, space.last, detail::BuildSessionIdentityKey(session));
                // HexCanvas 的可编辑标志默认 false（见 HexCanvas.h m_editable 初值），
                // 且只会被 WriteController 的 canvasReadOnlyHook_ 在"提交进行中"
                // 两端切换——从未提交过一次时这个钩子永远不会被调用，画布会一直
                // 停在"不可编辑"。换目标/换范围/换通道建立新地址空间时必须把它
                // 按"当前是否正在提交"重新置位一次，否则编辑功能形同摆设。
                // 通道本身是否允许写入由 MemoryIoByteStore/驱动层决定，这里只管
                // "此刻是否忙"，不提前猜测通道的写权限。
                hexPane_->setEditable(writeController_ ? !writeController_->isCommitting() : true);
            }
            else
            {
                hexPane_->clearAddressSpace();
            }
        }
        if (disasmView_ != nullptr)
        {
            disasmView_->reset();
            disasmView_->setAddressBits(static_cast<int>(session.addressBits));
            // 独立页从退出快照选择新进程后恢复编辑；空目标仍不可编辑。
            if (memoryDebugMode_)
            {
                disasmView_->setEditable(hasUsableTarget);
            }
        }
        // 文本页与对比页回到"尚未定位"，同时清三页的跟随状态（旧代码只把它们设成空窗口 (0,0)，
        // 状态行就会显示"0x0 超出已读取窗口"，而且从此没人再给它们喂过真地址）。
        resetSubPageFollow();

        if (sessionBar_ != nullptr)
        {
            sessionBar_->setSession(session.scope, session.channel, /*rememberAsUserChoice=*/false);
        }

        // 旧目标的导航历史与"切换并跳转"挂起请求对新目标没有意义。
        backStack_.clear();
        forwardStack_.clear();
        clearScopeSwitchPrompt();

        // 换目标时叠加层的暂存已随 LoadBaseline/清空地址空间一并清掉，会话条的
        // "N 字节待写入"必须同步（第二轮复核 B4）。
        refreshPendingPatchesDisplay();

        applyInt3Context(session);

        refreshChannelGateDisplay();
        refreshConfirmationsAndSuppression();
        refreshStatusBarChannelScopeText();
        refreshTargetDisplays();
        refreshProtectionDisplay();
        updateUndoRedoActionsEnabled();

        if (liveRefreshCheckBox_ != nullptr)
        {
            const bool ddma = (session.channel == ksword::memwb::Channel::Ddma);
            liveRefreshCheckBox_->setEnabled(!ddma);
            if (ddma && liveRefreshTimer_ != nullptr)
            {
                liveRefreshTimer_->stop();
            }
        }

        // 重启后恢复在子页（loadSettings 恢复了上次的子页下标）再附加进程：没有 currentChanged 事件，
        // 必须在身份变化收尾时补一次跟随；模块目录此刻必然还在加载，followSubPage 会挂起等它。
        if (subTabStack_ != nullptr && hasUsableTarget)
        {
            const int currentTab = subTabStack_->currentIndex();
            if (detail::IsFollowSubPage(currentTab))
            {
                followSubPage(currentTab, true);
            }
        }
    }

    // handleReloadOnly：仅"软重读"——原位重读基线窗口∪可见页，不清补丁、不清
    // 撤销历史、不触碰导航历史。
    void MemoryWorkbenchView::handleReloadOnly()
    {
        if (hexPane_ != nullptr)
        {
            hexPane_->rereadWindow();
        }
        refreshStatusBarChannelScopeText();
    }

    // applyInt3Context：把给定会话写成 int3 账本的"当前目标"。
    // 传入：session 本视图当前会话（调用方已取得，避免在 handleIdentityChange 里再次触发
    //       session() 的 DDMA 代次拉取）。
    // 说明：Int3Controller 全进程只有一份"当前目标"，主 Dock 的视图与内嵌进程详情窗口的视图
    // 都往里写；内容与账本现状完全一致时不再写（SetCurrentContext 每次都会发 changed，
    // 面板会因此重建表格）。
    void MemoryWorkbenchView::applyInt3Context(const ksword::memwb::MemoryTargetSession& session)
    {
        // 独立页不接管共享补丁账本，避免影响同进程的另一个普通工作台。
        if (memoryDebugMode_)
        {
            return;
        }
        auto& int3 = WorkbenchShared::Instance().Int3();
        const auto& current = int3.CurrentTarget();
        if (current.pid == session.pid
            && current.processCreateTime100ns == session.processCreateTime100ns
            && current.attachGeneration == session.attachGeneration
            && int3.CurrentScope() == session.scope
            && int3.CurrentChannel() == session.channel)
        {
            return;
        }
        int3.SetCurrentContext(
            ksword::memwb::PatchTarget{session.pid, session.processCreateTime100ns, session.attachGeneration},
            session.scope,
            session.channel);
    }

    // syncInt3Context：把"本视图的会话"重新声明为 int3 账本的当前目标。
    // 调用时机：任何依赖"当前目标"的 int3 操作之前（还原/写入/离开询问/分离安全网），以及视图
    // 被显示、窗口被激活时——别的视图（内嵌进程详情窗口）可能在这期间改过它。
    void MemoryWorkbenchView::syncInt3Context()
    {
        const QPointer<MemoryWorkbenchView> self(this);
        if (target_ == nullptr)
        {
            return;
        }
        const auto snapshot = target_->session();
        if (self) applyInt3Context(snapshot);
    }

    // onTargetAboutToDetach：int3 未经提示路径的安全网——仅当确实存在"当前目标"
    // 未还原的补丁时才强制 RestoreAll，不弹任何框（真正的提示在 requestLeave
    // 路径上）。
    void MemoryWorkbenchView::onTargetAboutToDetach()
    {
        if (memoryDebugMode_)
        {
            return;
        }
        // 用户刚在离开守卫里明确选择了"保留补丁继续"：尊重这个选择，不强制还原；记号一次性，
        // 取走即清（下一次未经提示的分离才由安全网兜底）。
        const bool keptByUser = int3KeptByLeaveGuard_;
        int3KeptByLeaveGuard_ = false;
        if (keptByUser)
        {
            return;
        }
        // 账本的"当前目标"可能被别的视图（内嵌进程详情窗口）改走：先声明回本视图的目标，
        // 否则 HasUnrestoredForCurrentTarget 查的是别人的目标，本视图的补丁会被漏还原。
        syncInt3Context();
        auto& int3 = WorkbenchShared::Instance().Int3();
        if (int3.HasUnrestoredForCurrentTarget())
        {
            int3.RestoreAll();
        }
    }

    // onWriteControllerCommitFinished：无参槛（头文件冻结签名），数据从
    // lastCommitReport_ 读（见该成员注释）。刷新状态条写入结果段三个旗标 chip、
    // 会话条待写入区，并按需求 §4 的"W4 收尾"转发失败文本。
    void MemoryWorkbenchView::onWriteControllerCommitFinished()
    {
        const auto& report = lastCommitReport_;
        if (statusBar_ != nullptr)
        {
            statusBar_->setWriteResultText(workbench_messages::CommitReportSummary(report));
            statusBar_->reportScratchAreaDirty(report.scratchAreaDirty);
            statusBar_->setReadModifyWriteWindow(report.readModifyWriteWindow);
            statusBar_->setNeedsReread(report.needsReread);
        }
        if (sessionBar_ != nullptr && hexPane_ != nullptr)
        {
            sessionBar_->setPendingPatches(
                hexPane_->overlay().PendingByteCount(),
                static_cast<quint64>(hexPane_->overlay().DiffBlocks().size()));
        }
        updateUndoRedoActionsEnabled();
    }

    // onWriteControllerCommitFailed：commitFinished 的子集，outcome 非
    // Committed/NoChange 且 failureText 非空时才转出 writeFailureText 信号——
    // 本视图自己不判断是不是权限问题，宿主决定要不要弹提权提示。
    void MemoryWorkbenchView::onWriteControllerCommitFailed(const ksword::memwb::CommitReport& report)
    {
        if (!report.failureText.empty())
        {
            emit writeFailureText(QString::fromStdString(report.failureText));
        }
        if (statusBar_ != nullptr)
        {
            statusBar_->setDiagnosticsText(QString::fromStdString(report.failureText), /*autoExpand=*/true);
        }
    }

    // onWriteControllerScratchAreaDirtyReported：常驻红 chip，只能用户点 × 消。
    void MemoryWorkbenchView::onWriteControllerScratchAreaDirtyReported()
    {
        if (statusBar_ != nullptr)
        {
            statusBar_->reportScratchAreaDirty(true);
        }
    }

    // onWriteControllerPendingPatchesChanged：刷新会话条"N 字节待写入"区域。
    void MemoryWorkbenchView::onWriteControllerPendingPatchesChanged(quint64 bytesPending, quint64 blocksPending)
    {
        if (bytesPending == 0 && pointerClearAfterPending_)
        {
            pointerBindings_->ClearActive();
            pointerClearAfterPending_ = false;
        }
        if (sessionBar_ != nullptr)
        {
            sessionBar_->setPendingPatches(bytesPending, blocksPending);
        }
    }

    // onWriteControllerCommitRejectedBusy："现在不能做"提示，不是失败。
    void MemoryWorkbenchView::onWriteControllerCommitRejectedBusy(const QString& source)
    {
        Q_UNUSED(source);
        if (statusBar_ != nullptr)
        {
            // 本项目不使用 Qt 的 tr()：setWriteResultText 拼成状态条整串文字，
            // 必须源头翻译（同 WorkbenchStatusBar.cpp 的 setReadResultText 惯例）。
            statusBar_->setWriteResultText(ks::i18n::sourceText(QStringLiteral("操作进行中，请稍候")));
        }
    }

    // updateUndoRedoActionsEnabled：目前没有独立的动作对象持有可用性状态
    // （WorkbenchActions.h 只是快捷键工厂，不持有 QAction），本函数把
    // canUndo/canRedo 的最新值写进状态条的诊断文本旁的提示——留空实现点，
    // 真正的按钮使能将在装配层（WP-K）把工具栏按钮接上这两个查询时统一刷新；
    // 这里保证至少调用点存在、且不会在管线缺失时崩溃。
    void MemoryWorkbenchView::updateUndoRedoActionsEnabled()
    {
        if (writeController_ == nullptr)
        {
            return;
        }
        Q_UNUSED(writeController_->canUndo());
        Q_UNUSED(writeController_->canRedo());
    }

    // ------------------------------------------------------------
    // 会话条请求 → 裁决 → 回写
    // ------------------------------------------------------------

    void MemoryWorkbenchView::onSessionBarScopeRequested(ksword::memwb::Scope scope)
    {
        if (target_ == nullptr || sessionBar_ == nullptr)
        {
            return;
        }
        IdentityRequest request;
        request.scope = scope;
        const auto rememberedChannel = sessionBar_->rememberedChannel(scope);
        request.channel = rememberedChannel;
        const QPointer<MemoryWorkbenchView> self(this);
        const bool accepted = target_->requestIdentity(request, LeaveReason::ScopeChange);
        if (!self || !accepted)
        {
            // 被拒绝：会话逐字段不变，什么都不回写（N2 不变式）。
            return;
        }
        sessionBar_->setSession(scope, rememberedChannel, /*rememberAsUserChoice=*/true);
    }

    void MemoryWorkbenchView::onSessionBarChannelRequested(ksword::memwb::Channel channel)
    {
        if (target_ == nullptr || sessionBar_ == nullptr)
        {
            return;
        }
        IdentityRequest request;
        request.channel = channel;
        const QPointer<MemoryWorkbenchView> self(this);
        const bool accepted = target_->requestIdentity(request, LeaveReason::ChannelChange);
        if (!self || !accepted)
        {
            return;
        }
        sessionBar_->setSession(sessionBar_->currentScope(), channel, /*rememberAsUserChoice=*/true);
    }

    void MemoryWorkbenchView::onSessionBarModeRequested(ksword::memwb::WriteMode mode)
    {
        if (sessionBar_ == nullptr || writeController_ == nullptr || hexPane_ == nullptr)
        {
            return;
        }
        const QPointer<MemoryWorkbenchView> self(this);
        const auto status = writeController_->requestModeSwitch(mode);
        if (!self)
        {
            return;
        }
        if (status == ksword::memwb::ModeSwitchStatus::Switched)
        {
            sessionBar_->setWriteMode(mode);
            refreshConfirmationsAndSuppression();
            return;
        }
        if (status != ksword::memwb::ModeSwitchStatus::NeedsDecision || confirmations_ == nullptr)
        {
            return;
        }
        const auto decision = confirmations_->PromptModeSwitch(
            writeController_->mode(),
            mode,
            hexPane_->overlay().PendingByteCount(),
            static_cast<std::uint64_t>(hexPane_->overlay().DiffBlocks().size()));
        if (!self)
        {
            return;
        }
        const auto result = writeController_->resolveModeSwitch(decision);
        if (!self)
        {
            return;
        }
        if (result.status == ksword::memwb::ModeSwitchStatus::Switched)
        {
            sessionBar_->setWriteMode(mode);
            refreshConfirmationsAndSuppression();
        }
        else if (result.status == ksword::memwb::ModeSwitchStatus::ApplyFailed && statusBar_ != nullptr)
        {
            const QString failureText = result.commitReport
                ? QString::fromStdString(result.commitReport->failureText)
                : QString();
            statusBar_->setDiagnosticsText(
                workbench_messages::ApplyFailedDiagnosticsPrefix() + failureText,
                /*autoExpand=*/true);
        }
    }

    void MemoryWorkbenchView::onSessionBarApplyRequested()
    {
        if (writeController_ != nullptr)
        {
            writeController_->commitPendingNow();
        }
    }

    void MemoryWorkbenchView::onSessionBarDiscardRequested()
    {
        if (hexPane_ == nullptr)
        {
            return;
        }
        const bool hadPendingPatches = hexPane_->overlay().HasPendingPatches();
        hexPane_->overlay().DiscardAll();
        if (hadPendingPatches && target_ != nullptr)
        {
            target_->noteContentChanged();
        }
        if (hexPane_->canvas() != nullptr)
        {
            hexPane_->canvas()->notifyOverlayChanged();
        }
        if (sessionBar_ != nullptr)
        {
            sessionBar_->setPendingPatches(0, 0);
        }
    }

    // onSessionBarPickTargetRequested：转发给 Dock，本类不碰下拉框。
    void MemoryWorkbenchView::onSessionBarPickTargetRequested()
    {
        emit pickTargetRequested();
    }

    // ------------------------------------------------------------
    // 地址簿 / int3 面板
    // ------------------------------------------------------------

    // onAddressBookValueEditRequested：把文本按 valueType 编码成字节后经
    // beginPendingStage 走正常提交管线（地址可能在窗口外，由 PendingStage 票据
    // 负责移动窗口覆盖）。本实现限制：只支持绝对地址条目（moduleName 为空）——
    // 模块+RVA 条目需要查询模块当前加载基址，本类没有接到模块目录的公开查询
    // 入口（见报告"接口缺口"一节），此时拒绝并提示，不会把字节写到错误地址。
    void MemoryWorkbenchView::onAddressBookValueEditRequested(
        quint64 id, ksword::memwb::ValueType valueType, const QString& text)
    {
        if (writeController_ == nullptr)
        {
            return;
        }
        const auto entry = WorkbenchShared::Instance().AddressBook().find(id);
        if (!entry)
        {
            return;
        }
        // 全局地址簿包含多个目标；必须匹配条目归属，禁止把其他进程的值写入当前目标。
        if (target_ == nullptr || entry->targetKey != currentAddressBookTargetKey())
        {
            if (statusBar_ != nullptr)
            {
                statusBar_->setWriteResultText(
                    ks::i18n::sourceText(QStringLiteral("目标身份与请求不一致")));
            }
            return;
        }
        const auto resolved = ksword::memwb::MemoryAddressBook::ResolveAddress(
            *entry, NoModuleLookup());
        if (resolved.status != ksword::memwb::ResolveStatus::Ok)
        {
            if (statusBar_ != nullptr)
            {
                statusBar_->setWriteResultText(
                    ks::i18n::sourceText(QStringLiteral("该条目绑定的模块当前未加载，无法定位地址")));
            }
            return;
        }
        const char* typeName = (valueType == ksword::memwb::ValueType::Hex8)
            ? "u8"
            : ksword::memwb::ValueTypeName(valueType);
        std::vector<std::uint8_t> bytes;
        const auto encodeStatus = ksword::memwb::EncodeValue(
            typeName, text.toUtf8().toStdString(), ksword::memwb::ByteOrder::Little, 8U, bytes);
        if (encodeStatus != ksword::memwb::EncodeStatus::Ok || bytes.empty())
        {
            if (statusBar_ != nullptr)
            {
                statusBar_->setWriteResultText(ks::i18n::sourceText(QStringLiteral("输入无法解析为该值类型")));
            }
            return;
        }
        QByteArray payload(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
        // 修复零覆盖路径暴露的真实缺陷（并入审核报告 P4 探针）：
        // beginPendingStage 自己从不触碰 PageProvider/BaselineFeeder（见
        // WorkbenchWriteController.PendingStage.cpp 文件头的分工说明），移动
        // 窗口覆盖目标地址是本类的职责。地址可能落在当前画布可见范围之外
        // （这正是"值"列编辑走 PendingStage 票据而不是直接 Stage 的理由），
        // 这里先用 jumpTo 把画布滚动过去——与地址条回车、模块表双击等既有
        // "跳转"入口同一套机制，不新增另一条移动窗口的路径；jumpTo 触发的
        // 基线刷新（50ms 防抖）落地后，connectPipelineSignals 里新接的
        // baselineRefreshed→notifyWindowMayCover 会让票据重新尝试一次 Stage。
        if (hexPane_ != nullptr)
        {
            hexPane_->jumpTo(resolved.address);
        }
        writeController_->beginPendingStage(resolved.address, payload);
    }

    void MemoryWorkbenchView::onAddressBookJumpRequested(quint64 id)
    {
        const auto entry = WorkbenchShared::Instance().AddressBook().find(id);
        if (!entry)
        {
            return;
        }
        if (entry->pointerChain)
        {
            resolvePointerChain(id, true);
            return;
        }
        // 跳转与编辑共用目标边界；不将其他目标的绝对地址解释为当前进程地址。
        if (target_ == nullptr || entry->targetKey != currentAddressBookTargetKey())
        {
            if (statusBar_ != nullptr)
            {
                statusBar_->setReadResultText(
                    ks::i18n::sourceText(QStringLiteral("目标身份与请求不一致")), true);
            }
            return;
        }
        const auto resolved = ksword::memwb::MemoryAddressBook::ResolveAddress(
            *entry, NoModuleLookup());
        if (resolved.status != ksword::memwb::ResolveStatus::Ok)
        {
            return;
        }
        NavRequest request;
        const auto& session = target_->session();
        request.scope = session.scope;
        if (session.scope == ksword::memwb::Scope::ProcessVirtual
            && target_->followMode() == ksword::memwb::MemoryTargetTracker::Follow::Pinned)
        {
            request.pid = session.pid;
            request.createTime = session.processCreateTime100ns;
        }
        request.address = resolved.address;
        request.origin = NavOrigin::AddressBook;
        openAt(request);
    }

    void MemoryWorkbenchView::onAddressBookOpenDisassemblyRequested(quint64 id)
    {
        const auto pointerEntry = WorkbenchShared::Instance().AddressBook().find(id);
        if (pointerEntry && pointerEntry->pointerChain)
        {
            resolvePointerChain(id, true, true);
            return;
        }
        const QPointer<MemoryWorkbenchView> self(this);
        onAddressBookJumpRequested(id);
        if (self && subTabStack_ != nullptr)
        {
            subTabStack_->setCurrentIndex(1);
        }
    }

    void MemoryWorkbenchView::onAddressBookPromoteRequested(quint64 id, ksword::memwb::EntryKind newKind)
    {
        WorkbenchShared::Instance().AddressBook().promote(id, newKind);
    }

    void MemoryWorkbenchView::onAddressBookRemoveRequested(const QList<quint64>& ids)
    {
        std::vector<std::uint64_t> idVec;
        idVec.reserve(static_cast<std::size_t>(ids.size()));
        for (const auto id : ids)
        {
            idVec.push_back(id);
        }
        WorkbenchShared::Instance().AddressBook().removeMany(idVec);
    }

    void MemoryWorkbenchView::onInt3ResultMessage(const QString& text, bool isError)
    {
        if (statusBar_ != nullptr)
        {
            statusBar_->setWriteResultText(text);
            if (isError)
            {
                statusBar_->setDiagnosticsText(text, /*autoExpand=*/true);
            }
        }
    }

    // addInsertionPointToAddressBook：G4 去重规则——同 targetKey 且解析后的绝对
    // 地址相同视为重复，提示而不阻止（允许用户坚持添加）。本实现只产出绝对地址
    // 条目（见文件头说明的接口缺口）。
    void MemoryWorkbenchView::addInsertionPointToAddressBook(std::uint64_t address)
    {
        if (target_ == nullptr)
        {
            return;
        }
        const std::string targetKey = currentAddressBookTargetKey();
        auto& store = WorkbenchShared::Instance().AddressBook();
        ksword::memwb::AddressFilter filter;
        filter.targetKey = targetKey;
        bool duplicate = false;
        for (const auto& existing : store.list(filter))
        {
            const auto resolved = ksword::memwb::MemoryAddressBook::ResolveAddress(
                existing, NoModuleLookup());
            if (resolved.status == ksword::memwb::ResolveStatus::Ok && resolved.address == address)
            {
                duplicate = true;
                break;
            }
        }
        const auto draft = ksword::memwb::MemoryAddressBook::FromAbsolute(
            targetKey, ksword::memwb::EntryKind::Bookmark, address);
        if (!draft)
        {
            return;
        }
        store.add(*draft);
        if (statusBar_ != nullptr && duplicate)
        {
            statusBar_->setWriteResultText(
                ks::i18n::sourceText(QStringLiteral("该地址已在地址簿中，已另外添加一条")));
        }
    }

    // currentAddressBookTargetKey：见 MemoryWorkbenchView.Internal.h 的说明，只随
    // 目标身份变化，不随通道变化。
    std::string MemoryWorkbenchView::currentAddressBookTargetKey() const
    {
        if (target_ == nullptr)
        {
            return std::string();
        }
        return detail::BuildAddressBookTargetKey(target_->session());
    }

    // ------------------------------------------------------------
    // 读反馈与 Gate
    // ------------------------------------------------------------

    void MemoryWorkbenchView::onProviderChannelUnavailable(const ksword::memwb::GateVerdict& verdict)
    {
        if (memoryDebugMode_ && target_ && target_->livenessState() == LivenessState::Exited)
        {
            // 页请求门禁不能把退出提示覆盖成“未选进程”，明确保留过期快照语义。
            statusBar_->setReadResultText(ks::i18n::sourceText(
                QStringLiteral("目标进程已退出，当前内容为过期快照")), true);
            return;
        }
        if (statusBar_ != nullptr && target_ != nullptr)
        {
            statusBar_->setReadResultText(
                workbench_messages::ChannelUnavailableReason(target_->session().channel, verdict),
                /*warning=*/true);
        }
        refreshChannelGateDisplay();
    }

    void MemoryWorkbenchView::onProviderReadFailed(quint64 sourceRevision, const QString& failureText, int failedRangeCount)
    {
        Q_UNUSED(sourceRevision);
        if (statusBar_ != nullptr)
        {
            statusBar_->setReadResultText(
                ks::i18n::sourceText(QStringLiteral("读取失败（%1 处可重试）")).arg(failedRangeCount),
                /*warning=*/true);
            statusBar_->setDiagnosticsText(failureText, /*autoExpand=*/true);
            statusBar_->setNeedsReread(true);
        }
    }

    void MemoryWorkbenchView::onProviderScratchAreaDirtyLatched()
    {
        if (statusBar_ != nullptr)
        {
            statusBar_->reportScratchAreaDirty(true);
        }
    }

    void MemoryWorkbenchView::onProviderRetryBlockedByLatch(quint64 sourceRevision)
    {
        Q_UNUSED(sourceRevision);
        if (statusBar_ != nullptr)
        {
            statusBar_->setReadResultText(
                ks::i18n::sourceText(QStringLiteral("暂存区尚未恢复，重读前请先处理")), /*warning=*/true);
        }
    }

    // onProviderJobLanded：每次页真正落地都会到达，用当前基线窗口对画布缓存
    // 取掩码统计拼"已读 M/N 字节"。严格意义上 ux.md 说的是"可见范围"，这里退一步
    // 用基线窗口近似（两者通常高度重叠，窗口跟随视口扩展/移动）——本类没有另外
    // 持有画布可见范围的缓存（那份状态在 hexPane_ 内部是私有的），记在报告里。
    void MemoryWorkbenchView::onProviderJobLanded()
    {
        if (statusBar_ == nullptr || hexPane_ == nullptr)
        {
            return;
        }
        auto& overlay = hexPane_->overlay();
        if (!overlay.HasBaseline() || overlay.BaselineSize() == 0)
        {
            return;
        }
        const auto copy = hexPane_->canvas()->copyCachedRangeWithMask(
            overlay.BaseAddress(), overlay.BaseAddress() + overlay.BaselineSize() - 1ULL);
        if (!copy)
        {
            return;
        }
        std::uint64_t validCount = 0;
        for (const auto mask : copy->validMask)
        {
            if (mask != 0)
            {
                ++validCount;
            }
        }
        const bool partial = validCount < copy->validMask.size();
        statusBar_->setReadResultText(
            ks::i18n::sourceText(QStringLiteral("已读 %1/%2 字节")).arg(validCount).arg(copy->validMask.size()),
            partial);
    }

    // refreshChannelGateDisplay：对四个通道各算一次 EvaluateChannel，刷新会话条
    // 的置灰/报红展示；输入未注入时按"全部最保守"处理（GateInputs 默认全假）。
    void MemoryWorkbenchView::refreshChannelGateDisplay()
    {
        if (sessionBar_ == nullptr || target_ == nullptr)
        {
            return;
        }
        auto inputs = gateInputsProvider_ ? gateInputsProvider_() : ksword::memwb::GateInputs{};
        if (memoryDebugMode_ && target_->livenessState() == LivenessState::Exited)
        {
            inputs.hasProcessTarget = false;
        }
        const auto scope = target_->session().scope;
        std::array<ksword::memwb::GateVerdict, 4> verdicts{};
        for (std::uint32_t i = 0; i < 4U; ++i)
        {
            verdicts[i] = ksword::memwb::EvaluateChannel(scope, static_cast<ksword::memwb::Channel>(i), inputs);
        }
        sessionBar_->setChannelVerdicts(verdicts);
    }

    void MemoryWorkbenchView::refreshStatusBarChannelScopeText()
    {
        if (statusBar_ == nullptr || target_ == nullptr)
        {
            return;
        }
        const auto& session = target_->session();
        statusBar_->setChannelScopeText(
            workbench_messages::ChannelName(session.channel) + QStringLiteral(" · ") +
            workbench_messages::ScopeName(session.scope));
    }

    // refreshProtectionDisplay：状态条"保护"段，由 protectionProvider_ 按当前
    // 插入点算好后喂入；未注入或返回空时该段不显示（role=None）。
    void MemoryWorkbenchView::refreshProtectionDisplay()
    {
        if (statusBar_ == nullptr)
        {
            return;
        }
        if (!protectionProvider_ || hexPane_ == nullptr)
        {
            statusBar_->setProtection(QString(), StatusRole::None);
            return;
        }
        const auto info = protectionProvider_(hexPane_->insertionAddress());
        if (info)
        {
            statusBar_->setProtection(info->text, info->role);
        }
        else
        {
            statusBar_->setProtection(QString(), StatusRole::None);
        }
    }

    // refreshConfirmationsAndSuppression：每次会话/模式变化调用一次，按 ux.md
    // §2 的确认策略表计算 suppressed，只转发给 writeController_，不碰
    // ConfirmApproval（不变式 15）。
    void MemoryWorkbenchView::refreshConfirmationsAndSuppression()
    {
        if (target_ == nullptr || sessionBar_ == nullptr || confirmations_ == nullptr || writeController_ == nullptr)
        {
            return;
        }
        const auto& session = target_->session();
        const auto mode = sessionBar_->currentWriteMode();
        confirmations_->SetCurrentContext(mode, session.scope, session.channel);
        const bool globalSkip = globalSkipDangerousConfirmProvider_ ? globalSkipDangerousConfirmProvider_() : false;
        const auto decision = WorkbenchShared::Instance().WritePolicy().Decide(mode, session.scope, session.channel, globalSkip);
        writeController_->setUiConfirmSuppressed(decision.suppressed);
    }

    // refreshTargetDisplays：见头文件 AttachedProcessDisplayInfo 的说明，同时
    // 刷新会话条目标 chip 与确认框正文描述。
    void MemoryWorkbenchView::refreshTargetDisplays()
    {
        if (target_ == nullptr)
        {
            return;
        }
        const auto& session = target_->session();
        const bool attached = (session.scope == ksword::memwb::Scope::ProcessVirtual) && (session.pid != 0);
        QString processName;
        bool canReadWrite = false;
        if (attached && attachedProcessInfoProvider_)
        {
            if (const auto info = attachedProcessInfoProvider_(session.pid))
            {
                processName = info->processName;
                canReadWrite = info->canReadWrite;
            }
        }
        if (sessionBar_ != nullptr)
        {
            sessionBar_->setTargetInfo(attached, processName, session.pid, session.addressBits, canReadWrite);
        }
        if (confirmations_ != nullptr)
        {
            confirmations_->SetTargetDescription(
                detail::BuildTargetDescriptionText(attached, processName, session.pid, session.addressBits, canReadWrite, session.scope));
        }
    }
}
