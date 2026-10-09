// ============================================================
// MemoryWorkbenchView.Nav.cpp
// 作用：
// - 统一跳转入口 openAt(N1-N4)：身份变化合并为一次离开守卫询问、地址空间
//   containment 核对（NeedsScopeSwitch/Unavailable）、同目标内跳转
//   （hexPane_->jumpTo）、后退/前进栈维护（64 项）。
// - 地址条：回车求值（target().evaluate，唯一入口）、后退/前进按钮、"切换并
//   跳转"按钮（NeedsScopeSwitch 的落点，不静默切换范围）。
// - 十六进制子页右键菜单扩展（添加到地址簿/写入字符串/从此处反汇编/写入还原
//   int3，ux.md §4.1）与反汇编子页的 stageRequested/requestHexLocate 转发。
// ============================================================

#include "MemoryWorkbenchView.h"
#include "MemoryWorkbenchView.Internal.h"

#include "HexCanvasFormat.h"
#include "Int3PatchPanel.h"
#include "WorkbenchDisasmView.h"
#include "WorkbenchMessages.h"
#include "WorkbenchSessionBar.h"
#include "WorkbenchSettings.h"
#include "WorkbenchShared.h"
#include "WorkbenchStatusBar.h"
#include "WorkbenchStringWriteDialog.h"
#include "WorkbenchWriteController.h"

#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"

#include "../../../../shared/evidence/memory_workbench/MemoryTargetTracker.h"
#include "../../../../shared/evidence/memory_workbench/SessionAddressResolver.h"

#include <QAction>
#include <QDateTime>
#include <QLineEdit>
#include <QMenu>
#include <QStackedWidget>
#include <QToolButton>

#include <optional>

namespace ks::ui
{
    namespace
    {
        // TranslateInt3InstallOutcome / TranslateInt3RestoreOutcome（修复缺陷 2）：
        // 把 Int3Controller::Install/Restore 的结果翻译成中文提示，文案逐字
        // 对齐 Int3PatchPanel::EmitInstallMessage/EmitRestoreMessage 已经在用
        // 的那些句子（同一功能两个入口，文案不该不一样；这些句子也已经登记在
        // 两个语言包里，逐字对齐才能被运行期翻译命中，不是巧合）——但那两个
        // 函数是私有方法，本类访问不到，只能各自写一份小翻译函数。结果经
        // onInt3ResultMessage 走状态条同一通道——右键菜单这条路径此前完全
        // 零反馈（审核报告 wpJ6/wave3 发现 2：成功靠侧栏列表自己刷新能看出
        // 来，失败则完全沉默）。
        // 第二轮复核 B5：这里返回的整句会被 onInt3ResultMessage 拼进状态条的整串文字，
        // 运行期整树扫描只按控件"当前整串文字"精确匹配，够不到拼接后的内容；所以每一句
        // 必须在源头经 ks::i18n::sourceText 翻译（词条在两个语言包里都已登记）。
        QString TranslateInt3InstallOutcome(const Int3InstallOutcome& outcome, const quint64 address)
        {
            using ks::i18n::sourceText;
            if (outcome.routeReject == Int3RouteReject::UnsupportedScope)
            {
                return sourceText(QStringLiteral("int3 补丁只支持进程范围，当前范围不可写入"));
            }
            if (outcome.routeReject == Int3RouteReject::UnsupportedChannel)
            {
                return sourceText(QStringLiteral("int3 补丁不支持磁盘传输通道，请切换到用户态 / 标准驱动 / HVM 通道"));
            }
            switch (outcome.status)
            {
            case ksword::memwb::InstallStatus::Installed:
                return sourceText(QStringLiteral("已写入 int3（%1）")).arg(hexcanvas_format::FormatAddress(address, 16));
            case ksword::memwb::InstallStatus::Duplicate:
                return sourceText(QStringLiteral("该地址已经写过 int3，无需重复写入"));
            case ksword::memwb::InstallStatus::ReadFailed:
                return sourceText(QStringLiteral("写入前读取原字节失败，目标可能不可读"));
            case ksword::memwb::InstallStatus::AlreadyContainsPatchByte:
                return sourceText(QStringLiteral("该地址原本就是 0xCC，无法安全记账，已拒绝写入"));
            case ksword::memwb::InstallStatus::WriteFailed:
                return sourceText(QStringLiteral("写入失败，目标可能不可写"));
            case ksword::memwb::InstallStatus::VerifyFailed:
                return outcome.rollbackAttempted
                    ? (outcome.rollbackWriteOk
                           ? sourceText(QStringLiteral("写入后回读不符，已尝试写回原字节"))
                           : sourceText(QStringLiteral("写入后回读不符，写回原字节也失败，请立即检查目标")))
                    : sourceText(QStringLiteral("写入后回读不符"));
            case ksword::memwb::InstallStatus::None:
            default:
                return sourceText(QStringLiteral("写入未执行"));
            }
        }

        QString TranslateInt3RestoreOutcome(const Int3RestoreOutcome& outcome)
        {
            using ks::i18n::sourceText;
            switch (outcome.status)
            {
            case ksword::memwb::RestoreStatus::Restored:
                return sourceText(QStringLiteral("已还原"));
            case ksword::memwb::RestoreStatus::NotFound:
                return sourceText(QStringLiteral("未找到该记录，可能已被还原或丢弃"));
            case ksword::memwb::RestoreStatus::Orphaned:
                return sourceText(QStringLiteral("目标已退出，无法还原，请使用\"清除\""));
            case ksword::memwb::RestoreStatus::TargetMismatch:
                return sourceText(QStringLiteral("当前目标与这条记录的目标不一致，拒绝还原"));
            case ksword::memwb::RestoreStatus::ReadFailed:
                return sourceText(QStringLiteral("读取当前字节失败"));
            case ksword::memwb::RestoreStatus::Diverged:
                return sourceText(QStringLiteral("当前字节已不是 CC（被别处改过），仅可丢弃记录"));
            case ksword::memwb::RestoreStatus::WriteFailed:
                return sourceText(QStringLiteral("写回失败"));
            case ksword::memwb::RestoreStatus::VerifyFailed:
                return sourceText(QStringLiteral("写回后回读不符"));
            case ksword::memwb::RestoreStatus::None:
            default:
                return sourceText(QStringLiteral("还原未执行"));
            }
        }
    }

    // openAt：见文件头。全部分支都通过 applyNavOutcome 统一发出
    // navigationRefused（Ok 不发）与状态条提示，调用方只需要看返回值决定要不要
    // 自己再做点什么（例如 NeedsAttach 时聚焦进程选择框）。
    NavStatus MemoryWorkbenchView::openAt(const NavRequest& request)
    {
        const QPointer<MemoryWorkbenchView> self(this);
        if (target_ == nullptr)
        {
            applyNavOutcome(request, NavStatus::Unavailable);
            return NavStatus::Unavailable;
        }

        // 修复缺陷 4（审核报告 wpJ6/wave3 P5 探针）：必须在 requestIdentity 之前
        // 取"旧地址"。身份变化一旦被接受，target_->requestIdentity 会同步触发
        // handleIdentityChange——后者会把画布的地址空间整个换掉
        // （hexPane_->setAddressSpace）并把插入点复位到新地址空间的起点，还会
        // 顺手清空 backStack_/forwardStack_。若在那之后才读
        // hexPane_->insertionAddress() 当"旧地址"，读到的已经是复位后的新起点
        // （例如内核范围的 0xffff800000000000），这个"幽灵地址"会被误当成
        // "旧目标里的上一个位置"重新压回刚清空的后退栈。
        const std::uint64_t previousAddressBeforeIdentity =
            (hexPane_ != nullptr) ? hexPane_->insertionAddress() : 0ULL;

        // ---- 身份变化合并为一次 requestIdentity（N2）----
        IdentityRequest identity;
        const auto& before = target_->session();
        if (!self)
        {
            return NavStatus::LeaveRefused;
        }
        if (request.scope != before.scope)
        {
            identity.scope = request.scope;
        }
        if (request.pid != 0)
        {
            identity.pinPid = request.pid;
            identity.expectCreateTime = request.createTime;
        }
        else if (!memoryDebugMode_
            && target_->followMode() == ksword::memwb::MemoryTargetTracker::Follow::Pinned)
        {
            // 请求"跟随 Dock"（pid==0）而当前钉在别的进程：回到跟随。
            identity.pinPid = 0U;
        }
        if (request.channel.has_value())
        {
            identity.channel = request.channel;
        }

        // 第二轮复核 B2：身份"真的变了"不能按请求里写了哪些字段来猜——同目标、同通道
        // 带显式 pid/channel 的请求（Dock 的外部请求正是这样发的）requestIdentity 会返回
        // true，却不会触发 handleIdentityChange，既没清栈也不该被当成"换了目标"而
        // 不压后退栈（旧实现读数：连续三次同目标跳转，带 pid/channel 的后退栈恒为 0）。
        // 改用 handleIdentityChange 的累计次数前后差值——它才是"栈已被清空"的真实事件。
        const std::uint64_t identityChangeCountBefore = identityChangeCount_;
        const bool identityRequested =
            identity.scope.has_value() || identity.pinPid.has_value() || identity.channel.has_value();
        if (identityRequested)
        {
            const bool accepted = target_->requestIdentity(identity, LeaveReason::ScopeChange);
            if (!self)
            {
                return NavStatus::LeaveRefused;
            }
            if (!accepted)
            {
                const auto failure = target_->lastIdentityFailure();
                applyNavOutcome(request, failure);
                return failure;
            }
        }
        const bool identityActuallyChanged = (identityChangeCount_ != identityChangeCountBefore);

        const auto& session = target_->session();
        if (!self)
        {
            return NavStatus::LeaveRefused;
        }
        const bool hasTarget = (session.scope != ksword::memwb::Scope::ProcessVirtual) || (session.pid != 0);
        if (!hasTarget)
        {
            applyNavOutcome(request, NavStatus::NeedsAttach);
            return NavStatus::NeedsAttach;
        }
        // 独立页保留退出快照，但不把新导航当作仍可读取的活动目标。
        if (memoryDebugMode_ && target_->livenessState() == LivenessState::Exited)
        {
            applyNavOutcome(request, NavStatus::TargetGone);
            return NavStatus::TargetGone;
        }

        // ---- 地址空间 containment + 建议范围（N4）----
        if (session.scope == ksword::memwb::Scope::ProcessVirtual &&
            ksword::memwb::IsKernelVirtualAddress(request.address))
        {
            // 不静默切换范围：记下待跳转请求，显示"切换并跳转"按钮，由用户主动确认。
            NavRequest rerouted = request;
            rerouted.scope = ksword::memwb::Scope::KernelVirtual;
            pendingScopeSwitchRequest_ = rerouted;
            if (rerouteButton_ != nullptr)
            {
                rerouteButton_->setVisible(true);
            }
            applyNavOutcome(request, NavStatus::NeedsScopeSwitch);
            return NavStatus::NeedsScopeSwitch;
        }

        const auto space = ksword::memwb::ScopeAddressSpace(session);
        if (!ksword::memwb::AddrSpaceContains(space, request.address))
        {
            applyNavOutcome(request, NavStatus::Unavailable);
            return NavStatus::Unavailable;
        }

        // ---- 跳转（同目标内跳转只 scrollToAddress+setCaretAddress）----
        if (hexPane_ != nullptr)
        {
            // 打开请求从目标所在行开始显示；前一段地址可能根本未映射，不能用
            // 就近可见把模块/区域基址放在末行。内部历史/查找仍走原有对齐政策。
            const bool jumped = hexPane_->jumpTo(
                request.address, request.selectLength, HexCanvas::ScrollAlign::Top);
            if (!self)
            {
                return NavStatus::LeaveRefused;
            }
            if (!jumped)
            {
                applyNavOutcome(request, NavStatus::Unavailable);
                return NavStatus::Unavailable;
            }
            // 修复缺陷 4 的第二部分——身份变化清栈、不压旧目标的地址，只有
            // "同目标内跳转"才把旧位置压入后退栈：identityActuallyChanged 为真时
            // handleIdentityChange 已经 clear 过 backStack_/forwardStack_，这里
            // 不能再把（哪怕是修复后正确读到的）旧目标地址重新压回去，否则刚
            // 清空的栈又多出一条不属于新目标的记录。
            if (!identityActuallyChanged && previousAddressBeforeIdentity != request.address)
            {
                pushBackStackEntry(previousAddressBeforeIdentity);
                forwardStack_.clear();
            }
        }
        if (request.focusView && subTabStack_ != nullptr)
        {
            subTabStack_->setCurrentIndex(0);
        }

        clearScopeSwitchPrompt();
        leavePointerChainNavigation();
        applyNavOutcome(request, NavStatus::Ok);
        return NavStatus::Ok;
    }

    // applyNavOutcome：非 Ok 统一发 navigationRefused + 状态条一句提示；Ok 什么都不发。
    void MemoryWorkbenchView::applyNavOutcome(const NavRequest& request, NavStatus status)
    {
        Q_UNUSED(request);
        if (status == NavStatus::Ok)
        {
            return;
        }
        emit navigationRefused(status);
        if (statusBar_ == nullptr)
        {
            return;
        }
        // 本项目不使用 Qt 的 tr()：setReadResultText 把文本存进私有成员再拼成
        // 状态条最终显示的整串文字，运行期整树扫描够不到拼接后的整串，必须在
        // 源头经 ks::i18n::sourceText 翻译（与 WorkbenchStatusBar.cpp 里
        // setReadResultText 的注释同一惯例）。
        switch (status)
        {
        case NavStatus::NeedsAttach:
            statusBar_->setReadResultText(memoryDebugMode_
                ? ks::i18n::sourceText(QStringLiteral("未选择进程"))
                : ks::i18n::sourceText(QStringLiteral("未附加目标，无法跳转")), true);
            break;
        case NavStatus::NeedsScopeSwitch:
            statusBar_->setReadResultText(
                ks::i18n::sourceText(QStringLiteral("该地址位于其它范围，点击「切换并跳转」")), true);
            break;
        case NavStatus::TargetMismatch:
            statusBar_->setReadResultText(ks::i18n::sourceText(QStringLiteral("目标身份与请求不一致")), true);
            break;
        case NavStatus::LeaveRefused:
            statusBar_->setReadResultText(ks::i18n::sourceText(QStringLiteral("操作已取消")), false);
            break;
        case NavStatus::Unavailable:
            statusBar_->setReadResultText(
                ks::i18n::sourceText(QStringLiteral("地址不在当前范围内，或当前策略不允许")), true);
            break;
        case NavStatus::TargetGone:
            statusBar_->setReadResultText(ks::i18n::sourceText(QStringLiteral("目标进程已不存在")), true);
            break;
        case NavStatus::Ok:
        default:
            break;
        }
    }

    // pushBackStackEntry：压入后退栈，容量上限 64（N1），丢弃最旧的一项。
    void MemoryWorkbenchView::pushBackStackEntry(std::uint64_t address)
    {
        backStack_.push_back(address);
        if (backStack_.size() > 64U)
        {
            backStack_.erase(backStack_.begin());
        }
    }

    // onAddressBarReturnPressed：地址条回车才求值（绝不逐键），唯一入口是
    // target_->evaluate；求值失败只在输入框标红+状态条显示，不弹模态框。
    void MemoryWorkbenchView::onAddressBarReturnPressed()
    {
        if (target_ == nullptr || addressEdit_ == nullptr)
        {
            return;
        }
        const QString text = addressEdit_->text();
        if (text.trimmed().isEmpty())
        {
            return;
        }
        const auto eval = target_->evaluate(text);
        if (!eval.expr.ok)
        {
            // 用 KswordTheme::ErrorHex() 现取当前主题的错误色，而不是把静态
            // #RRGGBB 烧进样式表——这是事件触发时现算，不是构造期固化，深浅
            // 主题切换后下一次触发同样的错误状态会现取新颜色（仓库已知坑，
            // 见 .claude/memory/ksword-theme-token-snapshot-trap.md）。
            addressEdit_->setStyleSheet(
                QStringLiteral("QLineEdit { border: 1px solid %1; }").arg(KswordTheme::ErrorHex()));
            if (statusBar_ != nullptr)
            {
                const QString message = (eval.issue != ksword::memwb::Issue::None)
                    ? workbench_messages::Translate(eval.issue)
                    : workbench_messages::Translate(eval.expr.error);
                statusBar_->setReadResultText(message, true);
            }
            return;
        }
        addressEdit_->setStyleSheet(QString());

        NavRequest request;
        const auto& session = target_->session();
        request.scope = session.scope;
        // 内部导航沿用当前固定目标；pid=0 专用于外部请求跟随 Dock。
        if (session.scope == ksword::memwb::Scope::ProcessVirtual
            && target_->followMode() == ksword::memwb::MemoryTargetTracker::Follow::Pinned)
        {
            request.pid = session.pid;
            request.createTime = session.processCreateTime100ns;
        }
        request.address = eval.expr.value;
        request.origin = NavOrigin::AddressBar;
        openAt(request);

        using namespace ks::ui::workbench_settings;
        SaveAddrHistory(PushAddrHistory(LoadAddrHistory(), text));
    }

    // onGoBackRequested / onGoForwardRequested：后退/前进栈互相转移当前地址。
    void MemoryWorkbenchView::onGoBackRequested()
    {
        if (backStack_.empty() || hexPane_ == nullptr)
        {
            return;
        }
        const std::uint64_t destination = backStack_.back();
        backStack_.pop_back();
        forwardStack_.push_back(hexPane_->insertionAddress());
        if (forwardStack_.size() > 64U)
        {
            forwardStack_.erase(forwardStack_.begin());
        }
        // 后退/前进是新的导航，之前挂起的"切换并跳转"请求随之作废（第二轮复核 B6：
        // 旧实现点后退后该按钮仍然可见，点了会跳到一个用户已经离开的地址）。
        clearScopeSwitchPrompt();
        hexPane_->jumpTo(destination);
        leavePointerChainNavigation();
    }

    void MemoryWorkbenchView::onGoForwardRequested()
    {
        if (forwardStack_.empty() || hexPane_ == nullptr)
        {
            return;
        }
        const std::uint64_t destination = forwardStack_.back();
        forwardStack_.pop_back();
        backStack_.push_back(hexPane_->insertionAddress());
        if (backStack_.size() > 64U)
        {
            backStack_.erase(backStack_.begin());
        }
        clearScopeSwitchPrompt();
        hexPane_->jumpTo(destination);
        leavePointerChainNavigation();
    }

    // onRerouteButtonClicked："切换并跳转"按钮——用户主动确认才真正切换范围。
    void MemoryWorkbenchView::onRerouteButtonClicked()
    {
        if (!pendingScopeSwitchRequest_.has_value())
        {
            return;
        }
        const NavRequest request = *pendingScopeSwitchRequest_;
        pendingScopeSwitchRequest_.reset();
        if (rerouteButton_ != nullptr)
        {
            rerouteButton_->setVisible(false);
        }
        openAt(request);
    }

    // ------------------------------------------------------------
    // 十六进制子页转发
    // ------------------------------------------------------------

    void MemoryWorkbenchView::onHexPaneInsertionPointChanged(quint64 address)
    {
        refreshProtectionDisplay();
        if (int3Panel_ != nullptr)
        {
            int3Panel_->SetInsertionPoint(address, true);
        }
        // 子页可见时十六进制的插入点/选区变了（点选、地址条回车、后退/前进都会走到这里）：
        // 让当前这页跟随；跟随过程中自己引起的跳转由 subPageFollowBusy_ 挡住，不会递归。
        if (subTabStack_ != nullptr && !subPageFollowBusy_)
        {
            const int currentTab = subTabStack_->currentIndex();
            if (detail::IsFollowSubPage(currentTab))
            {
                followSubPage(currentTab, false);
            }
        }
    }

    void MemoryWorkbenchView::onHexPaneEditRejected(const QString& reason)
    {
        if (statusBar_ != nullptr)
        {
            statusBar_->setWriteResultText(reason);
        }
    }

    // onHexPaneContextMenuAboutToShow：追加 ux.md §4.1 的四个菜单项，右键菜单
    // 显式套不透明样式（AGENTS.md：右键菜单是高风险点）。
    void MemoryWorkbenchView::onHexPaneContextMenuAboutToShow(QMenu* menu, quint64 address, bool hasByte)
    {
        if (menu == nullptr)
        {
            return;
        }
        menu->setStyleSheet(KswordTheme::ContextMenuStyle());
        menu->addSeparator();

        // 本项目不使用 Qt 的 tr()：QAction 是标准 Qt 类型，text/toolTip 属性
        // 直接写中文源文本即可被运行期整树扫描翻译（与 Int3PatchPanel.cpp 的
        // 右键菜单项同一惯例）。
        auto* addToBook = menu->addAction(QStringLiteral("添加到地址簿"));
        addToBook->setToolTip(QStringLiteral("把插入点加入书签（Ctrl+B）"));
        connect(addToBook, &QAction::triggered, this, [this, address]() {
            addInsertionPointToAddressBook(address);
        });

        auto* writeString = menu->addAction(QStringLiteral("写入字符串…"));
        writeString->setEnabled(hasByte);
        connect(writeString, &QAction::triggered, this, [this, address]() {
            WorkbenchStringWriteDialog dialog(this);
            if (dialog.exec() == QDialog::Accepted && writeController_)
            {
                writeController_->beginPendingStage(address, dialog.resultBytes());
            }
        });

        // "从此处反汇编"：旧实现调的是 onDisasmRequestHexLocate（在十六进制里重定位并停在十六进制页），
        // 点了之后反汇编页什么都没发生，菜单名与行为相反。现在直接切到反汇编页并锚到被点的地址，
        // 十六进制的选区保持不变。
        auto* openDisasm = menu->addAction(QStringLiteral("从此处反汇编"));
        connect(openDisasm, &QAction::triggered, this, [this, address]() {
            showSubPageAt(1, address);
        });

        // 修复缺陷 2（审核报告 wpJ6/wave3 发现 2）：原实现永远调用 Install、从不
        // Restore，结果被直接丢弃——菜单名暗示的"还原"分支永远不会发生，点击后
        // 界面没有任何反馈。现按"该地址对当前目标是否已有待还原的 int3 补丁"
        // 二选一，菜单文字与悬停说明随状态变化；只查"待还原条目"（Entries()），
        // 已孤立/已还原的条目不会匹配，与 Int3Controller 的既有口径一致。
        // 独立内存模式不安装或还原 int3；其它查看和编辑动作仍然保留。
        if (memoryDebugMode_)
        {
            return;
        }
        bool hasExistingPatch = false;
        if (target_ != nullptr)
        {
            const auto& session = target_->session();
            for (const auto& entry : WorkbenchShared::Instance().Int3().Entries())
            {
                if (entry.pid == session.pid &&
                    entry.processCreateTime100ns == session.processCreateTime100ns &&
                    entry.address == address)
                {
                    hasExistingPatch = true;
                    break;
                }
            }
        }
        auto* toggleInt3 = menu->addAction(hasExistingPatch
            ? QStringLiteral("还原 int3 补丁")
            : QStringLiteral("写入 int3 补丁"));
        toggleInt3->setToolTip(hasExistingPatch
            ? QStringLiteral("还原此处之前写入的 int3（Ctrl+Shift+P）")
            : QStringLiteral("在插入点写入 int3（0xCC），记下原字节以便还原（Ctrl+Shift+P）"));
        connect(toggleInt3, &QAction::triggered, this, [this, address]() {
            onToggleInt3AtAddress(address);
        });
    }

    // onToggleInt3AtAddress：见头文件声明处的注释，上面右键菜单项的真正执行
    // 函数。结果统一走 onInt3ResultMessage（与 int3Panel_ 的 resultMessage 同一
    // 处理函数），失败/成功都会在状态条留下一句话，不再无声无息。
    void MemoryWorkbenchView::onToggleInt3AtAddress(quint64 address)
    {
        // 快捷键与已打开菜单同样受当前模式约束，隐藏按钮不等于阻止操作。
        if (memoryDebugMode_)
        {
            return;
        }
        const QPointer<MemoryWorkbenchView> self(this);
        if (target_ == nullptr)
        {
            return;
        }
        const auto session = target_->session();
        if (!self) return;
        // Install/Restore 的路由预检与目标匹配都读账本的"当前目标"，先声明回本视图的会话。
        applyInt3Context(session);
        if (!self) return;
        auto& int3 = WorkbenchShared::Instance().Int3();
        std::optional<std::uint64_t> existingId;
        for (const auto& entry : int3.Entries())
        {
            if (entry.pid == session.pid &&
                entry.processCreateTime100ns == session.processCreateTime100ns &&
                entry.address == address)
            {
                existingId = entry.id;
                break;
            }
        }
        if (existingId.has_value())
        {
            const auto outcome = int3.Restore(*existingId);
            if (!self) return;
            onInt3ResultMessage(
                TranslateInt3RestoreOutcome(outcome),
                outcome.status != ksword::memwb::RestoreStatus::Restored);
            return;
        }
        std::string validationFailure;
        const bool allowed = validatePointerChainWrite(session, address, 1, validationFailure);
        if (!self) return;
        if (!allowed)
        {
            onInt3ResultMessage(QString::fromUtf8(validationFailure.c_str()), true);
            return;
        }
        const auto context = int3.CurrentTarget();
        if (context.pid != session.pid || context.processCreateTime100ns != session.processCreateTime100ns
            || context.attachGeneration != session.attachGeneration || int3.CurrentScope() != session.scope
            || int3.CurrentChannel() != session.channel)
        {
            onInt3ResultMessage(ks::i18n::sourceText(QStringLiteral("目标身份与请求不一致")), true);
            return;
        }
        const ksword::memwb::PatchTarget patchTarget{
            session.pid, session.processCreateTime100ns, session.attachGeneration};
        // nowTick：int3 账本要求调用方给定时钟读数以保持可测；界面侧用系统时钟
        // 即可（与 Int3PatchPanel::onInstallClicked 同一取法）。
        const std::uint64_t nowTick = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
        const auto outcome = int3.Install(patchTarget, address, nowTick);
        if (!self) return;
        const bool isError = (outcome.routeReject != Int3RouteReject::None) ||
            (outcome.status != ksword::memwb::InstallStatus::Installed);
        onInt3ResultMessage(TranslateInt3InstallOutcome(outcome, address), isError);
    }

    void MemoryWorkbenchView::onDisasmStageRequested(quint64 address, QByteArray bytes)
    {
        if (hexPane_ == nullptr || hexPane_->canvas() == nullptr)
        {
            return;
        }
        QString reason;
        if (!hexPane_->canvas()->stageBytes(address, bytes, &reason) && statusBar_ != nullptr)
        {
            statusBar_->setWriteResultText(reason);
        }
    }

    void MemoryWorkbenchView::onDisasmRequestHexLocate(quint64 address)
    {
        if (hexPane_ != nullptr)
        {
            hexPane_->jumpTo(address);
        }
        if (subTabStack_ != nullptr)
        {
            subTabStack_->setCurrentIndex(0);
        }
    }
}
