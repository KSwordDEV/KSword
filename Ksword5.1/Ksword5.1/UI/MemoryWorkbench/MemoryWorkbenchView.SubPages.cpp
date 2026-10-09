// ============================================================
// MemoryWorkbenchView.SubPages.cpp
// 作用：反汇编 / 文本 / 对比三个只读子页的"自动跳转（跟随十六进制）"。
//
// 真机反馈：三个子页切过去不会自动跳转——文本页与对比页从来没人喂过真地址（会话重置时只被设成
// 空窗口），反汇编页只有 Ctrl+D 会跳。根因有四层，只补"切页签时调一下 jumpTo"解决不了：
// 1) 三页的字节只能来自十六进制窗口已读到的部分（DisasmBytesProviderAdapter 只读叠加层），
//    宿主必须按基线窗口替文本/对比页算好窗口，让目标地址落在窗口里；
// 2) 基线是异步到达的：跳转那一刻窗口多半还没覆盖目标，必须订阅画布的 contentChanged 再刷新；
// 3) 附加后十六进制的插入点恒停在地址空间起点，没有"选区"可跟——此时落到起始模块的基址；
// 4) 重启后恢复在子页再附加进程时没有 currentChanged 事件，会话身份变化后要补一次跟随。
//
// 跟随规则（同步令牌）：
// - 每个子页记一个"令牌"：上次跟随时十六进制的原始选区起点（syncedSelectionStart）。
// - 切回子页 / 十六进制插入点变化 / 数据到达时，只有三种情况才重新定位：从未定位过、
//   令牌与当前选区起点不同（十六进制动过）、被强制（force）；否则只刷新数据，保留用户在
//   子页里手动导航到的位置（例如在反汇编里追 call 追到的地方）。
// - 显式动作（Ctrl+D、右键"从此处反汇编"）总是覆盖，并把令牌记成当前选区起点，避免随后
//   的 currentChanged 再覆盖一次。
//
// 没有选区时的落点：选区起点 == 地址空间起点视为"没动过"——进程范围取起始模块（先按进程名命中，
// 没命中取名字以 .exe 结尾的最低基址模块，再不行取最低基址），内核范围取 ntoskrnl.exe；模块目录
// 还在加载就挂起，等 modulesChanged / modulesFailed 再重试；目录失败/不可用就退回当前插入点，不空等。
// 物理范围与 DDMA 通道不做模块兜底（物理没有模块；DDMA 读取要借磁盘扇区中转，不能替用户自作主张）。
// ============================================================

#include "MemoryWorkbenchView.h"

#include "HexCanvas.h"
#include "WorkbenchCompareView.h"
#include "WorkbenchDisasmView.h"
#include "WorkbenchHexPane.h"
#include "WorkbenchTarget.h"
#include "WorkbenchTextView.h"

#include "../../../../shared/evidence/memory_workbench/MemoryDiffOverlay.h"
#include "../../../../shared/evidence/memory_workbench/SessionAddressResolver.h"

#include <QPointer>
#include <QScopedValueRollback>
#include <QScrollBar>
#include <QStackedWidget>
#include <QTableView>

#include <algorithm>
#include <limits>

namespace ks::ui
{
    namespace
    {
        // kDisasmTab / kTextTab / kCompareTab：三个只读子页在 subTabStack_ 里的下标。
        constexpr int kDisasmTab = 1;
        constexpr int kTextTab = 2;
        constexpr int kCompareTab = 3;

        // IsFollowTab：下标是否是需要跟随的只读子页（十六进制页自己就是被跟随的对象）。
        bool IsFollowTab(const int tabIndex)
        {
            return tabIndex >= kDisasmTab && tabIndex <= kCompareTab;
        }

        // AddressInWindow：address 是否落在 [base, base+size) 里；size 为 0 恒为假，不会因加法回绕误判。
        bool AddressInWindow(const std::uint64_t base, const std::uint64_t size, const std::uint64_t address)
        {
            return size > 0 && address >= base && (address - base) < size;
        }
    }

    // resetSubPageFollow：会话身份变化时调用——三页的跟随状态清零，文本页与对比页回到"尚未定位"。
    // （反汇编页的 reset 由 handleIdentityChange 自己做，这里不重复。）
    void MemoryWorkbenchView::resetSubPageFollow()
    {
        subPageFollow_.fill(SubPageFollowState{});
        subPageFollowPending_ = false;
        if (textView_ != nullptr)
        {
            textView_->reset();
        }
        if (compareView_ != nullptr)
        {
            compareView_->reset();
        }
    }

    // attachedProcessNameHint：宿主按 pid 查到的进程名（没有注入查询回调或查不到时为空串）。
    QString MemoryWorkbenchView::attachedProcessNameHint(const std::uint32_t pid) const
    {
        if (pid == 0 || !attachedProcessInfoProvider_)
        {
            return QString();
        }
        const auto info = attachedProcessInfoProvider_(pid);
        return info.has_value() ? info->processName : QString();
    }

    // ensureWindowCovers：目标地址不在叠加层基线窗口里时，把十六进制画布滚到该地址——
    // 画布的可见范围变化会让基线喂入器以新视口为锚重选窗口，三个子页才读得到数据。
    // 滚动是异步生效的，数据到达后由 onSubPageDataChanged 再刷新一次。
    void MemoryWorkbenchView::ensureWindowCovers(const std::uint64_t address)
    {
        if (hexPane_ == nullptr || hexPane_->canvas() == nullptr)
        {
            return;
        }
        const auto& overlay = hexPane_->overlay();
        if (AddressInWindow(overlay.BaseAddress(), overlay.BaselineSize(), address))
        {
            return;
        }
        hexPane_->requestBrowseWindow(address, 4096 + 15);
    }

    // positionSubPage：把某个子页定位到 address（不判断要不要跟随，调用方已决定）。
    // 反汇编：已定位在同一地址就只刷新，否则 jumpTo（会把旧锚点压进后退栈）；
    // 文本：窗口起点对齐到行宽，让目标落在第一行，长度取基线窗口内的有效长度（上限 kTextFollowBytes）；
    // 对比：窗口取基线窗口（上限 kCompareFollowBytes，目标前面留四分之一做上下文），再滚到目标所在分组。
    void MemoryWorkbenchView::positionSubPage(const int tabIndex, const std::uint64_t address, const bool scrollToTarget)
    {
        if (!IsFollowTab(tabIndex) || hexPane_ == nullptr || hexPane_->canvas() == nullptr)
        {
            return;
        }
        const auto& overlay = hexPane_->overlay();
        const std::uint64_t baseline = overlay.BaseAddress();
        const std::uint64_t baselineSize = overlay.BaselineSize();
        const bool covered = AddressInWindow(baseline, baselineSize, address);

        if (tabIndex == kDisasmTab)
        {
            if (disasmView_ == nullptr)
            {
                return;
            }
            if (const auto bounds = hexPane_->canvas()->addressSpaceRange()) disasmView_->setAddressBounds(bounds->first, bounds->last);
            const SubPageFollowState& state = subPageFollow_[0];
            if (state.positioned && disasmView_->anchorAddress() == address)
            {
                disasmView_->refreshView();
            }
            else
            {
                disasmView_->jumpTo(address);
            }
            return;
        }

        if (tabIndex == kTextTab)
        {
            if (textView_ == nullptr)
            {
                return;
            }
            const int rowBytes = std::max(1, hexPane_->canvas()->bytesPerRow());
            textView_->setBytesPerRow(rowBytes);
            const auto bounds = hexPane_->canvas()->addressSpaceRange();
            if (!bounds || address < bounds->first || address > bounds->last) { textView_->setWindow(address, 0); return; }
            textView_->setAddressBounds(bounds->first, bounds->last);
            const auto start = std::max(bounds->first, address - address % static_cast<std::uint64_t>(rowBytes));
            const auto length = std::min<std::uint64_t>(4096, bounds->last - start) + 1;
            textView_->setAddressBits(target_ ? target_->session().addressBits : 64);
            textView_->setWindow(start, length);
            return;
        }

        if (compareView_ == nullptr)
        {
            return;
        }
        if (!covered)
        {
            compareView_->setWindow(address, 0);
            return;
        }
        const std::uint64_t windowEnd = baseline + baselineSize;
        const std::uint64_t length = std::min<std::uint64_t>(baselineSize, kCompareFollowBytes);
        // 目标前面留四分之一窗口做上下文；再夹到 [baseline, windowEnd - length] 之内。
        std::uint64_t start = (address > baseline + length / 4U) ? (address - length / 4U) : baseline;
        start = std::min(start, windowEnd - length);
        compareView_->setWindow(start, length);
        if (scrollToTarget)
        {
            compareView_->scrollToAddress(address);
        }
    }

    // refreshSubPage：数据到达后刷新某个子页。反汇编只需要重新拉取；文本与对比的窗口依赖基线窗口，
    // 必须按上次定位的地址重新算窗口。
    void MemoryWorkbenchView::refreshSubPage(const int tabIndex)
    {
        if (!IsFollowTab(tabIndex))
        {
            return;
        }
        SubPageFollowState& state = subPageFollow_[static_cast<std::size_t>(tabIndex - 1)];
        if (!state.positioned)
        {
            return;
        }
        if (tabIndex == kDisasmTab)
        {
            if (disasmView_ != nullptr)
            {
                disasmView_->refreshView();
            }
        }
        else if (tabIndex == kCompareTab && compareView_ != nullptr)
        {
            // 对比页重算窗口会让表格 model reset；数据到达引起的刷新不能把用户从正在看的那一行拽回目标分组，
            // 所以不再滚到目标，并把滚动位置恢复成刷新前的值。
            QScrollBar* const bar = compareView_->table()->verticalScrollBar();
            const int previousScrollValue = bar->value();
            positionSubPage(tabIndex, state.anchor, false);
            bar->setValue(previousScrollValue);
        }
        else
        {
            // 文本页：窗口依赖基线窗口，按上次定位的地址重算；编辑器文本没变时 applyEditorText 不会重写，滚动位置保留。
            textView_->refreshView();
        }
        state.dirty = false;
    }

    // followSubPage：隐式跟随的核心——见文件头的规则。
    // 传入：tabIndex 要跟随的子页（1~3）；force 为真时无视令牌强制重新定位（身份变化后、模块列表就绪后）。
    void MemoryWorkbenchView::followSubPage(const int tabIndex, const bool force)
    {
        if (!IsFollowTab(tabIndex) || subPageFollowBusy_ || target_ == nullptr || hexPane_ == nullptr)
        {
            return;
        }
        // 先取会话再置 busy：session() 在 DDMA 通道下可能同步触发 sessionChanged，进而重入
        // handleIdentityChange 把本对象的状态改掉，取完立刻探活。
        const QPointer<MemoryWorkbenchView> self(this);
        const ksword::memwb::MemoryTargetSession session = target_->session();
        if (!self)
        {
            return;
        }
        QScopedValueRollback<bool> busyGuard(subPageFollowBusy_, true);
        subPageFollowPending_ = false;

        // 没有可用目标：保持"尚未定位"占位文案，不把 0x0 当成"用户在看地址 0"。
        if (session.scope == ksword::memwb::Scope::ProcessVirtual && session.pid == 0)
        {
            return;
        }

        SubPageFollowState& state = subPageFollow_[static_cast<std::size_t>(tabIndex - 1)];
        std::uint64_t raw = hexPane_->selectionStart();
        if (!force && state.positioned && state.syncedSelectionStart == raw)
        {
            // 十六进制没动过：只刷新数据，保留用户在子页里的手动位置。
            if (state.dirty)
            {
                refreshSubPage(tabIndex);
            }
            return;
        }

        std::uint64_t address = raw;
        const ksword::memwb::AddrSpace space = ksword::memwb::ScopeAddressSpace(session);
        const bool untouched = raw == space.first
            && session.scope != ksword::memwb::Scope::Physical
            && session.channel != ksword::memwb::Channel::Ddma;
        if (untouched)
        {
            const WorkbenchTarget::PrimaryModuleResult module =
                target_->primaryModule(attachedProcessNameHint(session.pid));
            if (module.state == WorkbenchTarget::PrimaryModuleState::Loading)
            {
                // 模块目录还在加载：挂起，等 modulesChanged / modulesFailed 再来一次。
                subPageFollowPending_ = true;
                return;
            }
            if (module.state == WorkbenchTarget::PrimaryModuleState::Ready)
            {
                // 十六进制也落到模块基址：让三个子页与十六进制在同一位置，数据才读得到。
                if (hexPane_->jumpTo(module.record.base))
                {
                    raw = module.record.base;
                    address = module.record.base;
                }
            }
        }

        ensureWindowCovers(address);
        // positionSubPage 里的反汇编分支靠 state.positioned 判断"是不是同一地址的重复跳转"，
        // 它反映的是"之前"有没有定位过，所以必须先定位、后置位。
        positionSubPage(tabIndex, address);
        state.positioned = true;
        state.syncedSelectionStart = raw;
        state.anchor = address;
        state.dirty = false;
    }

    NavStatus MemoryWorkbenchView::showDisassemblyAt(const std::uint64_t address)
    {
        if (!target_)
        {
            return NavStatus::Unavailable;
        }
        // 公开入口沿用当前身份，不能用 pid=0 意外取消独立钉住目标。
        const QPointer<MemoryWorkbenchView> self(this);
        const auto current = target_->session();
        if (!self)
        {
            return NavStatus::LeaveRefused;
        }
        NavRequest request;
        request.scope = current.scope;
        request.pid = current.pid;
        request.createTime = current.processCreateTime100ns;
        request.address = address;
        request.focusView = false;
        request.origin = NavOrigin::External;
        const NavStatus result = openAt(request);
        if (!self || result != NavStatus::Ok)
        {
            return result;
        }
        // 显式定位使用同一基线读池；数据晚到时原有跟随令牌保持这个地址。
        showSubPageAt(kDisasmTab, address);
        return NavStatus::Ok;
    }

    // showSubPageAt：显式地址（Ctrl+D、右键"从此处反汇编"）。总是覆盖，并把令牌记成当前选区起点，
    // 之后 setCurrentIndex 触发的隐式跟随看到令牌相同就不会再覆盖。
    void MemoryWorkbenchView::showSubPageAt(const int tabIndex, const std::uint64_t address)
    {
        if (!IsFollowTab(tabIndex) || target_ == nullptr || hexPane_ == nullptr || subTabStack_ == nullptr)
        {
            return;
        }
        {
            // busy 期间 positionSubPage/ensureWindowCovers 引发的插入点/内容信号不会再触发跟随。
            QScopedValueRollback<bool> busyGuard(subPageFollowBusy_, true);
            ensureWindowCovers(address);
            positionSubPage(tabIndex, address);
            SubPageFollowState& state = subPageFollow_[static_cast<std::size_t>(tabIndex - 1)];
            state.positioned = true;
            state.syncedSelectionStart = hexPane_->selectionStart();
            state.anchor = address;
            state.dirty = false;
        }
        subTabStack_->setCurrentIndex(tabIndex);
    }

    // onSubTabChanged：子页签切换（分段按钮、快捷键、loadSettings 恢复上次子页都经 currentChanged）。
    void MemoryWorkbenchView::onSubTabChanged(const int tabIndex)
    {
        if (hexPane_) hexPane_->setExternalBrowseMode(tabIndex == 1 || tabIndex == 2);
        if (IsFollowTab(tabIndex))
        {
            followSubPage(tabIndex, false);
        }
    }

    // onSubPageDataChanged：画布内容可能变了（页回填、换代次、暂存/丢弃、基线喂入）。
    // 三页都标脏；只处理当前可见的那一页，其余切过去时再刷。
    void MemoryWorkbenchView::onSubPageDataChanged()
    {
        for (SubPageFollowState& state : subPageFollow_)
        {
            state.dirty = true;
        }
        if (subTabStack_ == nullptr || subPageFollowBusy_)
        {
            return;
        }
        const int current = subTabStack_->currentIndex();
        if (IsFollowTab(current))
        {
            followSubPage(current, false);
        }
    }

    // onTargetModulesChanged：模块目录就绪或失败。只在有挂起的跟随请求、且当前就在子页时重试。
    void MemoryWorkbenchView::onTargetModulesChanged(const bool kernel)
    {
        Q_UNUSED(kernel);
        if (!subPageFollowPending_ || subTabStack_ == nullptr)
        {
            return;
        }
        const int current = subTabStack_->currentIndex();
        if (IsFollowTab(current))
        {
            followSubPage(current, false);
        }
    }
}
