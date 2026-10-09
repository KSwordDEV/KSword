#include "MemoryWorkbenchView.h"
#include "MemoryWorkbenchView.Internal.h"
#include "WorkbenchPseudocodeView.h"
#include "WorkbenchDisasmView.h"
#include "HexViewWidgets.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"
#include <QMenu>
#include <QPointer>
#include <QStackedWidget>
#include <algorithm>

namespace ks::ui
{
    // updatePseudocodeContext：把共同目标身份、来源代次、选区和缓存范围交给 C 页。
    // 没有多字节选区时读取函数位置后的一个 4 KiB 窗口，永远夹在当前地址空间内。
    void MemoryWorkbenchView::updatePseudocodeContext(const std::uint64_t address)
    {
        if (!pseudocodeView_ || !hexPane_ || !target_) return;
        const QPointer<MemoryWorkbenchView> self(this);
        const auto session = target_->session(); // session() 可能触发通道退化和重入。
        if (!self) return;
        WorkbenchPseudocodeContext context;
        context.sourceIdentity = QString::fromStdString(detail::BuildSessionIdentityKey(session));
        context.revision = target_->revisions().Source();
        context.addressBits = static_cast<int>(session.addressBits);
        context.maximumWindowBytes = 65536; // 共用缓存适配器一次只提供最多 64 KiB。
        context.baseAddress = address;
        context.selectedAddress = address;
        const auto bounds = hexPane_->canvas()->addressSpaceRange();
        if (bounds && address >= bounds->first && address <= bounds->last)
        {
            const auto selected = hexPane_->canvas()->selectedRange();
            if (selected && selected->first == address && selected->last > address)
            {
                // 显式选区必须完整分析，不能把范围尾部静默丢掉或补零。
                const auto delta = selected->last - address;
                context.length = delta == UINT64_MAX ? UINT64_MAX : delta + 1;
            }
            else context.length = std::min<std::uint64_t>(4095, bounds->last - address) + 1;
        }
        pseudocodeView_->setContext(context);
    }

    // connectPseudocodeSignals：C 页只有请求和导航信号，读取走既有 HEX 管线。
    void MemoryWorkbenchView::connectPseudocodeSignals()
    {
        connect(pseudocodeView_, &WorkbenchPseudocodeView::windowRequested, this,
            [this](quint64 address, quint64 length) {
                if (!hexPane_ || !length) return;
                const auto bounds = hexPane_->canvas()->addressSpaceRange();
                if (!bounds || address < bounds->first || address > bounds->last
                    || length - 1 > bounds->last - address) return;
                const QPointer<MemoryWorkbenchView> self(this);
                const bool wasBusy = subPageFollowBusy_;
                subPageFollowBusy_ = true;
                hexPane_->requestBrowseWindow(address, length);
                if (self) subPageFollowBusy_ = wasBusy;
            });
        connect(pseudocodeView_, &WorkbenchPseudocodeView::requestHexLocate, this,
            [this](quint64 address) {
                const QPointer<MemoryWorkbenchView> self(this);
                if (!hexPane_ || !hexPane_->jumpTo(address) || !self) return;
                subTabStack_->setCurrentIndex(0);
            });
        connect(pseudocodeView_, &WorkbenchPseudocodeView::requestDisasmLocate, this,
            [this](quint64 address) { showDisassemblyAt(address); });

        // 两个代码入口共用同一 C 子页；菜单显式套主题背景，避免透明继承。
        const auto addPseudocode = [this](QMenu* menu, quint64 address, bool valid) {
            if (!menu) return;
            menu->setStyleSheet(KswordTheme::ContextMenuStyle());
            auto* action = menu->addAction(ks::i18n::sourceText(QStringLiteral("反编译当前函数")));
            action->setEnabled(valid);
            action->setToolTip(ks::i18n::sourceText(QStringLiteral("C 伪代码")));
            connect(action, &QAction::triggered, this, [this, address]() { showPseudocodeAt(address); });
        };
        connect(disasmView_, &WorkbenchDisasmView::contextMenuAboutToShow, this, addPseudocode);
        connect(hexPane_->canvas(), &HexCanvas::contextMenuAboutToShow, this, addPseudocode);
    }

    // showPseudocodeAt：保留目标身份并走正式导航，再启动统一的函数分析页面。
    NavStatus MemoryWorkbenchView::showPseudocodeAt(const std::uint64_t address)
    {
        if (!target_ || !pseudocodeView_) return NavStatus::Unavailable;
        const QPointer<MemoryWorkbenchView> self(this);
        const auto session = target_->session();
        if (!self) return NavStatus::LeaveRefused;
        NavRequest request;
        request.scope = session.scope;
        request.pid = session.pid;
        request.createTime = session.processCreateTime100ns;
        request.address = address;
        request.focusView = false;
        request.origin = NavOrigin::External;
        const auto status = openAt(request);
        if (!self || status != NavStatus::Ok) return status;
        showSubPageAt(4, address);
        if (self) pseudocodeView_->startDecompilation();
        return status;
    }
}
