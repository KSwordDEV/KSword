#include "MemoryWorkbenchView.h"
#include "MemoryRowCanvas.h"
#include "HexViewWidgets.h"
#include "WorkbenchDisasmView.h"
#include "WorkbenchHexPane.h"
#include "WorkbenchTextView.h"
#include "WorkbenchTarget.h"
#include "../X64DbgNavigation.h"
#include <QMenu>
#include <QScopedValueRollback>
#include <QStackedWidget>
#include <algorithm>

namespace ks::ui
{
    void MemoryWorkbenchView::openActiveFind()
    {
        const int index = subTabStack_ ? subTabStack_->currentIndex() : 0;
        if (index == 1 && disasmView_) disasmView_->openFind();
        else if (index == 2 && textView_) textView_->openFind();
        else if (hexPane_) hexPane_->openFind();
    }
    void MemoryWorkbenchView::requestRowCanvasWindow(int tabIndex, std::uint64_t address, std::uint64_t length)
    {
        if (!hexPane_ || tabIndex < 1 || tabIndex > 2 || !length) return;
        const auto bounds = hexPane_->canvas()->addressSpaceRange();
        if (!bounds || address < bounds->first || address > bounds->last) return;
        QScopedValueRollback<bool> guard(subPageFollowBusy_, true);
        auto& state = subPageFollow_[static_cast<std::size_t>(tabIndex - 1)];
        state.anchor = address;
        state.positioned = true;
        state.dirty = true;
        if (tabIndex == 2)
        {
            const auto before = std::min<std::uint64_t>(4, address - bounds->first);
            hexPane_->requestBrowseWindow(address - before, std::min<std::uint64_t>(length, 65528) + before + 4);
        }
        else hexPane_->requestBrowseWindow(address, std::min<std::uint64_t>(length, 65536));
    }

    void MemoryWorkbenchView::connectRowCanvasSignals()
    {
        connect(disasmView_, &WorkbenchDisasmView::windowRequested, this,
            [this](quint64 address, quint64 length) { requestRowCanvasWindow(1, address, length); });
        connect(textView_, &WorkbenchTextView::windowRequested, this,
            [this](quint64 address, quint64 length) { requestRowCanvasWindow(2, address, length); });
        const auto selectHex = [this](int index, quint64 first, quint64 last) {
            if (!subTabStack_ || subTabStack_->currentIndex() != index || !hexPane_) return;
            QScopedValueRollback<bool> guard(subPageFollowBusy_, true);
            auto* hex = hexPane_->canvas();
            // The whole instruction/scalar is selected; its first byte remains the insertion point.
            hex->setCaretAddress(last, false, false);
            hex->setCaretAddress(first, true, false);
            auto& state = subPageFollow_[static_cast<std::size_t>(index - 1)];
            state.syncedSelectionStart = first;
        };
        connect(disasmView_, &WorkbenchDisasmView::selectionChanged, this,
            [selectHex](quint64 first, quint64 last) { selectHex(1, first, last); });
        connect(textView_, &WorkbenchTextView::selectionChanged, this,
            [selectHex](quint64 first, quint64 last) { selectHex(2, first, last); });
        connect(textView_, &WorkbenchTextView::requestHexLocate, this, [this](quint64 address) {
            QScopedValueRollback<bool> guard(subPageFollowBusy_, true);
            const auto selection = textView_->selectedByteRange();
            subTabStack_->setCurrentIndex(0);
            subTabSegmented_->setCurrentIndex(0);
            if (selection)
            {
                hexPane_->canvas()->setCaretAddress(selection->second, false, false);
                hexPane_->canvas()->setCaretAddress(selection->first, true, true);
            }
            else hexPane_->canvas()->setCaretAddress(address);
        });
        const auto addDebugger = [this](QMenu* menu, quint64 address, x64dbg_navigation::View view) {
            // 此模式承诺不创建调试附加；启动新 x64dbg 的导航入口在这里隐藏。
            if (memoryDebugMode_)
            {
                return;
            }
            if (!target_ || !menu) return;
            const auto session = target_->session();
            if (session.scope != ksword::memwb::Scope::ProcessVirtual || !session.pid
                || !session.processCreateTime100ns) return;
            // Navigation belongs to the identity that produced these bytes.
            // Looking up a missing identity here could authorize a reused PID.
            x64dbg_navigation::AddAction(menu, this, {session.pid, session.processCreateTime100ns, address, view});
        };
        connect(disasmView_, &WorkbenchDisasmView::contextMenuAboutToShow, this,
            [addDebugger](QMenu* menu, quint64 address, bool valid) { if (valid) addDebugger(menu, address, x64dbg_navigation::View::Disassembly); });
        connect(textView_, &WorkbenchTextView::contextMenuAboutToShow, this,
            [addDebugger](QMenu* menu, quint64 address, bool valid) { if (valid) addDebugger(menu, address, x64dbg_navigation::View::Dump); });
        connect(hexPane_->canvas(), &HexCanvas::contextMenuAboutToShow, this,
            [addDebugger](QMenu* menu, quint64 address, bool valid) { if (valid) addDebugger(menu, address, x64dbg_navigation::View::Dump); });
        // Zoom is a shared preference; changing it preserves every view's address selection and cache.
        connect(disasmView_->canvas(), &MemoryRowCanvas::zoomChanged, this, [this](int steps) {
            textView_->canvas()->setZoomSteps(steps);
            hexPane_->canvas()->setZoomLevel(steps);
        });
        connect(textView_->canvas(), &MemoryRowCanvas::zoomChanged, this, [this](int steps) {
            disasmView_->canvas()->setZoomSteps(steps);
            hexPane_->canvas()->setZoomLevel(steps);
        });
        connect(hexPane_->canvas(), &HexCanvas::zoomLevelChanged, this, [this](int steps) {
            disasmView_->canvas()->setZoomSteps(steps);
            textView_->canvas()->setZoomSteps(steps);
        });
    }
}
