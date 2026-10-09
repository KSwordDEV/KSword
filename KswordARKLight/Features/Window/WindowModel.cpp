#include "../../../shared/usermode/backend/window/WindowFormatting.h"
#include "WindowModel.h"

#include <algorithm>
#include <sstream>
#include <utility>

namespace Ksword::Features::Window {
namespace {
using namespace ks::r3::window;

// AddProperty appends a detail row. Inputs are detail, label and value; processing
// omits empty values to avoid noisy detail panes; no value is returned.
void AddProperty(WindowDetail& detail, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        detail.properties.push_back({ name, value });
    }
}

// StyleToText formats a window style value. Input is a DWORD style; output is a
// hexadecimal display string suitable for diagnostics.
std::wstring StyleToText(DWORD style) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << style;
    return stream.str();
}

// ProcessColumnText combines process identity into one compact list column.
// Inputs are a window row with process name/PID; output is suitable for the
// ListView PID column that now carries process icon, name, and numeric PID.
std::wstring ProcessColumnText(const WindowSnapshotRow& row) {
    const std::wstring name = row.processName.empty() ? L"(unknown process)" : row.processName;
    return name + L" (" + std::to_wstring(row.processId) + L")";
}

} // namespace

WindowModel::WindowModel() = default;

void WindowModel::setRows(std::vector<WindowSnapshotRow> rows) {
    originalRows_ = std::move(rows);
    rebuildRows();
}

void WindowModel::setSortMode(WindowSortMode mode) {
    if (sortMode_ == mode) {
        return;
    }
    sortMode_ = mode;
    rebuildRows();
}

WindowSortMode WindowModel::sortMode() const {
    return sortMode_;
}

const std::vector<WindowSnapshotRow>& WindowModel::rows() const {
    return rows_;
}

const WindowSnapshotRow* WindowModel::rowAt(int index) const {
    if (index < 0 || index >= static_cast<int>(rows_.size())) {
        return nullptr;
    }
    return &rows_[index];
}

void WindowModel::rebuildRows() {
    rows_ = originalRows_;
    if (sortMode_ == WindowSortMode::StackingOrder) {
        return;
    }

    std::sort(rows_.begin(), rows_.end(), [](const WindowSnapshotRow& left, const WindowSnapshotRow& right) {
        const std::wstring leftName = left.processName.empty() ? L"(unknown process)" : left.processName;
        const std::wstring rightName = right.processName.empty() ? L"(unknown process)" : right.processName;
        if (leftName != rightName) {
            return leftName < rightName;
        }
        if (left.processId != right.processId) {
            return left.processId < right.processId;
        }
        if (left.title != right.title) {
            return left.title < right.title;
        }
        return reinterpret_cast<UINT_PTR>(left.hwnd) < reinterpret_cast<UINT_PTR>(right.hwnd);
    });
}

std::wstring WindowModel::textForColumn(const WindowSnapshotRow& row, int column) const {
    switch (column) {
    case 0:
        return ProcessColumnText(row);
    case 1:
        return HwndToText(row.hwnd);
    case 2:
        return row.title.empty() ? L"(untitled)" : row.title;
    case 3:
        return row.className;
    case 4:
        return WindowStateText(row);
    default:
        break;
    }
    return {};
}

WindowDetail WindowModel::detailFromRow(const WindowSnapshotRow& row) const {
    WindowDetail detail;
    detail.found = true;
    detail.hwnd = row.hwnd;
    detail.title = row.title.empty() ? HwndToText(row.hwnd) : row.title;
    AddProperty(detail, L"HWND", HwndToText(row.hwnd));
    AddProperty(detail, L"Title", row.title.empty() ? L"(untitled)" : row.title);
    AddProperty(detail, L"Class", row.className);
    AddProperty(detail, L"Process ID", std::to_wstring(row.processId));
    AddProperty(detail, L"Process name", row.processName);
    AddProperty(detail, L"Thread ID", std::to_wstring(row.threadId));
    AddProperty(detail, L"State", WindowStateText(row));
    AddProperty(detail, L"Window rect", RectToText(row.windowRect));
    AddProperty(detail, L"Client rect", RectToText(row.clientRect));
    AddProperty(detail, L"Style", StyleToText(row.style));
    AddProperty(detail, L"Extended style", StyleToText(row.exStyle));
    AddProperty(detail, L"Unicode", row.unicode ? L"Yes" : L"No");
    AddProperty(detail, L"Process image", row.processImagePath);
    return detail;
}







} // namespace Ksword::Features::Window
