#include "EvidenceTimeline.h"

#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/Theme.h"

#include <windowsx.h>

#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr wchar_t kTimelineClass[] = L"KswordARKLight.ActionAnalyzeTimeline";
constexpr std::size_t kNamedLanes = 4;
using Ksword::Ui::Scale;

std::wstring LaneName(const std::vector<std::uint16_t>& categories, std::size_t lane) {
    return lane < categories.size() ? std::to_wstring(categories[lane]) : L"其余";
}

} // namespace

bool EvidenceTimeline::create(HWND parent, int controlId, std::function<void(std::size_t)> select) {
    select_ = std::move(select);
    const auto instance = reinterpret_cast<HINSTANCE>(::GetWindowLongPtrW(parent, GWLP_HINSTANCE));
    WNDCLASSW cls{};
    cls.lpfnWndProc = WindowProc;
    cls.hInstance = instance;
    cls.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    cls.lpszClassName = kTimelineClass;
    if (!::RegisterClassW(&cls) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    return ::CreateWindowExW(0, kTimelineClass, L"接收 QPC 瀑布", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)), instance, this) != nullptr;
}

std::size_t EvidenceTimeline::laneFor(std::uint16_t category) const {
    return static_cast<std::size_t>(std::find(categories_.begin(), categories_.end(), category) - categories_.begin());
}

void EvidenceTimeline::replace(const std::vector<EvidenceRecord>& rows) {
    points_.clear();
    categories_.clear();
    visible_.clear();
    selected_.reset();
    offset_ = 0;
    wheelRemainder_ = 0;
    for (const auto& row : rows) if (row.eventOrdinal) categories_.push_back(row.category);
    std::sort(categories_.begin(), categories_.end());
    categories_.erase(std::unique(categories_.begin(), categories_.end()), categories_.end());
    other_ = categories_.size() > kNamedLanes;
    if (other_) categories_.resize(kNamedLanes);
    enabled_.assign(categories_.size() + (other_ ? 1 : 0), true);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto& row = rows[i];
        if (row.receiveQpc) points_.push_back({ *row.receiveQpc, i, laneFor(row.category) });
    }
    std::stable_sort(points_.begin(), points_.end(), [](const Point& a, const Point& b) { return a.ticks < b.ticks; });
    scrollTo(0);
}

bool EvidenceTimeline::includes(const EvidenceRecord& record) const {
    return !record.eventOrdinal || enabled_[laneFor(record.category)];
}

bool EvidenceTimeline::chooseCategories(HWND anchor) {
    if (enabled_.empty()) return false;
    const HMENU menu = ::CreatePopupMenu();
    if (!menu) return false;
    for (std::size_t lane = 0; lane < enabled_.size(); ++lane) {
        const auto title = L"类别 " + LaneName(categories_, lane);
        ::AppendMenuW(menu, MF_STRING | (enabled_[lane] ? MF_CHECKED : MF_UNCHECKED), lane + 1, title.c_str());
    }
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    const UINT reset = static_cast<UINT>(enabled_.size() + 1);
    ::AppendMenuW(menu, MF_STRING, reset, L"显示所有类别");
    RECT rect{};
    ::GetWindowRect(anchor, &rect);
    const UINT picked = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, rect.left, rect.bottom, 0,
        ::GetParent(hwnd_), nullptr);
    ::DestroyMenu(menu);
    if (!picked) return false;
    if (picked == reset) std::fill(enabled_.begin(), enabled_.end(), true);
    else enabled_[picked - 1] = !enabled_[picked - 1];
    return true;
}

void EvidenceTimeline::setVisible(const std::vector<std::size_t>& rows) {
    visible_ = rows;
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void EvidenceTimeline::select(std::optional<std::size_t> record, bool reveal) {
    if (selected_ == record) return;
    selected_ = record;
    if (reveal && record) {
        const auto it = std::find_if(points_.begin(), points_.end(), [&](const Point& p) { return p.record == *record; });
        if (it != points_.end()) {
            RECT rect{};
            ::GetClientRect(hwnd_, &rect);
            const int y = pointY(*it);
            if (y < offset_) scrollTo(y);
            else if (y > offset_ + rect.bottom - Scale(58)) scrollTo(y - rect.bottom + Scale(58));
        }
    }
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

int EvidenceTimeline::pointY(const Point& point) const {
    const auto range = points_.back().ticks - points_.front().ticks;
    if (range == 0) return 0;
    const auto fraction = static_cast<double>(point.ticks - points_.front().ticks) / static_cast<double>(range);
    const auto extent = (std::max)(Scale(180), static_cast<int>(points_.size()) * Scale(18));
    return static_cast<int>(fraction * extent);
}

int EvidenceTimeline::laneX(std::size_t lane, int width) const {
    const int lanes = static_cast<int>(enabled_.size());
    return Scale(4) + ((width - Scale(8)) * (2 * static_cast<int>(lane) + 1)) / (2 * lanes);
}

void EvidenceTimeline::scrollTo(int offset) {
    RECT rect{};
    ::GetClientRect(hwnd_, &rect);
    const int extent = points_.empty() ? 0 : pointY(points_.back());
    const int page = (std::max)(1, static_cast<int>(rect.bottom) - Scale(58));
    offset_ = (std::clamp)(offset, 0, (std::max)(0, extent - page + 1));
    SCROLLINFO info{ sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL, 0, extent,
        static_cast<UINT>(page), offset_, 0 };
    ::SetScrollInfo(hwnd_, SB_VERT, &info, TRUE);
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void EvidenceTimeline::paint() {
    PAINTSTRUCT ps{};
    const HDC dc = ::BeginPaint(hwnd_, &ps);
    RECT rect{};
    ::GetClientRect(hwnd_, &rect);
    auto& theme = Ksword::Ui::AppTheme();
    ::FillRect(dc, &rect, theme.panelBrush());
    const auto label = [&](const std::wstring& text, RECT place, UINT alignment = DT_LEFT) {
        Ksword::Ui::DrawTextLine(dc, text, place, theme.textColor, Ksword::Ui::SystemUIFont(),
            alignment | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };
    label(L"接收 QPC ↓", { Scale(8), 0, rect.right, Scale(20) });
    if (points_.empty()) {
        label(L"无可绘制时间戳", { Scale(8), Scale(24), rect.right, Scale(48) });
    } else {
        label(std::to_wstring(points_.front().ticks) + L" 起", { Scale(8), Scale(19), rect.right, Scale(39) });
        for (std::size_t lane = 0; lane < enabled_.size(); ++lane) {
            const int x = laneX(lane, rect.right);
            const int half = ((rect.right - Scale(8)) / static_cast<int>(enabled_.size())) / 2;
            label(LaneName(categories_, lane), { x - half, Scale(39), x + half, Scale(57) }, DT_CENTER);
            RECT line{ x, Scale(58), x + 1, rect.bottom };
            ::FillRect(dc, &line, ::GetSysColorBrush(COLOR_3DLIGHT));
        }
        const int radius = Scale(3);
        const int firstY = Scale(59);
        const auto first = std::lower_bound(points_.begin(), points_.end(), offset_ - radius * 2,
            [&](const Point& point, int y) { return pointY(point) < y; });
        const Point* selected = nullptr;
        for (auto it = first; it != points_.end(); ++it) {
            const int y = firstY + pointY(*it) - offset_;
            if (y - radius > rect.bottom) break;
            if (y < firstY || !std::binary_search(visible_.begin(), visible_.end(), it->record)) continue;
            if (selected_ == it->record) { selected = &*it; continue; }
            const int x = laneX(it->lane, rect.right);
            RECT mark{ x - radius, y - radius, x + radius + 1, y + radius + 1 };
            ::FillRect(dc, &mark, ::GetSysColorBrush(COLOR_BTNSHADOW));
        }
        if (selected) {
            const int y = firstY + pointY(*selected) - offset_;
            const int x = laneX(selected->lane, rect.right);
            RECT mark{ x - radius * 2, y - radius, x + radius * 2 + 1, y + radius + 1 };
            ::FillRect(dc, &mark, theme.accentBrush());
        }
    }
    if (::GetFocus() == hwnd_) ::DrawFocusRect(dc, &rect);
    ::EndPaint(hwnd_, &ps);
}

void EvidenceTimeline::click(int x, int y) {
    if (y < Scale(58)) return;
    RECT rect{};
    ::GetClientRect(hwnd_, &rect);
    const Point* best = nullptr;
    int bestDistance = Scale(12);
    for (const auto& point : points_) {
        if (!std::binary_search(visible_.begin(), visible_.end(), point.record)) continue;
        const int dy = std::abs(Scale(59) + pointY(point) - offset_ - y);
        const int dx = std::abs(laneX(point.lane, rect.right) - x);
        if (dy + dx < bestDistance) {
            best = &point;
            bestDistance = dy + dx;
        }
    }
    if (best) select_(best->record);
}

void EvidenceTimeline::key(WPARAM keyCode) {
    if (keyCode == VK_PRIOR || keyCode == VK_NEXT) {
        RECT rect{};
        ::GetClientRect(hwnd_, &rect);
        scrollTo(offset_ + (keyCode == VK_NEXT ? rect.bottom : -rect.bottom));
        return;
    }
    if (keyCode != VK_UP && keyCode != VK_DOWN && keyCode != VK_HOME && keyCode != VK_END) return;
    const auto selected = std::find_if(points_.begin(), points_.end(), [&](const Point& p) { return selected_ == p.record; });
    const auto visible = [&](const Point& p) { return std::binary_search(visible_.begin(), visible_.end(), p.record); };
    if (keyCode == VK_UP || keyCode == VK_END) {
        const auto start = keyCode == VK_END || selected == points_.end() ? points_.rbegin() : std::make_reverse_iterator(selected);
        const auto next = std::find_if(start, points_.rend(), visible);
        if (next != points_.rend()) select_(next->record);
    } else {
        const auto start = keyCode == VK_HOME || selected == points_.end() ? points_.begin() : std::next(selected);
        const auto next = std::find_if(start, points_.end(), visible);
        if (next != points_.end()) select_(next->record);
    }
}

LRESULT CALLBACK EvidenceTimeline::WindowProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<EvidenceTimeline*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        self = static_cast<EvidenceTimeline*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        self->hwnd_ = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    if (!self) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: self->paint(); return 0;
    case WM_SIZE: self->scrollTo(self->offset_); return 0;
    case WM_SETFOCUS: case WM_KILLFOCUS: ::InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_GETDLGCODE: return DLGC_WANTARROWS;
    case WM_KEYDOWN: self->key(wp); return 0;
    case WM_LBUTTONDOWN:
        ::SetFocus(hwnd);
        self->click(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        return 0;
    case WM_MOUSEWHEEL: {
        const int delta = self->wheelRemainder_ + GET_WHEEL_DELTA_WPARAM(wp);
        self->wheelRemainder_ = static_cast<short>(delta % WHEEL_DELTA);
        self->scrollTo(self->offset_ - delta / WHEEL_DELTA * Scale(56));
        return 0;
    }
    case WM_VSCROLL: {
        SCROLLINFO info{ sizeof(info), SIF_ALL };
        ::GetScrollInfo(hwnd, SB_VERT, &info);
        int next = info.nPos;
        switch (LOWORD(wp)) {
        case SB_TOP: next = 0; break;
        case SB_BOTTOM: next = info.nMax; break;
        case SB_LINEUP: next -= Scale(18); break;
        case SB_LINEDOWN: next += Scale(18); break;
        case SB_PAGEUP: next -= static_cast<int>(info.nPage); break;
        case SB_PAGEDOWN: next += static_cast<int>(info.nPage); break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: next = info.nTrackPos; break;
        }
        self->scrollTo(next);
        return 0;
    }
    case WM_NCDESTROY:
        self->hwnd_ = nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}

} // namespace Ksword::Features::ActionAnalyze
