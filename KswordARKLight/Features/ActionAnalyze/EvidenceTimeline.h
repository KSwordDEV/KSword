#pragma once

#include "StoredEvidence.h"
#include "../../Core/Win32Lean.h"

namespace Ksword::Features::ActionAnalyze {

class EvidenceTimeline final {
public:
    struct Point {
        std::uint64_t ticks;
        std::size_t record;
        std::size_t lane;
    };

    bool create(HWND parent, int controlId, std::function<void(std::size_t)> select);
    HWND hwnd() const { return hwnd_; }
    void replace(const std::vector<EvidenceRecord>& rows);
    void setVisible(const std::vector<std::size_t>& rows);
    void select(std::optional<std::size_t> record, bool reveal);
    bool includes(const EvidenceRecord& record) const;
    bool hasCategories() const { return etwLane_.value_or(enabled_.size()) != 0; }
    bool hasEtw() const { return etwLane_.has_value(); }
    bool chooseCategories(HWND anchor);

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp);
    int pointY(const Point& point) const;
    int laneX(std::size_t lane, int width) const;
    std::size_t laneFor(std::uint16_t category) const;
    std::wstring laneName(std::size_t lane) const;
    void scrollTo(int offset);
    void paint();
    void click(int x, int y);
    void key(WPARAM keyCode);

    HWND hwnd_ = nullptr;
    std::function<void(std::size_t)> select_;
    std::optional<std::size_t> selected_;
    std::vector<Point> points_;
    std::vector<std::size_t> visible_;
    std::vector<std::uint16_t> categories_;
    std::vector<bool> enabled_;
    bool other_ = false;
    std::optional<std::size_t> etwLane_; // 原始 ETW 记录专用泳道，互不占用归档类别号。
    int offset_ = 0;
    short wheelRemainder_ = 0;
};

} // namespace Ksword::Features::ActionAnalyze
