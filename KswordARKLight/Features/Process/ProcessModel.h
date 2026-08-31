#pragma once

#include "ProcessEnumerator.h"
#include "ProcessColumns.h"

#include <array>
#include <string>
#include <vector>

namespace Ksword::Features::Process {

enum class ProcessViewMode {
    UtilizationFriendly,
    Detail
};

enum class ProcessFriendlyGroup {
    Applications,
    Background,
    WindowsSystem
};

struct ProcessDisplayRow {
    bool groupHeader = false;
    ProcessFriendlyGroup group = ProcessFriendlyGroup::Background;
    int depth = 0;
    std::size_t sourceIndex = 0;
    std::wstring title;
    std::wstring status;
};

// ProcessModel stores the latest NtQuerySystemInformation snapshot and prepares
// UI-facing rows. Inputs are ProcessSnapshotRow vectors; processing sorts and
// groups rows in a Process Explorer-like friendly layout; outputs are stable
// display rows and column strings consumed by ProcessView.
class ProcessModel final {
public:
    ProcessModel();

    // setRows replaces the current process snapshot. Input rows are copied into
    // the model; processing rebuilds both friendly and detail display rows; no
    // value is returned.
    void setRows(std::vector<ProcessSnapshotRow> rows);

    // rows returns the raw snapshot rows. There is no input; output is a const
    // reference valid until the next setRows call.
    const std::vector<ProcessSnapshotRow>& rows() const;

    // displayRows returns rows for the selected view mode. Input is the current
    // mode; output is a const reference valid until the next setRows call.
    const std::vector<ProcessDisplayRow>& displayRows(ProcessViewMode mode) const;

    // rowForDisplayIndex maps a visible row to a raw process row. Input is a
    // ProcessDisplayRow; output is nullptr for group headers or invalid indexes.
    const ProcessSnapshotRow* rowForDisplayRow(const ProcessDisplayRow& displayRow) const;

    // textForColumn returns the visible column text. Inputs are display row,
    // column index and view mode; output is an empty string for invalid columns.
    std::wstring textForColumn(const ProcessDisplayRow& displayRow, int column, ProcessViewMode mode) const;

    // textForColumn 用途：按稳定逻辑列 ID 返回文本，供列选择后的 ListView 渲染使用。
    // 输入 displayRow 与 column；输出为空表示无有效进程行，缺失采集字段由列格式化器标记不可用。
    std::wstring textForColumn(const ProcessDisplayRow& displayRow, ProcessColumnId column) const;

    // iconPathForRow returns the best executable path for Shell icon extraction.
    // Input is a display row; output is empty for group headers or inaccessible
    // processes without an image path.
    std::wstring iconPathForRow(const ProcessDisplayRow& displayRow) const;

    // selectedPids converts display row indexes into PIDs. Input is a vector of
    // selected visible indexes; output contains only process rows, no groups.
    std::vector<DWORD> selectedPids(const std::vector<int>& displayIndexes, ProcessViewMode mode) const;

    // toggleGroupCollapsed flips one friendly group between expanded and
    // collapsed state. Input is the group id clicked by the UI; processing
    // rebuilds both visible row caches; no value is returned.
    void toggleGroupCollapsed(ProcessFriendlyGroup group);

    // isGroupCollapsed reports the current expansion state. Input is a group id;
    // output is true when the process rows under that group are hidden.
    bool isGroupCollapsed(ProcessFriendlyGroup group) const;

private:
    void rebuildDisplayRows();
    void appendGroupRows(ProcessFriendlyGroup group, const std::vector<std::size_t>& sortedIndexes);
    void appendTreeRows(ProcessFriendlyGroup group,
        std::size_t sourceIndex,
        int depth,
        const std::vector<std::vector<std::size_t>>& childrenBySourceIndex,
        std::vector<bool>& emitted);
    static ProcessFriendlyGroup classifyRow(const ProcessSnapshotRow& row);
    std::wstring groupTitle(ProcessFriendlyGroup group, int count) const;
    static std::size_t groupIndex(ProcessFriendlyGroup group);

private:
    std::vector<ProcessSnapshotRow> rows_;
    std::vector<ProcessDisplayRow> friendlyRows_;
    std::vector<ProcessDisplayRow> detailRows_;
    std::array<bool, 3> collapsedGroups_{ false, false, false };
};

// FormatByteSize converts bytes to a compact text value. Input is a byte count;
// output is B/KiB/MiB/GiB text for list view columns.
std::wstring FormatByteSize(ULONGLONG bytes);

// LeafName extracts the file name from a path. Input may be a full path or a
// process image name; output is the last path segment or the original value.
std::wstring LeafName(const std::wstring& path);

} // namespace Ksword::Features::Process
