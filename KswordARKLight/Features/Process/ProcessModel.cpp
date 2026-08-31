#include "ProcessModel.h"
#include "ProcessColumns.h"

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <unordered_map>

namespace Ksword::Features::Process {
namespace {
std::wstring LowerText(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return text;
}

std::wstring NumberText(ULONGLONG value) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%llu", static_cast<unsigned long long>(value));
    return buffer;
}

// HexPointerText formats R0 object addresses for read-only audit columns. Input
// is an integer address copied from ArkDriverClient; output is "-" when absent.
std::wstring HexPointerText(std::uintptr_t value) {
    if (value == 0) {
        return L"-";
    }

    wchar_t buffer[32]{};
    ::swprintf_s(buffer,
        L"0x%0*llX",
        sizeof(void*) == 8 ? 16 : 8,
        static_cast<unsigned long long>(value));
    return buffer;
}

std::wstring PercentText(double value) {
    wchar_t buffer[32]{};
    ::swprintf_s(buffer, L"%.1f%%", value);
    return buffer;
}

} // namespace

ProcessModel::ProcessModel() = default;

void ProcessModel::setRows(std::vector<ProcessSnapshotRow> rows) {
    rows_ = std::move(rows);
    rebuildDisplayRows();
}

const std::vector<ProcessSnapshotRow>& ProcessModel::rows() const {
    return rows_;
}

const std::vector<ProcessDisplayRow>& ProcessModel::displayRows(ProcessViewMode mode) const {
    return mode == ProcessViewMode::Detail ? detailRows_ : friendlyRows_;
}

const ProcessSnapshotRow* ProcessModel::rowForDisplayRow(const ProcessDisplayRow& displayRow) const {
    if (displayRow.groupHeader || displayRow.sourceIndex >= rows_.size()) {
        return nullptr;
    }
    return &rows_[displayRow.sourceIndex];
}

std::wstring ProcessModel::textForColumn(const ProcessDisplayRow& displayRow, int column, ProcessViewMode mode) const {
    if (displayRow.groupHeader) {
        return column == 0 ? displayRow.title : (column == 1 ? displayRow.status : L"");
    }

    const ProcessSnapshotRow* row = rowForDisplayRow(displayRow);
    if (!row) {
        return {};
    }

    if (mode == ProcessViewMode::Detail) {
        switch (column) {
        case 0: return row->imageName;
        case 1: return NumberText(row->processId);
        case 2: return NumberText(row->parentProcessId);
        case 3: return NumberText(row->threadCount);
        case 4: return FormatByteSize(static_cast<ULONGLONG>(row->workingSetBytes));
        case 5: return FormatByteSize(static_cast<ULONGLONG>(row->privatePageBytes));
        case 6: return FormatByteSize(static_cast<ULONGLONG>(row->virtualSizeBytes));
        case 7: return NumberText(static_cast<ULONGLONG>(row->basePriority));
        case 8: return NumberText(row->sessionId);
        case 9: return HexPointerText(row->r0ProcessObjectAddress);
        case 10: return row->r0AuditSummary.empty() ? L"-" : row->r0AuditSummary;
        case 11: return row->r0AuditDetail.empty() ? L"-" : row->r0AuditDetail;
        case 12: return row->imagePath.empty() ? L"<access denied>" : row->imagePath;
        default: return {};
        }
    }

    switch (column) {
    case 0: return row->imageName;
    case 1: return NumberText(row->processId);
    case 2: return PercentText(row->cpuUsagePercent);
    case 3: return FormatByteSize(static_cast<ULONGLONG>(row->workingSetBytes));
    case 4: return FormatByteSize(static_cast<ULONGLONG>(row->privatePageBytes));
    case 5: return FormatByteSize(static_cast<ULONGLONG>(row->virtualSizeBytes));
    case 6: return NumberText(row->threadCount);
    case 7: return NumberText(row->sessionId);
    case 8: return NumberText(row->pageFaultCount);
    default: return {};
    }
}

std::wstring ProcessModel::textForColumn(const ProcessDisplayRow& displayRow, ProcessColumnId column) const {
    if (displayRow.groupHeader) {
        return column == ProcessColumnId::Name ? displayRow.title : std::wstring();
    }
    const ProcessSnapshotRow* row = rowForDisplayRow(displayRow);
    return row ? ProcessColumnText(*row, column) : std::wstring();
}

std::wstring ProcessModel::iconPathForRow(const ProcessDisplayRow& displayRow) const {
    const ProcessSnapshotRow* row = rowForDisplayRow(displayRow);
    if (!row) {
        return {};
    }
    return row->imagePath;
}

std::vector<DWORD> ProcessModel::selectedPids(const std::vector<int>& displayIndexes, ProcessViewMode mode) const {
    std::vector<DWORD> pids;
    const auto& visibleRows = displayRows(mode);
    for (int index : displayIndexes) {
        if (index < 0 || index >= static_cast<int>(visibleRows.size())) {
            continue;
        }
        const ProcessSnapshotRow* row = rowForDisplayRow(visibleRows[static_cast<std::size_t>(index)]);
        if (row) {
            pids.push_back(row->processId);
        }
    }
    return pids;
}

void ProcessModel::toggleGroupCollapsed(ProcessFriendlyGroup group) {
    const std::size_t index = groupIndex(group);
    if (index >= collapsedGroups_.size()) {
        return;
    }
    collapsedGroups_[index] = !collapsedGroups_[index];
    rebuildDisplayRows();
}

bool ProcessModel::isGroupCollapsed(ProcessFriendlyGroup group) const {
    const std::size_t index = groupIndex(group);
    return index < collapsedGroups_.size() ? collapsedGroups_[index] : false;
}

void ProcessModel::rebuildDisplayRows() {
    friendlyRows_.clear();
    detailRows_.clear();

    std::vector<std::size_t> indexes(rows_.size());
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        indexes[i] = i;
    }
    std::sort(indexes.begin(), indexes.end(), [this](std::size_t left, std::size_t right) {
        const ProcessSnapshotRow& a = rows_[left];
        const ProcessSnapshotRow& b = rows_[right];
        const std::wstring an = LowerText(a.imageName);
        const std::wstring bn = LowerText(b.imageName);
        if (an != bn) {
            return an < bn;
        }
        return a.processId < b.processId;
    });

    for (ProcessFriendlyGroup group : { ProcessFriendlyGroup::Applications, ProcessFriendlyGroup::Background, ProcessFriendlyGroup::WindowsSystem }) {
        appendGroupRows(group, indexes);
    }
}

void ProcessModel::appendGroupRows(ProcessFriendlyGroup group, const std::vector<std::size_t>& sortedIndexes) {
    std::vector<std::size_t> groupIndexes;
    for (std::size_t index : sortedIndexes) {
        if (classifyRow(rows_[index]) == group) {
            groupIndexes.push_back(index);
        }
    }

    const bool collapsed = isGroupCollapsed(group);
    const ProcessDisplayRow header{ true, group, 0, 0, groupTitle(group, static_cast<int>(groupIndexes.size())), collapsed ? L"Collapsed" : L"Expanded" };
    friendlyRows_.push_back(header);
    detailRows_.push_back(header);
    if (collapsed) {
        return;
    }

    std::unordered_map<DWORD, std::size_t> sourceByPid;
    for (std::size_t sourceIndex : groupIndexes) {
        sourceByPid.emplace(rows_[sourceIndex].processId, sourceIndex);
    }

    std::vector<std::vector<std::size_t>> childrenBySourceIndex(rows_.size());
    std::vector<std::size_t> roots;
    for (std::size_t sourceIndex : groupIndexes) {
        const DWORD parentPid = rows_[sourceIndex].parentProcessId;
        const auto parent = sourceByPid.find(parentPid);
        if (parent != sourceByPid.end() && parent->second != sourceIndex) {
            childrenBySourceIndex[parent->second].push_back(sourceIndex);
        } else {
            roots.push_back(sourceIndex);
        }
    }

    auto rowLess = [this](std::size_t left, std::size_t right) {
        const std::wstring leftName = LowerText(rows_[left].imageName);
        const std::wstring rightName = LowerText(rows_[right].imageName);
        if (leftName != rightName) {
            return leftName < rightName;
        }
        return rows_[left].processId < rows_[right].processId;
    };
    std::sort(roots.begin(), roots.end(), rowLess);
    for (std::vector<std::size_t>& children : childrenBySourceIndex) {
        std::sort(children.begin(), children.end(), rowLess);
    }

    std::vector<bool> emitted(rows_.size(), false);
    for (std::size_t root : roots) {
        appendTreeRows(group, root, 1, childrenBySourceIndex, emitted);
    }
    for (std::size_t sourceIndex : groupIndexes) {
        if (!emitted[sourceIndex]) {
            appendTreeRows(group, sourceIndex, 1, childrenBySourceIndex, emitted);
        }
    }
}

void ProcessModel::appendTreeRows(ProcessFriendlyGroup group,
    std::size_t sourceIndex,
    int depth,
    const std::vector<std::vector<std::size_t>>& childrenBySourceIndex,
    std::vector<bool>& emitted) {
    if (sourceIndex >= rows_.size() || emitted[sourceIndex]) {
        return;
    }

    emitted[sourceIndex] = true;
    const ProcessDisplayRow row{ false, group, depth, sourceIndex, {}, {} };
    friendlyRows_.push_back(row);
    detailRows_.push_back(row);

    if (sourceIndex < childrenBySourceIndex.size()) {
        for (std::size_t child : childrenBySourceIndex[sourceIndex]) {
            appendTreeRows(group, child, depth + 1, childrenBySourceIndex, emitted);
        }
    }
}

ProcessFriendlyGroup ProcessModel::classifyRow(const ProcessSnapshotRow& row) {
    const std::wstring name = LowerText(row.imageName);
    const std::wstring path = LowerText(row.imagePath);
    if (row.processId <= 4 || path.find(L"\\windows\\system32\\") != std::wstring::npos ||
        name == L"system" || name == L"smss.exe" || name == L"csrss.exe" || name == L"wininit.exe" ||
        name == L"services.exe" || name == L"lsass.exe" || name == L"winlogon.exe") {
        return ProcessFriendlyGroup::WindowsSystem;
    }
    if (path.find(L"\\program files") != std::wstring::npos || path.find(L"\\users\\") != std::wstring::npos) {
        return ProcessFriendlyGroup::Applications;
    }
    return ProcessFriendlyGroup::Background;
}

std::wstring ProcessModel::groupTitle(ProcessFriendlyGroup group, int count) const {
    const wchar_t* title = L"后台进程";
    if (group == ProcessFriendlyGroup::Applications) {
        title = L"应用";
    } else if (group == ProcessFriendlyGroup::WindowsSystem) {
        title = L"系统进程";
    }
    const wchar_t* marker = isGroupCollapsed(group) ? L"▶" : L"▼";
    wchar_t buffer[128]{};
    ::swprintf_s(buffer, L"%s %s (%d)", marker, title, count);
    return buffer;
}

std::size_t ProcessModel::groupIndex(ProcessFriendlyGroup group) {
    switch (group) {
    case ProcessFriendlyGroup::Applications: return 0;
    case ProcessFriendlyGroup::Background: return 1;
    case ProcessFriendlyGroup::WindowsSystem: return 2;
    default: return 1;
    }
}

std::wstring FormatByteSize(ULONGLONG bytes) {
    const wchar_t* suffixes[] = { L"B", L"KiB", L"MiB", L"GiB", L"TiB" };
    double value = static_cast<double>(bytes);
    int suffix = 0;
    while (value >= 1024.0 && suffix < 4) {
        value /= 1024.0;
        ++suffix;
    }
    wchar_t buffer[64]{};
    if (suffix == 0) {
        ::swprintf_s(buffer, L"%llu %s", static_cast<unsigned long long>(bytes), suffixes[suffix]);
    } else {
        ::swprintf_s(buffer, L"%.1f %s", value, suffixes[suffix]);
    }
    return buffer;
}

std::wstring LeafName(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos || slash + 1 >= path.size()) {
        return path;
    }
    return path.substr(slash + 1);
}

} // namespace Ksword::Features::Process
