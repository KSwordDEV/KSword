#pragma once
#include "../../../shared/usermode/backend/driver/DriverTypes.h"

// ============================================================
// DriverModel.h
// 作用说明：
// 1) 定义驱动概览与对象信息的只读展示模型；
// 2) 提供过滤、汇总和文本格式化辅助；
// 3) 不包含任何 Win32 控件、设备 I/O 或驱动调用逻辑。
// ============================================================

#include "../../Core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Driver {
using ks::r3::driver::DriverOverviewRow;
using ks::r3::driver::DriverObjectRow;
using ks::r3::driver::FormatHexAddress;
using ks::r3::driver::FormatByteSize;


// DriverOverviewRow stores one loaded-driver summary row. Inputs are module
// enumeration results; processing is done in DriverEnumerator; output is the
// value object consumed by DriverOverviewView and export helpers.


// DriverObjectRow stores one object-manager row from the driver-related
// directories. Inputs are directory enumeration and optional count lookups;
// processing is done in DriverEnumerator; output feeds DriverObjectView.


// DriverModel owns the latest overview/object snapshots and exposes filtering
// helpers for the Win32 views. Inputs are row vectors and filter strings;
// processing stores rows, applies keyword tests, and prepares summary text;
// outputs are stable const references or filtered copies.
class DriverModel final {
public:
    // DriverModel creates an empty snapshot store. There is no input and no
    // external side effect.
    DriverModel() = default;

    // setOverviewRows replaces the overview snapshot. Input rows are moved into
    // the model; processing clears the previous cache; no value is returned.
    void setOverviewRows(std::vector<DriverOverviewRow> rows);

    // setObjectRows replaces the object-info snapshot. Input rows are moved into
    // the model; processing clears the previous cache; no value is returned.
    void setObjectRows(std::vector<DriverObjectRow> rows);

    // overviewRows returns the current overview snapshot. There is no input;
    // output is a const reference valid until the next setOverviewRows call.
    const std::vector<DriverOverviewRow>& overviewRows() const;

    // objectRows returns the current object-info snapshot. There is no input;
    // output is a const reference valid until the next setObjectRows call.
    const std::vector<DriverObjectRow>& objectRows() const;

    // filterOverviewRows applies a keyword filter to the overview snapshot.
    // Input keywordText may be empty; processing performs case-insensitive text
    // matching across all visible columns; output is a copied filtered vector.
    std::vector<DriverOverviewRow> filterOverviewRows(const std::wstring& keywordText) const;

    // filterObjectRows applies directory/type/keyword filters to the object
    // snapshot. Inputs may be empty; processing performs case-insensitive text
    // matching; output is a copied filtered vector.
    std::vector<DriverObjectRow> filterObjectRows(
        const std::wstring& directoryFilterText,
        const std::wstring& typeFilterText,
        const std::wstring& keywordText) const;

    // overviewSummaryText builds a short Chinese status summary. Inputs are the
    // current overview snapshot and filter text; processing counts visible rows;
    // output is a status string for the page header.
    std::wstring overviewSummaryText(const std::wstring& keywordText) const;

    // objectSummaryText builds a short Chinese status summary. Inputs are the
    // current object snapshot and filter text; processing counts visible rows;
    // output is a status string for the page header.
    std::wstring objectSummaryText(
        const std::wstring& directoryFilterText,
        const std::wstring& typeFilterText,
        const std::wstring& keywordText) const;

    // overviewDirectories returns every unique overview directory/root label.
    // There is no input; output is sorted unique text for filter combos.
    std::vector<std::wstring> overviewDriverNames() const;

    // objectDirectories returns every unique source directory path. There is no
    // input; output is sorted unique text for filter combos.
    std::vector<std::wstring> objectDirectories() const;

    // objectTypes returns every unique object type text. There is no input;
    // output is sorted unique text for filter combos.
    std::vector<std::wstring> objectTypes() const;

    // sanitizeTsvCell prepares one text field for TSV serialization. Input is
    // raw text; processing flattens tabs/newlines; output is TSV-safe text.
    static std::wstring sanitizeTsvCell(const std::wstring& text);

private:
    static bool containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle);
    static std::wstring trimCopy(const std::wstring& text);
    static std::wstring toLowerCopy(const std::wstring& text);

private:
    std::vector<DriverOverviewRow> overviewRows_;
    std::vector<DriverObjectRow> objectRows_;
};

// FormatHexAddress converts a pointer-sized value into uppercase hexadecimal.
// Input is an address value; processing pads the hex text; output is a display
// string such as 0xFFFFF80012345678.


// FormatByteSize converts bytes into a compact human-readable size string.
// Input is a byte count; processing chooses B/KiB/MiB/GiB units; output is
// suitable for the overview size column.


} // namespace Ksword::Features::Driver
