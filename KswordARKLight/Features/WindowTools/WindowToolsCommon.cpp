#include "../../../shared/usermode/backend/window/PointerText.h"
#include "../../../shared/usermode/backend/window/WindowHierarchySupport.h"
#include "../../../shared/usermode/backend/window/ClipboardCopy.h"
#include "../../../shared/usermode/backend/window/WindowQueries.h"
#include "WindowToolsCommon.h"

#include <commctrl.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

namespace Ksword::Features::WindowTools {
namespace {
using namespace ks::r3::window_tools;
using namespace ks::r3::window_tools;
using namespace ks::r3::window_tools;
using namespace ks::r3::window_tools;

// StyleBitName pairs one flag value with the SDK spelling of its macro. The
// value is taken from the macro itself rather than a literal so a decoder can
// never drift from the header it claims to mirror.








// AppendUnknownBits reports whatever the table did not explain. Silently
// dropping leftovers would make an undocumented or newer flag look like it was
// simply not set, which is the opposite of what a diagnostic page is for.


// LeafName extracts the file name from a full image path. Inputs are the path
// and the process id it came from; output falls back to a stable placeholder so
// an inaccessible process still occupies its row instead of showing blank.


// ReadWindowInfo converts one HWND into a snapshot row. Input is a live
// top-level HWND; output has hwnd=nullptr when the window vanished mid-pass,
// which EnumWindows makes routine rather than exceptional.




} // namespace





























std::wstring RowsAsTsv(const Ksword::Ui::VirtualListView& list, const bool visibleRows, const int columnCount) {
    const auto& rows = list.rows();
    const auto& visible = list.visibleIndexes();
    const HWND hwnd = list.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows &&
            (!hwnd || (ListView_GetItemState(hwnd, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t rowIndex = visible[item];
        if (rowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[rowIndex].cells;
        const std::size_t limit = (std::min)(static_cast<std::size_t>(columnCount), cells.size());
        for (std::size_t column = 0; column < limit; ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

} // namespace Ksword::Features::WindowTools
