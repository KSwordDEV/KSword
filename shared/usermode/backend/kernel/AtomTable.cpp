#include "AtomTable.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
KernelOperationResult QueryAtomTable(const KernelRequest& request) {
    QueryPacket packet;
    const auto atomHexText = [](const UINT atomValue) {
        std::wostringstream stream;
        stream << L"0x" << std::uppercase << std::hex << std::setw(4) << std::setfill(L'0') << atomValue;
        return stream.str();
    };

    for (UINT atom = 0xC000; atom <= 0xFFFF; ++atom) {
        wchar_t globalNameBuffer[512]{};
        const UINT globalLength = ::GlobalGetAtomNameW(
            static_cast<ATOM>(atom),
            globalNameBuffer,
            static_cast<int>(_countof(globalNameBuffer)));

        wchar_t clipboardNameBuffer[512]{};
        const int clipboardLength = ::GetClipboardFormatNameW(
            atom,
            clipboardNameBuffer,
            static_cast<int>(_countof(clipboardNameBuffer)));

        if (globalLength == 0 && clipboardLength <= 0) {
            continue;
        }

        const std::wstring globalName = globalLength > 0
            ? std::wstring(globalNameBuffer, globalNameBuffer + globalLength)
            : std::wstring();
        const std::wstring clipboardName = clipboardLength > 0
            ? std::wstring(clipboardNameBuffer, clipboardNameBuffer + clipboardLength)
            : std::wstring();
        const std::wstring displayName = !globalName.empty() ? globalName : clipboardName;

        std::wstring sourceText;
        std::wstring detailText;
        if (!globalName.empty() && !clipboardName.empty()) {
            sourceText = L"GlobalGetAtomNameW + GetClipboardFormatNameW";
            if (_wcsicmp(globalName.c_str(), clipboardName.c_str()) == 0) {
                detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + atomHexText(atom) + L")\r\n"
                    L"名称: " + displayName + L"\r\n"
                    L"来源: Global + ClipboardFormat（同名）";
            } else {
                detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + atomHexText(atom) + L")\r\n"
                    L"Global名称: " + globalName + L"\r\n"
                    L"ClipboardFormat名称: " + clipboardName + L"\r\n"
                    L"来源: Global + ClipboardFormat（名称不同）";
            }
        } else if (!globalName.empty()) {
            sourceText = L"GlobalGetAtomNameW";
            detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + atomHexText(atom) + L")\r\n"
                L"名称: " + displayName + L"\r\n"
                L"来源: GlobalGetAtomNameW";
        } else {
            sourceText = L"GetClipboardFormatNameW";
            detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + atomHexText(atom) + L")\r\n"
                L"名称: " + displayName + L"\r\n"
                L"来源: GetClipboardFormatNameW";
        }

        packet.rows.push_back(Row({
            { L"Id", std::to_wstring(atom) },
            { L"Hex", atomHexText(atom) },
            { L"Name", displayName },
            { L"Source", sourceText },
            { L"Kind", sourceText },
            { L"Status", L"SUCCESS" },
            { L"GlobalName", globalName },
            { L"ClipboardName", clipboardName },
        }, detailText));
    }

    return MakeResult(request.featureId, true, L"Atom/Clipboard Format 遍历", std::move(packet));
}
}
