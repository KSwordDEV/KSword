#include "AtomTable.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
AtomSnapshot CollectAtoms(const AtomQueryOptions& options){AtomSnapshot result;if(options.first<0xc000||options.last>0xffff||options.first>options.last||(!options.global&&!options.clipboard)){result.malformed=true;return result;}const auto deadline=options.deadlineTick?options.deadlineTick: ::GetTickCount64()+8000;
    for(UINT id=options.first;id<=options.last;++id){if(options.cancelled&&options.cancelled()){result.cancelled=true;break;}if(::GetTickCount64()>=deadline){result.limited=true;break;}
        AtomEntry entry;entry.id=id;auto query=[&](AtomNameEvidence& evidence,bool global){wchar_t buffer[512]{};evidence.attempted=true;::SetLastError(0);
            const auto length=global?static_cast<std::int64_t>(::GlobalGetAtomNameW(static_cast<ATOM>(id),buffer,512)):static_cast<std::int64_t>(::GetClipboardFormatNameW(id,buffer,512));evidence.error=::GetLastError();
            if(length<0||length>=512){evidence.malformed=true;result.malformed=true;return;}if(length>0){evidence.available=true;evidence.name.assign(buffer,static_cast<std::size_t>(length));return;}
            evidence.absent=evidence.error==ERROR_INVALID_HANDLE||evidence.error==ERROR_INVALID_PARAMETER||evidence.error==ERROR_FILE_NOT_FOUND;
            if(!evidence.absent)++result.failedQueries;
        };
        if(options.global){query(entry.global,true);if(entry.global.available)++result.globalFound;}
        if(options.clipboard){query(entry.clipboard,false);if(entry.clipboard.available)++result.clipboardFound;}
        ++result.scannedIds;if(entry.global.available||entry.clipboard.available||entry.global.malformed||entry.clipboard.malformed||(entry.global.attempted&&!entry.global.absent)||(entry.clipboard.attempted&&!entry.clipboard.absent))result.entries.push_back(std::move(entry));
        if(result.malformed)break;
    }
    result.complete=!result.limited&&!result.cancelled&&!result.malformed&&result.scannedIds==options.last-options.first+1;return result;
}
KernelOperationResult QueryAtomTable(const KernelRequest& request) {
    QueryPacket packet;
    const auto atomHexText = [](const UINT atomValue) {
        std::wostringstream stream;
        stream << L"0x" << std::uppercase << std::hex << std::setw(4) << std::setfill(L'0') << atomValue;
        return stream.str();
    };

    const auto snapshot=CollectAtoms();
    for (const auto& entry:snapshot.entries) {
        if(!entry.global.available&&!entry.clipboard.available)continue;
        const auto atom=entry.id;const auto& globalName=entry.global.name;const auto& clipboardName=entry.clipboard.name;
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
