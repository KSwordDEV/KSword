#include "../../../shared/usermode/backend/process/ProcessPeb.h"
#include "ProcessDetailPage.h"

#include "ProcessDetailCollector.h"

#include "../../Ui/ExportUtil.h"

#include <commctrl.h>
#include <psapi.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace Ksword::Features::ProcessDetail {
namespace {
using namespace ks::r3::process_detail::peb;

constexpr UINT_PTR kCopySubclassId = 0x4B535745U;
constexpr UINT kCopyTextCommand = 65101U;














































std::wstring FormatByteHex(const std::uint64_t value) {
    std::wostringstream text;
    text << L"0x" << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0') << (value & 0xFFU);
    return text.str();
}



std::wstring ExtractDetailValue(const std::wstring& detail, const std::wstring& key) {
    const std::wstring marker = key + L"=";
    const std::size_t begin = detail.find(marker);
    if (begin == std::wstring::npos) {
        return {};
    }
    const std::size_t valueBegin = begin + marker.size();
    const std::size_t end = detail.find(L';', valueBegin);
    return TrimCopy(detail.substr(valueBegin, end == std::wstring::npos ? std::wstring::npos : end - valueBegin));
}

const ProcessR0AuditInfo* FindAuditScope(
    const std::vector<ProcessR0AuditInfo>& rows,
    const wchar_t* scope) {
    const auto found = std::find_if(rows.begin(), rows.end(), [scope](const ProcessR0AuditInfo& row) {
        return row.scope == scope;
    });
    return found == rows.end() ? nullptr : &*found;
}

const ProcessR0AuditInfo* FindAuditSource(
    const std::vector<ProcessR0AuditInfo>& rows,
    const wchar_t* source) {
    const auto found = std::find_if(rows.begin(), rows.end(), [source](const ProcessR0AuditInfo& row) {
        return row.scope == L"ProcessField" && row.sourceText == source;
    });
    return found == rows.end() ? nullptr : &*found;
}

bool CopyWindowTextToClipboard(HWND window) {
    if (!window) {
        return false;
    }
    const int length = ::GetWindowTextLengthW(window);
    if (length <= 0) {
        return false;
    }
    std::wstring text(static_cast<std::size_t>(length) + 1U, L'\0');
    ::GetWindowTextW(window, text.data(), static_cast<int>(text.size()));
    text.resize(std::wcslen(text.c_str()));
    return Ksword::Ui::CopyTextToClipboard(window, text, L"进程 PEB 证据");
}

LRESULT CALLBACK CopyableTextSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR) {
    if (message == WM_CONTEXTMENU) {
        POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (point.x == -1 && point.y == -1) {
            RECT bounds{};
            ::GetWindowRect(hwnd, &bounds);
            point = { bounds.left + 16, bounds.top + 16 };
        }
        HMENU menu = ::CreatePopupMenu();
        ::AppendMenuW(menu, MF_STRING, kCopyTextCommand, L"复制");
        const UINT command = ::TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            0,
            hwnd,
            nullptr);
        ::DestroyMenu(menu);
        if (command == kCopyTextCommand) {
            CopyWindowTextToClipboard(hwnd);
        }
        return 0;
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, CopyableTextSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

void MakeCopyable(HWND control) {
    if (control) {
        ::SetWindowSubclass(control, CopyableTextSubclassProc, kCopySubclassId, 0);
    }
}



























// CollectPebSnapshot owns all remote-memory reads and address-space enumeration
// performed by the PEB page. It receives only immutable request inputs and
// returns strings/values that can safely be applied after the worker finishes.


} // namespace

bool ProcessDetailPage::CreateEvidenceTab() {
    constexpr TabIndex page = TabIndex::Evidence;
    const auto addFormRow = [this](const wchar_t* label, const int valueId, const int y) {
        AddLabel(TabIndex::Evidence, 0, label, 20, y, 150, 20);
        MakeCopyable(AddLabel(TabIndex::Evidence, valueId, L"Unavailable", 180, y, -14, 20));
    };
    AddLabel(page, 0, L"查看当前进程的内核对象、字段状态和内存映射信息。", 8, 6, -8, 24);

    AddGroup(page, L"R0 扩展摘要", 8, 34, -8, 82);
    addFormRow(L"R0 状态", EvidenceR0Status, 52);
    addFormRow(L"DynData Capability", EvidenceCapability, 74);
    addFormRow(L"R0 镜像路径", EvidenceImagePath, 96);

    AddGroup(page, L"对象字段可用性", 8, 122, -8, 62);
    addFormRow(L"HandleTable", EvidenceHandleTable, 142);
    addFormRow(L"SectionObject", EvidenceSectionObject, 162);

    AddGroup(page, L"保护与签名字段", 8, 190, -8, 78);
    addFormRow(L"EPROCESS.Protection", EvidenceProtection, 208);
    addFormRow(L"SignatureLevel", EvidenceSignature, 228);
    addFormRow(L"SectionSignatureLevel", EvidenceSectionSignature, 248);

    AddGroup(page, L"字段来源", 8, 274, -8, 148);
    addFormRow(L"Session", EvidenceSessionSource, 292);
    addFormRow(L"ImagePath", EvidenceImagePathSource, 310);
    addFormRow(L"Protection", EvidenceProtectionSource, 328);
    addFormRow(L"SignatureLevel", EvidenceSignatureSource, 346);
    addFormRow(L"SectionSignatureLevel", EvidenceSectionSignatureSource, 364);
    addFormRow(L"ObjectTable", EvidenceObjectTableSource, 382);
    addFormRow(L"SectionObject", EvidenceSectionObjectSource, 400);

    AddGroup(page, L"EPROCESS 偏移", 8, 428, -8, 112);
    addFormRow(L"Protection", EvidenceProtectionOffset, 446);
    addFormRow(L"SignatureLevel", EvidenceSignatureOffset, 464);
    addFormRow(L"SectionSignatureLevel", EvidenceSectionSignatureOffset, 482);
    addFormRow(L"ObjectTable", EvidenceObjectTableOffset, 500);
    addFormRow(L"SectionObject", EvidenceSectionObjectOffset, 518);

    AddGroup(page, L"Section / ControlArea 映射关系", 8, 546, -8, -8);
    AddButton(page, EvidenceRefreshSection, L"刷新 Section", 20, 566, 116, 28);
    MakeCopyable(AddLabel(page, EvidenceSectionStatus, L"● 尚未刷新", 146, 566, -16, 28));
    AddEdit(
        page,
        EvidenceSectionOutput,
        L"Section/ControlArea 查询结果将在此处显示。",
        true,
        true,
        20,
        602,
        -16,
        -18);
    return true;
}

bool ProcessDetailPage::CreatePebTab() {
    constexpr TabIndex page = TabIndex::Peb;
    AddButton(page, PebRefresh, L"刷新PEB", 8, 8, 92, 30);
    AddButton(page, PebApply, L"应用修改", 108, 8, 96, 30);
    MakeCopyable(AddLabel(page, PebStatus, L"● 尚未刷新", 214, 8, -8, 30));

    AddGroup(page, L"PEB 可编辑字段（R3 写入目标进程内存）", 8, 44, -8, 230);
    AddLabel(page, 0, L"目标PEB", 20, 64, 124, 24);
    HWND target = AddCombo(page, PebTarget, 150, 62, 180, 240);
    if (target) {
        ::SendMessageW(target, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"NativePEB"));
        ::SendMessageW(target, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Wow64PEB"));
        ::SendMessageW(target, CB_SETCURSEL, 0, 0);
        MakeCopyable(target);
    }

    AddLabel(page, 0, L"CommandLine", 20, 94, 124, 24);
    AddEdit(page, PebCommandLine, L"", false, false, 150, 92, -16, 26);
    AddLabel(page, 0, L"ImagePathName", 20, 124, 124, 24);
    AddEdit(page, PebImagePath, L"", false, false, 150, 122, -16, 26);
    AddLabel(page, 0, L"CurrentDirectory", 20, 154, 124, 24);
    AddEdit(page, PebCurrentDirectory, L"", false, false, 150, 152, -16, 26);

    AddLabel(page, 0, L"环境变量名", 20, 184, 124, 24);
    AddEdit(page, PebEnvironmentName, L"", false, false, 150, 182, 260, 26);
    AddLabel(page, 0, L"环境变量值", 424, 184, 110, 24);
    AddEdit(page, PebEnvironmentValue, L"", false, false, 540, 182, -16, 26);

    AddLabel(page, 0, L"ImageBaseAddress", 20, 214, 124, 24);
    AddEdit(page, PebImageBase, L"", false, false, 150, 212, 260, 26);
    AddLabel(page, 0, L"AffinityMask", 424, 214, 110, 24);
    AddEdit(page, PebAffinity, L"", false, false, 540, 212, -16, 26);

    AddLabel(page, 0, L"PriorityClass", 20, 244, 124, 24);
    HWND priority = AddCombo(page, PebPriority, 150, 242, 260, 220);
    if (priority) {
        constexpr std::array<const wchar_t*, 7> priorities{
            L"不修改", L"IDLE", L"BELOW_NORMAL", L"NORMAL", L"ABOVE_NORMAL", L"HIGH", L"REALTIME"
        };
        for (const wchar_t* item : priorities) {
            ::SendMessageW(priority, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item));
        }
        ::SendMessageW(priority, CB_SETCURSEL, 0, 0);
        MakeCopyable(priority);
    }

    AddEdit(
        page,
        PebOutput,
        L"PEB 与地址空间摘要将在此处显示。",
        true,
        true,
        8,
        282,
        -8,
        252);
    AddEdit(
        page,
        PebReadonlyReason,
        L"不可直接修改/不建议直接修改：\r\n"
        L"- KernelCpuMs/UserCpuMs/WorkingSet/PrivateUsage/IO计数/PageFaultCount：系统统计计数，只能由内核/调度器/内存管理器更新。\r\n"
        L"- VirtualAddressRegionPreview：地址空间枚举结果；应通过 VirtualAllocEx/VirtualProtectEx/Unmap/Map 等专门操作改变。\r\n"
        L"- RegionCount/CommitBytes/MappedBytes/ImageBytes/PrivateBytes：统计结果，不是单一字段。\r\n"
        L"- HeapCount/HeapBlock：需要堆管理器一致性，不在 PEB 页直接写。\r\n"
        L"- ProcessParameters 指针/Environment 指针：Light 当前仅开放亲和性和优先级写入，远程字符串及指针写入未启用。",
        true,
        true,
        8,
        542,
        -8,
        118);
    if (actionTask_ && actionTask_->running()) {
        SetBackgroundActionControlsEnabled(false);
    }
    return true;
}

void ProcessDetailPage::PopulateEvidenceTab() {
    const ProcessR0AuditInfo* detail = FindAuditScope(snapshot_.r0AuditRows, L"ProcessDetail");
    const ProcessR0AuditInfo* protection = FindAuditSource(snapshot_.r0AuditRows, L"EP.Protection");
    const ProcessR0AuditInfo* signature = FindAuditSource(snapshot_.r0AuditRows, L"EP.SignatureLevel");
    const ProcessR0AuditInfo* sectionSignature = FindAuditSource(snapshot_.r0AuditRows, L"EP.SectionSignatureLevel");
    const ProcessR0AuditInfo* objectTable = FindAuditSource(snapshot_.r0AuditRows, L"EP.ObjectTable");
    const ProcessR0AuditInfo* sectionObject = FindAuditSource(snapshot_.r0AuditRows, L"EP.SectionObject");

    SetControlText(
        TabIndex::Evidence,
        EvidenceR0Status,
        detail ? detail->anomalyText : (snapshot_.r0AuditSucceeded ? L"Partial" : L"Unavailable"));
    const std::wstring capability = detail ? ExtractDetailValue(detail->detailText, L"dyn") : std::wstring{};
    SetControlText(TabIndex::Evidence, EvidenceCapability, capability.empty() ? L"Unavailable" : capability);
    SetControlText(
        TabIndex::Evidence,
        EvidenceImagePath,
        snapshot_.basic.imagePath.empty() ? L"-" : snapshot_.basic.imagePath);

    const std::wstring objectAddress = detail ? ExtractDetailValue(detail->detailText, L"objectTable") : std::wstring{};
    const std::wstring sectionAddress = detail ? ExtractDetailValue(detail->detailText, L"section") : std::wstring{};
    SetControlText(
        TabIndex::Evidence,
        EvidenceHandleTable,
        objectAddress.empty() ? L"Unavailable" : L"HandleTable available: " + objectAddress + L" (R0 process detail)");
    SetControlText(
        TabIndex::Evidence,
        EvidenceSectionObject,
        sectionAddress.empty() ? L"Unavailable" : L"SectionObject available: " + sectionAddress + L" (R0 process detail)");

    const auto fieldValue = [](const ProcessR0AuditInfo* row) {
        const std::wstring value = row ? ExtractDetailValue(row->detailText, L"value") : std::wstring{};
        if (value.empty()) {
            return std::wstring(L"Unavailable");
        }
        std::uint64_t parsed = 0;
        return ParseUnsigned(value, parsed) ? FormatByteHex(parsed) : value;
    };
    const auto fieldOffset = [](const ProcessR0AuditInfo* row) {
        const std::wstring value = row ? ExtractDetailValue(row->detailText, L"offset") : std::wstring{};
        return value.empty() ? std::wstring(L"Unavailable") : value;
    };
    const auto fieldSource = [](const ProcessR0AuditInfo* row) {
        return row ? std::wstring(L"R0 runtime field sample") : std::wstring(L"Unavailable");
    };

    SetControlText(TabIndex::Evidence, EvidenceProtection, fieldValue(protection));
    SetControlText(TabIndex::Evidence, EvidenceSignature, fieldValue(signature));
    SetControlText(TabIndex::Evidence, EvidenceSectionSignature, fieldValue(sectionSignature));
    SetControlText(TabIndex::Evidence, EvidenceSessionSource, snapshot_.basicSucceeded ? L"Win32 snapshot" : L"Unavailable");
    SetControlText(TabIndex::Evidence, EvidenceImagePathSource, snapshot_.basic.imagePath.empty() ? L"Unavailable" : L"Win32 snapshot");
    SetControlText(TabIndex::Evidence, EvidenceProtectionSource, fieldSource(protection));
    SetControlText(TabIndex::Evidence, EvidenceSignatureSource, fieldSource(signature));
    SetControlText(TabIndex::Evidence, EvidenceSectionSignatureSource, fieldSource(sectionSignature));
    SetControlText(TabIndex::Evidence, EvidenceObjectTableSource, detail || objectTable ? L"R0 process detail" : L"Unavailable");
    SetControlText(TabIndex::Evidence, EvidenceSectionObjectSource, detail || sectionObject ? L"R0 process detail" : L"Unavailable");
    SetControlText(TabIndex::Evidence, EvidenceProtectionOffset, fieldOffset(protection));
    SetControlText(TabIndex::Evidence, EvidenceSignatureOffset, fieldOffset(signature));
    SetControlText(TabIndex::Evidence, EvidenceSectionSignatureOffset, fieldOffset(sectionSignature));
    SetControlText(TabIndex::Evidence, EvidenceObjectTableOffset, fieldOffset(objectTable));
    SetControlText(TabIndex::Evidence, EvidenceSectionObjectOffset, fieldOffset(sectionObject));
}

void ProcessDetailPage::PopulatePebTab() {
    if (!pebLoaded_) {
        SetPageStatus(TabIndex::Peb, PebStatus, L"● 尚未刷新");
        SetControlText(TabIndex::Peb, PebOutput, L"PEB 与地址空间摘要将在此处显示。");
    }
}

bool ProcessDetailPage::HandleEvidenceCommand(const int controlId) {
    if (controlId == EvidenceRefreshSection) {
        RefreshSectionReport();
        return true;
    }
    return false;
}

bool ProcessDetailPage::HandlePebCommand(const int controlId) {
    if (controlId == PebRefresh) {
        RefreshPebReport();
        return true;
    }
    if (controlId == PebApply) {
        ApplyPebEdits();
        return true;
    }
    return false;
}

void ProcessDetailPage::RefreshSectionReport() {
    if (!evidenceTask_) {
        SetPageStatus(TabIndex::Evidence, EvidenceSectionStatus, L"● R0 证据后台任务不可用。");
        return;
    }
    SetPageStatus(TabIndex::Evidence, EvidenceSectionStatus, L"● 正在查询 Section/ControlArea...");
    const DWORD processId = processId_;
    const ULONGLONG expectedCreationTime100ns = expectedCreationTime100ns_;
    evidenceTask_->request(
        [processId, expectedCreationTime100ns] {
            ProcessDetailCollector collector;
            return collector.Collect(processId, expectedCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessDetailSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetPageStatus(TabIndex::Evidence, EvidenceSectionStatus, L"● R0 证据后台查询异常结束。");
                return;
            }
            snapshot_.r0AuditRows = std::move(result->r0AuditRows);
            snapshot_.r0AuditSucceeded = result->r0AuditSucceeded;
            if (!result->basic.imagePath.empty()) {
                snapshot_.basic.imagePath = std::move(result->basic.imagePath);
            }
            PopulateEvidenceTab();
            RenderSectionReport();
        });
}

void ProcessDetailPage::RenderSectionReport() {
    std::wostringstream report;
    report << L"[R0 Process Runtime Detail]\r\n";
    report << L"PID: " << processId_ << L"\r\n";
    report << L"R0 Audit: " << (snapshot_.r0AuditSucceeded ? L"OK" : L"Unavailable/Partial") << L"\r\n";
    report << L"Rows: " << snapshot_.r0AuditRows.size() << L"\r\n\r\n";
    report << L"[Process Detail Evidence]\r\n";
    for (std::size_t index = 0; index < snapshot_.r0AuditRows.size(); ++index) {
        const ProcessR0AuditInfo& row = snapshot_.r0AuditRows[index];
        report << L"#" << index + 1U << L" " << row.scope;
        if (row.threadId != 0) { report << L" TID=" << row.threadId; }
        report << L"\r\n";
        report << L"  Object=" << FormatHex(row.objectAddress)
               << L" Related=" << FormatHex(row.relatedObjectAddress)
               << L" Start=" << FormatHex(row.startAddress) << L"\r\n";
        report << L"  Source=" << (row.sourceText.empty() ? L"Unavailable" : row.sourceText)
               << L" Status=" << (row.anomalyText.empty() ? L"Unavailable" : row.anomalyText)
               << L" Confidence=" << row.confidence << L"\r\n";
        if (!row.detailText.empty()) {
            report << L"  Detail=" << row.detailText << L"\r\n";
        }
    }
    report << L"\r\n[R0 Section Query]\r\n";
    const ProcessR0AuditInfo* detail = FindAuditScope(snapshot_.r0AuditRows, L"ProcessDetail");
    if (detail) {
        report << L"ProcessObject: " << FormatHex(detail->objectAddress) << L"\r\n";
        report << L"ObjectTable: " << ExtractDetailValue(detail->detailText, L"objectTable") << L"\r\n";
        report << L"SectionObject: " << ExtractDetailValue(detail->detailText, L"section") << L"\r\n";
        report << L"DynDataCapability: " << ExtractDetailValue(detail->detailText, L"dyn") << L"\r\n";
        report << L"Status: " << detail->anomalyText << L"\r\n";
    } else {
        report << L"<empty or unavailable>\r\n";
    }
    report << L"[Mappings]\r\n";
    report << L"  当前 Light 快照未携带独立映射数组；上方审计行保留驱动返回的完整只读证据。\r\n";

    SetControlText(TabIndex::Evidence, EvidenceSectionOutput, report.str());
    SetPageStatus(
        TabIndex::Evidence,
        EvidenceSectionStatus,
        std::wstring(L"● 后台刷新完成") +
            (snapshot_.r0AuditSucceeded ? L"" : L" | R0证据部分不可用"));
    sectionLoaded_ = true;
}

void ProcessDetailPage::RefreshPebReport() {
    if (!pebTask_) {
        SetPageStatus(TabIndex::Peb, PebStatus, L"● PEB 后台任务不可用。");
        return;
    }
    SetPageStatus(TabIndex::Peb, PebStatus, L"● 正在刷新PEB...");
    const int selectedTarget = static_cast<int>(
        ::SendMessageW(Control(TabIndex::Peb, PebTarget), CB_GETCURSEL, 0, 0));
    const DWORD processId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    pebTask_->request(
        [processId, expectedProcessCreationTime100ns, selectedTarget] {
            return CollectPebSnapshot(processId, expectedProcessCreationTime100ns, selectedTarget);
        },
        [this](std::uint64_t, std::optional<ProcessPebSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetPageStatus(TabIndex::Peb, PebStatus, L"● PEB 后台查询异常结束。");
                return;
            }
            SetControlText(TabIndex::Peb, PebOutput, result->reportText);
            if (!result->identityMatched) {
                SetControlText(TabIndex::Peb, PebAffinity, L"Unavailable");
                ::SendMessageW(Control(TabIndex::Peb, PebPriority), CB_SETCURSEL, static_cast<WPARAM>(-1), 0);
                SetControlText(TabIndex::Peb, PebCommandLine, L"Unavailable");
                SetControlText(TabIndex::Peb, PebImagePath, L"Unavailable");
                SetControlText(TabIndex::Peb, PebCurrentDirectory, L"Unavailable");
                SetControlText(TabIndex::Peb, PebEnvironmentName, L"Unavailable");
                SetControlText(TabIndex::Peb, PebImageBase, L"Unavailable");
            } else {
                if (result->affinityKnown) {
                    SetControlText(TabIndex::Peb, PebAffinity, result->affinityText);
                }
                if (result->priorityKnown) {
                    ::SendMessageW(
                        Control(TabIndex::Peb, PebPriority),
                        CB_SETCURSEL,
                        static_cast<WPARAM>(result->priorityComboIndex),
                        0);
                }
                if (result->selectedPebKnown) {
                    SetControlText(TabIndex::Peb, PebCommandLine, result->commandLine);
                    SetControlText(TabIndex::Peb, PebImagePath, result->imagePath);
                    SetControlText(TabIndex::Peb, PebCurrentDirectory, result->currentDirectory);
                    SetControlText(TabIndex::Peb, PebImageBase, result->imageBase);
                }
            }
            SetPageStatus(TabIndex::Peb, PebStatus, result->statusText);
            pebLoaded_ = result->completed && result->identityMatched;
        });

}

void ProcessDetailPage::ApplyPebEdits() {
    const int confirmation = ::MessageBoxW(
        hwnd_,
        L"即将修改目标进程的亲和性或优先级。\r\n\r\n"
        L"Light 当前不写入远程 PEB 字符串、环境块或 ImageBaseAddress；这些字段会逐项报告为“未启用”，不会伪装成功。\r\n"
        L"是否继续？",
        L"确认修改进程属性",
        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
    if (confirmation != IDYES) {
        return;
    }

    const std::wstring commandLine = ControlText(TabIndex::Peb, PebCommandLine);
    const std::wstring imagePath = ControlText(TabIndex::Peb, PebImagePath);
    const std::wstring currentDirectory = ControlText(TabIndex::Peb, PebCurrentDirectory);
    const std::wstring environmentName = ControlText(TabIndex::Peb, PebEnvironmentName);
    const std::wstring imageBase = ControlText(TabIndex::Peb, PebImageBase);
    const std::wstring affinityText = TrimCopy(ControlText(TabIndex::Peb, PebAffinity));
    const int priorityIndex = static_cast<int>(
        ::SendMessageW(Control(TabIndex::Peb, PebPriority), CB_GETCURSEL, 0, 0));
    const DWORD processId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::Peb,
        PebStatus,
        L"● 正在后台修改进程属性…",
        [processId, expectedProcessCreationTime100ns, commandLine, imagePath, currentDirectory, environmentName, imageBase, affinityText, priorityIndex] {
            return ks::r3::process_detail::peb::ApplyPebAttributes(processId, expectedProcessCreationTime100ns, commandLine, imagePath, currentDirectory, environmentName, imageBase, affinityText, priorityIndex);
        });

}

} // namespace Ksword::Features::ProcessDetail

namespace Ksword::Features::ProcessDetail { namespace {

}}
