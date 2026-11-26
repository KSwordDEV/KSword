#pragma once

#include "LightExecutionGroupSession.h"
#include "../../Ui/ParameterWorkspace.h"
#include <array>
#include <commctrl.h>

namespace Ksword::Features::ActionAnalyze::execution_group_page {
enum : int {
    kPid = 58700, kCreation, kModule, kRva, kExport, kAddress, kRange, kCondition,
    kIdentify, kAdd, kRemove, kDraft, kAuthorized, kStart, kQuery, kContinueAll,
    kContinueSelected, kStepInto, kStepOver, kStepOut, kCancelStep, kClose,
    kMembers, kPreset, kTextMode, kCopy, kExportText, kText, kStatus, kLoadDraft,
    kPauseAll, kPauseSelected, kAddRange
};
enum Field : std::size_t { Pid, Creation, Module, Rva, Export, Address, Range, Condition, FieldCount };

// 页面只保存纯值快照；原生集合、调试owner与清退责任属于会话worker。
struct Page {
    HWND hwnd = nullptr;
    Ui::ParameterWorkspace parameters;
    std::array<HWND, FieldCount> labels{}, inputs{};
    HWND hint = nullptr, identity = nullptr, identify = nullptr;
    HWND rangeHint = nullptr, addRange = nullptr;
    HWND draft = nullptr, add = nullptr, remove = nullptr, loadDraft = nullptr, authorized = nullptr;
    HWND start = nullptr, query = nullptr, continueAll = nullptr, continueSelected = nullptr;
    HWND pauseAll = nullptr, pauseSelected = nullptr;
    HWND stepInto = nullptr, stepOver = nullptr, stepOut = nullptr, cancelStep = nullptr, close = nullptr;
    HWND members = nullptr, preset = nullptr, textMode = nullptr, copy = nullptr, exportText = nullptr;
    HWND text = nullptr, status = nullptr;
    HWND tooltip = nullptr;
    LightExecutionGroupSession session;
    LightExecutionGroupSnapshot shown;
    std::vector<execution_native::ExecutionGroupSite> sites;
    std::array<bool, 11> visibleColumns{true, true, true, true, true, false, false, false, false, false, true};
    std::vector<int> columns;
    std::vector<std::vector<std::wstring>> displayedRows;
    std::wstring document, error;
    std::uint64_t identityCreation = 0;
    std::uint64_t identityRevision = 0;
    std::uint32_t identityPid = 0;
    bool publishing = false;
    bool retiring = false;
};

bool CreateControls(Page& page);
void Layout(Page& page);
void Refresh(Page& page);
void RefreshText(Page& page);
void RefreshDraft(Page& page);
void RebuildColumns(Page& page);
void HeaderMenu(Page& page, POINT point);
void Command(Page& page, int id);
std::wstring InputText(HWND control);
std::wstring Widen(std::string_view text);
std::wstring SiteText(const execution_native::ExecutionGroupSite& site);
std::wstring GroupStateText(execution_native::ExecutionGroupState state);
std::vector<int> SelectedRows(const Page& page);
LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data);
}
