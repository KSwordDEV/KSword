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
    kPauseAll, kPauseSelected, kAddRange, kImageSha256, kProjectDirectory, kOpenProject, kSaveExecution, kDefinitionId,
    kApiPid, kApiCreation, kApiDuration, kCaptureApi, kMemoryAddress, kMemoryBytes, kReadMemory, kSaveMemory, kAppendMembers
};
// 末尾增加输入字段，保留既有控件ID与字段顺序；散列使用独立kImageSha256标识。
enum Field : std::size_t { Pid, Creation, Module, Rva, Export, Address, Range, Condition, ImageSha256, DefinitionId, FieldCount };

// 页面只保存纯值快照；原生集合、调试owner与清退责任属于会话worker。
struct Page {
    HWND hwnd = nullptr;
    Ui::ParameterWorkspace parameters;
    std::array<HWND, FieldCount> labels{}, inputs{};
    HWND hint = nullptr, identity = nullptr, identify = nullptr;
    HWND rangeHint = nullptr, addRange = nullptr;
    HWND projectLabel = nullptr, projectDirectory = nullptr, openProject = nullptr; // 独立项目草稿，Start时冻结。
    HWND saveExecution = nullptr; // 保存单选成员当前原事件，权限与Continue分开。
    std::array<HWND, 3> apiLabels{}, apiInputs{}; // 来源PID、创建时间和有限区间，与成员站点草稿分开。
    HWND captureApi = nullptr; // 原固定动作栏的同采样API入口。
    std::array<HWND, 2> memoryLabels{}, memoryInputs{}; // 独立只读范围，不与启动或追加NX范围共用草稿。
    HWND readMemory = nullptr, saveMemory = nullptr; // 读取唯一成员及保存当前原读取是两个明确动作。
    HWND draft = nullptr, add = nullptr, remove = nullptr, loadDraft = nullptr, authorized = nullptr;
    HWND start = nullptr, query = nullptr, continueAll = nullptr, continueSelected = nullptr;
    HWND appendMembers = nullptr; // 固定动作栏中显式追加当前表单新实例，沿原集合和采样。
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
