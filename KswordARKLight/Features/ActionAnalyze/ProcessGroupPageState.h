#pragma once

#include "LightProcessGroupSession.h"
#include "LightNativeControlToolbar.h"
#include "../../Ui/ParameterWorkspace.h"
#include <commctrl.h>

namespace Ksword::Features::ActionAnalyze::process_group_page {

// 仅本页面使用的控件编号；WM_COMMAND低16位内唯一，不定义任何驱动协议。
enum : int {
    kPid = 58500, // PID草稿。
    kCreation, // 创建时间草稿。
    kIdentify, // 身份只读回查。
    kAdd, // 加入草稿。
    kRemove, // 移除草稿。
    kAuthorized, // 明确授权。
    kConfigure, // 冻结配置。
    kMembers, // 多选成员表。
    kPauseAll, // 全集暂停。
    kPauseSelected, // 子集暂停。
    kContinueAll, // 全集继续。
    kContinueSelected, // 子集继续。
    kRefresh, // 状态回查。
    kRecover, // 原票据恢复。
    kClose, // 清退原集合。
    kHistory, // 历史票据。
    kDetails, // 完整详情。
    kStatus, // 状态回执。
    kNewCollection, // 显式准备新集合。
    kProject, // 项目目录草稿。
    kMemoryBase, // 读取起点草稿。
    kMemoryBytes, // 读取长度草稿。
    kReadMemory, // 显式读取。
    kSaveMemory, // 保存原capture。
    kCopyDetails, // 复制同一完整文档。
    kExportDetails // 导出同一完整文档。
};

// 本端页面草稿、控件及已发布值；不包含原生owner、writer或控制句柄。
struct Page {
    HWND hwnd = nullptr; // 页根，唯一6px外边距由布局模块负责。
    HWND hint = nullptr; // 授权范围与逐页非原子读取说明。
    HWND pidLabel = nullptr; // 目标进程号标签。
    HWND pid = nullptr; // 目标进程号草稿。
    HWND creationLabel = nullptr; // 创建FILETIME标签。
    HWND creation = nullptr; // 创建FILETIME草稿。
    HWND identityButton = nullptr; // 显式身份读取动作。
    HWND identityView = nullptr; // 身份查询结果。
    HWND authorized = nullptr; // 本轮明确授权复选框。
    HWND addButton = nullptr; // 加入未执行草稿。
    HWND removeButton = nullptr; // 移除草稿选中实例。
    HWND configureButton = nullptr; // 冻结并执行配置。
    HWND members = nullptr; // 精确实例多选清单，结果拥有独立滚动。
    HWND pauseAll = nullptr; // 全部冻结成员暂停。
    HWND pauseSelected = nullptr; // 明确所选子集暂停。
    HWND continueAll = nullptr; // 全组完整令牌继续。
    HWND continueSelected = nullptr; // 所选完整令牌继续。
    HWND refresh = nullptr; // 原状态只读回查。
    HWND recover = nullptr; // 原Continue票据恢复。
    HWND close = nullptr; // 原owner清退动作。
    HWND newCollection = nullptr; // clean后显式开放新草稿。
    HWND history = nullptr; // 原票据历史选择。
    HWND details = nullptr; // 单一完整详情文档控件。
    HWND status = nullptr; // 真实状态和失败说明。
    HWND copyDetails = nullptr; // 复制完整详情。
    HWND exportDetails = nullptr; // 导出同一完整详情。
    HWND projectLabel = nullptr; // 新项目目录说明。
    HWND projectDirectory = nullptr; // Configure前冻结的目录草稿。
    HWND memoryBaseLabel = nullptr; // 显式读取地址说明。
    HWND memoryBase = nullptr; // 显式地址草稿。
    HWND memoryBytesLabel = nullptr; // 范围字节数说明。
    HWND memoryBytes = nullptr; // 字节数草稿。
    HWND readMemory = nullptr; // 原worker读取动作。
    HWND saveMemory = nullptr; // 原sample保存动作。
    HWND tooltip = nullptr; // 本页拥有的悬停提示窗。
    Ui::ParameterWorkspace parameters; // 参数正文唯一滚动责任，动作与结果不随之移动。

    LightProcessGroupSession session; // 本端唯一串行会话，页面只提交值请求。
    std::shared_ptr<LightNativeControlPort> controlPort;
    std::shared_ptr<LightNativeControlSource> controlSource; // 页根持有，工具条仅通过弱引用访问原命令入口。
    LightProcessGroupSnapshot shown; // 实际发布的完整控制及归档回执。
    std::vector<group_native::ProcessGroupTarget> draft; // 新配置前未执行的成员草稿。
    std::vector<group_native::ProcessGroupTarget> rowTargets; // 当前每行绑定的真实实例。
    std::wstring inputError; // 本地输入或入队失败，不覆盖原生错误。
    std::wstring identityText; // 已显示身份文本，无变化不重写。
    std::wstring statusText; // 已显示状态文本。
    std::wstring detailText; // 搜索、复制与导出共用的完整详情。
    std::uint64_t shownRevision = UINT64_MAX; // 同一快照不重建成员表和历史选择。
    bool rebuilding = false; // 屏蔽程序重建列表时的同步选择通知。
    bool configured = false; // 已提交冻结配置；失败也须显式清退再开草稿。
    bool configuring = false; // 已接纳配置等待原worker发布结论。
    bool retiring = false; // 页面退出准入，与原生clean分开。
};

// 按真实客户区布局参数滚动正文、固定动作和独立清单/详情，不执行业务查询。
void Layout(Page& page);
// 创建共享原生控件及提示；返回false时宿主撤回本页，不产生控制副作用。
bool CreateControls(Page& page);
// 只复制会话快照并投影，布局模块创建完成后调用，不执行原生Query。
void Refresh(Page& page);
// 子控件键盘导航由业务页统一实现；参数聚焦时调用共享Reveal。
LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR data);
} // namespace Ksword::Features::ActionAnalyze::process_group_page
