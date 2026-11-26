#pragma once

#include "NetworkTrafficPage.h"
#include "LightNetworkTrafficWorker.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/ParameterWorkspace.h"

namespace Ksword::Features::ActionAnalyze::network_traffic_page {

inline constexpr UINT kCompleted = WM_APP + 986; // 本页单个后台事务回投消息。
inline constexpr UINT kExported = WM_APP + 987; // 文本导出后台完成消息。
enum : int { kProject = 58801, kBrowse, kSample, kPid, kCreation, kSource, kDuration,
    kOrdinal, kSequence, kCapture, kRead, kCancel, kCopy, kExport, kFind };

struct Page {
    HWND hwnd = nullptr; // 本页根窗口。
    Ui::ParameterWorkspace parameters; // 唯一参数滚动正文，结果和动作固定。
    HWND hint = nullptr; // 说明真实抓包和归属范围。
    HWND projectLabel = nullptr; // 已有项目输入标题。
    HWND project = nullptr; // 原项目目录/manifest草稿。
    HWND browse = nullptr; // 选择已有manifest。
    HWND sampleLabel = nullptr; // 原sample输入标题。
    HWND sample = nullptr; // 原sample UUID。
    HWND pidLabel = nullptr; // 目标PID输入标题。
    HWND pid = nullptr; // 下一次采集PID。
    HWND creationLabel = nullptr; // 精确创建时间标题。
    HWND creation = nullptr; // FILETIME草稿。
    HWND sourceLabel = nullptr; // 来源输入标题。
    HWND source = nullptr; // 显式来源下拉框。
    HWND durationLabel = nullptr; // 时长标题。
    HWND duration = nullptr; // 毫秒时长草稿。
    HWND ordinalLabel = nullptr; // 只读网络段号标题。
    HWND ordinal = nullptr; // 0最新或精确段号。
    HWND sequenceLabel = nullptr; // 可选记录序号标题。
    HWND sequence = nullptr; // 空表示预览，否则读全部保留字节。
    HWND capture = nullptr; // 显式采集固定动作。
    HWND read = nullptr; // 只读网络段固定动作。
    HWND cancel = nullptr; // 本次采集取消动作。
    HWND status = nullptr; // 状态与错误不覆盖旧结果来源。
    HWND receipt = nullptr; // 唯一正文，附加共享原生搜索。
    HWND copy = nullptr; // 复制实际正文。
    HWND exportText = nullptr; // 导出相同正文。
    HWND find = nullptr; // 打开正文搜索。
    HWND tooltip = nullptr; // 本页所有动作的悬停释义。
    std::unique_ptr<Ui::AsyncSnapshotTask<LightNetworkTrafficView>> worker; // 单个本端后台任务。
    std::unique_ptr<Ui::AsyncSnapshotTask<std::wstring>> exporter; // 文本写盘不阻塞UI。
    std::shared_ptr<std::atomic_bool> cancelled; // 采集器独立取消位。
    std::wstring shownText; // 最后发布的完整规范正文。
    bool retiring = false; // 宿主关闭期间拒绝新动作。
};

// 创建原生共享参数、动作和文本结构；失败返回false，由宿主撤回页面。
bool CreateControls(Page& page);
// 根据客户区和自然表单高度布局，窄窗参数滚动，结果不嵌入第二滚动壳。
void Layout(Page& page);
// 更新真实后台资格；参数仍允许编辑，不重定向已冻结请求。
void UpdateActions(Page& page);

} // namespace Ksword::Features::ActionAnalyze::network_traffic_page
