#pragma once

// F-09 离线结果跳转现场、F-12 现有页面联动。
//
// 离线会话里的一条结果被点击时，必须先拿它保存的身份和现场重新解析出的身份做
// 一次显式校验：对象已退出、PID 被复用、身份信息不足是三种不同结果，都不能把
// 操作交给"看起来像"的新对象。

#include "ObjectIdentity.h"
#include "ScanBudget.h"

#include <string>
#include <vector>

namespace Ksword::Evidence {

// 现场解析结果：调用方用当前枚举去查同 PID/同路径的对象，查到就填进来。
struct LiveResolution final {
    bool found = false;                 // 现场是否存在候选对象
    ProcessInstanceId liveProcess;      // found 为真时的现场身份
};

// 把离线保存的进程身份与现场解析结果比对。
LiveNavigationDecision ResolveProcessNavigation(const ProcessInstanceId& saved,
                                                const LiveResolution& live) noexcept;

// ---------------------------------------------------------------------------
// F-12：带身份和证据 id 的导航请求。
// ---------------------------------------------------------------------------
enum class NavigationPage {
    Unknown,
    RiskCenter,
    Driver,
    Process,
    Thread,
    Memory,
    Network,
    Timeline,
    File,
    Handle,
    Registry,
};

const char* NavigationPageName(NavigationPage page) noexcept;

struct NavigationRequest final {
    NavigationPage page = NavigationPage::Unknown;
    ObjectRef object;
    std::string evidenceId;      // 回到原始证据用；F-12 要求导航必须带得上它
    std::string anchor;          // 页面内定位锚点（RVA/地址/序号的文本形式）
    // requireExactMatch 只决定**锚点**是否必须精确落位（false 时允许落在对象所在的
    // 区块而不是精确那一行）。它不是身份门槛的开关 —— 身份门槛无条件生效。
    bool requireExactMatch = true;  // F-12：定位不到就说明原因，不许跳到首行
};

enum class NavigationOutcome {
    Delivered,            // 目标页已接收并精确定位
    TargetPageMissing,    // 目标页已关闭/未物化
    ObjectNotPresent,     // 页面在，但对象不在当前数据里
    IdentityUnusable,     // 引用身份不足，不允许跳转
    EvidenceIdMissing,    // 请求根本没带证据 id，回不到原始证据
    EvidenceNotSaved,     // 离线会话里这段数据没被保存
};

const char* NavigationOutcomeName(NavigationOutcome outcome) noexcept;

// 页面侧收到请求时的判定：只依据"目标页是否存在 + 对象是否命中 + 身份是否够用"，
// 绝不因为名字相近就落到别的行上。
NavigationOutcome DecideNavigation(const NavigationRequest& request,
                                   bool targetPageAvailable,
                                   bool objectPresentInPage,
                                   bool evidencePresentInSession) noexcept;

} // namespace Ksword::Evidence
