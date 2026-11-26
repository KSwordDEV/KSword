#pragma once

#include "../../Core/Win32Lean.h"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace Ksword::Features::ActionAnalyze {

// 纯UI动作，不携带历史记录、原生句柄或停止令牌；请求仍在原页面冻结。
enum class LightNativeControlAction : std::size_t {
    Continue, StepInto, StepOverCall, StepOut, CancelStep, Detach,
    PauseAll, PauseSelected, ContinueAll, ContinueSelected, Recover, CloseGroup, DumpMemory, Pause, Count
};
constexpr std::size_t kLightNativeControlActions = static_cast<std::size_t>(LightNativeControlAction::Count);

struct LightNativeControlState {
    std::array<bool, kLightNativeControlActions> enabled{};
    std::wstring scope; // 原页面发布的真实PID/creation或本集合及原成员选择。
    bool canDump = false; // 本端当前Held完整停点、项目和内存范围均可用，点击仍回原页冻结。
    std::wstring dumpHint; // 相机的实际范围或禁用原因，包含本会话项目要求。
    bool attached = false; // 原执行owner实际已附加；总览暂停优先路由不以canPause决定。
    bool canPause = false;
    std::wstring pauseHint; // 原页面发布的Armed准入与禁用原因。
    bool operator==(const LightNativeControlState&) const = default;
};

// 页面独占此对象，销毁前清空回调；端口仅持弱引用，旧页面不能转发到复用的HWND。
struct LightNativeControlSource {
    LightNativeControlState state;
    std::function<void(LightNativeControlAction)> submit;
};

// 同一行为分析工作区内的UI端口；所有调用均在UI线程，不拥有后台会话或轮询器。
class LightNativeControlPort final {
public:
    void Bind(bool group, const std::shared_ptr<LightNativeControlSource>& source);
    void Unbind(bool group, const std::shared_ptr<LightNativeControlSource>& source);
    void Publish(const std::shared_ptr<LightNativeControlSource>& source, LightNativeControlState state);
    LightNativeControlState Read(bool group) const;
    void Submit(LightNativeControlAction action);
    void Observe(const std::shared_ptr<std::function<void()>>& observer);
private:
    void Notify();
    std::weak_ptr<LightNativeControlSource> dataWatch_, group_;
    std::vector<std::weak_ptr<std::function<void()>>> observers_;
};

// 总览持有的可浮出工具条；浮出只移动原控件宿主，按钮和handler保持同一份。
class LightNativeControlToolbar final {
public:
    LightNativeControlToolbar();
    ~LightNativeControlToolbar();
    LightNativeControlToolbar(const LightNativeControlToolbar&) = delete;
    LightNativeControlToolbar& operator=(const LightNativeControlToolbar&) = delete;
    bool Create(HWND overview, std::shared_ptr<LightNativeControlPort> port);
    int Layout(int x, int y, int width, int maximumHeight); // 工具条内部滚动，保留总览结果高度。
    void Destroy();
    void SetRetiring(bool retiring);
    HWND Entry(bool reverse = false) const; // 反向进入末项；浮出时进入原位收回入口。
    bool HandleCommand(WPARAM command); // 仅处理原位收回按钮，不转发原生控制到HWND。
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

inline constexpr UINT kFocusLightNativeToolbar = WM_APP + 966;
// 原总览作为内容子页，顶部工具条单独布局；API表单和原总览业务无需重排。
HWND CreateLightNativeControlOverview(HWND parent, const RECT& bounds,
    std::shared_ptr<LightNativeControlPort> port,
    std::function<HWND(HWND, const RECT&)> createContent);

} // namespace Ksword::Features::ActionAnalyze
