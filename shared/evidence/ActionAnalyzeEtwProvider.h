#pragma once

#include <guiddef.h>
#include <string_view>

namespace ks::action_analyze::etw {

// KSword 自有 ETW 标识。激活与归档使用同一标识，PID 及来源代次仍由各采样独立验证。
inline constexpr std::string_view kProviderId = "d4a71ada-81b0-4b15-a173-417f33bc8107";
inline constexpr GUID kProviderGuid{0xd4a71ada, 0x81b0, 0x4b15, {0xa1, 0x73, 0x41, 0x7f, 0x33, 0xbc, 0x81, 0x07}};

// 版本 1 仅使用标准事件头。编号表示合作 Agent 自身的生命周期，不携带业务 API 参数。
enum class AgentEvent : unsigned short {
    PipeReady = 1,
    HooksInstalled = 2,
    HooksPartial = 3,
    InstallIncomplete = 4,
    HooksRestored = 5,
};

// 返回归档图使用的稳定操作名。未知描述符由读侧继续保留为通用 ETW 上下文。
constexpr std::string_view AgentOperation(AgentEvent event) noexcept
{
    switch (event) {
    case AgentEvent::PipeReady: return "etw.agent.pipe-ready.v1";
    case AgentEvent::HooksInstalled: return "etw.agent.hooks-installed.v1";
    case AgentEvent::HooksPartial: return "etw.agent.hooks-partial.v1";
    case AgentEvent::InstallIncomplete: return "etw.agent.install-incomplete.v1";
    case AgentEvent::HooksRestored: return "etw.agent.hooks-restored.v1";
    }
    return {};
}

} // namespace ks::action_analyze::etw
