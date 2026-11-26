#pragma once

#include "../../../shared/evidence/ApiMonitorClue.h"

#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Ksword::ActionAnalyze::Rules {

// 拥有型参数保留 UTF-8 字节，复制归档行后不会留下指向原包的字符串视图。
struct ApiBehaviorParameter {
    std::string_view id; // 静态字段目录中的稳定 ID。
    std::variant<std::uint64_t, std::string> value; // 仅发布通过布局核对的数值或有后继边界的文本。
};

// 普通强类型返回观察；不认证生产者、不读取指针、不建立跨事件句柄映射。
struct ApiBehaviorObservation {
    bool succeeded = false; // 按该精确导出的返回约定解释，不由错误码单独推断。
    std::uint64_t returnBits = 0; // 包中带显式标记的原返回位。
    std::optional<std::uint32_t> status; // StatusUnknown 时保持未采集。
    std::string_view statusDomain; // lstatus、ntstatus、win32 或 addrinfo-return，按真实错误源区分。
    std::vector<ApiBehaviorParameter> parameters; // 严格格式可解码的当前包参数。
};

// 输入完整已分类原包，输出独立返回观察。Raw/Fake/入口包及未登记返回约定返回空。
std::optional<ApiBehaviorObservation> ReadApiBehaviorObservation(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet);

} // namespace Ksword::ActionAnalyze::Rules
