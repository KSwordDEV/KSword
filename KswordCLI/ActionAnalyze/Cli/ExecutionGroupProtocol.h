#pragma once

#include "Protocol.h"
#include "../Control/OwnedExecutionGroup.h"

namespace ks::cli::action_analyze::execution_group {

// 小型 UTF-8 配置仅承载明确站点，不读取历史项目来授予控制权。
[[nodiscard]] std::vector<control::ExecutionGroupSite> ReadSites(const std::wstring& path);
// 同一完整快照形状服务pause/continue/step；含活绑定requestId、clean、stopReason、armedPause和stepState。
[[nodiscard]] JsonValue StopToken(const control::NativeControlResult& state);
[[nodiscard]] bool ParseStopToken(const JsonValue& token, control::NativeControlResult& state);
// 完整成员表冻结原owner与同一完整快照，供混合Held/Armed批量动作直接回传。
[[nodiscard]] JsonValue SessionToken(const control::ExecutionGroupMember& member);
[[nodiscard]] bool ParseSessionToken(const JsonValue& token, control::ExecutionGroupSessionEntry& entry);
[[nodiscard]] JsonValue Report(const control::ExecutionGroupResult& result, bool repl = false);
[[nodiscard]] JsonValue ControlReport(const control::NativeControlResult& state);
[[nodiscard]] std::string Utf8(std::wstring_view text);
[[nodiscard]] std::wstring Wide(std::string_view text);

// REPL 显式复制 token 的 UTF-8 JSON 十六进制字节；不存索引、不按停点 ID 补现场字段。
[[nodiscard]] std::string TokenText(const JsonValue& token);
[[nodiscard]] bool ParseTokenText(std::string_view text, JsonValue& token);

} // namespace ks::cli::action_analyze::execution_group
