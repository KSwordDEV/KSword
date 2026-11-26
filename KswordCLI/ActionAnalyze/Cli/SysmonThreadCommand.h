#pragma once

namespace Ksword::ActionAnalyze::Detection {
enum class SysmonLimit;
enum class SysmonReadState;
struct SysmonSubscriptionStatus;
struct SysmonThreadObservation;
struct SysmonThreadQuery;
}
namespace ks::cli { class Args; struct Json; }

namespace ks::cli::action_analyze {

// 由 analyze 命令族注册一次；注册本身不访问事件日志。
void RegisterSysmonThreadCommand();
void RegisterSysmonProjectCommands();
Ksword::ActionAnalyze::Detection::SysmonThreadQuery ParseSysmonThreadQuery(const Args& args);
const wchar_t* SysmonReadStateText(Ksword::ActionAnalyze::Detection::SysmonReadState state) noexcept;
const wchar_t* SysmonLimitText(Ksword::ActionAnalyze::Detection::SysmonLimit limit) noexcept;

// 历史查询和实时订阅的同一观察投影；输入须为通过来源解码的记录。
Json SysmonObservationJson(const Ksword::ActionAnalyze::Detection::SysmonThreadObservation& observation);

// 统一会话可投影自己持有的订阅状态，覆盖范围保持未知。
Json SysmonSubscriptionJson(const Ksword::ActionAnalyze::Detection::SysmonSubscriptionStatus& status);

} // namespace ks::cli::action_analyze
