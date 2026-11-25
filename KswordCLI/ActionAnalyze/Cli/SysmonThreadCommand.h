#pragma once

namespace Ksword::ActionAnalyze::Detection {
struct SysmonSubscriptionStatus;
struct SysmonThreadObservation;
}
namespace ks::cli { struct Json; }

namespace ks::cli::action_analyze {

// 由 analyze 命令族注册一次；注册本身不访问事件日志。
void RegisterSysmonThreadCommand();

// 历史查询和实时订阅的同一观察投影；输入须为通过来源解码的记录。
Json SysmonObservationJson(const Ksword::ActionAnalyze::Detection::SysmonThreadObservation& observation);

// 统一会话可投影自己持有的订阅状态，覆盖范围保持未知。
Json SysmonSubscriptionJson(const Ksword::ActionAnalyze::Detection::SysmonSubscriptionStatus& status);

} // namespace ks::cli::action_analyze
