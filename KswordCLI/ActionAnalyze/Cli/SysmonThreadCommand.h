#pragma once

namespace ks::cli::action_analyze {

// 由 analyze 命令族注册一次；注册本身不访问事件日志。
void RegisterSysmonThreadCommand();

} // namespace ks::cli::action_analyze
