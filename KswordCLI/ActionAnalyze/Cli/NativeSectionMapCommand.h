#pragma once

namespace ks::cli::action_analyze {

// RegisterNativeSectionMapCommands：登记独立 analyze execution map 命令及内置 help 元数据。
// 无输入/返回；只注册离线查询入口，不访问进程，统一挂接由 Cli/Commands.cpp 的所有者执行。
void RegisterNativeSectionMapCommands();

} // namespace ks::cli::action_analyze
