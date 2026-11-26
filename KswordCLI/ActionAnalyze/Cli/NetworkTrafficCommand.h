#pragma once

#include <functional>
#include <string>

namespace ks::cli::action_analyze {

// 由原网络命令登记入口调用；bootId 复用既有 Windows 启动身份读取器。
void RegisterNetworkTrafficCommands(std::function<std::string()> bootId);

} // namespace ks::cli::action_analyze
