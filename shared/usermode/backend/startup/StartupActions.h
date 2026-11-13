#pragma once
#include "StartupTypes.h"
namespace ks::r3::startup {
ActionResult SetStartupEntryEnabled(const StartupEntry& entry, bool enabled);
// 输入启动项及可选权限告警回调，返回删除与恢复的结构化结果。
ActionResult DeleteStartupEntry(const StartupEntry& entry, const std::function<void()>& permissionWarning);
}
