#pragma once
#include <optional>

namespace ks::rescue
{
    // 监护入口与 UAC 接替使用的内部命令行标记。
    inline constexpr wchar_t kHostArgument[] = L"--ksword-rescue-host";
    inline constexpr wchar_t kElevationAttemptArgument[] = L"--ksword-rescue-elevation-attempted";
    inline constexpr wchar_t kOriginalDesktopArgument[] = L"--ksword-rescue-origin-desktop";

    // KSword 启动时调用。普通启动返回空值，监护模式返回完整进程退出码（包括异常退出码）。
    std::optional<int> RunRescueDesktopHostIfRequested();
}
