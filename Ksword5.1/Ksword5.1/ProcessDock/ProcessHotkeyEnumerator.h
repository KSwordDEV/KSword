#pragma once

#include <QString>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ks::process
{
    // 来源是稳定业务身份，清除入口不得依赖可翻译的显示文字分流。
    enum class HotkeySourceKind : std::uint8_t
    {
        Unknown,
        WindowActivation,
        ShellLink,
        MenuShortcut,
        PeAccelerator
    };

    // 快捷方式文件在采集时的身份；任一字段缺失时只展示，不执行清除。
    struct HotkeyFileIdentity
    {
        bool valid = false;
        std::uint32_t volumeSerialNumber = 0;
        std::uint64_t fileIndex = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t lastWriteTime100ns = 0;
    };

    // UserModeHotkeyRecord：进程详情“热键”页中可由 R3 读取的一条热键记录。
    struct UserModeHotkeyRecord
    {
        QString objectText;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        QString hotkeyText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString processName;
        QString sourceText;
        QString detailText;
        HotkeySourceKind sourceKind = HotkeySourceKind::Unknown;
        std::uint64_t processCreationTime100ns = 0;
        std::uint64_t windowHandle = 0;
        std::uint16_t expectedWindowHotkeyValue = 0;
        std::uint16_t expectedShortcutHotkeyValue = 0;
        QString shortcutTargetPath;
        HotkeyFileIdentity shortcutFileIdentity;
    };

    struct UserModeHotkeyProcessTarget
    {
        std::uint32_t processId = 0;
        QString processName;
        QString processImagePath;
        std::uint64_t creationTime100ns = 0;
    };

    struct UserModeHotkeyBatchProgress
    {
        std::uint32_t completedProcessCount = 0;
        std::uint32_t totalProcessCount = 0;
        QString processName;
        QString diagnosticText;
        std::vector<UserModeHotkeyRecord> records;
    };

    using UserModeHotkeyBatchCallback = std::function<void(UserModeHotkeyBatchProgress progress)>;

    // EnumerateUserModeHotkeysForProcess：复用进程详情的 R3 热键采集路径。
    // 只扫描窗口热键、菜单快捷键、PE Accelerator 资源和 .lnk 快捷方式热键，不访问驱动。
    std::vector<UserModeHotkeyRecord> EnumerateUserModeHotkeysForProcess(
        std::uint32_t processId,
        QString processName = {},
        QString processImagePath = {},
        QString* diagnosticTextOut = nullptr,
        std::uint64_t processCreationTime100ns = 0);

    // EnumerateUserModeHotkeysForProcesses：全量扫描时共享一次 .lnk 读取结果，逐进程回调。
    void EnumerateUserModeHotkeysForProcesses(
        const std::vector<UserModeHotkeyProcessTarget>& targets,
        const UserModeHotkeyBatchCallback& progressCallback,
        QString* diagnosticTextOut = nullptr,
        const std::function<bool()>& canceled = {});
}
