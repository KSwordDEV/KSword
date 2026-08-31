#pragma once

#include <cstdint>
#include <string>

namespace Ksword::Core {

enum class EntityKind {
    None,
    Module,
    Process,
    Thread,
    File,
    RegistryKey,
    Window,
    Driver,
    NetworkEndpoint
};

enum class NavigationTarget {
    Default,
    ProcessDetails,
    MemoryOperations,
    FileBrowser,
    RegistryBrowser,
    NetworkConnections,
    HandleTable,
    WindowManager,
    EtwMonitor
};

// EntityRef identifies the same system entity across pages. Process and thread
// identities may include a creation time; text carries a path, module title or
// endpoint tuple without weakening the numeric identity fields.
struct EntityRef final {
    EntityKind kind = EntityKind::None;
    std::uint64_t id = 0;
    std::uint64_t parentId = 0;
    std::uint64_t creationTime100ns = 0;
    std::wstring text;
};

struct NavigationRequest final {
    NavigationTarget target = NavigationTarget::Default;
    EntityRef entity;
};

enum class CommandInputKind {
    Invalid,
    Navigation,
    Shell
};

struct CommandInputResult final {
    CommandInputKind kind = CommandInputKind::Invalid;
    NavigationRequest navigation;
    std::wstring shellCommand;
    std::wstring error;
};

// ParseCommandInput implements the Lite command palette grammar. A leading !
// is the only shell escape; all other recognized prefixes produce a typed
// navigation request so arbitrary text is never silently executed.
CommandInputResult ParseCommandInput(const std::wstring& input);

} // namespace Ksword::Core
