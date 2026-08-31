#include "EntityRef.h"

#include <algorithm>
#include <cwctype>
#include <limits>

namespace Ksword::Core {
namespace {

std::wstring Trim(std::wstring value) {
    while (!value.empty() && std::iswspace(value.back())) {
        value.pop_back();
    }
    std::size_t first = 0;
    while (first < value.size() && std::iswspace(value[first])) {
        ++first;
    }
    if (first != 0) {
        value.erase(0, first);
    }
    return value;
}

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool ParseUnsigned(const std::wstring& text, std::uint64_t& value) {
    const std::wstring trimmed = Trim(text);
    if (trimmed.empty()) {
        return false;
    }
    int base = 10;
    std::size_t first = 0;
    if (trimmed.size() > 2U && trimmed[0] == L'0' && (trimmed[1] == L'x' || trimmed[1] == L'X')) {
        base = 16;
        first = 2;
    }
    if (first >= trimmed.size()) {
        return false;
    }
    std::uint64_t parsed = 0;
    for (std::size_t index = first; index < trimmed.size(); ++index) {
        const wchar_t ch = trimmed[index];
        unsigned digit = 0;
        if (ch >= L'0' && ch <= L'9') {
            digit = static_cast<unsigned>(ch - L'0');
        } else if (base == 16 && ch >= L'a' && ch <= L'f') {
            digit = static_cast<unsigned>(ch - L'a' + 10);
        } else if (base == 16 && ch >= L'A' && ch <= L'F') {
            digit = static_cast<unsigned>(ch - L'A' + 10);
        } else {
            return false;
        }
        if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / static_cast<unsigned>(base)) {
            return false;
        }
        parsed = parsed * static_cast<unsigned>(base) + digit;
    }
    value = parsed;
    return true;
}

CommandInputResult NumericRequest(
    const std::wstring& argument,
    const EntityKind kind,
    const NavigationTarget target,
    const wchar_t* label) {
    CommandInputResult result{};
    std::uint64_t id = 0;
    if (!ParseUnsigned(argument, id) || id == 0) {
        result.error = std::wstring(label) + L" 必须是非零十进制或 0x 十六进制数字。";
        return result;
    }
    if (kind != EntityKind::Window && id > (std::numeric_limits<std::uint32_t>::max)()) {
        result.error = std::wstring(label) + L" 超出 Windows 32 位标识符范围。";
        return result;
    }
    result.kind = CommandInputKind::Navigation;
    result.navigation.target = target;
    result.navigation.entity.kind = kind;
    result.navigation.entity.id = id;
    return result;
}

const wchar_t* ModuleTitleForBareVerb(const std::wstring& verb) {
    if (verb == L"process" || verb == L"进程") { return L"进程"; }
    if (verb == L"memory" || verb == L"内存") { return L"内存"; }
    if (verb == L"window" || verb == L"窗口") { return L"窗口"; }
    if (verb == L"network" || verb == L"网络") { return L"网络"; }
    if (verb == L"handle" || verb == L"handles" || verb == L"句柄") { return L"句柄"; }
    if (verb == L"monitor" || verb == L"监控") { return L"监控"; }
    if (verb == L"file" || verb == L"文件") { return L"文件"; }
    if (verb == L"reg" || verb == L"registry" || verb == L"注册表") { return L"注册表"; }
    if (verb == L"driver" || verb == L"驱动") { return L"驱动"; }
    if (verb == L"kernel" || verb == L"内核") { return L"内核"; }
    if (verb == L"hardware" || verb == L"硬件") { return L"硬件"; }
    if (verb == L"startup" || verb == L"启动项") { return L"启动项"; }
    if (verb == L"service" || verb == L"services" || verb == L"服务") { return L"服务"; }
    if (verb == L"privilege" || verb == L"权限") { return L"权限"; }
    if (verb == L"systools" || verb == L"系统工具") { return L"系统工具"; }
    if (verb == L"misc" || verb == L"杂项安全") { return L"杂项安全"; }
    return nullptr;
}

} // namespace

CommandInputResult ParseCommandInput(const std::wstring& input) {
    const std::wstring trimmed = Trim(input);
    CommandInputResult result{};
    if (trimmed.empty()) {
        result.error = L"请输入模块名或导航命令。";
        return result;
    }
    if (trimmed.front() == L'!') {
        result.shellCommand = Trim(trimmed.substr(1));
        if (result.shellCommand.empty()) {
            result.error = L"! 后需要提供要执行的命令。";
            return result;
        }
        result.kind = CommandInputKind::Shell;
        return result;
    }

    const std::size_t separator = trimmed.find_first_of(L" \t");
    const std::wstring verb = Lower(trimmed.substr(0, separator));
    const std::wstring argument = separator == std::wstring::npos ? std::wstring{} : Trim(trimmed.substr(separator + 1));

    if (argument.empty() && ModuleTitleForBareVerb(verb) != nullptr) {
        result.kind = CommandInputKind::Navigation;
        result.navigation.entity.kind = EntityKind::Module;
        result.navigation.entity.text = ModuleTitleForBareVerb(verb);
        return result;
    }

    if (verb == L"pid" || verb == L"process" || verb == L"进程") {
        return NumericRequest(argument, EntityKind::Process, NavigationTarget::ProcessDetails, L"PID");
    }
    if (verb == L"tid" || verb == L"thread" || verb == L"线程") {
        return NumericRequest(argument, EntityKind::Thread, NavigationTarget::ProcessDetails, L"TID");
    }
    if (verb == L"mem" || verb == L"memory" || verb == L"内存") {
        return NumericRequest(argument, EntityKind::Process, NavigationTarget::MemoryOperations, L"PID");
    }
    if (verb == L"hwnd" || verb == L"window" || verb == L"窗口") {
        return NumericRequest(argument, EntityKind::Window, NavigationTarget::WindowManager, L"HWND");
    }
    if (verb == L"net" || verb == L"network" || verb == L"网络") {
        return NumericRequest(argument, EntityKind::Process, NavigationTarget::NetworkConnections, L"PID");
    }
    if (verb == L"handle" || verb == L"handles" || verb == L"句柄") {
        return NumericRequest(argument, EntityKind::Process, NavigationTarget::HandleTable, L"PID");
    }
    if (verb == L"etw" || verb == L"monitor" || verb == L"监控") {
        return NumericRequest(argument, EntityKind::Process, NavigationTarget::EtwMonitor, L"PID");
    }
    if (verb == L"file" || verb == L"文件") {
        if (argument.empty()) {
            result.error = L"file 后需要提供路径。";
            return result;
        }
        result.kind = CommandInputKind::Navigation;
        result.navigation.target = NavigationTarget::FileBrowser;
        result.navigation.entity.kind = EntityKind::File;
        result.navigation.entity.text = argument;
        return result;
    }
    if (verb == L"reg" || verb == L"registry" || verb == L"注册表") {
        if (argument.empty()) {
            result.error = L"reg 后需要提供注册表路径。";
            return result;
        }
        result.kind = CommandInputKind::Navigation;
        result.navigation.target = NavigationTarget::RegistryBrowser;
        result.navigation.entity.kind = EntityKind::RegistryKey;
        result.navigation.entity.text = argument;
        return result;
    }
    if (verb == L"module" || verb == L"模块") {
        if (argument.empty()) {
            result.error = L"module 后需要提供模块名称。";
            return result;
        }
        result.kind = CommandInputKind::Navigation;
        result.navigation.entity.kind = EntityKind::Module;
        result.navigation.entity.text = argument;
        return result;
    }

    result.kind = CommandInputKind::Navigation;
    result.navigation.entity.kind = EntityKind::Module;
    result.navigation.entity.text = trimmed;
    return result;
}

} // namespace Ksword::Core
