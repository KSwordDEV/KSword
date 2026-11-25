#pragma once

#include <Windows.h>

#include <cstdint>
#include <optional>
#include <string_view>

namespace ks::cli::action_analyze::control {

struct NativeImageSite {
    std::uintptr_t base = 0;
    std::uintptr_t address = 0;
    std::uint32_t rva = 0;
};

// 只解析该进程当前映射的 AMD64 PE；不装载映像，不查远程符号服务器。
DWORD ResolveNativeImageSite(HANDLE process, DWORD pid, std::wstring_view path,
    std::optional<std::uint32_t> rva, std::string_view exportName, NativeImageSite& site);

} // namespace ks::cli::action_analyze::control
