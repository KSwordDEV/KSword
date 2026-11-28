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
    // 间接数据关注点的选择器仍在映像中，实际关注地址冻结为当前私有分配。
    std::uintptr_t pointerExportAddress = 0;
    std::uintptr_t allocationBase = 0;
    std::uintptr_t regionBase = 0;
    std::size_t regionBytes = 0;
    std::uint32_t regionProtection = 0;
};

// 只解析该进程当前映射的 AMD64 PE；不装载映像，不查远程符号服务器。
// eventImageBase非零时必须来自已核对身份/文件的原始调试事件，供loader初始化前使用。
DWORD ResolveNativeImageSite(HANDLE process, DWORD pid, std::wstring_view path,
    std::optional<std::uint32_t> rva, std::string_view exportName, NativeImageSite& site,
    std::uint32_t dataBytes = 0, bool allowReadOnlyData = false, std::uintptr_t eventImageBase = 0);

// 读取 AMD64 映像中的指针数据导出，冻结其指向的单个可写私有内存区。
// 仅选择一次，不跟随之后改变的指针，也不修改目标内存保护。
// eventImageBase 与直接映像解析相同，只接受已核对文件身份的原始调试事件基址。
DWORD ResolveNativePointerDataSite(HANDLE process, DWORD pid, std::wstring_view path,
    std::string_view exportName, std::uint32_t dataBytes, NativeImageSite& site,
    std::uintptr_t eventImageBase = 0);

// 在停止期间回读选择器和区域属性；失败时停止使用旧地址，不静默重绑。
// VirtualQueryEx 没有分配代次，此核对不证明同地址释放再分配从未发生。
DWORD VerifyNativePointerDataSite(HANDLE process, const NativeImageSite& site, std::uint32_t dataBytes);

} // namespace ks::cli::action_analyze::control
