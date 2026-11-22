#include "ThreadLayoutProfile.h"
#include "../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"

#include <Windows.h>

#pragma comment(lib, "Version.lib")

namespace ks::threadlayout
{
    Version ReadImageVersion(const std::filesystem::path& image)
    {
        auto path = image; // 显式离线 PE 与默认系统内核使用同一固定版本资源解析。
        if (path.empty())
        {
            std::wstring system(32768, L'\0'); // 支持完整系统目录路径，不使用产品版本注册表值。
            const auto length = ::GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
            if (!length || length >= system.size())
            {
                return {};
            }
            system.resize(length);
            path = std::filesystem::path(system) / L"ntoskrnl.exe";
        }
        DWORD ignored = 0; // 旧版本 API 要求的未使用输出。
        const auto size = ::GetFileVersionInfoSizeW(path.c_str(), &ignored); // 只读取文件固定版本资源。
        if (!size || size > 1024 * 1024)
        {
            return {};
        }
        std::vector<unsigned char> bytes(size); // 版本资源的有界私有副本。
        VS_FIXEDFILEINFO* info = nullptr; // VerQueryValue 指向该副本内的固定版本结构。
        UINT count = 0; // 固定结构可用的字节数。
        if (!::GetFileVersionInfoW(path.c_str(), 0, size, bytes.data()) ||
            !::VerQueryValueW(bytes.data(), L"\\", reinterpret_cast<void**>(&info), &count) ||
            !info || count < sizeof(*info) || info->dwSignature != 0xFEEF04BD)
        {
            return {};
        }
        return {HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS),
            HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS)};
    }

    Identity ReadImageIdentity(const std::filesystem::path& image)
    {
        auto path = image; // CLI 可指定其他磁盘内核；GUI 默认选择系统目录。
        if (path.empty())
        {
            std::wstring system(32768, L'\0'); // 为系统目录保留完整 Unicode 路径。
            const auto length = ::GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
            if (!length || length >= system.size())
            {
                return {};
            }
            system.resize(length);
            path = std::filesystem::path(system) / L"ntoskrnl.exe";
        }
        ks::file::PeAnalysisOptions options; // 复用已有 PE 边界检查，不解析导入/导出。
        options.identityOnly = true;
        const auto pe = ks::file::AnalyzePeFile(path.wstring(), options);
        if (!pe.success || pe.machine != IMAGE_FILE_MACHINE_AMD64 || pe.rsdsKey.empty())
        {
            return {};
        }
        return {pe.machine, pe.timeDateStamp, pe.sizeOfImage, pe.rsdsKey};
    }
}
