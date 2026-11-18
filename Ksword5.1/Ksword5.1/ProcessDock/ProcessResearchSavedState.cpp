#include "ProcessResearchSavedState.h"
#include <QDir>
#include <QFileInfo>
#include <QScopeGuard>
#include <bit>
#include <iterator>

namespace ksword::detection
{
    bool ReadVmrsProcessFiles(HMODULE vmm, const QString& file, QByteArray& systemInfo, QByteArray& processes,
        MethodReport& report, const CancelCheck& stop)
    {
        const auto path = QFileInfo(file).canonicalFilePath();
        if (!vmm || path.isEmpty() || path.startsWith(QStringLiteral("//")) ||
            !path.endsWith(QStringLiteral(".vmrs"), Qt::CaseInsensitive))
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("请选择本地离线 VMRS 文件和 MemProcFS x64 的 vmm.dll。");
            return false;
        }
        const auto lease = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (lease == INVALID_HANDLE_VALUE)
        {
            const DWORD error = GetLastError();
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("无法取得 VMRS 只读文件租约，Win32=%1。").arg(error);
            return false;
        }
        const auto closeFile = qScopeGuard([&] { CloseHandle(lease); });
        // The VMM session is file-backed. No mount, live device, refresh, or symbol server is used.
        const auto init = std::bit_cast<HANDLE(*)(DWORD, LPCSTR*)>(GetProcAddress(vmm, "VMMDLL_Initialize"));
        const auto close = std::bit_cast<void(*)(HANDLE)>(GetProcAddress(vmm, "VMMDLL_Close"));
        const auto plugins = std::bit_cast<BOOL(*)(HANDLE)>(GetProcAddress(vmm, "VMMDLL_InitializePlugins"));
        const auto read = std::bit_cast<LONG(*)(HANDLE, LPCSTR, PBYTE, DWORD, PDWORD, ULONG64)>(GetProcAddress(vmm, "VMMDLL_VfsReadU"));
        if (!init || !close || !plugins || !read)
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("所选 VMM 库缺少保存态分析所需的 VFS 入口。");
            return false;
        }
        const auto device = QByteArray("HvSavedState://") + QDir::toNativeSeparators(path).toUtf8();
        LPCSTR args[] = {"", "-device", device.constData(), "-norefresh", "-waitinitialize", "-disable-python", "-disable-symbolserver"};
        const auto engine = init(static_cast<DWORD>(std::size(args)), args);
        if (!engine)
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("无法打开 HvSavedState 设备；请核对 VMRS、MemProcFS 保存态插件与 Windows SDK。");
            return false;
        }
        const auto closeEngine = qScopeGuard([&] { close(engine); });
        if (stop && stop()) { report.status = Status::Cancelled; return false; }
        if (!plugins(engine))
        {
            report.status = Status::Failed;
            report.detail = QStringLiteral("无法初始化离线 VMRS 的 MemProcFS 进程视图。");
            return false;
        }
        auto readFile = [&](const char* name, qsizetype maximum, QByteArray& data) {
            if (stop && stop()) { report.status = Status::Cancelled; return false; }
            data.resize(maximum + 1);
            DWORD received = 0;
            const auto status = read(engine, name, reinterpret_cast<PBYTE>(data.data()), static_cast<DWORD>(data.size()), &received, 0);
            if (status < 0 || !received || received > static_cast<DWORD>(maximum))
            {
                data.clear();
                report.status = Status::Failed;
                report.detail = QStringLiteral("%1 | NTSTATUS=0x%2 | bytes=%3")
                    .arg(QString::fromLatin1(name)).arg(quint32(status), 8, 16, QChar('0')).arg(received);
                return false;
            }
            data.resize(received);
            return true;
        };
        return readFile("\\sys\\sysinfo\\sysinfo.txt", 1024 * 1024, systemInfo) &&
            readFile("\\sys\\proc\\proc-time.txt", 8 * 1024 * 1024, processes);
    }
}
