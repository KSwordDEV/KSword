#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include "Diagnostics.h"
#include "RuntimeResolver.h"
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace standalone
{
    namespace
    {
        std::wstring Hex(std::uint64_t number)
        { std::wostringstream s; s << L"0x" << std::hex << number; return s.str(); }

        std::vector<unsigned char> ReadFileBytes(const std::filesystem::path& path)
        {
            std::ifstream f(path, std::ios::binary | std::ios::ate);
            if (!f || f.tellg() <= 0 || f.tellg() > 128 * 1024 * 1024)
                throw std::runtime_error("Cannot read a bounded PE image");
            std::vector<unsigned char> bytes(static_cast<std::size_t>(f.tellg()));
            f.seekg(0);
            if (!f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
                throw std::runtime_error("Incomplete file read");
            return bytes;
        }

        template<class T> T Read(const std::vector<unsigned char>& bytes, std::size_t at)
        {
            if (at > bytes.size() || sizeof(T) > bytes.size() - at) throw std::runtime_error("Truncated PE");
            T v{};
            std::memcpy(&v, bytes.data() + at, sizeof(v));
            return v;
        }

        std::wstring Hash(const std::vector<unsigned char>& bytes)
        {
            HCRYPTPROV provider = 0;
            HCRYPTHASH hash = 0;
            if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw std::runtime_error("SHA256 provider unavailable");
            std::array<unsigned char, 32> digest{};
            DWORD size = static_cast<DWORD>(digest.size());
            const bool ok = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)
                && CryptHashData(hash, bytes.data(), static_cast<DWORD>(bytes.size()), 0)
                && CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &size, 0);
            if (hash) CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            if (!ok) throw std::runtime_error("SHA256 failed");
            std::wostringstream s;
            for (auto b : digest) s << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<unsigned>(b);
            return s.str();
        }

        std::wstring Version(const std::filesystem::path& path)
        {
            DWORD unused = 0;
            const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &unused);
            if (!size || size > 1024 * 1024) return L"unavailable";
            std::vector<unsigned char> data(size);
            VS_FIXEDFILEINFO* info = nullptr;
            UINT length = 0;
            if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())
                || !VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &length)
                || length < sizeof(*info)) return L"unavailable";
            std::wostringstream s;
            s << HIWORD(info->dwFileVersionMS) << L'.' << LOWORD(info->dwFileVersionMS)
              << L'.' << HIWORD(info->dwFileVersionLS) << L'.' << LOWORD(info->dwFileVersionLS);
            return s.str();
        }

        std::string Utf8(const std::wstring& s)
        {
            if (s.empty()) return {};
            const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
            if (!size) throw std::runtime_error("Invalid UTF-16 report text");
            std::string out(size, '\0');
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size, nullptr, nullptr);
            return out;
        }

        void WriteText(const std::filesystem::path& path, const std::wstring& text)
        {
            const auto bytes = Utf8(text);
            std::ofstream f(path, std::ios::binary);
            f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            f.close();
            if (!f) throw std::runtime_error("Report write failed");
        }

        const wchar_t* FailureText(ks::dwm_order::runtime::Failure failure)
        {
            using F = ks::dwm_order::runtime::Failure;
            switch (failure)
            {
            case F::None: return L"None";
            case F::InvalidImage: return L"InvalidImage";
            case F::MissingPattern: return L"MissingPattern";
            case F::AmbiguousPattern: return L"AmbiguousPattern";
            case F::ReferenceMismatch: return L"ReferenceMismatch";
            case F::InvalidVtable: return L"InvalidVtable";
            case F::InvalidCfg: return L"InvalidCfg";
            case F::InvalidWindowList: return L"InvalidWindowList";
            case F::InvalidFragments: return L"InvalidFragments";
            }
            return L"Unknown";
        }
    }

    std::filesystem::path ExecutableDirectory()
    {
        std::wstring path(32768, L'\0');
        const DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (!size || size >= path.size()) throw std::runtime_error("Executable path unavailable");
        path.resize(size);
        return std::filesystem::path(path).parent_path();
    }

    bool IsAdministrator()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE;
        CloseHandle(token);
        return ok && elevation.TokenIsElevated;
    }

    std::wstring Timestamp()
    {
        SYSTEMTIME t{};
        GetSystemTime(&t);
        wchar_t buf[48]{};
        swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", t.wYear, t.wMonth, t.wDay,
            t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
        return buf;
    }

    Diagnostic Inspect()
    {
        using namespace ks::dwm_order::runtime;
        Diagnostic d;
        std::wostringstream s;
        s << L"report_schema=1\r\ntool_version=1.0.0\r\nutc=" << Timestamp()
          << L"\r\ninspection=on-disk PE only; no DWM injection\r\narchitecture=x64\r\nelevated=" << IsAdministrator() << L"\r\n";
        try
        {
            using RtlVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
            const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
            RtlVersionFn rtl = nullptr;
            static_assert(sizeof(rtl) == sizeof(address));
            std::memcpy(&rtl, &address, sizeof(rtl));
            RTL_OSVERSIONINFOW os{};
            os.dwOSVersionInfoSize = sizeof(os);
            if (rtl && rtl(&os) == 0) s << L"os_version=" << os.dwMajorVersion << L'.' << os.dwMinorVersion << L'.' << os.dwBuildNumber << L"\r\n";
            DWORD ubr = 0, size = sizeof(ubr);
            if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR",
                RRF_RT_REG_DWORD, nullptr, &ubr, &size) == ERROR_SUCCESS) s << L"os_ubr=" << ubr << L"\r\n";
            DWORD session = 0;
            if (ProcessIdToSessionId(GetCurrentProcessId(), &session)) s << L"session=" << session << L"\r\n";
            s << L"remote_session=" << GetSystemMetrics(SM_REMOTESESSION) << L"\r\n";
            for (DWORD i = 0; i < 16; ++i)
            {
                DISPLAY_DEVICEW gpu{};
                gpu.cb = sizeof(gpu);
                if (!EnumDisplayDevicesW(nullptr, i, &gpu, 0)) break;
                s << L"display_adapter=" << gpu.DeviceString << L"\r\n";
            }
            wchar_t system[MAX_PATH]{};
            if (!GetSystemDirectoryW(system, MAX_PATH)) throw std::runtime_error("System directory unavailable");
            d.udwm = std::filesystem::path(system) / L"uDWM.dll";
            const auto raw = ReadFileBytes(d.udwm);
            d.udwmHash = Hash(raw);
            const auto version = Version(d.udwm);
            s << L"udwm_version=" << version << L"\r\nudwm_sha256=" << d.udwmHash << L"\r\n";
            const auto dos = Read<IMAGE_DOS_HEADER>(raw, 0);
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x1000) throw std::runtime_error("Invalid DOS header");
            const auto nt = Read<IMAGE_NT_HEADERS64>(raw, dos.e_lfanew);
            if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                || nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)
                || nt.OptionalHeader.SizeOfImage > 128 * 1024 * 1024
                || nt.OptionalHeader.SizeOfHeaders > raw.size()
                || nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage
                || nt.FileHeader.NumberOfSections > 96) throw std::runtime_error("Invalid x64 PE");
            std::vector<unsigned char> image(nt.OptionalHeader.SizeOfImage);
            std::memcpy(image.data(), raw.data(), nt.OptionalHeader.SizeOfHeaders);
            for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
            {
                const auto section = Read<IMAGE_SECTION_HEADER>(raw, dos.e_lfanew + sizeof(nt) + i * sizeof(IMAGE_SECTION_HEADER));
                if (section.PointerToRawData > raw.size() || section.SizeOfRawData > raw.size() - section.PointerToRawData
                    || section.VirtualAddress > image.size() || section.SizeOfRawData > image.size() - section.VirtualAddress)
                    throw std::runtime_error("Invalid section bounds");
                std::memcpy(image.data() + section.VirtualAddress, raw.data() + section.PointerToRawData, section.SizeOfRawData);
            }
            const auto debug = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (debug.Size < 65536 && debug.VirtualAddress <= image.size() && debug.Size <= image.size() - debug.VirtualAddress)
                for (unsigned at = 0; at + sizeof(IMAGE_DEBUG_DIRECTORY) <= debug.Size; at += sizeof(IMAGE_DEBUG_DIRECTORY))
                {
                    const auto e = Read<IMAGE_DEBUG_DIRECTORY>(image, debug.VirtualAddress + at);
                    if (e.Type != IMAGE_DEBUG_TYPE_CODEVIEW || e.SizeOfData < 24) continue;
                    const auto p = e.AddressOfRawData;
                    if (p > image.size() || e.SizeOfData > image.size() - p || Read<DWORD>(image, p) != 0x53445352) continue;
                    const auto guid = Read<GUID>(image, p + 4);
                    wchar_t text[64]{};
                    swprintf_s(text, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", guid.Data1, guid.Data2, guid.Data3,
                        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
                    s << L"udwm_pdb_guid=" << text << L"\r\nudwm_pdb_age=" << Read<DWORD>(image, p + 20) << L"\r\n";
                }
            Resolved resolved{};
            Node node = Node::Count;
            const auto failure = Resolve(image.data(), image.size(), nt.OptionalHeader.ImageBase, resolved, &node);
            d.modelMatched = failure == Failure::None;
            s << L"resolve_failure=" << FailureText(failure) << L"\r\nfailed_node=" << static_cast<unsigned>(node)
              << L"\r\nmodel=" << resolved.model << L"\r\nwindow_list_offset=" << Hex(resolved.windowListOffset)
              << L"\r\nhook_slots=" << resolved.destroySlot << L',' << resolved.zOrderSlot << L',' << resolved.updateSlot << L"\r\n";
            for (unsigned i = 0; i < static_cast<unsigned>(Node::Count); ++i)
                s << L"function_rva_" << i << L'=' << Hex(resolved.functions[i]) << L"\r\n";
            d.summary = L"uDWM " + version + (d.modelMatched ? L"：文件特征匹配通过 / file model matched" : L"：文件特征不支持 / unsupported file model");
            s << L"visual_result=not inferred from file inspection\r\n";
            const auto agent = ExecutableDirectory() / L"KswordDwmZOrder.dll";
            if (std::filesystem::exists(agent)) s << L"agent_sha256=" << Hash(ReadFileBytes(agent)) << L"\r\n";
            else s << L"agent_file=missing\r\n";
            s << L"exe_sha256=" << Hash(ReadFileBytes(ExecutableDirectory() / L"DwmOrderTool.exe")) << L"\r\n";
            d.complete = true;
        }
        catch (const std::exception& e)
        {
            d.summary = L"文件诊断未完成 / inspection incomplete";
            s << L"inspection_error=";
            for (const char* p = e.what(); *p; ++p) s << static_cast<wchar_t>(static_cast<unsigned char>(*p));
            s << L"\r\n";
        }
        s << L"inspection_complete=" << d.complete << L"\r\n";
        d.details = s.str();
        return d;
    }

    std::wstring StatusText(ks::dwm_order::Status status)
    {
        using S = ks::dwm_order::Status;
        switch (status)
        {
        case S::Ok: return L"回执成功 / OK";
        case S::InvalidRequest: return L"请求无效 / Invalid request";
        case S::InvalidWindow: return L"窗口失效或身份变化 / Invalid window";
        case S::DifferentDesktop: return L"窗口不在同一桌面 / Different desktop";
        case S::UnsupportedRuntime: return L"当前 DWM 模型不支持 / Unsupported DWM runtime";
        case S::HookConflict: return L"排序回调冲突 / Hook conflict";
        case S::WindowNotComposed: return L"窗口未参与合成 / Window not composed";
        case S::NativeFailure: return L"内部调用失败，可能部分生效 / Native failure, possibly partial";
        case S::VerificationFailed: return L"回读未通过 / Verification failed";
        case S::NotRunning: return L"代理未运行 / Agent not running";
        case S::AgentMismatch: return L"代理版本不同，请注销后重试 / Agent mismatch; sign out and retry";
        case S::TransportFailure: return L"连接或加载失败 / Transport failure";
        case S::Timeout: return L"超时，结果未知 / Timeout, outcome unknown";
        case S::InternalException: return L"代理异常，结果未知 / Agent exception, outcome unknown";
        }
        return L"未知状态 / Unknown status";
    }

    std::wstring FormatOperation(const Operation& op)
    {
        const auto& r = op.reply.response;
        std::wostringstream s;
        s << L"utc=" << op.time << L"\r\naction=" << static_cast<unsigned>(op.request.action)
          << L"\r\nposition=" << static_cast<unsigned>(op.request.position) << L"\r\nmaintain_requested=" << op.request.maintain
          << L"\r\ntarget_hwnd=" << Hex(op.request.target.hwnd) << L"\r\nreference_hwnd=" << Hex(op.request.reference.hwnd)
          << L"\r\nstatus=" << static_cast<unsigned>(r.status) << L" (" << StatusText(r.status) << L")"
          << L"\r\nstage=" << static_cast<unsigned>(op.reply.stage) << L"\r\ntransport_win32=" << op.reply.error
          << L"\r\nagent_win32=" << r.win32Error << L"\r\nhresult=" << Hex(static_cast<std::uint32_t>(r.nativeResult))
          << L"\r\nloader_completed=" << op.reply.loaderCompleted << L"\r\nloader_thread_exit=" << Hex(op.reply.loaderThreadExitCode)
          << L"\r\nrequest_thread_exit=" << Hex(op.reply.requestThreadExitCode) << L"\r\ndwm_pid=" << r.dwmProcessId
          << L"\r\nflags=" << r.flags << L"\r\nverified=" << !!(r.flags & ks::dwm_order::Verified)
          << L"\r\nfront_index_zero_based=" << r.index << L"\r\nwindow_count=" << r.windowCount
          << L"\r\nband=" << r.band << L"\r\nabove_hwnd=" << Hex(r.previous) << L"\r\nbelow_hwnd=" << Hex(r.next)
          << L"\r\nmaintained_hwnd=" << Hex(r.maintainedWindow) << L"\r\nmaintenance_status=" << static_cast<unsigned>(r.maintenanceStatus) << L"\r\n";
        return s.str();
    }

    std::filesystem::path SaveReport(const std::filesystem::path& parent, const Diagnostic& d,
        const std::vector<Operation>& operations, const std::wstring& observation, const std::wstring& notes, bool includeSystemImage)
    {
        std::filesystem::create_directories(parent);
        auto stamp = Timestamp();
        for (auto& ch : stamp) if (ch == L':') ch = L'-';
        std::filesystem::path output;
        for (unsigned i = 0; i < 1000; ++i)
        {
            output = parent / (L"DwmOrder-report-" + stamp + L"-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(i));
            if (std::filesystem::create_directory(output)) break;
            output.clear();
        }
        if (output.empty()) throw std::runtime_error("Cannot create unique report directory");
        std::wostringstream report;
        report << d.details << L"\r\n[tester]\r\nobservation=" << observation << L"\r\nnotes=" << notes
            << L"\r\n\r\n[operations]\r\ncount=" << operations.size() << L"\r\n";
        for (std::size_t i = 0; i < operations.size(); ++i) report << L"\r\n[operation " << i << L"]\r\n" << FormatOperation(operations[i]);
        WriteText(output / L"report.txt", report.str());
        if (includeSystemImage)
        {
            const auto raw = ReadFileBytes(d.udwm);
            if (d.udwmHash.empty() || Hash(raw) != d.udwmHash) throw std::runtime_error("System image changed; inspect again before exporting");
            std::ofstream f(output / L"uDWM.dll", std::ios::binary);
            f.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
            f.close();
            if (!f) throw std::runtime_error("System image export failed");
        }
        return output;
    }

    int SelfTest(const std::filesystem::path& directory)
    {
        try
        {
            const auto d = Inspect();
            if (!d.complete || d.udwmHash.size() != 64) return 1;
            Operation op{};
            op.time = Timestamp();
            op.reply.response.status = ks::dwm_order::Status::Timeout;
            op.reply.requestThreadExitCode = 0xc0000409;
            const auto first = SaveReport(directory, d, {op}, L"not tested", L"中文报告 / Unicode", false);
            const auto second = SaveReport(directory, d, {}, L"not tested", L"", true);
            const auto report = ReadFileBytes(first / L"report.txt");
            const std::string text(report.begin(), report.end());
            if (first == second || std::filesystem::exists(first / L"uDWM.dll")
                || Hash(ReadFileBytes(second / L"uDWM.dll")) != d.udwmHash
                || text.find("0xc0000409") == std::string::npos
                || text.find(Utf8(L"中文报告")) == std::string::npos) return 2;
            WriteText(directory / L"self-test.txt", L"REPORT_SELF_TEST=PASS\r\nNo DWM injection performed.\r\n");
            return 0;
        }
        catch (...) { return 3; }
    }
}
