#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <io.h>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../shared/KswordArkLogProtocol.h"
#include "../shared/driver/KswordArkAlpcIoctl.h"
#include "../shared/driver/KswordArkCallbackIoctl.h"
#include "../shared/driver/KswordArkCapabilityIoctl.h"
#include "../shared/driver/KswordArkDynDataIoctl.h"
#include "../shared/driver/KswordArkDeviceAuditIoctl.h"
#include "../shared/driver/KswordArkFileIoctl.h"
#include "../shared/driver/KswordArkFileMonitorIoctl.h"
#include "../shared/driver/KswordArkFilterIoctl.h"
#include "../shared/driver/KswordArkHandleIoctl.h"
#include "../shared/driver/KswordArkHwidIoctl.h"
#include "../shared/driver/KswordArkKeyboardIoctl.h"
#include "../shared/driver/KswordArkKernelIoctl.h"
#include "../shared/driver/KswordArkKernelObjectIoctl.h"
#include "../shared/driver/KswordArkMemoryIoctl.h"
#include "../shared/driver/KswordArkMutationIoctl.h"
#include "../shared/driver/KswordArkNetworkIoctl.h"
#include "../shared/driver/KswordArkPreflightIoctl.h"
#include "../shared/driver/KswordArkProcessIoctl.h"
#include "../shared/driver/KswordArkRedirectIoctl.h"
#include "../shared/driver/KswordArkRegistryIoctl.h"
#include "../shared/driver/KswordArkSafetyIoctl.h"
#include "../shared/driver/KswordArkSecurityAuditIoctl.h"
#include "../shared/driver/KswordArkSectionIoctl.h"
#include "../shared/driver/KswordArkStorageIoctl.h"
#include "../shared/driver/KswordArkThreadIoctl.h"
#include "../shared/driver/KswordArkTrustIoctl.h"
#include "../shared/driver/KswordArkWin32kIoctl.h"
#include "../shared/driver/KswordArkWslSiloIoctl.h"
#include "ArkDriverExtended.h"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace
{
    constexpr DWORD kDefaultShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    constexpr DWORD kDefaultDesiredAccess = GENERIC_READ | GENERIC_WRITE;
    constexpr std::size_t kSmallResponseBytes = 64U * 1024U;
    constexpr std::size_t kLargeResponseBytes = 2U * 1024U * 1024U;
    constexpr std::size_t kHugeResponseBytes = 4U * 1024U * 1024U;
    constexpr std::size_t kMaxCommandBytes = 64U * 1024U * 1024U;
    constexpr std::size_t kMaxHexBytes = 256U;

    // IoctlResult mirrors the Win32 DeviceIoControl completion state.
    // Inputs: fields are assigned by sendIoctl after each kernel request.
    // Processing: no ownership is stored here; this is a plain result packet.
    // Returns: no behavior; callers inspect ok, win32Error, and bytesReturned.
    struct IoctlResult
    {
        bool ok = false;
        DWORD win32Error = ERROR_SUCCESS;
        DWORD bytesReturned = 0;
    };

    // DriverHandle owns a Win32 HANDLE returned by CreateFileW.
    // Inputs: constructed from a raw HANDLE or default-invalid state.
    // Processing: closes the handle in reset/destructor and supports moves.
    // Returns: native() exposes the raw handle for Win32 calls without transfer.
    class DriverHandle
    {
    public:
        DriverHandle() noexcept = default;

        explicit DriverHandle(HANDLE handle) noexcept
            : handle_(handle)
        {
        }

        ~DriverHandle()
        {
            reset();
        }

        DriverHandle(const DriverHandle&) = delete;
        DriverHandle& operator=(const DriverHandle&) = delete;

        DriverHandle(DriverHandle&& other) noexcept
            : handle_(other.release())
        {
        }

        DriverHandle& operator=(DriverHandle&& other) noexcept
        {
            if (this != &other)
            {
                reset(other.release());
            }
            return *this;
        }

        bool valid() const noexcept
        {
            return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
        }

        HANDLE native() const noexcept
        {
            return handle_;
        }

        HANDLE release() noexcept
        {
            HANDLE detached = handle_;
            handle_ = INVALID_HANDLE_VALUE;
            return detached;
        }

        void reset(HANDLE next = INVALID_HANDLE_VALUE) noexcept
        {
            if (valid())
            {
                ::CloseHandle(handle_);
            }
            handle_ = next;
        }

    private:
        HANDLE handle_ = INVALID_HANDLE_VALUE;
    };

    struct ParsedOption
    {
        bool present = false;
        std::wstring value;
    };

    struct NamedArgs
    {
        std::vector<std::wstring> positionals;
        std::map<std::wstring, std::wstring> options;
    };

    // Numeric parser forward declarations are needed because option helpers are
    // defined before the concrete parser implementations in this single-file
    // CLI. Inputs are raw argv tokens; return values are unsigned scalars.
    std::uint32_t parseU32(const wchar_t* token, const char* name);
    std::uint64_t parseU64(const wchar_t* token, const char* name);

    // queryCallbackInventory is implemented after the kernel command family in
    // this single translation unit. Inputs are parsed named arguments for the
    // callback inventory command; processing issues the read-only callback
    // enumeration IOCTL; return value is the CLI process exit code.
    int queryCallbackInventory(const NamedArgs& args);

    // printWin32Error renders a failed Win32 operation in a compact form.
    // Inputs: operation describes the API/IOCTL; error is GetLastError output.
    // Processing: prints decimal and hexadecimal forms for quick triage.
    // Returns: no value; output goes to stderr.
    void printWin32Error(const wchar_t* operation, DWORD error)
    {
        std::wcerr << L"error: " << operation << L" failed, win32=" << error
                   << L" (0x" << std::hex << error << std::dec << L")\n";
    }

    // openDriver opens the shared KswordARK control/log device.
    // Inputs: desiredAccess usually includes read/write because some IOCTLs are gated.
    // Processing: calls CreateFileW on the path exported by shared protocol headers.
    // Returns: RAII DriverHandle; caller checks valid() before issuing requests.
    DriverHandle openDriver(DWORD desiredAccess = kDefaultDesiredAccess)
    {
        return DriverHandle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
    }

    // sendIoctl wraps synchronous DeviceIoControl for fixed and variable buffers.
    // Inputs: open handle, control code, optional input and output buffers.
    // Processing: forwards arguments without interpreting protocol contents.
    // Returns: IoctlResult with Win32 success bit, error code, and returned byte count.
    IoctlResult sendIoctl(
        DriverHandle& handle,
        DWORD code,
        void* input,
        DWORD inputBytes,
        void* output,
        DWORD outputBytes)
    {
        IoctlResult result{};
        if (!handle.valid())
        {
            result.ok = false;
            result.win32Error = ERROR_INVALID_HANDLE;
            return result;
        }

        DWORD bytesReturned = 0;
        const BOOL ok = ::DeviceIoControl(
            handle.native(),
            code,
            input,
            inputBytes,
            output,
            outputBytes,
            &bytesReturned,
            nullptr);
        result.ok = (ok != FALSE);
        result.win32Error = result.ok ? ERROR_SUCCESS : ::GetLastError();
        result.bytesReturned = bytesReturned;
        return result;
    }

    // parseNamedArgs collects positional tokens after the command family/subcommand.
    // Inputs: argc/argv plus the start index for first option token.
    // Processing: preserves ordering for positional file/blob paths and flags.
    // Returns: NamedArgs with a positional list; option helpers scan argv directly.
    NamedArgs parseNamedArgs(int argc, wchar_t* argv[], int startIndex)
    {
        NamedArgs args{};
        for (int index = startIndex; index < argc; ++index)
        {
            if (argv[index] == nullptr || argv[index][0] == L'\0')
            {
                continue;
            }

            if (argv[index][0] == L'-')
            {
                if (index + 1 < argc && argv[index + 1] != nullptr && argv[index + 1][0] != L'-')
                {
                    args.options[argv[index]] = argv[index + 1];
                    ++index;
                }
                else
                {
                    args.options[argv[index]] = L"";
                }
                continue;
            }

            args.positionals.emplace_back(argv[index]);
        }
        return args;
    }

    // getOptionText returns a named option value from parsed args.
    // Inputs: option map and key with leading dashes.
    // Processing: caller can use fallback when the option is absent.
    // Returns: pointer to the stable internal string or nullptr.
    const std::wstring* getOptionText(const NamedArgs& args, const wchar_t* key)
    {
        const auto it = args.options.find(key);
        return it == args.options.end() ? nullptr : &it->second;
    }

    // getOptionU32 parses an option value as unsigned 32-bit.
    // Inputs: parsed args, key, and default value.
    // Processing: falls back to default when the switch is absent.
    // Returns: parsed or default value.
    std::uint32_t getOptionU32(const NamedArgs& args, const wchar_t* key, std::uint32_t defaultValue)
    {
        const std::wstring* value = getOptionText(args, key);
        return value == nullptr ? defaultValue : parseU32(value->c_str(), "option");
    }

    // getOptionU64 parses an option value as unsigned 64-bit.
    // Inputs: parsed args, key, and default value.
    // Processing: falls back to default when the switch is absent.
    // Returns: parsed or default value.
    std::uint64_t getOptionU64(const NamedArgs& args, const wchar_t* key, std::uint64_t defaultValue)
    {
        const std::wstring* value = getOptionText(args, key);
        return value == nullptr ? defaultValue : parseU64(value->c_str(), "option");
    }

    // getOptionBool reports whether the option is present.
    // Inputs: parsed args and key.
    // Processing: presence-only flag; no value is consumed.
    // Returns: true when present.
    bool getOptionBool(const NamedArgs& args, const wchar_t* key)
    {
        return args.options.find(key) != args.options.end();
    }

    // requireOptionText fetches a mandatory named option.
    // Inputs: parsed args and key.
    // Processing: throws when the switch is absent.
    // Returns: option value reference.
    const std::wstring& requireOptionText(const NamedArgs& args, const wchar_t* key)
    {
        const std::wstring* value = getOptionText(args, key);
        if (value == nullptr)
        {
            throw std::invalid_argument("missing option");
        }
        return *value;
    }

    // requireOptionU32 parses a mandatory unsigned 32-bit option.
    // Inputs: parsed args and key.
    // Processing: throws when the switch is absent or malformed.
    // Returns: parsed value.
    std::uint32_t requireOptionU32(const NamedArgs& args, const wchar_t* key)
    {
        return parseU32(requireOptionText(args, key).c_str(), "option");
    }

    // requireOptionU64 parses a mandatory unsigned 64-bit option.
    // Inputs: parsed args and key.
    // Processing: throws when the switch is absent or malformed.
    // Returns: parsed value.
    std::uint64_t requireOptionU64(const NamedArgs& args, const wchar_t* key)
    {
        return parseU64(requireOptionText(args, key).c_str(), "option");
    }

    // hasOption reports whether a named switch is present in argv.
    // Inputs: option name includes the leading dashes, for example "--pid".
    // Processing: exact case-sensitive match against the command line.
    // Returns: true when the option exists.
    bool hasOption(int argc, wchar_t* argv[], const wchar_t* option)
    {
        for (int index = 0; index < argc; ++index)
        {
            if (argv[index] != nullptr && std::wcscmp(argv[index], option) == 0)
            {
                return true;
            }
        }
        return false;
    }

    // findOptionValue returns the next token after a named switch.
    // Inputs: argv and option name; if missing, returns nullptr.
    // Processing: scans for exact option match and returns following token.
    // Returns: pointer to the following argument or nullptr.
    const wchar_t* findOptionValue(int argc, wchar_t* argv[], const wchar_t* option)
    {
        for (int index = 0; index + 1 < argc; ++index)
        {
            if (argv[index] != nullptr && std::wcscmp(argv[index], option) == 0)
            {
                return argv[index + 1];
            }
        }
        return nullptr;
    }

    // readFileBytes loads a whole file into memory for blob-style IOCTL inputs.
    // Inputs: path and an upper size bound to reject oversized protocol blobs.
    // Processing: opens the file in binary mode and validates the actual length.
    // Returns: byte vector on success; throws on IO or size violations.
    std::vector<std::uint8_t> readFileBytes(const std::wstring& path, std::size_t maxBytes)
    {
        if (path.empty())
        {
            throw std::invalid_argument("file path");
        }

        HANDLE file = ::CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error("open file");
        }

        LARGE_INTEGER size{};
        if (::GetFileSizeEx(file, &size) == FALSE)
        {
            ::CloseHandle(file);
            throw std::runtime_error("file size");
        }
        if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > maxBytes)
        {
            ::CloseHandle(file);
            throw std::out_of_range("file too large");
        }

        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
        DWORD readBytes = 0;
        if (!bytes.empty())
        {
            if (::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &readBytes, nullptr) == FALSE)
            {
                ::CloseHandle(file);
                throw std::runtime_error("file read");
            }
            bytes.resize(readBytes);
        }
        ::CloseHandle(file);
        return bytes;
    }

    // parseHexBytes accepts either 0x-prefixed numbers or raw hex byte strings.
    // Inputs: text token containing bytes like "DE AD BE EF" or "0x1234".
    // Processing: strips separators and decodes two hex digits per byte.
    // Returns: decoded bytes; throws on malformed input.
    std::vector<std::uint8_t> parseHexBytes(const std::wstring& text)
    {
        std::wstring normalized = text;
        if (normalized.size() >= 2U && normalized[0] == L'0' && (normalized[1] == L'x' || normalized[1] == L'X'))
        {
            normalized.erase(0U, 2U);
        }

        std::wstring cleaned;
        cleaned.reserve(text.size());
        for (wchar_t ch : normalized)
        {
            if (std::iswxdigit(ch))
            {
                cleaned.push_back(static_cast<wchar_t>(std::towupper(ch)));
            }
        }

        if (cleaned.empty())
        {
            return {};
        }
        if ((cleaned.size() % 2U) != 0U)
        {
            throw std::invalid_argument("hex bytes");
        }

        std::vector<std::uint8_t> bytes;
        bytes.reserve(cleaned.size() / 2U);
        for (std::size_t index = 0U; index < cleaned.size(); index += 2U)
        {
            const wchar_t hi = cleaned[index];
            const wchar_t lo = cleaned[index + 1U];
            const auto nibble = [](wchar_t c) -> int {
                if (c >= L'0' && c <= L'9') return static_cast<int>(c - L'0');
                if (c >= L'A' && c <= L'F') return static_cast<int>(10 + (c - L'A'));
                return -1;
            };
            const int hiValue = nibble(hi);
            const int loValue = nibble(lo);
            if (hiValue < 0 || loValue < 0)
            {
                throw std::invalid_argument("hex bytes");
            }
            bytes.push_back(static_cast<std::uint8_t>((hiValue << 4) | loValue));
        }
        return bytes;
    }

    // fixedAnsi copies a fixed char array into std::string safely.
    // Inputs: text points at protocol storage; maxBytes is the field capacity.
    // Processing: scans until NUL or capacity, whichever comes first.
    // Returns: a possibly empty string without embedded protocol padding.
    std::string fixedAnsi(const char* text, std::size_t maxBytes)
    {
        if (text == nullptr || maxBytes == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < maxBytes && text[length] != '\0')
        {
            ++length;
        }
        return std::string(text, text + length);
    }

    // fixedWide copies a fixed wchar_t array into std::wstring safely.
    // Inputs: text points at protocol storage; maxChars is the field capacity.
    // Processing: scans until NUL or capacity, whichever comes first.
    // Returns: a possibly empty wide string without trailing padding.
    std::wstring fixedWide(const wchar_t* text, std::size_t maxChars)
    {
        if (text == nullptr || maxChars == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < maxChars && text[length] != L'\0')
        {
            ++length;
        }
        return std::wstring(text, text + length);
    }

    // ipcSummaryStatusName renders KSWORD_ARK_IPC_SUMMARY_STATUS_* values.
    // Inputs: status is a shared protocol enum returned by query IPC summary.
    // Processing: keeps legacy STUB distinguishable from current unavailable
    // states so acceptance does not confuse old-driver fallback with R0 evidence.
    // Returns: a stable human-readable status label for CLI output.
    const wchar_t* ipcSummaryStatusName(std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_IPC_SUMMARY_STATUS_OK:
            return L"OK";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL:
            return L"Partial";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_STUB:
            return L"LegacyStub";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED:
            return L"Failed";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE:
        default:
            return L"Unavailable";
        }
    }

    // fixedUtf16 copies unsigned-short UTF-16 protocol fields into std::wstring.
    // Inputs: text points at UTF-16 code units; maxChars bounds the scan.
    // Processing: casts code units to wchar_t, matching Windows UTF-16 wchar_t.
    // Returns: a std::wstring suitable for console output on Windows.
    std::wstring fixedUtf16(const unsigned short* text, std::size_t maxChars)
    {
        if (text == nullptr || maxChars == 0U)
        {
            return {};
        }

        std::wstring value;
        for (std::size_t index = 0U; index < maxChars && text[index] != 0U; ++index)
        {
            value.push_back(static_cast<wchar_t>(text[index]));
        }
        return value;
    }

    // copyWideToFixed writes a command-line string into a protocol wchar_t field.
    // Inputs: destination/capacity are the protocol field; source is user text.
    // Processing: truncates to leave room for NUL and clears the destination first.
    // Returns: no value; destination is always NUL terminated when capacity > 0.
    void copyWideToFixed(wchar_t* destination, std::size_t capacity, const std::wstring& source)
    {
        if (destination == nullptr || capacity == 0U)
        {
            return;
        }

        std::fill(destination, destination + capacity, L'\0');
        const std::size_t chars = std::min<std::size_t>(source.size(), capacity - 1U);
        if (chars != 0U)
        {
            std::copy(source.data(), source.data() + chars, destination);
        }
    }

    // parseU32 parses a decimal or 0x-prefixed unsigned 32-bit number.
    // Inputs: token is a command-line argument; name is used in error text.
    // Processing: wcstoull is used so both decimal and hex are accepted.
    // Returns: parsed value, or throws invalid_argument/out_of_range.
    std::uint32_t parseU32(const wchar_t* token, const char* name)
    {
        if (token == nullptr || token[0] == L'\0')
        {
            throw std::invalid_argument(name);
        }

        wchar_t* end = nullptr;
        const unsigned long long value = std::wcstoull(token, &end, 0);
        if (end == token || *end != L'\0')
        {
            throw std::invalid_argument(name);
        }
        if (value > std::numeric_limits<std::uint32_t>::max())
        {
            throw std::out_of_range(name);
        }
        return static_cast<std::uint32_t>(value);
    }

    // parseU64 parses a decimal or 0x-prefixed unsigned 64-bit number.
    // Inputs: token is a command-line argument; name is used in error text.
    // Processing: wcstoull is used to preserve native Windows argument encoding.
    // Returns: parsed value, or throws invalid_argument.
    std::uint64_t parseU64(const wchar_t* token, const char* name)
    {
        if (token == nullptr || token[0] == L'\0')
        {
            throw std::invalid_argument(name);
        }

        wchar_t* end = nullptr;
        const unsigned long long value = std::wcstoull(token, &end, 0);
        if (end == token || *end != L'\0')
        {
            throw std::invalid_argument(name);
        }
        return static_cast<std::uint64_t>(value);
    }

    // parsePidListText converts a delimiter-separated PID list into unique PID values.
    // Inputs: text accepts decimal or 0x-prefixed numbers separated by comma, semicolon, pipe, or whitespace.
    // Processing: PID zero is ignored and duplicates are removed while preserving first-seen order.
    // Returns: normalized PID vector; throws when a token is malformed or the protocol maximum is exceeded.
    std::vector<std::uint32_t> parsePidListText(const std::wstring& text)
    {
        std::vector<std::uint32_t> processIds;
        std::wstring token;

        const auto flushToken = [&]()
        {
            if (token.empty())
            {
                return;
            }

            const std::uint32_t processId = parseU32(token.c_str(), "pid list");
            token.clear();
            if (processId == 0U)
            {
                return;
            }
            if (std::find(processIds.begin(), processIds.end(), processId) != processIds.end())
            {
                return;
            }
            if (processIds.size() >= KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT)
            {
                throw std::out_of_range("too many pids");
            }
            processIds.push_back(processId);
        };

        for (const wchar_t ch : text)
        {
            if (ch == L',' || ch == L';' || ch == L'|' || std::iswspace(ch) != 0)
            {
                flushToken();
                continue;
            }
            token.push_back(ch);
        }
        flushToken();
        return processIds;
    }

    // hex64 formats a 64-bit integer as a fixed-width hexadecimal value.
    // Inputs: value is the integer to render.
    // Processing: uses an isolated stringstream to avoid mutating global cout state.
    // Returns: wide string in 0xNNNN form.
    std::wstring hex64(std::uint64_t value)
    {
        std::wostringstream stream;
        stream << L"0x" << std::hex << std::uppercase << value;
        return stream.str();
    }

    // hexdump prints raw bytes in a stable offset+ASCII layout.
    // Inputs: source bytes and an optional row width.
    // Processing: emits to stdout only; suitable for debugging variable payloads.
    // Returns: no value.
    void hexdump(const std::uint8_t* data, std::size_t size, std::size_t width = 16U)
    {
        if (data == nullptr || size == 0U)
        {
            std::wcout << L"(empty)\n";
            return;
        }

        for (std::size_t offset = 0U; offset < size; offset += width)
        {
            const std::size_t lineBytes = std::min(width, size - offset);
            std::wcout << std::hex << std::setw(8) << std::setfill(L'0') << offset << L": ";
            for (std::size_t index = 0U; index < width; ++index)
            {
                if (index < lineBytes)
                {
                    std::wcout << std::setw(2) << static_cast<unsigned int>(data[offset + index]) << L' ';
                }
                else
                {
                    std::wcout << L"   ";
                }
            }
            std::wcout << L"|";
            for (std::size_t index = 0U; index < lineBytes; ++index)
            {
                const unsigned char ch = data[offset + index];
                std::wcout << (ch >= 32U && ch < 127U ? static_cast<wchar_t>(ch) : L'.');
            }
            std::wcout << L"|\n" << std::dec << std::setfill(L' ');
        }
    }

    // dumpWideText prints a fixed wide string only when it is non-empty.
    // Inputs: label and the decoded wide string.
    // Processing: emits one line in a consistent key/value format.
    // Returns: no value.
    void dumpWideText(const wchar_t* label, const std::wstring& value)
    {
        if (!value.empty())
        {
            std::wcout << L"  " << label << L"='" << value << L"'\n";
        }
    }

    // reportFixedResponse prints the common fixed-response banner.
    // Inputs: protocol version, status value, last status and bytesReturned.
    // Processing: standardizes the fields required by the plan.
    // Returns: no value.
    void reportFixedResponse(std::uint32_t version, std::uint32_t status, long lastStatus, DWORD bytesReturned)
    {
        std::wcout << L"version=" << version
                   << L" status=" << status
                   << L" lastStatus=0x" << std::hex << static_cast<unsigned long>(lastStatus)
                   << L" bytesReturned=" << std::dec << bytesReturned << L"\n";
    }

    // printResponseBanner keeps the older command implementations readable.
    // Inputs: the common version/status/last-status/byte-count tuple.
    // Processing: delegates to the normalized fixed-response printer.
    // Returns: no value; output goes to stdout.
    void printResponseBanner(std::uint32_t version, std::uint32_t status, long lastStatus, DWORD bytesReturned)
    {
        reportFixedResponse(version, status, lastStatus, bytesReturned);
    }

    // reportFixedStatus prints protocol/status fields for read-only fixed responses.
    // Inputs: protocol version, status and lastStatus fields.
    // Processing: leaves bytesReturned handling to the caller when it differs.
    // Returns: no value.
    void reportFixedStatus(std::uint32_t version, std::uint32_t status, long lastStatus)
    {
        std::wcout << L"version=" << version
                   << L" status=" << status
                   << L" lastStatus=0x" << std::hex << static_cast<unsigned long>(lastStatus)
                   << std::dec << L"\n";
    }

    // responseCountLimit bounds user-visible row printing.
    // Inputs: reported count, available count and CLI limit.
    // Processing: chooses the smallest count to keep parsing within buffer.
    // Returns: bounded count.
    std::size_t responseCountLimit(std::size_t reported, std::size_t available, std::size_t limit)
    {
        return std::min({ reported, available, limit });
    }

    // currentUtc100ns returns the current UTC FILETIME tick count.
    // Inputs: none.
    // Processing: converts GetSystemTimePreciseAsFileTime into a 64-bit scalar.
    // Returns: UTC time in 100ns units.
    std::uint64_t currentUtc100ns()
    {
        FILETIME fileTime{};
        ::GetSystemTimePreciseAsFileTime(&fileTime);
        ULARGE_INTEGER value{};
        value.HighPart = fileTime.dwHighDateTime;
        value.LowPart = fileTime.dwLowDateTime;
        return static_cast<std::uint64_t>(value.QuadPart);
    }

    // formatGuid128 renders the callback GUID packet in the same shape as UI code.
    // Inputs: fixed 16-byte GUID packet.
    // Processing: prints uppercase hexadecimal with 8-4-4-4-12 grouping.
    // Returns: formatted GUID text.
    std::wstring formatGuid128(const KSWORD_ARK_GUID128& guid)
    {
        std::wostringstream stream;
        const unsigned char* bytes = guid.bytes;
        stream << std::hex << std::uppercase << std::setfill(L'0')
               << std::setw(2) << static_cast<unsigned int>(bytes[0])
               << std::setw(2) << static_cast<unsigned int>(bytes[1])
               << std::setw(2) << static_cast<unsigned int>(bytes[2])
               << std::setw(2) << static_cast<unsigned int>(bytes[3]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[4])
               << std::setw(2) << static_cast<unsigned int>(bytes[5]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[6])
               << std::setw(2) << static_cast<unsigned int>(bytes[7]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[8])
               << std::setw(2) << static_cast<unsigned int>(bytes[9]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[10])
               << std::setw(2) << static_cast<unsigned int>(bytes[11])
               << std::setw(2) << static_cast<unsigned int>(bytes[12])
               << std::setw(2) << static_cast<unsigned int>(bytes[13])
               << std::setw(2) << static_cast<unsigned int>(bytes[14])
               << std::setw(2) << static_cast<unsigned int>(bytes[15]);
        return stream.str();
    }

    // parseGuid128 decodes a 32-hex-digit callback GUID string.
    // Inputs: GUID text with or without dashes.
    // Processing: strips separators and decodes byte pairs in order.
    // Returns: GUID packet or throws on malformed text.
    KSWORD_ARK_GUID128 parseGuid128(const std::wstring& text)
    {
        const std::vector<std::uint8_t> bytes = parseHexBytes(text);
        if (bytes.size() != 16U)
        {
            throw std::invalid_argument("guid");
        }

        KSWORD_ARK_GUID128 guid{};
        std::memcpy(guid.bytes, bytes.data(), 16U);
        return guid;
    }

    // loadBytesFromHexOrFile loads write payload bytes from --hex or --data-file.
    // Inputs: parsed args and the option names to consult.
    // Processing: enforces maxBytes and optional mandatory payload presence.
    // Returns: decoded bytes or throws on invalid/missing combinations.
    std::vector<std::uint8_t> loadBytesFromHexOrFile(
        const NamedArgs& args,
        const wchar_t* hexKey,
        const wchar_t* fileKey,
        std::size_t maxBytes,
        bool required)
    {
        const std::wstring* hexText = getOptionText(args, hexKey);
        const std::wstring* fileText = getOptionText(args, fileKey);
        if (hexText != nullptr && fileText != nullptr)
        {
            throw std::invalid_argument("mutually exclusive payload");
        }
        if (hexText == nullptr && fileText == nullptr)
        {
            if (required)
            {
                throw std::invalid_argument("payload");
            }
            return {};
        }

        std::vector<std::uint8_t> bytes =
            (hexText != nullptr) ? parseHexBytes(*hexText) : readFileBytes(*fileText, maxBytes);
        if (bytes.size() > maxBytes)
        {
            throw std::out_of_range("payload too large");
        }
        return bytes;
    }

    // openDriverOrReport opens the shared control device and emits a uniform error.
    // Inputs: desired access for the pending IOCTL.
    // Processing: caller receives a possibly-invalid handle and may stop on failure.
    // Returns: DriverHandle RAII wrapper.
    DriverHandle openDriverOrReport(DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriver(desiredAccess);
        if (!handle.valid())
        {
            printWin32Error(L"CreateFileW(" KSWORD_ARK_LOG_WIN32_PATH L")", ::GetLastError());
        }
        return handle;
    }

    // runNoOutputIoctl issues a control code whose success is mostly transport-level.
    // Inputs: control code and optional request buffer.
    // Processing: prints bytesReturned and Win32 completion information.
    // Returns: CLI exit code.
    int runNoOutputIoctl(
        const wchar_t* label,
        DWORD code,
        void* input,
        DWORD inputBytes,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.valid())
        {
            return 2;
        }

        IoctlResult io = sendIoctl(handle, code, input, inputBytes, nullptr, 0U);
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return 3;
        }

        std::wcout << L"bytesReturned=" << io.bytesReturned
                   << L" win32Error=" << io.win32Error << L"\n";
        return 0;
    }

    // printSimpleProcessEntry renders one process row with the most useful stable fields.
    // Inputs: shared process entry from a variable response.
    // Processing: prints IDs, field flags, object pointers and decoded names.
    // Returns: no value.
    void printSimpleProcessEntry(const KSWORD_ARK_PROCESS_ENTRY& entry)
    {
        std::wcout << L"  pid=" << entry.processId
                   << L" ppid=" << entry.parentProcessId
                   << L" flags=0x" << std::hex << entry.flags
                   << L" fieldFlags=0x" << entry.fieldFlags
                   << L" r0Status=" << std::dec << entry.r0Status
                   << L" image='" << fixedAnsi(entry.imageName, sizeof(entry.imageName)).c_str() << L"'\n";
        const std::wstring imagePath = fixedUtf16(entry.imagePath, KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS);
        dumpWideText(L"imagePath", imagePath);
    }

    // printSimpleThreadEntry renders one thread row with cross-view relevant fields.
    // Inputs: shared thread entry.
    // Processing: prints ID, flags, stack info availability and counter sources.
    // Returns: no value.
    void printSimpleThreadEntry(const KSWORD_ARK_THREAD_ENTRY& entry)
    {
        std::wcout << L"  tid=" << entry.threadId
                   << L" pid=" << entry.processId
                   << L" flags=0x" << std::hex << entry.flags
                   << L" fieldFlags=0x" << entry.fieldFlags
                   << L" r0Status=" << std::dec << entry.r0Status
                   << L" stackBase=" << hex64(entry.stackBase)
                   << L" kernelStack=" << hex64(entry.kernelStack) << L"\n";
    }

    template <typename TResponse>
    bool sendFixedNoInput(
        DWORD code,
        const wchar_t* label,
        TResponse& response,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.valid())
        {
            io.win32Error = ::GetLastError();
            return false;
        }

        io = sendIoctl(handle, code, nullptr, 0U, &response, static_cast<DWORD>(sizeof(response)));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return false;
        }
        if (io.bytesReturned < sizeof(response))
        {
            std::wcerr << L"error: " << label << L" response too small: " << io.bytesReturned << L" bytes\n";
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            return false;
        }
        return true;
    }

    template <typename TRequest, typename TResponse>
    bool sendFixedRequestResponse(
        DWORD code,
        const wchar_t* label,
        const TRequest& request,
        TResponse& response,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.valid())
        {
            io.win32Error = ::GetLastError();
            return false;
        }

        io = sendIoctl(
            handle,
            code,
            const_cast<TRequest*>(&request),
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return false;
        }
        if (io.bytesReturned < sizeof(response))
        {
            std::wcerr << L"error: " << label << L" response too small: " << io.bytesReturned << L" bytes\n";
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            return false;
        }
        return true;
    }




    // copyBytesToFixed copies a byte vector into a fixed protocol array.
    // Inputs: destination array, destination capacity, and source bytes.
    // Processing: zero-fills destination and copies at most capacity bytes.
    // Returns: no value; destination remains deterministic for METHOD_BUFFERED.
    void copyBytesToFixed(unsigned char* destination, std::size_t capacity, const std::vector<std::uint8_t>& source)
    {
        if (destination == nullptr || capacity == 0U)
        {
            return;
        }
        std::fill(destination, destination + capacity, 0U);
        const std::size_t copyBytes = std::min<std::size_t>(capacity, source.size());
        if (copyBytes != 0U)
        {
            std::copy(source.begin(), source.begin() + static_cast<std::ptrdiff_t>(copyBytes), destination);
        }
    }

    // checkedDwordSize converts vector sizes into Win32 DWORD byte counts.
    // Inputs: byte count in size_t.
    // Processing: rejects values that DeviceIoControl cannot represent.
    // Returns: DWORD byte count.
    DWORD checkedDwordSize(std::size_t bytes)
    {
        if (bytes > std::numeric_limits<DWORD>::max())
        {
            throw std::out_of_range("buffer too large");
        }
        return static_cast<DWORD>(bytes);
    }

    // boundedPathLength validates a fixed WCHAR path protocol field.
    // Inputs: command line path and target field capacity including terminator.
    // Processing: rejects empty or over-capacity paths before copying.
    // Returns: character length excluding NUL.
    unsigned short boundedPathLength(const std::wstring& pathText, std::size_t capacity)
    {
        if (pathText.empty() || pathText.size() >= capacity)
        {
            throw std::out_of_range("path length");
        }
        return static_cast<unsigned short>(pathText.size());
    }

    // sendRawIoctl opens the driver and performs one synchronous IOCTL call.
    // Inputs: label/code, optional input buffer, output buffer vector and access.
    // Processing: handles CreateFile/DeviceIoControl transport errors uniformly.
    // Returns: CLI-style exit code; io/output receive raw completion data.
    int sendRawIoctl(
        const wchar_t* label,
        DWORD code,
        void* input,
        DWORD inputBytes,
        std::vector<std::uint8_t>& output,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.valid())
        {
            return 2;
        }
        io = sendIoctl(
            handle,
            code,
            input,
            inputBytes,
            output.empty() ? nullptr : output.data(),
            checkedDwordSize(output.size()));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return 3;
        }
        return 0;
    }

    // FamilyHelp describes one top-level command family for overview output.
    // Inputs: name is argv[1] and summary is human-readable help text.
    // Processing: entries are static metadata used only by help rendering.
    // Returns: no behavior; callers read fields directly.
    struct FamilyHelp
    {
        const wchar_t* name;
        const wchar_t* summary;
    };

    // CommandHelp describes one concrete command or alias accepted by dispatch.
    // Inputs: family/subcommand identify argv tokens; syntax/options/notes are display text.
    // Processing: help lookup matches tokens exactly and never opens the driver.
    // Returns: no behavior; callers read fields directly.
    struct CommandHelp
    {
        const wchar_t* family;
        const wchar_t* subcommand;
        const wchar_t* syntax;
        const wchar_t* summary;
        const wchar_t* options;
        const wchar_t* notes;
    };

    constexpr FamilyHelp kFamilyHelps[] = {
        { L"log", L"Read bounded frames from the KswordARK log device." },
        { L"process", L"Inspect and control process visibility, PPL, DKOM, and cross-view state." },
        { L"memory", L"Query, read, write, translate, and audit virtual/physical memory." },
        { L"file", L"Inspect files, filters, storage evidence, and file-monitor runtime state." },
        { L"kernel", L"Inspect SSDT, hooks, driver objects, CPU, physical layout, CID, and IPC state." },
        { L"callback", L"Manage callback rules, pending decisions, callback inventory, and bypass PIDs." },
        { L"dyn", L"Query or apply dynamic kernel symbol/profile data." },
        { L"thread", L"Enumerate threads and compare R0/R3 thread evidence." },
        { L"handle", L"Enumerate process handles and inspect object metadata." },
        { L"driver", L"Driver integrity, device stack, and optional global evidence aliases." },
        { L"hardware", L"Device, input, USB, and PnP stack audit views." },
        { L"hwid", L"HWID Dispatch query and guarded control operations." },
        { L"window", L"Win32k, GUI, GPU, display, and watchdog audit views." },
        { L"misc", L"Security, CI/VBS, Hyper-V, AppLocker/BAM, and driver trust posture." },
        { L"alpc", L"ALPC port diagnostics for a process handle." },
        { L"section", L"Process and file section mapping diagnostics." },
        { L"trust", L"Image trust and signing diagnostics." },
        { L"safety", L"Safety policy query and update controls." },
        { L"preflight", L"Release-readiness and driver capability preflight checks." },
        { L"registry", L"Registry read, enumeration, and mutation helpers." },
        { L"redirect", L"File/registry redirect rules and runtime status." },
        { L"network", L"Network rules, endpoints, WFP/NDIS evidence, and R3 fallbacks." },
        { L"keyboard", L"Keyboard hotkey and hook inventory." },
        { L"mutation", L"Prepare, commit, rollback, and audit bounded mutation transactions." },
        { L"capability", L"Unified driver feature capability query." },
        { L"wsl", L"WSL silo and Linux PID/TID diagnostics." },
        { L"r0", L"Desktop-parity R0 forensic queries and bounded evidence reads." },
    };

    constexpr CommandHelp kCommandHelps[] = {
        { L"log", L"", L"KswordCLI.exe log [--max-frames N]", L"Read up to N log frames from the shared log device.", L"--max-frames defaults to 64.", L"No subcommand is used for the log family." },
        { L"process", L"terminate", L"KswordCLI.exe process terminate --pid PID [--exit-status NTSTATUS]", L"Terminate one process through the driver.", L"Required: --pid. Optional: --exit-status defaults to 0xC000013A.", L"" },
        { L"process", L"suspend", L"KswordCLI.exe process suspend --pid PID", L"Suspend one process.", L"Required: --pid.", L"" },
        { L"process", L"set-ppl", L"KswordCLI.exe process set-ppl --pid PID --level LEVEL", L"Set the process protection level byte.", L"Required: --pid, --level.", L"" },
        { L"process", L"set-integrity", L"KswordCLI.exe process set-integrity --pid PID (--rid RID | --level untrusted|low|medium|medium-plus|high|system) [--flags 0xN] [--confirm]", L"Set a process mandatory integrity label through R0.", L"Required: --pid and one integrity selector. Optional: --flags, --confirm adds UI-confirmed protocol bit.", L"Backed by IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY." },
        { L"process", L"inject-dll", L"KswordCLI.exe process inject-dll --pid PID --dll PATH [--flags 0xN] [--wait-thread] --confirm", L"Inject a DLL path through the R0 process injection protocol.", L"Required: --pid, --dll, --confirm. Optional: --flags overrides request flags; --wait-thread adds wait flag.", L"Backed by IOCTL_KSWORD_ARK_INJECT_PROCESS with LoadLibraryW entrypoint." },
        { L"process", L"inject-shellcode", L"KswordCLI.exe process inject-shellcode --pid PID --blob PATH [--flags 0xN] --confirm", L"Inject a raw shellcode blob through the R0 process injection protocol.", L"Required: --pid, --blob, --confirm. Optional: --flags overrides request flags.", L"Payload is capped by KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES." },
        { L"process", L"enum", L"KswordCLI.exe process enum [--flags 0xN] [--start-pid PID] [--end-pid PID] [--limit N]", L"Enumerate processes from R0 evidence.", L"Optional: --flags, --start-pid, --end-pid, --limit.", L"" },
        { L"process", L"set-visibility", L"KswordCLI.exe process set-visibility --action ACTION [--pid PID] [--flags 0xN]", L"Apply a process visibility action.", L"Required: --action. Optional: --pid defaults to 0, --flags.", L"" },
        { L"process", L"set-special-flags", L"KswordCLI.exe process set-special-flags --pid PID --action ACTION [--flags 0xN]", L"Apply special process flags.", L"Required: --pid, --action. Optional: --flags.", L"" },
        { L"process", L"dkom", L"KswordCLI.exe process dkom --pid PID [--action ACTION] [--flags 0xN]", L"Run the configured process DKOM action.", L"Required: --pid. Optional: --action, --flags.", L"" },
        { L"process", L"crossview", L"KswordCLI.exe process crossview [--flags 0xN] [--start-pid PID] [--end-pid PID] [--max-nodes N] [--limit N]", L"Compare process evidence across supported sources.", L"Optional: --flags, --start-pid, --end-pid, --max-nodes, --limit.", L"" },
        { L"process", L"detail", L"KswordCLI.exe process detail --pid PID [--flags 0xN]", L"Query fixed R0 process runtime detail.", L"Required: --pid. Optional: --flags defaults to include-all.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL." },
        { L"process", L"runtime-fields", L"KswordCLI.exe process runtime-fields --pid PID --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump]", L"Sample bounded EPROCESS runtime fields by checked offsets.", L"Required: --pid, --items. Optional: --flags, --hexdump.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS; each item is bounded by KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES." },
        { L"memory", L"query-va", L"KswordCLI.exe memory query-va --pid PID --address VA [--flags 0xN]", L"Query virtual memory metadata for one address.", L"Required: --pid, --address. Optional: --flags.", L"" },
        { L"memory", L"read-va", L"KswordCLI.exe memory read-va --pid PID --address VA --bytes N [--flags 0xN] [--hexdump]", L"Read virtual memory bytes.", L"Required: --pid, --address, --bytes. Optional: --flags, --hexdump.", L"With the kernel-address read flag, --pid may be omitted." },
        { L"memory", L"write-va", L"KswordCLI.exe memory write-va --pid PID --address VA (--hex HEX | --data-file PATH) [--flags 0xN]", L"Write virtual memory bytes.", L"Required: --pid, --address, and exactly one payload option. Optional: --flags.", L"With the kernel-address write flag, --pid may be omitted." },
        { L"memory", L"read-phys", L"KswordCLI.exe memory read-phys --address PA --bytes N [--hexdump]", L"Read physical memory bytes.", L"Required: --address, --bytes. Optional: --hexdump.", L"" },
        { L"memory", L"write-phys", L"KswordCLI.exe memory write-phys --address PA (--hex HEX | --data-file PATH) [--flags 0xN]", L"Write physical memory bytes.", L"Required: --address and exactly one payload option. Optional: --flags.", L"" },
        { L"memory", L"translate-va", L"KswordCLI.exe memory translate-va --pid PID --address VA [--flags 0xN]", L"Translate a virtual address to page-table evidence.", L"Required: --pid, --address. Optional: --flags.", L"" },
        { L"memory", L"query-pte", L"KswordCLI.exe memory query-pte --pid PID --address VA [--flags 0xN]", L"Query page-table entries for one virtual address.", L"Required: --pid, --address. Optional: --flags.", L"" },
        { L"memory", L"scan-kexec", L"KswordCLI.exe memory scan-kexec [--flags 0xN] [--max-entries N] [--start VA] [--end VA] [--limit N]", L"Scan executable kernel memory evidence.", L"Optional: --flags, --max-entries, --start, --end, --limit.", L"" },
        { L"memory", L"scan-evidence", L"KswordCLI.exe memory scan-evidence [--flags 0xN] [--max-rows N] [--start VA] [--end VA] [--max-bytes N] [--max-bigpool-rows N] [--sample-bytes N] [--limit N]", L"Scan kernel memory evidence rows.", L"Optional: --flags, --max-rows, --start, --end, --max-bytes, --max-bigpool-rows, --sample-bytes, --limit.", L"" },
        { L"file", L"delete-path", L"KswordCLI.exe file delete-path --path PATH [--flags 0xN]", L"Delete one path through the driver.", L"Required: --path. Optional: --flags.", L"" },
        { L"file", L"query-info", L"KswordCLI.exe file query-info --path PATH [--flags 0xN]", L"Query file object and basic file metadata.", L"Required: --path. Optional: --flags.", L"" },
        { L"file", L"set-integrity", L"KswordCLI.exe file set-integrity --path PATH (--rid RID | --level untrusted|low|medium|medium-plus|high|system) [--directory] [--flags 0xN] [--confirm]", L"Set a file or directory mandatory integrity label through R0.", L"Required: --path and one integrity selector. Optional: --directory, --flags, --confirm adds UI-confirmed protocol bit.", L"Win32/UNC paths are normalized to the driver NT path convention before IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY." },
        { L"file", L"fileobject", L"KswordCLI.exe file fileobject --path PATH [--flags 0xN]", L"Alias for file query-info.", L"Required: --path. Optional: --flags.", L"Prints an alias banner before query-info output." },
        { L"file", L"minifilter", L"KswordCLI.exe file minifilter [--flags 0xN] [--max-rows N] [--limit N]", L"Enumerate minifilter inventory rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"file", L"section", L"KswordCLI.exe file section", L"Report that the file section alias is unsupported.", L"No options.", L"Use section query-file-mappings --path PATH for the implemented section protocol." },
        { L"file", L"bitlocker", L"KswordCLI.exe file bitlocker [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query BitLocker/FVE storage audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"storage", L"KswordCLI.exe file storage [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query volume stack audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"mountmgr", L"KswordCLI.exe file mountmgr [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query MountMgr mapping audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"filesystem", L"KswordCLI.exe file filesystem [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query filesystem integrity audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"monitor-control", L"KswordCLI.exe file monitor-control --action ACTION [--operation-mask 0xN] [--pid PID] [--flags 0xN]", L"Control file monitor runtime state.", L"Required: --action. Optional: --operation-mask, --pid, --flags.", L"" },
        { L"file", L"monitor-drain", L"KswordCLI.exe file monitor-drain [--max-events N] [--flags 0xN]", L"Drain file monitor events.", L"Optional: --max-events, --flags.", L"" },
        { L"file", L"monitor-status", L"KswordCLI.exe file monitor-status", L"Query file monitor runtime status.", L"No options.", L"" },
        { L"kernel", L"ssdt", L"KswordCLI.exe kernel ssdt [--flags 0xN] [--limit N]", L"Enumerate SSDT entries.", L"Optional: --flags, --limit.", L"" },
        { L"kernel", L"shadow-ssdt", L"KswordCLI.exe kernel shadow-ssdt [--flags 0xN] [--limit N]", L"Enumerate shadow SSDT entries.", L"Optional: --flags, --limit.", L"" },
        { L"kernel", L"scan-inline-hooks", L"KswordCLI.exe kernel scan-inline-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]", L"Scan inline hook evidence.", L"Optional: --flags, --max-entries, --module, --limit.", L"" },
        { L"kernel", L"enum-iat-eat-hooks", L"KswordCLI.exe kernel enum-iat-eat-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]", L"Enumerate IAT/EAT hook evidence.", L"Optional: --flags, --max-entries, --module, --limit.", L"" },
        { L"kernel", L"patch-inline-hook", L"KswordCLI.exe kernel patch-inline-hook --mode MODE --function VA (--expected-hex HEX | --expected-file PATH) [--restore-hex HEX | --restore-file PATH] [--flags 0xN]", L"Patch or restore an inline hook using bounded byte evidence.", L"Required: --mode, --function, and expected payload. Optional: restore payload, --flags.", L"Hex and file payload forms are mutually exclusive per payload." },
        { L"kernel", L"query-driver-object", L"KswordCLI.exe kernel query-driver-object --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]", L"Query one DriverObject and device chain.", L"Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit.", L"" },
        { L"kernel", L"query-driver-integrity", L"KswordCLI.exe kernel query-driver-integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]", L"Query driver integrity evidence rows.", L"Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit.", L"" },
        { L"kernel", L"force-unload-driver", L"KswordCLI.exe kernel force-unload-driver --driver NAME [--module-base VA] [--timeout-ms N] [--flags 0xN]", L"Force an unload path for one driver.", L"Required: --driver. Optional: --module-base, --timeout-ms, --flags.", L"" },
        { L"kernel", L"query-cpu", L"KswordCLI.exe kernel query-cpu", L"Query CPU hardware summary.", L"No options.", L"" },
        { L"kernel", L"query-phys-layout", L"KswordCLI.exe kernel query-phys-layout", L"Query physical memory layout summary.", L"No options.", L"" },
        { L"kernel", L"cid", L"KswordCLI.exe kernel cid [--flags 0xN] [--max-entries N] [--max-visits N] [--start-cid CID] [--end-cid CID] [--limit N]", L"Enumerate CID table evidence.", L"Optional: --flags, --max-entries, --max-visits, --start-cid, --end-cid, --limit.", L"" },
        { L"kernel", L"object-summary", L"KswordCLI.exe kernel object-summary --target-kind KIND [--cid CID] [--object ADDRESS] [--flags 0xN]", L"Query object header/type/counter summary for CID or object evidence.", L"Required: --target-kind. Optional: --cid, --object, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY." },
        { L"kernel", L"ipc", L"KswordCLI.exe kernel ipc [--flags 0xN] [--pid PID] [--handle HANDLE] [--max-entries N]", L"Query IPC summary for a process/handle context.", L"Optional: --flags, --pid, --handle, --max-entries.", L"" },
        { L"kernel", L"callbacks", L"KswordCLI.exe kernel callbacks [--flags 0xN] [--max-entries N] [--limit N]", L"Alias for callback inventory.", L"Optional: --flags, --max-entries, --limit.", L"" },
        { L"kernel", L"hooks", L"KswordCLI.exe kernel hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]", L"Alias-style inline hook scan.", L"Optional: --flags, --max-entries, --module, --limit.", L"" },
        { L"callback", L"set-rules", L"KswordCLI.exe callback set-rules --blob PATH", L"Load callback rule bytes.", L"Required: --blob.", L"" },
        { L"callback", L"runtime-state", L"KswordCLI.exe callback runtime-state", L"Query callback runtime state.", L"No options.", L"" },
        { L"callback", L"monitor-start", L"KswordCLI.exe callback monitor-start [--categories LIST]", L"Start callback monitor capture with named categories.", L"Optional: --categories process,thread,image,registry,object,minifilter,core,all; defaults to core.", L"IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL; minifilter is high frequency and is not in core." },
        { L"callback", L"monitor-stop", L"KswordCLI.exe callback monitor-stop", L"Stop callback monitor capture without changing existing callback rules.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL." },
        { L"callback", L"monitor-status", L"KswordCLI.exe callback monitor-status", L"Query callback monitor capture state and ring counters.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY." },
        { L"callback", L"monitor-read", L"KswordCLI.exe callback monitor-read [--after-sequence N] [--max-records N] [--limit N]", L"Read callback monitor records through an independent cursor.", L"Optional: --after-sequence, --max-records, --limit.", L"Backed by IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ; use next_sequence for the next read." },
        { L"callback", L"wait-event", L"KswordCLI.exe callback wait-event [--waiter-tag N]", L"Wait for one callback event packet.", L"Optional: --waiter-tag.", L"" },
        { L"callback", L"answer-event", L"KswordCLI.exe callback answer-event --event-guid GUID --decision N --source-session-id N [--answered-at UTC100NS]", L"Answer one pending callback event.", L"Required: --event-guid, --decision, --source-session-id. Optional: --answered-at.", L"" },
        { L"callback", L"cancel-pending", L"KswordCLI.exe callback cancel-pending", L"Cancel all pending callback decisions.", L"No options.", L"" },
        { L"callback", L"remove", L"KswordCLI.exe callback remove --class N --callback VA [--flags 0xN]", L"Remove an external callback by class/address.", L"Required: --class, --callback. Optional: --flags.", L"" },
        { L"callback", L"remove-ex", L"KswordCLI.exe callback remove-ex --class N --callback VA [--registration VA] [--raw-storage VA] [--generation N] [--identity-hash N] [--source N] [--operation-mask 0xN] [--object-type-mask 0xN] [--trust-flags 0xN] [--remove-behavior N] [--flags 0xN]", L"Remove an external callback with extended identity hints.", L"Required: --class, --callback. Optional: extended identity, source, masks, trust, behavior, --flags.", L"" },
        { L"callback", L"set-minifilter-bypass-pids", L"KswordCLI.exe callback set-minifilter-bypass-pids --pids PID[,PID...] [--flags 0xN]", L"Set minifilter bypass PID list.", L"Required: --pids. Optional: --flags.", L"" },
        { L"callback", L"query-minifilter-bypass-pids", L"KswordCLI.exe callback query-minifilter-bypass-pids", L"Query minifilter bypass PID list.", L"No options.", L"" },
        { L"callback", L"enum", L"KswordCLI.exe callback enum [--flags 0xN] [--max-entries N] [--limit N]", L"Enumerate callback inventory.", L"Optional: --flags, --max-entries, --limit.", L"" },
        { L"dyn", L"status", L"KswordCLI.exe dyn status", L"Query DynData status.", L"No options.", L"" },
        { L"dyn", L"fields", L"KswordCLI.exe dyn fields [--limit N]", L"List DynData fields.", L"Optional: --limit.", L"" },
        { L"dyn", L"capabilities", L"KswordCLI.exe dyn capabilities", L"Query DynData capability mask.", L"No options.", L"" },
        { L"dyn", L"profile", L"KswordCLI.exe dyn profile [--limit N]", L"List v4 DynData module profile rows.", L"Optional: --limit.", L"Alias: dyn v4-modules." },
        { L"dyn", L"v4-modules", L"KswordCLI.exe dyn v4-modules [--limit N]", L"List v4 DynData module profile rows.", L"Optional: --limit.", L"Alias: dyn profile." },
        { L"dyn", L"v4-capabilities", L"KswordCLI.exe dyn v4-capabilities [--limit N]", L"List v4 DynData capability groups.", L"Optional: --limit.", L"Alias: dyn capability-groups." },
        { L"dyn", L"capability-groups", L"KswordCLI.exe dyn capability-groups [--limit N]", L"List v4 DynData capability groups.", L"Optional: --limit.", L"Alias: dyn v4-capabilities." },
        { L"dyn", L"v4-missing", L"KswordCLI.exe dyn v4-missing [--limit N]", L"List missing v4 DynData items.", L"Optional: --limit.", L"Alias: dyn missing-items." },
        { L"dyn", L"missing-items", L"KswordCLI.exe dyn missing-items [--limit N]", L"List missing v4 DynData items.", L"Optional: --limit.", L"Alias: dyn v4-missing." },
        { L"dyn", L"v4-items", L"KswordCLI.exe dyn v4-items [--limit N]", L"List every v4 DynData item status row.", L"Optional: --limit.", L"Backed by IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS." },
        { L"dyn", L"apply-profile-v4", L"KswordCLI.exe dyn apply-profile-v4 --blob PATH", L"Apply a raw v4 DynData profile packet.", L"Required: --blob.", L"" },
        { L"dyn", L"apply-profile", L"KswordCLI.exe dyn apply-profile --blob PATH", L"Apply a raw legacy DynData profile packet.", L"Required: --blob.", L"" },
        { L"dyn", L"apply-profile-ex", L"KswordCLI.exe dyn apply-profile-ex --blob PATH", L"Apply a raw extended DynData profile packet.", L"Required: --blob.", L"" },
        { L"capability", L"query-driver-capabilities", L"KswordCLI.exe capability query-driver-capabilities [--limit N]", L"Query unified driver feature capability rows.", L"Optional: --limit.", L"" },
        { L"thread", L"enum", L"KswordCLI.exe thread enum [--flags 0xN] [--pid PID] [--limit N]", L"Enumerate threads.", L"Optional: --flags, --pid, --limit.", L"" },
        { L"thread", L"crossview", L"KswordCLI.exe thread crossview [--flags 0xN] [--pid PID] [--start-tid TID] [--end-tid TID] [--max-nodes N] [--limit N]", L"Compare thread evidence across supported sources.", L"Optional: --flags, --pid, --start-tid, --end-tid, --max-nodes, --limit.", L"" },
        { L"thread", L"detail", L"KswordCLI.exe thread detail --tid TID [--pid PID] [--flags 0xN]", L"Query fixed R0 ETHREAD/KTHREAD runtime detail.", L"Required: --tid. Optional: --pid, --flags defaults to include-all.", L"Backed by IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL." },
        { L"thread", L"runtime-fields", L"KswordCLI.exe thread runtime-fields --tid TID [--pid PID] --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump]", L"Sample bounded ETHREAD/KTHREAD runtime fields by checked offsets.", L"Required: --tid, --items. Optional: --pid, --flags, --hexdump.", L"Backed by IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS; each item is bounded by KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES." },
        { L"handle", L"enum", L"KswordCLI.exe handle enum --pid PID [--flags 0xN] [--limit N]", L"Enumerate handles in one process.", L"Required: --pid. Optional: --flags, --limit.", L"Alias: handle object-table." },
        { L"handle", L"object-table", L"KswordCLI.exe handle object-table --pid PID [--flags 0xN] [--limit N]", L"Enumerate handles in one process.", L"Required: --pid. Optional: --flags, --limit.", L"Alias: handle enum." },
        { L"handle", L"query-object", L"KswordCLI.exe handle query-object --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]", L"Query one handle object.", L"Required: --pid, --handle. Optional: --access, --flags.", L"Aliases: handle object-header, handle type-matrix." },
        { L"handle", L"object-header", L"KswordCLI.exe handle object-header --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]", L"Query one handle object header projection.", L"Required: --pid, --handle. Optional: --access, --flags.", L"Alias: handle query-object." },
        { L"handle", L"type-matrix", L"KswordCLI.exe handle type-matrix --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]", L"Query one handle object type projection.", L"Required: --pid, --handle. Optional: --access, --flags.", L"Alias: handle query-object." },
        { L"alpc", L"query-port", L"KswordCLI.exe alpc query-port --pid PID --handle HANDLE [--flags 0xN]", L"Query ALPC port information for one handle.", L"Required: --pid, --handle. Optional: --flags.", L"" },
        { L"section", L"query-process", L"KswordCLI.exe section query-process --pid PID [--flags 0xN] [--max-mappings N] [--limit N]", L"Query section mappings for one process.", L"Required: --pid. Optional: --flags, --max-mappings, --limit.", L"" },
        { L"section", L"query-file-mappings", L"KswordCLI.exe section query-file-mappings --path PATH [--flags 0xN] [--max-mappings N] [--limit N]", L"Query section mappings for one file path.", L"Required: --path. Optional: --flags, --max-mappings, --limit.", L"" },
        { L"wsl", L"query-silo", L"KswordCLI.exe wsl query-silo [--pid PID] [--tid TID] [--flags 0xN]", L"Query WSL silo process/thread evidence.", L"Optional: --pid, --tid, --flags.", L"" },
        { L"r0", L"workqueue", L"KswordCLI.exe r0 workqueue [--flags 0xN] [--max-entries N] [--limit N]", L"Enumerate kernel worker queues through the desktop R0 client.", L"Optional: --flags, --max-entries, --limit.", L"Backed by IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE." },
        { L"r0", L"directory", L"KswordCLI.exe r0 directory --path PATH [--max-entries N] [--limit N]", L"Enumerate a directory through R0 ZwQueryDirectoryFile.", L"Required: --path. Optional: --max-entries, --limit.", L"Win32 and UNC paths are normalized to the driver NT-path convention." },
        { L"r0", L"directory-irp", L"KswordCLI.exe r0 directory-irp --path PATH [--layer N] [--max-entries N] [--limit N]", L"Enumerate a directory through a selected R0 file-system stack layer.", L"Required: --path. Optional: --layer, --max-entries, --limit.", L"Reports the resolved receiving layer and driver." },
        { L"r0", L"image-signature", L"KswordCLI.exe r0 image-signature --path PATH [--module-base VA] [--flags 0xN]", L"Read Authenticode certificate-table and CI evidence through R0.", L"Required: --path. Optional: --module-base, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE." },
        { L"r0", L"debug-output", L"KswordCLI.exe r0 debug-output [--after-sequence N] [--max-records N] [--limit N]", L"Drain captured kernel debug-output records.", L"Optional: --after-sequence, --max-records, --limit.", L"Backed by IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN; capture state remains driver-managed." },
        { L"r0", L"hvm-status", L"KswordCLI.exe r0 hvm-status", L"Query HVM/VT-x lifecycle and capability state.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_HVM." },
        { L"r0", L"hvm-events", L"KswordCLI.exe r0 hvm-events [--after-sequence N] [--max-rows N]", L"Read HVM event-ring evidence without clearing it.", L"Optional: --after-sequence, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_HVM_EVENTS." },
        { L"r0", L"ioctl-registry", L"KswordCLI.exe r0 ioctl-registry [--flags 0xN] [--max-entries N]", L"Query the driver's registered IOCTL dispatch inventory.", L"Optional: --flags, --max-entries.", L"Backed by IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY." },
        { L"r0", L"timer-dpc", L"KswordCLI.exe r0 timer-dpc [--max-entries N] [--max-per-bucket N]", L"Enumerate kernel timer and DPC evidence.", L"Optional: --max-entries, --max-per-bucket.", L"Backed by IOCTL_KSWORD_ARK_ENUM_TIMER_DPC." },
        { L"r0", L"unloaded", L"KswordCLI.exe r0 unloaded [--source mm|piddb|hash] [--max-rows N]", L"Query unloaded-driver, PiDDB, or hash-bucket evidence.", L"Optional: --source defaults to mm; --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS." },
        { L"r0", L"wfp-events", L"KswordCLI.exe r0 wfp-events [--after-sequence N] [--max-rows N]", L"Read bounded WFP event-ring metadata.", L"Optional: --after-sequence, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS." },
        { L"r0", L"traffic", L"KswordCLI.exe r0 traffic [--after-sequence N] [--max-rows N]", L"Read bounded traffic-capture metadata from the driver's existing ring.", L"Optional: --after-sequence, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS; this command does not enable capture." },
        { L"r0", L"piddb", L"KswordCLI.exe r0 piddb [--max-rows N]", L"Enumerate PiDDBCacheTable evidence without deleting entries.", L"Optional: --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PIDDB." },
        { L"r0", L"cpu-power", L"KswordCLI.exe r0 cpu-power", L"Query CPU power-management state and raw capability evidence.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_CPU_POWER." },
        { L"r0", L"process-protect", L"KswordCLI.exe r0 process-protect", L"Query the driver process-protection configuration and counters.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE." },
        { L"r0", L"raw-disk-backend", L"KswordCLI.exe r0 raw-disk-backend [--disk N] [--backend N] [--flags 0xN]", L"Query the selected raw-disk read backend.", L"Optional: --disk defaults to 0, --backend defaults to Windows stack, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND." },
        { L"r0", L"raw-disk-read", L"KswordCLI.exe r0 raw-disk-read --length N [--disk N] [--backend N] [--offset N] [--flags 0xN] [--hexdump]", L"Read a bounded raw-disk range for forensic inspection.", L"Required: --length. Optional: --disk, --backend, --offset, --flags, --hexdump.", L"Backed by IOCTL_KSWORD_ARK_READ_RAW_DISK; default display is capped at 256 bytes." },
        { L"r0", L"system-time", L"KswordCLI.exe r0 system-time", L"Query system-time virtualization and conflict state.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME." },
        { L"r0", L"slat-iommu", L"KswordCLI.exe r0 slat-iommu [--include-mmio]", L"Query SLAT and IOMMU firmware/runtime evidence.", L"Optional: --include-mmio.", L"Backed by IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT." },
        { L"r0", L"platform", L"KswordCLI.exe r0 platform [--scope 0xN] [--max-rows N]", L"Query HAL and WDF platform-audit evidence.", L"Optional: --scope defaults to all, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT." },
        { L"r0", L"i8042", L"KswordCLI.exe r0 i8042 [--max-rows N]", L"Query i8042prt callback and stack evidence without reading input data.", L"Optional: --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT." },
        { L"r0", L"object-types", L"KswordCLI.exe r0 object-types [--flags 0xN] [--max-entries N] [--start-index N]", L"Enumerate the kernel object-type table.", L"Optional: --flags, --max-entries, --start-index.", L"Backed by IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE." },
        { L"r0", L"win32k-timers", L"KswordCLI.exe r0 win32k-timers [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N]", L"Query PDB-backed win32k timer evidence.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS." },
        { L"r0", L"win32k-events", L"KswordCLI.exe r0 win32k-events [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N]", L"Query PDB-backed WinEvent-hook evidence.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS." },
        { L"trust", L"query-image", L"KswordCLI.exe trust query-image --path PATH [--flags 0xN]", L"Query image trust and signing evidence.", L"Required: --path. Optional: --flags.", L"" },
        { L"safety", L"query-policy", L"KswordCLI.exe safety query-policy [--flags 0xN]", L"Query safety policy state.", L"Optional: --flags.", L"" },
        { L"safety", L"set-policy", L"KswordCLI.exe safety set-policy [--set-flags 0xN] [--clear-flags 0xN] [--expected-generation N]", L"Update safety policy flags.", L"Optional: --set-flags, --clear-flags, --expected-generation.", L"" },
        { L"preflight", L"query", L"KswordCLI.exe preflight query [--flags 0xN] [--limit N]", L"Run release-readiness preflight checks.", L"Optional: --flags, --limit.", L"" },
        { L"registry", L"read-value", L"KswordCLI.exe registry read-value --key KEY [--value NAME] [--max-data-bytes N] [--flags 0xN] [--hexdump]", L"Read one registry value or default value.", L"Required: --key. Optional: --value, --max-data-bytes, --flags, --hexdump.", L"" },
        { L"registry", L"enum-key", L"KswordCLI.exe registry enum-key --key KEY [--flags 0xN] [--max-subkeys N] [--max-values N] [--max-value-data-bytes N] [--limit N]", L"Enumerate registry subkeys and values.", L"Required: --key. Optional: --flags, --max-subkeys, --max-values, --max-value-data-bytes, --limit.", L"" },
        { L"registry", L"set-value", L"KswordCLI.exe registry set-value --key KEY --type TYPE --data-file PATH [--value NAME] [--flags 0xN]", L"Set one registry value.", L"Required: --key, --type, --data-file. Optional: --value, --flags.", L"" },
        { L"registry", L"delete-value", L"KswordCLI.exe registry delete-value --key KEY [--value NAME] [--flags 0xN]", L"Delete one registry value or default value.", L"Required: --key. Optional: --value, --flags.", L"" },
        { L"registry", L"create-key", L"KswordCLI.exe registry create-key --key KEY [--flags 0xN]", L"Create one registry key.", L"Required: --key. Optional: --flags.", L"" },
        { L"registry", L"delete-key", L"KswordCLI.exe registry delete-key --key KEY [--flags 0xN]", L"Delete one registry key.", L"Required: --key. Optional: --flags.", L"" },
        { L"registry", L"rename-value", L"KswordCLI.exe registry rename-value --key KEY --old-value NAME --new-value NAME [--flags 0xN]", L"Rename one registry value.", L"Required: --key, --old-value, --new-value. Optional: --flags.", L"" },
        { L"registry", L"rename-key", L"KswordCLI.exe registry rename-key --key KEY --new-name NAME [--flags 0xN]", L"Rename one registry key.", L"Required: --key, --new-name. Optional: --flags.", L"" },
        { L"redirect", L"set-rules", L"KswordCLI.exe redirect set-rules --blob PATH", L"Load file/registry redirect rules.", L"Required: --blob.", L"" },
        { L"redirect", L"query-status", L"KswordCLI.exe redirect query-status [--limit N]", L"Query redirect runtime state and rules.", L"Optional: --limit.", L"" },
        { L"network", L"set-rules", L"KswordCLI.exe network set-rules --blob PATH", L"Load network rule bytes.", L"Required: --blob.", L"" },
        { L"network", L"query-status", L"KswordCLI.exe network query-status [--limit N]", L"Query network runtime state and rules.", L"Optional: --limit.", L"" },
        { L"network", L"audit", L"KswordCLI.exe network audit [--flags 0xN] [--max-rows N] [--limit N]", L"Query TCP endpoint audit as the default network audit view.", L"Optional: --flags, --max-rows, --limit.", L"Use network wfp or network ndis for chain-specific views." },
        { L"network", L"tcp", L"KswordCLI.exe network tcp [--flags 0xN] [--max-rows N] [--limit N]", L"Query TCP endpoint audit rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"udp", L"KswordCLI.exe network udp [--flags 0xN] [--max-rows N] [--limit N]", L"Query UDP endpoint audit rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"wfp", L"KswordCLI.exe network wfp [--flags 0xN] [--max-rows N] [--limit N]", L"Query WFP inventory rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"ndis", L"KswordCLI.exe network ndis [--flags 0xN] [--max-rows N] [--limit N]", L"Query NDIS chain rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"afd", L"KswordCLI.exe network afd [--limit N]", L"Print degraded R3 AFD endpoint fallback evidence.", L"Optional: --limit.", L"No dedicated R0 AFD audit IOCTL is used." },
        { L"network", L"nsi", L"KswordCLI.exe network nsi [--limit N]", L"Print degraded R3 NSI adapter/address fallback evidence.", L"Optional: --limit.", L"No dedicated R0 NSI audit IOCTL is used." },
        { L"keyboard", L"enum-hotkeys", L"KswordCLI.exe keyboard enum-hotkeys [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]", L"Enumerate keyboard hotkeys.", L"Optional: --flags, --pid, --max-entries, --limit.", L"" },
        { L"keyboard", L"enum-hooks", L"KswordCLI.exe keyboard enum-hooks [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]", L"Enumerate keyboard hooks.", L"Optional: --flags, --pid, --max-entries, --limit.", L"" },
        { L"driver", L"integrity", L"KswordCLI.exe driver integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]", L"Query driver integrity evidence.", L"Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit.", L"" },
        { L"driver", L"detail", L"KswordCLI.exe driver detail --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]", L"Query one DriverObject detail projection.", L"Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit.", L"" },
        { L"driver", L"device", L"KswordCLI.exe driver device [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query driver device stack audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Aliases: driver major, driver fastio." },
        { L"driver", L"major", L"KswordCLI.exe driver major [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for driver device audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: driver device." },
        { L"driver", L"fastio", L"KswordCLI.exe driver fastio [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for driver device audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: driver device." },
        { L"driver", L"unloaded", L"KswordCLI.exe driver unloaded [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]", L"Project MmUnloadedDrivers optional-global evidence.", L"Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit.", L"" },
        { L"driver", L"piddb", L"KswordCLI.exe driver piddb [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]", L"Project PiDDBCacheTable optional-global evidence.", L"Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit.", L"" },
        { L"hardware", L"audit", L"KswordCLI.exe hardware audit [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query generic hardware device stack audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: hardware pnp." },
        { L"hardware", L"pnp", L"KswordCLI.exe hardware pnp [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for hardware audit.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: hardware audit." },
        { L"hardware", L"input", L"KswordCLI.exe hardware input [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query input stack audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"" },
        { L"hardware", L"usb", L"KswordCLI.exe hardware usb [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query USB topology audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"" },
        { L"hwid", L"dispatch-query", L"KswordCLI.exe hwid dispatch-query", L"Query HWID Dispatch hook state.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY." },
        { L"hwid", L"dispatch-control", L"KswordCLI.exe hwid dispatch-control --action query|enable|disable|disable-all [--targets LIST] [--dry-run] [--flags 0xN] [--disk-mode custom|random|null] [--mac-mode random|custom] [--disk-serial TEXT] [--disk-product TEXT] [--disk-revision TEXT] [--gpu-serial TEXT] [--permanent-mac TEXT] [--current-mac TEXT] --confirm", L"Control HWID Dispatch hook targets with an explicit confirmation flag.", L"Required: --action and --confirm for non-query actions. Optional: --targets defaults to storage; --dry-run sets request dry-run.", L"Targets: disk, partmgr, mountmgr, nvidia, nsiproxy, storage, network, all. Behavior bits can be passed through --flags." },
        { L"window", L"win32k", L"KswordCLI.exe window win32k [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query win32k profile/session status.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"" },
        { L"window", L"gui", L"KswordCLI.exe window gui [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query GUI window snapshot rows.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"" },
        { L"window", L"gui-threads", L"KswordCLI.exe window gui-threads [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query GUI thread snapshot rows.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"" },
        { L"window", L"hotkeys-pdb", L"KswordCLI.exe window hotkeys-pdb [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query PDB-backed win32k hotkey chain rows.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB." },
        { L"window", L"hooks-pdb", L"KswordCLI.exe window hooks-pdb [--flags 0xN] [--match legacy|owner|target|both] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query PDB-backed win32k hook chain rows.", L"Optional: --flags (default 0x3), --match (overrides only owner/target selector bits in --flags; default legacy), --session-id, --pid, --tid, --max-entries (default 4096; hard maximum 8192), --limit.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB; legacy/both require the complete filter to match one side; prints traversal diagnostics." },
        { L"window", L"detail", L"KswordCLI.exe window detail --hwnd HWND [--pid PID] [--tid TID] [--flags 0xN]", L"Query one HWND/tagWND runtime detail packet.", L"Required: --hwnd. Optional: --pid, --tid, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL." },
        { L"window", L"gpu", L"KswordCLI.exe window gpu [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query GPU/display/watchdog audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Aliases: window display, window watchdog." },
        { L"window", L"display", L"KswordCLI.exe window display [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for window gpu audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: window gpu." },
        { L"window", L"watchdog", L"KswordCLI.exe window watchdog [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for window gpu audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: window gpu." },
        { L"misc", L"security", L"KswordCLI.exe misc security [--flags 0xN]", L"Query security/CI/VBS posture.", L"Optional: --flags.", L"Aliases: misc ci, misc vbs." },
        { L"misc", L"ci", L"KswordCLI.exe misc ci [--flags 0xN]", L"Alias for misc security.", L"Optional: --flags.", L"Alias: misc security." },
        { L"misc", L"vbs", L"KswordCLI.exe misc vbs [--flags 0xN]", L"Alias for misc security.", L"Optional: --flags.", L"Alias: misc security." },
        { L"misc", L"hyperv", L"KswordCLI.exe misc hyperv", L"Query Hyper-V summary posture.", L"No options.", L"" },
        { L"misc", L"applocker", L"KswordCLI.exe misc applocker", L"Query AppLocker/BAM posture.", L"No options.", L"Alias: misc bam." },
        { L"misc", L"bam", L"KswordCLI.exe misc bam", L"Alias for misc applocker.", L"No options.", L"Alias: misc applocker." },
        { L"misc", L"driver-trust", L"KswordCLI.exe misc driver-trust [--flags 0xN] [--max-entries N] [--limit N]", L"Query loaded-driver trust rows.", L"Optional: --flags, --max-entries, --limit.", L"" },
        { L"mutation", L"prepare", L"KswordCLI.exe mutation prepare --target-kind N (--after-hex HEX | --after-file PATH) [--before-hex HEX | --before-file PATH] [--pid PID] [--address VA] [--context N] [--flags 0xN]", L"Prepare a bounded mutation transaction.", L"Required: --target-kind and after payload. Optional: before payload, --pid, --address, --context, --flags.", L"Hex and file payload forms are mutually exclusive per payload." },
        { L"mutation", L"commit", L"KswordCLI.exe mutation commit --transaction-id ID [--flags 0xN]", L"Commit a prepared mutation transaction.", L"Required: --transaction-id. Optional: --flags.", L"" },
        { L"mutation", L"rollback", L"KswordCLI.exe mutation rollback --transaction-id ID [--flags 0xN]", L"Rollback a prepared mutation transaction.", L"Required: --transaction-id. Optional: --flags.", L"" },
        { L"mutation", L"query-audit", L"KswordCLI.exe mutation query-audit [--flags 0xN] [--max-entries N] [--start-sequence N] [--limit N] [--hexdump]", L"Query mutation audit ring entries.", L"Optional: --flags, --max-entries, --start-sequence, --limit, --hexdump.", L"" },
    };

    // sameToken compares an argv token with a metadata token.
    // Inputs: value may be null; expected is a static command token.
    // Processing: uses exact case-sensitive comparison to match dispatch behavior.
    // Returns: true when both tokens contain the same text.
    bool sameToken(const wchar_t* value, const wchar_t* expected)
    {
        return value != nullptr && expected != nullptr && std::wcscmp(value, expected) == 0;
    }

    // isHelpToken reports whether a token requests CLI help.
    // Inputs: raw argv token, possibly null.
    // Processing: accepts the same spellings that dispatch historically treated as help.
    // Returns: true for help, --help, -h, or /?.
    bool isHelpToken(const wchar_t* token)
    {
        return sameToken(token, L"help") ||
               sameToken(token, L"--help") ||
               sameToken(token, L"-h") ||
               sameToken(token, L"/?");
    }

    // findFamilyHelp returns metadata for one top-level family.
    // Inputs: family token from argv.
    // Processing: scans the static help table without side effects.
    // Returns: pointer to metadata or nullptr when the family is unknown.
    const FamilyHelp* findFamilyHelp(const std::wstring& family)
    {
        for (const FamilyHelp& entry : kFamilyHelps)
        {
            if (family == entry.name)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    // printCommandHelpEntry renders detailed help for one command row.
    // Inputs: static CommandHelp metadata.
    // Processing: writes syntax, summary, options, and optional notes to stdout.
    // Returns: no value.
    void printCommandHelpEntry(const CommandHelp& entry)
    {
        std::wcout << L"Command: " << entry.family;
        if (entry.subcommand[0] != L'\0')
        {
            std::wcout << L" " << entry.subcommand;
        }
        std::wcout << L"\n"
                   << L"Syntax:\n  " << entry.syntax << L"\n"
                   << L"Summary:\n  " << entry.summary << L"\n";
        if (entry.options[0] != L'\0')
        {
            std::wcout << L"Options:\n  " << entry.options << L"\n";
        }
        if (entry.notes[0] != L'\0')
        {
            std::wcout << L"Notes:\n  " << entry.notes << L"\n";
        }
    }

    // printFamilyHelp renders all concrete commands for one family.
    // Inputs: top-level family token.
    // Processing: validates the family and lists matching command metadata.
    // Returns: true when the family exists; false otherwise.
    bool printFamilyHelp(const std::wstring& family)
    {
        const FamilyHelp* familyHelp = findFamilyHelp(family);
        if (familyHelp == nullptr)
        {
            std::wcerr << L"error: unknown family '" << family << L"'\n";
            return false;
        }

        std::wcout << L"Family: " << familyHelp->name << L"\n"
                   << L"Summary: " << familyHelp->summary << L"\n"
                   << L"Commands:\n";
        for (const CommandHelp& command : kCommandHelps)
        {
            if (family == command.family)
            {
                std::wcout << L"  " << command.syntax << L"\n"
                           << L"    " << command.summary << L"\n";
            }
        }
        return true;
    }

    // printSpecificCommandHelp renders help for one family/subcommand pair.
    // Inputs: exact family and subcommand tokens from argv.
    // Processing: scans metadata and falls back to family help on misses.
    // Returns: true when a concrete command was found.
    bool printSpecificCommandHelp(const std::wstring& family, const std::wstring& subcommand)
    {
        for (const CommandHelp& command : kCommandHelps)
        {
            if (family == command.family && subcommand == command.subcommand)
            {
                printCommandHelpEntry(command);
                return true;
            }
        }

        std::wcerr << L"error: unknown command '" << family << L" " << subcommand << L"'\n";
        if (findFamilyHelp(family) != nullptr)
        {
            printFamilyHelp(family);
        }
        return false;
    }

    // printUsage prints the CLI command reference.
    // Inputs: none.
    // Processing: groups all registered commands by static command family metadata.
    // Returns: no value; output goes to stdout.
    void printUsage()
    {
        std::wcout
            << L"KswordCLI CLI\n"
            << L"usage: KswordCLI.exe <family> <subcommand> [--named-options]\n"
            << L"       KswordCLI.exe log [--max-frames N]\n"
            << L"       KswordCLI.exe help [family] [subcommand]\n\n"
            << L"Help forms:\n"
            << L"  KswordCLI.exe help\n"
            << L"  KswordCLI.exe help process\n"
            << L"  KswordCLI.exe help process enum\n"
            << L"  KswordCLI.exe process help\n"
            << L"  KswordCLI.exe process enum --help\n\n"
            << L"Families and subcommands:\n";

        for (const FamilyHelp& family : kFamilyHelps)
        {
            std::wcout << L"  " << std::left << std::setw(11) << family.name;
            bool first = true;
            for (const CommandHelp& command : kCommandHelps)
            {
                if (std::wcscmp(family.name, command.family) != 0)
                {
                    continue;
                }
                if (!first)
                {
                    std::wcout << L" | ";
                }
                std::wcout << ((command.subcommand[0] == L'\0') ? L"[no subcommand]" : command.subcommand);
                first = false;
            }
            std::wcout << std::right << L"\n";
        }

        std::wcout
            << L"\nCommon options: --flags 0xN --limit N --hexdump\n"
            << L"Use 'KswordCLI.exe help <family> <subcommand>' for exact syntax.\n"
            << L"Examples:\n"
            << L"  KswordCLI.exe capability query-driver-capabilities\n"
            << L"  KswordCLI.exe process enum --flags 0x1 --limit 32\n"
            << L"  KswordCLI.exe memory read-va --pid 1234 --address 0x7ff700000000 --bytes 64 --hexdump\n"
            << L"  KswordCLI.exe help memory read-va\n";
    }

    // printHelpForTarget handles help command argument routing.
    // Inputs: argc/argv from wmain and index of the first help target token.
    // Processing: prints overview, family help, or exact command help without IOCTLs.
    // Returns: process exit code; zero means help text was found and printed.
    int printHelpForTarget(int argc, wchar_t* argv[], int startIndex)
    {
        if (startIndex >= argc || argv[startIndex] == nullptr || isHelpToken(argv[startIndex]))
        {
            printUsage();
            return 0;
        }

        const std::wstring family = argv[startIndex];
        if (startIndex + 1 >= argc || argv[startIndex + 1] == nullptr || isHelpToken(argv[startIndex + 1]))
        {
            return printFamilyHelp(family) ? 0 : 1;
        }

        const std::wstring subcommand = argv[startIndex + 1];
        return printSpecificCommandHelp(family, subcommand) ? 0 : 1;
    }

    // hasTrailingHelpToken detects inline help requests after a command target.
    // Inputs: argc/argv plus the first token to inspect.
    // Processing: scans remaining tokens for help spellings and does not parse options.
    // Returns: true when any trailing token asks for help.
    bool hasTrailingHelpToken(int argc, wchar_t* argv[], int startIndex)
    {
        for (int index = startIndex; index < argc; ++index)
        {
            if (isHelpToken(argv[index]))
            {
                return true;
            }
        }
        return false;
    }

    // printCountHeader renders the common variable-response metadata.
    // Inputs: protocol version, total row count, returned row count, row byte size,
    // and DeviceIoControl bytesReturned.
    // Processing: prints the normalized acceptance fields first
    // (version/returned/total/entrySize/rowSize/bytesReturned/truncated), then keeps
    // legacy totalCount/returnedCount aliases so older scripts remain compatible.
    // Returns: no value.
    void printCountHeader(std::uint32_t version, std::uint32_t total, std::uint32_t returned, std::uint32_t entrySize, DWORD bytesReturned)
    {
        std::wcout << L"version=" << version
                   << L" returned=" << returned
                   << L" total=" << total
                   << L" entrySize=" << entrySize
                   << L" rowSize=" << entrySize
                   << L" bytesReturned=" << bytesReturned
                   << L" truncated=" << ((returned < total) ? 1U : 0U)
                   << L" totalCount=" << total
                   << L" returnedCount=" << returned << L"\n";
    }

    // containsIgnoreCase 作用：在 CLI 文本投影中做宽字符包含匹配。
    // 输入：haystack 为待搜索文本，needle 为目标片段。
    // 处理：逐字符转小写后比较，避免不同 R0 detail 大小写导致漏报。
    // 返回：命中返回 true；needle 为空时按“不过滤”返回 true。
    bool containsIgnoreCase(const std::wstring& haystack, const wchar_t* needle)
    {
        if (needle == nullptr || needle[0] == L'\0')
        {
            return true;
        }

        std::wstring loweredHaystack;
        loweredHaystack.reserve(haystack.size());
        for (const wchar_t ch : haystack)
        {
            loweredHaystack.push_back(static_cast<wchar_t>(std::towlower(ch)));
        }

        std::wstring loweredNeedle;
        for (const wchar_t* cursor = needle; *cursor != L'\0'; ++cursor)
        {
            loweredNeedle.push_back(static_cast<wchar_t>(std::towlower(*cursor)));
        }
        return loweredHaystack.find(loweredNeedle) != std::wstring::npos;
    }

    // validateVariable validates header + variable entries before parsing rows.
    // Inputs: returned bytes, header size, entry size and minimum row size.
    // Processing: checks short buffers and invalid row sizes.
    // Returns: available row count in the returned buffer.
    std::size_t validateVariable(DWORD bytesReturned, std::size_t headerSize, std::uint32_t entrySize, std::size_t minEntrySize, const wchar_t* label)
    {
        if (bytesReturned < headerSize)
        {
            std::wcerr << L"error: " << label << L" response too small: " << bytesReturned << L" bytes\n";
            throw std::runtime_error("small response");
        }
        if (entrySize < minEntrySize)
        {
            std::wcerr << L"error: " << label << L" invalid entrySize=" << entrySize << L"\n";
            throw std::runtime_error("entry size");
        }
        return (static_cast<std::size_t>(bytesReturned) - headerSize) / static_cast<std::size_t>(entrySize);
    }

    // isUnsupportedTransportError recognizes old-driver or missing-IOCTL results.
    // Inputs: Win32 error returned by DeviceIoControl.
    // Processing: maps common unsupported/unimplemented transport statuses.
    // Returns: true when the caller should print "unsupported / unavailable".
    bool isUnsupportedTransportError(DWORD error)
    {
        return error == ERROR_INVALID_FUNCTION ||
               error == ERROR_NOT_SUPPORTED ||
               error == ERROR_CALL_NOT_IMPLEMENTED ||
               error == ERROR_PROC_NOT_FOUND;
    }

    // normalizeIoctlRc keeps new audit commands graceful on older drivers.
    // Inputs: feature label, IoctlResult and the raw helper return code.
    // Processing: rewrites missing IOCTL failures into a clear audit message.
    // Returns: CLI exit code; 5 means supported by CLI but unavailable in driver.
    int normalizeIoctlRc(const wchar_t* feature, const IoctlResult& io, int rc)
    {
        if (rc == 3 && isUnsupportedTransportError(io.win32Error))
        {
            std::wcout << L"unsupported / unavailable: " << feature
                       << L" (driver does not expose this read-only IOCTL)\n";
            return 5;
        }
        return rc;
    }

    // commandUnsupported reports a known command whose protocol is not present.
    // Inputs: feature and reason strings.
    // Processing: prints a stable phrase required by acceptance checks.
    // Returns: non-zero CLI status to let scripts detect degraded support.
    int commandUnsupported(const wchar_t* feature, const wchar_t* reason)
    {
        std::wcout << L"unsupported / unavailable: " << feature
                   << L" (" << reason << L")\n";
        return 5;
    }

    std::wstring fixedAnsiWide(const char* text, std::size_t maxBytes);
    bool copyOptionalWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity);
    void printModuleIdentity(const wchar_t* label, const KSW_DYN_MODULE_IDENTITY_PACKET& module);

    // printV4ModuleIdentity renders DynData v4 module and PDB identity.
    // Inputs: v4 module packet from the shared protocol.
    // Processing: prints image identity first, then profile/PDB identity.
    // Returns: no value.
    void printV4ModuleIdentity(const KSW_DYN_V4_MODULE_IDENTITY_PACKET& module)
    {
        printModuleIdentity(L"image", module.image);
        std::wcout << L"    pdbName='" << fixedAnsiWide(module.pdb.pdbName, KSW_DYN_PDB_NAME_CHARS)
                   << L"' pdbGuid='" << fixedAnsiWide(module.pdb.pdbGuid, KSW_DYN_PDB_GUID_CHARS)
                   << L"' pdbAge=" << module.pdb.pdbAge
                   << L" profile='" << fixedAnsiWide(module.profileName, KSW_DYN_V4_PROFILE_NAME_CHARS) << L"'\n";
    }

    // queryDynV4Modules prints the applied multi-module profile state.
    // Inputs: parsed command options.
    // Processing: issues the read-only v4 modules IOCTL and bounds row output.
    // Returns: CLI exit code.
    int queryDynV4Modules(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int rc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES,
            nullptr,
            0U,
            buffer,
            io);
        if (rc != 0) return normalizeIoctlRc(L"dyn v4 modules", io, rc);
        constexpr std::size_t headerSize = KSW_QUERY_DYN_V4_MODULES_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_MODULES_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSW_DYN_V4_MODULE_STATUS_ENTRY), L"dyn v4 modules"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_MODULE_STATUS_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] moduleIndex=" << entry->moduleIndex
                       << L" statusFlags=0x" << std::hex << entry->statusFlags
                       << std::dec << L" itemCount=" << entry->itemCount
                       << L" groupCount=" << entry->capabilityGroupCount
                       << L" activeGroups=" << entry->activeCapabilityGroupCount
                       << L" missingRequired=" << entry->missingRequiredItemCount
                       << L" missingOptional=" << entry->missingOptionalItemCount << L"\n";
            printV4ModuleIdentity(entry->module);
        }
        return 0;
    }

    // queryDynV4CapabilityGroups prints v4 capability coverage rows.
    // Inputs: parsed command options.
    // Processing: reads active/required/optional counts per group.
    // Returns: CLI exit code.
    int queryDynV4CapabilityGroups(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int rc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS,
            nullptr,
            0U,
            buffer,
            io);
        if (rc != 0) return normalizeIoctlRc(L"dyn v4 capability groups", io, rc);
        constexpr std::size_t headerSize = KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY), L"dyn v4 capability groups"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] moduleClass=" << entry->moduleClassId
                       << L" groupId=" << entry->groupId
                       << L" statusFlags=0x" << std::hex << entry->statusFlags
                       << std::dec << L" required=" << entry->presentRequiredItemCount << L"/" << entry->requiredItemCount
                       << L" optional=" << entry->presentOptionalItemCount << L"/" << entry->optionalItemCount
                       << L" group='" << fixedAnsiWide(entry->groupName, KSW_DYN_V4_CAPABILITY_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryDynV4MissingItems prints required/optional item gaps.
    // Inputs: parsed command options.
    // Processing: queries missing item summaries and prints bounded rows.
    // Returns: CLI exit code.
    int queryDynV4MissingItems(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int rc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS,
            nullptr,
            0U,
            buffer,
            io);
        if (rc != 0) return normalizeIoctlRc(L"dyn v4 missing items", io, rc);
        constexpr std::size_t headerSize = KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSW_DYN_V4_MISSING_ITEM_ENTRY), L"dyn v4 missing items"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_MISSING_ITEM_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] moduleClass=" << entry->moduleClassId
                       << L" itemId=" << entry->itemId
                       << L" kind=" << entry->itemKind
                       << L" groupId=" << entry->capabilityGroupId
                       << L" missingKind=" << entry->missingKind
                       << L" item='" << fixedAnsiWide(entry->itemName, KSW_DYN_V4_ITEM_NAME_CHARS)
                       << L"' reason='" << fixedAnsiWide(entry->reason, KSW_DYN_V4_MISSING_REASON_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryDynV4Items prints every applied DynData v4 item packet.
    // Inputs: parsed command options; --limit caps console output only.
    // Processing: issues IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS and renders the
    // module class, item identity, group membership, values and auxiliary words.
    // Returns: CLI exit code; old drivers are reported through normalizeIoctlRc.
    int queryDynV4Items(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int rc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS,
            nullptr,
            0U,
            buffer,
            io);
        if (rc != 0) return normalizeIoctlRc(L"dyn v4 items", io, rc);
        constexpr std::size_t headerSize = KSW_QUERY_DYN_V4_ITEMS_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_ITEMS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSW_DYN_V4_ITEM_STATUS_ENTRY), L"dyn v4 items"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 256U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_ITEM_STATUS_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            const KSW_DYN_V4_ITEM_PACKET& item = entry->item;
            const std::uint64_t value64 =
                (static_cast<std::uint64_t>(item.valueHigh) << 32) |
                static_cast<std::uint64_t>(item.valueLow);
            std::wcout << L"  [" << i << L"] moduleClass=" << entry->moduleClassId
                       << L" itemIndex=" << entry->itemIndex
                       << L" itemId=" << item.itemId
                       << L" kind=" << item.itemKind
                       << L" groupId=" << item.capabilityGroupId
                       << L" flags=0x" << std::hex << item.flags
                       << L" valueLow=0x" << item.valueLow
                       << L" valueHigh=0x" << item.valueHigh
                       << L" value64=" << hex64(value64)
                       << L" aux=" << item.aux0 << L"/" << item.aux1 << L"/" << item.aux2 << L"/" << item.aux3
                       << std::dec << L"\n";
        }
        return 0;
    }

    // commandLogFamily reads the non-IOCTL log ReadFile channel.
    // Inputs: argc/argv from wmain.
    // Processing: reads bounded frames until END_OF_LOG or --max-frames.
    // Returns: process exit code.
    int commandLogFamily(int argc, wchar_t* argv[])
    {
        const NamedArgs args = parseNamedArgs(argc, argv, 2);
        const std::uint32_t maxFrames = getOptionU32(args, L"--max-frames", 64U);
        DriverHandle handle = openDriver(GENERIC_READ);
        if (!handle.valid())
        {
            printWin32Error(L"CreateFileW(" KSWORD_ARK_LOG_WIN32_PATH L")", ::GetLastError());
            return 2;
        }
        std::vector<char> buffer(4096U, '\0');
        for (std::uint32_t frame = 0; frame < maxFrames; ++frame)
        {
            DWORD bytesRead = 0;
            if (::ReadFile(handle.native(), buffer.data(), static_cast<DWORD>(buffer.size() - 1U), &bytesRead, nullptr) == FALSE)
            {
                printWin32Error(L"ReadFile(log)", ::GetLastError());
                return 3;
            }
            if (bytesRead == 0U) break;
            std::string text(buffer.data(), buffer.data() + bytesRead);
            const std::size_t marker = text.find(KSWORD_ARK_LOG_END_MARKER);
            if (marker != std::string::npos)
            {
                text.resize(marker);
                std::cout << text;
                break;
            }
            std::cout << text;
        }
        return 0;
    }


    // printProcessEnumRow renders a process enumeration entry.
    // Inputs: protocol row from KSWORD_ARK_PROCESS_ENTRY.
    // Processing: prints stable identifiers and optional image path.
    // Returns: no value.
    void printProcessEnumRow(const KSWORD_ARK_PROCESS_ENTRY& entry)
    {
        std::wcout << L"  pid=" << entry.processId
                   << L" ppid=" << entry.parentProcessId
                   << L" flags=0x" << std::hex << entry.flags
                   << L" fieldFlags=0x" << entry.fieldFlags
                   << std::dec << L" r0Status=" << entry.r0Status
                   << L" session=" << entry.sessionId
                   << L" objectTable=" << hex64(entry.objectTableAddress)
                   << L" section=" << hex64(entry.sectionObjectAddress)
                   << L" image='" << fixedAnsi(entry.imageName, sizeof(entry.imageName)).c_str() << L"'";
        const std::wstring imagePath = fixedUtf16(entry.imagePath, KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS);
        if (!imagePath.empty()) std::wcout << L" path='" << imagePath << L"'";
        std::wcout << L"\n";
    }

    // RuntimeFieldCliItem stores one CLI-requested bounded runtime field sample.
    // Inputs: runtimeItemId, offset, size, and optional flags parsed from --items.
    // Processing: command builders copy these values into process/thread request
    // packets after enforcing the shared protocol limits.
    // Returns: no behavior; this is a simple staging structure.
    struct RuntimeFieldCliItem
    {
        std::uint32_t runtimeItemId = 0U;
        std::uint32_t offset = 0U;
        std::uint32_t size = 0U;
        std::uint32_t flags = 0U;
    };

    // splitRuntimeFieldItem separates one "id:offset:size[:flags]" token.
    // Inputs: a token from --items where values may be decimal or 0x-prefixed.
    // Processing: validates the three required fields and the optional flags
    // field before protocol bounds are applied by the caller.
    // Returns: parsed item; throws on malformed text.
    RuntimeFieldCliItem splitRuntimeFieldItem(const std::wstring& token)
    {
        std::vector<std::wstring> parts;
        std::wstring current;
        for (const wchar_t ch : token)
        {
            if (ch == L':')
            {
                parts.push_back(current);
                current.clear();
                continue;
            }
            current.push_back(ch);
        }
        parts.push_back(current);

        if (parts.size() < 3U || parts.size() > 4U)
        {
            throw std::invalid_argument("runtime field item");
        }

        RuntimeFieldCliItem item{};
        item.runtimeItemId = parseU32(parts[0].c_str(), "runtime item id");
        item.offset = parseU32(parts[1].c_str(), "runtime item offset");
        item.size = parseU32(parts[2].c_str(), "runtime item size");
        item.flags = (parts.size() == 4U) ? parseU32(parts[3].c_str(), "runtime item flags") : 0U;
        if (item.size == 0U || item.size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES)
        {
            throw std::out_of_range("runtime item size");
        }
        if (item.offset > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET)
        {
            throw std::out_of_range("runtime item offset");
        }
        return item;
    }

    // parseRuntimeFieldItems parses the comma/semicolon/pipe separated --items list.
    // Inputs: text such as "1:0x448:8,2:0x5a8:1".
    // Processing: trims whitespace separators, validates each item, and caps the
    // count at KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS.
    // Returns: ordered item vector used to build variable-sized IOCTL input.
    std::vector<RuntimeFieldCliItem> parseRuntimeFieldItems(const std::wstring& text)
    {
        std::vector<RuntimeFieldCliItem> items;
        std::wstring token;
        const auto flush = [&]()
        {
            if (token.empty())
            {
                return;
            }
            if (items.size() >= KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS)
            {
                throw std::out_of_range("runtime item count");
            }
            items.push_back(splitRuntimeFieldItem(token));
            token.clear();
        };

        for (const wchar_t ch : text)
        {
            if (ch == L',' || ch == L';' || ch == L'|' || std::iswspace(ch) != 0)
            {
                flush();
                continue;
            }
            token.push_back(ch);
        }
        flush();
        if (items.empty())
        {
            throw std::invalid_argument("runtime items");
        }
        return items;
    }

    // printKernelGlobals renders the common process/thread runtime global packet.
    // Inputs: kernelGlobals returned by process/thread detail IOCTLs.
    // Processing: prints RVA/source/address triplets in a compact diagnostic form.
    // Returns: no value.
    void printKernelGlobals(const KSWORD_ARK_RUNTIME_KERNEL_GLOBALS& globals)
    {
        std::wcout << L"kernelGlobals"
                   << L" pspCidTable=" << hex64(globals.pspCidTableAddress) << L"/rva=0x" << std::hex << globals.pspCidTableRva << L"/src=" << globals.pspCidTableSource
                   << L" psLoadedModuleList=" << hex64(globals.psLoadedModuleListAddress) << L"/rva=0x" << globals.psLoadedModuleListRva << L"/src=" << globals.psLoadedModuleListSource
                   << L" mmUnloadedDrivers=" << hex64(globals.mmUnloadedDriversAddress) << L"/rva=0x" << globals.mmUnloadedDriversRva << L"/src=" << globals.mmUnloadedDriversSource
                   << L" piDdbCacheTable=" << hex64(globals.piDdbCacheTableAddress) << L"/rva=0x" << globals.piDdbCacheTableRva << L"/src=" << globals.piDdbCacheTableSource
                   << L" shadowSsdt=" << hex64(globals.keServiceDescriptorTableShadowAddress) << L"/rva=0x" << globals.keServiceDescriptorTableShadowRva << L"/src=" << globals.keServiceDescriptorTableShadowSource
                   << std::dec << L"\n";
    }

    // printRuntimeFieldSampleRows renders a variable process/thread sample response.
    // Inputs: raw returned buffer and a label used for validation diagnostics.
    // Processing: validates row size, prints object/capability metadata, and then
    // prints every bounded sample row up to --limit.
    // Returns: CLI exit code.
    int printRuntimeFieldSampleRows(
        const std::vector<std::uint8_t>& buffer,
        const IoctlResult& io,
        const NamedArgs& args,
        const wchar_t* label)
    {
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE) - sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW), label); }
        catch (...) { return 4; }

        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"object=" << hex64(response->objectAddress)
                   << L" dyn=0x" << std::hex << response->dynDataCapabilityMask
                   << std::dec << L" flags=0x" << std::hex << response->flags << std::dec << L"\n";

        const bool dump = getOptionBool(args, L"--hexdump");
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0U; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] item=" << row->runtimeItemId
                       << L" offset=0x" << std::hex << row->offset
                       << L" size=" << std::dec << row->size
                       << L" status=" << row->status
                       << L" bytesRead=" << row->bytesRead
                       << L" last=0x" << std::hex << static_cast<unsigned long>(row->lastStatus)
                       << L" value=" << hex64(row->valueU64)
                       << std::dec << L"\n";
            if (dump && row->bytesRead != 0U)
            {
                hexdump(row->sampleBytes, std::min<unsigned long>(row->bytesRead, KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES));
            }
        }
        return 0;
    }

    // printProcessDetail renders IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL output.
    // Inputs: fixed response and DeviceIoControl byte count.
    // Processing: prints identity, object pointers, security bytes, offsets and
    // source masks in a format suitable for scripts and manual triage.
    // Returns: no value.
    void printProcessDetail(const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"pid=" << response.processId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" requested=0x" << response.requestedFlags
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" missing=0x" << response.missingCapabilityMask
                   << L" eprocess=" << hex64(response.processObjectAddress)
                   << L" uniquePidValue=" << hex64(response.uniqueProcessIdValue)
                   << L" apl.flink=" << hex64(response.activeProcessLinksFlink)
                   << L" apl.blink=" << hex64(response.activeProcessLinksBlink)
                   << L" threadList.flink=" << hex64(response.threadListHeadFlink)
                   << L" threadList.blink=" << hex64(response.threadListHeadBlink)
                   << L" tokenFastRef=" << hex64(response.tokenFastRef)
                   << L" tokenObject=" << hex64(response.tokenObjectAddress)
                   << L" objectTable=" << hex64(response.objectTableAddress)
                   << L" section=" << hex64(response.sectionObjectAddress)
                   << std::dec << L"\n";
        std::wcout << L"security protection=0x" << std::hex << static_cast<unsigned int>(response.protection)
                   << L" signature=0x" << static_cast<unsigned int>(response.signatureLevel)
                   << L" sectionSignature=0x" << static_cast<unsigned int>(response.sectionSignatureLevel)
                   << std::dec << L" image='" << fixedAnsi(response.imageName, KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS).c_str() << L"'\n";
        std::wcout << L"offsets uniquePid=0x" << std::hex << response.offsets.epUniqueProcessId
                   << L" activeLinks=0x" << response.offsets.epActiveProcessLinks
                   << L" threadList=0x" << response.offsets.epThreadListHead
                   << L" image=0x" << response.offsets.epImageFileName
                   << L" token=0x" << response.offsets.epToken
                   << L" objectTable=0x" << response.offsets.epObjectTable
                   << L" section=0x" << response.offsets.epSectionObject
                   << L" protection=0x" << response.offsets.epProtection
                   << L" signature=0x" << response.offsets.epSignatureLevel
                   << L" sectionSignature=0x" << response.offsets.epSectionSignatureLevel
                   << std::dec << L"\n";
        printKernelGlobals(response.kernelGlobals);
        dumpWideText(L"detail", fixedWide(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
    }

    // printThreadDetail renders IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL output.
    // Inputs: fixed response and DeviceIoControl byte count.
    // Processing: prints ETHREAD/KTHREAD object pointers, start/stack/IO evidence,
    // offsets, and human-readable detail text.
    // Returns: no value.
    void printThreadDetail(const KSWORD_ARK_THREAD_DETAIL_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"tid=" << response.threadId
                   << L" pid=" << response.processId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" requested=0x" << response.requestedFlags
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" missing=0x" << response.missingCapabilityMask
                   << L" ethread=" << hex64(response.threadObjectAddress)
                   << L" eprocess=" << hex64(response.processObjectAddress)
                   << L" cidPid=" << hex64(response.cidUniqueProcess)
                   << L" cidTid=" << hex64(response.cidUniqueThread)
                   << L" list.flink=" << hex64(response.threadListEntryFlink)
                   << L" list.blink=" << hex64(response.threadListEntryBlink)
                   << L" start=" << hex64(response.startAddress)
                   << L" win32Start=" << hex64(response.win32StartAddress)
                   << L" ktProcess=" << hex64(response.kthreadProcessObject)
                   << std::dec << L"\n";
        std::wcout << L"stack initial=" << hex64(response.initialStack)
                   << L" limit=" << hex64(response.stackLimit)
                   << L" base=" << hex64(response.stackBase)
                   << L" kernel=" << hex64(response.kernelStack)
                   << L" io(read/write/other)=" << response.readOperationCount << L"/"
                   << response.writeOperationCount << L"/" << response.otherOperationCount
                   << L" bytes(read/write/other)=" << response.readTransferCount << L"/"
                   << response.writeTransferCount << L"/" << response.otherTransferCount << L"\n";
        std::wcout << L"offsets cid=0x" << std::hex << response.offsets.etCid
                   << L" list=0x" << response.offsets.etThreadListEntry
                   << L" start=0x" << response.offsets.etStartAddress
                   << L" win32Start=0x" << response.offsets.etWin32StartAddress
                   << L" ktProcess=0x" << response.offsets.ktProcess
                   << L" initialStack=0x" << response.offsets.ktInitialStack
                   << L" stackLimit=0x" << response.offsets.ktStackLimit
                   << L" stackBase=0x" << response.offsets.ktStackBase
                   << L" kernelStack=0x" << response.offsets.ktKernelStack
                   << std::dec << L"\n";
        printKernelGlobals(response.kernelGlobals);
        dumpWideText(L"detail", fixedWide(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
    }

    // buildProcessRuntimeFieldInput creates the variable input packet for EPROCESS sampling.
    // Inputs: parsed CLI args with --pid, --items, and optional --flags.
    // Processing: allocates a byte vector sized to the requested item count and
    // copies each validated item into the protocol array.
    // Returns: byte vector ready for DeviceIoControl input.
    std::vector<std::uint8_t> buildProcessRuntimeFieldInput(const NamedArgs& args)
    {
        const std::vector<RuntimeFieldCliItem> items = parseRuntimeFieldItems(requireOptionText(args, L"--items"));
        const std::size_t headerBytes = offsetof(KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST, items);
        std::vector<std::uint8_t> bytes(headerBytes + (items.size() * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST)), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST*>(bytes.data());
        request->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
        request->flags = getOptionU32(args, L"--flags", 0U);
        request->processId = requireOptionU32(args, L"--pid");
        request->itemCount = static_cast<unsigned long>(items.size());
        for (std::size_t index = 0U; index < items.size(); ++index)
        {
            request->items[index].runtimeItemId = items[index].runtimeItemId;
            request->items[index].offset = items[index].offset;
            request->items[index].size = items[index].size;
            request->items[index].flags = items[index].flags;
        }
        return bytes;
    }

    // buildThreadRuntimeFieldInput creates the variable input packet for ETHREAD sampling.
    // Inputs: parsed CLI args with --tid, optional --pid, --items, and --flags.
    // Processing: allocates a byte vector sized to the requested item count and
    // copies each validated item into the protocol array.
    // Returns: byte vector ready for DeviceIoControl input.
    std::vector<std::uint8_t> buildThreadRuntimeFieldInput(const NamedArgs& args)
    {
        const std::vector<RuntimeFieldCliItem> items = parseRuntimeFieldItems(requireOptionText(args, L"--items"));
        const std::size_t headerBytes = offsetof(KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST, items);
        std::vector<std::uint8_t> bytes(headerBytes + (items.size() * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST)), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST*>(bytes.data());
        request->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
        request->flags = getOptionU32(args, L"--flags", 0U);
        request->threadId = requireOptionU32(args, L"--tid");
        request->processId = getOptionU32(args, L"--pid", 0U);
        request->itemCount = static_cast<unsigned long>(items.size());
        for (std::size_t index = 0U; index < items.size(); ++index)
        {
            request->items[index].runtimeItemId = items[index].runtimeItemId;
            request->items[index].offset = items[index].offset;
            request->items[index].size = items[index].size;
            request->items[index].flags = items[index].flags;
        }
        return bytes;
    }


    // lowerWide returns a lowercase copy for command option tokens.
    // Inputs: arbitrary wide string from argv.
    // Processing: applies towlower one code unit at a time for stable ASCII-like
    // protocol option matching.
    // Returns: lowercase text used by integrity/HWID parsers.
    std::wstring lowerWide(std::wstring text)
    {
        for (wchar_t& ch : text)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
        return text;
    }

    // parseMandatoryIntegrityRid parses --rid or --level into a SID mandatory RID.
    // Inputs: named CLI args; accepted levels mirror Ksword5.1 UI presets.
    // Processing: --rid wins over --level; named levels map to SECURITY_MANDATORY_*.
    // Returns: RID value for R0 process/file integrity IOCTLs.
    std::uint32_t parseMandatoryIntegrityRid(const NamedArgs& args)
    {
        const std::wstring* ridText = getOptionText(args, L"--rid");
        if (ridText != nullptr)
        {
            return parseU32(ridText->c_str(), "integrity rid");
        }

        const std::wstring level = lowerWide(requireOptionText(args, L"--level"));
        if (level == L"untrusted") return SECURITY_MANDATORY_UNTRUSTED_RID;
        if (level == L"low") return SECURITY_MANDATORY_LOW_RID;
        if (level == L"medium") return SECURITY_MANDATORY_MEDIUM_RID;
        if (level == L"medium-plus" || level == L"mediumplus") return SECURITY_MANDATORY_MEDIUM_PLUS_RID;
        if (level == L"high") return SECURITY_MANDATORY_HIGH_RID;
        if (level == L"system") return SECURITY_MANDATORY_SYSTEM_RID;
        if (level == L"protected") return SECURITY_MANDATORY_PROTECTED_PROCESS_RID;
        throw std::invalid_argument("integrity level");
    }

    // normalizeFilePathForDriver converts Win32/UNC paths into the driver NT path
    // convention used by Ksword5.1 FileDock before sending file integrity IOCTLs.
    // Inputs: path from --path.
    // Processing: normalizes slashes and preserves already-normalized NT paths.
    // Returns: a non-empty path or throws when the input is empty.
    std::wstring normalizeFilePathForDriver(std::wstring path)
    {
        while (!path.empty() && std::iswspace(path.back()) != 0)
        {
            path.pop_back();
        }
        std::size_t first = 0U;
        while (first < path.size() && std::iswspace(path[first]) != 0)
        {
            ++first;
        }
        if (first != 0U)
        {
            path.erase(0U, first);
        }
        for (wchar_t& ch : path)
        {
            if (ch == L'/')
            {
                ch = L'\\';
            }
        }
        if (path.empty())
        {
            throw std::invalid_argument("path");
        }
        if (path.rfind(L"\\??\\", 0U) == 0U || path.rfind(L"\\Device\\", 0U) == 0U)
        {
            return path;
        }
        if (path.rfind(L"\\\\?\\", 0U) == 0U)
        {
            return L"\\??\\" + path.substr(4U);
        }
        if (path.rfind(L"\\\\", 0U) == 0U)
        {
            return L"\\??\\UNC\\" + path.substr(2U);
        }
        return L"\\??\\" + path;
    }

    // printProcessIntegrityResponse renders the fixed process-integrity response.
    // Inputs: shared response packet and DeviceIoControl byte count.
    // Processing: prints status, NTSTATUS and target RID.
    // Returns: no value.
    void printProcessIntegrityResponse(const KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"pid=" << response.processId
                   << L" integrityRid=0x" << std::hex << response.integrityRid
                   << L" lastStatus=0x" << static_cast<unsigned long>(response.lastStatus)
                   << std::dec << L"\n";
    }


    // printFileIntegrityResponse renders the fixed file-integrity response.
    // Inputs: shared response packet and bytesReturned.
    // Processing: prints status, NTSTATUS, target flags and path length.
    // Returns: no value.
    void printFileIntegrityResponse(const KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"flags=0x" << std::hex << response.flags
                   << L" integrityRid=0x" << response.integrityRid
                   << L" lastStatus=0x" << static_cast<unsigned long>(response.lastStatus)
                   << std::dec << L" pathLengthChars=" << response.pathLengthChars << L"\n";
    }

    // buildInjectRequestBuffer creates a METHOD_BUFFERED process injection packet.
    // Inputs: parsed args, inject type and payload bytes/entrypoint values.
    // Processing: allocates exactly header+payload bytes and fills the shared
    // protocol fields.
    // Returns: byte vector ready for IOCTL_KSWORD_ARK_INJECT_PROCESS.
    std::vector<std::uint8_t> buildInjectRequestBuffer(
        const NamedArgs& args,
        std::uint32_t injectType,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t entryPointAddress,
        std::uint64_t parameterAddress,
        unsigned long defaultFlags)
    {
        if (payload.empty() || payload.size() > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES)
        {
            throw std::out_of_range("inject payload");
        }
        const std::size_t headerSize = sizeof(KSWORD_ARK_INJECT_PROCESS_REQUEST) - sizeof(unsigned char);
        std::vector<std::uint8_t> buffer(headerSize + payload.size(), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_INJECT_PROCESS_REQUEST*>(buffer.data());
        request->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
        request->processId = requireOptionU32(args, L"--pid");
        request->injectType = injectType;
        request->flags = getOptionU32(args, L"--flags", defaultFlags);
        if (getOptionBool(args, L"--confirm"))
        {
            request->flags |= KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED;
        }
        if (getOptionBool(args, L"--wait-thread"))
        {
            request->flags |= KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD;
        }
        request->payloadBytes = static_cast<unsigned long>(payload.size());
        request->entryPointAddress = entryPointAddress;
        request->parameterAddress = parameterAddress;
        std::memcpy(request->payload, payload.data(), payload.size());
        return buffer;
    }

    // requireConfirmOption gates high-risk process injection and HWID control paths.
    // Inputs: parsed args and a command label.
    // Processing: throws when --confirm is absent.
    // Returns: no value when confirmation is present.
    void requireConfirmOption(const NamedArgs& args, const char* label)
    {
        if (!getOptionBool(args, L"--confirm"))
        {
            throw std::invalid_argument(label);
        }
    }

    // printInjectResponse renders the fixed process injection response.
    // Inputs: response packet and bytesReturned.
    // Processing: prints remote allocation and thread entry diagnostics.
    // Returns: no value.
    void printInjectResponse(const KSWORD_ARK_INJECT_PROCESS_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"pid=" << response.processId
                   << L" type=" << response.injectType
                   << L" flags=0x" << std::hex << response.flags
                   << L" entry=" << hex64(response.entryPointAddress)
                   << L" parameter=" << hex64(response.parameterAddress)
                   << L" remoteBase=" << hex64(response.remoteBaseAddress)
                   << L" remoteSize=" << hex64(response.remoteRegionSize)
                   << L" lastStatus=0x" << static_cast<unsigned long>(response.lastStatus)
                   << L" waitStatus=0x" << static_cast<unsigned long>(response.waitStatus)
                   << std::dec << L" bytesWritten=" << response.bytesWritten << L"\n";
    }

    // buildDllInjectPayload builds the UTF-16 LoadLibraryW payload.
    // Inputs: --dll path string.
    // Processing: includes the trailing NUL exactly like ArkDriverClient.
    // Returns: raw byte payload for R0 remote write.
    std::vector<std::uint8_t> buildDllInjectPayload(const std::wstring& dllPath)
    {
        if (dllPath.empty())
        {
            throw std::invalid_argument("dll path");
        }
        const std::size_t payloadBytes = (dllPath.size() + 1U) * sizeof(wchar_t);
        if (payloadBytes > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES)
        {
            throw std::out_of_range("dll path payload");
        }
        std::vector<std::uint8_t> payload(payloadBytes, 0U);
        std::memcpy(payload.data(), dllPath.c_str(), payloadBytes);
        return payload;
    }

    // resolveLoadLibraryW returns the current process LoadLibraryW address used by
    // the existing ArkDriverClient DLL-injection wrapper.
    // Inputs: none.
    // Processing: resolves kernel32!LoadLibraryW in this process.
    // Returns: function address as an integer or throws on failure.
    std::uint64_t resolveLoadLibraryW()
    {
        HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            throw std::runtime_error("kernel32.dll");
        }
        FARPROC loadLibrary = ::GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLibrary == nullptr)
        {
            throw std::runtime_error("LoadLibraryW");
        }
        return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(loadLibrary));
    }

    // commandProcessFamily implements all registered process IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: builds fixed or variable protocol requests from named args.
    // Returns: process exit code.
    int commandProcessFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: process requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"terminate")
        {
            KSWORD_ARK_TERMINATE_PROCESS_REQUEST request{};
            request.processId = requireOptionU32(args, L"--pid");
            request.exitStatus = static_cast<long>(getOptionU32(args, L"--exit-status", 0xC000013AUL));
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_TERMINATE_PROCESS", IOCTL_KSWORD_ARK_TERMINATE_PROCESS, &request, sizeof(request));
        }
        if (sub == L"suspend")
        {
            KSWORD_ARK_SUSPEND_PROCESS_REQUEST request{};
            request.processId = requireOptionU32(args, L"--pid");
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_SUSPEND_PROCESS", IOCTL_KSWORD_ARK_SUSPEND_PROCESS, &request, sizeof(request));
        }
        if (sub == L"set-ppl")
        {
            KSWORD_ARK_SET_PPL_LEVEL_REQUEST request{};
            request.processId = requireOptionU32(args, L"--pid");
            request.protectionLevel = static_cast<unsigned char>(requireOptionU32(args, L"--level") & 0xFFU);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_SET_PPL_LEVEL", IOCTL_KSWORD_ARK_SET_PPL_LEVEL, &request, sizeof(request));
        }
        if (sub == L"set-integrity")
        {
            KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST request{};
            KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION;
            request.processId = requireOptionU32(args, L"--pid");
            request.integrityRid = parseMandatoryIntegrityRid(args);
            request.flags = getOptionU32(args, L"--flags", 0U);
            if (getOptionBool(args, L"--confirm"))
            {
                request.flags |= KSWORD_ARK_PROCESS_INTEGRITY_FLAG_UI_CONFIRMED;
            }
            if (!sendFixedRequestResponse(
                    IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY,
                    L"IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY",
                    request,
                    response,
                    io,
                    GENERIC_READ | GENERIC_WRITE))
            {
                return normalizeIoctlRc(L"process set-integrity", io, 3);
            }
            printProcessIntegrityResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"inject-dll")
        {
            requireConfirmOption(args, "process inject-dll requires --confirm");
            KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
            const std::wstring& dllPath = requireOptionText(args, L"--dll");
            std::vector<std::uint8_t> payload = buildDllInjectPayload(dllPath);
            std::vector<std::uint8_t> request = buildInjectRequestBuffer(
                args,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                payload,
                resolveLoadLibraryW(),
                0ULL,
                KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD);
            std::vector<std::uint8_t> output(sizeof(response), 0U);
            const int rc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_INJECT_PROCESS",
                IOCTL_KSWORD_ARK_INJECT_PROCESS,
                request.data(),
                checkedDwordSize(request.size()),
                output,
                io,
                GENERIC_READ | GENERIC_WRITE);
            if (rc != 0)
            {
                return normalizeIoctlRc(L"process inject-dll", io, rc);
            }
            if (io.bytesReturned < sizeof(response))
            {
                std::wcerr << L"error: process inject-dll response too small: " << io.bytesReturned << L" bytes\n";
                return 4;
            }
            std::memcpy(&response, output.data(), sizeof(response));
            printInjectResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"inject-shellcode")
        {
            requireConfirmOption(args, "process inject-shellcode requires --confirm");
            KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
            std::vector<std::uint8_t> payload = readFileBytes(requireOptionText(args, L"--blob"), KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES);
            std::vector<std::uint8_t> request = buildInjectRequestBuffer(
                args,
                KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE,
                payload,
                0ULL,
                0ULL,
                0UL);
            std::vector<std::uint8_t> output(sizeof(response), 0U);
            const int rc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_INJECT_PROCESS",
                IOCTL_KSWORD_ARK_INJECT_PROCESS,
                request.data(),
                checkedDwordSize(request.size()),
                output,
                io,
                GENERIC_READ | GENERIC_WRITE);
            if (rc != 0)
            {
                return normalizeIoctlRc(L"process inject-shellcode", io, rc);
            }
            if (io.bytesReturned < sizeof(response))
            {
                std::wcerr << L"error: process inject-shellcode response too small: " << io.bytesReturned << L" bytes\n";
                return 4;
            }
            std::memcpy(&response, output.data(), sizeof(response));
            printInjectResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"enum")
        {
            KSWORD_ARK_ENUM_PROCESS_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.startPid = getOptionU32(args, L"--start-pid", 0U);
            request.endPid = getOptionU32(args, L"--end-pid", 0U);
            const std::uint32_t limit = getOptionU32(args, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_PROCESS", IOCTL_KSWORD_ARK_ENUM_PROCESS, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY);
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: process enum response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_PROCESS_ENTRY), L"process enum"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, limit);
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_PROCESS_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                printProcessEnumRow(*entry);
            }
            return 0;
        }
        if (sub == L"set-visibility")
        {
            KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST request{};
            KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE response{};
            request.processId = getOptionU32(args, L"--pid", 0U);
            request.action = requireOptionU32(args, L"--action");
            request.flags = getOptionU32(args, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY, L"IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId
                       << L" action=" << request.action
                       << L" requestFlags=0x" << std::hex << request.flags
                       << std::dec << L" hiddenCount=" << response.hiddenCount << L"\n";
            return 0;
        }
        if (sub == L"set-special-flags")
        {
            KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST request{};
            KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE response{};
            request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
            request.processId = requireOptionU32(args, L"--pid");
            request.action = requireOptionU32(args, L"--action");
            request.flags = getOptionU32(args, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS, L"IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" action=" << response.action
                       << L" appliedFlags=0x" << std::hex << response.appliedFlags
                       << std::dec << L" touchedThreadCount=" << response.touchedThreadCount << L"\n";
            return 0;
        }
        if (sub == L"dkom")
        {
            KSWORD_ARK_DKOM_PROCESS_REQUEST request{};
            KSWORD_ARK_DKOM_PROCESS_RESPONSE response{};
            request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
            request.processId = requireOptionU32(args, L"--pid");
            request.action = getOptionU32(args, L"--action", KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE);
            request.flags = getOptionU32(args, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_DKOM_PROCESS, L"IOCTL_KSWORD_ARK_DKOM_PROCESS", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" action=" << response.action
                       << L" removedEntries=" << response.removedEntries
                       << L" pspCidTable=" << hex64(response.pspCidTableAddress)
                       << L" processObject=" << hex64(response.processObjectAddress) << L"\n";
            return 0;
        }
        if (sub == L"crossview")
        {
            KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST request{};
            request.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL);
            request.startPid = getOptionU32(args, L"--start-pid", 0U);
            request.endPid = getOptionU32(args, L"--end-pid", 0U);
            request.maxNodes = getOptionU32(args, L"--max-nodes", KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
            const std::uint32_t limit = getOptionU32(args, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW", IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"process crossview", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: process crossview response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW), L"process crossview"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"dynMask=0x" << std::hex << response->dynDataCapabilityMask
                       << L" missingMask=0x" << response->missingCapabilityMask << std::dec << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, limit);
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_PROCESS_CROSSVIEW_ROW*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] pid=" << row->processId
                           << L" ppid=" << row->parentProcessId
                           << L" source=0x" << std::hex << row->sourceMask
                           << L" anomaly=0x" << row->anomalyFlags
                           << L" object=" << hex64(row->objectAddress)
                           << L" start=" << hex64(row->startAddress)
                           << std::dec << L" confidence=" << row->confidence
                           << L" image='" << fixedAnsi(row->imageName, sizeof(row->imageName)).c_str()
                           << L"' detail='" << fixedAnsi(row->detail, sizeof(row->detail)).c_str() << L"'\n";
            }
            return 0;
        }
        if (sub == L"detail")
        {
            // process detail:
            // - Inputs: --pid selects the process and --flags selects fixed
            //   read-only EPROCESS detail groups.
            // - Processing: sends the fixed detail request through the shared
            //   protocol and prints every returned identity/object/global field.
            // - Returns: CLI status from the transport/protocol parser.
            KSWORD_ARK_PROCESS_DETAIL_REQUEST request{};
            KSWORD_ARK_PROCESS_DETAIL_RESPONSE response{};
            request.version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(args, L"--pid");
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL, L"IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL", request, response, io))
            {
                return normalizeIoctlRc(L"process detail", io, 3);
            }
            printProcessDetail(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"runtime-fields")
        {
            // process runtime-fields:
            // - Inputs: --pid and --items id:offset:size[:flags] rows.
            // - Processing: builds the variable METHOD_BUFFERED input packet
            //   and receives a bounded array of field sample rows.
            // - Returns: zero after printing rows, non-zero on parse/transport error.
            std::vector<std::uint8_t> input = buildProcessRuntimeFieldInput(args);
            std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
            const int rc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS",
                IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS,
                input.data(),
                checkedDwordSize(input.size()),
                buffer,
                io);
            if (rc != 0)
            {
                return normalizeIoctlRc(L"process runtime-fields", io, rc);
            }
            return printRuntimeFieldSampleRows(buffer, io, args, L"process runtime-fields");
        }
        std::wcerr << L"error: unknown process subcommand '" << sub << L"'\n";
        return 1;
    }



    // printPageTableInfo renders translate/query-pte shared response data.
    // Inputs: page table info and bytesReturned.
    // Processing: prints every relevant resolved address and raw entry value.
    // Returns: no value.
    void printPageTableInfo(const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO& info, DWORD bytesReturned)
    {
        printResponseBanner(info.version, info.queryStatus, info.walkStatus, bytesReturned);
        std::wcout << L"pid=" << info.processId
                   << L" fields=0x" << std::hex << info.fieldFlags
                   << L" lookup=0x" << static_cast<unsigned long>(info.lookupStatus)
                   << L" va=" << hex64(info.virtualAddress)
                   << L" pa=" << hex64(info.physicalAddress)
                   << L" cr3=" << hex64(info.cr3PhysicalAddress)
                   << std::dec << L" resolved=" << info.resolved
                   << L" pageSize=" << info.pageSize
                   << L" largePageType=" << info.largePageType << L"\n";
        std::wcout << L"indexes pml4=" << info.pml4Index
                   << L" pdpt=" << info.pdptIndex
                   << L" pd=" << info.pdIndex
                   << L" pt=" << info.ptIndex << L"\n";
        std::wcout << L"entries pml4e=" << hex64(info.pml4eValue)
                   << L" pdpte=" << hex64(info.pdpteValue)
                   << L" pde=" << hex64(info.pdeValue)
                   << L" pte=" << hex64(info.pteValue) << L"\n";
    }

    // commandMemoryFamily implements all registered memory IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: supports scalar args and explicit --hex/--data-file writes.
    // Returns: process exit code.
    int commandMemoryFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: memory requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        const bool dump = getOptionBool(args, L"--hexdump");
        IoctlResult io{};

        if (sub == L"query-va")
        {
            KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST request{};
            KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE response{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(args, L"--pid");
            request.baseAddress = requireOptionU64(args, L"--address");
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY, L"IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY", request, response, io)) return 3;
            printResponseBanner(response.version, response.queryStatus, response.basicStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" fields=0x" << std::hex << response.fieldFlags
                       << L" requested=" << hex64(response.requestedBaseAddress)
                       << L" base=" << hex64(response.baseAddress)
                       << L" allocationBase=" << hex64(response.allocationBase)
                       << std::dec << L" regionSize=" << response.regionSize
                       << L" protect=0x" << std::hex << response.protect
                       << L" state=0x" << response.state << L" type=0x" << response.type << std::dec << L"\n";
            dumpWideText(L"mappedFile", fixedWide(response.mappedFileName, KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS));
            return 0;
        }
        if (sub == L"read-va")
        {
            KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.processId = ((request.flags & KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS) != 0UL)
                ? getOptionU32(args, L"--pid", 0U)
                : requireOptionU32(args, L"--pid");
            request.baseAddress = requireOptionU64(args, L"--address");
            request.bytesToRead = requireOptionU32(args, L"--bytes");
            if (request.bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES) { std::wcerr << L"error: --bytes exceeds protocol max\n"; return 1; }
            constexpr std::size_t headerSize = offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data);
            std::vector<std::uint8_t> buffer(headerSize + request.bytesToRead, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY", IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: read-va response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(buffer.data());
            printResponseBanner(response->version, response->readStatus, response->copyStatus, io.bytesReturned);
            std::wcout << L"pid=" << response->processId << L" fields=0x" << std::hex << response->fieldFlags
                       << L" requestFlags=0x" << request.flags
                       << L" copyStatus=0x" << static_cast<unsigned long>(response->copyStatus)
                       << L" source=" << std::dec << response->source
                       << L" requested=" << response->requestedBytes << L" read=" << response->bytesRead
                       << L" max=" << response->maxBytesPerRequest
                       << L" address=" << hex64(response->requestedBaseAddress) << L"\n";
            const std::size_t dataBytes = std::min<std::size_t>(static_cast<std::size_t>(io.bytesReturned) - headerSize, response->bytesRead);
            if (dump) hexdump(buffer.data() + headerSize, dataBytes);
            return 0;
        }
        if (sub == L"write-va")
        {
            const std::vector<std::uint8_t> bytes = loadBytesFromHexOrFile(args, L"--hex", L"--data-file", KSWORD_ARK_MEMORY_WRITE_MAX_BYTES, true);
            if (bytes.empty()) { std::wcerr << L"error: write-va payload is empty\n"; return 1; }
            constexpr std::size_t headerSize = offsetof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data);
            std::vector<std::uint8_t> input(headerSize + bytes.size(), 0U);
            auto* request = reinterpret_cast<KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*>(input.data());
            request->flags = getOptionU32(args, L"--flags", KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED);
            request->processId = ((request->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS) != 0UL)
                ? getOptionU32(args, L"--pid", 0U)
                : requireOptionU32(args, L"--pid");
            request->baseAddress = requireOptionU64(args, L"--address");
            request->bytesToWrite = static_cast<unsigned long>(bytes.size());
            std::copy(bytes.begin(), bytes.end(), request->data);
            KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE response{};
            DriverHandle handle = openDriverOrReport();
            if (!handle.valid()) return 2;
            io = sendIoctl(handle, IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY, input.data(), checkedDwordSize(input.size()), &response, sizeof(response));
            if (!io.ok) { printWin32Error(L"IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY", io.win32Error); return 3; }
            if (io.bytesReturned < sizeof(response)) { std::wcerr << L"error: write-va response too small\n"; return 4; }
            printResponseBanner(response.version, response.writeStatus, response.copyStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" fields=0x" << std::hex << response.fieldFlags
                       << L" requestFlags=0x" << request->flags
                       << L" copyStatus=0x" << static_cast<unsigned long>(response.copyStatus)
                       << L" source=" << std::dec << response.source
                       << L" address=" << hex64(response.requestedBaseAddress)
                       << L" requested=" << response.requestedBytes
                       << L" written=" << response.bytesWritten << L" max=" << response.maxBytesPerRequest << L"\n";
            return 0;
        }
        if (sub == L"read-phys")
        {
            KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST request{};
            request.physicalAddress = requireOptionU64(args, L"--address");
            request.bytesToRead = requireOptionU32(args, L"--bytes");
            if (request.bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES) { std::wcerr << L"error: --bytes exceeds protocol max\n"; return 1; }
            // 物理读响应有两个互不等价的数字，不能互相替代：
            // headerSize = sizeof-sizeof(data) = 55，驱动用它判断“输出缓冲还剩多少可用”，
            //   并按 55 + bytesCopied 回报 BytesWritten，所以分配和长度下限校验必须用它；
            // dataOffset = offsetof(data) = 48，才是驱动 MmCopyMemory 真正写入负载的位置。
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE) - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)nullptr)->data);
            constexpr std::size_t dataOffset = offsetof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE, data);
            std::vector<std::uint8_t> buffer(headerSize + request.bytesToRead, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY", IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: read-phys response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*>(buffer.data());
            printResponseBanner(response->version, response->readStatus, response->copyStatus, io.bytesReturned);
            std::wcout << L"fields=0x" << std::hex << response->fieldFlags
                       << L" address=" << hex64(response->requestedPhysicalAddress)
                       << std::dec << L" requested=" << response->requestedBytes
                       << L" read=" << response->bytesRead << L" max=" << response->maxBytesPerRequest << L"\n";
            // 负载起点只能是 data 的真实偏移，用 headerSize 会整体错位 7 字节；
            // 长度只用 bytesRead 与缓冲余量取小，不能由基于 55 约定的 bytesReturned 反推。
            const std::size_t dataBytes = std::min<std::size_t>(response->bytesRead, buffer.size() - dataOffset);
            if (dump) hexdump(buffer.data() + dataOffset, dataBytes);
            return 0;
        }
        if (sub == L"write-phys")
        {
            const std::vector<std::uint8_t> bytes = loadBytesFromHexOrFile(args, L"--hex", L"--data-file", KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES, true);
            if (bytes.empty()) { std::wcerr << L"error: write-phys payload is empty\n"; return 1; }
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST) - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)nullptr)->data);
            std::vector<std::uint8_t> input(headerSize + bytes.size(), 0U);
            auto* request = reinterpret_cast<KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*>(input.data());
            request->flags = getOptionU32(args, L"--flags", KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED);
            request->physicalAddress = requireOptionU64(args, L"--address");
            request->bytesToWrite = static_cast<unsigned long>(bytes.size());
            std::copy(bytes.begin(), bytes.end(), request->data);
            KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE response{};
            DriverHandle handle = openDriverOrReport();
            if (!handle.valid()) return 2;
            io = sendIoctl(handle, IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY, input.data(), checkedDwordSize(input.size()), &response, sizeof(response));
            if (!io.ok) { printWin32Error(L"IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY", io.win32Error); return 3; }
            if (io.bytesReturned < sizeof(response)) { std::wcerr << L"error: write-phys response too small\n"; return 4; }
            printResponseBanner(response.version, response.writeStatus, response.copyStatus, io.bytesReturned);
            std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                       << L" address=" << hex64(response.requestedPhysicalAddress)
                       << std::dec << L" requested=" << response.requestedBytes
                       << L" written=" << response.bytesWritten << L" max=" << response.maxBytesPerRequest << L"\n";
            return 0;
        }
        if (sub == L"translate-va" || sub == L"query-pte")
        {
            KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.processId = requireOptionU32(args, L"--pid");
            request.virtualAddress = requireOptionU64(args, L"--address");
            if (sub == L"translate-va")
            {
                KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE response{};
                if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS, L"IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS", request, response, io)) return 3;
                printPageTableInfo(response.info, io.bytesReturned);
            }
            else
            {
                KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE response{};
                if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY, L"IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY", request, response, io))
                {
                    return normalizeIoctlRc(L"memory pte", io, 3);
                }
                printPageTableInfo(response.info, io.bytesReturned);
            }
            return 0;
        }

        if (sub == L"scan-kexec")
        {
            KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL);
            request.maxEntries = getOptionU32(args, L"--max-entries", 4096U);
            request.startAddress = getOptionU64(args, L"--start", 0ULL);
            request.endAddress = getOptionU64(args, L"--end", 0ULL);
            const std::uint32_t limit = getOptionU32(args, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY", IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"memory kernel-exec", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY);
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: scan-kexec response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY), L"scan-kexec"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"moduleCount=" << response->moduleCount << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, limit);
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] va=" << hex64(entry->virtualAddress)
                           << L" pages=" << entry->pageCount << L" pageSize=" << entry->pageSize
                           << L" flags=0x" << std::hex << entry->effectiveFlags
                           << L" risk=0x" << entry->riskFlags
                           << L" moduleBase=" << hex64(entry->moduleBase)
                           << std::dec << L" owner=" << entry->ownerKind
                           << L" path='" << fixedWide(entry->modulePath, KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS) << L"'\n";
            }
            return 0;
        }
        if (sub == L"scan-evidence")
        {
            KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS);
            request.startAddress = getOptionU64(args, L"--start", 0ULL);
            request.endAddress = getOptionU64(args, L"--end", 0ULL);
            request.maxBytes = getOptionU64(args, L"--max-bytes", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES);
            request.maxBigPoolRows = getOptionU32(args, L"--max-bigpool-rows", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS);
            request.sampleBytes = getOptionU32(args, L"--sample-bytes", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES);
            const std::uint32_t limit = getOptionU32(args, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE", IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"memory evidence", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: scan-evidence response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->rowSize, sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW), L"scan-evidence"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
            std::wcout << L"responseFlags=0x" << std::hex << response->responseFlags
                       << L" sourceFlags=0x" << response->sourceFlags
                       << std::dec << L" bytesScanned=" << response->bytesScanned
                       << L" modules=" << response->moduleCount << L" bigPoolSeen=" << response->bigPoolRowsSeen << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedRows, available, limit);
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW*>(buffer.data() + headerSize + (i * response->rowSize));
                std::wcout << L"  [" << i << L"] kind=" << row->evidenceKind
                           << L" va=" << hex64(row->virtualAddress)
                           << L" size=" << row->regionSize
                           << L" pageSize=" << row->pageSize
                           << L" perm=0x" << std::hex << row->permissionFlags
                           << L" risk=0x" << row->riskFlags
                           << L" moduleBase=" << hex64(row->moduleBase)
                           << L" ownerAddress=" << hex64(row->ownerAddress)
                           << L" last=0x" << static_cast<unsigned long>(row->lastStatus)
                           << std::dec << L" owner='" << fixedWide(row->ownerName, KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS)
                           << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown memory subcommand '" << sub << L"'\n";
        return 1;
    }



    // printFileInfoResponse renders the fixed file-info response.
    // Inputs: response struct and bytesReturned.
    // Processing: prints status, timestamps and optional names.
    // Returns: no value.
    void printFileInfoResponse(const KSWORD_ARK_QUERY_FILE_INFO_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.queryStatus, response.basicStatus, bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" open=0x" << static_cast<unsigned long>(response.openStatus)
                   << L" object=0x" << static_cast<unsigned long>(response.objectStatus)
                   << L" name=0x" << static_cast<unsigned long>(response.nameStatus)
                   << L" attrs=0x" << response.fileAttributes
                   << L" fileObject=" << hex64(response.fileObjectAddress)
                   << L" sectionPointers=" << hex64(response.sectionObjectPointersAddress)
                   << L" dataSection=" << hex64(response.dataSectionObjectAddress)
                   << L" imageSection=" << hex64(response.imageSectionObjectAddress)
                   << std::dec << L" allocationSize=" << response.allocationSize
                   << L" endOfFile=" << response.endOfFile << L"\n";
        dumpWideText(L"ntPath", fixedWide(response.ntPath, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS));
        dumpWideText(L"objectName", fixedWide(response.objectName, KSWORD_ARK_FILE_INFO_OBJECT_NAME_MAX_CHARS));
    }

    // queryMinifilterInventory issues the read-only fltMgr public inventory IOCTL.
    // Inputs: parsed options for flags/max rows/visible row limit.
    // Processing: validates the variable response and prints filter/volume rows.
    // Returns: CLI exit code, including graceful unavailable status for old drivers.
    int queryMinifilterInventory(const NamedArgs& args)
    {
        KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL);
        request.maxRows = getOptionU32(args, L"--max-rows", 256U);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY", IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"file minifilter", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY), L"minifilter inventory"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"size=" << response->size << L" flags=0x" << std::hex << response->flags << std::dec << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] status=" << row->status
                       << L" fields=0x" << std::hex << row->fieldFlags
                       << L" source=0x" << row->sourceFlags
                       << L" filter=" << hex64(row->filterObject)
                       << L" volume=" << hex64(row->volumeObject)
                       << std::dec << L" instances=" << row->instanceCount
                       << L" volumeInstances=" << row->volumeBindingInstanceCount
                       << L" frameId=" << row->frameId
                       << L" name='" << fixedWide(row->filterName, KSWORD_ARK_MINIFILTER_INVENTORY_NAME_CHARS)
                       << L"' altitude='" << fixedWide(row->altitude, KSWORD_ARK_MINIFILTER_INVENTORY_ALTITUDE_CHARS)
                       << L"' volumeName='" << fixedWide(row->volumeName, KSWORD_ARK_MINIFILTER_INVENTORY_VOLUME_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // buildStorageRequest normalizes common storage audit CLI options.
    // Inputs: parsed args and optional --volume path text.
    // Processing: fills protocol version, flags, row/depth limits and fixed path.
    // Returns: request packet ready for a read-only storage IOCTL.
    KSWORD_ARK_STORAGE_AUDIT_REQUEST buildStorageRequest(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT);
        request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS);
        request.maxDepth = getOptionU32(args, L"--max-depth", KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH);
        if (const std::wstring* volume = getOptionText(args, L"--volume"))
        {
            request.volumePathLengthChars = boundedPathLength(*volume, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS);
            copyWideToFixed(request.volumePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, *volume);
        }
        return request;
    }

    // queryVolumeStackAudit prints R0 volume/device-stack audit rows.
    // Inputs: parsed storage options.
    // Processing: uses the read-only volume stack IOCTL and prints bounded rows.
    // Returns: CLI exit code.
    int queryVolumeStackAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT", IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"storage volume stack", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE) - sizeof(KSWORD_ARK_VOLUME_STACK_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->rowSize, sizeof(KSWORD_ARK_VOLUME_STACK_ROW), L"volume stack"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                   << std::dec << L" fvevolPresent=" << response->fvevolPresent
                   << L" fvevolPosition=" << response->fvevolPosition << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_VOLUME_STACK_ROW*>(buffer.data() + headerSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] stackIndex=" << row->stackIndex
                       << L" deviceType=0x" << std::hex << row->deviceType
                       << L" fields=0x" << row->fieldFlags
                       << L" risk=0x" << row->riskFlags
                       << L" device=" << hex64(row->deviceObjectAddress)
                       << L" driverObject=" << hex64(row->driverObjectAddress)
                       << L" attached=" << hex64(row->attachedDeviceAddress)
                       << std::dec << L" confidence=" << row->confidence
                       << L" driver='" << fixedWide(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS)
                       << L"' volume='" << fixedWide(row->volumeDeviceName, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryBitlockerAudit prints safe BitLocker/FVE status rows only.
    // Inputs: parsed storage options.
    // Processing: never serializes key material; it only renders protocol labels.
    // Returns: CLI exit code.
    int queryBitlockerAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT", IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"file bitlocker", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE) - sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->rowSize, sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW), L"bitlocker fve"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_BITLOCKER_FVE_ROW*>(buffer.data() + headerSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] fields=0x" << std::hex << row->fieldFlags
                       << L" risk=0x" << row->riskFlags
                       << std::dec << L" fvevolPresent=" << row->fvevolPresent
                       << L" fvevolPosition=" << row->fvevolStackPosition
                       << L" protection=" << row->protectionStatus
                       << L" conversion=" << row->conversionStatus
                       << L" lock=" << row->lockStatus
                       << L" confidence=" << row->confidence
                       << L" volume='" << fixedWide(row->volumeDeviceName, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryMountMgrAudit prints drive-letter and Volume GUID cross-view rows.
    // Inputs: parsed storage options.
    // Processing: renders only symbolic mapping evidence.
    // Returns: CLI exit code.
    int queryMountMgrAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT", IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"storage mountmgr", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE) - sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->rowSize, sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW), L"mountmgr mapping"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_MOUNTMGR_MAPPING_ROW*>(buffer.data() + headerSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] fields=0x" << std::hex << row->fieldFlags
                       << L" risk=0x" << row->riskFlags
                       << std::dec << L" confidence=" << row->confidence
                       << L" drive='" << fixedWide(row->driveLetter, KSWORD_ARK_STORAGE_DRIVE_LETTER_CHARS)
                       << L"' guid='" << fixedWide(row->volumeGuid, KSWORD_ARK_STORAGE_VOLUME_GUID_CHARS)
                       << L"' nt='" << fixedWide(row->ntDevicePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryFilesystemIntegrityAudit prints FS dispatch/FastIo owner evidence.
    // Inputs: parsed storage options.
    // Processing: emits read-only driver/slot/risk rows.
    // Returns: CLI exit code.
    int queryFilesystemIntegrityAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT", IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"file storage filesystem integrity", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->rowSize, sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW), L"filesystem integrity"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW*>(buffer.data() + headerSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] fs=" << row->fileSystemKind
                       << L" slotType=" << row->slotType
                       << L" slotIndex=" << row->slotIndex
                       << L" risk=0x" << std::hex << row->riskFlags
                       << L" driverObject=" << hex64(row->driverObjectAddress)
                       << L" target=" << hex64(row->targetAddress)
                       << L" ownerBase=" << hex64(row->ownerModuleBase)
                       << std::dec << L" confidence=" << row->confidence
                       << L" driver='" << fixedWide(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS)
                       << L"' owner='" << fixedWide(row->ownerModuleName, KSWORD_ARK_STORAGE_MODULE_NAME_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // buildNetworkAuditRequest fills the common bounded network audit request.
    // Inputs: parsed args with optional flags/max rows.
    // Processing: uses conservative protocol defaults and never requests mutation.
    // Returns: fixed query request for network endpoint/WFP/NDIS IOCTLs.
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST buildNetworkAuditRequest(const NamedArgs& args)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL);
        request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS);
        return request;
    }

    // networkAuditStatusText 作用：把网络审计协议状态转换成稳定的 CLI token。
    // 输入：shared/driver 定义的 KSWORD_ARK_NETWORK_STATUS_*。
    // 处理：未知值单独标记，避免把 DeviceIoControl 成功误报成 R0 可用。
    // 返回：便于脚本解析的英文状态名。
    const wchar_t* networkAuditStatusText(const unsigned long status)
    {
        switch (status)
        {
        case KSWORD_ARK_NETWORK_STATUS_APPLIED: return L"applied";
        case KSWORD_ARK_NETWORK_STATUS_CLEARED: return L"cleared";
        case KSWORD_ARK_NETWORK_STATUS_DISABLED: return L"disabled";
        case KSWORD_ARK_NETWORK_STATUS_INVALID_RULE: return L"invalid-rule";
        case KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE: return L"wfp-unavailable";
        case KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED: return L"operation-failed";
        case KSWORD_ARK_NETWORK_STATUS_AUDIT_UNAVAILABLE: return L"audit-unavailable";
        case KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB: return L"audit-stub";
        case KSWORD_ARK_NETWORK_STATUS_UNKNOWN:
        default:
            return L"unknown";
        }
    }

    constexpr std::uint32_t kNetworkStatusBufferOverflow = 0x80000005UL;
    constexpr std::uint32_t kNetworkStatusPartialCopy = 0x8000000DUL;

    // isRetainableNetworkInventoryPartial 作用：识别 WFP/NDIS 可保留的部分快照。
    // 输入：协议状态、lastStatus 和返回行数。
    // 处理：仅接受 OPERATION_FAILED + PARTIAL_COPY/BUFFER_OVERFLOW + 非零行。
    // 返回：true 表示 CLI 可输出这些合法行，但必须明确标记 partial。
    bool isRetainableNetworkInventoryPartial(
        const unsigned long status,
        const long lastStatus,
        const unsigned long returnedRows) noexcept
    {
        const std::uint32_t normalizedStatus =
            static_cast<std::uint32_t>(lastStatus);
        return status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED &&
            returnedRows != 0UL &&
            (normalizedStatus == kNetworkStatusPartialCopy ||
             normalizedStatus == kNetworkStatusBufferOverflow);
    }

    // validateNetworkAuditHeader 作用：校验 TCP/UDP/WFP/NDIS 共用响应头语义。
    // 输入：响应头字段、实际返回字节数、固定头大小和命令标签。
    // 处理：检查版本/大小/状态/来源位/计数/预算，拒绝损坏或错版驱动数据。
    // 返回：true 表示后续可以调用 validateVariable 解析明细行。
    bool validateNetworkAuditHeader(
        const unsigned long version,
        const unsigned long size,
        const unsigned long status,
        const unsigned long flags,
        const unsigned long totalRows,
        const unsigned long returnedRows,
        const unsigned long sourceFlags,
        const unsigned long budgetRows,
        const DWORD bytesReturned,
        const std::size_t headerSize,
        const wchar_t* featureLabel)
    {
        constexpr unsigned long knownSourceFlags =
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        const bool valid =
            version == KSWORD_ARK_NETWORK_PROTOCOL_VERSION &&
            size == headerSize &&
            size <= bytesReturned &&
            status <= KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB &&
            (flags & ~KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL) == 0UL &&
            (sourceFlags & ~knownSourceFlags) == 0UL &&
            returnedRows <= totalRows &&
            (budgetRows == 0UL || returnedRows <= budgetRows);
        if (!valid)
        {
            std::wcerr << featureLabel
                       << L": invalid network audit response"
                       << L" version=" << version
                       << L" size=" << size
                       << L" status=" << status
                       << L" flags=0x" << std::hex << flags
                       << L" sourceFlags=0x" << sourceFlags
                       << std::dec << L" total=" << totalRows
                       << L" returned=" << returnedRows
                       << L" budgetRows=" << budgetRows
                       << L" bytesReturned=" << bytesReturned << L"\n";
        }
        return valid;
    }

    // printNetworkAuditState 作用：输出 R0 可用性和明确降级原因。
    // 输入：协议状态、NTSTATUS、来源、预算、generation、计数和 partial 接受状态。
    // 处理：APPLIED 或协议认可的 partial 行标记 usableR0=1，并单列 complete/truncated。
    // 返回：无返回值。
    void printNetworkAuditState(
        const unsigned long status,
        const long lastStatus,
        const unsigned long sourceFlags,
        const unsigned long budgetRows,
        const unsigned long generation,
        const unsigned long totalRows,
        const unsigned long returnedRows,
        const bool partialRowsAccepted)
    {
        const bool complete =
            status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            totalRows == returnedRows;
        const bool appliedTruncated =
            status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            totalRows > returnedRows;
        const bool rowsUsable =
            status == KSWORD_ARK_NETWORK_STATUS_APPLIED ||
            partialRowsAccepted;
        const bool partial = partialRowsAccepted || appliedTruncated;
        const bool truncated = rowsUsable &&
            (totalRows > returnedRows ||
             (partialRowsAccepted &&
              static_cast<std::uint32_t>(lastStatus) ==
                  kNetworkStatusBufferOverflow));
        const wchar_t* scopeText = L"pdb/private";
        if (sourceFlags == KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE)
        {
            scopeText = L"none";
        }
        else if (sourceFlags == KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE)
        {
            scopeText = L"runtime-state-only";
        }
        std::wcout << L"evidence=R0-header"
                   << L" usableR0=" << (rowsUsable ? 1 : 0)
                   << L" completeR0=" << (complete ? 1 : 0)
                   << L" partial=" << (partial ? 1 : 0)
                   << L" truncated=" << (truncated ? 1 : 0)
                   << L" retainedRows=" << (rowsUsable ? returnedRows : 0UL)
                   << L" protocolStatus=" << networkAuditStatusText(status)
                   << L"(" << status << L")"
                   << L" scope=" << scopeText
                   << L" lastStatus=0x" << std::hex << static_cast<unsigned long>(lastStatus)
                   << L" sourceFlags=0x" << sourceFlags
                   << std::dec << L" budgetRows=" << budgetRows
                   << L" generation=" << generation << L"\n";
    }

    // networkAuditAddressToText 作用：格式化 R0 endpoint 行中的 IPv4/IPv6 地址。
    // 输入：共享协议地址族和固定 16 字节地址。
    // 处理：只调用 documented InetNtopW，不读取任何私有网络结构。
    // 返回：可直接与主机字节序端口拼接的地址文本。
    std::wstring networkAuditAddressToText(
        const unsigned long addressFamily,
        const unsigned char addressBytes[16])
    {
        wchar_t addressText[INET6_ADDRSTRLEN]{};
        if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4)
        {
            IN_ADDR address{};
            std::memcpy(&address, addressBytes, sizeof(address));
            return ::InetNtopW(AF_INET, &address, addressText, static_cast<DWORD>(std::size(addressText))) != nullptr
                ? std::wstring(addressText)
                : std::wstring(L"<invalid-ipv4>");
        }
        if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6)
        {
            IN6_ADDR address{};
            std::memcpy(&address, addressBytes, sizeof(address));
            return ::InetNtopW(AF_INET6, &address, addressText, static_cast<DWORD>(std::size(addressText))) != nullptr
                ? std::wstring(addressText)
                : std::wstring(L"<invalid-ipv6>");
        }
        return L"<unknown-address-family>";
    }

    // networkNdisObjectKindText 作用：把 NDIS 行类型转换成可审计 token。
    // UNKNOWN 是 collector 无法证明对象边界时的合法降级证据，不能伪称 miniport/LWF。
    const wchar_t* networkNdisObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN: return L"unknown-unproven";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT: return L"miniport";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER: return L"filter";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL: return L"protocol";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING: return L"binding";
        default: return L"invalid";
        }
    }

    // networkWfpObjectKindText 作用：把 WFP 行类型转换成稳定的可审计 token。
    const wchar_t* networkWfpObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER: return L"provider";
        case KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER: return L"sublayer";
        case KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER: return L"filter";
        case KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT: return L"callout";
        default: return L"invalid";
        }
    }

    // queryNetworkEndpoints prints TCP or UDP R0 endpoint audit rows.
    // Inputs: parsed args plus IOCTL code and display labels.
    // Processing: validates variable response rows and renders endpoint evidence.
    // Returns: CLI exit code.
    int queryNetworkEndpoints(const NamedArgs& args, DWORD code, const wchar_t* ioctlLabel, const wchar_t* featureLabel)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkAuditRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(ioctlLabel, code, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(featureLabel, io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*>(buffer.data());
        if (!validateNetworkAuditHeader(
            response->version,
            response->size,
            response->status,
            response->flags,
            response->totalRowCount,
            response->returnedRowCount,
            response->sourceFlags,
            response->budgetRows,
            io.bytesReturned,
            headerSize,
            featureLabel))
        {
            return 4;
        }
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW), featureLabel); }
        catch (...) { return 4; }
        if (available < response->returnedRowCount)
        {
            std::wcerr << featureLabel << L": returned rows exceed response bytes\n";
            return 4;
        }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRowCount, response->returnedRowCount, response->entrySize, io.bytesReturned);
        printNetworkAuditState(
            response->status,
            response->lastStatus,
            response->sourceFlags,
            response->budgetRows,
            response->generation,
            response->totalRowCount,
            response->returnedRowCount,
            false);
        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED)
        {
            std::wcerr
                << L"unsupported / unavailable: "
                << featureLabel
                << L" did not return an APPLIED endpoint snapshot\n";
            return 5;
        }
        const std::size_t parsed = responseCountLimit(response->returnedRowCount, available, getOptionU32(args, L"--limit", 128U));
        const unsigned long expectedProtocol =
            code == IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS
            ? KSWORD_ARK_NETWORK_PROTOCOL_TCP
            : KSWORD_ARK_NETWORK_PROTOCOL_UDP;
        constexpr unsigned long knownRowFlags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
        constexpr unsigned long knownSourceFlags =
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        for (std::size_t i = 0; i < response->returnedRowCount; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_NETWORK_ENDPOINT_ROW*>(buffer.data() + headerSize + (i * response->entrySize));
            const bool knownFamily =
                row->addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN ||
                row->addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 ||
                row->addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
            if (!knownFamily ||
                row->protocol != expectedProtocol ||
                (row->flags & ~knownRowFlags) != 0UL ||
                (row->sourceFlags & ~knownSourceFlags) != 0UL)
            {
                std::wcerr << featureLabel << L": invalid endpoint row at index " << i << L"\n";
                return 4;
            }
            if (i >= parsed)
            {
                continue;
            }
            std::wcout << L"  [" << i << L"] rowId=" << row->rowId
                       << L" af=" << row->addressFamily
                       << L" proto=" << row->protocol
                       << L" state=" << row->state
                       << L" pid=" << row->owningPid
                       << L" local=" << networkAuditAddressToText(row->addressFamily, row->localAddress) << L":" << row->localPort
                       << L" remote=" << networkAuditAddressToText(row->addressFamily, row->remoteAddress) << L":" << row->remotePort
                       << L" compartment=" << row->compartmentId
                       << L" ifIndex=" << row->interfaceIndex
                       << L" flags=0x" << std::hex << row->flags
                       << L" source=0x" << row->sourceFlags
                       << L" fieldMask=0x" << row->fieldMask
                       << L" endpoint=" << hex64(row->endpointObject)
                       << L" processObject=" << hex64(row->owningProcessObject)
                       << L" transport=" << hex64(row->transportObject)
                       << L" interfaceLuid=" << hex64(row->interfaceLuid)
                       << std::dec << L"\n";
        }
        return 0;
    }

    // queryNetworkWfp prints WFP provider/filter/callout inventory rows.
    // Inputs: parsed network options.
    // Processing: supports audit-stub responses without treating them as crashes.
    // Returns: CLI exit code.
    int queryNetworkWfp(const NamedArgs& args)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkAuditRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY", IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"network wfp", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*>(buffer.data());
        if (!validateNetworkAuditHeader(
            response->version,
            response->size,
            response->status,
            response->flags,
            response->totalRowCount,
            response->returnedRowCount,
            response->sourceFlags,
            response->budgetRows,
            io.bytesReturned,
            headerSize,
            L"network wfp"))
        {
            return 4;
        }
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW), L"network wfp"); }
        catch (...) { return 4; }
        if (available < response->returnedRowCount)
        {
            std::wcerr << L"network wfp: returned rows exceed response bytes\n";
            return 4;
        }
        const bool partialRowsAccepted =
            isRetainableNetworkInventoryPartial(
                response->status,
                response->lastStatus,
                response->returnedRowCount);
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRowCount, response->returnedRowCount, response->entrySize, io.bytesReturned);
        printNetworkAuditState(
            response->status,
            response->lastStatus,
            response->sourceFlags,
            response->budgetRows,
            response->generation,
            response->totalRowCount,
            response->returnedRowCount,
            partialRowsAccepted);
        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            !partialRowsAccepted)
        {
            std::wcerr
                << L"unsupported / unavailable: network wfp returned no retainable partial snapshot\n";
            return 5;
        }
        const std::size_t parsed = responseCountLimit(response->returnedRowCount, available, getOptionU32(args, L"--limit", 128U));
        constexpr unsigned long knownRowFlags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
        for (std::size_t i = 0; i < response->returnedRowCount; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW*>(buffer.data() + headerSize + (i * response->entrySize));
            if (row->objectKind < KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER ||
                row->objectKind > KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT ||
                (row->flags & ~knownRowFlags) != 0UL)
            {
                std::wcerr << L"network wfp: invalid row at index " << i << L"\n";
                return 4;
            }
            if (i >= parsed)
            {
                continue;
            }
            std::wcout << L"  [" << i << L"] rowId=" << row->rowId
                       << L" kind=" << networkWfpObjectKindText(row->objectKind)
                       << L"(" << row->objectKind << L")"
                       << L" layer=" << row->layerId
                       << L" calloutId=" << row->calloutId
                       << L" filterId=" << row->filterId
                       << L" classify=" << hex64(row->classifyAddress)
                       << L" notify=" << hex64(row->notifyAddress)
                       << L" flowDelete=" << hex64(row->flowDeleteAddress)
                       << L" ownerBase=" << hex64(row->ownerImageBase)
                       << L" owner='" << fixedWide(row->ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryNetworkNdis prints NDIS miniport/filter/protocol/binding rows.
    // Inputs: parsed network options.
    // Processing: renders object graph hints without changing bindings.
    // Returns: CLI exit code.
    int queryNetworkNdis(const NamedArgs& args)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkAuditRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN", IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"network ndis", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*>(buffer.data());
        if (!validateNetworkAuditHeader(
            response->version,
            response->size,
            response->status,
            response->flags,
            response->totalRowCount,
            response->returnedRowCount,
            response->sourceFlags,
            response->budgetRows,
            io.bytesReturned,
            headerSize,
            L"network ndis"))
        {
            return 4;
        }
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW), L"network ndis"); }
        catch (...) { return 4; }
        if (available < response->returnedRowCount)
        {
            std::wcerr << L"network ndis: returned rows exceed response bytes\n";
            return 4;
        }
        const bool partialRowsAccepted =
            isRetainableNetworkInventoryPartial(
                response->status,
                response->lastStatus,
                response->returnedRowCount);
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRowCount, response->returnedRowCount, response->entrySize, io.bytesReturned);
        printNetworkAuditState(
            response->status,
            response->lastStatus,
            response->sourceFlags,
            response->budgetRows,
            response->generation,
            response->totalRowCount,
            response->returnedRowCount,
            partialRowsAccepted);
        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            !partialRowsAccepted)
        {
            std::wcerr
                << L"unsupported / unavailable: network ndis returned no retainable partial snapshot\n";
            return 5;
        }
        const std::size_t parsed = responseCountLimit(response->returnedRowCount, available, getOptionU32(args, L"--limit", 128U));
        constexpr unsigned long knownRowFlags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
        for (std::size_t i = 0; i < response->returnedRowCount; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW*>(buffer.data() + headerSize + (i * response->entrySize));
            if (row->objectKind > KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING ||
                (row->flags & ~knownRowFlags) != 0UL)
            {
                std::wcerr << L"network ndis: invalid row at index " << i << L"\n";
                return 4;
            }
            if (i >= parsed)
            {
                continue;
            }
            std::wcout << L"  [" << i << L"] rowId=" << row->rowId
                       << L" kind=" << networkNdisObjectKindText(row->objectKind)
                       << L"(" << row->objectKind << L")"
                       << L" ifIndex=" << row->ifIndex
                       << L" order=" << row->filterOrder
                       << L" object=" << hex64(row->objectAddress)
                       << L" parent=" << hex64(row->parentObjectAddress)
                       << L" driverObject=" << hex64(row->driverObject)
                       << L" imageBase=" << hex64(row->imageBase)
                       << L" component='" << fixedWide(row->componentName, KSWORD_ARK_NETWORK_NAME_CHARS)
                       << L"' owner='" << fixedWide(row->ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // ipv4AddressToText 作用：把 IP Helper 返回的 IPv4 地址转为宽字符文本。
    // 输入：address 为 MIB_* 表中的 IPv4 地址，保持系统 API 返回的字节序。
    // 处理：调用 InetNtopW，失败时输出占位诊断，避免 CLI 崩溃。
    // 返回：可直接打印的 IPv4 文本。
    std::wstring ipv4AddressToText(const DWORD address)
    {
        IN_ADDR inAddress{};
        inAddress.S_un.S_addr = address;

        wchar_t addressText[INET_ADDRSTRLEN]{};
        if (::InetNtopW(AF_INET, &inAddress, addressText, static_cast<DWORD>(sizeof(addressText) / sizeof(addressText[0]))) == nullptr)
        {
            return L"<invalid-ipv4>";
        }
        return addressText;
    }

    // ipv6AddressToText 作用：把 IP Helper 返回的 IPv6 地址转为宽字符文本。
    // 输入：addressBytes 指向 16 字节 IPv6 地址，scopeId 是接口 scope。
    // 处理：格式化地址并在存在 scopeId 时追加 %scope，便于定位链路本地地址。
    // 返回：可直接打印的 IPv6 文本。
    std::wstring ipv6AddressToText(const UCHAR addressBytes[16], const DWORD scopeId)
    {
        IN6_ADDR inAddress{};
        std::memcpy(&inAddress, addressBytes, sizeof(inAddress));

        wchar_t addressText[INET6_ADDRSTRLEN]{};
        if (::InetNtopW(AF_INET6, &inAddress, addressText, static_cast<DWORD>(sizeof(addressText) / sizeof(addressText[0]))) == nullptr)
        {
            return L"<invalid-ipv6>";
        }

        std::wostringstream stream;
        stream << addressText;
        if (scopeId != 0U)
        {
            stream << L"%" << scopeId;
        }
        return stream.str();
    }

    // networkPortToHost 作用：把 IP Helper 表中的网络字节序端口转为主机字节序。
    // 输入：portValue 为 DWORD 存储的端口字段。
    // 处理：截取低 16 位并调用 ntohs。
    // 返回：可读端口号。
    std::uint16_t networkPortToHost(const DWORD portValue)
    {
        return ntohs(static_cast<u_short>(portValue));
    }

    // printAfdTcp4Fallback 作用：打印 AFD fallback 的 IPv4 TCP owner rows。
    // 输入：limit 为最大输出行数，printedRows 引用累计已打印数量。
    // 处理：GetExtendedTcpTable 只读获取 owner PID 表，不访问 R0 AFD 私有结构。
    // 返回：Win32 状态码，ERROR_SUCCESS 表示成功枚举或无行。
    DWORD printAfdTcp4Fallback(const std::size_t limit, std::size_t& printedRows)
    {
        ULONG bufferBytes = 0U;
        DWORD status = ::GetExtendedTcpTable(
            nullptr,
            &bufferBytes,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0U);
        if (status != ERROR_INSUFFICIENT_BUFFER || bufferBytes == 0U)
        {
            return status;
        }

        std::vector<std::uint8_t> buffer(bufferBytes, 0U);
        status = ::GetExtendedTcpTable(
            buffer.data(),
            &bufferBytes,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0U);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }

        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD rowIndex = 0U; rowIndex < table->dwNumEntries && printedRows < limit; ++rowIndex)
        {
            const MIB_TCPROW_OWNER_PID& row = table->table[rowIndex];
            std::wcout << L"  afd-fallback[tcp4][" << printedRows << L"] pid=" << row.dwOwningPid
                       << L" local=" << ipv4AddressToText(row.dwLocalAddr) << L":" << networkPortToHost(row.dwLocalPort)
                       << L" remote=" << ipv4AddressToText(row.dwRemoteAddr) << L":" << networkPortToHost(row.dwRemotePort)
                       << L" state=" << row.dwState
                       << L" source=GetExtendedTcpTable\n";
            ++printedRows;
        }
        return ERROR_SUCCESS;
    }

    // printAfdUdp4Fallback 作用：打印 AFD fallback 的 IPv4 UDP owner rows。
    // 输入：limit 为最大输出行数，printedRows 引用累计已打印数量。
    // 处理：GetExtendedUdpTable 只读获取 UDP owner PID 表。
    // 返回：Win32 状态码。
    DWORD printAfdUdp4Fallback(const std::size_t limit, std::size_t& printedRows)
    {
        ULONG bufferBytes = 0U;
        DWORD status = ::GetExtendedUdpTable(
            nullptr,
            &bufferBytes,
            FALSE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0U);
        if (status != ERROR_INSUFFICIENT_BUFFER || bufferBytes == 0U)
        {
            return status;
        }

        std::vector<std::uint8_t> buffer(bufferBytes, 0U);
        status = ::GetExtendedUdpTable(
            buffer.data(),
            &bufferBytes,
            FALSE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0U);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }

        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD rowIndex = 0U; rowIndex < table->dwNumEntries && printedRows < limit; ++rowIndex)
        {
            const MIB_UDPROW_OWNER_PID& row = table->table[rowIndex];
            std::wcout << L"  afd-fallback[udp4][" << printedRows << L"] pid=" << row.dwOwningPid
                       << L" local=" << ipv4AddressToText(row.dwLocalAddr) << L":" << networkPortToHost(row.dwLocalPort)
                       << L" source=GetExtendedUdpTable\n";
            ++printedRows;
        }
        return ERROR_SUCCESS;
    }

    // commandNetworkAfdFallback 作用：为 network afd 提供只读降级证据。
    // 输入：CLI 参数，支持 --limit 控制打印行数。
    // 处理：明确声明无专用 R0 IOCTL，并用 documented IP Helper owner 表展示 AFD 近似证据。
    // 返回：0 表示 fallback 查询完成；非 0 表示系统 API 不可用或失败。
    int commandNetworkAfdFallback(const NamedArgs& args)
    {
        const std::size_t limit = getOptionU32(args, L"--limit", 128U);
        std::size_t printedRows = 0U;

        std::wcout << L"network afd: degraded fallback\n"
                   << L"status=degraded unsupportedR0=1 reason='no dedicated AFD audit IOCTL is present in shared protocol'\n"
                   << L"source=R3 documented IP Helper owner PID tables\n";

        const DWORD tcp4Status = printAfdTcp4Fallback(limit, printedRows);
        const DWORD udp4Status = printAfdUdp4Fallback(limit, printedRows);

        std::wcout << L"summary rows=" << printedRows
                   << L" limit=" << limit
                   << L" tcp4Status=" << tcp4Status
                   << L" udp4Status=" << udp4Status
                   << L" ipv6OwnerPid='covered by network nsi fallback; SDK hides MIB_*6_OWNER_PID in this build context'\n";

        if (tcp4Status != ERROR_SUCCESS && udp4Status != ERROR_SUCCESS)
        {
            std::wcerr << L"unsupported / unavailable: network afd fallback APIs failed\n";
            return 5;
        }
        return 0;
    }

    // socketAddressToText 作用：把 GetAdaptersAddresses 的 SOCKET_ADDRESS 格式化。
    // 输入：socketAddress 为适配器地址节点中的原始 socket 地址。
    // 处理：按 AF_INET/AF_INET6 分支转换，未知地址族返回诊断文本。
    // 返回：可打印地址文本。
    std::wstring socketAddressToText(const SOCKET_ADDRESS& socketAddress)
    {
        if (socketAddress.lpSockaddr == nullptr)
        {
            return L"<null-address>";
        }
        if (socketAddress.lpSockaddr->sa_family == AF_INET)
        {
            const auto* ipv4 = reinterpret_cast<const SOCKADDR_IN*>(socketAddress.lpSockaddr);
            return ipv4AddressToText(ipv4->sin_addr.S_un.S_addr);
        }
        if (socketAddress.lpSockaddr->sa_family == AF_INET6)
        {
            const auto* ipv6 = reinterpret_cast<const SOCKADDR_IN6*>(socketAddress.lpSockaddr);
            return ipv6AddressToText(ipv6->sin6_addr.u.Byte, ipv6->sin6_scope_id);
        }
        return L"<unsupported-address-family>";
    }

    // commandNetworkNsiFallback 作用：为 network nsi 提供只读降级证据。
    // 输入：CLI 参数，支持 --limit 控制打印的单播地址数量。
    // 处理：使用 GetAdaptersAddresses 投影接口/地址状态，替代缺失的专用 NSI R0 IOCTL。
    // 返回：0 表示 fallback 查询完成；非 0 表示系统 API 不可用或失败。
    int commandNetworkNsiFallback(const NamedArgs& args)
    {
        const std::size_t limit = getOptionU32(args, L"--limit", 128U);
        ULONG bufferBytes = 16U * 1024U;
        std::vector<std::uint8_t> buffer(bufferBytes, 0U);
        constexpr ULONG queryFlags =
            GAA_FLAG_INCLUDE_PREFIX |
            GAA_FLAG_INCLUDE_GATEWAYS |
            GAA_FLAG_INCLUDE_ALL_INTERFACES;

        DWORD status = ::GetAdaptersAddresses(AF_UNSPEC, queryFlags, nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferBytes);
        if (status == ERROR_BUFFER_OVERFLOW)
        {
            buffer.assign(bufferBytes, 0U);
            status = ::GetAdaptersAddresses(AF_UNSPEC, queryFlags, nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferBytes);
        }

        std::wcout << L"network nsi: degraded fallback\n"
                   << L"status=degraded unsupportedR0=1 reason='no dedicated NSI audit IOCTL is present in shared protocol'\n"
                   << L"source=R3 documented GetAdaptersAddresses interface projection\n";

        if (status != ERROR_SUCCESS)
        {
            std::wcerr << L"unsupported / unavailable: GetAdaptersAddresses failed, win32=" << status
                       << L" (0x" << std::hex << status << std::dec << L")\n";
            return 5;
        }

        std::size_t adapterCount = 0U;
        std::size_t printedAdapterCount = 0U;
        std::size_t addressCount = 0U;
        const auto* adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data());
        for (; adapter != nullptr; adapter = adapter->Next)
        {
            ++adapterCount;
            if (printedAdapterCount >= limit)
            {
                continue;
            }
            std::wcout << L"  nsi-adapter[" << (adapterCount - 1U) << L"] ifIndex=" << adapter->IfIndex
                       << L" ipv6IfIndex=" << adapter->Ipv6IfIndex
                       << L" operStatus=" << adapter->OperStatus
                       << L" ifType=" << adapter->IfType
                       << L" mtu=" << adapter->Mtu
                       << L" name='" << (adapter->FriendlyName != nullptr ? adapter->FriendlyName : L"")
                       << L"' description='" << (adapter->Description != nullptr ? adapter->Description : L"")
                       << L"'\n";
            ++printedAdapterCount;

            const IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
            for (; unicast != nullptr && addressCount < limit; unicast = unicast->Next)
            {
                std::wcout << L"    nsi-unicast[" << addressCount << L"] address="
                           << socketAddressToText(unicast->Address)
                           << L" prefixLength=" << static_cast<unsigned int>(unicast->OnLinkPrefixLength)
                           << L" dadState=" << unicast->DadState
                           << L" validLifetime=" << unicast->ValidLifetime
                           << L" preferredLifetime=" << unicast->PreferredLifetime
                           << L"\n";
                ++addressCount;
            }
        }

        std::wcout << L"summary adapters=" << adapterCount
                   << L" printedAdapters=" << printedAdapterCount
                   << L" addresses=" << addressCount
                   << L" limit=" << limit
                   << L" truncated=" << ((adapterCount > printedAdapterCount || addressCount >= limit) ? 1U : 0U) << L"\n";
        return 0;
    }

    // queryDeviceAudit prints device/input/USB/GPU audit rows.
    // Inputs: parsed args plus protocol code/profile and labels.
    // Processing: sends a read-only request and renders bounded device evidence rows.
    // Returns: CLI exit code.
    int queryDeviceAudit(const NamedArgs& args, DWORD code, unsigned long profileFlags, const wchar_t* ioctlLabel, const wchar_t* featureLabel)
    {
        KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
        request.profileFlags = getOptionU32(args, L"--profile-flags", profileFlags);
        request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS);
        request.maxAttachedDepth = getOptionU32(args, L"--max-attached", KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);
        copyOptionalWideOption(args, L"--target", request.targetName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(ioctlLabel, code, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(featureLabel, io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE) - sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY), featureLabel); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"profileFlags=0x" << std::hex << response->profileFlags
                   << L" responseFlags=0x" << response->responseFlags
                   << std::dec << L" targetCount=" << response->targetCount
                   << L" driverCount=" << response->driverCount
                   << L" deviceCount=" << response->deviceCount << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_DEVICE_AUDIT_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] kind=" << row->rowKind
                       << L" role=" << row->roleHint
                       << L" status=" << row->status
                       << L" risk=0x" << std::hex << row->riskFlags
                       << L" driverObject=" << hex64(row->driverObjectAddress)
                       << L" deviceObject=" << hex64(row->deviceObjectAddress)
                       << L" attached=" << hex64(row->attachedDeviceAddress)
                       << L" next=" << hex64(row->nextDeviceObjectAddress)
                       << std::dec << L" confidence=" << row->confidence
                       << L" depth=" << row->relationDepth
                       << L" attachedDepth=" << row->attachedDepth
                       << L" driver='" << fixedWide(row->driverName, KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS)
                       << L"' service='" << fixedWide(row->serviceName, KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS)
                       << L"' device='" << fixedWide(row->deviceName, KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // buildWin32kRequest fills common win32k audit query fields.
    // Inputs: parsed args for session/pid/tid/limits.
    // Processing: keeps request bounded and current-session by default.
    // Returns: fixed win32k query request.
    KSWORD_ARK_WIN32K_QUERY_REQUEST buildWin32kRequest(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL);
        request.sessionId = getOptionU32(args, L"--session-id", 0U);
        request.processId = getOptionU32(args, L"--pid", 0U);
        request.threadId = getOptionU32(args, L"--tid", 0U);
        request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES);
        return request;
    }

    // applyMessageHookMatchOption maps the readable --match option onto the
    // shared owner/target selector bits without disturbing other --flags bits.
    // Inputs: parsed arguments and the flags produced by buildWin32kRequest.
    // Processing: validates legacy|owner|target|both case-insensitively.
    // Returns: flags with only the selector mask replaced when --match exists.
    std::uint32_t applyMessageHookMatchOption(
        const NamedArgs& args,
        std::uint32_t flags)
    {
        const std::wstring* option = getOptionText(args, L"--match");
        if (option == nullptr)
        {
            return flags;
        }

        const std::wstring mode = lowerWide(*option);
        flags &= ~KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK;
        if (mode == L"legacy")
        {
            return flags;
        }
        if (mode == L"owner")
        {
            return flags | KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER;
        }
        if (mode == L"target")
        {
            return flags | KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET;
        }
        if (mode == L"both")
        {
            return flags | KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK;
        }
        throw std::invalid_argument(
            "invalid --match value (expected legacy, owner, target, or both)");
    }

    // messageHookMatchName renders the effective selector bits returned by R0.
    // Inputs: response/request flags.
    // Processing: ignores all flags outside the shared selector mask.
    // Returns: a stable CLI label for diagnostics and scripts.
    const wchar_t* messageHookMatchName(const std::uint32_t flags)
    {
        switch (flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK)
        {
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER:
            return L"owner";
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET:
            return L"target";
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK:
            return L"both";
        default:
            return L"legacy";
        }
    }

    // queryWin32kProfileStatus prints module/profile/session readiness.
    // Inputs: parsed window options.
    // Processing: validates the variable session row response.
    // Returns: CLI exit code.
    int queryWin32kProfileStatus(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS", IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"window win32k", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY), L"win32k profile"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"capability=0x" << std::hex << response->capabilityMask
                   << L" missing=0x" << response->missingCapabilityMask
                   << L" userGetSiloGlobals=" << hex64(response->userGetSiloGlobals)
                   << std::dec << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_SESSION_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] session=" << row->sessionId
                       << L" status=" << row->status
                       << L" processCount=" << row->processCount
                       << L" guiThreadCount=" << row->guiThreadCount
                       << L" representativePid=" << row->representativeProcessId
                       << L" representativeTid=" << row->representativeThreadId
                       << L" capability=0x" << std::hex << row->capabilityMask
                       << std::dec << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kWindows prints HWND/tagWND cross-view rows.
    // Inputs: parsed window options.
    // Processing: renders only snapshot evidence; no message interception.
    // Returns: CLI exit code.
    int queryWin32kWindows(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS", IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"window gui", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY), L"win32k windows"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_WINDOW_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] hwnd=" << hex64(row->hwnd)
                       << L" tagWnd=" << hex64(row->tagWnd)
                       << L" pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" session=" << row->sessionId
                       << L" status=" << row->status
                       << L" fields=0x" << std::hex << row->fieldFlags
                       << std::dec << L" title='" << fixedWide(row->title, KSWORD_ARK_WIN32K_TITLE_CHARS)
                       << L"' class='" << fixedWide(row->className, KSWORD_ARK_WIN32K_CLASS_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kGuiThreads prints GUI thread/queue rows.
    // Inputs: parsed window options.
    // Processing: reports focus/capture/active evidence only.
    // Returns: CLI exit code.
    int queryWin32kGuiThreads(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS", IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"window gui threads", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY), L"win32k gui threads"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" session=" << row->sessionId
                       << L" status=" << row->status
                       << L" threadInfo=" << hex64(row->threadInfo)
                       << L" queue=" << hex64(row->queueObject)
                       << L" active=" << hex64(row->activeHwnd)
                       << L" focus=" << hex64(row->focusHwnd)
                       << L" capture=" << hex64(row->captureHwnd)
                       << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // printWin32kModuleState renders one fixed win32k module/profile state.
    // Inputs: display label and module state packet from a win32k response.
    // Processing: prints load/profile state and image identity.
    // Returns: no value.
    void printWin32kModuleState(const wchar_t* label, const KSWORD_ARK_WIN32K_MODULE_STATE& module)
    {
        std::wcout << label
                   << L" loaded=" << module.loaded
                   << L" profileState=" << module.profileState
                   << L" imageBase=" << hex64(module.imageBase)
                   << L" imageSize=" << module.imageSize
                   << L" name='" << fixedWide(module.moduleName, KSWORD_ARK_WIN32K_MODULE_NAME_CHARS) << L"'\n";
    }

    // queryWin32kHotkeysPdb prints PDB-backed win32k hotkey chain rows.
    // Inputs: parsed window options for session/pid/tid/filter budgets.
    // Processing: issues IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB and renders
    // diagnostic-only hotkey object rows.
    // Returns: CLI exit code with old-driver normalization.
    int queryWin32kHotkeysPdb(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB", IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"window hotkeys-pdb", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY), L"win32k hotkeys-pdb"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"capability=0x" << std::hex << response->capabilityMask
                   << L" missing=0x" << response->missingCapabilityMask
                   << std::dec << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_HOTKEY_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] source=" << row->source
                       << L" status=" << row->status
                       << L" flags=0x" << std::hex << row->flags
                       << L" hotkey=" << hex64(row->hotkeyObject)
                       << L" next=" << hex64(row->nextHotkeyObject)
                       << L" hwnd=" << hex64(row->hwnd)
                       << L" tagWnd=" << hex64(row->tagWnd)
                       << L" threadInfo=" << hex64(row->threadInfo)
                       << L" desktop=" << hex64(row->desktopObject)
                       << std::dec << L" session=" << row->sessionId
                       << L" pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" modifiers=0x" << std::hex << row->modifiers
                       << std::dec << L" vk=" << row->virtualKey
                       << L" id=" << row->hotkeyId
                       << L" depth=" << row->depth
                       << L" last=0x" << std::hex << static_cast<unsigned long>(row->lastStatus)
                       << std::dec << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kHooksPdb prints PDB-backed win32k hook chain rows.
    // Inputs: parsed window options for session/pid/tid/filter budgets.
    // Processing: issues IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB and renders
    // diagnostic-only hook object/procedure rows.
    // Returns: CLI exit code with old-driver normalization.
    int queryWin32kHooksPdb(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        request.flags = applyMessageHookMatchOption(args, request.flags);
        request.maxEntries = getOptionU32(
            args,
            L"--max-entries",
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES);
        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE) -
            sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
        constexpr std::size_t hardMaxResponseBytes =
            headerSize +
            (static_cast<std::size_t>(KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES) *
                sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY));
        static_assert(
            hardMaxResponseBytes <= kHugeResponseBytes,
            "win32k hook response buffer must hold the protocol hard maximum");
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB", IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"window hooks-pdb", io, rc);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY), L"win32k hooks-pdb"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"capability=0x" << std::hex << response->capabilityMask
                   << L" missing=0x" << response->missingCapabilityMask
                   << std::dec
                   << L" match=" << messageHookMatchName(response->flags)
                   << L" chains=" << response->discoveredChainCount
                   << L" visited=" << response->visitedNodeCount
                   << L" readFailures=" << response->readFailureCount
                   << L" corruptLinks=" << response->corruptLinkCount
                   << L" duplicates=" << response->duplicateCount
                   << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_HOOK_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] source=" << row->source
                       << L" status=" << row->status
                       << L" flags=0x" << std::hex << row->flags
                       << L" hook=" << hex64(row->hookObject)
                       << L" chainHead=" << hex64(row->chainHead)
                       << L" next=" << hex64(row->nextHookObject)
                       << L" threadInfo=" << hex64(row->threadInfo)
                       << L" targetThreadInfo=" << hex64(row->targetThreadInfo)
                       << L" desktop=" << hex64(row->desktopObject)
                       << L" proc=" << hex64(row->procedureAddress)
                       << L" moduleBase=" << hex64(row->moduleBase)
                       << std::dec << L" session=" << row->sessionId
                       << L" pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" targetSession=" << row->targetSessionId
                       << L" targetPid=" << row->targetProcessId
                       << L" targetTid=" << row->targetThreadId
                       << L" type=" << row->hookType
                       << L" scope=" << row->hookScope
                       << L" last=0x" << std::hex << static_cast<unsigned long>(row->lastStatus)
                       << std::dec << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kWindowDetail prints one fixed HWND/tagWND detail packet.
    // Inputs: --hwnd plus optional --pid/--tid context and --flags.
    // Processing: never accepts a tagWND pointer from user mode; R0 resolves the
    // requested HWND and returns stable profile/readiness evidence.
    // Returns: CLI exit code with old-driver normalization.
    int queryWin32kWindowDetail(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST request{};
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE response{};
        request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_DIAGNOSTICS);
        request.processId = getOptionU32(args, L"--pid", 0U);
        request.threadId = getOptionU32(args, L"--tid", 0U);
        request.hwnd = requireOptionU64(args, L"--hwnd");
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL, L"IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL", request, response, io))
        {
            return normalizeIoctlRc(L"window detail", io, 3);
        }
        printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
        std::wcout << L"hwnd=" << hex64(response.hwnd)
                   << L" tagWnd=" << hex64(response.tagWnd)
                   << L" threadInfo=" << hex64(response.threadInfo)
                   << L" queue=" << hex64(response.queueObject)
                   << L" desktop=" << hex64(response.desktopObject)
                   << L" capability=0x" << std::hex << response.capabilityMask
                   << L" missing=0x" << response.missingCapabilityMask
                   << std::dec << L" pid=" << response.processId
                   << L" tid=" << response.threadId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" flags=0x" << response.flags
                   << std::dec << L"\n";
        printWin32kModuleState(L"win32k", response.win32k);
        printWin32kModuleState(L"win32kbase", response.win32kbase);
        printWin32kModuleState(L"win32kfull", response.win32kfull);
        dumpWideText(L"title", fixedWide(response.title, KSWORD_ARK_WIN32K_TITLE_CHARS));
        dumpWideText(L"className", fixedWide(response.className, KSWORD_ARK_WIN32K_CLASS_CHARS));
        dumpWideText(L"detail", fixedWide(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
        return 0;
    }

    // querySecurityStatus prints CI/VBS/SKCI/test-signing posture.
    // Inputs: parsed args with optional flags.
    // Processing: sends the fixed read-only security status IOCTL.
    // Returns: CLI exit code.
    int querySecurityStatus(const NamedArgs& args)
    {
        KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST request{};
        KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE response{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", 0U);
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS, L"IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS", request, response, io))
        {
            return normalizeIoctlRc(L"misc security", io, 3);
        }
        printResponseBanner(response.version, static_cast<std::uint32_t>(response.queryStatus), response.codeIntegrityStatus, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" source=0x" << response.sourceMask
                   << L" ciOptions=0x" << response.codeIntegrityOptions
                   << std::dec << L" secureBoot=" << response.secureBootEnabled
                   << L" secureBootCapable=" << response.secureBootCapable
                   << L" ciEnabled=" << response.ciEnabled
                   << L" umci=" << response.umciEnabled
                   << L" hvciKmci=" << response.hvciKmciEnabled
                   << L" hvciAudit=" << response.hvciAuditMode
                   << L" hvciStrict=" << response.hvciStrictMode
                   << L" vbsPresent=" << response.vbsPresent
                   << L" testSigning=" << response.testSigningEnabled
                   << L" ciDebug=" << response.ciDebugModeEnabled
                   << L" kernelDebuggerEnabled=" << response.kernelDebuggerEnabled
                   << L" kernelDebuggerNotPresent=" << response.kernelDebuggerNotPresent
                   << L" ciModuleLoaded=" << response.ciModuleLoaded
                   << L" secureKernelLoaded=" << response.secureKernelModuleLoaded
                   << L" skciLoaded=" << response.skciModuleLoaded << L"\n";
        return 0;
    }

    // queryDriverTrustView prints bounded loaded-driver signing posture rows.
    // Inputs: parsed args with flags/max rows/limit.
    // Processing: validates variable trust rows and prints conflict flags.
    // Returns: CLI exit code.
    int queryDriverTrustView(const NamedArgs& args)
    {
        KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT);
        request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW", IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW, &request, sizeof(request), buffer, io);
        if (rc != 0) return normalizeIoctlRc(L"misc security driver trust", io, rc);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE*>(buffer.data());
        const std::uint32_t entrySize = sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        const std::size_t available = (io.bytesReturned < headerSize) ? 0U : ((io.bytesReturned - headerSize) / entrySize);
        if (io.bytesReturned < headerSize) { std::wcerr << L"error: driver trust response too small\n"; return 4; }
        printResponseBanner(response->version, static_cast<std::uint32_t>(response->queryStatus), response->moduleQueryStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalModuleCount, response->entryCount, entrySize, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response->fieldFlags
                   << L" source=0x" << response->sourceMask
                   << std::dec << L" maxEntriesAccepted=" << response->maxEntriesAccepted
                   << L" truncated=" << response->truncated << L"\n";
        const std::size_t parsed = responseCountLimit(response->entryCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY*>(buffer.data() + headerSize + (i * entrySize));
            std::wcout << L"  [" << i << L"] base=" << hex64(row->imageBase)
                       << L" size=" << row->imageSize
                       << L" fields=0x" << std::hex << row->fieldFlags
                       << L" source=0x" << row->sourceMask
                       << L" conflict=0x" << row->conflictFlags
                       << L" pathHash=0x" << row->pathHash
                       << std::dec << L" signingLevel=" << row->signingLevel
                       << L" signingStatus=0x" << std::hex << static_cast<unsigned long>(row->signingStatus)
                       << std::dec << L" module='" << fixedWide(row->moduleName, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryHypervSummary prints fixed Hyper-V/VBS module availability posture.
    // Inputs: none beyond parsed args for future compatibility.
    // Processing: sends a no-input fixed response IOCTL.
    // Returns: CLI exit code.
    int queryHypervSummary(const NamedArgs&)
    {
        KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE response{};
        IoctlResult io{};
        if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY, L"IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY", response, io))
        {
            return normalizeIoctlRc(L"misc hyperv", io, 3);
        }
        printResponseBanner(response.version, static_cast<std::uint32_t>(response.queryStatus), response.moduleQueryStatus, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" source=0x" << response.sourceMask
                   << std::dec << L" hypervisorPresent=" << response.hypervisorPresent
                   << L" rootPartition=" << response.rootPartitionStatus
                   << L" vmbus=" << response.vmbusStatus
                   << L" vSwitch=" << response.vSwitchStatus
                   << L" vPci=" << response.vPciStatus
                   << L" hvSocket=" << response.hvSocketStatus
                   << L" winHv=" << response.winHvStatus
                   << L" vendor='" << fixedWide(response.hypervisorVendor, KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS) << L"'\n";
        return 0;
    }

    // queryAppControlStatus prints AppID/AppLocker/mssecflt/BAM summary posture.
    // Inputs: none beyond parsed args for future compatibility.
    // Processing: sends fixed app-control status IOCTL.
    // Returns: CLI exit code.
    int queryAppControlStatus(const NamedArgs&)
    {
        KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE response{};
        IoctlResult io{};
        if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS, L"IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS", response, io))
        {
            return normalizeIoctlRc(L"misc applocker", io, 3);
        }
        printResponseBanner(response.version, static_cast<std::uint32_t>(response.queryStatus), response.moduleQueryStatus, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" source=0x" << response.sourceMask
                   << std::dec << L" appid=" << response.appidStatus
                   << L" appidPolicy=" << response.appidPolicyStatus
                   << L" applockerFilter=" << response.appLockerFilterStatus
                   << L" applockerOwner=" << response.appLockerCallbackOwnerStatus
                   << L" mssecflt=" << response.mssecfltStatus
                   << L" mssecfltOwner=" << response.mssecfltCallbackOwnerStatus
                   << L" ahcache=" << response.ahcacheStatus
                   << L" bam=" << response.bamStatus
                   << L" applockerOwnerModule='" << fixedWide(response.appLockerOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS)
                   << L"' mssecfltOwnerModule='" << fixedWide(response.mssecfltOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS) << L"'\n";
        return 0;
    }

    // commandFileFamily implements file and file-monitor IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: handles delete/query and monitor control/status/drain.
    // Returns: process exit code.
    int commandFileFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: file requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"delete-path")
        {
            KSWORD_ARK_DELETE_PATH_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            const std::wstring& pathText = requireOptionText(args, L"--path");
            request.pathLengthChars = boundedPathLength(pathText, KSWORD_ARK_DELETE_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_DELETE_PATH_MAX_CHARS, pathText);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_DELETE_PATH", IOCTL_KSWORD_ARK_DELETE_PATH, &request, sizeof(request));
        }
        if (sub == L"query-info")
        {
            KSWORD_ARK_QUERY_FILE_INFO_REQUEST request{};
            KSWORD_ARK_QUERY_FILE_INFO_RESPONSE response{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            const std::wstring& pathText = requireOptionText(args, L"--path");
            request.pathLengthChars = boundedPathLength(pathText, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS, pathText);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_FILE_INFO, L"IOCTL_KSWORD_ARK_QUERY_FILE_INFO", request, response, io)) return 3;
            printFileInfoResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"set-integrity")
        {
            KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST request{};
            KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_FILE_INTEGRITY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            if (getOptionBool(args, L"--directory"))
            {
                request.flags |= KSWORD_ARK_FILE_INTEGRITY_FLAG_DIRECTORY;
            }
            if (getOptionBool(args, L"--confirm"))
            {
                request.flags |= KSWORD_ARK_FILE_INTEGRITY_FLAG_UI_CONFIRMED;
            }
            request.integrityRid = parseMandatoryIntegrityRid(args);
            const std::wstring ntPath = normalizeFilePathForDriver(requireOptionText(args, L"--path"));
            request.pathLengthChars = boundedPathLength(ntPath, KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS, ntPath);
            if (!sendFixedRequestResponse(
                    IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY,
                    L"IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY",
                    request,
                    response,
                    io,
                    GENERIC_READ | GENERIC_WRITE))
            {
                return normalizeIoctlRc(L"file set-integrity", io, 3);
            }
            printFileIntegrityResponse(response, io.bytesReturned);
            dumpWideText(L"ntPath", ntPath);
            return 0;
        }
        if (sub == L"fileobject")
        {
            std::wcout << L"alias: file fileobject -> file query-info\n";
            KSWORD_ARK_QUERY_FILE_INFO_REQUEST request{};
            KSWORD_ARK_QUERY_FILE_INFO_RESPONSE response{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            const std::wstring& pathText = requireOptionText(args, L"--path");
            request.pathLengthChars = boundedPathLength(pathText, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS, pathText);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_FILE_INFO, L"IOCTL_KSWORD_ARK_QUERY_FILE_INFO", request, response, io)) return 3;
            printFileInfoResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"minifilter")
        {
            return queryMinifilterInventory(args);
        }
        if (sub == L"section")
        {
            return commandUnsupported(L"file section", L"use section query-file-mappings --path <path> for the existing read-only Section protocol");
        }
        if (sub == L"bitlocker")
        {
            return queryBitlockerAudit(args);
        }
        if (sub == L"storage")
        {
            return queryVolumeStackAudit(args);
        }
        if (sub == L"mountmgr")
        {
            return queryMountMgrAudit(args);
        }
        if (sub == L"filesystem")
        {
            return queryFilesystemIntegrityAudit(args);
        }
        if (sub == L"monitor-control")
        {
            KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST request{};
            request.action = requireOptionU32(args, L"--action");
            request.operationMask = getOptionU32(args, L"--operation-mask", 0U);
            request.processId = getOptionU32(args, L"--pid", 0U);
            request.flags = getOptionU32(args, L"--flags", 0U);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL", IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL, &request, sizeof(request));
        }
        if (sub == L"monitor-drain")
        {
            KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST request{};
            request.maxEvents = getOptionU32(args, L"--max-events", KSWORD_ARK_FILE_MONITOR_RING_CAPACITY);
            request.flags = getOptionU32(args, L"--flags", 0U);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) - sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN", IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            if (io.bytesReturned < headerSize) { std::wcerr << L"error: file-monitor drain response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_FILE_MONITOR_EVENT), L"file-monitor drain"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalQueuedBeforeDrain, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"droppedCount=" << response->droppedCount
                       << L" runtimeFlags=0x" << std::hex << response->runtimeFlags
                       << std::dec << L" ringCapacity=" << response->ringCapacity << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, request.maxEvents);
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_FILE_MONITOR_EVENT*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] op=" << entry->operationType
                           << L" major=" << entry->majorFunction
                           << L" minor=" << entry->minorFunction
                           << L" pid=" << entry->processId
                           << L" tid=" << entry->threadId
                           << L" flags=0x" << std::hex << entry->fieldFlags
                           << L" result=0x" << static_cast<unsigned long>(entry->resultStatus)
                           << std::dec << L" seq=" << entry->sequence
                           << L" path='" << fixedWide(entry->path, KSWORD_ARK_FILE_MONITOR_PATH_CHARS) << L"'";
                if ((entry->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_FSCTL_PRESENT) != 0UL)
                {
                    const wchar_t* fsctlText = KswordARKFileMonitorFsctlCodeToText(entry->fsControlCode);
                    std::wcout << L" fsctl=0x" << std::hex << entry->fsControlCode
                               << std::dec << L" fsInput=" << entry->fsInputBufferLength
                               << L" fsOutput=" << entry->fsOutputBufferLength
                               << L" oplock=" << (KswordARKFileMonitorFsctlIsOplockRelated(entry->fsControlCode) ? L"true" : L"false");
                    if (fsctlText != nullptr)
                    {
                        std::wcout << L" fsctlName='" << fsctlText << L"'";
                    }
                }
                std::wcout << L"\n";
            }
            return 0;
        }
        if (sub == L"monitor-status")
        {
            KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS, L"IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS", response, io)) return 3;
            printResponseBanner(response.version, response.runtimeFlags, response.lastErrorStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" operationMask=0x" << std::hex << response.operationMask
                       << std::dec << L" pidFilter=" << response.processIdFilter
                       << L" ringCapacity=" << response.ringCapacity
                       << L" queued=" << response.queuedCount
                       << L" dropped=" << response.droppedCount
                       << L" sequence=" << response.sequence
                       << L" registerStatus=0x" << std::hex << static_cast<unsigned long>(response.registerStatus)
                       << L" startStatus=0x" << static_cast<unsigned long>(response.startStatus)
                       << std::dec << L"\n";
            return 0;
        }
        std::wcerr << L"error: unknown file subcommand '" << sub << L"'\n";
        return 1;
    }

    // fixedAnsiWide widens a fixed ANSI protocol field for wide console output.
    // Inputs: a char buffer and its protocol capacity.
    // Processing: extracts the NUL-terminated ANSI text and widens byte-for-byte.
    // Returns: a wide string suitable for std::wcout.
    std::wstring fixedAnsiWide(const char* text, std::size_t maxBytes)
    {
        const std::string value = fixedAnsi(text, maxBytes);
        return std::wstring(value.begin(), value.end());
    }

    // requireWideCapacity rejects strings that cannot fit in fixed protocol fields.
    // Inputs: source text, destination capacity, and a human-readable field name.
    // Processing: enforces room for a trailing NUL to avoid silent truncation.
    // Returns: no value; throws when the string is empty or too long.
    void requireWideCapacity(const std::wstring& text, std::size_t capacity, const char* name)
    {
        if (text.empty() || text.size() >= capacity)
        {
            throw std::out_of_range(name);
        }
    }

    // copyRequiredWideOption copies a mandatory named option into a fixed field.
    // Inputs: parsed args, option key, destination field, and field capacity.
    // Processing: validates capacity and writes a NUL-terminated copy.
    // Returns: no value; throws when the option is missing or too long.
    void copyRequiredWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity)
    {
        const std::wstring& value = requireOptionText(args, key);
        requireWideCapacity(value, capacity, "wide option");
        copyWideToFixed(destination, capacity, value);
    }

    // copyOptionalWideOption copies an optional named option into a fixed field.
    // Inputs: parsed args, option key, destination field, and field capacity.
    // Processing: leaves the field unchanged when the option is absent.
    // Returns: true when the option was supplied.
    bool copyOptionalWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity)
    {
        const std::wstring* value = getOptionText(args, key);
        if (value == nullptr)
        {
            return false;
        }
        requireWideCapacity(*value, capacity, "wide option");
        copyWideToFixed(destination, capacity, *value);
        return true;
    }

    // printBytesInline renders a short byte array summary on one line.
    // Inputs: label, source pointer, byte count, and display cap.
    // Processing: prints hexadecimal bytes and an ellipsis when truncated.
    // Returns: no value.
    void printBytesInline(const wchar_t* label, const unsigned char* data, std::size_t count, std::size_t maxDisplay = 32U)
    {
        std::wcout << label << L"=";
        if (data == nullptr || count == 0U)
        {
            std::wcout << L"(empty)\n";
            return;
        }

        const std::size_t shown = std::min<std::size_t>(count, maxDisplay);
        std::wcout << std::hex << std::setfill(L'0');
        for (std::size_t index = 0U; index < shown; ++index)
        {
            std::wcout << (index == 0U ? L"" : L" ")
                       << std::setw(2) << static_cast<unsigned int>(data[index]);
        }
        std::wcout << std::dec << std::setfill(L' ');
        if (shown < count)
        {
            std::wcout << L" ...";
        }
        std::wcout << L"\n";
    }

    // readRequiredBlobOption reads a mandatory blob-style file option.
    // Inputs: parsed args, option key, and protocol maximum length.
    // Processing: delegates to readFileBytes and rejects empty blobs.
    // Returns: the raw file bytes.
    std::vector<std::uint8_t> readRequiredBlobOption(const NamedArgs& args, const wchar_t* key, std::size_t maxBytes)
    {
        const std::wstring& path = requireOptionText(args, key);
        std::vector<std::uint8_t> bytes = readFileBytes(path, maxBytes);
        if (bytes.empty())
        {
            throw std::invalid_argument("empty blob");
        }
        return bytes;
    }

    // sendBlobFixedResponse sends a raw input blob and receives one fixed response.
    // Inputs: IOCTL label/code, blob bytes, response object, result packet, access.
    // Processing: performs METHOD_BUFFERED DeviceIoControl with size validation.
    // Returns: true on a transport-level success with a full fixed response.
    template <typename TResponse>
    bool sendBlobFixedResponse(
        DWORD code,
        const wchar_t* label,
        std::vector<std::uint8_t>& input,
        TResponse& response,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.valid())
        {
            io.win32Error = ::GetLastError();
            return false;
        }

        io = sendIoctl(handle, code, input.data(), checkedDwordSize(input.size()), &response, static_cast<DWORD>(sizeof(response)));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return false;
        }
        if (io.bytesReturned < sizeof(response))
        {
            std::wcerr << L"error: " << label << L" response too small: " << io.bytesReturned << L" bytes\n";
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            return false;
        }
        return true;
    }

    // printModuleIdentity renders a DynData module identity packet.
    // Inputs: label and module packet.
    // Processing: prints stable scalar fields and the fixed module name.
    // Returns: no value.
    void printModuleIdentity(const wchar_t* label, const KSW_DYN_MODULE_IDENTITY_PACKET& module)
    {
        std::wcout << label << L": present=" << module.present
                   << L" class=" << module.classId
                   << L" machine=0x" << std::hex << module.machine
                   << L" timestamp=0x" << module.timeDateStamp
                   << L" imageBase=" << hex64(module.imageBase)
                   << std::dec << L" sizeOfImage=" << module.sizeOfImage
                   << L" name='" << fixedWide(module.moduleName, KSW_DYN_MODULE_NAME_CHARS) << L"'\n";
    }

    // commandKernelFamily implements kernel inspection and mutation IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: routes SSDT, hook, DriverObject, CPU, memory-layout and unload commands.
    // Returns: process exit code.
    int commandKernelFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: kernel requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"ssdt" || sub == L"shadow-ssdt")
        {
            KSWORD_ARK_ENUM_SSDT_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const DWORD code = (sub == L"ssdt") ? IOCTL_KSWORD_ARK_ENUM_SSDT : IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT;
            const wchar_t* label = (sub == L"ssdt") ? L"IOCTL_KSWORD_ARK_ENUM_SSDT" : L"IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT";
            const int rc = sendRawIoctl(label, code, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_SSDT_RESPONSE) - sizeof(KSWORD_ARK_SSDT_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_SSDT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_SSDT_ENTRY), label); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"serviceTableBase=" << hex64(response->serviceTableBase)
                       << L" serviceCountFromTable=" << response->serviceCountFromTable << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_SSDT_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] index=" << entry->serviceIndex
                           << L" flags=0x" << std::hex << entry->flags
                           << L" zw=" << hex64(entry->zwRoutineAddress)
                           << L" service=" << hex64(entry->serviceRoutineAddress)
                           << std::dec << L" name='" << fixedAnsiWide(entry->serviceName, sizeof(entry->serviceName))
                           << L"' module='" << fixedAnsiWide(entry->moduleName, sizeof(entry->moduleName)) << L"'\n";
            }
            return 0;
        }

        if (sub == L"scan-inline-hooks" || sub == L"enum-iat-eat-hooks")
        {
            KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL);
            request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES);
            copyOptionalWideOption(args, L"--module", request.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            if (sub == L"scan-inline-hooks")
            {
                const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS", IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS, &request, sizeof(request), buffer, io);
                if (rc != 0) return rc;
                constexpr std::size_t headerSize = sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY);
                const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*>(buffer.data());
                std::size_t available = 0U;
                try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY), L"scan-inline-hooks"); }
                catch (...) { return 4; }
                printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
                printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
                std::wcout << L"moduleCount=" << response->moduleCount << L"\n";
                const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
                for (std::size_t i = 0; i < parsed; ++i)
                {
                    const auto* entry = reinterpret_cast<const KSWORD_ARK_INLINE_HOOK_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                    std::wcout << L"  [" << i << L"] status=" << entry->status
                               << L" type=" << entry->hookType
                               << L" flags=0x" << std::hex << entry->flags
                               << L" function=" << hex64(entry->functionAddress)
                               << L" target=" << hex64(entry->targetAddress)
                               << L" moduleBase=" << hex64(entry->moduleBase)
                               << std::dec << L" function='" << fixedAnsiWide(entry->functionName, sizeof(entry->functionName))
                               << L"' module='" << fixedWide(entry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS)
                               << L"' targetModule='" << fixedWide(entry->targetModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS) << L"'\n";
                }
                return 0;
            }

            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS", IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY), L"enum-iat-eat-hooks"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"moduleCount=" << response->moduleCount << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_IAT_EAT_HOOK_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] class=" << entry->hookClass
                           << L" status=" << entry->status
                           << L" ordinal=" << entry->ordinal
                           << L" thunk=" << hex64(entry->thunkAddress)
                           << L" current=" << hex64(entry->currentTarget)
                           << L" expected=" << hex64(entry->expectedTarget)
                           << L" function='" << fixedAnsiWide(entry->functionName, sizeof(entry->functionName))
                           << L"' module='" << fixedWide(entry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS) << L"'\n";
            }
            return 0;
        }

        if (sub == L"patch-inline-hook")
        {
            KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST request{};
            KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE response{};
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.mode = requireOptionU32(args, L"--mode");
            request.functionAddress = requireOptionU64(args, L"--function");
            const std::vector<std::uint8_t> expected = loadBytesFromHexOrFile(args, L"--expected-hex", L"--expected-file", KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, true);
            const std::vector<std::uint8_t> restore = loadBytesFromHexOrFile(args, L"--restore-hex", L"--restore-file", KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, false);
            request.patchBytes = static_cast<unsigned long>(std::max(expected.size(), restore.size()));
            copyBytesToFixed(request.expectedCurrentBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, expected);
            copyBytesToFixed(request.restoreBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, restore);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK, L"IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"bytesPatched=" << response.bytesPatched
                       << L" fieldFlags=0x" << std::hex << response.fieldFlags
                       << L" function=" << hex64(response.functionAddress) << std::dec << L"\n";
            printBytesInline(L"beforeBytes", response.beforeBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES);
            printBytesInline(L"afterBytes", response.afterBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES);
            return 0;
        }

        if (sub == L"query-driver-object")
        {
            KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL);
            request.maxDevices = getOptionU32(args, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(args, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            copyRequiredWideOption(args, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT", IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->deviceEntrySize, sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY), L"query-driver-object"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalDeviceCount, response->returnedDeviceCount, response->deviceEntrySize, io.bytesReturned);
            std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" driverObject=" << hex64(response->driverObjectAddress)
                       << L" driverStart=" << hex64(response->driverStart)
                       << L" driverSection=" << hex64(response->driverSection)
                       << L" driverUnload=" << hex64(response->driverUnload)
                       << std::dec << L" majorFunctionCount=" << response->majorFunctionCount
                       << L" driverFlags=0x" << std::hex << response->driverFlags
                       << std::dec << L" driverSize=" << response->driverSize << L"\n";
            dumpWideText(L"driverName", fixedWide(response->driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS));
            dumpWideText(L"serviceKeyName", fixedWide(response->serviceKeyName, KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS));
            dumpWideText(L"imagePath", fixedWide(response->imagePath, KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS));
            const std::size_t majorCount = std::min<std::size_t>(response->majorFunctionCount, KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT);
            for (std::size_t i = 0; i < majorCount; ++i)
            {
                const auto& major = response->majorFunctions[i];
                std::wcout << L"  major[" << i << L"] fn=" << major.majorFunction
                           << L" flags=0x" << std::hex << major.flags
                           << L" dispatch=" << hex64(major.dispatchAddress)
                           << L" moduleBase=" << hex64(major.moduleBase)
                           << std::dec << L" module='" << fixedWide(major.moduleName, KSWORD_ARK_DRIVER_MODULE_NAME_CHARS) << L"'\n";
            }
            const std::size_t parsed = responseCountLimit(response->returnedDeviceCount, available, getOptionU32(args, L"--limit", 64U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* device = reinterpret_cast<const KSWORD_ARK_DRIVER_DEVICE_ENTRY*>(buffer.data() + headerSize + (i * response->deviceEntrySize));
                std::wcout << L"  device[" << i << L"] depth=" << device->relationDepth
                           << L" type=0x" << std::hex << device->deviceType
                           << L" flags=0x" << device->flags
                           << L" object=" << hex64(device->deviceObjectAddress)
                           << L" attached=" << hex64(device->attachedDeviceObjectAddress)
                           << L" driver=" << hex64(device->driverObjectAddress)
                           << L" nameStatus=0x" << static_cast<unsigned long>(device->nameStatus)
                           << std::dec << L" name='" << fixedWide(device->deviceName, KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS) << L"'\n";
            }
            return 0;
        }

        if (sub == L"query-driver-integrity")
        {
            KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
            request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT);
            request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS);
            request.maxIdtVectorsPerCpu = getOptionU32(args, L"--max-idt-vectors", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
            request.maxDevices = getOptionU32(args, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(args, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            request.targetModuleBase = getOptionU64(args, L"--module-base", 0ULL);
            copyOptionalWideOption(args, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY", IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE), L"query-driver-integrity"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"flags=0x" << std::hex << response->flags
                       << L" sourceMask=0x" << response->sourceMask
                       << std::dec << L" cpuCount=" << response->cpuCount
                       << L" moduleCount=" << response->moduleCount << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] class=" << entry->evidenceClass
                           << L" risk=0x" << std::hex << entry->riskFlags
                           << L" source=0x" << entry->sourceMask
                           << L" object=" << hex64(entry->objectAddress)
                           << L" target=" << hex64(entry->targetAddress)
                           << L" ownerBase=" << hex64(entry->ownerModuleBase)
                           << std::dec << L" confidence=" << entry->confidence
                           << L" owner='" << fixedWide(entry->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS)
                           << L"' detail='" << fixedWide(entry->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }

        if (sub == L"force-unload-driver")
        {
            KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST request{};
            KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE response{};
            request.version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.timeoutMilliseconds = getOptionU32(args, L"--timeout-ms", 5000U);
            request.targetModuleBase = getOptionU64(args, L"--module-base", 0ULL);
            copyRequiredWideOption(args, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER, L"IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"flags=0x" << std::hex << response.flags
                       << L" waitStatus=0x" << static_cast<unsigned long>(response.waitStatus)
                       << L" driverObject=" << hex64(response.driverObjectAddress)
                       << L" unload=" << hex64(response.driverUnloadAddress)
                       << std::dec << L" cleanupFlagsApplied=" << response.cleanupFlagsApplied
                       << L" deletedDeviceCount=" << response.deletedDeviceCount
                       << L" callbackCandidates=" << response.callbackCandidates
                       << L" callbacksRemoved=" << response.callbacksRemoved
                       << L" callbackFailures=" << response.callbackFailures
                       << L" callbackLastStatus=0x" << std::hex << static_cast<unsigned long>(response.callbackLastStatus)
                       << std::dec << L" driverName='" << fixedWide(response.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) << L"'\n";
            return 0;
        }

        if (sub == L"query-cpu")
        {
            KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE, L"IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE", response, io)) return 3;
            printResponseBanner(response.version, response.fieldFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"logical=" << response.logicalProcessorCount
                       << L" active=" << response.activeProcessorCount
                       << L" packages=" << response.packageCount
                       << L" family=" << response.family
                       << L" model=" << response.model
                       << L" stepping=" << response.stepping
                       << L" featureMask=0x" << std::hex << response.featureMask
                       << L" leaf1Ecx=0x" << response.leaf1Ecx
                       << L" leaf1Edx=0x" << response.leaf1Edx
                       << std::dec << L" vendor='" << fixedAnsiWide(response.vendor, KSWORD_ARK_CPU_HARDWARE_VENDOR_CHARS)
                       << L"' brand='" << fixedAnsiWide(response.brand, KSWORD_ARK_CPU_HARDWARE_BRAND_CHARS) << L"'\n";
            return 0;
        }

        if (sub == L"query-phys-layout")
        {
            KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT, L"IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT", response, io)) return 3;
            printResponseBanner(response.version, response.fieldFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"rangeCount=" << response.rangeCount
                       << L" zeroLengthRangeCount=" << response.zeroLengthRangeCount
                       << L" truncated=" << response.truncated
                       << L" totalPhysicalBytes=" << response.totalPhysicalBytes
                       << L" highestPhysicalAddress=" << hex64(response.highestPhysicalAddress)
                       << L" largestRangeBytes=" << response.largestRangeBytes
                       << L" smallestRangeBytes=" << response.smallestRangeBytes
                       << L" firstBaseAddress=" << hex64(response.firstBaseAddress)
                       << L" lastEndAddress=" << hex64(response.lastEndAddress)
                       << L" estimatedAddressSpaceGapBytes=" << response.estimatedAddressSpaceGapBytes << L"\n";
            return 0;
        }
        if (sub == L"cid")
        {
            KSWORD_ARK_ENUM_CID_TABLE_REQUEST request{};
            request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL);
            request.maxEntries = getOptionU32(args, L"--max-entries", 4096U);
            request.maxVisitCount = getOptionU32(args, L"--max-visits", 65536U);
            request.startCid = getOptionU32(args, L"--start-cid", 0U);
            request.endCid = getOptionU32(args, L"--end-cid", 0U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_CID_TABLE", IOCTL_KSWORD_ARK_ENUM_CID_TABLE, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"kernel cid", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_CID_TABLE_RESPONSE) - sizeof(KSWORD_ARK_CID_TABLE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_CID_TABLE_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_CID_TABLE_ENTRY), L"kernel cid"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"flags=0x" << std::hex << response->flags
                       << L" pspCidTable=" << hex64(response->pspCidTableAddress)
                       << L" dyn=0x" << response->dynDataCapabilityMask
                       << std::dec << L" visited=" << response->visitedCount
                       << L" maxVisitCount=" << response->maxVisitCount << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_CID_TABLE_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] cid=" << entry->cidValue
                           << L" index=" << entry->handleIndex
                           << L" kind=" << entry->expectedObjectKind
                           << L" lookup=" << entry->lookupStatus
                           << L" flags=0x" << std::hex << entry->flags
                           << L" object=" << hex64(entry->objectAddress)
                           << L" refStatus=0x" << static_cast<unsigned long>(entry->referenceStatus)
                           << std::dec << L"\n";
            }
            return 0;
        }
        if (sub == L"object-summary")
        {
            // kernel object-summary:
            // - Inputs: --target-kind plus either --cid and/or --object evidence.
            // - Processing: sends the fixed KernelObject summary protocol and
            //   prints object header/type/counter status without mutating objects.
            // - Returns: normalized CLI status for old-driver compatibility.
            KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST request{};
            KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE response{};
            request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_ALL);
            request.targetKind = requireOptionU32(args, L"--target-kind");
            request.cidValue = getOptionU32(args, L"--cid", 0U);
            request.expectedObjectAddress = getOptionU64(args, L"--object", 0ULL);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY, L"IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY", request, response, io))
            {
                return normalizeIoctlRc(L"kernel object-summary", io, 3);
            }
            printResponseBanner(response.version, response.status, response.lookupStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" fields=0x" << std::hex << response.fieldFlags
                       << L" object=" << hex64(response.objectAddress)
                       << L" expected=" << hex64(response.expectedObjectAddress)
                       << L" typeObject=" << hex64(response.objectTypeAddress)
                       << L" dyn=0x" << response.dynDataCapabilityMask
                       << std::dec << L" targetKind=" << response.targetKind
                       << L" cid=" << response.cidValue
                       << L" typeStatus=0x" << std::hex << static_cast<unsigned long>(response.typeStatus)
                       << L" counterStatus=0x" << static_cast<unsigned long>(response.counterStatus)
                       << std::dec << L" headerStatus=" << response.objectHeaderStatus
                       << L" typeIndex=" << response.typeIndex
                       << L" pointerCount=" << response.pointerCount
                       << L" handleCount=" << response.handleCount
                       << L" otNameOffset=0x" << std::hex << response.otNameOffset
                       << L" otIndexOffset=0x" << response.otIndexOffset
                       << std::dec << L" type='" << fixedWide(response.typeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)
                       << L"' detail='" << fixedWide(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS) << L"'\n";
            return 0;
        }
        if (sub == L"ipc")
        {
            KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST request{};
            KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE response{};
            request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(args, L"--pid", 0U);
            request.handleValue = getOptionU64(args, L"--handle", 0ULL);
            request.maxEntries = getOptionU32(args, L"--max-entries", 128U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY, L"IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY", request, response, io))
            {
                return normalizeIoctlRc(L"kernel ipc", io, 3);
            }
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" fields=0x" << std::hex << response.fieldFlags
                       << L" handle=" << hex64(response.handleValue)
                       << L" alpcObject=" << hex64(response.alpcObjectAddress)
                       << L" dyn=0x" << response.dynDataCapabilityMask
                       << std::dec << L" pid=" << response.processId
                       << L" alpcStatus=" << ipcSummaryStatusName(response.alpcStatus)
                       << L"(" << response.alpcStatus << L")"
                       << L" pipeStatus=" << ipcSummaryStatusName(response.namedPipeStatus)
                       << L"(" << response.namedPipeStatus << L")"
                       << L" mailslotStatus=" << ipcSummaryStatusName(response.mailslotStatus)
                       << L"(" << response.mailslotStatus << L")"
                       << L" type='" << fixedWide(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)
                       << L"' detail='" << fixedWide(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS) << L"'\n";
            return 0;
        }
        if (sub == L"callbacks")
        {
            return queryCallbackInventory(args);
        }
        if (sub == L"hooks")
        {
            KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL);
            request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES);
            copyOptionalWideOption(args, L"--module", request.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS", IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"kernel hooks", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY), L"kernel hooks"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_INLINE_HOOK_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] status=" << entry->status
                           << L" type=" << entry->hookType
                           << L" function=" << hex64(entry->functionAddress)
                           << L" target=" << hex64(entry->targetAddress)
                           << L" module='" << fixedWide(entry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS)
                           << L"' functionName='" << fixedAnsiWide(entry->functionName, sizeof(entry->functionName)) << L"'\n";
            }
            return 0;
        }

        std::wcerr << L"error: unknown kernel subcommand '" << sub << L"'\n";
        return 1;
    }

    // printCallbackEventPacket renders one callback wait-event response.
    // Inputs: fixed event packet and returned byte count.
    // Processing: prints rule identity, decision metadata, paths and patterns.
    // Returns: no value.
    void printCallbackEventPacket(const KSWORD_ARK_CALLBACK_EVENT_PACKET& packet, DWORD bytesReturned)
    {
        std::wcout << L"size=" << packet.size
                   << L" version=" << packet.version
                   << L" bytesReturned=" << bytesReturned
                   << L" eventGuid=" << formatGuid128(packet.eventGuid) << L"\n";
        std::wcout << L"callbackType=" << packet.callbackType
                   << L" operationType=" << packet.operationType
                   << L" action=" << packet.action
                   << L" matchMode=" << packet.matchMode
                   << L" defaultDecision=" << packet.defaultDecision
                   << L" timeoutMs=" << packet.timeoutMs
                   << L" groupId=" << packet.groupId
                   << L" ruleId=" << packet.ruleId
                   << L" pid=" << packet.originatingPid
                   << L" tid=" << packet.originatingTid
                   << L" sessionId=" << packet.sessionId
                   << L" pathUnavailable=" << packet.pathUnavailable << L"\n";
        std::wcout << L"createdAtUtc100ns=" << packet.createdAtUtc100ns
                   << L" deadlineUtc100ns=" << packet.deadlineUtc100ns << L"\n";
        dumpWideText(L"initiatorPath", fixedWide(packet.initiatorPath, KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS));
        dumpWideText(L"targetPath", fixedWide(packet.targetPath, KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS));
        dumpWideText(L"ruleInitiatorPattern", fixedWide(packet.ruleInitiatorPattern, KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS));
        dumpWideText(L"ruleTargetPattern", fixedWide(packet.ruleTargetPattern, KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS));
        dumpWideText(L"groupName", fixedWide(packet.groupName, KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS));
        dumpWideText(L"ruleName", fixedWide(packet.ruleName, KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS));
    }

    // queryCallbackInventory：分页打印只读 callback/hook/filter 证据，绝不调用移除控制。
    // 输入：flags、每页最大条目数以及控制台可见条目上限。
    // 处理：依据 nextIndex 连续请求，直到达到可见上限或驱动明确返回末页。
    // 返回：成功返回 0；协议或 IOCTL 失败返回对应 CLI 错误码。
    int queryCallbackInventory(const NamedArgs& args)
    {
        KSWORD_ARK_ENUM_CALLBACKS_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);
        request.maxEntries = getOptionU32(args, L"--max-entries", 512U);
        const std::size_t visibleLimit = getOptionU32(args, L"--limit", 128U);
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) - sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        std::size_t printedCount = 0U;
        std::uint32_t pageCount = 0U;
        std::uint32_t startIndex = 0U;
        std::uint64_t snapshotHash = 0U;
        std::uint32_t snapshotTotalCount = 0U;

        while (printedCount < visibleLimit)
        {
            IoctlResult io{};
            std::fill(buffer.begin(), buffer.end(), 0U);
            request.startIndex = startIndex;
            request.expectedSnapshotHash = snapshotHash;
            request.expectedTotalCount = snapshotTotalCount;
            request.snapshotPolicy = snapshotHash == 0U
                ? KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_NONE
                : KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH;

            const int rc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_ENUM_CALLBACKS",
                IOCTL_KSWORD_ARK_ENUM_CALLBACKS,
                &request,
                sizeof(request),
                buffer,
                io);
            if (rc != 0)
            {
                return normalizeIoctlRc(L"callback inventory", io, rc);
            }

            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*>(buffer.data());
            if ((response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED) != 0UL)
            {
                std::wcerr << L"error: callback inventory changed during pagination; rerun the command\n";
                return 4;
            }
            if ((response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID) == 0UL ||
                response->snapshotHash == 0ULL)
            {
                std::wcerr << L"error: callback enum v3 response omitted snapshot metadata\n";
                return 4;
            }
            if (snapshotHash == 0U)
            {
                snapshotHash = response->snapshotHash;
                snapshotTotalCount = response->totalCount;
            }
            else if (snapshotHash != response->snapshotHash ||
                snapshotTotalCount != response->totalCount)
            {
                std::wcerr << L"error: callback inventory snapshot metadata is inconsistent\n";
                return 4;
            }
            std::size_t available = 0U;
            try
            {
                available = validateVariable(
                    io.bytesReturned,
                    headerSize,
                    response->entrySize,
                    sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY),
                    L"callback enum");
            }
            catch (...)
            {
                return 4;
            }

            if (pageCount == 0U)
            {
                printResponseBanner(response->version, response->flags, response->lastStatus, io.bytesReturned);
                printCountHeader(
                    response->version,
                    response->totalCount,
                    response->returnedCount,
                    response->entrySize,
                    io.bytesReturned);
                std::wcout << L"snapshotGeneration=" << hex64(response->enumerationGeneration)
                           << L" snapshotHash=" << hex64(response->snapshotHash)
                           << L" snapshotHashValid=1 identityHashValid="
                           << (((response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID) != 0UL) ? 1 : 0)
                           << L"\n";
            }

            const std::size_t remainingVisible = visibleLimit - printedCount;
            const std::size_t parsed = responseCountLimit(
                response->returnedCount,
                available,
                remainingVisible);
            for (std::size_t i = 0U; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_CALLBACK_ENUM_ENTRY*>(
                    buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << (static_cast<std::size_t>(startIndex) + i)
                           << L"] class=" << entry->callbackClass
                           << L" registrationType=" << entry->registrationType
                           << L" source=" << entry->source
                           << L" status=" << entry->status
                           << L" fields=0x" << std::hex << entry->fieldFlags
                           << L" callback=" << hex64(entry->callbackAddress)
                           << L" context=" << hex64(entry->contextAddress)
                           << L" registration=" << hex64(entry->registrationAddress)
                           << L" rawStorage=" << hex64(entry->rawStorageValue)
                           << L" generation=" << hex64(entry->enumerationGeneration)
                           << L" identityHash=" << hex64(entry->identityHash)
                           << L" moduleBase=" << hex64(entry->moduleBase)
                           << std::dec << L" operationMask=0x" << std::hex << entry->operationMask
                           << L" objectTypeMask=0x" << entry->objectTypeMask
                           << std::dec << L" name='" << fixedWide(entry->name, KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS)
                           << L"' altitude='" << fixedWide(entry->altitude, KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS)
                           << L"' detail='" << fixedWide(entry->detail, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS) << L"'\n";
            }
            printedCount += parsed;
            ++pageCount;

            const bool hasMore = (response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA) != 0UL;
            if (!hasMore || printedCount >= visibleLimit)
            {
                break;
            }
            if (response->returnedCount == 0UL || response->nextIndex <= startIndex || pageCount >= 128U)
            {
                std::wcerr << L"error: callback enum pagination did not make forward progress\n";
                return 4;
            }
            startIndex = response->nextIndex;
        }
        std::wcout << L"pages=" << pageCount
                   << L" snapshotHash=" << hex64(snapshotHash)
                   << L" rowsPrinted=" << printedCount << L"\n";
        return 0;
    }

    // commandCallbackFamily implements callback rule/control IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: handles blob rule loading, event wait/answer and external callback removal.
    // Returns: process exit code.
    int commandCallbackFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: callback requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        if (sub == L"monitor-start" || sub == L"monitor-stop" ||
            sub == L"monitor-status" || sub == L"monitor-read")
        {
            return commandArkDriverCallbackMonitor(argc, argv);
        }
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"set-rules")
        {
            std::vector<std::uint8_t> blob = readRequiredBlobOption(args, L"--blob", kMaxCommandBytes);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_SET_CALLBACK_RULES", IOCTL_KSWORD_ARK_SET_CALLBACK_RULES, blob.data(), checkedDwordSize(blob.size()), GENERIC_READ | GENERIC_WRITE);
        }
        if (sub == L"runtime-state")
        {
            KSWORD_ARK_CALLBACK_RUNTIME_STATE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE, L"IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE", response, io)) return 3;
            printResponseBanner(response.version, response.driverOnline, 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" callbacksRegisteredMask=0x" << std::hex << response.callbacksRegisteredMask
                       << std::dec << L" globalEnabled=" << response.globalEnabled
                       << L" rulesApplied=" << response.rulesApplied
                       << L" groupCount=" << response.groupCount
                       << L" ruleCount=" << response.ruleCount
                       << L" pendingDecisionCount=" << response.pendingDecisionCount
                       << L" waitingReceiverCount=" << response.waitingReceiverCount
                       << L" appliedRuleVersion=" << response.appliedRuleVersion
                       << L" appliedAtUtc100ns=" << response.appliedAtUtc100ns << L"\n";
            // 降级启动时每类回调的原始 NTSTATUS，0 表示注册正常。
            std::wcout << std::hex
                       << L"waitQueueStatus=0x" << static_cast<std::uint32_t>(response.waitQueueStatus)
                       << L" registryCallbackStatus=0x" << static_cast<std::uint32_t>(response.registryCallbackStatus)
                       << L" processCallbackStatus=0x" << static_cast<std::uint32_t>(response.processCallbackStatus)
                       << L" threadCallbackStatus=0x" << static_cast<std::uint32_t>(response.threadCallbackStatus)
                       << L" imageCallbackStatus=0x" << static_cast<std::uint32_t>(response.imageCallbackStatus)
                       << L" objectCallbackStatus=0x" << static_cast<std::uint32_t>(response.objectCallbackStatus)
                       << std::dec << L"\n";
            return 0;
        }
        if (sub == L"wait-event")
        {
            KSWORD_ARK_CALLBACK_WAIT_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
            request.waiterTag = getOptionU32(args, L"--waiter-tag", 0U);
            KSWORD_ARK_CALLBACK_EVENT_PACKET response{};
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT, L"IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT", request, response, io)) return 3;
            printCallbackEventPacket(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"answer-event")
        {
            KSWORD_ARK_CALLBACK_ANSWER_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
            request.eventGuid = parseGuid128(requireOptionText(args, L"--event-guid"));
            request.decision = requireOptionU32(args, L"--decision");
            request.sourceSessionId = requireOptionU32(args, L"--source-session-id");
            request.answeredAtUtc100ns = getOptionU64(args, L"--answered-at", currentUtc100ns());
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT", IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT, &request, sizeof(request));
        }
        if (sub == L"cancel-pending")
        {
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS", IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS, nullptr, 0U);
        }
        if (sub == L"remove")
        {
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST request{};
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
            request.callbackClass = requireOptionU32(args, L"--class");
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.callbackAddress = requireOptionU64(args, L"--callback");
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK, L"IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.callbackClass, response.ntstatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" callback=" << hex64(response.callbackAddress)
                       << L" moduleBase=" << hex64(response.moduleBase)
                       << L" moduleSize=" << response.moduleSize
                       << L" mappingFlags=0x" << std::hex << response.mappingFlags << std::dec << L"\n";
            dumpWideText(L"modulePath", fixedWide(response.modulePath, KSWORD_ARK_EXTERNAL_CALLBACK_MODULE_NAME_MAX_CHARS));
            dumpWideText(L"serviceName", fixedWide(response.serviceName, KSWORD_ARK_EXTERNAL_CALLBACK_SERVICE_NAME_MAX_CHARS));
            return 0;
        }
        if (sub == L"remove-ex")
        {
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST request{};
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
            request.callbackClass = requireOptionU32(args, L"--class");
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.callbackAddress = requireOptionU64(args, L"--callback");
            request.registrationAddress = getOptionU64(args, L"--registration", 0ULL);
            request.rawStorageValue = getOptionU64(args, L"--raw-storage", 0ULL);
            request.enumerationGeneration = getOptionU64(args, L"--generation", 0ULL);
            request.identityHash = getOptionU64(args, L"--identity-hash", 0ULL);
            request.source = getOptionU32(args, L"--source", 0U);
            request.operationMask = getOptionU32(args, L"--operation-mask", 0U);
            request.objectTypeMask = getOptionU32(args, L"--object-type-mask", 0U);
            request.trustFlags = getOptionU32(args, L"--trust-flags", 0U);
            request.removeBehavior = getOptionU32(args, L"--remove-behavior", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX, L"IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.callbackClass, response.ntstatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" source=" << response.source
                       << L" callback=" << hex64(response.callbackAddress)
                       << L" registration=" << hex64(response.registrationAddress)
                       << L" rawStorage=" << hex64(response.rawStorageValue)
                       << L" generation=" << response.enumerationGeneration
                       << L" identityHash=" << hex64(response.identityHash)
                       << L" revalidationStatus=0x" << std::hex << static_cast<unsigned long>(response.revalidationStatus)
                       << L" trustFlags=0x" << response.trustFlags
                       << L" removeBehavior=0x" << response.removeBehavior
                       << L" mappingFlags=0x" << response.mappingFlags
                       << L" moduleBase=" << hex64(response.moduleBase)
                       << std::dec << L" moduleSize=" << response.moduleSize << L"\n";
            dumpWideText(L"modulePath", fixedWide(response.modulePath, KSWORD_ARK_EXTERNAL_CALLBACK_MODULE_NAME_MAX_CHARS));
            dumpWideText(L"serviceName", fixedWide(response.serviceName, KSWORD_ARK_EXTERNAL_CALLBACK_SERVICE_NAME_MAX_CHARS));
            dumpWideText(L"message", fixedWide(response.message, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS));
            return 0;
        }
        if (sub == L"set-minifilter-bypass-pids")
        {
            const std::vector<std::uint32_t> processIds = parsePidListText(requireOptionText(args, L"--pids"));
            KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.pidCount = static_cast<unsigned long>(processIds.size());
            for (std::size_t index = 0U; index < processIds.size(); ++index)
            {
                request.processIds[index] = static_cast<unsigned long>(processIds[index]);
            }
            return runNoOutputIoctl(
                L"IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS",
                IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS,
                &request,
                sizeof(request));
        }
        if (sub == L"query-minifilter-bypass-pids")
        {
            KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE response{};
            if (!sendFixedNoInput(
                IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS,
                L"IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS",
                response,
                io))
            {
                return 3;
            }
            if (response.size < sizeof(response) ||
                response.version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION ||
                response.pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT)
            {
                std::wcerr << L"error: minifilter bypass PID response header invalid\n";
                return 4;
            }
            printResponseBanner(response.version, response.pidCount, 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" flags=0x" << std::hex << response.flags
                       << std::dec << L" pidCount=" << response.pidCount << L" pids=";
            for (unsigned long index = 0UL; index < response.pidCount; ++index)
            {
                if (index != 0UL)
                {
                    std::wcout << L",";
                }
                std::wcout << response.processIds[index];
            }
            std::wcout << L"\n";
            return 0;
        }
        if (sub == L"enum")
        {
            return queryCallbackInventory(args);
        }
        std::wcerr << L"error: unknown callback subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandDynFamily implements DynData status, field and profile IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: handles fixed status/capability queries and raw profile blobs.
    // Returns: process exit code.
    int commandDynFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: dyn requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"status")
        {
            KSW_QUERY_DYN_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_DYN_STATUS, L"IOCTL_KSWORD_ARK_QUERY_DYN_STATUS", response, io))
            {
                return normalizeIoctlRc(L"dyn status", io, 3);
            }
            printResponseBanner(response.version, response.statusFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" systemInformerDataVersion=" << response.systemInformerDataVersion
                       << L" systemInformerDataLength=" << response.systemInformerDataLength
                       << L" matchedProfileClass=" << response.matchedProfileClass
                       << L" matchedProfileOffset=" << response.matchedProfileOffset
                       << L" matchedFieldsId=" << response.matchedFieldsId
                       << L" fieldCount=" << response.fieldCount
                       << L" capabilityMask=0x" << std::hex << response.capabilityMask << std::dec << L"\n";
            printModuleIdentity(L"ntoskrnl", response.ntoskrnl);
            printModuleIdentity(L"lxcore", response.lxcore);
            dumpWideText(L"unavailableReason", fixedWide(response.unavailableReason, KSW_DYN_REASON_CHARS));
            return 0;
        }
        if (sub == L"fields")
        {
            std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS", IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS, nullptr, 0U, buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"dyn fields", io, rc);
            constexpr std::size_t headerSize = sizeof(KSW_QUERY_DYN_FIELDS_RESPONSE) - sizeof(KSW_DYN_FIELD_ENTRY);
            const auto* response = reinterpret_cast<const KSW_QUERY_DYN_FIELDS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSW_DYN_FIELD_ENTRY), L"dyn fields"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSW_DYN_FIELD_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] id=" << entry->fieldId
                           << L" flags=0x" << std::hex << entry->flags
                           << L" source=" << std::dec << entry->source
                           << L" offset=0x" << std::hex << entry->offset
                           << L" capabilityMask=0x" << entry->capabilityMask
                           << std::dec << L" field='" << fixedAnsiWide(entry->fieldName, KSW_DYN_FIELD_NAME_CHARS)
                           << L"' sourceName='" << fixedAnsiWide(entry->sourceName, KSW_DYN_FIELD_SOURCE_CHARS)
                           << L"' feature='" << fixedAnsiWide(entry->featureName, KSW_DYN_FIELD_FEATURE_CHARS) << L"'\n";
            }
            return 0;
        }
        if (sub == L"capabilities")
        {
            KSW_QUERY_CAPABILITIES_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_CAPABILITIES, L"IOCTL_KSWORD_ARK_QUERY_CAPABILITIES", response, io))
            {
                return normalizeIoctlRc(L"dyn capabilities", io, 3);
            }
            printResponseBanner(response.version, response.statusFlags, 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" capabilityMask=0x" << std::hex << response.capabilityMask
                       << std::dec << L" reserved=" << response.reserved << L"\n";
            return 0;
        }
        if (sub == L"profile" || sub == L"v4-modules")
        {
            return queryDynV4Modules(args);
        }
        if (sub == L"v4-capabilities" || sub == L"capability-groups")
        {
            return queryDynV4CapabilityGroups(args);
        }
        if (sub == L"v4-missing" || sub == L"missing-items")
        {
            return queryDynV4MissingItems(args);
        }
        if (sub == L"v4-items")
        {
            return queryDynV4Items(args);
        }
        if (sub == L"apply-profile-v4")
        {
            // apply-profile-v4 用途：
            // - 输入：--blob 指向由 PDB extractor 后续生成的 KSW_APPLY_DYN_PROFILE_V4_REQUEST 原始包；
            // - 处理：仅做 CLI 透传，不在用户态重复定义协议字段或猜测偏移；
            // - 返回：打印驱动侧校验/应用摘要，旧驱动缺 IOCTL 时稳定返回 unsupported / unavailable。
            const std::size_t maxBytes =
                KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE +
                (static_cast<std::size_t>(KSW_DYN_V4_MAX_ITEMS_PER_MODULE) * sizeof(KSW_DYN_V4_ITEM_PACKET));
            std::vector<std::uint8_t> blob = readRequiredBlobOption(args, L"--blob", maxBytes);
            KSW_APPLY_DYN_PROFILE_V4_RESPONSE response{};
            if (!sendBlobFixedResponse(
                    IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4,
                    L"IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4",
                    blob,
                    response,
                    io,
                    GENERIC_READ))
            {
                if (isUnsupportedTransportError(io.win32Error))
                {
                    return commandUnsupported(L"dyn apply-profile-v4", L"driver does not expose IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4");
                }
                return 3;
            }
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), response.status, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" statusFlags=0x" << std::hex << response.statusFlags
                       << std::dec << L" appliedItemCount=" << response.appliedItemCount
                       << L" rejectedItemCount=" << response.rejectedItemCount
                       << L" required=" << response.presentRequiredItemCount << L"/" << response.requiredItemCount
                       << L" optional=" << response.presentOptionalItemCount << L"/" << response.optionalItemCount
                       << L" activeCapabilityGroupCount=" << response.activeCapabilityGroupCount
                       << L" missingRequired=" << response.missingRequiredItemCount
                       << L" missingOptional=" << response.missingOptionalItemCount << L"\n";
            printV4ModuleIdentity(response.module);
            dumpWideText(L"message", fixedWide(response.message, KSW_DYN_REASON_CHARS));
            return 0;
        }
        if (sub == L"apply-profile")
        {
            const std::size_t maxBytes = KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE + (static_cast<std::size_t>(KSW_DYN_PROFILE_MAX_FIELDS) * sizeof(KSW_DYN_PROFILE_FIELD_PACKET));
            std::vector<std::uint8_t> blob = readRequiredBlobOption(args, L"--blob", maxBytes);
            KSW_APPLY_DYN_PROFILE_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE, L"IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" appliedFieldCount=" << response.appliedFieldCount
                       << L" rejectedFieldCount=" << response.rejectedFieldCount
                       << L" unknownFieldCount=" << response.unknownFieldCount
                       << L" statusFlags=0x" << std::hex << response.statusFlags
                       << L" capabilityMask=0x" << response.capabilityMask << std::dec << L"\n";
            dumpWideText(L"message", fixedWide(response.message, KSW_DYN_REASON_CHARS));
            return 0;
        }
        if (sub == L"apply-profile-ex")
        {
            const std::size_t maxBytes = KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE + (static_cast<std::size_t>(KSW_DYN_PROFILE_EX_MAX_ITEMS) * sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET));
            std::vector<std::uint8_t> blob = readRequiredBlobOption(args, L"--blob", maxBytes);
            KSW_APPLY_DYN_PROFILE_EX_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX, L"IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" appliedItemCount=" << response.appliedItemCount
                       << L" rejectedItemCount=" << response.rejectedItemCount
                       << L" unknownItemCount=" << response.unknownItemCount
                       << L" statusFlags=0x" << std::hex << response.statusFlags
                       << L" capabilityMask=0x" << response.capabilityMask << std::dec << L"\n";
            dumpWideText(L"message", fixedWide(response.message, KSW_DYN_REASON_CHARS));
            return 0;
        }
        std::wcerr << L"error: unknown dyn subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandCapabilityFamily implements the unified driver capability query.
    // Inputs: argc/argv from wmain.
    // Processing: parses a variable response containing feature rows.
    // Returns: process exit code.
    int commandCapabilityFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: capability requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub != L"query-driver-capabilities")
        {
            std::wcerr << L"error: unknown capability subcommand '" << sub << L"'\n";
            return 1;
        }

        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES", IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES, nullptr, 0U, buffer, io);
        if (rc != 0) return rc;
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE) - sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY), L"driver capabilities"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->statusFlags, response->lastErrorStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalFeatureCount, response->returnedFeatureCount, response->entrySize, io.bytesReturned);
        std::wcout << L"size=" << response->size
                   << L" driverProtocolVersion=0x" << std::hex << response->driverProtocolVersion
                   << L" securityPolicyFlags=0x" << response->securityPolicyFlags
                   << L" dynDataStatusFlags=0x" << response->dynDataStatusFlags
                   << L" dynDataCapabilityMask=0x" << response->dynDataCapabilityMask
                   << std::dec << L" lastErrorSource='" << fixedAnsiWide(response->lastErrorSource, KSWORD_ARK_CAPABILITY_ERROR_SOURCE_CHARS)
                   << L"' lastErrorSummary='" << fixedAnsiWide(response->lastErrorSummary, KSWORD_ARK_CAPABILITY_ERROR_SUMMARY_CHARS) << L"'\n";
        const std::size_t parsed = responseCountLimit(response->returnedFeatureCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSWORD_ARK_FEATURE_CAPABILITY_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] featureId=" << entry->featureId
                       << L" state=" << entry->state
                       << L" flags=0x" << std::hex << entry->flags
                       << L" requiredPolicy=0x" << entry->requiredPolicyFlags
                       << L" deniedPolicy=0x" << entry->deniedPolicyFlags
                       << L" requiredDyn=0x" << entry->requiredDynDataMask
                       << L" presentDyn=0x" << entry->presentDynDataMask
                       << std::dec << L" feature='" << fixedAnsiWide(entry->featureName, KSWORD_ARK_CAPABILITY_NAME_CHARS)
                       << L"' stateName='" << fixedAnsiWide(entry->stateName, KSWORD_ARK_CAPABILITY_STATE_CHARS)
                       << L"' reason='" << fixedAnsiWide(entry->reasonText, KSWORD_ARK_CAPABILITY_REASON_CHARS) << L"'\n";
        }
        return 0;
    }

    // commandThreadFamily implements thread enumeration and cross-view IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: issues variable response queries and prints bounded rows.
    // Returns: process exit code.
    int commandThreadFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: thread requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"enum")
        {
            KSWORD_ARK_ENUM_THREAD_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(args, L"--pid", 0U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_THREAD", IOCTL_KSWORD_ARK_ENUM_THREAD, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_THREAD_RESPONSE) - sizeof(KSWORD_ARK_THREAD_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_THREAD_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_THREAD_ENTRY), L"thread enum"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_THREAD_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                printSimpleThreadEntry(*entry);
            }
            return 0;
        }
        if (sub == L"crossview")
        {
            KSWORD_ARK_THREAD_CROSSVIEW_REQUEST request{};
            request.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(args, L"--pid", 0U);
            request.startTid = getOptionU32(args, L"--start-tid", 0U);
            request.endTid = getOptionU32(args, L"--end-tid", 0U);
            request.maxNodes = getOptionU32(args, L"--max-nodes", KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW", IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"thread crossview", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW), L"thread crossview"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"dynDataCapabilityMask=0x" << std::hex << response->dynDataCapabilityMask
                       << L" missingCapabilityMask=0x" << response->missingCapabilityMask << std::dec << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_THREAD_CROSSVIEW_ROW*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] pid=" << row->processId
                           << L" tid=" << row->threadId
                           << L" object=" << hex64(row->objectAddress)
                           << L" processObject=" << hex64(row->processObjectAddress)
                           << L" start=" << hex64(row->startAddress)
                           << L" source=0x" << std::hex << row->sourceMask
                           << L" anomaly=0x" << row->anomalyFlags
                           << L" last=0x" << static_cast<unsigned long>(row->lastStatus)
                           << std::dec << L" confidence=" << row->confidence
                           << L" image='" << fixedAnsiWide(row->imageName, sizeof(row->imageName))
                           << L"' detail='" << fixedAnsiWide(row->detail, KSWORD_ARK_CROSSVIEW_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        if (sub == L"detail")
        {
            // thread detail:
            // - Inputs: --tid is required; --pid narrows the expected owner
            //   process when the caller already has context.
            // - Processing: requests fixed ETHREAD/KTHREAD runtime detail and
            //   prints object, start, stack, I/O and global evidence fields.
            // - Returns: normalized CLI status.
            KSWORD_ARK_THREAD_DETAIL_REQUEST request{};
            KSWORD_ARK_THREAD_DETAIL_RESPONSE response{};
            request.version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL);
            request.threadId = requireOptionU32(args, L"--tid");
            request.processId = getOptionU32(args, L"--pid", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL, L"IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL", request, response, io))
            {
                return normalizeIoctlRc(L"thread detail", io, 3);
            }
            printThreadDetail(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"runtime-fields")
        {
            // thread runtime-fields:
            // - Inputs: --tid, optional --pid, and --items sample descriptors.
            // - Processing: builds the variable ETHREAD/KTHREAD sample request
            //   and prints the bounded response rows.
            // - Returns: zero on printed rows, non-zero on parse/transport error.
            std::vector<std::uint8_t> input = buildThreadRuntimeFieldInput(args);
            std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
            const int rc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS",
                IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS,
                input.data(),
                checkedDwordSize(input.size()),
                buffer,
                io);
            if (rc != 0)
            {
                return normalizeIoctlRc(L"thread runtime-fields", io, rc);
            }
            return printRuntimeFieldSampleRows(buffer, io, args, L"thread runtime-fields");
        }
        std::wcerr << L"error: unknown thread subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandHandleFamily implements handle table and object queries.
    // Inputs: argc/argv from wmain.
    // Processing: queries process handles or details for one handle value.
    // Returns: process exit code.
    int commandHandleFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: handle requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"enum" || sub == L"object-table")
        {
            KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(args, L"--pid");
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES", IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"handle object table", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE) - sizeof(KSWORD_ARK_HANDLE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_HANDLE_ENTRY), L"handle enum"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->overallStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"processId=" << response->processId << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_HANDLE_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] pid=" << entry->processId
                           << L" handle=0x" << std::hex << entry->handleValue
                           << L" fields=0x" << entry->fieldFlags
                           << L" access=0x" << entry->grantedAccess
                           << L" attrs=0x" << entry->attributes
                           << L" object=" << hex64(entry->objectAddress)
                           << L" dyn=0x" << entry->dynDataCapabilityMask
                           << std::dec << L" typeIndex=" << entry->objectTypeIndex
                           << L" decodeStatus=" << entry->decodeStatus << L"\n";
            }
            return 0;
        }
        if (sub == L"query-object" || sub == L"object-header" || sub == L"type-matrix")
        {
            KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST request{};
            KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE response{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(args, L"--pid");
            request.handleValue = requireOptionU64(args, L"--handle");
            request.requestedAccess = getOptionU32(args, L"--access", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT, L"IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT", request, response, io))
            {
                return normalizeIoctlRc(L"handle object details", io, 3);
            }
            printResponseBanner(response.version, response.queryStatus, response.objectReferenceStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" pid=" << response.processId
                       << L" fields=0x" << std::hex << response.fieldFlags
                       << L" handle=" << hex64(response.handleValue)
                       << L" object=" << hex64(response.objectAddress)
                       << L" dyn=0x" << response.dynDataCapabilityMask
                       << L" typeStatus=0x" << static_cast<unsigned long>(response.typeStatus)
                       << L" nameStatus=0x" << static_cast<unsigned long>(response.nameStatus)
                       << L" proxyNtStatus=0x" << static_cast<unsigned long>(response.proxyNtStatus)
                       << std::dec << L" typeIndex=" << response.objectTypeIndex
                       << L" proxyStatus=" << response.proxyStatus
                       << L" requestedAccess=" << response.requestedAccess
                       << L" actualGrantedAccess=" << response.actualGrantedAccess
                       << L" proxyHandle=" << hex64(response.proxyHandle) << L"\n";
            dumpWideText(L"typeName", fixedWide(response.typeName, KSWORD_ARK_OBJECT_TYPE_NAME_CHARS));
            dumpWideText(L"objectName", fixedWide(response.objectName, KSWORD_ARK_OBJECT_NAME_CHARS));
            return 0;
        }
        std::wcerr << L"error: unknown handle subcommand '" << sub << L"'\n";
        return 1;
    }

    // printAlpcPortInfo renders one ALPC related-port packet.
    // Inputs: label and protocol port info.
    // Processing: prints relation, status, object pointers and optional name.
    // Returns: no value.
    void printAlpcPortInfo(const wchar_t* label, const KSWORD_ARK_ALPC_PORT_INFO& info)
    {
        std::wcout << L"  " << label
                   << L": relation=" << info.relation
                   << L" fields=0x" << std::hex << info.fieldFlags
                   << L" flags=0x" << info.flags
                   << L" object=" << hex64(info.objectAddress)
                   << L" context=" << hex64(info.portContext)
                   << L" basicStatus=0x" << static_cast<unsigned long>(info.basicStatus)
                   << L" nameStatus=0x" << static_cast<unsigned long>(info.nameStatus)
                   << std::dec << L" ownerPid=" << info.ownerProcessId
                   << L" state=" << info.state
                   << L" sequence=" << info.sequenceNo
                   << L" name='" << fixedWide(info.portName, KSWORD_ARK_ALPC_PORT_NAME_CHARS) << L"'\n";
    }

    // commandAlpcFamily implements ALPC port diagnostics.
    // Inputs: argc/argv from wmain.
    // Processing: queries an ALPC handle in a process.
    // Returns: process exit code.
    int commandAlpcFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: alpc requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub != L"query-port")
        {
            std::wcerr << L"error: unknown alpc subcommand '" << sub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_ALPC_PORT_REQUEST request{};
        KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE response{};
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL);
        request.processId = requireOptionU32(args, L"--pid");
        request.handleValue = requireOptionU64(args, L"--handle");
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_ALPC_PORT, L"IOCTL_KSWORD_ARK_QUERY_ALPC_PORT", request, response, io)) return 3;
        printResponseBanner(response.version, response.queryStatus, response.objectReferenceStatus, io.bytesReturned);
        std::wcout << L"size=" << response.size
                   << L" pid=" << response.processId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" handle=" << hex64(response.handleValue)
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" typeStatus=0x" << static_cast<unsigned long>(response.typeStatus)
                   << L" basicStatus=0x" << static_cast<unsigned long>(response.basicStatus)
                   << L" communicationStatus=0x" << static_cast<unsigned long>(response.communicationStatus)
                   << L" nameStatus=0x" << static_cast<unsigned long>(response.nameStatus)
                   << std::dec << L" typeName='" << fixedWide(response.typeName, KSWORD_ARK_ALPC_TYPE_NAME_CHARS) << L"'\n";
        printAlpcPortInfo(L"queryPort", response.queryPort);
        printAlpcPortInfo(L"connectionPort", response.connectionPort);
        printAlpcPortInfo(L"serverPort", response.serverPort);
        printAlpcPortInfo(L"clientPort", response.clientPort);
        return 0;
    }

    // commandSectionFamily implements process and file section mapping queries.
    // Inputs: argc/argv from wmain.
    // Processing: prints variable mapping rows with bounded parsing.
    // Returns: process exit code.
    int commandSectionFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: section requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"query-process")
        {
            KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(args, L"--pid");
            request.maxMappings = getOptionU32(args, L"--max-mappings", KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION", IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE) - sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY), L"section query-process"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"pid=" << response->processId
                       << L" fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" sectionObject=" << hex64(response->sectionObjectAddress)
                       << L" controlArea=" << hex64(response->controlAreaAddress)
                       << L" dyn=0x" << response->dynDataCapabilityMask << std::dec << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_SECTION_MAPPING_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] type=" << entry->viewMapType
                           << L" pid=" << entry->processId
                           << L" start=" << hex64(entry->startVa)
                           << L" end=" << hex64(entry->endVa) << L"\n";
            }
            return 0;
        }
        if (sub == L"query-file-mappings")
        {
            KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL);
            request.maxMappings = getOptionU32(args, L"--max-mappings", KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
            const std::wstring& path = requireOptionText(args, L"--path");
            request.pathLengthChars = boundedPathLength(path, KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS, path);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS", IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE) - sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY), L"section query-file-mappings"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" fileObject=" << hex64(response->fileObjectAddress)
                       << L" sectionPointers=" << hex64(response->sectionObjectPointersAddress)
                       << L" dataControlArea=" << hex64(response->dataControlAreaAddress)
                       << L" imageControlArea=" << hex64(response->imageControlAreaAddress)
                       << L" dyn=0x" << response->dynDataCapabilityMask << std::dec << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] sectionKind=" << entry->sectionKind
                           << L" type=" << entry->viewMapType
                           << L" pid=" << entry->processId
                           << L" controlArea=" << hex64(entry->controlAreaAddress)
                           << L" start=" << hex64(entry->startVa)
                           << L" end=" << hex64(entry->endVa) << L"\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown section subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandWslFamily implements WSL silo diagnostics.
    // Inputs: argc/argv from wmain.
    // Processing: sends pid/tid query and prints the fixed response.
    // Returns: process exit code.
    int commandWslFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: wsl requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub != L"query-silo")
        {
            std::wcerr << L"error: unknown wsl subcommand '" << sub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_WSL_SILO_REQUEST request{};
        KSWORD_ARK_QUERY_WSL_SILO_RESPONSE response{};
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_ALL);
        request.processId = getOptionU32(args, L"--pid", 0U);
        request.threadId = getOptionU32(args, L"--tid", 0U);
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_WSL_SILO, L"IOCTL_KSWORD_ARK_QUERY_WSL_SILO", request, response, io)) return 3;
        printResponseBanner(response.version, response.queryStatus, response.processLookupStatus, io.bytesReturned);
        std::wcout << L"size=" << response.size
                   << L" fieldFlags=0x" << std::hex << response.fieldFlags
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" processLookup=0x" << static_cast<unsigned long>(response.processLookupStatus)
                   << L" threadLookup=0x" << static_cast<unsigned long>(response.threadLookupStatus)
                   << std::dec << L" pid=" << response.processId
                   << L" tid=" << response.threadId
                   << L" processSubsystemType=" << response.processSubsystemType
                   << L" threadSubsystemType=" << response.threadSubsystemType
                   << L" linuxPid=" << response.linuxProcessId
                   << L" linuxTid=" << response.linuxThreadId
                   << L" siloRoutinesMask=0x" << std::hex << response.siloRoutinesMask << std::dec << L"\n";
        printModuleIdentity(L"lxcore", response.lxcore);
        return 0;
    }

    // commandTrustFamily implements image trust diagnostics.
    // Inputs: argc/argv from wmain.
    // Processing: sends a path-based trust query and prints CI/signing fields.
    // Returns: process exit code.
    int commandTrustFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: trust requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub != L"query-image")
        {
            std::wcerr << L"error: unknown trust subcommand '" << sub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST request{};
        KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE response{};
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_ALL);
        const std::wstring& path = requireOptionText(args, L"--path");
        request.pathLengthChars = boundedPathLength(path, KSWORD_ARK_TRUST_PATH_MAX_CHARS);
        copyWideToFixed(request.path, KSWORD_ARK_TRUST_PATH_MAX_CHARS, path);
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST, L"IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST", request, response, io)) return 3;
        printResponseBanner(response.version, response.queryStatus, response.openStatus, io.bytesReturned);
        std::wcout << L"size=" << response.size
                   << L" fieldFlags=0x" << std::hex << response.fieldFlags
                   << L" ciOptions=0x" << response.codeIntegrityOptions
                   << L" fileObject=" << hex64(response.fileObjectAddress)
                   << L" ciStatus=0x" << static_cast<unsigned long>(response.codeIntegrityStatus)
                   << L" secureBootStatus=0x" << static_cast<unsigned long>(response.secureBootStatus)
                   << L" objectStatus=0x" << static_cast<unsigned long>(response.objectStatus)
                   << L" signingStatus=0x" << static_cast<unsigned long>(response.signingLevelStatus)
                   << std::dec << L" trustSource=" << response.trustSource
                   << L" signingLevel=" << response.signingLevel
                   << L" signingLevelFlags=" << response.signingLevelFlags
                   << L" secureBootEnabled=" << response.secureBootEnabled
                   << L" secureBootCapable=" << response.secureBootCapable
                   << L" thumbprintAlgorithm=" << response.thumbprintAlgorithm
                   << L" thumbprintSize=" << response.thumbprintSize << L"\n";
        printBytesInline(L"thumbprint", response.thumbprint, std::min<std::size_t>(response.thumbprintSize, KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES), KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES);
        dumpWideText(L"ntPath", fixedWide(response.ntPath, KSWORD_ARK_TRUST_PATH_MAX_CHARS));
        return 0;
    }

    // commandSafetyFamily implements safety policy query/update IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: sends fixed request/response policy packets.
    // Returns: process exit code.
    int commandSafetyFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: safety requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"query-policy")
        {
            KSWORD_ARK_QUERY_SAFETY_POLICY_REQUEST request{};
            KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_SAFETY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY, L"IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY", request, response, io)) return 3;
            printResponseBanner(response.version, response.policyFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" defaultPolicyFlags=0x" << std::hex << response.defaultPolicyFlags
                       << std::dec << L" generation=" << response.policyGeneration
                       << L" lastOperation=" << response.lastOperation
                       << L" lastDecision=" << response.lastDecision
                       << L" lastReason=" << response.lastReason
                       << L" lastRiskLevel=" << response.lastRiskLevel
                       << L" lastTargetPid=" << response.lastTargetProcessId
                       << L" allowed=" << response.allowedCount
                       << L" denied=" << response.deniedCount
                       << L" auditOnly=" << response.auditOnlyCount
                       << L" lastTargetText='" << fixedWide(response.lastTargetText, KSWORD_ARK_SAFETY_TEXT_MAX_CHARS) << L"'\n";
            return 0;
        }
        if (sub == L"set-policy")
        {
            KSWORD_ARK_SET_SAFETY_POLICY_REQUEST request{};
            KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_SAFETY_PROTOCOL_VERSION;
            request.setFlags = getOptionU32(args, L"--set-flags", 0U);
            request.clearFlags = getOptionU32(args, L"--clear-flags", 0U);
            request.expectedGeneration = getOptionU32(args, L"--expected-generation", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_SAFETY_POLICY, L"IOCTL_KSWORD_ARK_SET_SAFETY_POLICY", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), response.status, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" oldPolicyFlags=0x" << std::hex << response.oldPolicyFlags
                       << L" newPolicyFlags=0x" << response.newPolicyFlags
                       << std::dec << L" oldGeneration=" << response.oldGeneration
                       << L" newGeneration=" << response.newGeneration << L"\n";
            return 0;
        }
        std::wcerr << L"error: unknown safety subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandPreflightFamily implements the release-readiness preflight query.
    // Inputs: argc/argv from wmain.
    // Processing: sends a bounded variable response and prints check rows.
    // Returns: process exit code.
    int commandPreflightFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: preflight requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub != L"query")
        {
            std::wcerr << L"error: unknown preflight subcommand '" << sub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_PREFLIGHT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_ALL);
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        IoctlResult io{};
        const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_PREFLIGHT", IOCTL_KSWORD_ARK_QUERY_PREFLIGHT, &request, sizeof(request), buffer, io);
        if (rc != 0) return rc;
        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE) - sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY), L"preflight"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->overallStatus, response->dynDataLastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCheckCount, response->returnedCheckCount, response->entrySize, io.bytesReturned);
        std::wcout << L"size=" << response->size
                   << L" fieldFlags=0x" << std::hex << response->fieldFlags
                   << L" dynDataStatusFlags=0x" << response->dynDataStatusFlags
                   << L" dynDataCapabilityMask=0x" << response->dynDataCapabilityMask
                   << L" safetyPolicyFlags=0x" << response->safetyPolicyFlags
                   << L" fileMonitorRuntimeFlags=0x" << response->fileMonitorRuntimeFlags
                   << L" trustFieldFlags=0x" << response->trustFieldFlags
                   << L" codeIntegrityOptions=0x" << response->codeIntegrityOptions
                   << std::dec << L" buildConfiguration=" << response->buildConfiguration
                   << L" targetArchitecture=" << response->targetArchitecture
                   << L" ioctlRegistryCount=" << response->ioctlRegistryCount
                   << L" ioctlDuplicateCount=" << response->ioctlDuplicateCount
                   << L" safetyGeneration=" << response->safetyPolicyGeneration
                   << L" fileMonitorQueued=" << response->fileMonitorQueuedCount
                   << L" fileMonitorDropped=" << response->fileMonitorDroppedCount
                   << L" secureBootEnabled=" << response->secureBootEnabled
                   << L" secureBootCapable=" << response->secureBootCapable << L"\n";
        const std::size_t parsed = responseCountLimit(response->returnedCheckCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0; i < parsed; ++i)
        {
            const auto* check = reinterpret_cast<const KSWORD_ARK_PREFLIGHT_CHECK_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] id=" << check->checkId
                       << L" status=" << check->status
                       << L" ntstatus=0x" << std::hex << static_cast<unsigned long>(check->ntstatus)
                       << std::dec << L" name='" << fixedAnsiWide(check->checkName, KSWORD_ARK_PREFLIGHT_CHECK_NAME_CHARS)
                       << L"' detail='" << fixedAnsiWide(check->detail, KSWORD_ARK_PREFLIGHT_CHECK_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // printRegistryOperationResponse renders common registry mutation response fields.
    // Inputs: response and bytesReturned.
    // Processing: prints status and NTSTATUS.
    // Returns: no value.
    void printRegistryOperationResponse(const KSWORD_ARK_REGISTRY_OPERATION_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
    }

    // commandRegistryFamily implements all registry read/enumeration/mutation IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: copies fixed key/value fields and optional binary data file.
    // Returns: process exit code.
    int commandRegistryFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: registry requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"read-value")
        {
            KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST request{};
            KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.maxDataBytes = getOptionU32(args, L"--max-data-bytes", KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (copyOptionalWideOption(args, L"--value", request.valueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS))
            {
                request.flags |= KSWORD_ARK_REGISTRY_READ_FLAG_VALUE_NAME_PRESENT;
            }
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"valueType=" << response.valueType
                       << L" dataBytes=" << response.dataBytes
                       << L" requiredBytes=" << response.requiredBytes << L"\n";
            const std::size_t dataBytes = std::min<std::size_t>(response.dataBytes, KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
            if (getOptionBool(args, L"--hexdump")) hexdump(response.data, dataBytes);
            else printBytesInline(L"data", response.data, dataBytes);
            return 0;
        }
        if (sub == L"enum-key")
        {
            KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST request{};
            KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
            request.maxSubKeys = getOptionU32(args, L"--max-subkeys", KSWORD_ARK_REGISTRY_ENUM_MAX_SUBKEYS);
            request.maxValues = getOptionU32(args, L"--max-values", KSWORD_ARK_REGISTRY_ENUM_MAX_VALUES);
            request.maxValueDataBytes = getOptionU32(args, L"--max-value-data-bytes", KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES);
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY, L"IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"subKeyCount=" << response.subKeyCount
                       << L" returnedSubKeyCount=" << response.returnedSubKeyCount
                       << L" valueCount=" << response.valueCount
                       << L" returnedValueCount=" << response.returnedValueCount << L"\n";
            const std::size_t subKeyCount = std::min<std::size_t>({ response.returnedSubKeyCount, KSWORD_ARK_REGISTRY_ENUM_MAX_SUBKEYS, getOptionU32(args, L"--limit", 128U) });
            for (std::size_t i = 0; i < subKeyCount; ++i)
            {
                std::wcout << L"  subkey[" << i << L"] '" << fixedWide(response.subKeys[i].name, KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS) << L"'\n";
            }
            const std::size_t valueCount = std::min<std::size_t>({ response.returnedValueCount, KSWORD_ARK_REGISTRY_ENUM_MAX_VALUES, getOptionU32(args, L"--limit", 128U) });
            for (std::size_t i = 0; i < valueCount; ++i)
            {
                const auto& value = response.values[i];
                std::wcout << L"  value[" << i << L"] type=" << value.valueType
                           << L" dataBytes=" << value.dataBytes
                           << L" requiredBytes=" << value.requiredBytes
                           << L" flags=0x" << std::hex << value.flags << std::dec
                           << L" name='" << fixedWide(value.name, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS) << L"'\n";
                printBytesInline(L"    data", value.data, std::min<std::size_t>(value.dataBytes, KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES), 24U);
            }
            return 0;
        }
        if (sub == L"set-value")
        {
            KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.valueType = requireOptionU32(args, L"--type");
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (copyOptionalWideOption(args, L"--value", request.valueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS))
            {
                request.flags |= KSWORD_ARK_REGISTRY_SET_FLAG_VALUE_NAME_PRESENT;
            }
            const std::vector<std::uint8_t> data = readRequiredBlobOption(args, L"--data-file", KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
            request.dataBytes = static_cast<unsigned long>(data.size());
            copyBytesToFixed(request.data, KSWORD_ARK_REGISTRY_DATA_MAX_BYTES, data);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"delete-value")
        {
            KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (copyOptionalWideOption(args, L"--value", request.valueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS))
            {
                request.flags |= KSWORD_ARK_REGISTRY_DELETE_VALUE_FLAG_NAME_PRESENT;
            }
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"create-key" || sub == L"delete-key")
        {
            KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            const DWORD code = (sub == L"create-key") ? IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY : IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY;
            const wchar_t* label = (sub == L"create-key") ? L"IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY" : L"IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY";
            if (!sendFixedRequestResponse(code, label, request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"rename-value")
        {
            KSWORD_ARK_RENAME_REGISTRY_VALUE_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            copyRequiredWideOption(args, L"--old-value", request.oldValueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS);
            copyRequiredWideOption(args, L"--new-value", request.newValueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"rename-key")
        {
            KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            copyRequiredWideOption(args, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            copyRequiredWideOption(args, L"--new-name", request.newKeyName, KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY, L"IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        std::wcerr << L"error: unknown registry subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandRedirectFamily implements redirect rule load and status query.
    // Inputs: argc/argv from wmain.
    // Processing: accepts a blob for rule snapshots and prints runtime rules.
    // Returns: process exit code.
    int commandRedirectFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: redirect requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"set-rules")
        {
            std::vector<std::uint8_t> blob = readRequiredBlobOption(args, L"--blob", kMaxCommandBytes);
            KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_REDIRECT_SET_RULES, L"IOCTL_KSWORD_ARK_REDIRECT_SET_RULES", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << L" appliedCount=" << std::dec << response.appliedCount
                       << L" rejectedIndex=" << response.rejectedIndex
                       << L" fileRuleCount=" << response.fileRuleCount
                       << L" registryRuleCount=" << response.registryRuleCount
                       << L" generation=" << response.generation << L"\n";
            return 0;
        }
        if (sub == L"query-status")
        {
            KSWORD_ARK_REDIRECT_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS, L"IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS", response, io)) return 3;
            printResponseBanner(response.version, response.status, response.registryRegisterStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << std::dec << L" fileRuleCount=" << response.fileRuleCount
                       << L" registryRuleCount=" << response.registryRuleCount
                       << L" generation=" << response.generation
                       << L" fileHits=" << response.fileRedirectHits
                       << L" registryHits=" << response.registryRedirectHits
                       << L" registryRegisterStatus=0x" << std::hex << static_cast<unsigned long>(response.registryRegisterStatus) << std::dec << L"\n";
            const std::size_t limit = getOptionU32(args, L"--limit", 16U);
            for (std::size_t i = 0; i < std::min<std::size_t>(KSWORD_ARK_REDIRECT_MAX_RULES, limit); ++i)
            {
                const auto& rule = response.rules[i];
                if (rule.ruleId == 0U && rule.sourcePath[0] == L'\0' && rule.targetPath[0] == L'\0')
                {
                    continue;
                }
                std::wcout << L"  rule[" << i << L"] id=" << rule.ruleId
                           << L" type=" << rule.type
                           << L" action=" << rule.action
                           << L" matchMode=" << rule.matchMode
                           << L" flags=0x" << std::hex << rule.flags
                           << std::dec << L" pid=" << rule.processId
                           << L" source='" << fixedWide(rule.sourcePath, KSWORD_ARK_REDIRECT_PATH_CHARS)
                           << L"' target='" << fixedWide(rule.targetPath, KSWORD_ARK_REDIRECT_PATH_CHARS) << L"'\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown redirect subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandNetworkFamily implements network rule load and status query.
    // Inputs: argc/argv from wmain.
    // Processing: accepts a blob for rules and prints runtime snapshot state.
    // Returns: process exit code.
    int commandNetworkFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: network requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"set-rules")
        {
            std::vector<std::uint8_t> blob = readRequiredBlobOption(args, L"--blob", kMaxCommandBytes);
            KSWORD_ARK_NETWORK_SET_RULES_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_NETWORK_SET_RULES, L"IOCTL_KSWORD_ARK_NETWORK_SET_RULES", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << std::dec << L" appliedCount=" << response.appliedCount
                       << L" blockedRuleCount=" << response.blockedRuleCount
                       << L" hiddenPortRuleCount=" << response.hiddenPortRuleCount
                       << L" rejectedIndex=" << response.rejectedIndex
                       << L" generation=" << response.generation << L"\n";
            return 0;
        }
        if (sub == L"query-status")
        {
            KSWORD_ARK_NETWORK_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS", response, io))
            {
                return normalizeIoctlRc(L"network status", io, 3);
            }
            printResponseBanner(response.version, response.status, response.registerStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << std::dec << L" ruleCount=" << response.ruleCount
                       << L" blockedRuleCount=" << response.blockedRuleCount
                       << L" hiddenPortRuleCount=" << response.hiddenPortRuleCount
                       << L" generation=" << response.generation
                       << L" classifyCount=" << response.classifyCount
                       << L" blockedCount=" << response.blockedCount
                       << L" registerStatus=0x" << std::hex << static_cast<unsigned long>(response.registerStatus)
                       << L" engineStatus=0x" << static_cast<unsigned long>(response.engineStatus) << std::dec << L"\n";
            const std::size_t limit = getOptionU32(args, L"--limit", 16U);
            for (std::size_t i = 0; i < std::min<std::size_t>(KSWORD_ARK_NETWORK_MAX_RULES, limit); ++i)
            {
                const auto& rule = response.rules[i];
                if (rule.ruleId == 0U && rule.localPort == 0U && rule.remotePort == 0U && rule.processId == 0U)
                {
                    continue;
                }
                std::wcout << L"  rule[" << i << L"] id=" << rule.ruleId
                           << L" action=" << rule.action
                           << L" dir=0x" << std::hex << rule.directionMask
                           << L" proto=" << std::dec << rule.protocol
                           << L" pid=" << rule.processId
                           << L" flags=0x" << std::hex << rule.flags
                           << std::dec << L" localPort=" << rule.localPort
                           << L" remotePort=" << rule.remotePort << L"\n";
            }
            return 0;
        }
        if (sub == L"audit")
        {
            std::wcout << L"network audit: querying TCP endpoint audit first; use wfp/ndis for chain-specific views\n";
            return queryNetworkEndpoints(args, IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS", L"network audit");
        }
        if (sub == L"tcp")
        {
            return queryNetworkEndpoints(args, IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS", L"network tcp");
        }
        if (sub == L"udp")
        {
            return queryNetworkEndpoints(args, IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS", L"network udp");
        }
        if (sub == L"wfp")
        {
            return queryNetworkWfp(args);
        }
        if (sub == L"ndis")
        {
            return queryNetworkNdis(args);
        }
        if (sub == L"afd")
        {
            return commandNetworkAfdFallback(args);
        }
        if (sub == L"nsi")
        {
            return commandNetworkNsiFallback(args);
        }
        std::wcerr << L"error: unknown network subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandKeyboardFamily implements keyboard hotkey and hook enumeration.
    // Inputs: argc/argv from wmain.
    // Processing: prints bounded row lists and diagnostic offsets.
    // Returns: process exit code.
    int commandKeyboardFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: keyboard requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"enum-hotkeys" || sub == L"enum-hooks")
        {
            KSWORD_ARK_ENUM_KEYBOARD_REQUEST request{};
            request.version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(args, L"--pid", 0U);
            request.maxEntries = getOptionU32(args, L"--max-entries", 256U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            if (sub == L"enum-hotkeys")
            {
                const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS", IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS, &request, sizeof(request), buffer, io);
                if (rc != 0) return rc;
                constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY);
                const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE*>(buffer.data());
                std::size_t available = 0U;
                try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY), L"keyboard hotkeys"); }
                catch (...) { return 4; }
                printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
                printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
                std::wcout << L"win32kBase=" << hex64(response->win32kBase)
                           << L" sessionGlobals=" << hex64(response->sessionGlobals)
                           << L" tableOffset=" << response->tableOffset
                           << L" hotkeyNextOffset=" << response->hotkeyNextOffset
                           << L" hotkeyModifiersOffset=" << response->hotkeyModifiersOffset
                           << L" hotkeyVkOffset=" << response->hotkeyVkOffset
                           << L" hotkeyIdOffset=" << response->hotkeyIdOffset << L"\n";
                const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
                for (std::size_t i = 0; i < parsed; ++i)
                {
                    const auto* entry = reinterpret_cast<const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                    std::wcout << L"  [" << i << L"] source=" << entry->source
                               << L" status=" << entry->status
                               << L" flags=0x" << std::hex << entry->flags
                               << L" bucket=" << entry->bucketIndex
                               << L" depth=" << entry->depth
                               << L" modifiers=0x" << entry->modifiers
                               << L" modifiers2=0x" << entry->modifierFlags2
                               << L" vk=" << std::dec << entry->virtualKey
                               << L" id=" << entry->hotkeyId
                               << L" pid=" << entry->processId
                               << L" tid=" << entry->threadId
                               << L" last=0x" << std::hex << static_cast<unsigned long>(entry->lastStatus)
                               << std::dec << L" detail='" << fixedWide(entry->detail, KSWORD_ARK_KEYBOARD_DETAIL_CHARS) << L"'\n";
                }
                return 0;
            }
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS", IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY), L"keyboard hooks"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"win32kBase=" << hex64(response->win32kBase)
                       << L" threadHookArrayOffset=" << response->threadHookArrayOffset
                       << L" desktopInfoOffset=" << response->desktopInfoOffset
                       << L" desktopHookArrayOffset=" << response->desktopHookArrayOffset
                       << L" hookNextOffset=" << response->hookNextOffset
                       << L" hookTypeOffset=" << response->hookTypeOffset
                       << L" hookProcedureOffset=" << response->hookProcedureOffset
                       << L" hookFlagsOffset=" << response->hookFlagsOffset
                       << L" hookModuleIdOffset=" << response->hookModuleIdOffset
                       << L" hookTargetThreadInfoOffset=" << response->hookTargetThreadInfoOffset << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_KEYBOARD_HOOK_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] source=" << entry->source
                           << L" status=" << entry->status
                           << L" flags=0x" << std::hex << entry->flags
                           << L" type=" << entry->hookType
                           << L" scope=" << entry->hookScope
                           << L" pid=" << std::dec << entry->processId
                           << L" tid=" << entry->threadId
                           << L" moduleId=" << entry->moduleId
                           << L" last=0x" << std::hex << static_cast<unsigned long>(entry->lastStatus)
                           << L" hook=" << hex64(entry->hookObject)
                           << L" proc=" << hex64(entry->procedureAddress)
                           << std::dec << L" detail='" << fixedWide(entry->detail, KSWORD_ARK_KEYBOARD_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown keyboard subcommand '" << sub << L"'\n";
        return 1;
    }

    // queryDriverOptionalGlobalEvidence 作用：复用 Driver Integrity 的可选全局证据。
    // 输入：CLI 参数、命令标签、detail 过滤关键字和展示名。
    // 处理：只读查询 OPTIONAL_GLOBALS，不新增协议，不枚举/修改内核表内容。
    // 返回：0 表示成功打印 R0 证据；5 表示旧驱动不支持或没有返回目标证据。
    int queryDriverOptionalGlobalEvidence(
        const NamedArgs& args,
        const wchar_t* featureLabel,
        const wchar_t* detailNeedle,
        const wchar_t* displayName)
    {
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
        request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
        request.flags =
            getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS) |
            KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS;
        request.maxRows = getOptionU32(args, L"--max-rows", 32U);
        request.maxIdtVectorsPerCpu = getOptionU32(args, L"--max-idt-vectors", 0U);
        request.maxDevices = getOptionU32(args, L"--max-devices", 0U);
        request.maxAttachedDevices = getOptionU32(args, L"--max-attached", 0U);
        request.targetModuleBase = getOptionU64(args, L"--module-base", 0ULL);

        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int rc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY",
            IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY,
            &request,
            sizeof(request),
            buffer,
            io);
        if (rc != 0)
        {
            return normalizeIoctlRc(featureLabel, io, rc);
        }

        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) -
            sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
        const auto* response =
            reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try
        {
            available = validateVariable(
                io.bytesReturned,
                headerSize,
                response->entrySize,
                sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE),
                featureLabel);
        }
        catch (...)
        {
            return 4;
        }

        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"projection=" << displayName
                   << L" source=driver-integrity optional-globals"
                   << L" fieldFlags=0x" << std::hex << response->fieldFlags
                   << L" statusFlags=0x" << response->statusFlags
                   << std::dec << L"\n";

        const std::size_t limit = getOptionU32(args, L"--limit", 16U);
        const std::size_t parsed = responseCountLimit(response->returnedCount, available, limit);
        std::size_t matchedCount = 0U;
        for (std::size_t index = 0U; index < parsed; ++index)
        {
            const auto* entry = reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(
                buffer.data() + headerSize + (index * response->entrySize));
            const std::wstring detailText = fixedWide(entry->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS);
            const bool optionalGlobalRow =
                entry->evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL;
            if (!optionalGlobalRow || !containsIgnoreCase(detailText, detailNeedle))
            {
                continue;
            }

            ++matchedCount;
            std::wcout << L"  [" << index << L"] class=" << entry->evidenceClass
                       << L" statusFlags=0x" << std::hex << entry->statusFlags
                       << L" risk=0x" << entry->riskFlags
                       << L" fieldMask=0x" << entry->fieldMask
                       << L" object=" << hex64(entry->objectAddress)
                       << L" target=" << hex64(entry->targetAddress)
                       << L" ownerBase=" << hex64(entry->ownerModuleBase)
                       << std::dec << L" confidence=" << entry->confidence
                       << L" owner='" << fixedWide(entry->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS)
                       << L"' detail='" << detailText << L"'\n";
        }

        if (matchedCount == 0U)
        {
            std::wcout << L"unsupported / unavailable: " << featureLabel
                       << L" (Driver Integrity returned no matching optional-global evidence for "
                       << displayName << L")\n";
            return 5;
        }
        return 0;
    }

    // commandDriverFamily exposes driver audit aliases requested by PDB R0 work.
    // Inputs: argc/argv from wmain.
    // Processing: routes read-only aliases to existing kernel/storage queries.
    // Returns: process exit code.
    int commandDriverFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: driver requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub == L"integrity")
        {
            KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
            request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT);
            request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS);
            request.maxIdtVectorsPerCpu = getOptionU32(args, L"--max-idt-vectors", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
            request.maxDevices = getOptionU32(args, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(args, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            request.targetModuleBase = getOptionU64(args, L"--module-base", 0ULL);
            copyOptionalWideOption(args, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            IoctlResult io{};
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY", IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"driver integrity", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE), L"driver integrity"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" statusFlags=0x" << response->statusFlags
                       << L" sourceMask=0x" << response->sourceMask
                       << std::dec << L" cpuCount=" << response->cpuCount
                       << L" moduleCount=" << response->moduleCount << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] class=" << entry->evidenceClass
                           << L" risk=0x" << std::hex << entry->riskFlags
                           << L" source=0x" << entry->sourceMask
                           << L" object=" << hex64(entry->objectAddress)
                           << L" target=" << hex64(entry->targetAddress)
                           << L" ownerBase=" << hex64(entry->ownerModuleBase)
                           << std::dec << L" confidence=" << entry->confidence
                           << L" owner='" << fixedWide(entry->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS)
                           << L"' detail='" << fixedWide(entry->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        if (sub == L"detail")
        {
            KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST request{};
            request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL);
            request.maxDevices = getOptionU32(args, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(args, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            copyRequiredWideOption(args, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            IoctlResult io{};
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT", IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT, &request, sizeof(request), buffer, io);
            if (rc != 0) return normalizeIoctlRc(L"driver detail", io, rc);
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->deviceEntrySize, sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY), L"driver detail"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalDeviceCount, response->returnedDeviceCount, response->deviceEntrySize, io.bytesReturned);
            std::wcout << L"driverObject=" << hex64(response->driverObjectAddress)
                       << L" driverStart=" << hex64(response->driverStart)
                       << L" driverSection=" << hex64(response->driverSection)
                       << L" driverUnload=" << hex64(response->driverUnload)
                       << L" driver='" << fixedWide(response->driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS)
                       << L"' service='" << fixedWide(response->serviceKeyName, KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS) << L"'\n";
            const std::size_t parsed = responseCountLimit(response->returnedDeviceCount, available, getOptionU32(args, L"--limit", 64U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* device = reinterpret_cast<const KSWORD_ARK_DRIVER_DEVICE_ENTRY*>(buffer.data() + headerSize + (i * response->deviceEntrySize));
                std::wcout << L"  device[" << i << L"] depth=" << device->relationDepth
                           << L" object=" << hex64(device->deviceObjectAddress)
                           << L" attached=" << hex64(device->attachedDeviceObjectAddress)
                           << L" driver=" << hex64(device->driverObjectAddress)
                           << L" name='" << fixedWide(device->deviceName, KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS) << L"'\n";
            }
            return 0;
        }
        if (sub == L"device" || sub == L"major" || sub == L"fastio")
        {
            return queryDeviceAudit(args, IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK, L"IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT", L"driver device");
        }
        if (sub == L"unloaded")
        {
            return queryDriverOptionalGlobalEvidence(args, L"driver unloaded", L"MmUnloadedDrivers", L"MmUnloadedDrivers");
        }
        if (sub == L"piddb")
        {
            return queryDriverOptionalGlobalEvidence(args, L"driver piddb", L"PiDDBCacheTable", L"PiDDBCacheTable");
        }
        std::wcerr << L"error: unknown driver subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandHardwareFamily exposes input/USB/PnP/GPU device audit commands.
    // Inputs: argc/argv from wmain.
    // Processing: routes to read-only device audit IOCTLs where present.
    // Returns: process exit code.
    int commandHardwareFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: hardware requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub == L"audit" || sub == L"pnp")
        {
            return queryDeviceAudit(args, IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK, L"IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT", L"hardware audit");
        }
        if (sub == L"input")
        {
            return queryDeviceAudit(args, IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK, L"IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT", L"hardware input");
        }
        if (sub == L"usb")
        {
            return queryDeviceAudit(args, IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY, L"IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT", L"hardware usb");
        }
        std::wcerr << L"error: unknown hardware subcommand '" << sub << L"'\n";
        return 1;
    }


    // parseHwidDispatchAction converts action names into shared HWID constants.
    // Inputs: --action text or numeric token.
    // Processing: accepts query/enable/disable/disable-all and decimal/hex values.
    // Returns: KSWORD_ARK_HWID_DISPATCH_ACTION_* value.
    std::uint32_t parseHwidDispatchAction(const std::wstring& text)
    {
        const std::wstring lowered = lowerWide(text);
        if (lowered == L"query") return KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY;
        if (lowered == L"enable") return KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE;
        if (lowered == L"disable") return KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE;
        if (lowered == L"disable-all" || lowered == L"disableall") return KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL;
        return parseU32(text.c_str(), "hwid action");
    }

    // addHwidTargetToken ORs one target token into a HWID target mask.
    // Inputs: token and mutable mask.
    // Processing: recognizes individual target and group names.
    // Returns: no value; throws on unknown target names.
    void addHwidTargetToken(const std::wstring& token, std::uint32_t& flags)
    {
        const std::wstring lowered = lowerWide(token);
        if (lowered.empty()) return;
        if (lowered == L"disk") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_DISK; return; }
        if (lowered == L"partmgr" || lowered == L"partition") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR; return; }
        if (lowered == L"mountmgr" || lowered == L"volume") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR; return; }
        if (lowered == L"nvidia" || lowered == L"gpu") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA; return; }
        if (lowered == L"nsiproxy" || lowered == L"nsi" || lowered == L"network") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_NETWORK; return; }
        if (lowered == L"storage") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_STORAGE; return; }
        if (lowered == L"all") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_ALL; return; }
        flags |= parseU32(token.c_str(), "hwid target");
    }

    // parseHwidTargetFlags parses --targets into a target mask.
    // Inputs: parsed args.
    // Processing: accepts comma/semicolon/pipe/space separated target names.
    // Returns: target mask; storage is the default to match the main UI defaults.
    std::uint32_t parseHwidTargetFlags(const NamedArgs& args)
    {
        const std::wstring* text = getOptionText(args, L"--targets");
        if (text == nullptr || text->empty())
        {
            return KSWORD_ARK_HWID_DISPATCH_TARGET_STORAGE;
        }
        std::uint32_t flags = 0U;
        std::wstring token;
        const auto flush = [&]()
        {
            addHwidTargetToken(token, flags);
            token.clear();
        };
        for (const wchar_t ch : *text)
        {
            if (ch == L',' || ch == L';' || ch == L'|' || std::iswspace(ch) != 0)
            {
                flush();
                continue;
            }
            token.push_back(ch);
        }
        flush();
        return flags;
    }

    // parseHwidDiskMode maps disk mode text to protocol constants.
    // Inputs: optional --disk-mode value.
    // Processing: accepts custom/random/null or numeric values.
    // Returns: protocol disk mode.
    std::uint32_t parseHwidDiskMode(const NamedArgs& args)
    {
        const std::wstring* text = getOptionText(args, L"--disk-mode");
        if (text == nullptr || text->empty()) return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM;
        const std::wstring lowered = lowerWide(*text);
        if (lowered == L"custom") return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM;
        if (lowered == L"random") return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM;
        if (lowered == L"null" || lowered == L"empty") return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_NULL;
        return parseU32(text->c_str(), "hwid disk mode");
    }

    // parseHwidMacMode maps MAC mode text to protocol constants.
    // Inputs: optional --mac-mode value.
    // Processing: accepts random/custom or numeric values.
    // Returns: protocol MAC mode.
    std::uint32_t parseHwidMacMode(const NamedArgs& args)
    {
        const std::wstring* text = getOptionText(args, L"--mac-mode");
        if (text == nullptr || text->empty()) return KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM;
        const std::wstring lowered = lowerWide(*text);
        if (lowered == L"random") return KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM;
        if (lowered == L"custom") return KSWORD_ARK_HWID_DISPATCH_MAC_MODE_CUSTOM;
        return parseU32(text->c_str(), "hwid mac mode");
    }

    // printHwidDispatchResponse renders HWID Dispatch state/control packets.
    // Inputs: response packet and bytesReturned.
    // Processing: prints summary, active profile and per-target dispatch rows.
    // Returns: no value.
    void printHwidDispatchResponse(const KSWORD_ARK_HWID_DISPATCH_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.overallStatus, response.lastStatus, bytesReturned);
        std::wcout << L"responseFlags=0x" << std::hex << response.responseFlags
                   << L" supported=0x" << response.supportedTargetFlags
                   << L" requested=0x" << response.requestedTargetFlags
                   << L" active=0x" << response.activeTargetFlags
                   << L" failed=0x" << response.failedTargetFlags
                   << L" generation=0x" << response.generation
                   << std::dec << L"\n";
        const KSWORD_ARK_HWID_DISPATCH_PROFILE& profile = response.activeProfile;
        std::wcout << L"profile targetFlags=0x" << std::hex << profile.targetFlags
                   << L" behaviorFlags=0x" << profile.behaviorFlags
                   << std::dec << L" diskMode=" << profile.diskMode
                   << L" macMode=" << profile.macMode << L"\n";
        dumpWideText(L"diskSerial", fixedWide(profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"diskProduct", fixedWide(profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"diskRevision", fixedWide(profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"gpuSerial", fixedWide(profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"permanentMac", fixedWide(profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"currentMac", fixedWide(profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        for (std::size_t index = 0U; index < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++index)
        {
            const KSWORD_ARK_HWID_DISPATCH_ENTRY& entry = response.entries[index];
            std::wcout << L"  [" << index << L"] target=0x" << std::hex << entry.targetFlag
                       << L" driverObject=" << hex64(entry.driverObjectAddress)
                       << L" original=" << hex64(entry.originalDispatchAddress)
                       << L" current=" << hex64(entry.currentDispatchAddress)
                       << L" lastStatus=0x" << static_cast<unsigned long>(entry.lastStatus)
                       << std::dec << L" active=" << entry.active
                       << L" driver='" << fixedWide(entry.driverName, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS) << L"'\n";
        }
    }

    // commandHwidFamily exposes HWID Dispatch query/control IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: routes fixed query and guarded control requests.
    // Returns: process exit code.
    int commandHwidFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: hwid requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (sub == L"dispatch-query")
        {
            KSWORD_ARK_HWID_DISPATCH_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY, L"IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY", response, io))
            {
                return normalizeIoctlRc(L"hwid dispatch-query", io, 3);
            }
            printHwidDispatchResponse(response, io.bytesReturned);
            return 0;
        }
        if (sub == L"dispatch-control")
        {
            KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST request{};
            KSWORD_ARK_HWID_DISPATCH_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
            request.action = parseHwidDispatchAction(requireOptionText(args, L"--action"));
            if (request.action != KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY)
            {
                requireConfirmOption(args, "hwid dispatch-control requires --confirm");
            }
            if (getOptionBool(args, L"--confirm"))
            {
                request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED;
            }
            if (getOptionBool(args, L"--dry-run"))
            {
                request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN;
            }
            request.profile.size = sizeof(request.profile);
            request.profile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
            request.profile.targetFlags = parseHwidTargetFlags(args);
            request.profile.behaviorFlags = getOptionU32(args, L"--flags", 0U);
            request.profile.diskMode = parseHwidDiskMode(args);
            request.profile.macMode = parseHwidMacMode(args);
            copyOptionalWideOption(args, L"--disk-serial", request.profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(args, L"--disk-product", request.profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(args, L"--disk-revision", request.profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(args, L"--gpu-serial", request.profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(args, L"--permanent-mac", request.profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(args, L"--current-mac", request.profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            if (!sendFixedRequestResponse(
                    IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL,
                    L"IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL",
                    request,
                    response,
                    io,
                    GENERIC_READ | GENERIC_WRITE))
            {
                return normalizeIoctlRc(L"hwid dispatch-control", io, 3);
            }
            printHwidDispatchResponse(response, io.bytesReturned);
            return 0;
        }
        std::wcerr << L"error: unknown hwid subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandWindowFamily exposes read-only win32k/GUI/GPU/display commands.
    // Inputs: argc/argv from wmain.
    // Processing: uses win32k and device-audit protocols; unsupported pieces report clearly.
    // Returns: process exit code.
    int commandWindowFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: window requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub == L"win32k")
        {
            return queryWin32kProfileStatus(args);
        }
        if (sub == L"gui")
        {
            return queryWin32kWindows(args);
        }
        if (sub == L"gui-threads")
        {
            return queryWin32kGuiThreads(args);
        }
        if (sub == L"hotkeys-pdb")
        {
            return queryWin32kHotkeysPdb(args);
        }
        if (sub == L"hooks-pdb")
        {
            return queryWin32kHooksPdb(args);
        }
        if (sub == L"detail")
        {
            return queryWin32kWindowDetail(args);
        }
        if (sub == L"gpu" || sub == L"display" || sub == L"watchdog")
        {
            return queryDeviceAudit(args, IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG, L"IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT", L"window gpu/display/watchdog");
        }
        std::wcerr << L"error: unknown window subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandMiscFamily exposes security/CI/VBS/Hyper-V/AppLocker/BAM posture.
    // Inputs: argc/argv from wmain.
    // Processing: routes to fixed read-only security audit queries.
    // Returns: process exit code.
    int commandMiscFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: misc requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        if (sub == L"security" || sub == L"ci" || sub == L"vbs")
        {
            return querySecurityStatus(args);
        }
        if (sub == L"hyperv")
        {
            return queryHypervSummary(args);
        }
        if (sub == L"applocker" || sub == L"bam")
        {
            return queryAppControlStatus(args);
        }
        if (sub == L"driver-trust")
        {
            return queryDriverTrustView(args);
        }
        std::wcerr << L"error: unknown misc subcommand '" << sub << L"'\n";
        return 1;
    }

    // commandMutationFamily implements prepare/commit/rollback and audit queries.
    // Inputs: argc/argv from wmain.
    // Processing: loads hex or file blobs and renders audit rows.
    // Returns: process exit code.
    int commandMutationFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: mutation requires a subcommand\n"; return 1; }
        const std::wstring sub = argv[2];
        const NamedArgs args = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (sub == L"prepare")
        {
            std::vector<std::uint8_t> afterBytes = loadBytesFromHexOrFile(args, L"--after-hex", L"--after-file", KSWORD_ARK_MUTATION_MAX_BYTES, true);
            std::vector<std::uint8_t> beforeBytes = loadBytesFromHexOrFile(args, L"--before-hex", L"--before-file", KSWORD_ARK_MUTATION_MAX_BYTES, false);
            KSWORD_ARK_MUTATION_PREPARE_REQUEST request{};
            KSWORD_ARK_MUTATION_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.targetKind = requireOptionU32(args, L"--target-kind");
            request.processId = getOptionU32(args, L"--pid", 0U);
            request.bytes = static_cast<unsigned long>(afterBytes.size());
            request.targetAddress = getOptionU64(args, L"--address", 0ULL);
            request.targetContext = getOptionU64(args, L"--context", 0ULL);
            copyBytesToFixed(request.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, afterBytes);
            copyBytesToFixed(request.expectedBeforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, beforeBytes);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_MUTATION_PREPARE, L"IOCTL_KSWORD_ARK_MUTATION_PREPARE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" targetKind=" << response.targetKind
                       << L" pid=" << response.processId
                       << L" bytes=" << response.bytes
                       << L" riskFlags=0x" << std::hex << response.riskFlags
                       << L" transactionId=" << response.transactionId
                       << L" targetAddress=" << hex64(response.targetAddress)
                       << L" targetContext=" << hex64(response.targetContext)
                       << L" beforeHash=" << hex64(response.beforeHash)
                       << L" afterHash=" << hex64(response.afterHash)
                       << std::dec << L" timestampTick=" << response.timestampTick << L"\n";
            printBytesInline(L"beforeBytes", response.beforeBytes, response.bytes);
            printBytesInline(L"afterBytes", response.afterBytes, response.bytes);
            return 0;
        }
        if (sub == L"commit" || sub == L"rollback")
        {
            KSWORD_ARK_MUTATION_TRANSACTION_REQUEST request{};
            KSWORD_ARK_MUTATION_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.transactionId = requireOptionU64(args, L"--transaction-id");
            const DWORD code = (sub == L"commit") ? IOCTL_KSWORD_ARK_MUTATION_COMMIT : IOCTL_KSWORD_ARK_MUTATION_ROLLBACK;
            const wchar_t* label = (sub == L"commit") ? L"IOCTL_KSWORD_ARK_MUTATION_COMMIT" : L"IOCTL_KSWORD_ARK_MUTATION_ROLLBACK";
            if (!sendFixedRequestResponse(code, label, request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" targetKind=" << response.targetKind
                       << L" pid=" << response.processId
                       << L" bytes=" << response.bytes
                       << L" riskFlags=0x" << std::hex << response.riskFlags
                       << L" transactionId=" << response.transactionId
                       << L" targetAddress=" << hex64(response.targetAddress)
                       << L" targetContext=" << hex64(response.targetContext)
                       << L" beforeHash=" << hex64(response.beforeHash)
                       << L" afterHash=" << hex64(response.afterHash)
                       << std::dec << L" timestampTick=" << response.timestampTick << L"\n";
            printBytesInline(L"beforeBytes", response.beforeBytes, response.bytes);
            printBytesInline(L"afterBytes", response.afterBytes, response.bytes);
            return 0;
        }
        if (sub == L"query-audit")
        {
            KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
            request.flags = getOptionU32(args, L"--flags", 0U);
            request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
            request.startSequence = getOptionU64(args, L"--start-sequence", 0ULL);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int rc = sendRawIoctl(L"IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT", IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT, &request, sizeof(request), buffer, io);
            if (rc != 0) return rc;
            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE) - sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, headerSize, response->entrySize, sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY), L"mutation audit"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"size=" << response->size
                       << L" lostCount=" << response->lostCount
                       << L" oldestSequence=" << response->oldestSequence
                       << L" nextSequence=" << response->nextSequence << L"\n";
            const std::size_t parsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
            for (std::size_t i = 0; i < parsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_MUTATION_AUDIT_ENTRY*>(buffer.data() + headerSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] op=" << entry->operation
                           << L" status=" << entry->status
                           << L" targetKind=" << entry->targetKind
                           << L" pid=" << entry->processId
                           << L" bytes=" << entry->bytes
                           << L" risk=0x" << std::hex << entry->riskFlags
                           << L" flags=0x" << entry->flags
                           << L" transactionId=" << entry->transactionId
                           << L" sequence=" << entry->sequence
                           << L" targetAddress=" << hex64(entry->targetAddress)
                           << L" targetContext=" << hex64(entry->targetContext)
                           << L" beforeHash=" << hex64(entry->beforeHash)
                           << L" afterHash=" << hex64(entry->afterHash)
                           << std::dec << L" timestampTick=" << entry->timestampTick << L"\n";
                if (getOptionBool(args, L"--hexdump"))
                {
                    printBytesInline(L"    byteData", entry->byteData, std::min<std::size_t>(entry->bytes, KSWORD_ARK_MUTATION_MAX_BYTES), 32U);
                }
            }
            return 0;
        }
        std::wcerr << L"error: unknown mutation subcommand '" << sub << L"'\n";
        return 1;
    }

    // dispatchCommand maps the first CLI token to an IOCTL command family.
    // Inputs: argc/argv from wmain; argv[1] is the command family.
    // Processing: keeps family routing centralized and leaves subcommand parsing
    //             to the family handlers.
    // Returns: process exit code from the selected handler.
    int dispatchCommand(int argc, wchar_t* argv[])
    {
        if (argc < 2 || argv[1] == nullptr)
        {
            printUsage();
            return 1;
        }

        const std::wstring family = argv[1];
        if (isHelpToken(argv[1]))
        {
            return printHelpForTarget(argc, argv, 2);
        }
        if (argc >= 3 && isHelpToken(argv[2]))
        {
            return printHelpForTarget(argc, argv, 1);
        }
        if (argc >= 4 && hasTrailingHelpToken(argc, argv, 3))
        {
            return printSpecificCommandHelp(family, argv[2]) ? 0 : 1;
        }
        if (family == L"log") return commandLogFamily(argc, argv);
        if (family == L"process") return commandProcessFamily(argc, argv);
        if (family == L"memory") return commandMemoryFamily(argc, argv);
        if (family == L"file") return commandFileFamily(argc, argv);
        if (family == L"kernel") return commandKernelFamily(argc, argv);
        if (family == L"callback") return commandCallbackFamily(argc, argv);
        if (family == L"dyn") return commandDynFamily(argc, argv);
        if (family == L"thread") return commandThreadFamily(argc, argv);
        if (family == L"handle") return commandHandleFamily(argc, argv);
        if (family == L"driver") return commandDriverFamily(argc, argv);
        if (family == L"hardware") return commandHardwareFamily(argc, argv);
        if (family == L"hwid") return commandHwidFamily(argc, argv);
        if (family == L"window") return commandWindowFamily(argc, argv);
        if (family == L"misc") return commandMiscFamily(argc, argv);
        if (family == L"alpc") return commandAlpcFamily(argc, argv);
        if (family == L"section") return commandSectionFamily(argc, argv);
        if (family == L"trust") return commandTrustFamily(argc, argv);
        if (family == L"safety") return commandSafetyFamily(argc, argv);
        if (family == L"preflight") return commandPreflightFamily(argc, argv);
        if (family == L"registry") return commandRegistryFamily(argc, argv);
        if (family == L"redirect") return commandRedirectFamily(argc, argv);
        if (family == L"network") return commandNetworkFamily(argc, argv);
        if (family == L"keyboard") return commandKeyboardFamily(argc, argv);
        if (family == L"mutation") return commandMutationFamily(argc, argv);
        if (family == L"capability") return commandCapabilityFamily(argc, argv);
        if (family == L"wsl") return commandWslFamily(argc, argv);
        if (family == L"r0") return commandArkDriverExtended(argc, argv);

        std::wcerr << L"error: unknown family '" << family << L"'\n";
        printUsage();
        return 1;
    }

    // configureConsole prepares stdout/stderr for Unicode-friendly diagnostics.
    // Inputs: none.
    // Processing: uses UTF-8 wide-text mode so console and redirected output do
    //             not contain UTF-16 NUL separators.
    // Returns: no value.
    void configureConsole()
    {
        (void)_setmode(_fileno(stdout), _O_U8TEXT);
        (void)_setmode(_fileno(stderr), _O_U8TEXT);
    }
}

// wmain is the process entry point for the Unicode CLI.
// Inputs: raw command-line arguments from the Windows CRT.
// Processing: configures console output, dispatches the requested family, and
//             converts parser/runtime exceptions into stable CLI errors.
// Returns: process exit code; zero means the requested operation completed.
int wmain(int argc, wchar_t* argv[])
{
    configureConsole();
    try
    {
        return dispatchCommand(argc, argv);
    }
    catch (const std::exception& ex)
    {
        const std::string message = ex.what();
        std::wcerr << L"error: " << std::wstring(message.begin(), message.end()) << L"\n";
        return 1;
    }
}
