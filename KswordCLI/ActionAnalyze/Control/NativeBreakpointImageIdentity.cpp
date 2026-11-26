#include "NativeBreakpointImageIdentity.h"

#include <bcrypt.h>
#include <array>

#pragma comment(lib, "bcrypt.lib")

namespace ks::cli::action_analyze::control
{
    namespace
    {
        using Error = native_owner_detail::NativeDebugError; // 与原owner的稳定阶段和Win32错误一致。

        // 输入失败阶段，输出当前系统错误；在任何句柄清理前调用以保留原错误。
        Error Failure(const char* stage)
        {
            const auto code = GetLastError(); // 本次原生调用的实际失败原因。
            return {stage, code ? code : ERROR_GEN_FAILURE};
        }

        struct Hash final
        {
            BCRYPT_HASH_HANDLE value = nullptr; // CNG拥有的流式SHA256上下文。
            ~Hash()
            {
                if (value)
                {
                    BCryptDestroyHash(value);
                }
            }
        };

        // 输入禁止写入/替换的实际映像文件，输出全文件SHA256；仅本地分块读，不装载映像或解析PDB。
        Error Digest(HANDLE file, std::string& observed)
        {
            LARGE_INTEGER size{}, origin{}; // 文件实际长度与独立读句柄的起始位置。
            if (GetFileType(file) != FILE_TYPE_DISK || !GetFileSizeEx(file, &size) || size.QuadPart <= 0)
            {
                return {"image-hash-invalid-file", ERROR_FILE_INVALID};
            }
            if (!SetFilePointerEx(file, origin, nullptr, FILE_BEGIN))
            {
                return Failure("image-hash-seek");
            }
            Hash hash; // 所有退出路径释放CNG状态。
            if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash.value, nullptr, 0, nullptr, 0, 0) < 0)
            {
                return {"image-hash-create", ERROR_GEN_FAILURE};
            }
            std::array<unsigned char, 64 * 1024> buffer{}; // 固定64KiB流式缓冲，不按文件大小分配内存。
            std::uint64_t remaining = static_cast<std::uint64_t>(size.QuadPart); // 必须完整覆盖原文件长度。
            while (remaining)
            {
                const auto wanted = static_cast<DWORD>(remaining < buffer.size() ? remaining : buffer.size()); // 本轮有限字节数。
                DWORD read = 0; // 系统实际返回字节数，短读不能按完整散列接受。
                if (!ReadFile(file, buffer.data(), wanted, &read, nullptr))
                {
                    return Failure("image-hash-read");
                }
                if (read != wanted)
                {
                    return {"image-hash-short-read", ERROR_HANDLE_EOF};
                }
                if (BCryptHashData(hash.value, buffer.data(), read, 0) < 0)
                {
                    return {"image-hash-update", ERROR_GEN_FAILURE};
                }
                remaining -= read;
            }
            std::array<unsigned char, 32> digest{}; // SHA256实际32字节输出。
            if (BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
            {
                return {"image-hash-finish", ERROR_GEN_FAILURE};
            }
            constexpr char digits[] = "0123456789abcdef"; // 与项目冻结散列保持同一种无损编码。
            observed.reserve(64);
            for (const auto byte : digest)
            {
                observed.push_back(digits[byte >> 4]);
                observed.push_back(digits[byte & 15]);
            }
            return {};
        }
    }

    bool ValidNativeImageSha256(std::string_view value)
    {
        if (value.size() != 64)
        {
            return false;
        }
        for (const auto digit : value) // 逐位检查原约束编码，不自动修改用户保存的定义。
        {
            if (!((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    native_owner_detail::NativeDebugError NativeBreakpointImageIdentity::Observe(const DEBUG_EVENT& event)
    {
        HANDLE file = nullptr; // OS交给本次装载事件的真实文件，在Receive返回前会被关闭。
        std::uintptr_t base = 0; // 对应映像在该目标进程的实际模块基址。
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            file = event.u.CreateProcessInfo.hFile;
            base = reinterpret_cast<std::uintptr_t>(event.u.CreateProcessInfo.lpBaseOfImage);
        }
        else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            file = event.u.LoadDll.hFile;
            base = reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll);
        }
        else if (event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT)
        {
            files_.erase(reinterpret_cast<std::uintptr_t>(event.u.UnloadDll.lpBaseOfDll));
        }
        if (!base || !file || file == INVALID_HANDLE_VALUE)
        {
            return {}; // 无文件事件不补路径身份；若恰为目标映像，Verify明确拒绝缺失来源。
        }
        HANDLE duplicate = nullptr; // 原owner持有的独立句柄，不向目标或其它worker传递。
        if (!DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            return Failure("image-hash-hold-event-file");
        }
        files_.insert_or_assign(base, native_owner_detail::NativeDebugHandle(duplicate));
        return {};
    }

    native_owner_detail::NativeDebugError NativeBreakpointImageIdentity::Verify(std::uintptr_t moduleBase,
        std::string_view expected, std::string& observed)
    {
        observed.clear(); // 失败不遗留上次模块的散列。
        const auto found = files_.find(moduleBase); // 必须与实际解析成功的模块基址来自同一次装载。
        if (found == files_.end() || !ValidNativeImageSha256(expected))
        {
            return {"image-hash-event-file-unavailable", ERROR_INVALID_DATA};
        }
        native_owner_detail::NativeDebugHandle pinned(ReOpenFile(found->second.Get(), GENERIC_READ, FILE_SHARE_READ,
            FILE_FLAG_SEQUENTIAL_SCAN)); // 从原文件对象打开独立读位置，禁止并发写入和路径替换。
        if (!pinned)
        {
            return Failure("image-hash-pin-event-file");
        }
        if (const auto error = Digest(pinned.Get(), observed); error)
        {
            return error;
        }
        if (observed != expected)
        {
            return {"image-hash-mismatch", ERROR_CRC};
        }
        files_.clear(); // 其它装载文件不参与该站点身份，核对后释放。
        files_.emplace(moduleBase, std::move(pinned)); // 保留真实已核对文件，直到原绑定退出/清退。
        return {}; // 文件散列不证明目标MEM_IMAGE页面从未被修改。
    }

    void NativeBreakpointImageIdentity::Reset() noexcept
    {
        files_.clear(); // 只释放文件对象引用，没有目标线程、页保护或调试事件副作用。
    }
}
