#include "ArkThreadStackSymbols.h"
#include "../../../shared/usermode/backend/driver/DriverQueries.h"
#include "../ksword/dbghelp_serialization.h"

#include <DbgHelp.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>

#pragma comment(lib, "Dbghelp.lib")

namespace ksword::ark
{
    namespace
    {
        // 输入路径，返回是否为本地磁盘路径；不接受符号服务器、UNC 或网络驱动器。
        bool LocalPath(const std::wstring& path)
        {
            if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
                path.find_first_of(L"*;\r\n") != std::wstring::npos)
            {
                return false;
            }
            const std::wstring root = path.substr(0, 3); // GetDriveType 只接收卷根路径。
            const auto type = ::GetDriveTypeW(root.c_str()); // 网络映射盘不能触发后台网络查询。
            return type == DRIVE_FIXED || type == DRIVE_RAMDISK;
        }

        // 输入 PE 的 CodeView 身份，返回 Microsoft 本地缓存目录使用的 GUID/Age 键。
        std::wstring PdbKey(const SYMSRV_INDEX_INFOW& index)
        {
            std::array<wchar_t, 48> text{}; // GUID 的 32 位十六进制文本及 Age。
            swprintf_s(text.data(), text.size(),
                L"%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%lX",
                index.guid.Data1, index.guid.Data2, index.guid.Data3,
                index.guid.Data4[0], index.guid.Data4[1], index.guid.Data4[2], index.guid.Data4[3],
                index.guid.Data4[4], index.guid.Data4[5], index.guid.Data4[6], index.guid.Data4[7], index.age);
            return text.data();
        }

        // 输入调用方本地目录；返回可用目录串，不继承环境中的网络符号服务器。
        std::wstring SearchPath(const std::wstring& requested)
        {
            std::vector<std::wstring> paths; // 顺序优先：用户指定、本程序目录、常见本地缓存。
            std::size_t start = 0; // 分号分隔的目录起点。
            while (start <= requested.size())
            {
                const auto end = requested.find(L';', start); // 单个目录的结束位置。
                paths.push_back(requested.substr(start, end == requested.npos ? requested.npos : end - start));
                if (end == requested.npos)
                {
                    break;
                }
                start = end + 1;
            }
            std::array<wchar_t, 32768> executable{}; // 宿主 GUI 或 CLI 的真实路径。
            const auto length = ::GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
            if (length && length < executable.size())
            {
                const auto directory = std::filesystem::path(executable.data()).parent_path(); // 正式产物所在目录。
                paths.push_back(directory.wstring());
                paths.push_back((directory / L"symbols").wstring());
            }
            paths.push_back(L"C:\\Symbols");
            paths.push_back(L"C:\\ProgramData\\Dbg\\sym");
            std::array<wchar_t, MAX_PATH + 1> temporary{}; // 仅利用已经下载的本地缓存，不创建目录。
            const auto count = ::GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
            if (count && count < temporary.size())
            {
                paths.push_back((std::filesystem::path(temporary.data()) / L"KswordSymbols").wstring());
            }
            std::wstring joined; // 仅由已存在的本地目录组成的显式 DbgHelp 搜索路径。
            for (const auto& path : paths)
            {
                if (LocalPath(path) && ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
                {
                    if (!joined.empty())
                    {
                        joined += L';';
                    }
                    joined += path;
                }
            }
            return joined;
        }

        // 输入前后模块快照与帧地址；仅接受唯一、范围合法且两侧身份文字一致的模块。
        const ks::r3::driver::DriverOverviewRow* StableModule(const std::uint64_t address,
            const std::vector<ks::r3::driver::DriverOverviewRow>& before,
            const std::vector<ks::r3::driver::DriverOverviewRow>& after)
        {
            const ks::r3::driver::DriverOverviewRow* found = nullptr; // 不接受重叠模块的任意首项。
            for (const auto& candidate : before)
            {
                if (!candidate.baseKnown || !candidate.sizeKnown || !candidate.rangeValid ||
                    address < candidate.baseAddress || address - candidate.baseAddress >= candidate.imageSize)
                {
                    continue;
                }
                const auto matches = std::count_if(after.begin(), after.end(), [&candidate](const auto& item)
                {
                    return item.baseKnown && item.sizeKnown && item.rangeValid &&
                        item.baseAddress == candidate.baseAddress && item.imageSize == candidate.imageSize &&
                        _wcsicmp(item.pathText.c_str(), candidate.pathText.c_str()) == 0;
                }); // 只比较模块观察身份，不宣称模块在两次观察之间从未卸载重载。
                if (found || matches != 1)
                {
                    return nullptr;
                }
                found = &candidate;
            }
            return found;
        }

        // 输入本地 PE 路径和已初始化的符号会话；只加载精确 GUID/Age 的本地 PDB。
        bool LoadLocalPdb(const HANDLE session, const ks::r3::driver::DriverOverviewRow& module,
            const std::wstring& search, std::vector<DriverHandle>& files)
        {
            const auto image = ks::r3::driver::ResolveKernelImagePathForTrust(module.pathText); // 仅规范本地系统路径。
            if (!LocalPath(image))
            {
                return false;
            }
            DriverHandle imageFile(::CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)); // 禁止解析期间替换本地 PE。
            SYMSRV_INDEX_INFOW index{}; // 本地 PE 提供的 CodeView 身份，不是运行中内核内存读数。
            index.sizeofstruct = sizeof(index);
            if (!imageFile.isValid() || !::SymSrvGetFileIndexInfoW(image.c_str(), &index, 0) ||
                index.size != module.imageSize || !index.age || !index.pdbfile[0])
            {
                return false;
            }

            const auto name = std::filesystem::path(index.pdbfile).filename().wstring(); // 不使用构建机嵌入的绝对目录。
            std::wstring path = search + L';' + std::filesystem::path(image).parent_path().wstring(); // 映像同目录的 PDB 也允许匹配。
            std::size_t start = 0; // 为普通目录补齐微软缓存的两级目录，不启用 symsrv 下载。
            const auto plain = path; // 迭代原目录串，避免追加时改变边界。
            while (start <= plain.size())
            {
                const auto end = plain.find(L';', start); // 当前显式目录的结束位置。
                const auto directory = plain.substr(start, end == plain.npos ? plain.npos : end - start);
                if (LocalPath(directory))
                {
                    path += L';' + (std::filesystem::path(directory) / name / PdbKey(index)).wstring();
                }
                if (end == plain.npos)
                {
                    break;
                }
                start = end + 1;
            }
            std::array<wchar_t, MAX_PATH + 1> pdbPath{}; // SymFindFileInPathW 要求的固定输出容量。
            if (!::SymFindFileInPathW(session, path.c_str(), name.c_str(), &index.guid,
                index.age, 0, SSRVOPT_GUIDPTR, pdbPath.data(), nullptr, nullptr) || !LocalPath(pdbPath.data()))
            {
                return false;
            }
            DriverHandle pdb(::CreateFileW(pdbPath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)); // PDB 在 SymCleanup 前保持打开。
            // 必须把 PE 与 PDB 一起交给 DbgHelp；直接加载 PDB 会保留 PdbUnmatched，不能放宽该校验。
            const auto exactDirectory = std::filesystem::path(pdbPath.data()).parent_path().wstring(); // 仅搜索已锁定的精确本地 PDB 目录。
            const auto base = pdb.isValid() && ::SymSetSearchPathW(session, exactDirectory.c_str()) ?
                ::SymLoadModuleExW(session, imageFile.native(), image.c_str(),
                module.driverName.c_str(), module.baseAddress, module.imageSize, nullptr, 0) : 0;
            IMAGEHLP_MODULEW64 loaded{}; // 加载后再次确认实际采用的 PDB 身份，而不是仅相信查找成功。
            loaded.SizeOfStruct = sizeof(loaded);
            if (base != module.baseAddress || !::SymGetModuleInfoW64(session, base, &loaded) ||
                loaded.SymType != SymPdb || loaded.PdbUnmatched || loaded.PdbAge != index.age ||
                std::memcmp(&loaded.PdbSig70, &index.guid, sizeof(GUID)) != 0)
            {
                if (base)
                {
                    (void)::SymUnloadModule64(session, base);
                }
                return false;
            }
            files.push_back(std::move(imageFile));
            files.push_back(std::move(pdb));
            return true;
        }
    }

    std::vector<ThreadStackFrameSymbol> ResolveThreadStackFrames(
        const KSWORD_ARK_THREAD_STACK_RESPONSE& response,
        const std::vector<ks::r3::driver::DriverOverviewRow>& before,
        const std::vector<ks::r3::driver::DriverOverviewRow>& after, const std::wstring& localSymbolPath)
    {
        std::vector<ThreadStackFrameSymbol> frames; // 永远一项对应一个驱动帧，符号失败也不丢失地址。
        for (unsigned long index = 0; index < response.frameCount && index < KSWORD_ARK_THREAD_STACK_MAX_FRAMES; ++index)
        {
            ThreadStackFrameSymbol row; // 当前真实返回地址的只读投影。
            row.address = response.frames[index];
            if (const auto* module = StableModule(row.address, before, after))
            {
                row.moduleBase = module->baseAddress;
                row.moduleName = module->driverName;
                row.displacement = row.address - row.moduleBase;
            }
            frames.push_back(std::move(row));
        }

        const std::lock_guard<std::mutex> lock(ks::dbghelp::SerializationMutex()); // 与 R3、转储共享唯一 DbgHelp 锁。
        const DriverHandle session(::CreateEventW(nullptr, TRUE, FALSE, nullptr)); // 不冒用目标进程或请求者线程身份。
        std::vector<DriverHandle> files; // 其析构晚于下方会话清理，保证懒加载文件仍有效。
        const auto oldOptions = ::SymGetOptions(); // DbgHelp 选项是全局状态，用后必须恢复。
        struct Cleanup
        {
            HANDLE session; // 当前私有符号会话，不代表内核执行目标。
            DWORD options; // 原进程级 DbgHelp 配置。
            bool initialized = false; // 只清理由本函数成功初始化的会话。
            ~Cleanup()
            {
                if (initialized)
                {
                    (void)::SymCleanup(session);
                }
                ::SymSetOptions(options);
            }
        } cleanup{session.native(), oldOptions}; // 所有提前返回路径同样恢复全局选项。
        ::SymSetOptions((oldOptions & ~(SYMOPT_LOAD_ANYTHING | SYMOPT_DEFERRED_LOADS)) |
            SYMOPT_EXACT_SYMBOLS | SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS | SYMOPT_FAIL_CRITICAL_ERRORS |
            SYMOPT_IGNORE_NT_SYMPATH | SYMOPT_NO_IMAGE_SEARCH);
        const auto search = SearchPath(localSymbolPath); // 没有网络服务器的显式目录列表。
        if (!session.isValid() || !::SymInitializeW(session.native(), search.c_str(), FALSE))
        {
            return frames;
        }
        cleanup.initialized = true;
        std::map<std::uint64_t, bool> loaded; // 每个模块仅尝试一次精确本地符号加载。
        for (auto& frame : frames)
        {
            const auto* module = StableModule(frame.address, before, after); // 未经两侧观察匹配的地址不附加函数名。
            if (!module)
            {
                continue;
            }
            auto state = loaded.find(module->baseAddress); // 本次会话内的模块加载结果。
            if (state == loaded.end())
            {
                state = loaded.emplace(module->baseAddress, LoadLocalPdb(session.native(), *module, search, files)).first;
            }
            if (!state->second)
            {
                continue;
            }
            alignas(SYMBOL_INFOW) std::array<unsigned char, sizeof(SYMBOL_INFOW) + 1024 * sizeof(wchar_t)> storage{};
            auto* symbol = reinterpret_cast<SYMBOL_INFOW*>(storage.data()); // 容纳本帧函数名的对齐缓冲。
            symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
            symbol->MaxNameLen = 1024;
            DWORD64 offset = 0; // 从实际函数入口计算的字节偏移。
            if (::SymFromAddrW(session.native(), frame.address, &offset, symbol) &&
                symbol->NameLen < 1024 && symbol->ModBase == module->baseAddress)
            {
                frame.symbolName.assign(symbol->Name, symbol->NameLen);
                frame.displacement = offset;
                frame.localPdbMatched = true;
            }
        }
        return frames;
    }
}
