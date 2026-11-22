// 只读符号投影回归：不打开驱动，不采集线程，不把固定地址投影冒充现场回溯。
// 调用：LiveThreadStackSymbolTests.exe <本地PE> <本地PDB目录> <十六进制RVA>。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkThreadStackSymbols.h"
#include <DbgHelp.h>
#include <array>
#include <cstdio>
#include <cwchar>
#include <filesystem>

// 独立输出系统 DbgHelp 的每个阶段，便于定位来宾本地符号依赖，且不改变生产符号策略。
static void Diagnose(const wchar_t* image, const wchar_t* search, const DWORD64 base)
{
    SYMSRV_INDEX_INFOW identity{}; // 磁盘 PE 中的符号身份，不代表已加载映像。
    identity.sizeofstruct = sizeof(identity);
    SetLastError(ERROR_SUCCESS);
    const auto indexed = SymSrvGetFileIndexInfoW(image, &identity, 0); // 只读取磁盘文件。
    std::printf("INDEX=%d ERROR=%lu SIZE=%lu AGE=%lu\n", indexed, GetLastError(), identity.size, identity.age);
    if (!indexed)
    {
        return;
    }
    const auto session = CreateEventW(nullptr, TRUE, FALSE, nullptr); // 仅作为私有符号会话键。
    const auto initialized = SymInitializeW(session, search, FALSE); // 不枚举进程，不继承网络服务器。
    std::printf("INITIALIZED=%d ERROR=%lu\n", initialized, GetLastError());
    if (initialized)
    {
        std::array<wchar_t, MAX_PATH + 1> pdb{}; // DbgHelp 指定的固定输出容量。
        const auto name = std::filesystem::path(identity.pdbfile).filename().wstring(); // 丢弃构建机目录。
        SetLastError(ERROR_SUCCESS);
        const auto found = SymFindFileInPathW(session, search, name.c_str(), &identity.guid,
            identity.age, 0, SSRVOPT_GUIDPTR, pdb.data(), nullptr, nullptr); // 与生产查找参数相同。
        std::printf("FOUND=%d ERROR=%lu\n", found, GetLastError());
        if (found)
        {
            SetLastError(ERROR_SUCCESS);
            const auto exactDirectory = std::filesystem::path(pdb.data()).parent_path().wstring(); // 搜索限于已确认 PDB 所在目录。
            SymSetSearchPathW(session, exactDirectory.c_str()); // 由 PE 提供匹配约束，而不是直接把 PDB 当作映像。
            const auto loaded = SymLoadModuleExW(session, nullptr, image, nullptr,
                base, identity.size, nullptr, 0); // 只允许本地 PE 与精确 PDB 的组合。
            std::printf("LOADED=%llx ERROR=%lu\n", loaded, GetLastError());
            IMAGEHLP_MODULEW64 module{}; // 复核实际采用的 PDB GUID/Age 与符号类型。
            module.SizeOfStruct = sizeof(module);
            const auto queried = SymGetModuleInfoW64(session, base, &module);
            std::printf("QUERIED=%d ERROR=%lu TYPE=%d AGE=%lu UNMATCHED=%d\n",
                queried, GetLastError(), static_cast<int>(module.SymType), module.PdbAge, module.PdbUnmatched);
        }
        SymCleanup(session); // 测试会话不留下符号状态或打开的文件。
    }
    CloseHandle(session); // 不持有任何目标线程或内核对象句柄。
}

// 输入磁盘 PE/PDB 与固定 RVA；校验生产投影保留帧、拒绝不稳定模块并解析精确本地符号。
int wmain(const int argc, wchar_t** argv)
{
    if (argc != 4)
    {
        return 64;
    }
    wchar_t* end = nullptr; // 验证整个 RVA 文本，而非接受部分有效前缀。
    const auto rva = std::wcstoull(argv[3], &end, 16); // 测试地址只是文件 RVA 投影。
    SYMSRV_INDEX_INFOW identity{}; // 取得实际磁盘映像大小。
    identity.sizeofstruct = sizeof(identity);
    if (end == argv[3] || *end || !SymSrvGetFileIndexInfoW(argv[1], &identity, 0) || rva >= identity.size)
    {
        return 64;
    }
    constexpr DWORD64 base = 0xfffff80010000000ULL; // 与任何现场无关的固定测试映像基址。
    Diagnose(argv[1], argv[2], base);
    ks::r3::driver::DriverOverviewRow module; // 模拟已独立观察的模块范围，不伪称现场来源。
    module.baseKnown = true;
    module.sizeKnown = true;
    module.rangeValid = true;
    module.baseAddress = base;
    module.imageSize = identity.size;
    module.pathText = argv[1];
    module.driverName = std::filesystem::path(argv[1]).filename().wstring();
    const std::vector<ks::r3::driver::DriverOverviewRow> stable{module}; // 两侧相同的只读测试观察。
    KSWORD_ARK_THREAD_STACK_RESPONSE response{}; // 只测试已给定帧的注释，不验证或构造采集成功状态。
    response.frameCount = 1;
    response.frames[0] = base + rva;
    const auto untrusted = ksword::ark::ResolveThreadStackFrames(response, stable, {}, argv[2]);
    if (untrusted.size() != 1 || untrusted[0].address != response.frames[0] ||
        !untrusted[0].moduleName.empty() || untrusted[0].localPdbMatched)
    {
        return 1;
    }
    const auto matched = ksword::ark::ResolveThreadStackFrames(response, stable, stable, argv[2]);
    const auto passed = matched.size() == 1 && matched[0].address == response.frames[0] &&
        matched[0].moduleBase == base && matched[0].localPdbMatched && !matched[0].symbolName.empty();
    std::printf("PRODUCTION_LOCAL_SYMBOL_PROJECTION=%s\n", passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
