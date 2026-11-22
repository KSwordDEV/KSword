// 合成/离线元数据回归，直接链接生产范围检查器；不打开驱动，也不声称采集到现场线程。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" BOOLEAN KswSavedStackCheck(ULONG64, ULONG, const void*, PCONTEXT, ULONG64, ULONG64, PULONG);

namespace
{
    unsigned checks = 0; // 计数只代表合成断言，不能作为 VM 验收次数。
    bool passed = true; // 某次失败不会因后续用例成功而被覆盖。

    // 输出单个断言结果，并保留本轮全部失败。
    void Check(bool condition, const char* name)
    {
        ++checks;
        if (!condition)
        {
            std::printf("FAIL=%s\n", name);
            passed = false;
        }
    }

    // 只读映射精确 NT 文件后，将其真实元数据与本机系统原生展开器交叉比较。
    void ExactImage(const wchar_t* path, DWORD rva)
    {
        const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr); // 磁盘只读句柄。
        const HANDLE mapping = file != INVALID_HANDLE_VALUE ? CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr) : nullptr; // 不执行映像代码。
        const auto* image = mapping ? static_cast<const unsigned char*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)) : nullptr; // 只为 RVA 寻址保留映像布局。
        Check(image != nullptr, "exact-image-read-only-map");
        if (image)
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image); // 已知测试 PE 的标准头。
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew); // 测试不接受任意用户输入文件。
            const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]; // 实际静态展开表。
            const auto* entries = reinterpret_cast<const RUNTIME_FUNCTION*>(image + directory.VirtualAddress); // 目录只读视图。
            constexpr unsigned char prolog[] = {0x48, 0x55, 0x48, 0x83, 0xec, 0x30}; // 两份精确切换序言，避免助记符与字节前缀混淆。
            const DWORD internal = rva == 0x3fbf96 ? 0x3fc270 : 0x6b9820; // 只用于已授权两个测试映像的只读证据。
            Check(std::memcmp(image + internal, prolog, sizeof(prolog)) == 0, "exact-switch-prologue-bytes");
            const RUNTIME_FUNCTION* entry = nullptr; // 精确控制地址必须存在唯一静态项。
            for (DWORD index = 0; index < directory.Size / sizeof(*entries); ++index)
            {
                if (entries[index].BeginAddress <= rva && rva < entries[index].EndAddress) entry = &entries[index];
            }
            Check(entry != nullptr, "exact-context-switch-entry");
            if (entry)
            {
                alignas(16) std::array<unsigned char, 1024> stack{}; // 完全合成的私有栈，绝不当作现场数据。
                const auto base = reinterpret_cast<DWORD64>(image); // 映像只读基址。
                const auto low = reinterpret_cast<DWORD64>(stack.data()); // 有界测试副本下界。
                const DWORD64 ret = base + 0x12345; // 合成返回槽值只用于精确单步比较。
                std::memcpy(stack.data() + 0x178, &ret, sizeof(ret));
                CONTEXT context{}; // 已知切换返回点的合成寄存器起点。
                context.Rip = base + rva;
                context.Rsp = low + 0x40;
                context.Rbp = low + 0x100;
                auto expected = context; // 生产范围检查器的独立计算容器。
                ULONG cs = 0; // 普通函数不应伪造用户态机器帧证据。
                const bool checked = KswSavedStackCheck(base, nt->OptionalHeader.SizeOfImage, entry, &expected, low, low + stack.size(), &cs) != FALSE;
                Check(checked && cs == 0, "exact-v2-preflight");
                void* data = nullptr; // 原生展开器输出，不执行语言异常处理器。
                DWORD64 establisher = 0; // 当前建帧基准输出。
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, context.Rip, const_cast<PRUNTIME_FUNCTION>(entry), &context, &data, &establisher, nullptr);
                Check(expected.Rip == ret && expected.Rsp == low + 0x180, "exact-switch-expected-layout");
                Check(context.Rip == expected.Rip && context.Rsp == expected.Rsp && context.Rbp == expected.Rbp, "exact-native-cross-check");
                expected = CONTEXT{};
                expected.Rip = base + rva;
                expected.Rsp = low + 0x40;
                Check(!KswSavedStackCheck(base, nt->OptionalHeader.SizeOfImage, entry, &expected, low, low + 0x100, &cs), "short-stack-refused-before-native");
            }
            UnmapViewOfFile(image);
        }
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
}

// 输入两份已有精确 PE；输出有界检查器的离线交叉比较与越界拒绝，不产生内核现场结论。
int wmain(int argc, wchar_t** argv)
{
    if (argc != 1 && argc != 3) return 64;
    if (argc == 3)
    {
        ExactImage(argv[1], 0x3fbf96);
        ExactImage(argv[2], 0x6b97b6);
    }
    alignas(16) std::array<unsigned char, 128> image{}; // 人工机器帧元数据容器。
    alignas(16) std::array<DWORD64, 16> stack{}; // 每个槽都有明确语义的合成机器帧。
    const auto base = reinterpret_cast<DWORD64>(image.data()); // 合成映像起点，不代表加载中模块。
    const auto low = reinterpret_cast<DWORD64>(stack.data()); // 合成副本边界。
    RUNTIME_FUNCTION function{0, 16, 32}; // 唯一合成函数的固定元数据位置。
    image[32] = 1;
    image[34] = 1;
    image[37] = 10; // 一个明确的 UWOP_PUSH_MACHFRAME，无错误码。
    stack[0] = 0x00007ff612341234;
    stack[1] = 0x33;
    stack[2] = 0x202;
    stack[3] = 0x0000001234500000;
    stack[4] = 0x2b;
    CONTEXT context{}; // 必须由明确的机器帧才能恢复用户 CS/RIP/RSP。
    context.Rip = base + 4;
    context.Rsp = low;
    ULONG cs = 0; // 普通或失败帧不得保留旧段证据。
    Check(KswSavedStackCheck(base, static_cast<ULONG>(image.size()), &function, &context, low, low + sizeof(stack), &cs) &&
        context.Rip == stack[0] && context.Rsp == stack[3] && cs == 0x33, "real-machine-slot-semantics");
    context.Rip = base + 4;
    context.Rsp = low;
    Check(!KswSavedStackCheck(base, static_cast<ULONG>(image.size()), &function, &context, low, low + 32, &cs), "truncated-machine-frame-refused");
    std::printf("SAVED_STACK_PREFLIGHT_OFFLINE_ONLY=%s checks=%u; no driver access\n", passed ? "PASS" : "FAIL", checks);
    return passed ? 0 : 1;
}
