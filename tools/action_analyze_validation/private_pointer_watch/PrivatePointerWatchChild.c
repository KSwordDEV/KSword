// 私有内存指针导出的合作目标。正式 CLI 只观察本程序自己创建的分布，
// 初始化完成后先置位 Ready，只有宿主写入 Gate 字节 '1' 才执行业务写入。
// 该文件同时可由 MSVC 工程和本机 GCC 夹具编译，导出的节布局保持一致。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// 盘上合作声明。正式 CLI 在启动前读取该导出，确认目标显式选择此协议。
__declspec(dllexport) const DWORD KSwordActionAnalyzeDataWatchV1 = 1;

#if defined(__GNUC__)
#define KSWORD_ALIGN8 __attribute__((aligned(8))) // GCC 不解析变量上的 __declspec(align)。
#else
#define KSWORD_ALIGN8 __declspec(align(8))
#endif

// 选择器本身位于映像可写数据节，保存一个 AMD64 指针。
// 初始化前为 0；正式 CLI 必须拒绝空指针而不是猜测地址。
__declspec(dllexport) KSWORD_ALIGN8 volatile ULONGLONG WatchedPointer = 0;

// MEM_IMAGE 负例使用该对齐数据导出，证明非私有内存不会被接受。
__declspec(dllexport) KSWORD_ALIGN8 volatile ULONGLONG WatchedData = 0x8877665511223344ULL;

// 私有分配固定 64 KiB，便于稳定构造同值、范围和后建线程用例。
#define REGION_BYTES 0x10000u
#define COMMIT_BYTES 0x1000u
#define WATCH_OFFSET 0x100u

enum FixtureMode {
    MODE_VALID = 0,
    MODE_NULL,
    MODE_MISALIGNED,
    MODE_READONLY,
    MODE_IMAGE,
    MODE_BOUNDARY,
    MODE_POINTER_CHANGE,
    MODE_PROTECT_CHANGE,
    MODE_MAPPED_REUSE,
    MODE_NO_READY,
    MODE_EXIT_BEFORE_READY,
};

static volatile unsigned char* g_target = NULL; // 本轮实际硬件关注起点。
static unsigned g_width = 0; // 正式 CLI 传入的关注宽度。
static void* g_region = NULL; // 原始私有分配，供负例与失效用例修改。
static void* g_second = NULL; // 指针变更后使用的新私有分配。
static HANDLE g_section = NULL; // 同址映射复用负例的节对象。

// 在失败的原生调用后立即保留错误，避免零值被当成成功。
static DWORD LastFailure(void)
{
    const DWORD error = GetLastError();
    return error ? error : ERROR_GEN_FAILURE;
}

// 只接受协调者传入的继承句柄；十进制表示且不允许尾随内容。
static HANDLE InheritedHandle(const char* text)
{
    char* end = NULL;
    const unsigned long long raw = _strtoui64(text, &end, 10);
    if (!raw || text[0] < '1' || text[0] > '9' || *end || raw != (ULONG_PTR)raw) {
        return NULL;
    }
    return (HANDLE)(ULONG_PTR)raw;
}

static HANDLE OpenEventByName(const char* prefix, const char* suffix, DWORD access)
{
    char name[160];
    if (sprintf_s(name, sizeof(name), "%s-%s", prefix, suffix) <= 0) {
        return NULL;
    }
    return OpenEventA(access, FALSE, name);
}

// 把本程序实际使用的地址和区域属性写入回执，供夹具独立核对 CLI 输出。
// 回执不是产品协议，只用于本机验收的地址真实性对比。
static void WriteReceipt(const char* protectionMode)
{
    const char* path = getenv("KSWORD_PRIVATE_POINTER_RECEIPT");
    if (!path || !*path || !g_target) {
        return;
    }
    MEMORY_BASIC_INFORMATION memory;
    if (!VirtualQuery((LPCVOID)g_target, &memory, sizeof(memory))) {
        return;
    }
    FILE* file = NULL;
    if (fopen_s(&file, path, "wb") != 0 || !file) {
        return;
    }
    fprintf(file, "pointer=0x%llX\n", (unsigned long long)(ULONG_PTR)g_target);
    fprintf(file, "allocationBase=0x%llX\n", (unsigned long long)(ULONG_PTR)memory.AllocationBase);
    fprintf(file, "regionBase=0x%llX\n", (unsigned long long)(ULONG_PTR)memory.BaseAddress);
    fprintf(file, "regionBytes=%llu\n", (unsigned long long)memory.RegionSize);
    fprintf(file, "regionProtection=%lu\n", (unsigned long)memory.Protect);
    fprintf(file, "type=%lu\n", (unsigned long)memory.Type);
    fprintf(file, "protectMode=%s\n", protectionMode);
    fclose(file);
}

static int ReadWidth(void)
{
    const char* text = getenv("KSWORD_PRIVATE_POINTER_WIDTH");
    if (!text || !*text) {
        return 8;
    }
    const int width = atoi(text);
    return width == 1 || width == 2 || width == 4 || width == 8 ? width : 0;
}

static enum FixtureMode ReadMode(void)
{
    const char* text = getenv("KSWORD_PRIVATE_POINTER_MODE");
    if (!text || !*text || !strcmp(text, "valid")) return MODE_VALID;
    if (!strcmp(text, "null")) return MODE_NULL;
    if (!strcmp(text, "misaligned")) return MODE_MISALIGNED;
    if (!strcmp(text, "readonly")) return MODE_READONLY;
    if (!strcmp(text, "image")) return MODE_IMAGE;
    if (!strcmp(text, "boundary")) return MODE_BOUNDARY;
    if (!strcmp(text, "pointer-change")) return MODE_POINTER_CHANGE;
    if (!strcmp(text, "protect-change")) return MODE_PROTECT_CHANGE;
    if (!strcmp(text, "mapped-reuse")) return MODE_MAPPED_REUSE;
    if (!strcmp(text, "no-ready")) return MODE_NO_READY;
    if (!strcmp(text, "exit-before-ready")) return MODE_EXIT_BEFORE_READY;
    return -1; // 未知模式直接失败，避免静默跑成正常用例。
}

// 分配私有 RW 或 RWX 区域，并把选择器指向其中的对齐起点。
// 所有负例都在调用 Ready 前完成，正式 CLI 只看到最终指针状态。
static int InitializeRegion(enum FixtureMode mode, unsigned width)
{
    const char* protect = getenv("KSWORD_PRIVATE_POINTER_PROTECT");
    const int rwx = protect && !strcmp(protect, "rwx");
    const DWORD allocationProtect = rwx ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

    if (mode == MODE_BOUNDARY) {
        // 整段保留但只提交一页；起点放在提交末页末端，使关注宽度越出该区。
        g_region = VirtualAlloc(NULL, REGION_BYTES, MEM_RESERVE, PAGE_READWRITE);
        if (!g_region || !VirtualAlloc(g_region, COMMIT_BYTES, MEM_COMMIT, PAGE_READWRITE)) {
            return 2;
        }
        g_target = (volatile unsigned char*)g_region + COMMIT_BYTES - 4;
        WatchedPointer = (ULONGLONG)(ULONG_PTR)g_target;
    } else {
        g_region = VirtualAlloc(NULL, REGION_BYTES, MEM_RESERVE | MEM_COMMIT, allocationProtect);
        if (!g_region) {
            return 2;
        }
        g_target = (volatile unsigned char*)g_region + WATCH_OFFSET;
        // 基线固定为 0x44，第一轮同值写才能真实提交同一字节。
        for (unsigned index = 0; index < width + 1; ++index) {
            g_target[index] = 0x44;
        }
        g_second = VirtualAlloc(NULL, REGION_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!g_second) {
            return 2;
        }
        memset((void*)g_second, 0x44, width);
        WatchedPointer = (ULONGLONG)(ULONG_PTR)g_target;
    }

    switch (mode) {
    case MODE_NULL:
        WatchedPointer = 0; // 空指针必须被拒绝。
        break;
    case MODE_MISALIGNED:
        WatchedPointer = (ULONGLONG)(ULONG_PTR)g_target + 4; // 8 字节宽度下未对齐。
        break;
    case MODE_READONLY: {
        DWORD old = 0;
        if (!VirtualProtect(g_region, REGION_BYTES, PAGE_READONLY, &old)) {
            return 2;
        }
        break;
    }
    case MODE_IMAGE:
        // 指向映像内可写数据节：地址可读，但类型不是 MEM_PRIVATE。
        WatchedPointer = (ULONGLONG)(ULONG_PTR)&WatchedData;
        break;
    default:
        break;
    }
    return 0;
}

// 后建线程完成关注范围末字节的写入，命中点因此有独立的线程身份。
typedef struct NewThreadArgs {
    HANDLE done;
    volatile unsigned char* target;
    unsigned offset;
} NewThreadArgs;

static DWORD WINAPI WriteFromNewThread(void* value)
{
    const NewThreadArgs* args = (const NewThreadArgs*)value;
    args->target[args->offset] ^= 1;
    return SetEvent(args->done) ? 0 : 1;
}

static int SpawnLastByteWriter(HANDLE done, unsigned width)
{
    NewThreadArgs args = {done, g_target, width - 1};
    const HANDLE writer = CreateThread(NULL, 0, WriteFromNewThread, &args, 0, NULL);
    if (!writer) {
        return 4;
    }
    DWORD code = 1;
    const BOOL complete = WaitForSingleObject(writer, 20000) == WAIT_OBJECT_0 &&
        GetExitCodeThread(writer, &code) && code == 0;
    CloseHandle(writer);
    return complete ? 0 : 4;
}

// 在进程仍运行时制造区间失效，使下一次硬件写入停点回读不到原绑定。
// 指针、保护属性和同址映射替换分别覆盖三种不能静默重绑的情况。
static int InvalidateRegion(enum FixtureMode mode)
{
    if (mode == MODE_POINTER_CHANGE) {
        WatchedPointer = (ULONGLONG)(ULONG_PTR)g_second; // 选择器改指新分配，旧地址仍是硬件关注点。
        return 0;
    }
    if (mode == MODE_PROTECT_CHANGE) {
        DWORD old = 0;
        // 改成同样可写的 RXW：写入仍可完成，但冻结的保护属性已不同。
        // PAGE_NOCACHE 在部分系统上会被忽略，不能作为可靠的变化证据。
        return VirtualProtect(g_region, COMMIT_BYTES, PAGE_EXECUTE_READWRITE, &old) ? 0 : 2;
    }
    if (mode == MODE_MAPPED_REUSE) {
        // 释放后在同一地址映射文件视图：写入仍可执行，但类型不再是 MEM_PRIVATE。
        const ULONG_PTR base = (ULONG_PTR)g_region;
        g_section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, REGION_BYTES, NULL);
        if (!g_section || !VirtualFree(g_region, 0, MEM_RELEASE)) {
            return 2;
        }
        void* reused = MapViewOfFileEx(g_section, FILE_MAP_ALL_ACCESS, 0, 0, REGION_BYTES, (LPVOID)base);
        if (!reused) {
            return 2;
        }
        g_region = reused;
        g_target = (volatile unsigned char*)reused + WATCH_OFFSET; // 仍写原地址。
        return 0;
    }
    return 0;
}

// 四轮业务：范围外/同值、主线程真实变化、后建线程变化、脱离后写入。
// 第三轮在失效模式先破坏绑定，再执行同一个旧地址写入。
static int RunRounds(HANDLE trigger, HANDLE done, enum FixtureMode mode, unsigned width)
{
    for (unsigned round = 0; round < 4; ++round) {
        if (WaitForSingleObject(trigger, 20000) != WAIT_OBJECT_0) {
            return 3;
        }
        if (round == 0) {
            if (g_target[width] == 0xFF) { // 范围外字节，硬件关注点不应触发。
                g_target[width] = 0;
            } else {
                g_target[width] ^= 1;
            }
            const unsigned char same = g_target[0]; // 同值写必须自然完成。
            g_target[0] = same;
        } else if (round == 1 || round == 3) {
            g_target[0] ^= 1;
        } else {
            const int invalid = InvalidateRegion(mode);
            if (invalid) {
                return invalid;
            }
            const int writer = SpawnLastByteWriter(done, width);
            if (writer) {
                return writer;
            }
            continue;
        }
        if (!SetEvent(done)) {
            return 5;
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    HANDLE ready = NULL; // 目标初始化完成事件。
    HANDLE gate = NULL; // 宿主唯一写端的读端，EOF 表示取消启动。
    for (int index = 1; index + 1 < argc; index += 2) {
        if (!strcmp(argv[index], "--ksword-breakpoint-ready")) {
            ready = InheritedHandle(argv[index + 1]);
        } else if (!strcmp(argv[index], "--ksword-breakpoint-gate")) {
            gate = InheritedHandle(argv[index + 1]);
        }
    }
    if (!ready || !gate) {
        return 2; // 只接受正式 CLI 的私有数据启动方式。
    }

    const enum FixtureMode mode = ReadMode();
    const int width = ReadWidth();
    if ((int)mode < 0 || !width) {
        return 2;
    }
    if (mode == MODE_EXIT_BEFORE_READY) {
        return 7; // 宿主必须把提前退出与 Ready 超时分开报告。
    }
    if (InitializeRegion(mode, (unsigned)width)) {
        return 2;
    }
    g_width = (unsigned)width;
    const char* protect = getenv("KSWORD_PRIVATE_POINTER_PROTECT");
    WriteReceipt(protect && !strcmp(protect, "rwx") ? "rwx" : "rw");

    if (mode != MODE_NO_READY) {
        if (!SetEvent(ready)) {
            return 2;
        }
    }
    CloseHandle(ready);
    char start = 0;
    DWORD bytes = 0;
    const BOOL received = ReadFile(gate, &start, sizeof(start), &bytes, NULL);
    const DWORD readError = received ? ERROR_SUCCESS : LastFailure();
    CloseHandle(gate);
    if (!received) {
        // 宿主在武装前取消启动时关闭写端；目标按合作协议正常退出。
        return readError == ERROR_BROKEN_PIPE ? 0 : 2;
    }
    if (bytes != sizeof(start) || start != '1') {
        return 2; // 只有固定的一个字节许可才进入业务。
    }
    if (mode == MODE_NO_READY) {
        return 0; // 无 Ready 模式从不执行业务，只验证取消路径。
    }

    const char* prefix = getenv("KSWORD_PRIVATE_POINTER_EVENTS");
    HANDLE trigger = NULL;
    HANDLE done = NULL;
    if (prefix && *prefix) {
        trigger = OpenEventByName(prefix, "trigger", SYNCHRONIZE);
        done = OpenEventByName(prefix, "done", EVENT_MODIFY_STATE);
    }
    int result = 2;
    if (trigger && done) {
        result = RunRounds(trigger, done, mode, (unsigned)width);
    }
    if (done) CloseHandle(done);
    if (trigger) CloseHandle(trigger);
    if (g_second) VirtualFree(g_second, 0, MEM_RELEASE);
    if (g_section) CloseHandle(g_section);
    // 映射复用模式已接管原区域，其余模式仍在自己的分配内存中。
    if (g_region && mode == MODE_MAPPED_REUSE) {
        UnmapViewOfFile(g_region);
    } else if (g_region) {
        VirtualFree(g_region, 0, MEM_RELEASE);
    }
    return result;
}
