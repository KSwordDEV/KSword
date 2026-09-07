/*
 * attest_probe —— 取回安全内核（VTL1）签名的运行时驱动清单并原样打印。
 *
 * 为什么值得有这么个东西：在开着 VBS 的机器上我们拿不到 EPT（见
 * docs/next/VBS共存结论.md），但 VBS 本身白送了一个我们从没用过的判据面 ——
 * GetRuntimeAttestationReport 让一个**普通 VTL0 用户态进程**拿到一份由
 * 安全内核生成并签名的模块清单，**而且包含已经卸载的模块**。
 * 那是 EPT cross-view 也给不了的东西：EPT 只能看见此刻映射着的页。
 *
 * 本工具**只打印，不下判据**。差集判据要等这份原始数据看清楚之后再写 ——
 * 这条路的失败形态是假阳性告警，对一个 ARK 工具比漏报更难看。
 *
 * 三个已实测的坑，都在下面就地注明：
 *   1. 导出在 kernelbase.dll，**不在** kernel32（微软文档写的是 kernel32）；
 *   2. 尺寸查询返回 **FALSE + ERROR_INSUFFICIENT_BUFFER(122)**，
 *      按"FALSE 即失败"写会直接把这条路判死；
 *   3. RUNTIME_REPORT_PACKAGE_HEADER 因 UINT64 对齐实际 sizeof 是 40 而非
 *      字段和 36 —— 手算布局会差 4 字节。本文件一律用 sizeof/FIELD_OFFSET。
 */

#include <windows.h>
#include <psapi.h>
/*
 * mscat.h 链进来的 mssip.h 里有无名 union，在 /W4 /WX 下是 C4201 错误。
 * 那是 SDK 自己的头，只在这一处局部关掉，不动本工具的告警级别。
 */
#pragma warning(push)
#pragma warning(disable: 4201)
#include <mscat.h>
#pragma warning(pop)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")

/*
 * 用 GetProcAddress 而不是直接调用，有两个独立理由：
 *   * 声明被 NTDDI_WIN11_GE 门控，直接调要抬整个 SDK 目标版本；
 *   * 真正的导出在 kernelbase.dll，链接 kernel32.lib 找不到符号
 *     （官方文档的 req.dll/req.lib 两行都写的是 Kernel32 —— 实测是错的）。
 */
typedef BOOL (WINAPI *PFN_GET_RUNTIME_ATTESTATION_REPORT)(
    UCHAR* Nonce,
    UINT16 PackageVersion,
    UINT64 ReportTypesBitmap,
    PVOID ReportBuffer,
    PUINT32 ReportBufferSize);

static int g_json = 0;
static int g_verdict = 0;

/*
 * 变异测试用：把某个 VTL0 模块从参照面里抹掉，模拟"它对 VTL0 隐身"。
 * 注入点刻意放在**数据侧**（抹哈希与名字），判据代码一行不动 ——
 * 否则测的是测试桩不是判据。零命中这种结果没有证明力，
 * 必须先证明判据能命中，"本机基线为零"才是一句有内容的话。
 */
static const char* g_hideName = NULL;

/*
 * 反向判据的变异测试：把某个 VTL0 模块同时从"运行时报告"与"启动清单"两侧
 * 抹掉，模拟"它正加载着，但没有任何一份签名清单认识它"。
 * 同样只动数据，不动判据代码。
 */
static const char* g_orphanName = NULL;

static void PrintHashHex(const BYTE* data, size_t bytes, size_t maxBytes)
{
    size_t i;
    size_t n = (bytes < maxBytes) ? bytes : maxBytes;

    for (i = 0U; i < n; ++i) {
        printf("%02X", data[i]);
    }
    if (bytes > n) {
        printf("...");
    }
}

/* 把 CALG_* 摘要算法号翻译成人话；未知的原样给出编号。 */
static const char* HashAlgName(UINT16 alg)
{
    switch (alg) {
    case 0x8003: return "MD5";
    case 0x8004: return "SHA1";
    case 0x800C: return "SHA256";
    case 0x800D: return "SHA384";
    case 0x800E: return "SHA512";
    case 0:      return "(无)";
    default:     return "(未知)";
    }
}

/*
 * 摘要的**有效**长度由每条自己的 ImageHashAlgorithm 决定，不是
 * DRIVER_REPORT_DIGEST_MAX_SIZE。按最大长度打会把紧跟其后的
 * PublisherThumbprint 一起打出来 —— 实测 afd.sys 的"哈希"后半段
 * 恰好就是它的证书指纹，看上去像一个 64 字节摘要，其实是两个字段。
 */
static UINT32 HashLen(UINT16 alg)
{
    switch (alg) {
    case 0x8003: return 16U;  /* MD5    */
    case 0x8004: return 20U;  /* SHA1   */
    case 0x800C: return 32U;  /* SHA256 */
    case 0x800D: return 48U;  /* SHA384 */
    case 0x800E: return 64U;  /* SHA512 */
    default:     return 0U;
    }
}

/* 证书指纹恒为 SHA1，20 字节。 */
#define THUMBPRINT_LEN 20U

/* JSON 字符串转义，只处理这份报告里可能出现的字符。 */
static void PrintJsonString(const char* s, size_t maxLen)
{
    size_t i;

    putchar('"');
    for (i = 0U; i < maxLen && s[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            printf("\\%c", c);
        } else if (c < 0x20 || c >= 0x7F) {
            printf("\\u%04X", c);
        } else {
            putchar((char)c);
        }
    }
    putchar('"');
}

/*
 * VTL0 侧的参照面用 NtQuerySystemInformation(SystemModuleInformation) 而不是
 * psapi 的 EnumDeviceDrivers。理由是实测出来的：EnumDeviceDrivers 能给出正确的
 * **条数**，但配套的 GetDeviceDriverBaseName 在本机把 265 条名字**全部**返回成
 * "ntoskrnl.exe"。拿那个当参照面，差集里会凭空多出两百多条假阳性。
 * SystemModuleInformation 直接带 FullPathName，不依赖二次查询。
 */
#define SYSTEM_MODULE_INFORMATION_CLASS 11
#define STATUS_INFO_LENGTH_MISMATCH_L   ((LONG)0xC0000004L)

typedef struct _KSW_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} KSW_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _KSW_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    KSW_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} KSW_RTL_PROCESS_MODULES;

typedef LONG (WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

#define ATTEST_NAME_MAX 128

/*
 * ---- TCG Log (WBCL) ----
 *
 * VTL1 的运行时报告里 IncludeBootDrivers=0，启动期驱动整批缺失。那一批在
 * 引导期被度量进 TPM，日志由 Windows 落在 %WINDIR%\Logs\MeasuredBoot\ 下，
 * **普通用户可读，不需要提权，也不需要机器上真有 TPM**（本机 Get-Tpm 查不到
 * 信息，日志照样在）。所以不走 TBS 的 Tbsi_Get_TCG_Log。
 *
 * 本机实测（Windows 11 26300，日志 95043 字节）：
 *   45 条顶层事件，恰好吃满整个文件；摘要表只有一种算法 SHA256(0x000B/32 字节)；
 *   EV_EVENT_TAG 里 9 条 SIPAEVENT_TRUSTBOUNDARY(0x40010001) 容器；
 *   其中嵌着 212 个 SIPAEVENT_LOADEDMODULE_AGGREGATION(0x40010003)：
 *   PCR12 106 个（只有摘要与大小）、PCR13 106 个（带路径/证书/内部名）。
 *   106 个模块里 74 个是 .sys。
 *
 * **最关键的一条标定**：这 74 个 .sys 的 0x00070004 摘要与磁盘文件的
 * Authenticode PE image hash **74/74 逐字节一致，零例外**。也就是说
 * 启动清单、VTL1 运行时报告、我们自己对磁盘算的哈希，三者是同一套键空间。
 */
#define TCG_EV_EVENT_TAG            0x00000006UL
#define SIPA_AGGREGATION_BIT        0x40000000UL
#define SIPAEVENT_TRUSTBOUNDARY     0x40010001UL
#define SIPAEVENT_LOADEDMODULE_AGG  0x40010003UL
#define SIPAEVENT_MODULE_PATH       0x00070001UL
#define SIPAEVENT_MODULE_SIZE       0x00070002UL
#define SIPAEVENT_MODULE_HASHALG    0x00070003UL
#define SIPAEVENT_MODULE_HASH       0x00070004UL
#define SIPAEVENT_MODULE_THUMBPRINT 0x00070009UL
#define SIPAEVENT_MODULE_INTERNAL   0x0007000DUL

#define BOOT_MODULE_MAX 512

typedef struct {
    char   path[MAX_PATH];       /* NT 相对路径，形如 \WINDOWS\System32\drivers\x.sys */
    char   internalName[ATTEST_NAME_MAX];
    BYTE   hash[64];
    UINT32 hashLen;
    UINT16 alg;                  /* CALG_*，本机恒为 0x800C(SHA256) */
    BYTE   thumb[20];
    int    haveThumb;
    int    matchedLoaded;        /* 这条启动模块在 VTL0 当前枚举里还在不在 */
} BOOT_MODULE;

typedef struct {
    BOOT_MODULE items[BOOT_MODULE_MAX];
    UINT32 count;
    UINT32 dropped;              /* 超出容量被丢掉的条数 */
    UINT32 containers;           /* 见到的 0x40010003 容器总数（含 PCR12 的简版）*/
    int    truncated;            /* 解析中途越界，清单不完整 */
    UINT32 algFallback;          /* 摘要算法不在 digestSizes 表里，用了内置长度 */
    char   logPath[MAX_PATH];
    int    staleWarning;         /* 日志比本次开机还早 */
} BOOT_MODULE_SET;

/*
 * 比对用的一条名字。raw 是小写化后的原名，key 是再去掉 ".sys" 后的比对键。
 * 需要两个而不是一个：报告里的 InternalName 取自 PE 版本资源，同一台机器上
 * 有的带扩展名有的不带（qwavedrv.sys / ndis 混在一起），只按 raw 严格比对会
 * 凭空造出一批"只在一边"的条目 —— 那正是假阳性的来源。
 */
typedef struct {
    char   raw[ATTEST_NAME_MAX];
    char   key[ATTEST_NAME_MAX];
    char   path[MAX_PATH];   /* 仅 VTL0 侧：模块的 Win32 路径 */
    BYTE   sha256[32];
    BYTE   sha1[20];
    UINT32 sha256Len;        /* 0 = 没算出来 */
    UINT32 sha1Len;
    BYTE   reportHash[64];   /* 仅报告侧：ImageHash */
    UINT32 reportHashLen;
    UINT16 reportAlg;
    int    unloaded;
    int    matched;          /* 名字对上 */
    int    hashMatched;      /* 哈希对上 */
    int    orphan;           /* 变异测试：强制视为两份清单都不认识它 */
} NAME_SLOT;

/*
 * 用 catalog API 算 Authenticode PE image hash，而不是文件 flat hash。
 * 已实测标定：报告里的 ImageHash 与 AppLocker 给的
 * "SHA256 0xDECE1DEF…" 对 afd.sys 逐字节相同，而 flat SHA256 完全不同。
 * 换句话说安全内核记的是 **CI 用于签名验证的那个哈希**，
 * 它跳过 PE 校验和与证书表，所以对同一份签名镜像是稳定的。
 */
static int HashFileAuthenticode(HCATADMIN hAdmin, const char* path,
                                BYTE* out, UINT32 outCapacity, UINT32* outLen)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD cb = outCapacity;
    int ok = 0;

    if (hAdmin == NULL) { return 0; }
    hFile = CreateFileA(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { return 0; }
    if (CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &cb, out, 0)) {
        *outLen = (UINT32)cb;
        ok = 1;
    }
    CloseHandle(hFile);
    return ok;
}

/* 内核给的是 NT 路径，要转成 Win32 才能 CreateFile。 */
static int BuildWin32Path(const char* full, char* out, size_t outSize)
{
    char winDir[MAX_PATH];

    if (full[0] == '\0') { return 0; }
    if (_strnicmp(full, "\\SystemRoot\\", 12) == 0) {
        if (GetWindowsDirectoryA(winDir, (UINT)sizeof(winDir)) == 0U) { return 0; }
        return _snprintf_s(out, outSize, _TRUNCATE, "%s\\%s", winDir, full + 12) > 0;
    }
    if (_strnicmp(full, "\\??\\", 4) == 0) {
        return _snprintf_s(out, outSize, _TRUNCATE, "%s", full + 4) > 0;
    }
    if (full[0] == '\\') {
        /* 形如 \Windows\System32\... —— 补上系统盘符。 */
        if (GetWindowsDirectoryA(winDir, (UINT)sizeof(winDir)) == 0U) { return 0; }
        winDir[2] = '\0';
        return _snprintf_s(out, outSize, _TRUNCATE, "%s%s", winDir, full) > 0;
    }
    return _snprintf_s(out, outSize, _TRUNCATE, "%s", full) > 0;
}

/* 小写化拷贝，始终以 NUL 结尾。源可能是定长非 NUL 结尾数组，故显式带上限。 */
static void LowerCopy(char* dst, const char* src, size_t maxLen)
{
    size_t i;

    for (i = 0U; i < maxLen && i + 1U < (size_t)ATTEST_NAME_MAX && src[i] != '\0'; ++i) {
        char c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    dst[i] = '\0';
}

static void StripSysExt(char* s)
{
    size_t n = strlen(s);

    if (n > 4U && strcmp(s + n - 4U, ".sys") == 0) {
        s[n - 4U] = '\0';
    }
}

/* raw -> key：小写化已经做过，这里只负责去扩展名。 */
static void FillKeyFromRaw(NAME_SLOT* slot)
{
    memcpy(slot->key, slot->raw, strlen(slot->raw) + 1U);
    StripSysExt(slot->key);
}

/* 有界读，越界即失败而不是读进相邻内存。 */
static int TcgRead(const BYTE* b, size_t len, size_t* off, void* out, size_t n)
{
    if (*off > len || len - *off < n) { return 0; }
    memcpy(out, b + *off, n);
    *off += n;
    return 1;
}

static int TcgSkip(size_t len, size_t* off, size_t n)
{
    if (*off > len || len - *off < n) { return 0; }
    *off += n;
    return 1;
}

/* UTF-16LE → 本地 char，只为显示与比对基名，非 ASCII 用 '?' 顶掉。 */
static void Utf16ToNarrow(const BYTE* src, UINT32 srcBytes, char* dst, size_t dstSize)
{
    size_t o = 0U;
    UINT32 i;

    for (i = 0U; i + 1U < srcBytes && o + 1U < dstSize; i += 2U) {
        UINT16 w = (UINT16)(src[i] | ((UINT16)src[i + 1U] << 8));
        if (w == 0U) { break; }
        dst[o++] = (w < 0x80U) ? (char)w : '?';
    }
    dst[o] = '\0';
}

/*
 * 走一层 SIPA 事件序列。聚合事件（ID 带 0x40000000）的数据又是一串 SIPA 事件，
 * 所以要递归；depth 限制是防畸形日志把栈走穿，不是业务需要。
 */
static void SipaWalk(const BYTE* b, size_t start, size_t end, int depth,
                     BOOT_MODULE_SET* set)
{
    size_t o = start;

    if (depth > 8) { return; }
    while (o + 8U <= end) {
        UINT32 id = 0U;
        UINT32 len = 0U;
        size_t body;

        memcpy(&id, b + o, 4U);
        memcpy(&len, b + o + 4U, 4U);
        body = o + 8U;
        if (len > end - body) { set->truncated = 1; return; }

        if (id == SIPAEVENT_LOADEDMODULE_AGG) {
            BOOT_MODULE m;
            size_t f = body;
            size_t fend = body + len;

            set->containers++;
            memset(&m, 0, sizeof(m));
            while (f + 8U <= fend) {
                UINT32 fid = 0U;
                UINT32 flen = 0U;
                const BYTE* fd;

                memcpy(&fid, b + f, 4U);
                memcpy(&flen, b + f + 4U, 4U);
                fd = b + f + 8U;
                if (flen > fend - (f + 8U)) { set->truncated = 1; break; }

                if (fid == SIPAEVENT_MODULE_PATH) {
                    Utf16ToNarrow(fd, flen, m.path, sizeof(m.path));
                } else if (fid == SIPAEVENT_MODULE_INTERNAL) {
                    Utf16ToNarrow(fd, flen, m.internalName, sizeof(m.internalName));
                } else if (fid == SIPAEVENT_MODULE_HASH) {
                    if (flen != 0U && flen <= sizeof(m.hash)) {
                        memcpy(m.hash, fd, flen);
                        m.hashLen = flen;
                    }
                } else if (fid == SIPAEVENT_MODULE_HASHALG) {
                    if (flen == 4U) {
                        UINT32 a = 0U;
                        memcpy(&a, fd, 4U);
                        m.alg = (UINT16)a;
                    }
                } else if (fid == SIPAEVENT_MODULE_THUMBPRINT) {
                    if (flen == sizeof(m.thumb)) {
                        memcpy(m.thumb, fd, flen);
                        m.haveThumb = 1;
                    }
                }
                f += 8U + flen;
            }

            if (m.hashLen != 0U) {
                /*
                 * PCR12 与 PCR13 度量同一批模块：PCR12 的容器只有摘要与大小，
                 * PCR13 的才带路径与证书。按摘要去重，并让带路径的那份覆盖
                 * 先到的简版 —— 否则清单里一半条目没有名字。
                 */
                UINT32 k;
                int merged = 0;

                for (k = 0U; k < set->count; ++k) {
                    if (set->items[k].hashLen == m.hashLen &&
                        memcmp(set->items[k].hash, m.hash, m.hashLen) == 0) {
                        if (set->items[k].path[0] == '\0' && m.path[0] != '\0') {
                            set->items[k] = m;
                        }
                        merged = 1;
                        break;
                    }
                }
                if (!merged) {
                    if (set->count < BOOT_MODULE_MAX) {
                        set->items[set->count++] = m;
                    } else {
                        set->dropped++;
                    }
                }
            }
        } else if ((id & SIPA_AGGREGATION_BIT) != 0U) {
            SipaWalk(b, body, body + len, depth + 1, set);
        }
        o = body + len;
    }
}

/* 选本次开机那份日志：文件名是 <引导计数>-<恢复计数>.log，按数值取最大。 */
static int FindLatestBootLog(char* out, size_t outSize)
{
    char dir[MAX_PATH];
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    unsigned long bestBoot = 0UL;
    unsigned long bestResume = 0UL;
    char bestName[MAX_PATH];
    int found = 0;

    if (GetWindowsDirectoryA(dir, (UINT)sizeof(dir)) == 0U) { return 0; }
    if (_snprintf_s(pattern, sizeof(pattern), _TRUNCATE,
                    "%s\\Logs\\MeasuredBoot\\*.log", dir) < 0) {
        return 0;
    }
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { return 0; }
    bestName[0] = '\0';
    do {
        unsigned long bc = 0UL;
        unsigned long rc = 0UL;

        if (sscanf_s(fd.cFileName, "%lu-%lu.log", &bc, &rc) == 2) {
            if (!found || bc > bestBoot || (bc == bestBoot && rc > bestResume)) {
                bestBoot = bc;
                bestResume = rc;
                found = 1;
                memcpy(bestName, fd.cFileName, strlen(fd.cFileName) + 1U);
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (!found) { return 0; }
    return _snprintf_s(out, outSize, _TRUNCATE,
                       "%s\\Logs\\MeasuredBoot\\%s", dir, bestName) > 0;
}

/*
 * 读并解析启动度量日志。返回 1 表示拿到了模块清单。
 *
 * 摘要长度**必须**从首条 Spec ID Event 的 digestSizes 表里读，不能硬编码：
 * 换台机器可能同时度量 SHA1 与 SHA256，写死 32 会当场把偏移走飞。
 */
static int LoadBootModules(BOOT_MODULE_SET* set)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize;
    BYTE* b = NULL;
    DWORD got = 0U;
    size_t len = 0U;
    size_t off = 0U;
    UINT32 eventSize = 0U;
    UINT32 algCount = 0U;
    UINT16 algIds[16];
    UINT16 algSizes[16];
    UINT32 i;
    int ok = 0;

    memset(set, 0, sizeof(*set));
    if (!FindLatestBootLog(set->logPath, sizeof(set->logPath))) { return 0; }

    hFile = CreateFileA(set->logPath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { return 0; }
    if (!GetFileSizeEx(hFile, &fileSize) ||
        fileSize.QuadPart <= 0 || fileSize.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return 0;
    }

    /*
     * 日志属不属于本次开机要核对，不能默认。拿它当"启动期驱动的白名单"时，
     * 一份上次开机的日志会让本次真正新增的启动驱动全部落进告警。
     */
    {
        FILETIME ftWrite;
        FILETIME ftNow;
        ULONGLONG now;
        ULONGLONG wrote;
        ULONGLONG bootAt;

        if (GetFileTime(hFile, NULL, NULL, &ftWrite)) {
            GetSystemTimeAsFileTime(&ftNow);
            now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;
            wrote = ((ULONGLONG)ftWrite.dwHighDateTime << 32) | ftWrite.dwLowDateTime;
            bootAt = now - (GetTickCount64() * 10000ULL);
            /* 容 60 秒：开机时刻是由 tick 反推的，本来就不精确。 */
            if (wrote + 60ULL * 10000000ULL < bootAt) {
                set->staleWarning = 1;
            }
        }
    }

    len = (size_t)fileSize.QuadPart;
    b = (BYTE*)malloc(len);
    if (b == NULL) { CloseHandle(hFile); return 0; }
    if (!ReadFile(hFile, b, (DWORD)len, &got, NULL) || got != (DWORD)len) {
        free(b);
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);

    /* 首条是 legacy TCG_PCClientPCREvent：PCR(4) 类型(4) SHA1 摘要(20) 长度(4)。 */
    if (!TcgSkip(len, &off, 4U + 4U + 20U) ||
        !TcgRead(b, len, &off, &eventSize, 4U)) {
        free(b);
        return 0;
    }
    {
        /* Spec ID Event：签名(16) 平台类(4) 次(1) 主(1) 勘误(1) uintn(1) 算法数(4) */
        size_t spec = off;

        if (!TcgSkip(len, &spec, 16U + 4U + 1U + 1U + 1U + 1U) ||
            !TcgRead(b, len, &spec, &algCount, 4U) ||
            algCount == 0U || algCount > 16U) {
            free(b);
            return 0;
        }
        for (i = 0U; i < algCount; ++i) {
            if (!TcgRead(b, len, &spec, &algIds[i], 2U) ||
                !TcgRead(b, len, &spec, &algSizes[i], 2U)) {
                free(b);
                return 0;
            }
        }
    }
    if (!TcgSkip(len, &off, eventSize)) { free(b); return 0; }

    /* 其后全是 TCG_PCR_EVENT2。 */
    while (off + 12U <= len) {
        UINT32 pcr = 0U;
        UINT32 type = 0U;
        UINT32 digestCount = 0U;
        UINT32 d;

        if (!TcgRead(b, len, &off, &pcr, 4U) ||
            !TcgRead(b, len, &off, &type, 4U) ||
            !TcgRead(b, len, &off, &digestCount, 4U)) {
            set->truncated = 1;
            break;
        }
        if (digestCount > 16U) { set->truncated = 1; break; }
        for (d = 0U; d < digestCount; ++d) {
            UINT16 alg = 0U;
            UINT16 dlen = 0U;
            UINT32 k;

            if (!TcgRead(b, len, &off, &alg, 2U)) { set->truncated = 1; break; }
            for (k = 0U; k < algCount; ++k) {
                if (algIds[k] == alg) { dlen = algSizes[k]; break; }
            }
            if (dlen == 0U) {
                /*
                 * 规范要求出现过的算法都登记在 digestSizes 表里，但现实中有固件
                 * 违规。查表失败就退回内置长度并记一笔，而不是整份日志作废 ——
                 * 作废等于反向判据静默失效。退回过就记 truncated，让健康门把
                 * 反向方向关掉，宁可不判也不要拿一份可疑的清单去报。
                 */
                switch (alg) {
                case 0x0004: dlen = 20U; break;  /* SHA1   */
                case 0x000B: dlen = 32U; break;  /* SHA256 */
                case 0x000C: dlen = 48U; break;  /* SHA384 */
                case 0x000D: dlen = 64U; break;  /* SHA512 */
                case 0x0012: dlen = 32U; break;  /* SM3_256 */
                default: break;
                }
                set->algFallback++;
                if (dlen == 0U) { set->truncated = 1; break; }
            }
            if (!TcgSkip(len, &off, dlen)) { set->truncated = 1; break; }
        }
        if (set->truncated) { break; }
        if (!TcgRead(b, len, &off, &eventSize, 4U)) { set->truncated = 1; break; }
        if (eventSize > len - off) { set->truncated = 1; break; }

        if (type == TCG_EV_EVENT_TAG && eventSize >= 8U) {
            UINT32 tagId = 0U;
            UINT32 tagLen = 0U;

            memcpy(&tagId, b + off, 4U);
            memcpy(&tagLen, b + off + 4U, 4U);
            if (tagId == SIPAEVENT_TRUSTBOUNDARY && tagLen <= eventSize - 8U) {
                SipaWalk(b, off + 8U, off + 8U + tagLen, 1, set);
            }
        }
        off += eventSize;
        ok = 1;
    }

    free(b);
    return ok && set->count != 0U;
}

int main(int argc, char** argv)
{
    HMODULE kernelbase = NULL;
    PFN_GET_RUNTIME_ATTESTATION_REPORT fn = NULL;
    UCHAR nonce[RUNTIME_REPORT_NONCE_SIZE];
    BYTE* buffer = NULL;
    UINT32 size = 0U;
    DWORD err = 0U;
    const RUNTIME_REPORT_PACKAGE_HEADER* pkg = NULL;
    const DRIVER_RUNTIME_REPORT* rep = NULL;
    const BYTE* authStart = NULL;
    UINT32 authOffset = 0U;
    UINT16 index = 0U;
    NAME_SLOT* repNames = NULL;
    int verdictHits = 0;
    int i;

    (void)SetConsoleOutputCP(CP_UTF8);
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--json") == 0) { g_json = 1; }
        if (strcmp(argv[i], "--verdict") == 0) { g_verdict = 1; }
        if (strncmp(argv[i], "--selftest-hide=", 16) == 0) {
            g_hideName = argv[i] + 16;
        }
        if (strncmp(argv[i], "--selftest-orphan=", 18) == 0) {
            g_orphanName = argv[i] + 18;
        }
    }

    kernelbase = GetModuleHandleW(L"kernelbase.dll");
    if (kernelbase == NULL) {
        kernelbase = LoadLibraryW(L"kernelbase.dll");
    }
    if (kernelbase != NULL) {
        fn = (PFN_GET_RUNTIME_ATTESTATION_REPORT)(void*)
            GetProcAddress(kernelbase, "GetRuntimeAttestationReport");
    }
    if (fn == NULL) {
        fprintf(stderr,
                "kernelbase.dll 里没有 GetRuntimeAttestationReport。\n"
                "这个 API 需要 Windows 11 一代及以上；老系统上这条路不存在。\n");
        return 2;
    }

    /* nonce 只用于让签名绑定这一次请求，内容不需要保密。 */
    for (i = 0; i < RUNTIME_REPORT_NONCE_SIZE; ++i) {
        nonce[i] = (UCHAR)(rand() & 0xFF);
    }

    /*
     * 坑 2：这次调用**成功**的表现就是返回 FALSE 且 GetLastError()==122。
     * 把它当失败处理会在第一步就判死整条路。
     */
    SetLastError(0);
    (void)fn(nonce, RUNTIME_REPORT_PACKAGE_VERSION_CURRENT,
             RUNTIME_REPORT_TYPE_TO_MASK(RuntimeReportTypeDriver),
             NULL, &size);
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER || size == 0U) {
        fprintf(stderr,
                "尺寸查询没有按预期返回 ERROR_INSUFFICIENT_BUFFER：err=%lu size=%u\n"
                "常见成因：系统未开 VBS，或 testsigning/调试标志开着（文档要求关闭）。\n",
                err, size);
        return 3;
    }

    buffer = (BYTE*)calloc(1U, size);
    if (buffer == NULL) {
        fprintf(stderr, "分配 %u 字节失败\n", size);
        return 4;
    }

    SetLastError(0);
    if (!fn(nonce, RUNTIME_REPORT_PACKAGE_VERSION_CURRENT,
            RUNTIME_REPORT_TYPE_TO_MASK(RuntimeReportTypeDriver),
            buffer, &size)) {
        fprintf(stderr, "取报告失败：err=%lu\n", GetLastError());
        free(buffer);
        return 5;
    }

    pkg = (const RUNTIME_REPORT_PACKAGE_HEADER*)buffer;
    if (pkg->Magic != RUNTIME_REPORT_PACKAGE_MAGIC) {
        fprintf(stderr, "包头 Magic 不是 RTRP：0x%08X\n", pkg->Magic);
        free(buffer);
        return 6;
    }

    /*
     * 坑 3：布局用 sizeof 累加，不要手算字段和。
     * 认证段 = 包头 + nonce + 摘要头 + 签名，之后才是报告本体。
     */
    authOffset = (UINT32)sizeof(RUNTIME_REPORT_PACKAGE_HEADER) +
                 (UINT32)RUNTIME_REPORT_NONCE_SIZE +
                 pkg->TotalReportDigestsSize +
                 pkg->SignatureSize;
    if (authOffset + pkg->TotalAuthenticatedReportsSize > size) {
        fprintf(stderr,
                "布局越界：authOffset=%u + auth=%u > size=%u\n",
                authOffset, pkg->TotalAuthenticatedReportsSize, size);
        free(buffer);
        return 7;
    }
    authStart = buffer + authOffset;
    rep = (const DRIVER_RUNTIME_REPORT*)authStart;

    if (rep->Header.ReportType != RuntimeReportTypeDriver) {
        fprintf(stderr, "第一份报告不是 Driver 类型：%u\n", rep->Header.ReportType);
        free(buffer);
        return 8;
    }

    if (g_json) {
        printf("{\"kind\":\"attest-drivers\",\"packageSize\":%u,"
               "\"signatureScheme\":%u,\"signatureSize\":%u,"
               "\"digestAlg\":\"%s\",\"numberOfDrivers\":%u,"
               "\"reportOverflowed\":%s,\"partialReport\":%s,"
               "\"includeBootDrivers\":%s,\"drivers\":[",
               pkg->PackageSize, pkg->SignatureScheme, pkg->SignatureSize,
               HashAlgName(pkg->ReportDigestType), rep->NumberOfDrivers,
               rep->Flags.ReportOverflowed ? "true" : "false",
               rep->Flags.PartialReport ? "true" : "false",
               rep->Flags.IncludeBootDrivers ? "true" : "false");
    } else {
        printf("\n=== 安全内核（VTL1）签名的运行时驱动报告 ===\n");
        printf("  包大小       : %u 字节\n", pkg->PackageSize);
        printf("  摘要算法     : %s (0x%04X)\n",
               HashAlgName(pkg->ReportDigestType), pkg->ReportDigestType);
        printf("  签名方案     : %u %s   签名长度 %u 字节\n",
               pkg->SignatureScheme,
               pkg->SignatureScheme ==
                   RUNTIME_REPORT_SIGNATURE_SCHEME_SHA512_RSA_PSS_SHA512
                   ? "(SHA512-RSA-PSS-SHA512)" : "(未知方案)",
               pkg->SignatureSize);
        printf("  驱动条数     : %u\n", rep->NumberOfDrivers);
        printf("  报告标志     : ReportOverflowed=%u  PartialReport=%u  "
               "IncludeBootDrivers=%u\n",
               rep->Flags.ReportOverflowed, rep->Flags.PartialReport,
               rep->Flags.IncludeBootDrivers);
        if (!rep->Flags.IncludeBootDrivers) {
            printf("               ^ 为 0 表示**不含启动期驱动**，那部分信息在 "
                   "TCG Log 里。\n"
                   "                 直接拿这份清单与已加载模块做差集，会把全部"
                   "启动驱动误判成隐藏驱动。\n");
        }
        if (rep->Flags.ReportOverflowed) {
            printf("               ^ ReportOverflowed=1：安全内核的条数上限被"
                   "撑满，**清单不完整**。\n");
        }
        printf("\n  %-34s %5s %-8s %s\n",
               "InternalName", "Load", "标志", "镜像摘要 / 证书指纹");
        printf("  %s\n",
               "--------------------------------------------------------------"
               "-----------------");
    }

    repNames = (NAME_SLOT*)calloc(
        rep->NumberOfDrivers ? rep->NumberOfDrivers : 1U, sizeof(NAME_SLOT));
    if (repNames == NULL) {
        fprintf(stderr, "分配名字表失败\n");
        free(buffer);
        return 9;
    }

    for (index = 0U; index < rep->NumberOfDrivers; ++index) {
        const DRIVER_INFO_ENTRY* e = &rep->DriverEntries[index];
        char name[DRIVER_REPORT_NAME_MAX_LENGTH + 1];
        const BYTE* imageHash = NULL;
        const BYTE* thumb = NULL;
        const char* oem = NULL;

        /* InternalName 是定长 CHAR 数组，未必以 NUL 结尾。 */
        memcpy(name, e->InternalName, DRIVER_REPORT_NAME_MAX_LENGTH);
        name[DRIVER_REPORT_NAME_MAX_LENGTH] = '\0';

        LowerCopy(repNames[index].raw, name, DRIVER_REPORT_NAME_MAX_LENGTH);
        FillKeyFromRaw(&repNames[index]);
        repNames[index].unloaded = e->Flags.Unloaded ? 1 : 0;
        repNames[index].reportAlg = e->ImageHashAlgorithm;

        /* 动态区偏移是**相对报告起点**的，不是相对包起点。 */
        if (e->ImageHashOffset != 0U &&
            e->ImageHashOffset < pkg->TotalAuthenticatedReportsSize) {
            imageHash = authStart + e->ImageHashOffset;
            if (HashLen(e->ImageHashAlgorithm) != 0U) {
                repNames[index].reportHashLen = HashLen(e->ImageHashAlgorithm);
                memcpy(repNames[index].reportHash, imageHash,
                       repNames[index].reportHashLen);
            }
        }
        if (e->PublisherThumbprintOffset != 0U &&
            e->PublisherThumbprintOffset < pkg->TotalAuthenticatedReportsSize) {
            thumb = authStart + e->PublisherThumbprintOffset;
        }
        if (e->OemNameSize != 0U && e->OemNameOffset != 0U &&
            e->OemNameOffset < pkg->TotalAuthenticatedReportsSize) {
            oem = (const char*)(authStart + e->OemNameOffset);
        }

        if (g_json) {
            printf("%s{\"name\":", index ? "," : "");
            PrintJsonString(name, DRIVER_REPORT_NAME_MAX_LENGTH);
            printf(",\"loadCount\":%u,\"unloaded\":%s,\"bootDriver\":%s,"
                   "\"hotPatch\":%s,\"imageHashAlg\":\"%s\",\"imageHash\":\"",
                   e->LoadCount,
                   e->Flags.Unloaded ? "true" : "false",
                   e->Flags.BootDriver ? "true" : "false",
                   e->Flags.HotPatch ? "true" : "false",
                   HashAlgName(e->ImageHashAlgorithm));
            if (imageHash != NULL && HashLen(e->ImageHashAlgorithm) != 0U) {
                PrintHashHex(imageHash, HashLen(e->ImageHashAlgorithm),
                             HashLen(e->ImageHashAlgorithm));
            }
            printf("\",\"publisherThumbprint\":\"");
            if (thumb != NULL) {
                PrintHashHex(thumb, THUMBPRINT_LEN, THUMBPRINT_LEN);
            }
            printf("\",\"oemName\":");
            if (oem != NULL) { PrintJsonString(oem, e->OemNameSize); }
            else { printf("null"); }
            printf("}");
        } else {
            printf("  %-34.34s %5u %c%c%c      ",
                   name, e->LoadCount,
                   e->Flags.Unloaded   ? 'U' : '-',
                   e->Flags.BootDriver ? 'B' : '-',
                   e->Flags.HotPatch   ? 'H' : '-');
            printf("%-6s ", HashAlgName(e->ImageHashAlgorithm));
            if (imageHash != NULL && HashLen(e->ImageHashAlgorithm) != 0U) {
                PrintHashHex(imageHash, HashLen(e->ImageHashAlgorithm), 8U);
            } else {
                printf("(无摘要)");
            }
            printf(" / ");
            if (thumb != NULL) {
                PrintHashHex(thumb, THUMBPRINT_LEN, 8U);
            } else {
                printf("(无指纹)");
            }
            if (oem != NULL && e->OemNameSize != 0U) {
                printf("  OEM=%.*s", (int)e->OemNameSize, oem);
            }
            printf("\n");
        }
    }

    if (g_json) {
        printf("],");
    } else {
        printf("\n  标志：U=已卸载  B=启动期驱动  H=可热补丁\n");
    }

    /*
     * 并排比对：VTL1 签名的报告 vs VTL0 自己的枚举。
     *
     * **这里只列出两边的差，不下任何判据。** 两个方向各自都有已知的良性成因：
     *   * 只在 VTL1 里 —— 已卸载模块，VTL0 当然枚举不到，这正是这条路的价值；
     *   * 只在 VTL0 里 —— IncludeBootDrivers=0 意味着全部启动期驱动都不在报告里；
     *     另有一批驱动的 InternalName 与磁盘基名本就不同。
     * 这两类不先标定掉就写差集判据，产出的是假阳性告警。
     */
    {
        enum { MAX_LOADED = 4096 };
        PFN_NT_QUERY_SYSTEM_INFORMATION ntq = NULL;
        HMODULE ntdll = NULL;
        KSW_RTL_PROCESS_MODULES* sysmods = NULL;
        ULONG sysmodsSize = 0U;
        LONG st = 0;
        NAME_SLOT* loaded = NULL;
        LPVOID* mods = NULL;
        DWORD needed = 0U;
        DWORD psapiCount = 0U;
        DWORD count = 0U;
        DWORD di = 0U;
        DWORD both = 0U;
        DWORD relaxed = 0U;
        DWORD truncated = 0U;
        UINT16 ri = 0U;
        UINT16 onlyReport = 0U;
        DWORD onlyLoaded = 0U;
        DWORD nameMissHashHit = 0U;   /* 名字对不上、哈希对上 —— 同一份镜像换了个名 */
        DWORD nameHitHashMiss = 0U;   /* 名字对上、哈希对不上 —— 磁盘上的文件已不是加载的那份 */
        DWORD neitherReport = 0U;     /* 两维都对不上（报告侧）*/
        DWORD neitherLoaded = 0U;     /* 两维都对不上（VTL0 侧）*/
        DWORD noReportHash = 0U;      /* 报告里没带摘要 */
        DWORD noFileHash = 0U;        /* 磁盘文件哈希算不出来 */
        DWORD hitCount = 0U;          /* 正向判据命中数 */
        BOOT_MODULE_SET* boot = NULL; /* TCG Log 里的启动期模块清单 */
        int haveBoot = 0;
        DWORD bootReportHit = 0U;     /* 报告侧未匹配条目在启动清单里找到的 */
        DWORD bootLoadedHit = 0U;     /* VTL0 侧两维未匹配条目在启动清单里找到的 */
        DWORD reverseHits = 0U;       /* 三处都找不到的 VTL0 模块 —— 反向判据 */
        int reverseUsable = 0;        /* 启动清单健康才允许反向判 */

        /* psapi 只留作条数交叉核验，名字不采信（见文件上方注释）。 */
        mods = (LPVOID*)calloc(MAX_LOADED, sizeof(LPVOID));
        if (mods != NULL &&
            EnumDeviceDrivers(mods, (DWORD)(MAX_LOADED * sizeof(LPVOID)), &needed)) {
            psapiCount = needed / (DWORD)sizeof(LPVOID);
        }
        free(mods);
        mods = NULL;

        ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != NULL) {
            ntq = (PFN_NT_QUERY_SYSTEM_INFORMATION)(void*)
                GetProcAddress(ntdll, "NtQuerySystemInformation");
        }
        if (ntq != NULL) {
            /*
             * 尺寸会在两次调用之间变化（有驱动正在加载/卸载），所以是重试循环
             * 而不是"查一次尺寸再取一次"。多给 16KB 余量减少重试。
             */
            ULONG want = 0U;
            int attempt;

            st = ntq(SYSTEM_MODULE_INFORMATION_CLASS, NULL, 0U, &want);
            if (want == 0U) { want = 64U * 1024U; }
            for (attempt = 0; attempt < 8; ++attempt) {
                free(sysmods);
                sysmodsSize = want + 16U * 1024U;
                sysmods = (KSW_RTL_PROCESS_MODULES*)calloc(1U, sysmodsSize);
                if (sysmods == NULL) { break; }
                st = ntq(SYSTEM_MODULE_INFORMATION_CLASS, sysmods, sysmodsSize, &want);
                if (st != STATUS_INFO_LENGTH_MISMATCH_L) { break; }
            }
            if (st != 0 && sysmods != NULL) {
                free(sysmods);
                sysmods = NULL;
            }
        }

        if (sysmods != NULL) {
            count = sysmods->NumberOfModules;
            if (count > (DWORD)MAX_LOADED) {
                truncated = count - (DWORD)MAX_LOADED;
                count = (DWORD)MAX_LOADED;
            }
        }

        loaded = (NAME_SLOT*)calloc(count ? count : 1U, sizeof(NAME_SLOT));
        if (loaded != NULL && sysmods != NULL) {
            for (di = 0U; di < count; ++di) {
                const KSW_RTL_PROCESS_MODULE_INFORMATION* m = &sysmods->Modules[di];
                const char* full = (const char*)m->FullPathName;
                const char* base = full;

                /* OffsetToFileName 是内核给的基名偏移；越界就自己找分隔符。 */
                if (m->OffsetToFileName < sizeof(m->FullPathName)) {
                    base = full + m->OffsetToFileName;
                } else {
                    const char* p = strrchr(full, '\\');
                    if (p != NULL) { base = p + 1; }
                }
                LowerCopy(loaded[di].raw, base,
                          sizeof(m->FullPathName) - (size_t)(base - full));
                FillKeyFromRaw(&loaded[di]);
                (void)BuildWin32Path(full, loaded[di].path, sizeof(loaded[di].path));
            }
        }

        /*
         * VTL0 侧的 Authenticode 哈希。两个 HCATADMIN 各建一次而不是每文件一次：
         * 265 个模块 × 2 种算法 = 530 次哈希，逐次 AcquireContext 的开销比哈希本身还大。
         */
        if (loaded != NULL && sysmods != NULL) {
            HCATADMIN hSha1 = NULL;
            HCATADMIN hSha256 = NULL;

            (void)CryptCATAdminAcquireContext2(&hSha1,   NULL, L"SHA1",   NULL, 0U);
            (void)CryptCATAdminAcquireContext2(&hSha256, NULL, L"SHA256", NULL, 0U);
            for (di = 0U; di < count; ++di) {
                if (loaded[di].path[0] == '\0') { continue; }
                if (!HashFileAuthenticode(hSha256, loaded[di].path,
                                          loaded[di].sha256, 32U,
                                          &loaded[di].sha256Len)) {
                    loaded[di].sha256Len = 0U;
                }
                if (!HashFileAuthenticode(hSha1, loaded[di].path,
                                          loaded[di].sha1, 20U,
                                          &loaded[di].sha1Len)) {
                    loaded[di].sha1Len = 0U;
                }
            }
            if (hSha1   != NULL) { (void)CryptCATAdminReleaseContext(hSha1, 0U); }
            if (hSha256 != NULL) { (void)CryptCATAdminReleaseContext(hSha256, 0U); }

            if (g_hideName != NULL) {
                DWORD hidden = 0U;

                for (di = 0U; di < count; ++di) {
                    if (_stricmp(loaded[di].raw, g_hideName) != 0) { continue; }
                    loaded[di].sha1Len = 0U;
                    loaded[di].sha256Len = 0U;
                    loaded[di].key[0] = '\0';
                    hidden++;
                }
                if (!g_json) {
                    printf("\n  *** 变异测试模式：已把 %lu 个名为 \"%s\" 的模块"
                           "从 VTL0 参照面抹掉 ***\n"
                           "      下面的结果**不是**本机真实状态。\n",
                           hidden, g_hideName);
                }
            }
        }
        if (loaded != NULL && sysmods != NULL) {

            /* 按 key 做双向标记；O(n*m)，n=193 m=265，不值得上哈希表。 */
            for (di = 0U; di < count; ++di) {
                if (loaded[di].key[0] == '\0') { continue; }
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    if (repNames[ri].key[0] == '\0') { continue; }
                    if (strcmp(loaded[di].key, repNames[ri].key) == 0) {
                        loaded[di].matched = 1;
                        repNames[ri].matched = 1;
                        both++;
                        if (strcmp(loaded[di].raw, repNames[ri].raw) != 0) {
                            relaxed++;
                        }
                        break;
                    }
                }
                if (!loaded[di].matched) { onlyLoaded++; }
            }
            for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                if (!repNames[ri].matched) { onlyReport++; }
            }

            /*
             * 第二维匹配：Authenticode 哈希。名字维度已被数据判死
             * （InternalName 是版本资源自由文本，且在 32 字节处截断），
             * 哈希是唯一与名字无关的键。
             */
            for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                if (repNames[ri].reportHashLen == 0U) { continue; }
                for (di = 0U; di < count; ++di) {
                    const BYTE* v = NULL;
                    UINT32 vlen = 0U;

                    if (repNames[ri].reportAlg == 0x800C) {
                        v = loaded[di].sha256; vlen = loaded[di].sha256Len;
                    } else if (repNames[ri].reportAlg == 0x8004) {
                        v = loaded[di].sha1;   vlen = loaded[di].sha1Len;
                    }
                    if (vlen == 0U || vlen != repNames[ri].reportHashLen) { continue; }
                    if (memcmp(repNames[ri].reportHash, v, vlen) == 0) {
                        repNames[ri].hashMatched = 1;
                        loaded[di].hashMatched = 1;
                        break;
                    }
                }
            }
            for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                if (repNames[ri].reportHashLen == 0U) { noReportHash++; continue; }
                if (repNames[ri].hashMatched) {
                    if (!repNames[ri].matched) { nameMissHashHit++; }
                } else {
                    if (repNames[ri].matched) { nameHitHashMiss++; }
                    else { neitherReport++; }
                    /*
                     * 判据只看哈希、不看名字：名字对上不该救一个哈希对不上的条目
                     * —— 隐藏驱动完全可以把 InternalName 写成某个合法驱动的名字。
                     */
                    if (!repNames[ri].unloaded) { hitCount++; }
                }
            }
            for (di = 0U; di < count; ++di) {
                if (!loaded[di].matched && !loaded[di].hashMatched) { neitherLoaded++; }
                if (loaded[di].sha256Len == 0U && loaded[di].sha1Len == 0U) {
                    noFileHash++;
                }
            }

            /*
             * 第三个来源：TCG Log 的启动期模块清单，用来补上
             * IncludeBootDrivers=0 缺掉的那一批。三份清单的摘要都是
             * Authenticode PE image hash，所以可以直接按哈希并到一起。
             */
            if (g_orphanName != NULL) {
                DWORD orphaned = 0U;

                for (di = 0U; di < count; ++di) {
                    if (_stricmp(loaded[di].raw, g_orphanName) != 0) { continue; }
                    loaded[di].orphan = 1;
                    loaded[di].hashMatched = 0;
                    orphaned++;
                }
                if (!g_json) {
                    printf("\n  *** 变异测试模式：已把 %lu 个名为 \"%s\" 的模块"
                           "从**两份签名清单**里同时抹掉 ***\n"
                           "      下面的结果**不是**本机真实状态。\n",
                           orphaned, g_orphanName);
                }
            }

            boot = (BOOT_MODULE_SET*)calloc(1U, sizeof(BOOT_MODULE_SET));
            haveBoot = (boot != NULL) && LoadBootModules(boot);
            if (haveBoot) {
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    UINT32 k;

                    if (repNames[ri].hashMatched) { continue; }
                    if (repNames[ri].reportHashLen == 0U) { continue; }
                    for (k = 0U; k < boot->count; ++k) {
                        if (boot->items[k].hashLen == repNames[ri].reportHashLen &&
                            memcmp(boot->items[k].hash, repNames[ri].reportHash,
                                   boot->items[k].hashLen) == 0) {
                            bootReportHit++;
                            break;
                        }
                    }
                }
                for (di = 0U; di < count; ++di) {
                    UINT32 k;
                    int inBoot = 0;

                    for (k = 0U; k < boot->count && !loaded[di].orphan; ++k) {
                        if (boot->items[k].hashLen == 32U &&
                            loaded[di].sha256Len == 32U &&
                            memcmp(boot->items[k].hash, loaded[di].sha256, 32U) == 0) {
                            inBoot = 1;
                            boot->items[k].matchedLoaded = 1;
                            break;
                        }
                        if (boot->items[k].hashLen == 20U &&
                            loaded[di].sha1Len == 20U &&
                            memcmp(boot->items[k].hash, loaded[di].sha1, 20U) == 0) {
                            inBoot = 1;
                            boot->items[k].matchedLoaded = 1;
                            break;
                        }
                    }
                    if (!loaded[di].matched && !loaded[di].hashMatched && inBoot) {
                        bootLoadedHit++;
                    }
                    /*
                     * 反向判据的候选：这个模块此刻在 VTL0 里加载着，但它的镜像
                     * 既不在 VTL1 运行时报告里，也不在启动度量清单里。
                     * 磁盘哈希算不出来的不算候选 —— 那是我们看不见，不是它可疑。
                     */
                    if (!loaded[di].hashMatched && !inBoot &&
                        (loaded[di].sha256Len != 0U || loaded[di].sha1Len != 0U)) {
                        reverseHits++;
                    }
                }
                /*
                 * 反向方向只有在启动清单**健康**时才算数。日志过期、解析越界、
                 * 或超容量丢过条目，任何一条成立都会把"缺失"变成假阳性，
                 * 那时宁可不判也不要报。
                 */
                reverseUsable = !boot->staleWarning && !boot->truncated &&
                                boot->dropped == 0U && boot->algFallback == 0U;
            }
        }

        if (g_json) {
            printf("\"loadedModules\":%lu,\"matchedBoth\":%lu,"
                   "\"matchedOnlyAfterStrippingSys\":%lu,"
                   "\"enumTruncated\":%lu,"
                   "\"nameMissHashHit\":%lu,\"nameHitHashMiss\":%lu,"
                   "\"neitherReport\":%lu,\"neitherLoaded\":%lu,"
                   "\"noReportHash\":%lu,\"noFileHash\":%lu,"
                   "\"verdictHits\":%lu,"
                   "\"bootModules\":%lu,\"bootLogStale\":%s,"
                   "\"bootReportHit\":%lu,\"bootLoadedHit\":%lu,"
                   "\"reverseHits\":%lu,\"reverseUsable\":%s,"
                   "\"onlyInReport\":[",
                   count, both, relaxed, truncated,
                   nameMissHashHit, nameHitHashMiss,
                   neitherReport, neitherLoaded, noReportHash, noFileHash,
                   hitCount + (reverseUsable ? reverseHits : 0UL),
                   haveBoot ? boot->count : 0UL,
                   (haveBoot && boot->staleWarning) ? "true" : "false",
                   bootReportHit, bootLoadedHit, reverseHits,
                   reverseUsable ? "true" : "false");
            if (loaded != NULL && sysmods != NULL) {
                DWORD emitted = 0U;
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    if (repNames[ri].matched) { continue; }
                    printf("%s{\"name\":", emitted ? "," : "");
                    PrintJsonString(repNames[ri].raw, ATTEST_NAME_MAX);
                    printf(",\"unloaded\":%s,\"hashMatched\":%s}",
                           repNames[ri].unloaded ? "true" : "false",
                           repNames[ri].hashMatched ? "true" : "false");
                    emitted++;
                }
                printf("],\"onlyInLoaded\":[");
                emitted = 0U;
                for (di = 0U; di < count; ++di) {
                    if (loaded[di].matched) { continue; }
                    printf("%s", emitted ? "," : "");
                    PrintJsonString(loaded[di].raw, ATTEST_NAME_MAX);
                    emitted++;
                }
                printf("]");
            } else {
                printf("],\"onlyInLoaded\":[]");
            }
            printf("}\n");
        } else {
            printf("\n=== 并排比对（原始数据，未下判据）===\n");
            printf("  VTL1 签名报告            : %u 条\n", rep->NumberOfDrivers);
            printf("  VTL0 SystemModuleInfo    : %lu 条%s\n", count,
                   truncated ? "（**被缓冲截断**，下面的差不完整）" : "");
            printf("  （交叉核验）EnumDeviceDrivers : %lu 条 —— 只用条数，"
                   "它的基名在本机全部返回 ntoskrnl.exe，不可用作参照面\n",
                   psapiCount);
            if (loaded == NULL || sysmods == NULL) {
                printf("  比对未进行：SystemModuleInformation 查询失败"
                       "（st=0x%08X）或分配失败。\n", (unsigned)st);
            } else {
                printf("\n  [名字维度]\n");
                printf("    两边都有               : %lu 条"
                       "（其中 %lu 条是去掉 .sys 才对上的）\n", both, relaxed);
                printf("    只在 VTL1 报告里       : %u 条\n", onlyReport);
                printf("    只在 VTL0 枚举里       : %lu 条\n", onlyLoaded);

                printf("\n  [Authenticode 哈希维度 —— 与名字无关]\n");
                printf("    名字对不上但哈希对上   : %lu 条  ← 同一份镜像，"
                       "只是 InternalName 与文件名不同\n", nameMissHashHit);
                printf("    名字对上但哈希对不上   : %lu 条  ← 磁盘上的文件"
                       "已不是当初加载的那一份\n", nameHitHashMiss);
                printf("    两维都对不上（报告侧） : %lu 条\n", neitherReport);
                printf("    两维都对不上（VTL0侧） : %lu 条\n", neitherLoaded);
                printf("    报告里无摘要           : %lu 条\n", noReportHash);
                printf("    磁盘文件哈希算不出     : %lu 条\n", noFileHash);

                printf("\n  [TCG Log 启动期清单 —— 补 IncludeBootDrivers=0 的缺口]\n");
                if (!haveBoot) {
                    printf("    取不到启动度量日志，反向差集仍然不可用。\n");
                } else {
                    printf("    日志                   : %s\n", boot->logPath);
                    printf("    启动期模块             : %lu 条"
                           "（见到 %lu 个度量容器，PCR12/13 按摘要归并后）\n",
                           boot->count, boot->containers);
                    if (boot->staleWarning) {
                        printf("    [警告] 这份日志比本次开机还早 —— 它不是本次启动的度量，"
                               "下面的数字不可用。\n");
                    }
                    if (boot->truncated) {
                        printf("    [警告] 解析中途越界，启动清单不完整。\n");
                    }
                    if (boot->dropped != 0U) {
                        printf("    [警告] 超出容量丢弃 %lu 条。\n", boot->dropped);
                    }
                    printf("    补上报告侧未匹配       : %lu 条\n", bootReportHit);
                    printf("    补上 VTL0 侧未匹配     : %lu / %lu 条\n",
                           bootLoadedHit, neitherLoaded);
                    printf("    三处都找不到的 VTL0 模块: %lu 条  ← 反向判据的候选\n",
                           reverseHits);
                }

                printf("\n  --- 只在 VTL1 报告里（按名字）---\n");
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    if (repNames[ri].matched) { continue; }
                    printf("    %-34.34s %-10s%s\n",
                           repNames[ri].raw[0] ? repNames[ri].raw : "(空名)",
                           repNames[ri].hashMatched ? "[哈希对上]" : "[哈希也没对上]",
                           repNames[ri].unloaded ? " [已卸载 —— 预期如此]" : "");
                }

                printf("\n  --- 只在 VTL0 枚举里（按名字）---\n");
                for (di = 0U; di < count; ++di) {
                    const char* tag = "";
                    UINT32 k;

                    if (loaded[di].matched) { continue; }
                    if (loaded[di].hashMatched) {
                        tag = "[运行时报告里有]";
                    } else if (haveBoot) {
                        tag = "[三处都没有]";
                        for (k = 0U; k < boot->count; ++k) {
                            if (boot->items[k].hashLen == 32U &&
                                loaded[di].sha256Len == 32U &&
                                memcmp(boot->items[k].hash, loaded[di].sha256, 32U) == 0) {
                                tag = "[启动清单里有]";
                                break;
                            }
                        }
                        if (loaded[di].sha256Len == 0U && loaded[di].sha1Len == 0U) {
                            tag = "[磁盘哈希算不出，无法判断]";
                        }
                    }
                    printf("    %-34.34s %s\n",
                           loaded[di].raw[0] ? loaded[di].raw : "(取名失败)", tag);
                }

                printf("\n  上面两张表都**不是**结论：\n"
                       "    * 只在 VTL1 里：已卸载模块本就该只出现在这边，"
                       "这正是本条路相对 EPT cross-view 的增量；\n"
                       "    * 只在 VTL0 里：IncludeBootDrivers=%u，为 0 时"
                       "全部启动期驱动都不在报告里；\n"
                       "      另有一批驱动的 InternalName 与磁盘基名本就不同。\n"
                       "      这两类不先标定掉就写差集判据，产出的是假阳性告警。\n",
                       rep->Flags.IncludeBootDrivers);
            }
        }

        /*
         * 第 3 步的判据。默认关闭，要 --verdict 才跑 —— 判据一旦上线，
         * 它的失败形态是**假阳性告警**，对一个 ARK 工具比漏报更难看，
         * 所以它必须是显式动作而不是顺带产物。
         */
        if (g_verdict) {
            if (loaded == NULL || sysmods == NULL) {
                verdictHits = -1;
                if (!g_json) {
                    printf("\n[判据未运行] VTL0 参照面取不到，无法比对。\n");
                }
            } else {
                verdictHits = (int)hitCount + (reverseUsable ? (int)reverseHits : 0);
                if (!g_json) {
                    printf("\n=== 判据（--verdict）===\n");
                    printf("  【正向】报告里**未卸载**的条目，其 Authenticode 摘要在\n"
                           "          VTL0 当前全部已加载模块的磁盘文件里找不到。\n");
                    printf("          成因二选一：模块对 VTL0 隐身，或磁盘文件已被换掉。\n");
                    printf("  【反向】VTL0 此刻加载着的模块，其 Authenticode 摘要在\n"
                           "          VTL1 运行时报告与 TCG 启动度量清单里**都**找不到。\n");
                    printf("  **只用哈希不用名字** —— 名字维度已被本机数据判死：\n"
                           "    InternalName 取自 PE 版本资源，可为空、可带版本号、"
                           "可在 32 字节处截断。\n");
                    if (!reverseUsable) {
                        printf("  [反向未启用] 启动清单不健康"
                               "（取不到 / 过期 / 解析越界 / 丢过条目），\n"
                               "               该方向本轮不判 —— **不等于该方向干净**。\n");
                    }
                    if (noFileHash != 0U) {
                        printf("  [降级] VTL0 侧有 %lu 个模块算不出磁盘哈希"
                               "（如 crashdump 栈的 dump_* 副本，磁盘上没有对应文件），\n"
                               "         它们两个方向都无法参与匹配。\n",
                               noFileHash);
                    }
                    /*
                     * 两个方向共有的一条假阳性来源，必须随判据一起显示：
                     * 我们比的是**磁盘文件此刻**的哈希，而两份清单记的是模块
                     * 被加载/被度量那一刻的镜像。Windows Update 换过文件但还没
                     * 重启时，两者本来就不同 —— 那不是篡改。
                     */
                    printf("  [注意] 比的是磁盘文件**此刻**的哈希，两份清单记的是"
                           "加载/度量当时的镜像。\n"
                           "         打过补丁尚未重启时两者本就不同，"
                           "**不匹配不等于被篡改**，命中要人工核而不是直接告警。\n");
                    for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                        if (repNames[ri].unloaded) { continue; }
                        if (repNames[ri].reportHashLen == 0U) { continue; }
                        if (repNames[ri].hashMatched) { continue; }
                        printf("  [正向命中] %-28.28s  ",
                               repNames[ri].raw[0] ? repNames[ri].raw : "(空名)");
                        PrintHashHex(repNames[ri].reportHash,
                                     repNames[ri].reportHashLen,
                                     repNames[ri].reportHashLen);
                        printf("\n");
                    }
                    if (reverseUsable) {
                        for (di = 0U; di < count; ++di) {
                            UINT32 k;
                            int inBoot = 0;

                            if (loaded[di].hashMatched) { continue; }
                            if (loaded[di].sha256Len == 0U &&
                                loaded[di].sha1Len == 0U) { continue; }
                            for (k = 0U; k < boot->count && !loaded[di].orphan; ++k) {
                                if (boot->items[k].hashLen == 32U &&
                                    loaded[di].sha256Len == 32U &&
                                    memcmp(boot->items[k].hash,
                                           loaded[di].sha256, 32U) == 0) {
                                    inBoot = 1;
                                    break;
                                }
                            }
                            if (inBoot) { continue; }
                            printf("  [反向命中] %-28.28s  ",
                                   loaded[di].raw[0] ? loaded[di].raw : "(取名失败)");
                            if (loaded[di].sha256Len == 32U) {
                                PrintHashHex(loaded[di].sha256, 32U, 32U);
                            }
                            printf("\n    %s\n", loaded[di].path);
                        }
                    }
                    printf("  命中 %d 条（正向 %lu + 反向 %lu）。%s\n",
                           verdictHits, hitCount,
                           reverseUsable ? reverseHits : 0UL,
                           verdictHits == 0 ? "本机基线为零。" : "以上每条都要人工核。");
                }
            }
        }

        free(boot);
        free(loaded);
        free(sysmods);
    }

    free(repNames);
    free(buffer);

    /*
     * 退出码分三档，刻意不与 2..9 的错误码重叠：
     *   0  正常（未开判据，或判据零命中）
     *   20 判据有命中 —— 需要人工核，不是"工具出错"
     *   21 判据没跑成（VTL0 参照面取不到）—— **不等于干净**
     */
    if (g_verdict && verdictHits < 0) { return 21; }
    if (g_verdict && verdictHits > 0) { return 20; }
    return 0;
}
