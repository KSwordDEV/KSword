#include "ProbeStages.h"

// A deliberately small, CRT-free *test* bootstrap. It hooks only the owned
// fixture EXE's CreateFileW import. It is not the API Monitor Agent or a generic
// production injector. No DLL loading, thread creation or waiting in DllMain.
using CreateFileFunction = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileFunction originalCreateFile;
static ProbeStages* stages;
static HANDLE stageMapping;

static bool EndsWith(LPCWSTR path, LPCWSTR suffix)
{
    if (!path) return false;
    const int length = lstrlenW(path), suffixLength = lstrlenW(suffix);
    return length >= suffixLength && lstrcmpiW(path + length - suffixLength, suffix) == 0;
}

static HANDLE WINAPI RecordCreateFile(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
    DWORD disposition, DWORD attributes, HANDLE templateFile)
{
    const DWORD incomingError = GetLastError();
    if (stages) {
        if (EndsWith(name, L"\\tls.marker")) InterlockedIncrement(&stages->tlsCaptured);
        if (EndsWith(name, L"\\constructor.marker")) InterlockedIncrement(&stages->constructorCaptured);
        if (EndsWith(name, L"\\main.marker")) InterlockedIncrement(&stages->mainCaptured);
    }
    SetLastError(incomingError);
    return originalCreateFile(name, access, share, security, disposition, attributes, templateFile);
}

static bool IsCreateFile(const char* name)
{
    const char expected[] = "CreateFileW";
    for (unsigned i = 0; i < sizeof(expected); ++i) if (name[i] != expected[i]) return false;
    return true;
}

static bool InstallOwnedImport()
{
    auto* base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto* descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
    const unsigned count = directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (unsigned i = 0; i < count && descriptors[i].Name; ++i) {
        const auto& descriptor = descriptors[i];
        if (!descriptor.OriginalFirstThunk) continue;
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor.OriginalFirstThunk);
        auto* addresses = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor.FirstThunk);
        for (unsigned n = 0; n < 4096 && names[n].u1.AddressOfData; ++n) {
            if (IMAGE_SNAP_BY_ORDINAL(names[n].u1.Ordinal)) continue;
            auto* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names[n].u1.AddressOfData);
            if (!IsCreateFile(import->Name)) continue;
            DWORD protection = 0, ignored = 0;
            auto* slot = &addresses[n].u1.Function;
            if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &protection)) return false;
            originalCreateFile = reinterpret_cast<CreateFileFunction>(*slot);
            InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(slot), reinterpret_cast<void*>(&RecordCreateFile));
            const BOOL restored = VirtualProtect(slot, sizeof(*slot), protection, &ignored);
            return restored != FALSE;
        }
    }
    return false;
}

extern "C" void StartupProbeImport() {}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    wchar_t name[256];
    if (!GetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_MAP", name, 256)) return FALSE;
    stageMapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, name);
    if (!stageMapping) return FALSE;
    stages = static_cast<ProbeStages*>(MapViewOfFile(stageMapping, FILE_MAP_WRITE, 0, 0, sizeof(ProbeStages)));
    if (!stages) return FALSE;
    InterlockedIncrement(&stages->bootstrapLoaded);
    if (!stages->tls && !stages->constructor && !stages->main) InterlockedIncrement(&stages->bootstrapBeforeTls);
    if (!InstallOwnedImport()) return FALSE;
    InterlockedIncrement(&stages->bootstrapInstalled);
    return TRUE;
}
