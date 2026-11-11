#include <Windows.h>
#include <cstdint>
#include <cstdio>
        template<class T> bool TrySafeIoValue(const T* value, T* output)
        {
            if (!value || !output) return false;
            __try { *output = *value; return true; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }
        template<class T> T SafeIoValue(const T* value, T fallback = {})
        {
            __try { return value ? *value : fallback; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return fallback; }
        }
        // A query failure can be caused by its own arguments or wait, not by
        // completion of the I/O. Require a readable failing NTSTATUS whose
        // mapped error agrees with the query before marking it complete.
        bool ConfirmFailedIoCompletion(const OVERLAPPED* overlapped, DWORD error)
        {
            ULONG_PTR internal = 0;
            if (!overlapped || !TrySafeIoValue(&overlapped->Internal, &internal)) return false;
            const NTSTATUS status = static_cast<NTSTATUS>(internal);
            if (status >= 0) return false;
            using Convert = ULONG(NTAPI*)(NTSTATUS);
            const auto convert = reinterpret_cast<Convert>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
            return convert && convert(status) == error;
        }

int main(){OVERLAPPED ov{};ov.Internal=0x103; if(ConfirmFailedIoCompletion(&ov,ERROR_IO_INCOMPLETE))return 1; ov.Internal=0xC0000120u; if(!ConfirmFailedIoCompletion(&ov,ERROR_OPERATION_ABORTED))return 2; if(ConfirmFailedIoCompletion(&ov,ERROR_INVALID_PARAMETER))return 3; if(ConfirmFailedIoCompletion(reinterpret_cast<OVERLAPPED*>(1),ERROR_OPERATION_ABORTED))return 4; ov.Internal=0; if(ConfirmFailedIoCompletion(&ov,ERROR_INVALID_PARAMETER))return 5; puts("PASS pending, matched cancellation, mismatched errors, invalid OVERLAPPED");}
