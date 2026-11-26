#pragma once
#include <Windows.h>
#include <winternl.h> // NTSTATUS由公开NT头提供，独立编译及x86/x64均不依赖包含顺序。
#include "../../shared/evidence/ApiMemoryLifecycleFields.h"

namespace apimon {
// 三个Nt入口共用本次栈内观察，不开新流、不持有或复制目标句柄。
class ApiMemoryLifecycleObservation final {
public:
    // kind/process/base/size/type/protection为原请求；构造时只安全读取输入和强实例。
    ApiMemoryLifecycleObservation(Ksword::Evidence::ApiMemoryOperation kind, HANDLE process,
        PVOID const* base, const SIZE_T* size, ULONG type, ULONG protection) noexcept;
    void MarkEntry() noexcept; // 原调用前取QPC并保留LastError，无返回值。
    void MarkReturn() noexcept; // 原调用后取QPC并保留LastError，无返回值。
    // status为原NTSTATUS；成功Allocate/Protect才读base/size，成功Protect才读oldProtection。
    void Complete(NTSTATUS status, PVOID const* base, const SIZE_T* size, const ULONG* oldProtection = nullptr) noexcept;
    // fields：返回本次只读值，发送端同步借用，不转移任何资源。
    const Ksword::Evidence::ApiMemoryLifecycleFieldsV1& fields() const noexcept
    {
        return fields_;
    }
private:
    HANDLE process_ = nullptr; // 原请求句柄，只用于前后身份复核。
    Ksword::Evidence::ApiMemoryLifecycleFieldsV1 fields_{}; // 本次独立协议值。
};
} // namespace apimon
