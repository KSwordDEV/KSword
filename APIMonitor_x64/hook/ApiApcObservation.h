#pragma once

#include "../../shared/evidence/ApiApcFields.h"
#include "ApiThreadTargetObservation.h"

namespace apimon {
// ApiApcObservation：调用方持有 ScopedHookGuard 并执行原 API，本类只采集入队请求。
class ApiApcObservation {
public:
    // thread 为原线程句柄，routine 为请求例程，argument1/2/3 为原始参数位模式。
    // reserveHandle 只由 NtQueueApcThreadEx 传入；其它 APC 接口保持零，不解引用参数。
    ApiApcObservation(HANDLE thread, std::uint64_t routine, std::uint64_t argument1,
        std::uint64_t argument2 = 0, std::uint64_t argument3 = 0,
        std::uint64_t reserveHandle = 0, std::optional<std::uint32_t> queueFlags = std::nullopt) noexcept;
    void MarkEntry() noexcept; // 记录原 API 进入时点，保留 LastError。
    void MarkReturn() noexcept; // 记录原 API 返回时点，保留 LastError。
    void Complete() noexcept; // 复核目标身份并转换为独立 AAAP1 字段。
    // fields：提供本次调用的只读协议字段，不推断入队是否成功或例程是否执行。
    const Ksword::Evidence::ApiApcFieldsV1& fields() const noexcept
    {
        return fields_;
    }
private:
    // CopyIdentity：把已采到的身份与时点投影到协议字段；构造及调用后复核共用，不额外查询。
    void CopyIdentity() noexcept;
    ApiThreadTargetObservation identity_; // 共用的线程/所属进程代次采集器。
    Ksword::Evidence::ApiApcFieldsV1 fields_{}; // 当前 APC 请求的独立协议字段。
};
}
