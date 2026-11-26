#pragma once

#include "../../shared/evidence/ApiInjectionFields.h"

namespace apimon
{
    // ApiInjectionObservation：所有方法在 ScopedHookGuard 内执行，仅查询调用方原句柄。
    // 不另开目标句柄，不替换原参数，不改变既有 AAIP1 字段和操作语义。
    class ApiInjectionObservation
    {
    public:
        // operation 为写入/创建线程；process 为原进程句柄；address/requestedBytes 为原请求。
        ApiInjectionObservation(Ksword::Evidence::ApiInjectionOperation operation,
            HANDLE process, std::uint64_t address, std::uint64_t requestedBytes) noexcept;
        void MarkEntry() noexcept; // 记录原调用前的 QPC，保留 LastError。
        void MarkReturn() noexcept; // 记录原调用返回的 QPC，保留 LastError。
        // success 为原调用成功判定；仅成功后安全读取 completedBytes 实际写入长度。
        void CompleteWrite(bool success, const SIZE_T* completedBytes) noexcept;
        // success 为原调用成功判定；thread 为原返回句柄，仅读取线程身份。
        void CompleteThread(bool success, HANDLE thread) noexcept;
        // success 为 NT 原调用成功判定；thread 为返回句柄地址，仅成功后安全解引用。
        void CompleteThreadOutput(bool success, const HANDLE* thread) noexcept;
        // fields：提供当前调用的只读 AAIP1 字段，不转移任何资源所有权。
        const Ksword::Evidence::ApiInjectionFieldsV1& fields() const noexcept
        {
            return fields_;
        }

    private:
        void RecheckTarget() noexcept; // 原调用返回后核对目标进程创建代次。
        HANDLE process_ = nullptr; // 借用的原输入进程句柄。
        Ksword::Evidence::ApiInjectionFieldsV1 fields_{}; // 当前调用的身份、范围与计时结果。
    };
}
