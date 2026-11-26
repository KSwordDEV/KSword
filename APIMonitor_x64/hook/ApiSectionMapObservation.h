#pragma once
#include <Windows.h>
#include "../../shared/evidence/ApiSectionMapFields.h"

namespace apimon {
// ApiSectionMapObservation：采集节映射请求及成功输出，不推断写入、别名传播或执行。
class ApiSectionMapObservation {
public:
    // section/process 为原句柄；base/size/offset 是原请求地址；protection 为请求保护值。
    ApiSectionMapObservation(HANDLE section, HANDLE process, PVOID const* base,
        const SIZE_T* size, const LARGE_INTEGER* offset, ULONG protection) noexcept;
    void MarkEntry() noexcept; // 记录原 API 进入时点，保留 LastError。
    void MarkReturn() noexcept; // 记录原 API 返回时点，保留 LastError。
    // Complete：复核进程身份，仅 success 时分别安全读回 base/size 输出。
    void Complete(bool success, PVOID const* base, const SIZE_T* size) noexcept;
    // fields：返回本次映射的只读协议字段，不转移任何句柄所有权。
    const Ksword::Evidence::ApiSectionMapFieldsV1& fields() const noexcept
    {
        return fields_;
    }
private:
    HANDLE process_ = nullptr; // 借用的原目标进程句柄，用于前后代次核对。
    Ksword::Evidence::ApiSectionMapFieldsV1 fields_{}; // 本次映射请求、输出和有效位。
};
}
