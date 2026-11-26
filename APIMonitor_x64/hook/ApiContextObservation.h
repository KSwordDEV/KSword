#pragma once
#include "../../shared/evidence/ApiContextFields.h"
#include "ApiThreadTargetObservation.h"

namespace apimon {
// ApiContextObservation：记录原生 CONTEXT 请求，不把请求寄存器解释成实际执行。
class ApiContextObservation {
public:
    // thread 为借用的原线程句柄，context 为原请求地址；读取失败时保留未知。
    ApiContextObservation(HANDLE thread, const CONTEXT* context) noexcept;
    // MarkEntry：记录原调用前时点并保留 LastError。
    void MarkEntry() noexcept
    {
        identity_.MarkEntry();
    }
    // MarkReturn：记录原调用返回时点并保留 LastError。
    void MarkReturn() noexcept
    {
        identity_.MarkReturn();
    }
    // Complete：复核线程身份，再投影到独立上下文协议。
    void Complete() noexcept;
    // fields：返回只读请求字段，原 API 成败仍由包中原返回表达。
    const Ksword::Evidence::ApiContextFieldsV1& fields() const noexcept
    {
        return fields_;
    }
private:
    ApiThreadTargetObservation identity_; // 共用线程及所属进程身份采集器。
    Ksword::Evidence::ApiContextFieldsV1 fields_{}; // 本次上下文请求的字段和有效位。
};
}
