// ApiTransferValidationHelper.cpp
// 生产 helper 负测：直接编译正式源文件 APIMonitor_x64/hook/ApiInjectionObservation.cpp，
// 验证正式采集类在 null/不可读输出、失败返回、LastError 与 QPC 顺序下的安全性。
// 该测试不经过 Hook 引擎与管道，与正式 Agent 实测分开报告，不互相替代。

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "hook/ApiInjectionObservation.h"

using Ksword::Evidence::ApiInjectionFieldsV1;
using Ksword::Evidence::ApiInjectionOperation;
using apimon::ApiInjectionObservation;

namespace
{
    int g_passed = 0;
    int g_failed = 0;

    void Check(bool condition, const char* name)
    {
        if (condition) { ++g_passed; printf("PASS %s\n", name); }
        else { ++g_failed; printf("FAIL %s\n", name); }
    }

    ApiInjectionFieldsV1 MakeWriteObservation(HANDLE target)
    {
        ApiInjectionObservation observation(ApiInjectionOperation::MemoryWrite,
            target, 0x12345678ull, 4096);
        observation.MarkEntry();
        observation.MarkReturn();
        return observation.fields();
    }

    ApiInjectionFieldsV1 RunCompleteWrite(HANDLE target, bool success, const SIZE_T* out)
    {
        ApiInjectionObservation observation(ApiInjectionOperation::MemoryWrite,
            target, 0x12345678ull, 4096);
        observation.MarkEntry();
        observation.MarkReturn();
        observation.CompleteWrite(success, out);
        return observation.fields();
    }

    ApiInjectionFieldsV1 RunCompleteThreadOutput(HANDLE target, bool success, const HANDLE* out)
    {
        ApiInjectionObservation observation(ApiInjectionOperation::ThreadCreate,
            target, 0xabcdef00ull, 0);
        observation.MarkEntry();
        observation.MarkReturn();
        observation.CompleteThreadOutput(success, out);
        return observation.fields();
    }
}

int wmain()
{
    // 1) LastError 与 QPC 顺序：观察过程不得改变调用方可见 LastError。
    {
        ::SetLastError(0x1234);
        ApiInjectionObservation observation(ApiInjectionOperation::MemoryWrite,
            ::GetCurrentProcess(), 0x1000, 64);
        observation.MarkEntry();
        observation.MarkReturn();
        SIZE_T written = 32;
        observation.CompleteWrite(true, &written);
        const DWORD lastError = ::GetLastError();
        Check(lastError == 0x1234, "last_error_preserved");
        const auto& fields = observation.fields();
        Check(fields.enterQpc > 0 && fields.returnQpc >= fields.enterQpc, "qpc_order");
        Check((fields.flags & Ksword::Evidence::ApiInjectionCompletedLength) != 0
            && fields.completedBytes == 32, "write_completed_value");
        Check((fields.flags & Ksword::Evidence::ApiInjectionActorIdentity) != 0
            && fields.actorCreationFileTime != 0, "actor_identity_pseudo_handle");
    }

    // 2) null 输出：成功调用无长度标志、不解引用。
    {
        const auto fields = RunCompleteWrite(::GetCurrentProcess(), true, nullptr);
        Check((fields.flags & Ksword::Evidence::ApiInjectionCompletedLength) == 0, "null_output_no_flag");
        Check(fields.completedBytes == 0, "null_output_no_value");
    }

    // 3) 失败调用不解引用输出指针。
    {
        SIZE_T written = 0xAAAA;
        const auto fields = RunCompleteWrite(::GetCurrentProcess(), false, &written);
        Check((fields.flags & Ksword::Evidence::ApiInjectionCompletedLength) == 0, "failed_call_no_deref");
    }

    // 4) 成功但不可读输出：SEH 捕获，不崩溃、不设置标志（正式 Agent 管道中无法稳定
    //    构造“成功且输出不可读”的真实调用，故此负测在生产 helper 层面验证）。
    {
        LPVOID guard = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        Check(guard != nullptr, "guard_page_allocated");
        if (guard)
        {
            const auto fields = RunCompleteWrite(::GetCurrentProcess(), true,
                static_cast<const SIZE_T*>(guard));
            Check((fields.flags & Ksword::Evidence::ApiInjectionCompletedLength) == 0,
                "unreadable_output_survives");
            ::VirtualFree(guard, 0, MEM_RELEASE);
        }
    }

    // 5) 线程输出：null / 失败 / 不可读均不解引用；无效句柄不产生身份。
    {
        const auto nullFields = RunCompleteThreadOutput(::GetCurrentProcess(), true, nullptr);
        Check((nullFields.flags & Ksword::Evidence::ApiInjectionThreadIdentity) == 0,
            "thread_null_output_no_flag");

        HANDLE bogus = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x1));
        const auto failedFields = RunCompleteThreadOutput(::GetCurrentProcess(), false, &bogus);
        Check((failedFields.flags & Ksword::Evidence::ApiInjectionThreadIdentity) == 0,
            "thread_failed_no_deref");

        LPVOID guard = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        if (guard)
        {
            const auto unreadable = RunCompleteThreadOutput(::GetCurrentProcess(), true,
                static_cast<const HANDLE*>(guard));
            Check((unreadable.flags & Ksword::Evidence::ApiInjectionThreadIdentity) == 0,
                "thread_unreadable_output_survives");
            ::VirtualFree(guard, 0, MEM_RELEASE);
        }

        const auto invalid = RunCompleteThreadOutput(::GetCurrentProcess(), true, &bogus);
        Check((invalid.flags & Ksword::Evidence::ApiInjectionThreadIdentity) == 0
            && invalid.targetTid == 0, "thread_invalid_handle_no_identity");
    }

    // 6) 无效目标句柄：不产生目标身份、Stable 与完成长度。
    //    注意 INVALID_HANDLE_VALUE == (HANDLE)-1 是当前进程伪句柄，会被真实解析；
    //    这里使用非伪句柄的无效值验证"查询失败保留未知"语义。
    {
        constexpr std::uintptr_t kBogusProcessHandleValue = 0x1234;
        const HANDLE bogusProcess = reinterpret_cast<HANDLE>(kBogusProcessHandleValue);
        const auto fields = RunCompleteWrite(bogusProcess, true, nullptr);
        Check((fields.flags & (Ksword::Evidence::ApiInjectionTargetIdentity
            | Ksword::Evidence::ApiInjectionTargetStable
            | Ksword::Evidence::ApiInjectionCompletedLength)) == 0,
            "invalid_handle_no_identity");
        Check(fields.inputHandle == kBogusProcessHandleValue,
            "input_handle_recorded");
        Check(fields.address == 0x12345678ull && fields.requestedBytes == 4096
            && (fields.flags & Ksword::Evidence::ApiInjectionAddress) != 0,
            "address_and_request_recorded");
    }

    // 7) 结构字段编码往返与拒绝语义（共享只读契约）。
    {
        namespace evidence = Ksword::Evidence;
        ks::winapi_monitor::ApiMonitorEventPacket packet{};
        // 真实生产包只在 hasReturnValue && ApiCall 时承载注入字段，此时
        // snapshotIndex 恒为 kApiCallReturnValueMarker；解码端同样强制该前提。
        packet.snapshotIndex = ks::winapi_monitor::kApiCallReturnValueMarker;
        ApiInjectionFieldsV1 fields{};
        fields.operation = ApiInjectionOperation::ThreadCreate;
        fields.flags = evidence::ApiInjectionActorIdentity | evidence::ApiInjectionThreadIdentity
            | evidence::ApiInjectionStartAddress | evidence::ApiInjectionTargetStable;
        fields.actorCreationFileTime = 0x01D5ABCDEF123456ull;
        fields.targetPid = 4242;
        fields.targetCreationFileTime = 0x01D5FEDCBA987654ull;
        fields.targetTid = 8080;
        fields.targetThreadCreationFileTime = 0x01D5112233445566ull;
        fields.startAddress = 0x7FF600001234ull;
        fields.enterQpc = 100;
        fields.returnQpc = 200;
        fields.inputHandle = 0xABC;

        evidence::StoreApiInjectionFields(packet, fields);
        auto decoded = evidence::ReadApiInjectionFields(packet);
        Check(decoded.has_value(), "roundtrip_decodes");
        if (decoded)
        {
            const auto& value = *decoded;
            Check(value.operation == fields.operation
                && value.flags == fields.flags
                && value.actorCreationFileTime == fields.actorCreationFileTime
                && value.targetPid == fields.targetPid
                && value.targetCreationFileTime == fields.targetCreationFileTime
                && value.targetTid == fields.targetTid
                && value.targetThreadCreationFileTime == fields.targetThreadCreationFileTime
                && value.startAddress == fields.startAddress
                && value.enterQpc == fields.enterQpc
                && value.returnQpc == fields.returnQpc
                && value.inputHandle == fields.inputHandle,
                "roundtrip_fields_equal");
        }

        // 截断文本不能变成结构化证据。
        ks::winapi_monitor::ApiMonitorEventPacket truncated = packet;
        truncated.detailText[evidence::kApiInjectionTextLength - 1] = L'\0';
        Check(!evidence::ReadApiInjectionFields(truncated).has_value(), "truncated_rejected");

        // 错误标记、非规范十六进制、超范围 flags 均拒绝。
        ks::winapi_monitor::ApiMonitorEventPacket wrongMarker = packet;
        wrongMarker.coverageState = 0;
        Check(!evidence::ReadApiInjectionFields(wrongMarker).has_value(), "marker_required");

        ks::winapi_monitor::ApiMonitorEventPacket upperCase = packet;
        upperCase.detailText[evidence::kApiInjectionFieldsPrefix.size()] = L'A';
        Check(!evidence::ReadApiInjectionFields(upperCase).has_value(), "canonical_hex_required");

        ks::winapi_monitor::ApiMonitorEventPacket wideFlags = packet;
        wideFlags.detailText[evidence::kApiInjectionFieldsPrefix.size() + 16 + 1] = L'8';
        Check(!evidence::ReadApiInjectionFields(wideFlags).has_value(), "flags_range_rejected");

        // 11 项核对路径：四种 API 的成功/失败/部分/未知基线。
        auto makePacket = [](const wchar_t* module, const wchar_t* api, std::uint32_t category,
            std::int32_t code, std::uint64_t returnBits, const ApiInjectionFieldsV1& value) {
                ks::winapi_monitor::ApiMonitorEventPacket item{};
                item.size = sizeof(item);
                item.version = ks::winapi_monitor::kProtocolVersion;
                item.eventKind = static_cast<std::uint32_t>(ks::winapi_monitor::EventKind::ApiCall);
                item.hookKind = static_cast<std::uint32_t>(ks::winapi_monitor::HookKind::Strong);
                item.resultKind = static_cast<std::uint32_t>(ks::winapi_monitor::EventResultKind::StatusCode);
                item.snapshotIndex = ks::winapi_monitor::kApiCallReturnValueMarker;
                item.category = category;
                item.resultCode = code;
                item.hookAddress = returnBits;
                wcscpy_s(item.moduleName, module);
                wcscpy_s(item.apiName, api);
                evidence::StoreApiInjectionFields(item, value);
                return item;
            };

        ApiInjectionFieldsV1 writeFields{};
        writeFields.operation = ApiInjectionOperation::MemoryWrite;
        writeFields.requestedBytes = 100;
        writeFields.completedBytes = 100;
        writeFields.flags = evidence::ApiInjectionCompletedLength;

        auto writePacket = makePacket(L"KernelBase", L"WriteProcessMemory", 8, 0, 1, writeFields);
        Check(evidence::ApiInjectionCallOutcome(writePacket, writeFields)
            == evidence::ApiInjectionOutcome::Succeeded, "wpm_success");

        ApiInjectionFieldsV1 failedFields{};
        failedFields.operation = ApiInjectionOperation::MemoryWrite;
        failedFields.requestedBytes = 100;
        auto failedPacket = makePacket(L"KernelBase", L"WriteProcessMemory", 8, 5, 0, failedFields);
        Check(evidence::ApiInjectionCallOutcome(failedPacket, failedFields)
            == evidence::ApiInjectionOutcome::Failed, "wpm_failure");

        ApiInjectionFieldsV1 partialFields{};
        partialFields.operation = ApiInjectionOperation::MemoryWrite;
        partialFields.requestedBytes = 100;
        partialFields.completedBytes = 40;
        partialFields.flags = evidence::ApiInjectionCompletedLength;
        // 解码端要求 enterQpc 非零且 returnQpc >= enterQpc；真实包同样满足。
        partialFields.enterQpc = 100;
        partialFields.returnQpc = 200;
        auto partialPacket = makePacket(L"KernelBase", L"WriteProcessMemory", 8, 0, 1, partialFields);
        Check(evidence::ApiInjectionCallOutcome(partialPacket, partialFields)
            == evidence::ApiInjectionOutcome::Partial, "wpm_success_partial");

        auto failedPartial = makePacket(L"KernelBase", L"WriteProcessMemory", 8, 299, 0, partialFields);
        Check(evidence::ApiInjectionCallOutcome(failedPartial, partialFields)
            == evidence::ApiInjectionOutcome::Partial, "wpm_failed_completed_partial");

        // completed > requested 的文本由解码端接受为字段，但产出核对拒绝为 Unknown：
        // ApiInjectionCallOutcome 使用调用方传入的 fields，因此必须先解码再核对。
        auto overflow = makePacket(L"KernelBase", L"WriteProcessMemory", 8, 0, 1, partialFields);
        overflow.detailText[evidence::kApiInjectionFieldsPrefix.size() + 9 * 17] = L'8'; // completed > requested。
        auto overflowFields = evidence::ReadApiInjectionFields(overflow);
        Check(overflowFields.has_value(), "overflow_text_decodes");
        if (overflowFields)
        {
            Check(evidence::ApiInjectionCallOutcome(overflow, *overflowFields)
                == evidence::ApiInjectionOutcome::Unknown, "overflow_rejected_unknown");
        }

        ApiInjectionFieldsV1 ntFields{};
        ntFields.operation = ApiInjectionOperation::MemoryWrite;
        ntFields.requestedBytes = 8192;
        ntFields.completedBytes = 4096;
        ntFields.flags = evidence::ApiInjectionCompletedLength;
        auto ntPartial = makePacket(L"ntdll", L"NtWriteVirtualMemory", 8,
            static_cast<std::int32_t>(0x8000000Dull), 0x8000000Dull, ntFields);
        Check(evidence::ApiInjectionCallOutcome(ntPartial, ntFields)
            == evidence::ApiInjectionOutcome::Partial, "ntwvm_partial_copy");

        auto mismatch = makePacket(L"ntdll", L"NtWriteVirtualMemory", 8, -1, 1, ntFields);
        Check(evidence::ApiInjectionCallOutcome(mismatch, ntFields)
            == evidence::ApiInjectionOutcome::Unknown, "ntwvm_status_return_mismatch");

        ApiInjectionFieldsV1 threadFields{};
        threadFields.operation = ApiInjectionOperation::ThreadCreate;
        // NTSTATUS API 的返回位必须与 resultCode 相同，不一致时产品端保留 Unknown。
        auto threadOk = makePacket(L"ntdll", L"NtCreateThreadEx", 9, 0, 0, threadFields);
        Check(evidence::ApiInjectionCallOutcome(threadOk, threadFields)
            == evidence::ApiInjectionOutcome::Succeeded, "ntcte_success");

        auto crtFail = makePacket(L"KernelBase", L"CreateRemoteThread", 9, 6, 0, threadFields);
        Check(evidence::ApiInjectionCallOutcome(crtFail, threadFields)
            == evidence::ApiInjectionOutcome::Failed, "crt_failure");

        auto unknownApi = makePacket(L"KernelBase", L"VirtualAllocEx", 8, 0, 1, writeFields);
        Check(evidence::ApiInjectionCallOutcome(unknownApi, writeFields)
            == evidence::ApiInjectionOutcome::Unknown, "other_api_unknown");

        auto unknownResultKind = makePacket(L"ntdll", L"NtWriteVirtualMemory", 8, 0, 1, writeFields);
        unknownResultKind.resultKind = static_cast<std::uint32_t>(
            ks::winapi_monitor::EventResultKind::EntryOnly);
        Check(evidence::ApiInjectionCallOutcome(unknownResultKind, writeFields)
            == evidence::ApiInjectionOutcome::Unknown, "entry_only_unknown");
    }

    // 8) 文本长度契约。
    Check(Ksword::Evidence::kApiInjectionTextLength == 6 + 14 * 16 + 13,
        "text_length_contract");

    printf("SUMMARY passed=%d failed=%d\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
