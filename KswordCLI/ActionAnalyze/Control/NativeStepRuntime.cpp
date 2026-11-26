#include "NativeStepRuntime.h"
#include "NativePrivateExecutionPage.h"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace ks::cli::action_analyze::control {
namespace {
constexpr DWORD kTf = 0x100;
constexpr DWORD64 kSlot1Control = 0x00f0000c;
constexpr DWORD64 kSlot1Enable = 4;
constexpr DWORD64 kReasons = 0xe00f;
constexpr DWORD64 kBs = 0x4000;
constexpr DWORD64 kDr0 = 1;
NativeStepError Error(const char* stage) {
    const auto error = GetLastError();
    return {stage, error ? error : ERROR_GEN_FAILURE};
}
std::uint64_t Ip(const CONTEXT& context) {
#if defined(_M_X64)
    return context.Rip;
#else
    return context.Eip;
#endif
}
std::uint64_t Sp(const CONTEXT& context) {
#if defined(_M_X64)
    return context.Rsp;
#else
    return context.Esp;
#endif
}
std::uint64_t Time(FILETIME value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

// 有界AMD64长度解码结果只用于取指和CALL返回边界；完成仍由实际TF/DR事件确认。
struct Instruction { std::size_t size = 0; bool call = false; bool ret = false; };

// 页尾取指使用有界长度解码。未列入的编码返回未知，不以最长15字节冒充实际指令。
// 此处只确定opcode/ModRM/SIB/位移/立即数边界；运行完成仍必须由真实BS证明。
Instruction DecodeFetch(const std::uint8_t* bytes, std::size_t count) {
    count = (std::min)(count, std::size_t{15});
    std::size_t offset = 0;
    bool operand16 = false, address32 = false, rexW = false, rex = false;
    while (offset < count) {
        const auto prefix = bytes[offset];
        if (prefix >= 0x40 && prefix <= 0x4f) { rex = true; rexW = (prefix & 8) != 0; }
        else if (prefix == 0x66 || prefix == 0x67 || prefix == 0xf0 || prefix == 0xf2 || prefix == 0xf3 ||
            prefix == 0x26 || prefix == 0x2e || prefix == 0x36 || prefix == 0x3e || prefix == 0x64 || prefix == 0x65) {
            operand16 = operand16 || prefix == 0x66;
            address32 = address32 || prefix == 0x67;
            rex = rexW = false; // legacy前缀后的REX才有效。
        } else break;
        ++offset;
    }
    if (offset >= count) return {};
    auto opcode = bytes[offset++];
    unsigned map = 0;
    bool vector = false;
    if (opcode == 0xc5) {
        if (rex || offset + 1 >= count) return {};
        ++offset; map = 1; vector = true; opcode = bytes[offset++];
    } else if (opcode == 0xc4 || opcode == 0x62) {
        const bool evex = opcode == 0x62;
        if (rex || offset + (evex ? 3 : 2) >= count) return {};
        const auto first = bytes[offset];
        map = first & (evex ? 7 : 31);
        if (!map || map > 3 || (evex && ((first & 8) || !(bytes[offset + 1] & 4)))) return {};
        offset += evex ? 3 : 2; vector = true; opcode = bytes[offset++];
    } else if (opcode == 0x0f) {
        if (offset >= count) return {};
        map = 1; opcode = bytes[offset++];
        if (opcode == 0x38 || opcode == 0x3a) {
            map = opcode == 0x38 ? 2 : 3;
            if (offset >= count) return {};
            opcode = bytes[offset++];
        }
    }
    std::size_t immediate = 0;
    bool modrm = false, call = false, ret = false;
    const auto operandBytes = operand16 && !rexW ? std::size_t{2} : std::size_t{4};
    if (!map) {
        if (opcode <= 0x3d && (opcode & 7) <= 5) {
            const auto form = opcode & 7;
            modrm = form <= 3;
            immediate = form == 4 ? 1 : form == 5 ? operandBytes : 0;
        } else if ((opcode >= 0x50 && opcode <= 0x5f) || (opcode >= 0x90 && opcode <= 0x9c) ||
            (opcode >= 0xa4 && opcode <= 0xa7) || (opcode >= 0xaa && opcode <= 0xaf) ||
            opcode == 0xc9 || opcode == 0xcc || opcode == 0xf5 || (opcode >= 0xf8 && opcode <= 0xfd)) {
            // 单字节/前缀指令，无额外编码字节。
        } else if (opcode >= 0x70 && opcode <= 0x7f) immediate = 1;
        else if (opcode >= 0xb0 && opcode <= 0xbf) immediate = opcode < 0xb8 ? 1 : rexW ? 8 : operandBytes;
        else if (opcode >= 0xa0 && opcode <= 0xa3) immediate = address32 ? 4 : 8;
        else switch (opcode) {
        case 0x63: case 0x84: case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
        case 0x8a: case 0x8b: case 0x8c: case 0x8d: case 0x8e: case 0x8f: case 0xfe: case 0xff:
        case 0xf6: case 0xf7: modrm = true; break;
        case 0x69: case 0x81: case 0xc7: modrm = true; immediate = operandBytes; break;
        case 0x6b: case 0x80: case 0x83: case 0xc0: case 0xc1: case 0xc6: modrm = true; immediate = 1; break;
        case 0xd0: case 0xd1: case 0xd2: case 0xd3:
        case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd: case 0xde: case 0xdf: modrm = true; break;
        case 0x68: case 0xa9: immediate = operand16 ? 2 : 4; break;
        case 0x6a: case 0xa8: case 0xcd: case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xeb: immediate = 1; break;
        case 0xc2: immediate = 2; ret = true; break;
        case 0xc3: ret = true; break;
        case 0xc8: immediate = 3; break;
        case 0xe8: call = true; [[fallthrough]];
        case 0xe9: immediate = 4; break;
        default: return {}; // POPF/IRET/SS及特权转换仍不在可推进范围。
        }
    } else if (map == 1) {
        if (!vector && opcode >= 0x80 && opcode <= 0x8f) immediate = 4;
        else if (opcode == 0x77 || (!vector && (opcode == 0x31 || opcode == 0xa2 || opcode == 0xc8 ||
            (opcode >= 0xc9 && opcode <= 0xcf) || opcode == 0xa0 || opcode == 0xa1 || opcode == 0xa8 || opcode == 0xa9))) {
        } else if ((opcode >= 0x10 && opcode <= 0x1f) || (opcode >= 0x28 && opcode <= 0x2f) ||
            (opcode >= 0x40 && opcode <= 0x76) || (opcode >= 0x78 && opcode <= 0x7f) ||
            (!vector && opcode >= 0x90 && opcode <= 0x9f) || opcode == 0xa3 || opcode == 0xa4 || opcode == 0xa5 ||
            opcode == 0xab || opcode == 0xac || opcode == 0xad || opcode == 0xae || opcode == 0xaf ||
            opcode == 0xb0 || opcode == 0xb1 || (opcode >= 0xb3 && opcode <= 0xbf) || opcode == 0xc0 || opcode == 0xc1 ||
            opcode == 0xc2 || opcode == 0xc3 || opcode == 0xc4 || opcode == 0xc5 || opcode == 0xc6 || opcode == 0xc7 || opcode >= 0xd0) {
            // 双立即数的EXTRQ/INSERTQ编码不共用普通ModRM长度规则。
            if (opcode == 0x78 || opcode == 0x79) return {};
            modrm = true;
            if (opcode == 0x70 || opcode == 0x71 || opcode == 0x72 || opcode == 0x73 || opcode == 0xa4 ||
                opcode == 0xac || opcode == 0xba || opcode == 0xc2 || opcode == 0xc4 || opcode == 0xc5 || opcode == 0xc6) immediate = 1;
        } else return {};
    } else if (map == 2) {
        if (!(opcode <= 0x0b || (opcode >= 0x10 && opcode <= 0x17) || (opcode >= 0x1c && opcode <= 0x25) ||
            (opcode >= 0x28 && opcode <= 0x41) || (opcode >= 0x58 && opcode <= 0x5f) ||
            (opcode >= 0x78 && opcode <= 0x7f) || (opcode >= 0x90 && opcode <= 0xbf) ||
            (opcode >= 0xdb && opcode <= 0xdf) || (opcode >= 0xf0 && opcode <= 0xf7))) return {};
        modrm = true;
    } else {
        if (!(opcode <= 0x0f || (opcode >= 0x14 && opcode <= 0x22) || (opcode >= 0x38 && opcode <= 0x42) ||
            (opcode >= 0x44 && opcode <= 0x46) || (opcode >= 0x60 && opcode <= 0x63) || opcode == 0xcc || opcode == 0xdf || opcode == 0xf0)) return {};
        modrm = true; immediate = 1;
    }
    if (modrm) {
        if (offset >= count) return {};
        const auto value = bytes[offset++];
        const auto mod = value >> 6, group = (value >> 3) & 7, rm = value & 7;
        if (!map && ((opcode == 0x8e && group == 2) || (opcode == 0xff && (group == 3 || group == 5 || group == 7)) ||
            ((opcode == 0xc6 || opcode == 0xc7 || opcode == 0x8f) && group != 0))) return {};
        if (!map && opcode == 0xff && group == 2) call = true;
        if (!map && (opcode == 0xf6 || opcode == 0xf7) && group <= 1) immediate = opcode == 0xf6 ? 1 : operandBytes;
        std::size_t displacement = mod == 1 ? 1 : mod == 2 ? 4 : 0;
        if (mod != 3 && rm == 4) {
            if (offset >= count) return {};
            if ((bytes[offset++] & 7) == 5 && mod == 0) displacement = 4;
        } else if (mod == 0 && rm == 5) displacement = 4;
        offset += displacement;
    }
    const auto length = offset + immediate;
    return length <= count && length <= 15 ? Instruction{length, call && !operand16, ret && !operand16 && opcode == 0xc3} : Instruction{};
}
}

NativeStepRuntime::~NativeStepRuntime() {
    // The owner does not retire while HasResources() is true. Never silently
    // resume debts here: destructor has no independently verified stopped event.
    if (selected_) CloseHandle(selected_);
    for (const auto& peer : peers_) CloseHandle(peer.thread);
}

bool NativeStepRuntime::HasResources() const noexcept {
    return contextOwned_ || selectedSuspendDebt_ ||
        std::any_of(peers_.begin(), peers_.end(), [](const auto& hold) { return hold.debt; });
}

NativeStepError NativeStepRuntime::Read(std::uint64_t address, void* bytes, std::size_t count) const {
    SIZE_T read = 0;
    if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)), bytes, count, &read))
        return Error("step-read-memory");
    return read == count ? NativeStepError{} : NativeStepError{"step-short-read", ERROR_PARTIAL_COPY};
}

NativeStepError NativeStepRuntime::DecodeInstructionFetch(HANDLE process, std::uint64_t rip, NativeInstructionFetch& fetch) {
    fetch = {}; fetch.address = rip;
    for (std::size_t count = 1; count <= fetch.bytes.size(); ++count) {
        if (!rip || rip > (std::numeric_limits<std::uintptr_t>::max)() - (count - 1))
            return {"page-instruction-address-overflow", ERROR_INVALID_ADDRESS};
        if (count == 1 || ((rip + count - 1) & 4095) == 0) {
            MEMORY_BASIC_INFORMATION mapping{};
            if (VirtualQueryEx(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(rip + count - 1)),
                &mapping, sizeof(mapping)) != sizeof(mapping)) return Error("page-query-instruction-mapping");
            if (mapping.State != MEM_COMMIT || (mapping.Protect & PAGE_GUARD) || (mapping.Protect & 0xff) == PAGE_NOACCESS)
                return {"page-instruction-mapping-unreadable", ERROR_NOACCESS};
        }
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(rip + count - 1)),
            &fetch.bytes[count - 1], 1, &read)) return Error("page-read-instruction-byte");
        if (read != 1) return {"page-read-instruction-byte", ERROR_PARTIAL_COPY};
        const auto decoded = DecodeFetch(fetch.bytes.data(), count);
        if (decoded.size) { fetch.length = decoded.size; return {}; }
    }
    return {"page-instruction-length-unsupported", ERROR_NOT_SUPPORTED};
}

NativeStepError NativeStepRuntime::Executable(std::uint64_t address) const {
    if (executionRange_ && executionRange_->Contains(address)) {
        const auto error = executionRange_->Verify(process_);
        return error ? NativeStepError{"step-frozen-execution-range-changed", error} : NativeStepError{};
    }
    MEMORY_BASIC_INFORMATION region{};
    if (!address || VirtualQueryEx(process_, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
        &region, sizeof(region)) != sizeof(region)) return Error("step-query-destination");
    const auto protect = region.Protect & 0xff;
    if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) ||
        (protect != PAGE_EXECUTE && protect != PAGE_EXECUTE_READ && protect != PAGE_EXECUTE_READWRITE &&
            protect != PAGE_EXECUTE_WRITECOPY)) return {"step-destination-not-executable", ERROR_NOT_SUPPORTED};
    std::uint8_t byte = 0;
    if (const auto error = Read(address, &byte, 1); error) return error;
    return byte == 0xcc ? NativeStepError{"step-user-int3-conflict", ERROR_BUSY} : NativeStepError{};
}

NativeStepError NativeStepRuntime::CheckPageTrapInstruction(std::uint64_t address) const {
    // 普通步进与NX推进共用：排除已知会抑制/改写TF或跨特权交付的入口，不预测下一IP。
    // 长度由DecodeFetch单独核验；普通内存、SSE/AVX、跳转、near CALL/RET按实际BS完成。
    std::uint8_t op = 0;
    std::size_t offset = 0;
    bool repeat = false; // REP字符串的一次BS可能只完成一轮，不能发布整条instruction-completed。
    for (; offset < 15; ++offset) {
        if (address > (std::numeric_limits<std::uint64_t>::max)() - offset)
            return {"page-trap-opcode-address-overflow", ERROR_INVALID_ADDRESS};
        if (const auto error = Read(address + offset, &op, 1); error) return error;
        repeat = repeat || op == 0xf2 || op == 0xf3;
        if ((op >= 0x40 && op <= 0x4f) || op == 0x66 || op == 0x67 || op == 0xf0 || op == 0xf2 || op == 0xf3 ||
            op == 0x26 || op == 0x2e || op == 0x36 || op == 0x3e || op == 0x64 || op == 0x65) continue;
        break;
    }
    if (offset == 15) return {"page-trap-opcode-prefix-limit", ERROR_NOT_SUPPORTED};
    if (op == 0xcc) return {"step-user-int3-conflict", ERROR_BUSY};
    if (repeat && ((op >= 0xa4 && op <= 0xa7) || (op >= 0xaa && op <= 0xaf)))
        return {"step-repeat-string-completion-unsupported", ERROR_NOT_SUPPORTED};
    if (op == 0x9d || op == 0xcf || op == 0x17 || op == 0xca || op == 0xcb || op == 0x9a || op == 0xea)
        return {"page-trap-tf-control-instruction-unsupported", ERROR_NOT_SUPPORTED};
    if (op == 0x0f || op == 0x8e || op == 0xff) {
        if (address + offset == (std::numeric_limits<std::uint64_t>::max)())
            return {"page-trap-opcode-address-overflow", ERROR_INVALID_ADDRESS};
        std::uint8_t second = 0;
        if (const auto error = Read(address + offset + 1, &second, 1); error) return error;
        if ((op == 0x0f && (second == 0x05 || second == 0x07 || second == 0x34 || second == 0x35 || second == 0xb2)) ||
            (op == 0x8e && (second & 0x38) == 0x10) ||
            (op == 0xff && ((second & 0x38) == 0x18 || (second & 0x38) == 0x28)))
            return {"page-trap-tf-control-instruction-unsupported", ERROR_NOT_SUPPORTED};
    }
    return {};
}

NativeStepError NativeStepRuntime::Destination(const CONTEXT& context, std::optional<std::uint64_t>& destination) {
    const auto ip = Ip(context); // 当前实际停止线程的冻结取指地址。
    NativeInstructionFetch fetched; // 最多读取一条15字节指令，不预读无关下一页。
    const auto* frozen = executionRange_ && executionRange_->Instruction() && executionRange_->Instruction()->address == ip &&
        executionRange_->Instruction()->length ? &*executionRange_->Instruction() : nullptr;
    if (frozen) {
        fetched = *frozen; // NX跨页已经冻结的编码，后续Prepare仍核验同一指令字节。
    } else {
        if (const auto error = DecodeInstructionFetch(process_, ip, fetched); error) return error;
    }
    if (const auto error = CheckPageTrapInstruction(ip); error) return error;
    const auto instruction = DecodeFetch(fetched.bytes.data(), fetched.length); // 普通地址与NX页使用同一长度规则。
    callReturn_.reset();
    if (receipt_.request.mode == NativeStepMode::Out) {
        std::uint64_t returnIp = 0;
        if (const auto error = Read(Sp(context), &returnIp, sizeof(returnIp)); error) return error;
        const bool entryProof = frame_ && frame_->thread == receipt_.request.thread && frame_->ip == ip &&
            frame_->sp == Sp(context) && frame_->returnIp == returnIp;
        if (!instruction.ret && !entryProof) return {"step-out-frame-unproven", ERROR_NOT_SUPPORTED};
        if (Sp(context) > std::numeric_limits<std::uint64_t>::max() - 8) return {"step-stack-overflow", ERROR_INVALID_DATA};
        expectedSp_ = Sp(context) + 8;
        destination = returnIp;
        return Executable(returnIp);
    }
    if (!instruction.size) return {"step-instruction-unsupported", ERROR_NOT_SUPPORTED};
    if (instruction.call) {
        if (ip > std::numeric_limits<std::uint64_t>::max() - instruction.size)
            return {"step-instruction-overflow", ERROR_INVALID_DATA};
        callReturn_ = ip + instruction.size;
    }
    if (receipt_.request.mode == NativeStepMode::OverCall) {
        if (!instruction.call) return {"step-over-requires-call", ERROR_NOT_SUPPORTED};
        destination = callReturn_;
        expectedSp_ = Sp(context);
        return Executable(*destination);
    }
    return {};
}

NativeStepError NativeStepRuntime::ReadThreadIdentity(HANDLE thread, ThreadObjectIdentity& identity)
{
    ThreadObjectIdentity observed; // 先完整读取再发布，失败不覆盖已保存的对象身份。
    observed.processId = GetProcessIdOfThread(thread);
    if (!observed.processId) {
        return Error("step-query-thread-process");
    }
    observed.threadId = GetThreadId(thread);
    if (!observed.threadId) {
        return Error("step-query-thread-id");
    }
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetThreadTimes(thread, &created, &exited, &kernel, &user)) {
        return Error("step-query-thread-times");
    }
    observed.creationTime = Time(created);
    if (!observed.creationTime) {
        return {"step-thread-creation-time-missing", ERROR_INVALID_DATA};
    }
    identity = observed;
    return {};
}

NativeStepError NativeStepRuntime::Enroll(HANDLE thread)
{
    return HoldPeer(thread, false);
}

NativeStepError NativeStepRuntime::EnrollCreated(const DEBUG_EVENT& event)
{
    if (!running_ || event.dwDebugEventCode != CREATE_THREAD_DEBUG_EVENT) {
        return {"step-new-peer-requires-create-event", ERROR_INVALID_STATE};
    }
    ThreadObjectIdentity identity; // 创建事件直接携带的线程句柄必须属于当前进程和当前事件TID。
    if (const auto error = ReadThreadIdentity(event.u.CreateThread.hThread, identity); error) {
        return error;
    }
    if (!process_ || event.dwProcessId != GetProcessId(process_) || event.dwProcessId != identity.processId ||
        event.dwThreadId != identity.threadId) {
        return {"step-create-event-thread-mismatch", ERROR_INVALID_DATA};
    }
    return HoldPeer(event.u.CreateThread.hThread, false);
}

NativeStepError NativeStepRuntime::HoldPeer(HANDLE thread, bool preparing)
{
    ThreadObjectIdentity identity; // 只从调用方持有的强线程对象读取身份，不按TID重开后替换。
    if (const auto error = ReadThreadIdentity(thread, identity); error) {
        return error;
    }
    if (!process_ || identity.processId != GetProcessId(process_)) {
        return {"step-peer-process-mismatch", ERROR_INVALID_DATA};
    }
    if (CompareObjectHandles(thread, selected_)) {
        return identity == selectedIdentity_ ? NativeStepError{} :
            NativeStepError{"step-selected-object-identity-mismatch", ERROR_INVALID_DATA};
    }
    for (const auto& hold : peers_) {
        if (!CompareObjectHandles(hold.thread, thread)) {
            continue;
        }
        if (!(identity == hold.identity)) {
            return {"step-peer-object-identity-mismatch", ERROR_INVALID_DATA};
        }
        if (hold.conflicted) {
            return {"step-suspend-count-conflict", ERROR_INVALID_DATA};
        }
        if (hold.debt) {
            return {}; // 同一强对象只取得一次暂停，重复登记不再增加计数。
        }
        const auto wait = WaitForSingleObject(hold.thread, 0);
        if (wait == WAIT_OBJECT_0) {
            return {}; // 已确认退出的同一对象不产生新债务。
        }
        if (wait != WAIT_TIMEOUT) {
            return Error("step-check-enrolled-thread-lifetime");
        }
        return {"step-peer-hold-not-established", ERROR_INVALID_STATE};
    }
    if (!preparing && !running_) {
        return {"step-new-peer-requires-active-step", ERROR_INVALID_STATE};
    }
    if (peers_.size() >= 1024) {
        return {"step-peer-capacity", ERROR_BUFFER_OVERFLOW};
    }
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return Error("step-hold-peer");
    }
    peers_.push_back({duplicate, false, false, identity});
    const auto previous = SuspendThread(duplicate);
    if (previous == static_cast<DWORD>(-1)) {
        const auto error = Error("step-suspend-peer");
        // 精确句柄刚退出的竞态不产生暂停债；仍存在的线程保留原错误。
        return WaitForSingleObject(duplicate, 0) == WAIT_OBJECT_0 ? NativeStepError{} : error;
    }
    peers_.back().debt = true;
    return {};
}

NativeStepError NativeStepRuntime::RetireExitedThread(const DEBUG_EVENT& event, HANDLE eventThread)
{
    if (event.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT) {
        return {};
    }
    if (!process_ || event.dwProcessId != GetProcessId(process_)) {
        return {"step-exit-event-process-mismatch", ERROR_INVALID_DATA};
    }
    const bool selectedCandidate = selected_ && !selectedExited_ && selectedIdentity_.threadId == event.dwThreadId;
    const bool peerCandidate = std::any_of(peers_.begin(), peers_.end(), [&](const auto& hold) {
        return hold.debt && hold.identity.threadId == event.dwThreadId;
    });
    if (!selectedCandidate && !peerCandidate) {
        return {}; // 与本轮对象无关的退出事件，不触碰任何同伴责任。
    }
    HANDLE resolved = nullptr; // 退出事件没有hThread；仅在原owner仍持有该事件时解析当前对象。
    if (!eventThread) {
        resolved = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, event.dwThreadId);
        if (!resolved) {
            return Error("step-open-exit-event-thread");
        }
        eventThread = resolved;
    }
    ThreadObjectIdentity identity;
    const auto identityError = ReadThreadIdentity(eventThread, identity);
    const bool selectedMatch = selectedCandidate && !identityError && identity == selectedIdentity_ &&
        CompareObjectHandles(selected_, eventThread);
    auto peer = peers_.end();
    if (!identityError) {
        peer = std::find_if(peers_.begin(), peers_.end(), [&](const auto& hold) {
            return identity == hold.identity && CompareObjectHandles(hold.thread, eventThread);
        });
    }
    if (resolved) {
        CloseHandle(resolved);
    }
    if (identityError) {
        return identityError;
    }
    if (identity.processId != event.dwProcessId || identity.threadId != event.dwThreadId ||
        (!selectedMatch && peer == peers_.end())) {
        return {"step-exit-thread-instance-mismatch", ERROR_INVALID_DATA};
    }
    // EXIT_THREAD交付时句柄未必已signaled，精确原生退出事件本身可免除该线程自己的暂停债。
    // 绝不能把selected退出当作整个进程退出，从而清掉其它仍存在线程的计数。
    if (selectedMatch) {
        selectedExited_ = true;
        contextOwned_ = pageTrapOwned_ = false;
        selectedSuspendDebt_ = selectedSuspendConflict_ = false;
    }
    if (peer != peers_.end()) {
        peer->debt = false;
        peer->conflicted = false;
    }
    receipt_.resourcesRestored = !HasResources();
    return {};
}

NativeStepError NativeStepRuntime::Prepare(HANDLE process, HANDLE selected, const NativeStepRequest& request,
    const std::vector<HANDLE>& peers, const NativePrivateExecutionPage* executionRange) {
    return PrepareImpl(process, selected, request, peers, false, executionRange);
}

NativeStepError NativeStepRuntime::PrepareImpl(HANDLE process, HANDLE selected, const NativeStepRequest& request,
    const std::vector<HANDLE>& peers, bool tfOnly, const NativePrivateExecutionPage* executionRange) {
#if !defined(_M_X64)
    (void)process; (void)selected; (void)request; (void)peers; (void)tfOnly; (void)executionRange;
    return {"step-native-amd64-required", ERROR_NOT_SUPPORTED};
#else
    if (running_ || HasResources()) return {"step-already-active", ERROR_BUSY};
    for (const auto& hold : peers_) CloseHandle(hold.thread);
    peers_.clear();
    if (selected_) CloseHandle(std::exchange(selected_, nullptr));
    selectedIdentity_ = {};
    process_ = process;
    executionRange_ = executionRange;
    receipt_ = {};
    receipt_.request = request;
    cancelRequested_ = false;
    timeoutRequested_ = false;
    pageTrapOwned_ = false;
    selectedExited_ = false;
    selectedEventStopped_ = true;
    selectedSuspendDebt_ = false;
    selectedSuspendConflict_ = false;
    eventKind_ = NativeStepEventKind::None;
    observedDr6_ = 0;
    disposition_ = DBG_CONTINUE;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetThreadId(selected) != request.tid || GetProcessIdOfThread(selected) != GetProcessId(process) ||
        !GetThreadTimes(selected, &created, &exited, &kernel, &user) || Time(created) != request.threadCreationTime)
        return {"step-thread-instance-mismatch", ERROR_INVALID_DATA};
    if (!DuplicateHandle(GetCurrentProcess(), selected, GetCurrentProcess(), &selected_, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return Error("step-hold-selected");
    if (const auto error = ReadThreadIdentity(selected_, selectedIdentity_); error) {
        return error;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(selected_, &context)) return Error("step-read-selected-context");
    if (executionRange_ && executionRange_->Instruction()) {
        if (const auto error = executionRange_->VerifyInstruction(process_, Ip(context))) return {"page-step-frozen-instruction-changed", error};
    }
    if ((context.EFlags & kTf) || (context.Dr7 & 0xfc)) return {"step-competing-tf-or-dr", ERROR_BUSY};
    receipt_.startIp = Ip(context);
    receipt_.startSp = Sp(context);
    std::optional<std::uint64_t> destination;
    callReturn_.reset();
    if (!tfOnly) {
        if (const auto error = Destination(context, destination); error) return error;
    } else if (const auto error = CheckPageTrapInstruction(Ip(context)); error) return error;
    // TF-only不预测普通指令；只有同一线程真实BS事件才能结束本次推进。
    receipt_.destination = destination;
    originalDr1_ = context.Dr1;
    originalDr7_ = context.Dr7 & kSlot1Control;
    originalFlags_ = context.EFlags;
    for (const auto peer : peers) {
        if (const auto error = HoldPeer(peer, true); error) {
            return error;
        }
    }
    if (executionRange_ && executionRange_->Instruction()) {
        if (const auto error = executionRange_->VerifyInstruction(process_, Ip(context))) return {"page-step-frozen-instruction-changed", error};
        if (const auto error = CheckPageTrapInstruction(Ip(context)); error) return error;
    }
    if (const auto error = Arm(context, destination); error) return error;
    running_ = true;
    frame_.reset();
    return {};
#endif
}

NativeStepError NativeStepRuntime::PreparePageAdvance(HANDLE process, HANDLE selected, NativeStepRequest request,
    const std::vector<HANDLE>& peers, const NativePrivateExecutionPage* executionRange)
{
    request.mode = NativeStepMode::Into;
    request.release.requestId.clear(); // 内部TF不占用户step流水，也不能产生instruction-completed证据。
    return PrepareImpl(process, selected, request, peers, true, executionRange);
}

NativeStepError NativeStepRuntime::ArmPageTrap()
{
    if (!running_ || !contextOwned_) return {"page-trap-requires-running-step", ERROR_INVALID_STATE};
    if (!receipt_.destination) return {}; // Into已经持有TF，不重复取得责任。
    if (pageTrapOwned_) return {"page-trap-already-owned", ERROR_BUSY};
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(selected_, &context)) return Error("page-trap-read-context");
    if (executionRange_ && executionRange_->Instruction()) {
        if (const auto error = executionRange_->VerifyInstruction(process_, Ip(context))) return {"page-trap-frozen-instruction-changed", error};
    }
    if (context.EFlags & kTf) return {"page-trap-competing-tf", ERROR_BUSY};
    if (const auto error = CheckPageTrapInstruction(Ip(context)); error) return error;
    // 叠加TF按实际BS交付确认，不借旧用户步进白名单预测下一IP；缺事件由owner中止恢复。
    pageTrapOwned_ = true; // 先记账，Set失败也由原Restore清退。
    context.EFlags |= kTf;
    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~kBs);
    if (!SetThreadContext(selected_, &context)) return Error("page-trap-arm-context");
    if (!GetThreadContext(selected_, &context)) return Error("page-trap-read-armed-context");
    return context.EFlags & kTf ? NativeStepError{} : NativeStepError{"page-trap-verify-tf", ERROR_INVALID_DATA};
}

NativeStepError NativeStepRuntime::FinishPageTrap(const DEBUG_EVENT& event, bool& onlyAdvance)
{
    onlyAdvance = false;
    if (!pageTrapOwned_ || event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT ||
        event.dwThreadId != receipt_.request.tid || !event.u.Exception.dwFirstChance ||
        event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP) return {};
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(selected_, &context)) return Error("page-trap-read-stop-context");
    const auto reasons = context.Dr6 & kReasons;
    onlyAdvance = reasons == kBs; // 写回失败时也保留已核实的本端纯BS分派，供Close清退。
    // 非本端单步原因交给原Observe/异常分派，但仍归还本端TF。
    context.EFlags = (context.EFlags & ~kTf) | (originalFlags_ & kTf);
    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~kBs);
    if (!SetThreadContext(selected_, &context)) return Error("page-trap-restore-context");
    if (!GetThreadContext(selected_, &context)) return Error("page-trap-read-restored-context");
    if ((context.EFlags & kTf) != (originalFlags_ & kTf) || (context.Dr6 & kBs))
        return {"page-trap-verify-restored-context", ERROR_INVALID_DATA};
    pageTrapOwned_ = false;
    // B1仍留给用户Over/Out，不能把内部BS当成其完成。
    return {};
}

NativeStepError NativeStepRuntime::Arm(CONTEXT context, std::optional<std::uint64_t> destination) {
    contextOwned_ = true; // write failures retain restoration responsibility
    // Over/Out只拥有DR1；不能因安装执行槽而重写RIP/RSP或其它控制寄存器。
    context.ContextFlags = destination ? CONTEXT_DEBUG_REGISTERS : CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    const auto ownedReason = destination ? DWORD64{2} : kBs; // 本轮只清理自己使用的原因位。
    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~ownedReason);
    if (destination) {
        context.Dr1 = static_cast<decltype(context.Dr1)>(*destination);
        context.Dr7 = static_cast<decltype(context.Dr7)>((context.Dr7 & ~kSlot1Control) | kSlot1Enable);
    } else context.EFlags |= kTf;
    if (!SetThreadContext(selected_, &context)) return Error("step-arm-context");
    if (!GetThreadContext(selected_, &context)) return Error("step-read-armed-context");
    if (destination ? (context.Dr1 != *destination || (context.Dr7 & kSlot1Control) != kSlot1Enable) : !(context.EFlags & kTf))
        return {"step-verify-armed-context", ERROR_INVALID_DATA};
    return {};
}

NativeStepError NativeStepRuntime::ReleaseHold(HANDLE thread, bool& debt, bool& conflicted,
    bool processExited, const char* stage) {
    if (!debt) return {};
    const auto wait = processExited ? WAIT_OBJECT_0 : WaitForSingleObject(thread, 0);
    if (wait == WAIT_OBJECT_0) { debt = false; conflicted = false; return {}; }
    if (wait != WAIT_TIMEOUT) return Error("step-check-held-thread-lifetime");
    if (conflicted) return {"step-suspend-count-conflict", ERROR_INVALID_DATA};
    const auto previous = ResumeThread(thread);
    if (previous == static_cast<DWORD>(-1)) {
        const auto error = Error(stage);
        if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) { debt = false; return {}; }
        return error; // 暂停线程仍存在则债务原样保留，下一次恢复逐项重试。
    }
    if (!previous) {
        conflicted = true; // 未减任何计数，不可清账，也不可重试时误减后来外来暂停。
        return {"step-suspend-count-conflict", ERROR_INVALID_DATA};
    }
    debt = false; // 只移除本端一次增量，原先已暂停的线程仍保留原计数。
    return {};
}

// 输入原线程对象及该对象暂停债；仅已退出时结清，失败写入首个错误，存活对象不放行。
void NativeStepRuntime::DischargeExitedHold(HANDLE thread, bool& debt, bool& conflicted, NativeStepError& first)
{
    if (!debt)
    {
        return;
    }
    const auto wait = WaitForSingleObject(thread, 0); // 只使用持有句柄对应对象的退出证据，不按TID重开。
    if (wait == WAIT_OBJECT_0)
    {
        // 对象已退出：暂停计数随线程对象消亡，不存在可归还的暂停，无需也无法Resume。
        debt = false;
        conflicted = false;
        return;
    }
    if (wait == WAIT_FAILED)
    {
        const auto error = Error("step-check-held-thread-lifetime"); // 不覆盖较早的上下文恢复错误。
        if (!first)
        {
            first = error;
        }
        return;
    }
    // WAIT_TIMEOUT：对象仍存活。恢复失败期间保留债务，等待恢复路径逐项重试；不猜测放行，不批量清账。
}

NativeStepError NativeStepRuntime::RestoreSelectedContext() {
    if (selectedSuspendConflict_) return {"step-selected-suspend-count-conflict", ERROR_INVALID_DATA};
    const bool temporary = receipt_.destination.has_value();
    const bool flagsOwned = !temporary || pageTrapOwned_;
    if (flagsOwned && !selectedEventStopped_ && !selectedSuspendDebt_) {
        if (SuspendThread(selected_) == static_cast<DWORD>(-1)) return Error("step-suspend-selected-for-restore");
        selectedSuspendDebt_ = true; // 先取得独立暂停，不能将等待中的控制现场直接回写。
    }
    CONTEXT context{};
    context.ContextFlags = flagsOwned ? CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS : CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(selected_, &context)) return Error("step-read-restore-context");
    const auto bits = context.Dr7 & kSlot1Control;
    if (temporary && !((context.Dr1 == *receipt_.destination && bits == kSlot1Enable) ||
        (context.Dr1 == originalDr1_ && bits == originalDr7_))) return {"step-dr-restore-conflict", ERROR_INVALID_DATA};
    const auto ownedReason = (temporary ? DWORD64{2} : kBs) | (pageTrapOwned_ ? kBs : 0);
    if ((context.Dr6 & ownedReason) || (temporary && (context.Dr1 != originalDr1_ || bits != originalDr7_))) {
        // DR1和DR6只写DEBUG_REGISTERS；不携带内核等待线程的RIP/RSP/段寄存器。
        CONTEXT debug = context;
        debug.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (temporary) {
            debug.Dr1 = static_cast<decltype(debug.Dr1)>(originalDr1_);
            debug.Dr7 = static_cast<decltype(debug.Dr7)>((debug.Dr7 & ~kSlot1Control) | originalDr7_);
        }
        debug.Dr6 = static_cast<decltype(debug.Dr6)>(debug.Dr6 & ~ownedReason);
        if (!SetThreadContext(selected_, &debug)) return Error("step-restore-debug-context");
        debug.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(selected_, &debug)) return Error("step-read-restored-debug-context");
        if ((debug.Dr6 & ownedReason) || (temporary &&
            (debug.Dr1 != originalDr1_ || (debug.Dr7 & kSlot1Control) != originalDr7_)))
            return {"step-verify-restored-debug-context", ERROR_INVALID_DATA};
    }
    if (flagsOwned && (context.EFlags & kTf) != (originalFlags_ & kTf)) {
        // 只修改当前TF，不还原最初RIP/RSP；不可用的用户返回现场留给Recovery，绝不写成零。
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(selected_, &context)) return Error("step-read-restore-control-context");
        const auto ip = Ip(context);
        const auto sp = Sp(context);
        const auto cs = context.SegCs;
        const auto ss = context.SegSs;
        if (!ip || !sp || ip >= 0x0000800000000000ull || sp >= 0x0000800000000000ull ||
            (cs & 3) != 3 || (ss & 3) != 3) return {"step-user-control-context-unavailable", ERROR_INVALID_DATA};
        context.EFlags = (context.EFlags & ~kTf) | (originalFlags_ & kTf);
        context.ContextFlags = CONTEXT_CONTROL;
        if (!SetThreadContext(selected_, &context)) return Error("step-restore-control-context");
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(selected_, &context)) return Error("step-read-restored-control-context");
        if ((context.EFlags & kTf) != (originalFlags_ & kTf) || Ip(context) != ip || Sp(context) != sp ||
            context.SegCs != cs || context.SegSs != ss) return {"step-verify-restored-control-context", ERROR_INVALID_DATA};
    }
    contextOwned_ = pageTrapOwned_ = false;
    return {};
}

NativeStepError NativeStepRuntime::Restore(bool processExited, const DEBUG_EVENT* heldEvent) {
    const auto reject = [&](NativeStepError error) {
        MarkFailure(error); // 身份或退出证明失败也进入恢复状态，已有句柄及每一笔债务保持原样。
        receipt_.resourcesRestored = !HasResources();
        return error;
    };
    if (heldEvent) {
        if (!process_ || heldEvent->dwProcessId != GetProcessId(process_)) {
            return reject({"step-restore-event-process-mismatch", ERROR_INVALID_DATA});
        }
    }
    if (processExited) {
        // 调用方布尔值不是免除全部债务的证据；须有同一强进程的退出事件或终止信号。
        const bool exitEvent = heldEvent && heldEvent->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
        if (!exitEvent) {
            const auto wait = WaitForSingleObject(process_, 0);
            if (wait == WAIT_FAILED) {
                return reject(Error("step-check-process-exit"));
            }
            if (wait != WAIT_OBJECT_0) {
                return reject({"step-process-exit-unconfirmed", ERROR_INVALID_STATE});
            }
        }
    }
    if (heldEvent) {
        selectedEventStopped_ = heldEvent->dwThreadId == receipt_.request.tid;
        if (const auto error = RetireExitedThread(*heldEvent); error) {
            return reject(error);
        }
    }
    NativeStepError first;
    const auto remember = [&](NativeStepError error) { if (error && !first) first = error; };
    // 上下文恢复失败时contextPending为真：暂停债仍须逐对象结清，不能被单个对象的失败整体阻断。
    bool contextPending = false;
    if (contextOwned_) {
        const auto wait = processExited || selectedExited_ ? WAIT_OBJECT_0 : WaitForSingleObject(selected_, 0);
        if (wait == WAIT_OBJECT_0) { contextOwned_ = false; pageTrapOwned_ = false; }
        else if (wait == WAIT_TIMEOUT)
        {
            if (const auto error = RestoreSelectedContext()) // 上下文未恢复时保留所有存活对象的暂停责任。
            {
                remember(error);
                contextPending = true;
            }
        }
        else
        {
            remember(Error("step-check-selected-lifetime"));
            contextPending = true;
        }
    }
    if (!contextPending) {
        // 精确所选线程退出只免除其上下文/自身暂停；存活peer仍逐个移除本端一次暂停。
        remember(ReleaseHold(selected_, selectedSuspendDebt_, selectedSuspendConflict_,
            processExited || selectedExited_, "step-resume-selected"));
        for (auto& hold : peers_)
            remember(ReleaseHold(hold.thread, hold.debt, hold.conflicted, processExited, "step-resume-peer"));
    } else {
        // 恢复失败路径的逐对象兜底：每个真实线程对象按自身signaled退出证据独立处理。
        // 已退出对象免除债务（不存在可归还的暂停）；存活对象的暂停债原样保留等待恢复重试。
        // 不猜测放行全部线程，不批量清账，也不跳过恢复状态。
        DischargeExitedHold(selected_, selectedSuspendDebt_, selectedSuspendConflict_, first);
        for (auto& hold : peers_) // 每笔债均以原线程句柄判断，不合并为一次全体释放。
        {
            DischargeExitedHold(hold.thread, hold.debt, hold.conflicted, first);
        }
    }
    receipt_.resourcesRestored = !HasResources();
    if (first) MarkFailure(first);
    return first;
}

void NativeStepRuntime::MarkFailure(NativeStepError error) {
    running_ = false;
    receipt_.state = NativeStepState::RecoveryRequired;
    receipt_.stage = error.stage;
    receipt_.win32Error = error.code;
}

void NativeStepRuntime::BindStop(std::string groupId, NativeEventKey event) {
    receipt_.stopGroupId = std::move(groupId);
    receipt_.observedEvent = std::move(event);
}

bool NativeStepRuntime::Observe(const DEBUG_EVENT& event, bool cancellationBreak, bool ownsDr0) {
    if (!running_) return false;
    if (event.dwProcessId != GetProcessId(process_)) {
        MarkFailure({"step-event-process-mismatch", ERROR_INVALID_DATA}); return true;
    }
    const bool exit = event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
    if (const auto error = RetireExitedThread(event); error) {
        MarkFailure(error);
        return true;
    }
    const bool selectedExit = event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && selectedExited_ &&
        event.dwThreadId == selectedIdentity_.threadId;
    if (!exit && !selectedExit && event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) return false;
    selectedEventStopped_ = event.dwThreadId == receipt_.request.tid;
    bool completed = false;
    disposition_ = DBG_EXCEPTION_NOT_HANDLED;
    eventKind_ = NativeStepEventKind::None;
    observedDr6_ = 0;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!exit && !selectedExit && event.dwThreadId == receipt_.request.tid) {
        if (!GetThreadContext(selected_, &context)) { MarkFailure(Error("step-read-event-context")); return true; }
        receipt_.observedIp = Ip(context);
        receipt_.observedSp = Sp(context);
        observedDr6_ = context.Dr6;
        const auto& exception = event.u.Exception;
        if (exception.dwFirstChance && exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            const auto reasons = context.Dr6 & kReasons;
            if (receipt_.destination) {
                completed = reasons == 2 && Ip(context) == *receipt_.destination && Sp(context) == expectedSp_;
                if (reasons == 2) disposition_ = DBG_CONTINUE;
            } else {
                completed = reasons == kBs;
                if (reasons == kBs) disposition_ = DBG_CONTINUE;
                if (completed && callReturn_ && receipt_.startSp >= 8 && Sp(context) == receipt_.startSp - 8) {
                    std::uint64_t slot = 0;
                    if (!Read(Sp(context), &slot, sizeof(slot)) && slot == *callReturn_)
                        frame_ = EntryFrame{Ip(context), Sp(context), slot, receipt_.request.thread};
                }
            }
            // The user's own DR0 breakpoint fired before the step destination.
            // The owner's breakpoint stays authoritative for that event.
            if (!completed && ownsDr0 && (reasons & kDr0) != 0) {
                eventKind_ = NativeStepEventKind::CompetingBreakpoint;
                disposition_ = DBG_CONTINUE;
            }
        } else if (exception.dwFirstChance) {
            eventKind_ = NativeStepEventKind::ApplicationException;
        }
    } else if (!exit && !selectedExit) {
        eventKind_ = NativeStepEventKind::ApplicationException;
    }
    if (exit) { eventKind_ = NativeStepEventKind::ProcessExit; }
    if (selectedExit) { eventKind_ = NativeStepEventKind::SelectedThreadExit; }
    if (exit || selectedExit) disposition_ = DBG_CONTINUE;
    if (cancellationBreak) disposition_ = DBG_CONTINUE;
    if (completed) { eventKind_ = NativeStepEventKind::StepCompleted; }
    receipt_.state = exit || selectedExit ? NativeStepState::Exited : cancelRequested_ ? NativeStepState::Cancelled :
        completed ? NativeStepState::Completed : NativeStepState::Interrupted;
    receipt_.stage = exit || selectedExit ? "step-thread-or-process-exited" : timeoutRequested_ ? "page-advance-timeout-interrupted" :
        cancelRequested_ ? "step-cancelled" :
        completed ? "step-completed" : "step-interrupted";
    if (timeoutRequested_ && !exit && !selectedExit) receipt_.win32Error = ERROR_TIMEOUT;
    running_ = false;
    if (exit || selectedExit) {
        // 精确退出事件免除所选线程上下文恢复；同伴仍通过统一可重试路径清账。
        // Resume失败时保留债务和RecoveryRequired，不能先清账再丢弃原生错误。
        (void)Restore(exit, &event); // 整进程退出免除所有债务，单线程退出只恢复存活同伴。
        return true;
    }
    (void)Restore(false, &event);
    return true;
}

} // namespace ks::cli::action_analyze::control
