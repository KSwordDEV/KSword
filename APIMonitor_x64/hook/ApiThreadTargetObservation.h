#pragma once
#include <Windows.h>
#include <cstdint>

namespace apimon {
// ApiThreadTargetFlag：线程句柄采集结果的有效位，供各独立协议显式转换。
enum ApiThreadTargetFlag : std::uint64_t {
    ThreadTargetActor = 1ull << 0, // 源进程创建代次有效。
    ThreadTargetProcess = 1ull << 1, // 目标进程 PID 和创建代次有效。
    ThreadTargetThread = 1ull << 2, // 目标线程 TID 和创建代次有效。
    ThreadTargetStable = 1ull << 4, // 原调用前后进程和线程代次一致。
};
// ApiThreadTargetFields：仅承载采集结果，不定义 APC 或上下文的业务语义。
struct ApiThreadTargetFields {
    std::uint64_t flags = 0; // ApiThreadTargetFlag 有效位。
    std::uint64_t actorCreationFileTime = 0; // 当前源进程创建 FILETIME。
    std::uint64_t targetPid = 0; // 输入线程句柄所属进程 PID。
    std::uint64_t targetCreationFileTime = 0; // 目标进程创建 FILETIME。
    std::uint64_t targetTid = 0; // 输入句柄对应线程 TID。
    std::uint64_t targetThreadCreationFileTime = 0; // 目标线程创建 FILETIME。
    std::uint64_t enterQpc = 0; // 原 API 调用前的时点。
    std::uint64_t returnQpc = 0; // 原 API 返回后的时点。
    std::uint64_t inputThreadHandle = 0; // 原句柄位模式，仅作为参数保存。
};
// ApiThreadTargetObservation：复用调用方的 ScopedHookGuard，不另开外部进程或线程。
class ApiThreadTargetObservation {
public:
    // thread 是原输入线程句柄；构造时采集调用前身份，不取得句柄所有权。
    explicit ApiThreadTargetObservation(HANDLE thread) noexcept;
    // MarkEntry：记录原调用之前的 QPC，并保留调用方 LastError。
    void MarkEntry() noexcept;
    // MarkReturn：记录原调用刚返回时的 QPC，并保留原调用 LastError。
    void MarkReturn() noexcept;
    // Complete：重新查询原句柄及进程代次，一致时才声明稳定。
    void Complete() noexcept;
    // fields：返回本次调用的采集结果，只读引用不转移所有权。
    const ApiThreadTargetFields& fields() const noexcept
    {
        return fields_;
    }
private:
    HANDLE thread_ = nullptr; // 借用的原线程句柄，仅用于前后身份复核。
    ApiThreadTargetFields fields_{}; // 本次调用的身份和时点采集结果。
};
}
