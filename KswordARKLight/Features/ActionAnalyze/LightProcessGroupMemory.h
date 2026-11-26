#pragma once

#include "../../Core/Win32Lean.h"

#include "../../../KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h"
#include "../../../KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Memory/SelectedMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Ksword::Features::ActionAnalyze {

namespace process_group_native = ks::cli::action_analyze::control;
namespace project = Ksword::ActionAnalyze;

// 页面输入解析失败的稳定阶段；全部为纯值诊断，不含任何系统调用结果。
enum class LightMemoryInputStage {
    None,        // 无失败。
    BaseEmpty,   // 起始地址文本为空。
    BaseInvalid, // 起始地址不是合法的无符号数字文本。
    BaseZero,    // 起始地址为 0；底层同样拒绝零基址。
    BytesEmpty,  // 范围字节数文本为空。
    BytesInvalid,// 范围字节数不是合法的十进制无符号文本。
    BytesZero,   // 范围字节数为 0；空范围没有采样意义。
    RangeOverflow, // base + bytes 超出无符号 64 位地址空间。
    EpochEmpty,  // 调用会话未提供 trackingEpoch（控制者代次）。
    MemberNotHeld  // 目标成员不存在、无控制回执或未处于 HeldComplete 完整停点。
};

struct LightMemoryInputRejection {
    LightMemoryInputStage stage = LightMemoryInputStage::None; // 本端解析失败阶段。
    const char* detail = ""; // 稳定英文诊断值，与原生 stage 风格一致。
};

// 项目身份与归档回执的只读投影；保存回执和本次读取在展示层始终分开保留。
struct LightProcessGroupMemoryProjectView {
    std::wstring projectDirectory; // 本端显式创建的项目目录；空表示尚无项目。
    std::string sampleId; // 项目采样 ID；无项目时为 owner 会话采样标签。
    project::ProjectResult projectResult; // 最近一次项目创建或归档操作的真实结果。
    std::optional<project::ProjectMemorySnapshotReceipt> archive; // 最近保存回执；blocked 时保留失败回执。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> archiveSource; // 实际保存的完整capture身份。
    bool archiveBlocked = false; // 写入或回读失败后阻止追加；不得通过跳段或覆盖恢复。
};

// 纯值函数：把页面输入解析为一次 HeldEvent 只读显式范围内存请求；不做任何系统调用、
// 不开线程、不接 owner。base 文本带 0x/0X 前缀按十六进制解析、否则按十进制；
// bytes 文本只接受十进制；两者均为无符号严格解析，拒绝空文本、0 值、非法字符与
// 64 位溢出，并拒绝 base + bytes 溢出。64 页范围上限由底层 PassiveDirtyMemory::Begin
// 按真实页大小复核，本函数复用该底层检查、不新增隐藏范围限制。
// sampleId 取自成员原生组回执 member.control.group.sampleId；stop 原样复制、不在本端改写；
// trackingEpoch 由调用会话提供（控制者代次）；Plan.target 仅冻结 PID 与创建 FILETIME 这两项
// 真实系统身份，machineId/bootId 填入会话局部标签，不宣称系统机器或启动身份。
// 返回 false 时 rejection 保存失败阶段，out 保持不变。
bool PrepareHeldMemoryRequest(const process_group_native::ProcessGroupResult& group, const process_group_native::ProcessGroupTarget& target,
    std::string_view trackingEpoch, const std::wstring& baseText, const std::wstring& bytesText,
    process_group_native::ProcessMemorySnapshotRequest& out, LightMemoryInputRejection& rejection);

// 成功页原字节预览的每页上限；完整原字节仍只保存在快照与归档中，预览仅用于字段文本。
inline constexpr std::size_t kLightMemoryPreviewBytesPerPage = 256;

// 纯值投影：把本次显式范围只读内存结果投影为字段文本（每行"字段: 值"）。
// 包含目标身份、范围、来源（仅 HeldEvent）、读前读后停点一致性、原生诊断、总成功/失败页数、
// 实际读取字节、轮次采样起止 QPC 与频率；每个采样页给出状态、错误、readQPC；
// 成功页附有界原字节预览，每页最多 256 字节，完整原字节仍只存在于快照内。
// 读取失败时仍保留快照内的部分证据文本，不填零、不省略失败页。
std::wstring FormatLightProcessGroupMemory(const process_group_native::ProcessMemorySnapshotResult& read);

// 纯值投影：把项目路径/采样/项目结果/错误与归档回执投影为字段文本。
// 与 FormatLightProcessGroupMemory 的返回值分开保留；archiveBlocked 时附加保留现场、
// 停止追加的诊断，新的读取不会清除该诊断。
std::wstring FormatLightProcessGroupMemoryArchive(const LightProcessGroupMemoryProjectView& view);

// 后台状态类：不创建线程、不接 owner、无窗口依赖。由后续 Light session 的同串行工作
// 线程持有并调用；全部方法只能在持有对应 OwnedProcessGroup 的同一串行线程执行，
// 与 Continue/Close 的互斥由持有会话保证，本类不加锁。无项目时仍允许按 owner 采样读取。
class LightProcessGroupMemoryState final {
public:
    LightProcessGroupMemoryState() = default;
    ~LightProcessGroupMemoryState() = default;
    LightProcessGroupMemoryState(const LightProcessGroupMemoryState&) = delete;
    LightProcessGroupMemoryState& operator=(const LightProcessGroupMemoryState&) = delete;

    // 显式创建全新项目目录并登记一个新采样；成功时更新 owner.sampleId 供会话重建原生组。
    // ProjectDocument::Create 拒绝已存在项目，绝不抢占其他页面的活动写租约。
    // 失败时保留既有项目身份与采样不变，仅回执最近一次项目结果。
    project::ProjectResult CreateNewProject(const std::wstring& path, process_group_native::OwnerIdentity& owner);
    // 原集合确认clean后由原串行worker释放项目租约；所有已发布结果和失败段坐标保持不变。
    void CloseProject();

    // 在同串行 owner 上执行一次只读显式范围内存采集。页面只暴露 HeldEvent 通道：
    // 非 HeldEvent 或缺完整停点令牌在本层直接拒绝，完整令牌与 sample 一致性由底层
    // CaptureProcessGroupMemory 在读前读后两次核对，失败不回退 Live 实时读取。
    // 采集失败仍保留快照内的部分证据；新读取不清除保存失败导致的 blocked 诊断。
    // 返回本次结果；同一 shared_ptr 指针即 Save 的唯一保存凭据。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> Read(process_group_native::OwnedProcessGroup& group,
        const process_group_native::ProcessMemorySnapshotRequest& request);

    // 只保存当前显示的同一指针不可变读取结果；ProjectDocument 写租约由本状态独占。
    // 按 ordinal + previousSequence 调用 WriteProcessGroupMemorySnapshot，完整保留readContext；仅当
    // projectResult 成功且 receipt.verified && receipt.raw.flushed 时，前序取真实
    // flushed->lastSequence 再 ++ordinal；失败保留原段并置 blocked 阻止追加，不跳段不覆盖。
    project::ProjectResult Save(const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& displayed);

    // 只读投影：项目身份与归档回执；仅复制值，供会话在其自身锁内发布快照。
    LightProcessGroupMemoryProjectView ProjectView() const;
    // 最新显式读取结果；未读取过时为空。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> LatestRead() const;
    // 当前项目采样 ID；无项目时为 owner 会话采样标签。
    const std::string& SampleId() const;

private:
    std::optional<project::ProjectDocument> project_; // 项目写租约归本状态；惰性构造，异常安全。
    std::wstring projectDirectory_; // 本次请求的真实目录，半创建失败也保留。
    std::string sampleId_; // 已登记项目采样，或 owner 会话采样标签。
    project::ProjectResult projectResult_; // 最近项目操作回执。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> lastMemory_; // 原字节只由显式读生成。
    std::optional<project::ProjectMemorySnapshotReceipt> archive_; // 最近保存回执。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> archiveSource_; // 坏尾对应原capture，新读取不得替换。
    bool archiveBlocked_ = false; // 坏尾不能通过跳段或覆盖文件规避；新项目才能重新开始。
    std::uint64_t nextMemoryOrdinal_ = 1; // 独立 raw-memory lane 段号，不占 API/ETW 段号。
    std::optional<std::uint64_t> previousMemorySequence_ = 0; // 新sample空链为0；前段使用真实flushed末序号。
};

} // namespace Ksword::Features::ActionAnalyze
