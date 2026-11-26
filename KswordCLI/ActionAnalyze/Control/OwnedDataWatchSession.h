#pragma once

#include "NativeDebugOwner.h"
#include "ProcessGroupMemorySnapshot.h"
#include "../Rules/RuleExpression.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Ksword::ActionAnalyze { class ProjectDocument; struct ProjectResult; struct ProjectNativeExecutionReceipt; }

namespace ks::cli::action_analyze::control {

class CooperativeBreakpointGate; // 间接绑定启动许可，在本会话工作线程上串行推进。

// 桌面端使用同一条件编译器。未填写条件时，谓词保持未绑定并沿用原停点行为。
struct DataWatchConditionPreparation {
    Ksword::ActionAnalyze::Rules::PreparedPredicate predicate; // 启动时已校验的类型化条件。
    const char* diagnostic = nullptr; // 稳定错误标识；空表示可启动。
    std::optional<Ksword::ActionAnalyze::Rules::ExpressionLocation> location; // UTF-8 源位置，若可定位。
};

// 编译单次启动的条件草稿；传入 UTF-16 原文，返回已验证的谓词或错误位置。
[[nodiscard]] DataWatchConditionPreparation PrepareDataWatchCondition(std::wstring_view source);

// 检查快照是否持有本会话可控制的写入、私有执行或步进事件；不查询现场，也不授予旧令牌资格。
[[nodiscard]] const EventResponsibility* DataWatchHeldStop(const NativeControlResult& state) noexcept;
// 输入原会话已发布快照，仅判断主动暂停按钮资格；实际请求由原owner再次核验。
[[nodiscard]] bool CanPauseDataWatchSession(const NativeControlResult& state) noexcept;
// 仅当步进回执的原生事件与当前停止组一致时为真，原写入条件不作用于普通步进停点。
[[nodiscard]] bool IsDataWatchStepStop(const NativeControlResult& state) noexcept;
// 输入显示快照，返回同址私有写转执行按钮资格；只作界面提示，原owner仍核对现场和完整票据。
[[nodiscard]] bool CanFollowDataWatchPrivateExecution(const NativeControlResult& state) noexcept;

struct DataWatchConditionDecision {
    NativeEventKey event; // 已经求值的唯一原生事件。
    std::string groupId; // 求值时所属的冻结停止组。
    std::uint64_t stateRevision = 0; // 求值时的停止组修订。
    Ksword::ActionAnalyze::Rules::Evaluation evaluation; // 三值及求值故障，均来自同一冻结快照。
    std::optional<ReleaseResult> release; // 实际自动继续回执；集合保留Unknown时为空，旧单目标策略不变。
    const char* failureStage = nullptr; // 自动继续失败的诊断，要求显式清退。
    std::uint32_t releaseError = 0; // 自动继续失败时原生错误码。
};

struct DataWatchConditionReport {
    std::uint64_t trueCount = 0; // 条件为真并发布停点的次数。
    std::uint64_t falseCount = 0; // 条件为假的次数。
    std::uint64_t unknownCount = 0; // 字段未知或求值失败的次数。
    std::optional<DataWatchConditionDecision> last; // 最近一次求值，可能晚于最近一次手动停点。
};

// 在调用方已有的串行工作线程执行所有操作及销毁。一个实例只创建一个子进程。
// Close 可能返回尚未清退的原生状态。保留会话并 Query 或再次 Close，直到确认 clean。
class OwnedDataWatchSession final {
public:
    // 集合传true保留未知条件；默认false兼容旧单目标假/未知自动继续的已验语义。
    explicit OwnedDataWatchSession(bool holdUnknownCondition = false);
    ~OwnedDataWatchSession();
    OwnedDataWatchSession(const OwnedDataWatchSession&) = delete;
    OwnedDataWatchSession& operator=(const OwnedDataWatchSession&) = delete;

    // 用户明确授权后调用。路径为本机非根目录下的绝对 DOS 路径，导出名区分大小写，宽度为 1/2/4/8 字节。
    // 先核对盘上标记和数据范围，再启动并提交原生绑定。可选条件通过 PrepareDataWatchCondition 编译。
    [[nodiscard]] NativeControlResult Start(const std::wstring& path, const std::string& exportName, std::uint32_t width,
        Ksword::ActionAnalyze::Rules::PreparedPredicate condition = {}, bool indirect = false,
        std::string_view sampleId = {});
    // 显式选择私有执行入口；输入8字节映像数据指针导出，返回原owner的武装/失败回执。
    // 不将零宽度解释为写入，不创建另一个owner；沿同一Ready/Gate启动链路。
    [[nodiscard]] NativeControlResult StartPrivateExecution(const std::wstring& path, const std::string& exportName,
        Ksword::ActionAnalyze::Rules::PreparedPredicate condition = {}, std::string_view sampleId = {});
    // 两端后台可直接关注已运行实例的私有地址，无EXE导出或合作握手。
    // width=0为执行，1/2/4/8为写入；调用方显式授权后在原串行worker执行。
    [[nodiscard]] NativeControlResult AttachPrivateAddress(std::uint32_t pid, std::uint64_t creationFileTime,
        std::uint64_t address, std::uint32_t width,
        Ksword::ActionAnalyze::Rules::PreparedPredicate condition = {}, std::string_view sampleId = {},
        std::uint64_t privateRangeBytes = 0);
    // 在原worker附加已有实例的普通模块执行位置；RVA与精确PE导出二选一，不使用PDB符号。
    // 调用方冻结PID/创建时间、绝对模块路径与条件，结果仍由同一个NativeDebugOwner回读。
    [[nodiscard]] NativeControlResult AttachImageExecution(std::uint32_t pid, std::uint64_t creationFileTime,
        const std::wstring& modulePath, std::optional<std::uint32_t> rva, const std::string& exportName,
        Ksword::ActionAnalyze::Rules::PreparedPredicate condition = {}, std::string_view sampleId = {},
        std::optional<std::string> imageSha256 = std::nullopt,
        bool waitForModule = false); // 集合可等首次加载；约束由原owner验证实际装载文件后才武装。
    // 回读原生状态。结果按值跨线程传递，诊断字符串具有静态存储期。
    [[nodiscard]] NativeControlResult Query();
    // 为同采样API等只读准入回读原owner；不应用条件、打开合作Gate或提交自动Continue。
    [[nodiscard]] NativeControlResult QueryWithoutCondition();
    // 输入点击时的原会话快照，在既有调试附加中请求主动下断；返回接受不代表已经停止。
    [[nodiscard]] NativeControlResult Pause(const NativeControlResult& displayedSession);
    // 将点击时展示的原生快照按值入队。使用其中的精确事件与修订继续，旧快照会被拒绝。
    [[nodiscard]] NativeControlResult Continue(const NativeControlResult& displayedStop);
    // 保留原写入事件和冻结条件，仅转换当前同址私有RWX起点；不继续、不重启目标、不创建owner。
    [[nodiscard]] NativeControlResult FollowPrivateExecution(const NativeControlResult& displayedStop);
    // 完整Held下纳入新的NX范围；输入点击时原停止快照及范围，不执行条件自动继续。
    [[nodiscard]] NativeControlResult AddPrivateExecutionRange(const NativeControlResult& displayedStop,
        std::uint64_t address, std::uint64_t bytes);
    // 用点击时快照中的精确事件线程提交原生步进；继续与步进共用单调释放序列。
    [[nodiscard]] NativeControlResult Step(const NativeControlResult& displayedStop, NativeStepMode mode);
    // 取消当前显示的步进请求。旧请求不能中止后来发起的步进；取消后仍回读实际停点。
    [[nodiscard]] NativeControlResult CancelStep(const NativeControlResult& displayedStep);
    // 请求原所有者清退并返回它的实际回执。
    [[nodiscard]] NativeControlResult Close();
    // 原会话串行读取显示时的精确停点；不触发条件自动继续、不改变停止令牌。
    [[nodiscard]] ProcessMemorySnapshotResult CaptureMemory(const NativeControlResult& displayedStop,
        const memory::Plan& plan, const std::atomic_bool* cancel = nullptr);
    // 只保存原 owner 当前执行观测；普通写入事件不会生成执行证据。调用方持原项目写租约。
    [[nodiscard]] Ksword::ActionAnalyze::ProjectResult SaveExecution(Ksword::ActionAnalyze::ProjectDocument& project,
        std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
        const NativeControlResult& displayedStop, Ksword::ActionAnalyze::ProjectNativeExecutionReceipt& receipt);
    // 只读身份供同线程项目归档绑定；历史档案不能替换该身份或本会话的原 owner。
    [[nodiscard]] const OwnerIdentity& Identity() const noexcept { return identity_; }
    // 与 Query/Continue/Close 同线程回读冻结的求值计数和最近判断，不执行新控制操作。
    [[nodiscard]] const DataWatchConditionReport& ConditionReport() const noexcept { return conditionReport_; }

private:
    struct AbortedLaunch;
    // 两个显式启动入口共用创建与身份核对；execute为真时仅接受间接执行和零写入宽度。
    [[nodiscard]] NativeControlResult StartBound(const std::wstring& path, const std::string& exportName,
        std::uint32_t width, Ksword::ActionAnalyze::Rules::PreparedPredicate condition, bool indirect,
        std::string_view sampleId, bool execute);
    // 只处理尚未交给调试所有者的失败启动，保留句柄直到确认退出。
    [[nodiscard]] NativeControlResult ObserveAbortedLaunch(bool requestTermination);
    // 使用新快照求值；假值自动继续，未知按构造策略保留或继续，真值保持原停点。
    [[nodiscard]] NativeControlResult ApplyCondition(NativeControlResult state);
    // 使用调用方已核验的原生令牌提交继续。自动和手动操作共享同一个序列。
    [[nodiscard]] NativeControlResult ReleaseWrite(const NativeControlResult& state, const EventResponsibility& stop);
    // 核对显示快照与当前快照的完整停止身份及条件资格，失败时保留当前回执。
    [[nodiscard]] bool MatchesDisplayedStop(const NativeControlResult& displayed, const NativeControlResult& current) const;

    OwnerIdentity identity_; // 本会话独立身份，继续提交给同一个原生账本。
    std::unique_ptr<NativeDebugOwner> owner_; // 原生调试线程和清退责任的所有者。
    std::unique_ptr<AbortedLaunch> aborted_; // 首次执行前撤销的启动及其回执。
    std::unique_ptr<CooperativeBreakpointGate> launchGate_; // 仅间接私有内存模式等待初始化并控制业务放行。
    Ksword::ActionAnalyze::Rules::PreparedPredicate condition_; // 本次生效的冻结谓词。
    DataWatchConditionReport conditionReport_; // 不与页面的下一次输入草稿共享。
    std::uint64_t releaseSequence_ = 0; // 按原生滚动账本约定生成继续请求 ID。
    std::uint64_t followSequence_ = 0; // 独立follow/N票据，不消费继续和单步流水。
    std::uint64_t rangeSequence_ = 0; // 独立range/N票据，不消费继续、步进或follow序列。
    std::uint64_t pauseSequence_ = 0; // 原执行owner主动暂停的独立pause/N流水。
    bool closing_ = false; // 关闭一经请求，停止接受继续和启动。
    bool holdUnknownCondition_ = false; // 构造时冻结，集合未知条件可调查和显式继续，不热改旧单目标行为。
};

} // namespace ks::cli::action_analyze::control
