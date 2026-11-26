#pragma once

#include "ProcessGroupSession.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedDataWatchSession.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectNativeExecution.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NativeBoundApiCapture.h"
#include "NativeStopMemoryCandidates.h"
#include <unordered_map>

namespace ks::action_analyze
{
    struct NativeExecutionArchiveView
    {
        Ksword::ActionAnalyze::ProjectResult result; // 执行流独立结果，不覆盖内存归档失败。
        std::optional<Ksword::ActionAnalyze::ProjectNativeExecutionReceipt> receipt; // 原段坐标、刷盘和散列回执。
        std::optional<process_group_native::NativeExecutionEvidence> observation; // 保存点击时原事件身份，不随当前停点变化。
        bool blocked = false; // 本流失败阻止追加，但原session仍可清退。
        bool duplicate = false; // 同一原生事件返回已存坐标，不重复写段。
        std::shared_ptr<const NativeExecutionArchiveView> blockedFailure; // 回看旧成功事件仍保留首次阻断回执。
    };

    // 写入／步进页的本端归档状态；由原SessionOwner持有，所有方法只在原串行worker调用。
    class NativeStopMemoryArchive final
    {
    public:
        // 输入启动前冻结目录与显式打开方式；同一写会话新建sample，失败不得启动目标。
        bool PrepareProject(const std::wstring& directory, bool openExisting = false);
        // 真实启动前核对本次sample的已保存定义，拒绝错误项目或不同RVA，失败不附加目标。
        bool ValidateImageDefinition(std::string_view definitionId, const std::wstring& modulePath, std::uint32_t rva);
        const std::optional<std::string>& ImageSha256() const { return m_imageSha256; } // 原sample核验后的约束，供同worker原native附加。
        // Start末尾传入该真实sample；空值保留原会话默认采样，不改写任何已采集Plan。
        const std::string& SampleId() const;
        // 使用原会话与点击时的完整控制回执读取，不查询条件、不创建第二owner。
        void Capture(process_group_native::OwnedDataWatchSession& session,
            const process_group_native::NativeControlResult& displayed,
            const ks::cli::action_analyze::memory::Plan& plan);
        // 保存点击时实际显示的不可变capture，完整readContext写入原采样。
        void Save(const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& displayed);
        // 只返回内存与项目值投影；GUI借用现有MemoryPane显示，不能从投影取得原生控制权。
        ProcessGroupSessionSnapshot View() const;
        // 原session串行保存可提取的真实执行停点，普通dataWrite由核心再次拒绝。
        void SaveExecution(process_group_native::OwnedDataWatchSession& session,
            const process_group_native::NativeControlResult& displayed);
        // 只复制执行流回执；历史receipt不能转成停止令牌。
        NativeExecutionArchiveView ExecutionView() const;
        // 原worker传入明确请求和刚从原owner回读的nativeTarget；只写私有document原SampleId。
        // 不Continue/Close原session；采用有限区间同步返回，不另建控制或取消入口。
        void CaptureApi(const Ksword::ActionAnalyze::NativeBoundApiRequest& request,
            const Ksword::ActionAnalyze::NativeBoundApiTarget& nativeTarget);
        // 返回最近API纯值快照；空指针表示未请求，GUI不得据此打开归档文件。
        std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> ApiView() const;
        // 原串行worker只读同一document；sample强制取SampleId，不另开writer或读写项目。
        void ReadExecutionCandidates(const NativeExecutionCandidatesRequest& request);
        // 返回最近请求的不可变纯值回执；空指针表示尚未请求，不授予原生控制权。
        std::shared_ptr<const NativeExecutionCandidatesResult> CandidateView() const;
        // 仅在原session确认clean后于同worker关闭项目租约，保留已发布值回执。
        void CloseProject();

    private:
        std::optional<Ksword::ActionAnalyze::ProjectDocument> m_project; // 原worker独占的新项目写租约。
        std::optional<std::string> m_imageSha256; // 冻结定义散列；手工站点及失败时保持空。
        std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> m_api; // 最近API请求及完整独立回执。
        std::shared_ptr<const NativeExecutionCandidatesResult> m_candidates; // 最近候选请求的独立只读快照。
        ProcessGroupSessionSnapshot m_view; // 内存结果、原项目身份及失败归档回执。
        std::uint64_t m_ordinal = 1; // 当前原采样raw-memory段号。
        std::optional<std::uint64_t> m_previous = 0; // 新sample空链起点为0，后段使用真实末序号。
        NativeExecutionArchiveView m_execution; // 独立raw-native结果与阻断标志。
        bool m_executionBlocked = false; // 流级坏尾状态不随同事件历史回执切换而恢复。
        std::shared_ptr<const NativeExecutionArchiveView> m_executionFailure; // 首次失败值快照，不包含自身引用。
        std::uint64_t m_executionOrdinal = 1; // 全新sample的raw-native起段，不扫描其他流。
        std::optional<std::uint64_t> m_executionPrevious = 0; // 全新sample空链为0，新段成功后O(1)推进。
        std::unordered_map<std::string, NativeExecutionArchiveView> m_executionJournal; // 同活owner事件去重表。
    };
}
