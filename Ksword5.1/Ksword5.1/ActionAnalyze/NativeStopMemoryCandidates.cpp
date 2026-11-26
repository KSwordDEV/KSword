#include "../Framework.h"
#include "NativeStopMemoryArchive.h"

#include <utility>

namespace ks::action_analyze
{
    namespace project = Ksword::ActionAnalyze;
    namespace detection = project::Detection;

    // 输入两个原绑定快照，返回是否属于同一轮归档与目标强实例；不把PID单独作为身份。
    bool SameExecutionCandidatesBinding(const NativeExecutionCandidatesContext& left,
        const NativeExecutionCandidatesContext& right)
    {
        return !left.projectDirectory.empty() && !left.sampleId.empty() &&
            left.target.pid && left.target.creationFileTime &&
            left.projectDirectory == right.projectDirectory &&
            (left.projectId.empty() || right.projectId.empty() || left.projectId == right.projectId) &&
            left.sampleId == right.sampleId && left.target.pid == right.target.pid &&
            left.target.creationFileTime == right.target.creationFileTime;
    }

    // 在原archive所属的串行worker调用；request为点击冻结值，不包含借用的string_view。
    void NativeStopMemoryArchive::ReadExecutionCandidates(const NativeExecutionCandidatesRequest& request)
    {
        NativeExecutionCandidatesResult view; // 无论成功失败都保存本次请求及archive实际归属。
        view.request = request;
        view.context = request.context;
        view.context.projectDirectory = m_view.projectDirectory;
        view.context.projectId = m_project && m_project->Info() ? m_project->Info()->projectId : std::string{};
        view.context.sampleId = SampleId();

        // target仅为调用worker已回读并冻结的目标提示；本方法不查询owner或授予Held资格。
        // 原页面派发前仍须核对本轮身份；底层读取始终强制用archive自己的采样。
        try
        {
            if (!m_project || !m_project->Info() || SampleId().empty())
            {
                view.result = {project::ProjectError::NotOpen, 0, "nativeCandidatesOriginalProject"};
            }
            else if (!request.serial || !SameExecutionCandidatesBinding(request.context, view.context))
            {
                view.result = {project::ProjectError::StaleRevision, 0, "nativeCandidatesOriginalBinding"};
            }
            else
            {
                detection::PrivateExecutionCandidatesRequest read; // 所有借用值仅在本同步调用内存活。
                read.sampleId = SampleId();
                read.throughOrdinal = request.throughOrdinal;
                read.after = request.after;
                read.expectedSnapshot = request.snapshot;
                read.limit = detection::kPrivateCandidateMaxPage;

                // 原writer仍持租约时直接只读同一个document；不关闭writer，也不打开第二个项目。
                detection::PrivateExecutionCandidatesPage page; // 核心只在全部核验通过后替换此页。
                view.result = detection::ReadPrivateExecutionCandidates(*m_project, read, page);
                if (view.result)
                {
                    view.page = std::make_shared<const detection::PrivateExecutionCandidatesPage>(std::move(page));
                }
            }
        }
        catch (...)
        {
            view.page.reset(); // 异常不能留下可供UI当成完整结果的局部页。
            view.result = {project::ProjectError::IoError, 0, "nativeCandidatesReadException"};
        }

        FILETIME now{}; // 读取完成时间只用于结果来源说明，不参与AAIM1调用顺序推断。
        GetSystemTimeAsFileTime(&now);
        view.readFileTime = (std::uint64_t{now.dwHighDateTime} << 32) | now.dwLowDateTime;
        m_candidates = std::make_shared<const NativeExecutionCandidatesResult>(std::move(view));
    }

    // 只在同一worker复制共享指针，调用者再随原session快照发布给GUI；不跨线程调用archive。
    std::shared_ptr<const NativeExecutionCandidatesResult> NativeStopMemoryArchive::CandidateView() const
    {
        return m_candidates;
    }
}
