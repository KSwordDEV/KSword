#pragma once

#include <QList>
#include <QString>
#include <functional>

namespace ks::action_analyze
{
    enum class ReadStatus { Ready, Unavailable, Invalid, Unsupported, Canceled };

    struct ReadProblem
    {
        ReadStatus status = ReadStatus::Ready; // 文件可用性与格式问题分别报告。
        QString relativeFile;                 // 失败文件相对项目根的路径。
    };

    struct SampleSummary
    {
        QString id;              // 目录中的采样 UUID。
        QString title;           // 采样创建时写入的标题。
        quint64 createdUtc = 0;  // FILETIME UTC，保留 100ns 精度。
        QString revisionId;      // 采样冻结时引用的项目修订。
        QString snapshotId;      // 冻结配置快照 UUID。
        QString descriptionHash; // sample.json 预期 SHA-256。
    };

    struct ProjectSnapshot
    {
        QString manifestPath;     // 本次读取的规范清单路径。
        QString id;               // 项目 UUID。
        QString title;            // 当前修订的项目标题。
        QString revisionId;       // 清单指定的当前修订。
        quint64 generation = 0;   // 清单发布时的代次。
        QList<SampleSummary> samples; // 仅来自清单指定的采样目录页。
        ReadProblem problem;
    };

    struct SampleRequest
    {
        QString manifestPath; // 已展示的项目路径，切换时随选择一起冻结。
        QString projectId;    // 已展示的项目 UUID。
        SampleSummary sample; // 已展示的目录行及其预期散列。
    };

    struct SampleDetails
    {
        QString configurationTitle; // 快照中冻结的标题。
        QString configurationNotes; // 快照中冻结的说明。
        QString configurationHash;  // 快照中记录的配置语义散列。
        ReadProblem problem;
    };

    using CancelCheck = std::function<bool()>; // 由调用者提供可跨线程读的取消查询。

    // 后台根据清单路径读取目录及采样摘要，返回带状态的只读值快照。
    ProjectSnapshot ReadProjectCatalog(const QString& manifestPath, const CancelCheck& isCanceled);
    // 后台按冻结请求读取已选采样及配置；出错时不提交任何新详情。
    SampleDetails ReadSampleDetails(const SampleRequest& request, const CancelCheck& isCanceled);
}
