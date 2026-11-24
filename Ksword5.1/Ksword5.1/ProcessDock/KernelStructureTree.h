#pragma once

#include "../../../shared/usermode/ThreadLayoutProfile.h"
#include "../../../shared/usermode/StructureSampleProjection.h"
#include "KernelStructureCandidates.h"

#include <QString>
#include <QHash>

class QStandardItem;
class QStandardItemModel;
class QSortFilterProxyModel;
class QTreeView;
class QLineEdit;

namespace ks::ui::kernelstructure
{
    struct Layout
    {
        threadlayout::Profile profile; // PE 与 PDB 都匹配系统磁盘文件的符号布局。
        QList<Candidate> candidates; // 仅未命中精确分片时使用的可选邻版元数据。
        bool runningMatch = false; // 驱动回报的当前内核三元组与磁盘相符。
        bool bracketed = false; // 邻版参考是否具备同架构同分支的严格前后版本；不影响精确布局背景。
    };

    struct Sample
    {
        std::uint32_t offset = 0; // 固定回执中字段的相对偏移。
        QString value; // 已按固定协议解读的采样值。
        QString type; // 固定视图在没有布局时使用的类型。
        structure_sample::FieldStatus status = structure_sample::FieldStatus::Sampled; // 本行真实采样/解码状态。
        bool unionInterpretation = false; // 共同存储的原始解释，不代表活动分支。
        bool byteValidityVerified = false; // 仅正文投影可确认该字段所需字节全部有效。
        bool zeroValue = false; // 已解码的数值确实为零，不是缺失数据的默认填充值。
        std::uint32_t width = 0; // 本次完整读取的标量字节数，供单格悬停核对。
    };
    using Samples = QHash<QString, Sample>; // 按从根开始的成员路径索引独立现场值。

    // 输入精确布局及已验证字节投影；输出逐行值和失败状态，不访问驱动。
    Samples ProjectedSamples(const threadlayout::Profile& profile, const structure_sample::Projection& projection);

    // 工作线程读取当前用户态分片；不会向驱动下发字段偏移。
    Layout LoadLayout(threadlayout::Kind kind);

    // 为两个对象页准备同一五列主题、过滤和复制行为。
    void Configure(QTreeView& tree, QStandardItemModel& model, QSortFilterProxyModel& filter, QLineEdit& search);

    // 把五列数据行追加到 parent；返回可承载子行的第 0 列。
    QStandardItem* Append(QStandardItem& parent, const QStringList& cells, bool prepend = false);

    // 添加符号树，只有同偏移、已核验的固定回执能填入现场值。
    void AppendLayout(QStandardItem& root, const Layout& layout, std::uint64_t base, const Samples& live);

    // 返回布局来源说明，图区不把磁盘符号冒充当前运行内核。
    QString LayoutStatus(const Layout& layout);
}
