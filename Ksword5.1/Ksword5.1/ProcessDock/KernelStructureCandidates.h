#pragma once

#include "../../../shared/usermode/ThreadLayoutProfile.h"

#include <QList>
#include <QString>

class QStandardItem;

namespace ks::ui::kernelstructure
{
    // 候选仅描述其他版本的符号位置；没有现场值、地址或编辑能力。
    struct Candidate
    {
        enum class Source { Agreement, Previous, Next, Single } source; // 双侧一致、前版、后版或无双侧边界的单侧参考。
        QString field; // 完整成员路径。
        QString offset; // 用十六进制显示局部偏移；该版本无成员时为空。
        QString type; // 符号类型和位域信息。
        QString version; // 对比来源的修订号。
    };

    // 工作线程按目标磁盘 PE/PDB 身份读取其独立元数据；校验失败返回空列表。
    QList<Candidate> LoadCandidates(const std::filesystem::path& file, const threadlayout::Identity& current);

    // 输入包内最近前后版本的已验证布局；输出只读参考，任意一侧缺失时所有行均为黄色语义。
    QList<Candidate> CompareCandidates(const threadlayout::Profile& previous, const threadlayout::Profile& next,
        const threadlayout::Neighbors& neighbors, threadlayout::Kind kind);

    // 输入目标行与风险色，给整行着色；只修改背景，不改变字段、地址或采样值。
    void ColorReferenceRow(QStandardItem& item, bool yellow);
    // 输入一个 R0 结构根，递归标黄；不得传入包含独立 R3 设置的整个模型根。
    void ColorUnbracketedTree(QStandardItem& root);

    // GUI 线程将黄色参考行及成对红色冲突行投影到只读分支。
    QStandardItem* AppendCandidates(QStandardItem& root, const QList<Candidate>& rows, bool forceYellow = false);
}
