#include "KernelStructureCandidates.h"
#include "KernelStructureTree.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QFile>
#include <QRegularExpression>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QMap>

namespace ks::ui::kernelstructure
{
    QList<Candidate> LoadCandidates(const std::filesystem::path& path, const threadlayout::Identity& current)
    {
        QFile file(QString::fromStdWString(path.wstring())); // 仅打开当前身份的可选说明分片。
        constexpr qint64 limit = 512 * 1024; // 限制单次读取和渲染预算。
        if (!file.open(QIODevice::ReadOnly) || file.size() <= 0 || file.size() > limit)
        {
            return {};
        }
        const auto bytes = file.read(limit + 1); // 文件读取期间如增长，不使用部分内容。
        if (bytes.size() > limit || !bytes.endsWith('\n'))
        {
            return {};
        }
        auto lines = QString::fromUtf8(bytes).split(QLatin1Char('\n')); // 发布分片是 UTF-8、LF TSV。
        if (lines.size() < 3 || lines.size() > 8194)
        {
            return {};
        }
        lines.removeLast(); // 末尾换行未承载字段。
        const auto tags = lines.takeFirst().split(QLatin1Char('\t')); // 目标身份和双侧版本。
        const QRegularExpression versionPattern(QStringLiteral("^[0-9]+(?:\\.[0-9]+){3}$"));
        if (tags.size() != 7 || tags[0] != QLatin1String("KSWNEIGHBORS1") ||
            tags[1] != QString::number(current.machine) || tags[2] != QString::number(current.timestamp) ||
            tags[3] != QString::number(current.imageSize) || tags[4] != QString::fromStdString(current.pdbKey) ||
            !versionPattern.match(tags[5]).hasMatch() || !versionPattern.match(tags[6]).hasMatch())
        {
            return {};
        }
        QList<Candidate> rows; // 保留发布顺序；冲突行必须成对且同名。
        for (const auto& line : lines)
        {
            const auto cells = line.split(QLatin1Char('\t')); // 状态、限定名、偏移、类型、位域起点和宽度。
            if (cells.size() != 6 || cells[1].isEmpty() || cells[1].size() > 1024 || cells[3].size() > 1024)
            {
                return {};
            }
            const auto state = cells[0]; // 认不出的候选状态丢弃整片。
            const bool pending = !rows.isEmpty() && rows.constLast().source == Candidate::Source::Previous;
            if (pending != (state == QLatin1String("after")) || (pending && rows.constLast().field != cells[1]))
            {
                return {};
            }
            Candidate row; // 只接受展示文本，不计算目标地址。
            row.field = cells[1];
            if (state == QLatin1String("agree"))
            {
                row.source = Candidate::Source::Agreement;
                row.version = tags[5] + QStringLiteral(" / ") + tags[6];
            }
            else if (state == QLatin1String("before") || state == QLatin1String("after"))
            {
                row.source = pending ? Candidate::Source::Next : Candidate::Source::Previous;
                row.version = pending ? tags[6] : tags[5];
            }
            else
            {
                return {};
            }
            bool offsetValid = false; // 缺字段为空；零必须保持有效。
            const auto offset = cells[2].toUInt(&offsetValid, 10);
            if (cells[2].isEmpty() != cells[3].isEmpty() || (!cells[2].isEmpty() && (!offsetValid || offset > 65535)) ||
                (cells[2].isEmpty() && (row.source == Candidate::Source::Agreement || !cells[4].isEmpty() || !cells[5].isEmpty())))
            {
                return {};
            }
            row.offset = offsetValid ? QStringLiteral("0x%1").arg(offset, 4, 16, QLatin1Char('0')) : QString();
            row.type = cells[3];
            if (!cells[4].isEmpty() || !cells[5].isEmpty())
            {
                bool bitOk = false, widthOk = false; // 两列必须是一对有效数字。
                const auto bit = cells[4].toUInt(&bitOk);
                const auto width = cells[5].toUInt(&widthOk);
                if (!bitOk || !widthOk || bit >= 64 || !width || width > 64 - bit)
                {
                    return {};
                }
                row.type += QStringLiteral(" [%1:%2]").arg(bit).arg(width);
            }
            rows.append(std::move(row));
        }
        return !rows.isEmpty() && rows.constLast().source != Candidate::Source::Previous ? rows : QList<Candidate>{};
    }

    QList<Candidate> CompareCandidates(const threadlayout::Profile& previous, const threadlayout::Profile& next,
        const threadlayout::Neighbors& neighbors, const threadlayout::Kind kind)
    {
        struct Field
        {
            threadlayout::Field metadata; // 原始相对偏移、类型、位域和联合体语义。
            std::uint32_t absolute = 0; // 仅用于比较父结构移动后的字段位置，不计算目标地址。
        };
        const auto flatten = [kind](const threadlayout::Profile& profile) // 输入精确包内布局，输出限定名索引。
        {
            QMap<QString, Field> fields; // 确保前后两个布局的同名字段稳定配对。
            QList<QPair<QString, std::uint32_t>> parents{{kind == threadlayout::Kind::Thread ?
                QStringLiteral("_ETHREAD") : QStringLiteral("_EPROCESS"), 0}}; // 根名称与结构类别一致。
            for (const auto& field : profile.fields)
            {
                const auto& parent = parents.at(field.parent); // 精确布局加载器已检查父行编号和范围。
                const auto path = parent.first + QLatin1Char('.') + QString::fromStdString(field.name);
                const auto absolute = parent.second + field.offset; // 根内相对位置，绝不提供给采样后端。
                fields.insert(path, {field, absolute});
                parents.append({path, absolute});
            }
            return fields;
        };
        const auto before = flatten(previous); // 较早版本的规范成员路径。
        const auto after = flatten(next); // 较晚版本的规范成员路径。
        auto names = before.keys(); // 按成员路径顺序生成参考树行。
        for (const auto& name : after.keys())
        {
            if (!before.contains(name))
            {
                names.append(name);
            }
        }
        names.sort();
        const auto version = [](const threadlayout::Version& value) // 输入数字版本，输出来源文字。
        {
            return QStringLiteral("%1.%2.%3.%4").arg(value[0]).arg(value[1]).arg(value[2]).arg(value[3]);
        };
        QList<Candidate> rows; // 单侧缺失不能伪造双侧一致，也不能产生红色冲突。
        const auto append = [&rows, &version](const QString& name, const Field* field,
            const Candidate::Source source, const threadlayout::Version& from)
        {
            Candidate row; // 只显示包内符号元数据，永远不填入现场值。
            row.field = name;
            row.source = source;
            row.version = version(from);
            if (field)
            {
                row.offset = QStringLiteral("0x%1").arg(field->metadata.offset, 4, 16, QLatin1Char('0'));
                row.type = QString::fromStdString(field->metadata.type);
                if (field->metadata.bitOffset >= 0)
                {
                    row.type += QStringLiteral(" [%1:%2]").arg(field->metadata.bitOffset).arg(field->metadata.bitWidth);
                }
            }
            rows.append(std::move(row));
        };
        for (const auto& name : names)
        {
            const auto old = before.constFind(name); // 两个迭代器均来自各自稳定的只读映射。
            const auto newer = after.constFind(name);
            const bool hasOld = old != before.cend(); // 缺少字段仍要保留明确的该版无字段行。
            const bool hasNew = newer != after.cend();
            if (!neighbors.bracketed || previous.fields.empty() || next.fields.empty())
            {
                append(name, hasOld ? &old.value() : &newer.value(), Candidate::Source::Single,
                    hasOld ? neighbors.previous.version : neighbors.next.version);
                continue;
            }
            const bool agree = hasOld && hasNew && old->absolute == newer->absolute &&
                old->metadata.offset == newer->metadata.offset && old->metadata.type == newer->metadata.type &&
                old->metadata.bitOffset == newer->metadata.bitOffset && old->metadata.bitWidth == newer->metadata.bitWidth &&
                old->metadata.unionAlias == newer->metadata.unionAlias; // 父项移动也会使子项判为冲突。
            if (agree)
            {
                append(name, &old.value(), Candidate::Source::Agreement, neighbors.previous.version);
                rows.last().version += QStringLiteral(" / ") + version(neighbors.next.version);
            }
            else
            {
                append(name, hasOld ? &old.value() : nullptr, Candidate::Source::Previous, neighbors.previous.version);
                append(name, hasNew ? &newer.value() : nullptr, Candidate::Source::Next, neighbors.next.version);
            }
        }
        return rows;
    }

    void ColorReferenceRow(QStandardItem& item, const bool yellow)
    {
        auto* parent = item.parent(); // 共享结构树每行均有明确父项，保持整行颜色一致。
        if (!parent && !item.model())
        {
            return;
        }
        QColor tint = KswordTheme::AccentColor(yellow ? KswordTheme::AccentRole::Yellow : KswordTheme::AccentRole::Red);
        tint.setAlpha(yellow ? 52 : 68); // 风险底色不覆盖文字、选择与焦点语义。
        const int count = parent ? parent->columnCount() : item.model()->columnCount(); // 顶层根的父项由模型隐式持有。
        for (int column = 0; column < count; ++column)
        {
            if (auto* cell = parent ? parent->child(item.row(), column) : item.model()->item(item.row(), column))
            {
                cell->setBackground(tint);
            }
        }
    }

    void ColorUnbracketedTree(QStandardItem& root)
    {
        ColorReferenceRow(root, true); // 无双侧边界时不保留内部红色，整棵 R0 子树统一为黄色。
        for (int row = 0; row < root.rowCount(); ++row)
        {
            if (auto* child = root.child(row, 0)) // 只递归第零列节点，避免重复遍历同一行。
            {
                ColorUnbracketedTree(*child);
            }
        }
    }

    QStandardItem* AppendCandidates(QStandardItem& root, const QList<Candidate>& rows, const bool forceYellow)
    {
        if (rows.isEmpty())
        {
            return nullptr;
        }
        const auto empty = QStringLiteral("—"); // 候选行绝不显示目标地址。
        auto* group = Append(root, {empty, empty, i18n::displayText(QStringLiteral("邻版布局参考")), {},
            i18n::displayText(QStringLiteral("参考偏移不代表现场读值"))});
        for (const auto& row : rows)
        {
            const bool single = forceYellow || row.source == Candidate::Source::Single; // 无双侧边界时，黄色优先于原冲突标签。
            const bool agree = row.source == Candidate::Source::Agreement;
            const auto source = i18n::displayText(single ? QStringLiteral("未被双侧版本夹住 · 仅参考") :
                agree ? QStringLiteral("双侧一致 · 待验证") :
                row.source == Candidate::Source::Previous ? QStringLiteral("前版候选 · 只读") : QStringLiteral("后版候选 · 只读"));
            const auto detail = row.offset.isEmpty() ? i18n::displayText(QStringLiteral("该版无此字段")) :
                i18n::displayText(QStringLiteral("仅布局，未采样"));
            auto* item = Append(*group, {row.offset.isEmpty() ? empty : row.offset, empty, row.field, row.type,
                QStringLiteral("%1 · %2 · %3").arg(source, row.version, detail)});
            ColorReferenceRow(*item, single || agree);
        }
        return group;
    }
}
