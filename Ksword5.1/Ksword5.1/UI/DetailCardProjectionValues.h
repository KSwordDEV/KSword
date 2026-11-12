#pragma once

#include "StructuredFieldView.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <deque>

namespace ks::ui::detail_cards
{
    // Pure values. The GUI reads a bounded slice; canonical copy/export still
    // belongs to StructuredFieldView, never to the materialized QLabel subset.
    struct Field
    {
        QString name, value, semantic, searchContext;
        bool note = false;
        int column = 0;
    };
    class Heights
    {
    public:
        void append(qint64 height) { m_values.append(qMax<qint64>(0, height)); }
        void build()
        {
            m_tree.fill(0, m_values.size() + 1);
            for (qsizetype i = 0; i < m_values.size(); ++i)
            {
                m_tree[i + 1] += m_values.at(i);
                const qsizetype next = (i + 1) + ((i + 1) & -(i + 1));
                if (next < m_tree.size()) m_tree[next] += m_tree.at(i + 1);
            }
        }
        qsizetype size() const { return m_values.size(); }
        qint64 at(qsizetype index) const { return m_values.at(index); }
        qint64 prefix(qsizetype count) const
        {
            qint64 value = 0;
            for (; count > 0; count -= count & -count) value += m_tree.at(count);
            return value;
        }
        qint64 total() const { return prefix(size()); }
        bool set(qsizetype index, qint64 height)
        {
            height = qMax<qint64>(0, height);
            const qint64 difference = height - m_values.at(index);
            if (!difference) return false;
            m_values[index] = height;
            for (qsizetype i = index + 1; i < m_tree.size(); i += i & -i) m_tree[i] += difference;
            return true;
        }
        qsizetype containing(qint64 position) const
        {
            qsizetype index = 0, bit = 1;
            while (bit <= size() / 2) bit *= 2;
            qint64 sum = 0;
            for (; bit; bit /= 2)
            {
                const qsizetype next = index + bit;
                if (next <= size() && sum + m_tree.at(next) <= position)
                { index = next; sum += m_tree.at(next); }
            }
            return qMin(index, size());
        }
    private:
        QVector<qint64> m_values, m_tree;
    };
    struct Section
    {
        QString title;
        QVector<Field> fields;
        std::array<QVector<int>, 3> accepted;
        int fieldCount = 0;
        QVector<int> acceptedOrder;
    };
    struct RowWindow { qsizetype begin = 0, end = 0; };
    inline RowWindow rowWindow(const Heights& heights, qint64 columnStart, qint64 firstPixel, qint64 lastPixel)
    {
        if (lastPixel <= columnStart || firstPixel >= columnStart + heights.total() || lastPixel <= firstPixel) return {};
        const qsizetype first = heights.containing(qMax<qint64>(0, firstPixel - columnStart));
        const qsizetype last = qMin(heights.size(), heights.containing(qMax<qint64>(0, lastPixel - columnStart - 1)) + 1);
        return { first, last };
    }
    struct Geometry
    {
        std::array<Heights, 3> columns;
        std::array<int, 3> labelWidths{}; // 整段规范字段共同决定名称列宽，虚拟窗口滚动不重新求宽。
        qint64 header = 0;
        bool twoColumns = false;
        qint64 columnHeight(int column) const { return qMax<qint64>(0, columns[column].total() - (columns[column].size() ? 6 : 0)); }
        qint64 columnStart(int column) const
        {
            if (column == 0) return header;
            if (column == 1) return header + (twoColumns ? 0 : columnHeight(0) + (columns[0].size() && columns[1].size() ? 16 : 0));
            return header + (twoColumns ? qMax(columnHeight(0), columnHeight(1))
                : columnHeight(0) + columnHeight(1) + (columns[0].size() && columns[1].size() ? 16 : 0))
                + (columns[2].size() && (columns[0].size() || columns[1].size()) ? 10 : 0);
        }
        qint64 height() const { return columnStart(2) + columnHeight(2) + 14; }
    };
    struct Projection
    {
        QVector<Section> sections;
        QVector<Geometry> geometry; // UI-owned mutable height corrections, never read by workers.
        Heights sectionsHeight;
        QString query;
        bool sameStructure = false;
    };
    using Translate = std::function<QString(const QString&)>;
    using Measure = std::function<int(const Field&, bool)>;

    inline std::shared_ptr<Projection> prepare(const FieldDocument& document, const Translate& translate,
        const QString& search, bool wide, int lineHeight, const Measure& measure,
        const std::shared_ptr<const Projection>& previous = {}, const std::shared_ptr<std::atomic_bool>& cancel = {})
    {
        auto result = std::make_shared<Projection>();
        result->query = search.trimmed();
        auto canceled = [&] { return cancel && cancel->load(std::memory_order_relaxed); };
        Section loose{translate(document.title)};
        const auto flatten = [&](const QVector<FieldNode>& roots, Section& section)
        {
            struct Cursor { const FieldNode* node; QString prefix, ancestors; };
            QVector<Cursor> pending;
            for (auto it = roots.crbegin(); it != roots.crend(); ++it) pending.append({&*it, {}, {}});
            while (!pending.isEmpty())
            {
                if (canceled()) return false;
                Cursor cursor = pending.takeLast();
                const auto& node = *cursor.node;
                const QString name = node.translateName ? translate(node.name) : node.name;
                const QString path = cursor.prefix.isEmpty() ? name : cursor.prefix + QStringLiteral(" / ") + name;
                const QString value = node.translateValue ? translate(node.value) : node.value;
                const QString context = cursor.ancestors + QLatin1Char('\n') + name + QLatin1Char(' ') + value;
                if (node.kind == FieldNode::Kind::Field)
                {
                    const QString semantic = node.value == QStringLiteral("Enabled") || node.value == QStringLiteral("Enabled (permanent)")
                        || (node.name == QStringLiteral("管理员") && node.value == QStringLiteral("是")) ? QStringLiteral("success")
                        : node.value == QStringLiteral("Disabled") || (node.name == QStringLiteral("管理员") && node.value == QStringLiteral("否"))
                            ? QStringLiteral("error") : QString();
                    section.fields.append({path, value, semantic, context, false, 0});
                    ++section.fieldCount;
                }
                else if (node.kind == FieldNode::Kind::Note)
                    section.fields.append({{}, translate(node.value), {}, context, true, 2});
                for (auto it = node.children.crbegin(); it != node.children.crend(); ++it)
                    pending.append({&*it, node.kind == FieldNode::Kind::Note ? cursor.prefix : path, context});
            }
            return true;
        };
        const auto append = [&](Section&& section)
        {
            Geometry geometry;
            geometry.header = 14 + (section.title.isEmpty() ? 0
                : qMax(lineHeight, measure(Field{{}, section.title, {}, {}, true, 2}, false)) + 10);
            geometry.twoColumns = wide && section.fieldCount >= 8;
            const bool groupMatch = !result->query.isEmpty() && section.title.contains(result->query, Qt::CaseInsensitive);
            int ordinal = 0;
            for (int index = 0; index < section.fields.size(); ++index)
            {
                if (canceled()) return;
                auto& field = section.fields[index];
                if (!field.note) field.column = section.fieldCount >= 8 && ordinal++ >= (section.fieldCount + 1) / 2 ? 1 : 0;
                const bool accepted = result->query.isEmpty() || groupMatch || field.name.contains(result->query, Qt::CaseInsensitive)
                    || field.value.contains(result->query, Qt::CaseInsensitive) || field.searchContext.contains(result->query, Qt::CaseInsensitive);
                if (accepted)
                {
                    section.accepted[field.column].append(index);
                    section.acceptedOrder.append(index);
                    geometry.columns[field.column].append(qMax(lineHeight, measure(field, geometry.twoColumns)) + 6);
                }
            }
            for (auto& column : geometry.columns) column.build();
            const bool visible = !section.accepted[0].isEmpty() || !section.accepted[1].isEmpty() || !section.accepted[2].isEmpty();
            result->sectionsHeight.append(visible ? geometry.height() + 14 : 0);
            result->sections.append(std::move(section));
            result->geometry.append(std::move(geometry));
        };
        QVector<FieldNode> pendingLoose;
        for (const auto& node : document.nodes)
        {
            if (canceled()) return {};
            if (node.kind != FieldNode::Kind::Section) { pendingLoose.append(node); continue; }
            if (!pendingLoose.isEmpty())
            {
                if (!flatten(pendingLoose, loose)) return {};
                append(std::move(loose)); loose = Section{translate(document.title)}; pendingLoose.clear();
            }
            Section section{node.translateName ? translate(node.name) : node.name};
            if (!flatten(node.children, section)) return {};
            append(std::move(section));
        }
        if (!pendingLoose.isEmpty()) { if (!flatten(pendingLoose, loose)) return {}; append(std::move(loose)); }
        result->sectionsHeight.build();
        for (int index = 0; index < result->geometry.size(); ++index)
        {
            const auto& s = result->sections.at(index);
            const bool visible = !s.accepted[0].isEmpty() || !s.accepted[1].isEmpty() || !s.accepted[2].isEmpty();
            result->sectionsHeight.set(index, visible ? result->geometry.at(index).height() + 14 : 0);
        }
        result->sameStructure = previous && previous->sections.size() == result->sections.size();
        for (int s = 0; result->sameStructure && s < result->sections.size() && !canceled(); ++s)
        {
            const auto& a = result->sections.at(s); const auto& b = previous->sections.at(s);
            result->sameStructure = a.title == b.title && a.fields.size() == b.fields.size();
            for (int r = 0; result->sameStructure && r < a.fields.size() && !canceled(); ++r)
                result->sameStructure = a.fields.at(r).name == b.fields.at(r).name && a.fields.at(r).note == b.fields.at(r).note;
        }
        return canceled() ? std::shared_ptr<Projection>() : result;
    }

    inline qint64 logicalTop(int physical, int physicalHeight, int viewportHeight, qint64 logicalHeight)
    {
        if (physical <= 0 || logicalHeight <= physicalHeight) return physical;
        return static_cast<qint64>(static_cast<long double>(physical) * qMax<qint64>(0, logicalHeight - viewportHeight)
            / qMax(1, physicalHeight - viewportHeight));
    }
    inline int physicalTop(qint64 logical, int physicalHeight, int viewportHeight, qint64 logicalHeight)
    {
        if (logical <= 0 || logicalHeight <= physicalHeight) return static_cast<int>(logical);
        return static_cast<int>(static_cast<long double>(logical) * qMax(0, physicalHeight - viewportHeight)
            / qMax<qint64>(1, logicalHeight - viewportHeight));
    }

    inline std::shared_ptr<Projection> workerOwned(std::shared_ptr<Projection> values,
        std::function<void(std::function<void()>)> schedule)
    {
        if (!values) return {};
        return std::shared_ptr<Projection>(new Projection(std::move(*values)), [schedule = std::move(schedule)](Projection* value)
            { schedule([value] { delete value; }); });
    }

    // A row is the disposal unit, including intentionally pinned selections.
    // The QWidget integration supplies the two small operations; tests use the
    // same queue/budget algorithm without constructing any widgets.
    template<class Card, class ReleaseRow, class ReleaseCard>
    int drainBudget(std::deque<Card>& cards, int budget, const ReleaseRow& releaseRow, const ReleaseCard& releaseCard)
    {
        int used = 0;
        while (used < budget && !cards.empty())
        {
            ++used;
            if (!releaseRow(cards.front())) { releaseCard(cards.front()); cards.pop_front(); }
        }
        return used;
    }
}
