#include "KernelStructureTree.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TablePresentation.h"
#include "../UI/PageControlStyle.h"
#include "../theme.h"

#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QTreeView>
#include <limits>

namespace ks::ui::kernelstructure
{
    namespace
    {
        // 将相对偏移或地址显示为十六进制；零是合法值。
        QString Hex(const std::uint64_t value, const int width = 0)
        {
            return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), width, 16, QLatin1Char('0'));
        }
    }

    Layout LoadLayout(const threadlayout::Kind kind)
    {
        Layout result; // 找不到分片时保留原固定字段结果。
        const auto identity = threadlayout::ReadImageIdentity(); // 匹配系统磁盘内核 RSDS。
        if (identity.pdbKey.empty())
        {
            return result;
        }
        const auto directory = std::filesystem::path(QCoreApplication::applicationDirPath().toStdWString()) /
            L"profiles" / threadlayout::Directory(kind); // 发布目录的独立分片。
        const auto catalog = threadlayout::LoadCatalog(directory); // 只比较实际包内分片对应的数字文件版本。
        auto version = threadlayout::ReadImageVersion(); // 当前磁盘 PE 的固定文件版本，不按时间戳推断先后。
        const auto neighbors = threadlayout::SelectNeighbors(catalog, identity, version); // 缺少一侧必须黄色。
        const auto previous = neighbors.previous.identity.pdbKey.empty() ? threadlayout::Profile{} :
            threadlayout::Load(directory / threadlayout::FileName(neighbors.previous.identity), &neighbors.previous.identity, kind);
        const auto next = neighbors.next.identity.pdbKey.empty() ? threadlayout::Profile{} :
            threadlayout::Load(directory / threadlayout::FileName(neighbors.next.identity), &neighbors.next.identity, kind);
        result.bracketed = neighbors.bracketed && !previous.fields.empty() && !next.fields.empty();
        result.profile = threadlayout::Load(directory / threadlayout::FileName(identity), &identity, kind);
        if (result.profile.fields.empty())
        {
            auto sidecar = directory / threadlayout::FileName(identity); // 不寻找不匹配的旧版完整分片。
            sidecar += L".neighbors";
            result.candidates = LoadCandidates(sidecar, identity);
            if (result.candidates.isEmpty())
            {
                result.candidates = CompareCandidates(previous, next, neighbors, kind); // 无精确布局也能显示包内前后参考，绝不授权采样。
            }
        }
        if (!result.profile.fields.empty())
        {
            const auto status = ksword::ark::DriverClient().queryDynDataStatus(); // 只取现有模块身份回执。
            result.runningMatch = status.io.ok && status.ntoskrnl.present &&
                status.ntoskrnl.machine == identity.machine && status.ntoskrnl.timeDateStamp == identity.timestamp &&
                status.ntoskrnl.sizeOfImage == identity.imageSize;
        }
        return result;
    }

    Samples ProjectedSamples(const threadlayout::Profile& profile, const structure_sample::Projection& projection)
    {
        Samples result; // 身份不匹配或行数不完整时，不生成可显示的现场回执。
        if (!projection.identityMatched || profile.fields.size() != projection.fields.size())
        {
            return result;
        }
        for (std::size_t index = 0; index < projection.fields.size(); ++index)
        {
            const auto& value = projection.fields[index]; // 与精确符号行一一对应的值和状态。
            Sample sample; // 未解码行也保留原因，不伪装成后端从未尝试读取。
            sample.offset = value.offset;
            sample.value = QString::fromStdString(value.text);
            sample.type = QString::fromStdString(profile.fields[index].type);
            sample.status = value.status;
            sample.unionInterpretation = value.unionInterpretation;
            sample.byteValidityVerified = value.status == structure_sample::FieldStatus::Sampled;
            sample.zeroValue = sample.byteValidityVerified && value.value == 0;
            sample.width = value.width;
            result.insert(QString::fromStdString(value.path), std::move(sample));
        }
        return result;
    }

    void Configure(QTreeView& tree, QStandardItemModel& model, QSortFilterProxyModel& filter, QLineEdit& search)
    {
        model.setHorizontalHeaderLabels({i18n::displayText(QStringLiteral("相对偏移")),
            i18n::displayText(QStringLiteral("地址")), i18n::displayText(QStringLiteral("字段")),
            i18n::displayText(QStringLiteral("类型")), i18n::displayText(QStringLiteral("实际值 / 解释值"))});
        filter.setSourceModel(&model);
        filter.setFilterKeyColumn(-1);
        filter.setFilterCaseSensitivity(Qt::CaseInsensitive);
        filter.setRecursiveFilteringEnabled(true);
        filter.setAutoAcceptChildRows(true);
        tree.setModel(&filter); // 复制、搜索、展示共用规范模型。
        tree.setTreePosition(2);
        tree.setEditTriggers(QAbstractItemView::NoEditTriggers);
        tree.setSelectionBehavior(QAbstractItemView::SelectRows);
        tree.setWordWrap(false);
        tree.setAlternatingRowColors(true);
        auto* header = tree.header(); // 固定五列，窄窗可水平滚动并手工调宽。
        header->setSectionsMovable(false);
        header->setSectionResizeMode(QHeaderView::Interactive);
        header->resizeSection(0, 102);
        header->resizeSection(1, 180);
        header->resizeSection(2, 214);
        header->resizeSection(3, 160);
        header->resizeSection(4, 285);
        header->setStretchLastSection(true);
        ApplyTablePresentation(&tree); // 专业树无重复表格操作条。

        search.setPlaceholderText(i18n::displayText(QStringLiteral("搜索字段或值")));
        search.setAccessibleName(search.placeholderText());
        search.setClearButtonEnabled(true);
        search.setMaximumWidth(320);
        StyleSearchField(&search);
        QObject::connect(&search, &QLineEdit::textChanged, &tree, [&filter, &tree](const QString& query)
        {
            const auto text = query.trimmed(); // 过滤规范数据，不请求重采样。
            filter.setFilterFixedString(text);
            if (!text.isEmpty())
            {
                tree.expandAll();
            }
        });

        tree.setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(&tree, &QTreeView::customContextMenuRequested, &tree, [&tree](const QPoint& point)
        {
            const auto index = tree.indexAt(point); // 冻结点击项，菜单期间异步更新不会更改复制目标。
            if (!index.isValid())
            {
                return;
            }
            const auto cell = index.data().toString(); // 单格原始显示文本。
            QStringList cells; // 五列制表符记录。
            for (int column = 0; column < tree.model()->columnCount(index.parent()); ++column)
            {
                cells.append(index.siblingAtColumn(column).data().toString());
            }
            QMenu menu; // 直接使用不透明的共享菜单样式。
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            auto* copyCell = menu.addAction(i18n::displayText(QStringLiteral("复制单元格")));
            auto* copyRow = menu.addAction(i18n::displayText(QStringLiteral("复制行")));
            const auto* selected = menu.exec(tree.viewport()->mapToGlobal(point));
            if (selected == copyCell || selected == copyRow)
            {
                QApplication::clipboard()->setText(selected == copyCell ? cell : cells.join(QLatin1Char('\t')));
            }
        });
    }

    QStandardItem* Append(QStandardItem& parent, const QStringList& cells, const bool prepend)
    {
        QList<QStandardItem*> row; // 父模型负责释放各个新单元格。
        for (const auto& cell : cells)
        {
            auto* item = new QStandardItem(cell);
            item->setToolTip(cell);
            item->setEditable(false);
            row.append(item);
        }
        if (prepend)
        {
            parent.insertRow(0, row);
        }
        else
        {
            parent.appendRow(row);
        }
        return row.first();
    }

    void AppendLayout(QStandardItem& root, const Layout& layout, const std::uint64_t base, const Samples& live)
    {
        struct Path
        {
            QStandardItem* item; // Qt 树上的父行第 0 列。
            QString name; // 累积限定名，与固定回执索引对接。
            std::uint32_t absolute; // 相对于结构根的偏移，不是裸系统地址。
            bool unionAlias; // 含未知活动分支的任意祖先。
        };
        QList<Path> paths{{&root, {}, 0, false}}; // 布局文件已校验父行只引用先前行。
        const auto empty = QStringLiteral("—"); // 无运行时证据时不填入地址。
        const auto unread = i18n::displayText(QStringLiteral("仅布局，未采样"));
        const auto alias = i18n::displayText(QStringLiteral("联合体活动分支未知"));
        for (const auto& field : layout.profile.fields)
        {
            const auto& parent = paths.at(field.parent); // 以直接父对象为偏移基准。
            const auto name = QString::fromUtf8(field.name); // 保留符号原名，不翻译。
            const auto path = parent.name.isEmpty() ? name : parent.name + QLatin1Char('.') + name;
            const auto absolute = parent.absolute + field.offset;
            const bool ambiguous = parent.unionAlias || field.unionAlias;
            const auto value = live.constFind(path); // 只有固定协议证实的位置和值才会填入此列。
            const auto address = layout.runningMatch && base && absolute <= (std::numeric_limits<std::uint64_t>::max)() - base
                ? Hex(base + absolute) : empty;
            const bool hasSample = value != live.cend() && value->offset == absolute; // 名称和偏移同时匹配。
            const bool hasValue = hasSample && value->status == structure_sample::FieldStatus::Sampled &&
                (!ambiguous || value->unionInterpretation); // union 只有显式原始解释才可显示。
            QString text = hasValue ? value->value : ambiguous ? alias : unread; // 当前行自己的读取结果。
            if (hasValue && value->unionInterpretation)
            {
                text += QStringLiteral(" · ") + i18n::displayText(QStringLiteral("联合体原始解释；活动分支未知"));
            }
            else if (hasSample)
            {
                switch (value->status)
                {
                case structure_sample::FieldStatus::Aggregate:
                    text = i18n::displayText(QStringLiteral("结构容器；展开查看成员"));
                    break;
                case structure_sample::FieldStatus::UnsupportedType:
                    text = i18n::displayText(QStringLiteral("已采集快照；暂不支持此类型解码"));
                    break;
                case structure_sample::FieldStatus::OutsideSnapshot:
                    text = i18n::displayText(QStringLiteral("本次未完整读取该字段"));
                    break;
                case structure_sample::FieldStatus::InvalidLayout:
                    text = i18n::displayText(QStringLiteral("字段边界或位域描述无效"));
                    break;
                case structure_sample::FieldStatus::Sampled:
                    break;
                }
            }
            auto* item = Append(*parent.item, {Hex(field.offset, 4), address, name, QString::fromUtf8(field.type), text});
            if (!layout.bracketed)
            {
                ColorReferenceRow(*item, true); // 早于、晚于或缺少任意一侧版本时，所有布局字段一律黄色。
            }
            if (hasValue && value->byteValidityVerified)
            {
                const auto proof = i18n::displayText(value->zeroValue ?
                    QStringLiteral("已采集零值；字段所需的 %1 字节全部有效，不是读取失败填零") :
                    QStringLiteral("字段所需的 %1 字节全部有效；仅解释本次快照字节"))
                    .arg(value->width); // 零值需要额外可核对证据，不通过颜色宣称值是否合理。
                for (int column = 0; column < parent.item->columnCount(); ++column)
                {
                    auto* cell = parent.item->child(item->row(), column); // 同一字段整行悬停均能核对有效性。
                    cell->setToolTip(cell->text() + QLatin1Char('\n') + proof);
                }
            }
            paths.append({item, path, absolute, ambiguous});
        }
    }

    QString LayoutStatus(const Layout& layout)
    {
        if (layout.profile.fields.empty())
        {
            return i18n::displayText(layout.candidates.isEmpty() ? QStringLiteral("未找到匹配的符号布局") :
                QStringLiteral("仅有邻版布局参考"));
        }
        const auto label = layout.runningMatch ? QStringLiteral("匹配符号布局") : QStringLiteral("磁盘符号布局，运行内核未核验");
        return QStringLiteral("%1 · %2").arg(i18n::displayText(label), QString::fromStdString(layout.profile.identity.pdbKey));
    }
}
