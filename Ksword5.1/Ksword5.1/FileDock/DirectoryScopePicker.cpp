#include "DirectoryScopePicker.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TablePresentation.h"
#include "../UI/VisibleTableWidget.h"

#include <QDir>
#include <QEvent>
#include <QFileSystemModel>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QTreeView>
#include <QVBoxLayout>

DirectoryScopePicker::DirectoryScopePicker(QWidget* parent) : QWidget(parent)
{
    setObjectName(QStringLiteral("disk_space_scope_picker"));
    setMinimumSize(0, 0);
    setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    m_model = new QFileSystemModel(this);
    m_model->setReadOnly(true);
    m_model->setOption(QFileSystemModel::DontUseCustomDirectoryIcons, true);
    m_model->setOption(QFileSystemModel::DontResolveSymlinks, true);
    m_model->setFilter(QDir::Dirs | QDir::Drives | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot);

    m_tree = new QTreeView(this);
    m_tree->setObjectName(QStringLiteral("disk_space_scope_tree"));
    m_tree->setMinimumSize(0, 100);
    m_tree->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    m_tree->setUniformRowHeights(true);
    m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tree->setDragDropMode(QAbstractItemView::NoDragDrop);
    m_tree->setAnimated(false);
    m_tree->setModel(m_model);
    for (int column = 1; column < m_model->columnCount(); ++column) m_tree->hideColumn(column);
    m_tree->setHeaderHidden(true);
    m_tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    ks::ui::SetTableColumnAutoFitEnabled(m_tree, false);
    m_tree->setProperty(ks::ui::TableActionBarModeProperty, int(ks::ui::TableActionBarMode::None));
    ks::ui::ApplyTablePresentation(m_tree);
    layout->addWidget(m_tree, 1);

    m_summary = new QLabel(this);
    m_summary->setObjectName(QStringLiteral("disk_space_scope_summary"));
    m_summary->setTextFormat(Qt::PlainText);
    m_summary->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    m_summary->installEventFilter(this);
    layout->addWidget(m_summary);

    connect(m_tree->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this](const QModelIndex& index, const QModelIndex&) {
            // FilePathRole comes from the model's metadata cache. Do not add
            // a synchronous QFileInfo/exists/access check on this UI path.
            const QString selected = index.isValid()
                ? QDir::toNativeSeparators(m_model->data(index, QFileSystemModel::FilePathRole).toString()) : QString();
            if (selected == m_selectedPath) return;
            m_selectedPath = selected;
            updateSummary();
            // Copy both values so a page callback may safely replace this
            // widget without the invocation borrowing any member afterward.
            const auto callback = selectionChanged;
            if (callback) callback(selected);
        });

    // Empty root exposes the standard drive list. Never pre-expand a drive,
    // call expandAll(), or use a selected folder as an eager recursive root.
    // QFileSystemModel performs each requested directory fetch on its worker.
    m_model->setRootPath(QString());
    updateTranslations();
}

QSize DirectoryScopePicker::sizeHint() const
{
    return QSize(300, 320);
}

void DirectoryScopePicker::updateSummary()
{
    if (!m_summary) return;
    const QString summary = m_selectedPath.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("尚未选择扫描范围")) : m_selectedPath;
    m_summary->setText(m_summary->fontMetrics().elidedText(summary, Qt::ElideMiddle, m_summary->width()));
    m_summary->setToolTip(summary);
    m_summary->setAccessibleName(summary);
}

void DirectoryScopePicker::updateTranslations()
{
    const QString title = ks::i18n::sourceText(QStringLiteral("选择扫描文件夹"));
    const QString hint = ks::i18n::sourceText(QStringLiteral("展开磁盘并选择文件夹，点击“开始扫描”后才统计空间。这里只显示目录；无权限或不可用的目录会在扫描时报告，目录链接和脱机内容会跳过。"));
    m_tree->setAccessibleName(title);
    m_tree->setToolTip(hint);
    m_tree->setWhatsThis(hint);
    updateSummary();
}

void DirectoryScopePicker::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_tree && m_summary) updateTranslations();
}

bool DirectoryScopePicker::eventFilter(QObject* watched, QEvent* event)
{
    // Use the label's actual width after native layout geometry settles.
    if (watched == m_summary && (event->type() == QEvent::Resize || event->type() == QEvent::FontChange)) updateSummary();
    return QWidget::eventFilter(watched, event);
}
