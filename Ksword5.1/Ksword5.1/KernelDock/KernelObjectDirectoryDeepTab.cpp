
#include "KernelObjectDirectoryDeepTab.h"
#include "../UI/ToolbarMetrics.h"
#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"

#include <memory>

// ============================================================
// KernelObjectDirectoryDeepTab.cpp
// 作用说明：
// 1) 提供目录递归能力的独立 QWidget；
// 2) 后台调用 KernelObjectDirectoryDeepWorker；
// 3) 将结果以树和详情框形式展示。
// ============================================================

#include "../UI/StructuredFieldView.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <thread>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class DirectoryDeepColumn : int
    {
        Name = 0,
        Type,
        FullPath,
        Depth,
        Status,
        Count
    };

    constexpr int SourceIndexRole = Qt::UserRole + 1;
    constexpr qulonglong InvalidSourceIndex = std::numeric_limits<qulonglong>::max();

    QString normalizeObjectPathForUi(const QString& rawPath)
    {
        // 输入：用户输入或 Worker 返回的对象路径。
        // 处理：压缩斜杠并保证以 "\" 开头，便于树节点 key 统一。
        // 返回：规范化路径；空输入返回 "\"。
        QString path = rawPath.trimmed();
        path.replace('/', '\\');
        while (path.contains(QStringLiteral("\\\\")))
        {
            path.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }
        if (path.isEmpty())
        {
            return QStringLiteral("\\");
        }
        if (!path.startsWith('\\'))
        {
            path.prepend('\\');
        }
        while (path.size() > 1 && path.endsWith('\\'))
        {
            path.chop(1);
        }
        return path;
    }

    QString leafNameFromObjectPathForUi(const QString& objectPath)
    {
        // 输入：完整对象路径。
        // 处理：取末段名称，根路径返回 "\"。
        // 返回：树节点名称。
        const QString normalizedPath = normalizeObjectPathForUi(objectPath);
        if (normalizedPath == QStringLiteral("\\"))
        {
            return QStringLiteral("\\");
        }
        const int slashIndex = normalizedPath.lastIndexOf('\\');
        return slashIndex >= 0 ? normalizedPath.mid(slashIndex + 1) : normalizedPath;
    }

    QString parentPathFromObjectPathForUi(const QString& objectPath)
    {
        // 输入：完整对象路径。
        // 处理：取父路径，一级对象父路径为 "\"。
        // 返回：父目录路径。
        const QString normalizedPath = normalizeObjectPathForUi(objectPath);
        if (normalizedPath == QStringLiteral("\\"))
        {
            return QStringLiteral("\\");
        }
        const int slashIndex = normalizedPath.lastIndexOf('\\');
        if (slashIndex <= 0)
        {
            return QStringLiteral("\\");
        }
        return normalizedPath.left(slashIndex);
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        // 输入：颜色十六进制字符串。
        // 返回：状态标签样式字符串。
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QTreeWidgetItem* ensurePathItem(
        QTreeWidget* treeWidget,
        QMap<QString, QTreeWidgetItem*>& itemByPath,
        const QString& objectPath)
    {
        // 输入：树控件、路径到节点的缓存、要确保存在的对象路径。
        // 处理：递归确保父节点存在，再创建当前路径节点。
        // 返回：对应路径的树节点；treeWidget 为空时返回 nullptr。
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        const QString normalizedPath = normalizeObjectPathForUi(objectPath);
        QTreeWidgetItem* existingItem = itemByPath.value(normalizedPath, nullptr);
        if (existingItem != nullptr)
        {
            return existingItem;
        }

        QTreeWidgetItem* newItem = nullptr;
        if (normalizedPath == QStringLiteral("\\"))
        {
            newItem = new QTreeWidgetItem(treeWidget);
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Name), QStringLiteral("\\"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Type), QStringLiteral("Directory"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::FullPath), QStringLiteral("\\"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Depth), QStringLiteral("0"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Status), kernelText("kernel.object_directory.tree.root_status", QStringLiteral("根目录")));
        }
        else
        {
            QTreeWidgetItem* parentItem = ensurePathItem(
                treeWidget,
                itemByPath,
                parentPathFromObjectPathForUi(normalizedPath));
            newItem = new QTreeWidgetItem(parentItem != nullptr ? parentItem : treeWidget->invisibleRootItem());
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Name), leafNameFromObjectPathForUi(normalizedPath));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Type), QStringLiteral("Directory"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::FullPath), normalizedPath);
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Depth), QStringLiteral("-"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::Status), kernelText("kernel.object_directory.tree.parent_placeholder", QStringLiteral("父目录占位")));
        }
        newItem->setData(0, SourceIndexRole, InvalidSourceIndex);
        itemByPath.insert(normalizedPath, newItem);
        return newItem;
    }

    QString treeItemAsTsv(const QTreeWidget* treeWidget, const QTreeWidgetItem* treeItem)
    {
        // 输入：目录递归结果树和当前节点。
        // 处理：按当前列顺序读取文本，使用 Tab 分隔，便于复制到表格工具。
        // 返回：TSV 文本；输入为空时返回空字符串。
        if (treeWidget == nullptr || treeItem == nullptr)
        {
            return QString();
        }

        QStringList fieldList;
        fieldList.reserve(treeWidget->columnCount());
        for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
        {
            const QString cellText = treeItem->text(columnIndex).trimmed();
            fieldList.push_back(cellText.isEmpty() ? kernelText("kernel.object_directory.placeholder.empty", QStringLiteral("<空>")) : cellText);
        }
        return fieldList.join('\t');
    }

    void showTreeCopyRowMenu(QTreeWidget* treeWidget, const QPoint& localPosition)
    {
        // 输入：结果树和右键位置。
        // 处理：同步点击节点为当前节点，显示显式样式菜单并复制当前行。
        // 返回：无；无节点或剪贴板不可用时静默返回。
        if (treeWidget == nullptr)
        {
            return;
        }

        QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
        if (clickedItem != nullptr)
        {
            const int clickedColumn = treeWidget->columnAt(localPosition.x());
            treeWidget->setCurrentItem(clickedItem, clickedColumn >= 0 ? clickedColumn : 0);
        }

        QTreeWidgetItem* currentItem = treeWidget->currentItem();
        QMenu contextMenu(treeWidget);
        contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());

        QAction* copyRowAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.object_directory.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(currentItem != nullptr);

        const QAction* selectedAction = contextMenu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
        if (selectedAction != copyRowAction || currentItem == nullptr)
        {
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        const QString rowText = treeItemAsTsv(treeWidget, currentItem);
        if (clipboard != nullptr && !rowText.isEmpty())
        {
            clipboard->setText(rowText);
        }
    }
}

KernelObjectDirectoryDeepTab::KernelObjectDirectoryDeepTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelObjectDirectoryDeepTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    auto* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    auto* rootPathLabel = new QLabel(kernelText("kernel.object_directory.toolbar.root_path.label", QStringLiteral("根路径:")), this);
    m_rootPathEdit = new QLineEdit(this);
    m_rootPathEdit->setText(QStringLiteral("\\"));
    m_rootPathEdit->setPlaceholderText(kernelText("kernel.object_directory.toolbar.root_path.placeholder", QStringLiteral("\\、\\Device、\\BaseNamedObjects、\\Sessions")));
    m_rootPathEdit->setToolTip(kernelText("kernel.object_directory.toolbar.root_path.tooltip", QStringLiteral("Object Manager Directory 根路径，必须是 Directory 对象。")));

    auto* depthLabel = new QLabel(kernelText("kernel.object_directory.toolbar.max_depth.label", QStringLiteral("最大深度:")), this);
    m_maxDepthSpinBox = new QSpinBox(this);
    m_maxDepthSpinBox->setRange(0, 32);
    m_maxDepthSpinBox->setValue(4);
    m_maxDepthSpinBox->setToolTip(kernelText("kernel.object_directory.toolbar.max_depth.tooltip", QStringLiteral("只对 TypeName == Directory 的对象继续下钻，达到深度后停止。")));

    m_refreshButton = new QPushButton(kernelText("kernel.object_directory.toolbar.refresh", QStringLiteral("刷新")), this);
    m_refreshButton->setToolTip(kernelText("kernel.object_directory.toolbar.refresh.tooltip", QStringLiteral("后台递归枚举指定 Object Manager Directory。")));

    m_statusLabel = new QLabel(kernelText("kernel.object_directory.status.waiting", QStringLiteral("状态：等待刷新")), this);
    m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));

    toolLayout->addWidget(rootPathLabel, 0);
    toolLayout->addWidget(m_rootPathEdit, 1);
    toolLayout->addWidget(depthLabel, 0);
    toolLayout->addWidget(m_maxDepthSpinBox, 0);
    toolLayout->addWidget(m_refreshButton, 0);
    toolLayout->addWidget(m_statusLabel, 0);
    ks::ui::NormalizeToolbarRow(toolLayout);
    rootLayout->addLayout(toolLayout);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    rootLayout->addWidget(splitter, 1);

    m_resultTree = new QTreeWidget(splitter);
    m_resultTree->setColumnCount(static_cast<int>(DirectoryDeepColumn::Count));
    m_resultTree->setHeaderLabels(QStringList{
        kernelText("kernel.object_directory.header.name", QStringLiteral("名称")),
        kernelText("kernel.object_directory.header.type", QStringLiteral("类型")),
        kernelText("kernel.object_directory.header.full_path", QStringLiteral("完整路径")),
        kernelText("kernel.object_directory.header.depth", QStringLiteral("深度")),
        kernelText("kernel.object_directory.header.status", QStringLiteral("状态"))
        });
    m_resultTree->setAlternatingRowColors(true);
    m_resultTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_resultTree->setRootIsDecorated(true);
    m_resultTree->setContextMenuPolicy(Qt::CustomContextMenu);
    if (m_resultTree->header() != nullptr)
    {
        m_resultTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
        m_resultTree->header()->setSectionResizeMode(static_cast<int>(DirectoryDeepColumn::FullPath), QHeaderView::Stretch);
    }

    m_detailEditor = new ks::ui::StructuredFieldView(splitter);

    m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.object_directory.detail.initial", QStringLiteral("输入根路径后点击刷新。"))));

    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(m_resultTree, m_detailEditor, this);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        startRefresh();
    });
    connect(m_rootPathEdit, &QLineEdit::returnPressed, this, [this]() {
        startRefresh();
    });
    connect(m_resultTree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*) {
        showCurrentItemDetail();
    });
    connect(m_resultTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showTreeCopyRowMenu(m_resultTree, localPosition);
    });
}

void KernelObjectDirectoryDeepTab::setRefreshRunning(const bool running)
{
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(!running);
    }
    if (m_rootPathEdit != nullptr)
    {
        m_rootPathEdit->setEnabled(!running);
    }
    if (m_maxDepthSpinBox != nullptr)
    {
        m_maxDepthSpinBox->setEnabled(!running);
    }
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(running
            ? kernelText("kernel.object_directory.status.enumerating", QStringLiteral("状态：递归枚举中..."))
            : kernelText("kernel.object_directory.status.idle", QStringLiteral("状态：空闲")));
        m_statusLabel->setStyleSheet(statusLabelStyle(running ? KswordTheme::InfoHex() : KswordTheme::TextSecondaryHex()));
    }
}

void KernelObjectDirectoryDeepTab::startRefresh()
{
    const QPointer<KernelObjectDirectoryDeepTab> deferredGuard(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-object-directory-refresh-start"),
        { m_resultTree },
        [deferredGuard]()
        {
            if (!deferredGuard.isNull())
            {
                deferredGuard->startRefresh();
            }
        }))
    {
        return;
    }

    if (m_refreshRunning.exchange(true))
    {
        return;
    }

    KernelObjectDirectoryDeepOptions options;
    options.rootPath = m_rootPathEdit != nullptr ? m_rootPathEdit->text().trimmed() : QStringLiteral("\\");
    options.maxDepth = m_maxDepthSpinBox != nullptr ? m_maxDepthSpinBox->value() : 4;
    options.maxEntriesPerDirectory = 4096;
    options.maxTotalEntries = 50000;

    setRefreshRunning(true);
    if (m_resultTree != nullptr)
    {
        ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);
        m_resultTree->clear();
    }
    if (m_detailEditor != nullptr)
    {
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.object_directory.detail.background", QStringLiteral("正在后台递归枚举：%1")).arg(options.rootPath)));
    }

    QPointer<KernelObjectDirectoryDeepTab> guardThis(this);
    std::thread([guardThis, options]() {
        KernelObjectDirectoryDeepResult result =
            runKernelObjectDirectoryDeepSnapshotTask(options);

        QMetaObject::invokeMethod(guardThis, [guardThis, result = std::move(result)]() mutable {
            const auto deferredResult =
                std::make_shared<KernelObjectDirectoryDeepResult>(std::move(result));
            auto commitResult = [guardThis, deferredResult]() mutable
            {
            KernelObjectDirectoryDeepResult& result = *deferredResult;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_refreshRunning.store(false);
            guardThis->setRefreshRunning(false);

            if (!result.success)
            {
                guardThis->m_rows.clear();
                if (guardThis->m_statusLabel != nullptr)
                {
                    guardThis->m_statusLabel->setText(kernelText("kernel.object_directory.status.failed", QStringLiteral("状态：刷新失败")));
                    guardThis->m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                }
                if (guardThis->m_detailEditor != nullptr)
                {
                    guardThis->m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(result.errorText));
                }
                return;
            }

            guardThis->m_rows = std::move(result.rows);
            guardThis->rebuildTree();

            QString statusText = kernelText("kernel.object_directory.status.summary", QStringLiteral("状态：已枚举 %1 项，目录 %2 个，失败目录 %3 个"))
                .arg(guardThis->m_rows.size())
                .arg(result.visitedDirectoryCount)
                .arg(result.failedDirectoryCount);
            if (result.depthLimitReached)
            {
                statusText += kernelText("kernel.object_directory.status.depth_limit", QStringLiteral("，触达深度上限"));
            }
            if (result.perDirectoryLimitReached)
            {
                statusText += kernelText("kernel.object_directory.status.per_directory_limit", QStringLiteral("，触达单目录上限"));
            }
            if (result.totalLimitReached)
            {
                statusText += kernelText("kernel.object_directory.status.total_limit", QStringLiteral("，触达总上限"));
            }

            if (guardThis->m_statusLabel != nullptr)
            {
                guardThis->m_statusLabel->setText(statusText);
                guardThis->m_statusLabel->setStyleSheet(
                    statusLabelStyle(result.failedDirectoryCount == 0 ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));
            }
            if (guardThis->m_resultTree != nullptr && guardThis->m_resultTree->topLevelItemCount() > 0)
            {
                guardThis->m_resultTree->expandToDepth(1);
                guardThis->m_resultTree->setCurrentItem(guardThis->m_resultTree->topLevelItem(0), 0);
            }
            else if (guardThis->m_detailEditor != nullptr)
            {
                guardThis->m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.object_directory.detail.no_records", QStringLiteral("当前根路径没有返回可显示记录。"))));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-object-directory-snapshot-apply"),
                { guardThis->m_resultTree },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelObjectDirectoryDeepTab::rebuildTree()
{
    if (m_resultTree == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);

    m_resultTree->setUpdatesEnabled(false);
    m_resultTree->clear();

    QMap<QString, QTreeWidgetItem*> itemByPath;
    for (std::size_t rowIndex = 0; rowIndex < m_rows.size(); ++rowIndex)
    {
        const KernelObjectDirectoryDeepEntry& entry = m_rows[rowIndex];
        QTreeWidgetItem* parentItem = ensurePathItem(m_resultTree, itemByPath, entry.directoryPath);
        QTreeWidgetItem* item = itemByPath.value(normalizeObjectPathForUi(entry.fullPath), nullptr);
        if (item == nullptr || item->data(0, SourceIndexRole).toULongLong() != InvalidSourceIndex)
        {
            item = new QTreeWidgetItem(parentItem != nullptr ? parentItem : m_resultTree->invisibleRootItem());
            itemByPath.insert(normalizeObjectPathForUi(entry.fullPath), item);
        }

        item->setText(static_cast<int>(DirectoryDeepColumn::Name), entry.objectName);
        item->setText(static_cast<int>(DirectoryDeepColumn::Type), entry.objectType);
        item->setText(static_cast<int>(DirectoryDeepColumn::FullPath), entry.fullPath);
        item->setText(static_cast<int>(DirectoryDeepColumn::Depth), QString::number(entry.depth));
        item->setText(static_cast<int>(DirectoryDeepColumn::Status), entry.statusText);
        item->setData(0, SourceIndexRole, static_cast<qulonglong>(rowIndex));
    }

    m_resultTree->setUpdatesEnabled(true);
}

void KernelObjectDirectoryDeepTab::showCurrentItemDetail()
{
    if (m_resultTree == nullptr || m_detailEditor == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = m_resultTree->currentItem();
    if (currentItem == nullptr)
    {
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.object_directory.detail.select_hint", QStringLiteral("请选择目录递归结果节点。"))));
        return;
    }

    bool convertOk = false;
    const qulonglong sourceIndex = currentItem->data(0, SourceIndexRole).toULongLong(&convertOk);
    if (!convertOk || sourceIndex == InvalidSourceIndex || sourceIndex >= m_rows.size())
    {
        ks::ui::FieldDocument detailText;
        detailText.field(QStringLiteral("节点名称"), QStringLiteral("%1").arg(currentItem->text(static_cast<int>(DirectoryDeepColumn::Name))));
        detailText.field(QStringLiteral("节点类型"), QStringLiteral("%1").arg(currentItem->text(static_cast<int>(DirectoryDeepColumn::Type))));
        detailText.field(QStringLiteral("完整路径"), QStringLiteral("%1").arg(currentItem->text(static_cast<int>(DirectoryDeepColumn::FullPath))));
        detailText.field(QStringLiteral("说明"), QStringLiteral("该节点为 UI 父目录占位，未直接绑定 Worker 返回记录。"), true);
        m_detailEditor->setDocument(detailText);
        return;
    }

    m_detailEditor->setDocument(formatEntryDetail(m_rows[static_cast<std::size_t>(sourceIndex)]));
}

ks::ui::FieldDocument KernelObjectDirectoryDeepTab::formatEntryDetail(const KernelObjectDirectoryDeepEntry& entry)
{
    ks::ui::FieldDocument detailText;
    detailText.section(QStringLiteral("Object Manager Directory Recursive Entry"));
    detailText.field(QStringLiteral("RootPath"), QStringLiteral("%1").arg(entry.rootPath));
    detailText.field(QStringLiteral("DirectoryPath"), QStringLiteral("%1").arg(entry.directoryPath));
    detailText.field(QStringLiteral("ObjectName"), QStringLiteral("%1").arg(entry.objectName));
    detailText.field(QStringLiteral("ObjectType"), QStringLiteral("%1").arg(entry.objectType));
    detailText.field(QStringLiteral("FullPath"), QStringLiteral("%1").arg(entry.fullPath));
    detailText.field(QStringLiteral("Depth"), QStringLiteral("%1").arg(entry.depth));
    detailText.field(QStringLiteral("IsDirectory"), QStringLiteral("%1").arg(entry.isDirectory ? QStringLiteral("true") : QStringLiteral("false")));
    detailText.field(QStringLiteral("QuerySucceeded"), QStringLiteral("%1").arg(entry.querySucceeded ? QStringLiteral("true") : QStringLiteral("false")));
    detailText.field(QStringLiteral("Status"), QStringLiteral("%1").arg(entry.statusText));
    return detailText;
}
