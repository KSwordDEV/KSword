#include "DiskFileSystemForensicsPanel.h"
#include <QList>
#include "../../UI/ToolbarMetrics.h"
#include "../../UI/DetailDialogChrome.h"

#include "../../ArkDriverClient/ArkDriverTypes.h"
#include "../../UI/StructuredFieldView.h"
#include "../../FileDock/FilePropertyPeAnalyzer.h"
#include "../../UI/KernelDisassemblyDialog.h"
#include "../../ksword/file/pe_analyzer.h"
#include "../../theme.h"
#include "../../UI/VisibleTableWidget.h"

#include <QAbstractItemView>
#include <QAction>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <thread>
#include <utility>

namespace
{
    QString hexOffset(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QTableWidget* createTable(
        QWidget* parent,
        const QStringList& headers)
    {
        auto* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setAlternatingRowColors(true);
        table->horizontalHeader()->setStretchLastSection(true);
        table->setStyleSheet(QStringLiteral(
            "QTableWidget{border:1px solid %1;border-radius:6px;"
            "background:%2;alternate-background-color:%3;color:%4;}"
            "QHeaderView::section{border:none;border-bottom:1px solid %1;"
            "background:transparent;color:%5;padding:5px;font-weight:700;}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex));
        return table;
    }

    bool parseUnsignedAddress(
        const QString& text,
        std::uint64_t& valueOut)
    {
        QString normalized = text.trimmed();
        int base = 10;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2);
            base = 16;
        }
        bool ok = false;
        const qulonglong parsed = normalized.toULongLong(&ok, base);
        if (!ok)
        {
            return false;
        }
        valueOut = parsed;
        return true;
    }

    bool supportsRawBrowser(
        const ks::misc::ForensicFileSystemKind kind)
    {
        switch (kind)
        {
        case ks::misc::ForensicFileSystemKind::Ntfs:
        case ks::misc::ForensicFileSystemKind::Fat12:
        case ks::misc::ForensicFileSystemKind::Fat16:
        case ks::misc::ForensicFileSystemKind::Fat32:
        case ks::misc::ForensicFileSystemKind::ExFat:
        case ks::misc::ForensicFileSystemKind::ReFs:
        case ks::misc::ForensicFileSystemKind::Ext2:
        case ks::misc::ForensicFileSystemKind::Ext3:
        case ks::misc::ForensicFileSystemKind::Ext4:
        case ks::misc::ForensicFileSystemKind::Btrfs:
        case ks::misc::ForensicFileSystemKind::Apfs:
        case ks::misc::ForensicFileSystemKind::Hfs:
        case ks::misc::ForensicFileSystemKind::HfsPlus:
            return true;
        default:
            return false;
        }
    }

    QString bytePreview(const QByteArray& bytes)
    {
        QString text;
        for (qsizetype row = 0; row < bytes.size(); row += 16)
        {
            const qsizetype rowLength =
                std::min<qsizetype>(16, bytes.size() - row);
            text += QStringLiteral("%1  ")
                .arg(static_cast<qulonglong>(row), 8, 16, QChar('0'))
                .toUpper();
            QString characters;
            for (qsizetype column = 0; column < 16; ++column)
            {
                if (column < rowLength)
                {
                    const unsigned char value =
                        static_cast<unsigned char>(bytes[row + column]);
                    text += QStringLiteral("%1 ")
                        .arg(value, 2, 16, QChar('0'))
                        .toUpper();
                    characters += value >= 0x20U && value <= 0x7EU
                        ? QChar(value)
                        : QChar('.');
                }
                else
                {
                    text += QStringLiteral("   ");
                    characters += QChar(' ');
                }
            }
            text += QStringLiteral(" |%1|\n").arg(characters);
        }
        return text;
    }
}

namespace ks::misc
{
    DiskFileSystemForensicsPanel::DiskFileSystemForensicsPanel(
        SelectionProvider selectionProvider,
        JumpCallback jumpCallback,
        QWidget* parent)
        : QWidget(parent)
        , m_selectionProvider(std::move(selectionProvider))
        , m_jumpCallback(std::move(jumpCallback))
    {
        initializeUi();
        initializeConnections();
    }

    void DiskFileSystemForensicsPanel::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(4, 4, 4, 4);
        rootLayout->setSpacing(6);

        auto* probeGroup = new QGroupBox(
            QStringLiteral("分区文件系统原始探测"),
            this);
        auto* probeLayout = new QVBoxLayout(probeGroup);
        auto* probeToolbar = new QGridLayout();
        m_probeButton = new QPushButton(
            QStringLiteral("探测当前分区"),
            probeGroup);
        m_probeButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_probeSummaryLabel = new QLabel(
            QStringLiteral(
                "支持 NTFS、FAT12/16/32、exFAT、ReFS、Ext2/3/4、"
                "BtrFS、APFS、HFS/HFS+ 的原始只读元数据探测。"),
            probeGroup);
        m_probeSummaryLabel->setWordWrap(true);
        probeToolbar->addWidget(m_probeButton, 0, 0);
        probeToolbar->addWidget(m_probeSummaryLabel, 0, 1);
        probeLayout->addLayout(probeToolbar);
        m_probeTable = createTable(probeGroup, {
            QStringLiteral("字段"),
            QStringLiteral("值"),
            QStringLiteral("绝对偏移"),
            QStringLiteral("长度"),
            QStringLiteral("说明")
            });
        // 文件系统原始字段映射不需要快照工具条。
        ks::ui::SetTableActionBarMode(m_probeTable, ks::ui::TableActionBarMode::None);
        probeLayout->addWidget(m_probeTable, 1);
        rootLayout->addWidget(probeGroup, 2);

        auto* rawGroup = new QGroupBox(
            QStringLiteral("未挂载分区原始目录与文件浏览"),
            this);
        auto* rawLayout = new QVBoxLayout(rawGroup);
        auto* rawToolbar = new QGridLayout();
        m_rawPathEdit = new QLineEdit(
            QStringLiteral("\\"),
            rawGroup);
        m_rawPathEdit->setPlaceholderText(
            QStringLiteral("分区内路径，例如 \\ 或 \\Users"));
        m_rawUpButton = new QPushButton(
            QStringLiteral("上级目录"),
            rawGroup);
        m_rawListButton = new QPushButton(
            QStringLiteral("列出目录"),
            rawGroup);
        m_rawPreviewButton = new QPushButton(
            QStringLiteral("预览前 4 KiB"),
            rawGroup);
        m_rawExportButton = new QPushButton(
            QStringLiteral("导出选中文件"),
            rawGroup);
        m_rawMoreButton = new QToolButton(rawGroup);
        m_rawMoreButton->setText(QStringLiteral("更多操作"));
        m_rawMoreButton->setPopupMode(
            QToolButton::InstantPopup);
        auto* rawMoreMenu = new QMenu(m_rawMoreButton);
        auto* rawAdvancedMenu = rawMoreMenu->addMenu(
            QStringLiteral("高级分析"));
        m_rawPeAction = rawAdvancedMenu->addAction(
            QStringLiteral("分析并反汇编原始 PE…"));
        m_rawMoreButton->setMenu(rawMoreMenu);
        m_rawUpButton->setEnabled(false);
        m_rawListButton->setEnabled(false);
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        m_rawUpButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_rawListButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_rawPreviewButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_rawExportButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_rawMoreButton->setStyleSheet(
            KswordTheme::ThemedButtonStyle());
        m_rawSummaryLabel = new QLabel(
            QStringLiteral(
                "先探测当前分区；NTFS（含命名流/ADS）、FAT12/16/32、"
                "exFAT、ReFS、Ext2/3/4、BtrFS、APFS、HFS/HFS+ "
                "可直接浏览目录、查看物理区段并导出文件。"),
            rawGroup);
        m_rawSummaryLabel->setWordWrap(true);
        rawToolbar->addWidget(m_rawPathEdit, 0, 0);
        rawToolbar->addWidget(m_rawUpButton, 0, 1);
        rawToolbar->addWidget(m_rawListButton, 0, 2);
        rawToolbar->addWidget(m_rawPreviewButton, 0, 3);
        rawToolbar->addWidget(m_rawExportButton, 0, 4);
        rawToolbar->addWidget(m_rawMoreButton, 0, 5);
        rawToolbar->addWidget(m_rawSummaryLabel, 1, 0, 1, 6);
        rawLayout->addLayout(rawToolbar);
        m_rawTable = createTable(rawGroup, {
            QStringLiteral("名称"),
            QStringLiteral("类型"),
            QStringLiteral("逻辑大小"),
            QStringLiteral("分配大小"),
            QStringLiteral("对象 ID"),
            QStringLiteral("元数据偏移"),
            QStringLiteral("首个物理偏移"),
            QStringLiteral("区段")
            });
        // 原始目录浏览已有专用预览/导出动作，不添加重复操作栏。
        ks::ui::SetTableActionBarMode(m_rawTable, ks::ui::TableActionBarMode::None);
        rawLayout->addWidget(m_rawTable, 1);
        rootLayout->addWidget(rawGroup, 2);

        auto* deletedGroup = new QGroupBox(
            QStringLiteral("删除目录项取证与精确区间擦除"),
            this);
        auto* deletedLayout = new QVBoxLayout(deletedGroup);
        auto* deletedToolbar = new QGridLayout();
        m_deletedScanButton = new QPushButton(
            QStringLiteral("扫描 FAT/exFAT 删除项"),
            deletedGroup);
        m_deletedEraseButton = new QPushButton(
            QStringLiteral("安全擦除选中精确区间"),
            deletedGroup);
        m_deletedEraseButton->setEnabled(false);
        m_deletedScanButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_deletedEraseButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_deletedSummaryLabel = new QLabel(
            QStringLiteral(
                "NTFS 删除项由“文件管理 → 文件恢复”扫描；"
                "此处补充 FAT12/16/32 与 exFAT，并只允许擦除已证明精确且当前空闲的离线磁盘区间。"),
            deletedGroup);
        m_deletedSummaryLabel->setWordWrap(true);
        deletedToolbar->addWidget(m_deletedScanButton, 0, 0);
        deletedToolbar->addWidget(m_deletedEraseButton, 0, 1);
        deletedToolbar->addWidget(m_deletedSummaryLabel, 0, 2);
        deletedLayout->addLayout(deletedToolbar);
        m_deletedTable = createTable(deletedGroup, {
            QStringLiteral("名称"),
            QStringLiteral("原目录"),
            QStringLiteral("大小"),
            QStringLiteral("首簇"),
            QStringLiteral("目录项偏移"),
            QStringLiteral("精确区间"),
            QStringLiteral("擦除资格"),
            QStringLiteral("证据")
            });
        // 删除目录项是一次性证据结果，保留紧凑复制导出。
        ks::ui::SetTableActionBarMode(m_deletedTable, ks::ui::TableActionBarMode::Compact);
        deletedLayout->addWidget(m_deletedTable, 1);
        rootLayout->addWidget(deletedGroup, 2);

        auto* extentGroup = new QGroupBox(
            QStringLiteral("文件物理区间与磁盘定位"),
            this);
        auto* extentLayout = new QVBoxLayout(extentGroup);
        auto* extentToolbar = new QGridLayout();
        m_filePathEdit = new QLineEdit(extentGroup);
        m_filePathEdit->setPlaceholderText(
            QStringLiteral("选择 Windows 已挂载卷中的文件或目录"));
        m_fileBrowseButton = new QPushButton(
            QStringLiteral("选择文件"),
            extentGroup);
        m_extentButton = new QPushButton(
            QStringLiteral("解析物理区间"),
            extentGroup);
        m_extentButton->setToolTip(QStringLiteral("解析所选文件在磁盘上的物理区段（扇区）位置"));
        m_fileBrowseButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_extentButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        extentToolbar->addWidget(m_filePathEdit, 0, 0);
        extentToolbar->addWidget(m_fileBrowseButton, 0, 1);
        extentToolbar->addWidget(m_extentButton, 0, 2);
        extentLayout->addLayout(extentToolbar);
        m_extentTable = createTable(extentGroup, {
            QStringLiteral("磁盘"),
            QStringLiteral("文件偏移"),
            QStringLiteral("VCN"),
            QStringLiteral("LCN"),
            QStringLiteral("物理偏移"),
            QStringLiteral("长度"),
            QStringLiteral("状态")
            });
        // 文件区间映射是静态下钻结果，不需要冻结或快照比较。
        ks::ui::SetTableActionBarMode(m_extentTable, ks::ui::TableActionBarMode::None);
        extentLayout->addWidget(m_extentTable, 1);
        rootLayout->addWidget(extentGroup, 2);

        auto* reverseGroup = new QGroupBox(
            QStringLiteral("按卷簇号反查文件流"),
            this);
        auto* reverseLayout = new QVBoxLayout(reverseGroup);
        auto* reverseToolbar = new QGridLayout();
        m_volumePathEdit = new QLineEdit(
            QStringLiteral("C:"),
            reverseGroup);
        m_volumePathEdit->setPlaceholderText(
            QStringLiteral("卷路径，例如 C: 或 \\\\?\\Volume{GUID}\\"));
        m_clusterEdit = new QLineEdit(
            QStringLiteral("0"),
            reverseGroup);
        m_clusterEdit->setPlaceholderText(
            QStringLiteral("LCN，支持十进制或 0x"));
        m_reverseButton = new QPushButton(
            QStringLiteral("反查占用文件"),
            reverseGroup);
        m_reverseButton->setToolTip(QStringLiteral("根据卷簇号（LCN）反查是哪个文件占用了该簇"));
        m_reverseButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        reverseToolbar->addWidget(
            new QLabel(QStringLiteral("卷"), reverseGroup),
            0,
            0);
        reverseToolbar->addWidget(m_volumePathEdit, 0, 1);
        reverseToolbar->addWidget(
            new QLabel(QStringLiteral("簇号"), reverseGroup),
            0,
            2);
        reverseToolbar->addWidget(m_clusterEdit, 0, 3);
        reverseToolbar->addWidget(m_reverseButton, 0, 4);
        reverseLayout->addLayout(reverseToolbar);
        m_reverseTable = createTable(reverseGroup, {
            QStringLiteral("簇号"),
            QStringLiteral("簇数量"),
            QStringLiteral("文件流路径")
            });
        // 单个簇号的反查结果较少，隐藏无关快照工具条。
        ks::ui::SetTableActionBarMode(m_reverseTable, ks::ui::TableActionBarMode::None);
        reverseLayout->addWidget(m_reverseTable, 1);
        rootLayout->addWidget(reverseGroup, 1);

        // 五个取证子区各自保留栅格；只规范已确认的动作和单行参数。
        for (QGridLayout* toolbar : { probeToolbar, rawToolbar, deletedToolbar, extentToolbar, reverseToolbar })
        {
            toolbar->setHorizontalSpacing(8);
            toolbar->setVerticalSpacing(8);
        }
        const QList<QWidget*> controls { m_probeButton, m_rawPathEdit, m_rawUpButton, m_rawListButton,
            m_rawPreviewButton, m_rawExportButton, m_rawMoreButton, m_deletedScanButton, m_deletedEraseButton,
            m_filePathEdit, m_fileBrowseButton, m_extentButton, m_volumePathEdit, m_clusterEdit, m_reverseButton };
        for (QWidget* control : controls)
        {
            ks::ui::NormalizeToolbarControl(control);
        }
    }

    void DiskFileSystemForensicsPanel::initializeConnections()
    {
        connect(m_probeButton, &QPushButton::clicked, this, [this]()
        {
            probeCurrentPartition();
        });
        connect(m_rawListButton, &QPushButton::clicked, this, [this]()
        {
            browseRawDirectory();
        });
        connect(m_rawUpButton, &QPushButton::clicked, this, [this]()
        {
            QString path = m_rawPathEdit->text().trimmed();
            path.replace(QChar('/'), QChar('\\'));
            while (path.contains(QStringLiteral("\\\\")))
            {
                path.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
            }
            if (!path.startsWith(QChar('\\')))
            {
                path.prepend(QChar('\\'));
            }
            if (path.size() > 1 && path.endsWith(QChar('\\')))
            {
                path.chop(1);
            }
            if (path != QStringLiteral("\\"))
            {
                const qsizetype separator = path.lastIndexOf(QChar('\\'));
                path = separator <= 0
                    ? QStringLiteral("\\")
                    : path.left(separator);
                m_rawPathEdit->setText(path);
                browseRawDirectory();
            }
        });
        connect(m_rawPreviewButton, &QPushButton::clicked, this, [this]()
        {
            previewSelectedRawFile();
        });
        connect(m_rawExportButton, &QPushButton::clicked, this, [this]()
        {
            exportSelectedRawFile();
        });
        connect(m_rawPeAction, &QAction::triggered, this, [this]()
        {
            analyzeSelectedRawPe();
        });
        connect(
            m_rawTable,
            &QTableWidget::itemSelectionChanged,
            this,
            [this]()
            {
                const int row = m_rawTable->currentRow();
                const bool fileSelected =
                    row >= 0
                    && row < static_cast<int>(m_rawEntries.size())
                    && m_rawEntries[static_cast<std::size_t>(row)].type
                        != RawFileObjectType::Directory;
                m_rawPreviewButton->setEnabled(
                    !m_busy && fileSelected);
                m_rawExportButton->setEnabled(
                    !m_busy && fileSelected);
                m_rawPeAction->setEnabled(
                    !m_busy && fileSelected);
            });
        connect(
            m_rawTable,
            &QTableWidget::cellDoubleClicked,
            this,
            [this](const int row, const int column)
            {
                if (row < 0
                    || row >= static_cast<int>(m_rawEntries.size()))
                {
                    return;
                }
                if (column == 6)
                {
                    const QTableWidgetItem* item =
                        m_rawTable->item(row, column);
                    if (item != nullptr
                        && item->data(Qt::UserRole + 1).toBool()
                        && m_jumpCallback)
                    {
                        m_jumpCallback(
                            item->data(Qt::UserRole).toULongLong());
                    }
                    return;
                }
                const RawFileEntry& entry =
                    m_rawEntries[static_cast<std::size_t>(row)];
                if (entry.type == RawFileObjectType::Directory)
                {
                    m_rawPathEdit->setText(entry.fullPath);
                    browseRawDirectory();
                    return;
                }
                previewSelectedRawFile();
            });
        connect(m_fileBrowseButton, &QPushButton::clicked, this, [this]()
        {
            const QString selected = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择要解析物理区间的文件"),
                m_filePathEdit->text());
            if (!selected.isEmpty())
            {
                m_filePathEdit->setText(selected);
            }
        });
        connect(m_extentButton, &QPushButton::clicked, this, [this]()
        {
            resolveCurrentFile();
        });
        connect(m_reverseButton, &QPushButton::clicked, this, [this]()
        {
            reverseLookupCurrentCluster();
        });
        connect(m_deletedScanButton, &QPushButton::clicked, this, [this]()
        {
            scanDeletedEntries();
        });
        connect(m_deletedEraseButton, &QPushButton::clicked, this, [this]()
        {
            eraseSelectedDeletedEntry();
        });
        connect(m_probeTable, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            const QTableWidgetItem* item = m_probeTable->item(row, 2);
            if (item != nullptr && m_jumpCallback)
            {
                m_jumpCallback(item->data(Qt::UserRole).toULongLong());
            }
        });
        connect(m_extentTable, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            const QTableWidgetItem* item = m_extentTable->item(row, 4);
            if (item != nullptr
                && item->data(Qt::UserRole + 1).toBool()
                && m_jumpCallback)
            {
                m_jumpCallback(item->data(Qt::UserRole).toULongLong());
            }
        });
        connect(
            m_deletedTable,
            &QTableWidget::itemSelectionChanged,
            this,
            [this]()
            {
                const int row = m_deletedTable->currentRow();
                const bool eligible =
                    row >= 0
                    && row < static_cast<int>(m_deletedEntries.size())
                    && m_deletedEntries[static_cast<std::size_t>(row)]
                        .exactExtents
                    && m_deletedEntries[static_cast<std::size_t>(row)]
                        .clustersCurrentlyFree;
                m_deletedEraseButton->setEnabled(!m_busy && eligible);
            });
        connect(
            m_deletedTable,
            &QTableWidget::cellDoubleClicked,
            this,
            [this](const int row, const int column)
            {
                Q_UNUSED(column);
                if (row < 0
                    || row >= static_cast<int>(m_deletedEntries.size())
                    || !m_jumpCallback)
                {
                    return;
                }
                const DeletedDirectoryEntry& entry =
                    m_deletedEntries[static_cast<std::size_t>(row)];
                const std::uint64_t offset = !entry.extents.empty()
                    ? entry.extents.front().physicalOffset
                    : entry.directoryEntryOffset;
                m_jumpCallback(offset);
            });
    }

    void DiskFileSystemForensicsPanel::probeCurrentPartition()
    {
        if (m_busy)
        {
            return;
        }
        const std::optional<DiskForensicsSelection> selection =
            m_selectionProvider ? m_selectionProvider() : std::nullopt;
        if (!selection.has_value())
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件系统取证"),
                QStringLiteral("请先在磁盘图或分区表中选择一个有效分区。"));
            return;
        }

        m_busy = true;
        m_probeButton->setEnabled(false);
        m_probeSummaryLabel->setText(
            QStringLiteral("正在探测 %1 ...").arg(selection->displayText));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selectionValue = *selection]()
        {
            FileSystemProbeResult result =
                DiskFileSystemForensics::probePartition(
                    selectionValue.diskIndex,
                    selectionValue.backend,
                    selectionValue.partitionOffset,
                    selectionValue.partitionLength,
                    selectionValue.logicalSectorSize);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis,
                    selectionValue,
                    result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyProbeResult(
                            selectionValue,
                            std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::browseRawDirectory()
    {
        if (m_busy
            || !m_rawSelection.has_value()
            || !supportsRawBrowser(m_rawFileSystem))
        {
            return;
        }
        const QString path = m_rawPathEdit->text().trimmed();
        const DiskForensicsSelection selection = *m_rawSelection;
        const ForensicFileSystemKind fileSystem = m_rawFileSystem;
        m_busy = true;
        m_rawUpButton->setEnabled(false);
        m_rawListButton->setEnabled(false);
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        m_rawSummaryLabel->setText(
            QStringLiteral("正在解析 %1 的原始目录 %2 ...")
                .arg(selection.displayText)
                .arg(path));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis, selection, fileSystem, path]()
            {
                RawDirectoryResult result =
                    DiskRawFileSystemBrowser::listDirectory(
                        selection.diskIndex,
                        selection.backend,
                        selection.partitionOffset,
                        selection.partitionLength,
                        selection.logicalSectorSize,
                        fileSystem,
                        path,
                        4096U);
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis,
                        selection,
                        result = std::move(result)]() mutable
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->applyRawDirectoryResult(
                                selection,
                                std::move(result));
                        }
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::previewSelectedRawFile()
    {
        if (m_busy || !m_rawSelection.has_value())
        {
            return;
        }
        const int row = m_rawTable->currentRow();
        if (row < 0 || row >= static_cast<int>(m_rawEntries.size()))
        {
            return;
        }
        const RawFileEntry entry =
            m_rawEntries[static_cast<std::size_t>(row)];
        if (entry.type == RawFileObjectType::Directory)
        {
            return;
        }
        if (entry.fileSizeBytes == 0U)
        {
            QMessageBox::information(
                this,
                QStringLiteral("原始文件预览"),
                QStringLiteral("该文件长度为 0 字节。"));
            return;
        }
        const DiskForensicsSelection selection = *m_rawSelection;
        const ForensicFileSystemKind fileSystem = m_rawFileSystem;
        const std::uint32_t previewLength =
            static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    entry.fileSizeBytes,
                    4096U));
        m_busy = true;
        m_rawListButton->setEnabled(false);
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        m_rawSummaryLabel->setText(
            QStringLiteral("正在读取 %1 的前 %2 字节 ...")
                .arg(entry.fullPath)
                .arg(previewLength));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis,
                selection,
                fileSystem,
                filePath = entry.fullPath,
                previewLength]()
            {
                RawFileReadResult result =
                    DiskRawFileSystemBrowser::readFile(
                        selection.diskIndex,
                        selection.backend,
                        selection.partitionOffset,
                        selection.partitionLength,
                        selection.logicalSectorSize,
                        fileSystem,
                        filePath,
                        0U,
                        previewLength);
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis, result = std::move(result)]() mutable
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->applyRawReadResult(
                                std::move(result));
                        }
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::exportSelectedRawFile()
    {
        if (m_busy || !m_rawSelection.has_value())
        {
            return;
        }
        const int row = m_rawTable->currentRow();
        if (row < 0 || row >= static_cast<int>(m_rawEntries.size()))
        {
            return;
        }
        const RawFileEntry entry =
            m_rawEntries[static_cast<std::size_t>(row)];
        if (entry.type == RawFileObjectType::Directory)
        {
            return;
        }
        const QString destination = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出原始文件"),
            entry.name);
        if (destination.isEmpty())
        {
            return;
        }
        const DiskForensicsSelection selection = *m_rawSelection;
        const ForensicFileSystemKind fileSystem = m_rawFileSystem;
        m_busy = true;
        m_rawListButton->setEnabled(false);
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        m_rawSummaryLabel->setText(
            QStringLiteral("正在导出 %1 ...").arg(entry.fullPath));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis,
                selection,
                fileSystem,
                source = entry.fullPath,
                destination]()
            {
                RawFileExportResult result =
                    DiskRawFileSystemBrowser::exportFile(
                        selection.diskIndex,
                        selection.backend,
                        selection.partitionOffset,
                        selection.partitionLength,
                        selection.logicalSectorSize,
                        fileSystem,
                        source,
                        destination);
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis, result = std::move(result)]() mutable
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->applyRawExportResult(
                                std::move(result));
                        }
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::analyzeSelectedRawPe()
    {
        if (m_busy || !m_rawSelection.has_value())
        {
            return;
        }
        const int row = m_rawTable->currentRow();
        if (row < 0 || row >= static_cast<int>(m_rawEntries.size()))
        {
            return;
        }
        const RawFileEntry entry =
            m_rawEntries[static_cast<std::size_t>(row)];
        if (entry.type == RawFileObjectType::Directory)
        {
            return;
        }
        constexpr std::uint64_t kMaximumPeBytes =
            512ULL * 1024ULL * 1024ULL;
        constexpr std::uint32_t kReadChunkBytes =
            4U * 1024U * 1024U;
        if (entry.fileSizeBytes == 0U
            || entry.fileSizeBytes > kMaximumPeBytes
            || entry.fileSizeBytes
                > static_cast<std::uint64_t>(
                    std::numeric_limits<int>::max()))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("原始 PE 分析"),
                QStringLiteral(
                    "PE 字节长度必须在 1 字节到 512 MiB 之间。"));
            return;
        }

        const DiskForensicsSelection selection = *m_rawSelection;
        const ForensicFileSystemKind fileSystem = m_rawFileSystem;
        m_busy = true;
        m_rawListButton->setEnabled(false);
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        m_rawSummaryLabel->setText(
            QStringLiteral("正在读取并分析原始 PE：%1 ...")
                .arg(entry.fullPath));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis,
                selection,
                fileSystem,
                entry]()
            {
                std::vector<std::uint8_t> fileBytes;
                fileBytes.reserve(
                    static_cast<std::size_t>(
                        entry.fileSizeBytes));
                QString readError;
                std::uint64_t offset = 0U;
                while (offset < entry.fileSizeBytes)
                {
                    const std::uint32_t length =
                        static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(
                                kReadChunkBytes,
                                entry.fileSizeBytes - offset));
                    RawFileReadResult chunk =
                        DiskRawFileSystemBrowser::readFile(
                            selection.diskIndex,
                            selection.backend,
                            selection.partitionOffset,
                            selection.partitionLength,
                            selection.logicalSectorSize,
                            fileSystem,
                            entry.fullPath,
                            offset,
                            length);
                    if (!chunk.success
                        || chunk.bytes.size()
                            != static_cast<qsizetype>(length))
                    {
                        readError = chunk.errorText.isEmpty()
                            ? QStringLiteral(
                                "原始文件读取在 0x%1 处被截断。")
                                .arg(
                                    static_cast<qulonglong>(offset),
                                    0,
                                    16)
                            : chunk.errorText;
                        break;
                    }
                    const auto* chunkBegin =
                        reinterpret_cast<
                            const std::uint8_t*>(
                            chunk.bytes.constData());
                    fileBytes.insert(
                        fileBytes.end(),
                        chunkBegin,
                        chunkBegin
                            + static_cast<std::size_t>(
                                chunk.bytes.size()));
                    offset += length;
                }

                ks::file::PeAnalysisResult analysis;
                if (readError.isEmpty())
                {
                    analysis =
                        ks::file::AnalyzePeBytes(fileBytes);
                }
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis,
                        sourcePath = entry.fullPath,
                        readError,
                        fileBytes = std::move(fileBytes),
                        analysis = std::move(analysis)]() mutable
                    {
                        if (safeThis.isNull())
                        {
                            return;
                        }
                        safeThis->m_busy = false;
                        safeThis->m_rawListButton->setEnabled(
                            safeThis->m_rawSelection.has_value());
                        const int selectedRow =
                            safeThis->m_rawTable->currentRow();
                        const bool fileSelected =
                            selectedRow >= 0
                            && selectedRow
                                < static_cast<int>(
                                    safeThis->m_rawEntries.size())
                            && safeThis->m_rawEntries[
                                static_cast<std::size_t>(
                                    selectedRow)].type
                                != RawFileObjectType::Directory;
                        safeThis->m_rawPreviewButton->setEnabled(
                            fileSelected);
                        safeThis->m_rawExportButton->setEnabled(
                            fileSelected);
                        safeThis->m_rawPeAction->setEnabled(
                            fileSelected);
                        if (!readError.isEmpty())
                        {
                            safeThis->m_rawSummaryLabel->setText(
                                QStringLiteral(
                                    "原始 PE 读取失败：%1")
                                    .arg(readError));
                            QMessageBox::warning(
                                safeThis.data(),
                                QStringLiteral("原始 PE 分析"),
                                readError);
                            return;
                        }

                        safeThis->m_rawSummaryLabel->setText(
                            analysis.success
                                ? QStringLiteral(
                                    "原始 PE 分析完成：%1")
                                    .arg(sourcePath)
                                : QStringLiteral(
                                    "原始 PE 解析失败：%1")
                                    .arg(sourcePath));
                        QDialog dialog(safeThis.data());
                        dialog.setWindowTitle(
                            QStringLiteral("原始 PE 分析"));
                        dialog.resize(980, 700);
                        auto* layout = new QVBoxLayout(&dialog);
                        auto* editor =
                            new ks::ui::StructuredFieldView(&dialog);
                        editor->setDocument(file_dock_detail::buildPeAnalysisDocument(analysis));
                        layout->addWidget(editor, 1);
                        auto* buttons = new QDialogButtonBox(
                            QDialogButtonBox::Close,
                            &dialog);
                        auto* disassembleButton =
                            buttons->addButton(
                                QStringLiteral("反汇编入口点"),
                                QDialogButtonBox::ActionRole);
                        disassembleButton->setEnabled(
                            analysis.success
                            && analysis.entryPointFileOffsetValid
                            && analysis.imageBase
                                <= std::numeric_limits<
                                    std::uint64_t>::max()
                                    - analysis.entryPointRva
                            && analysis.entryPointFileOffset
                                < static_cast<std::uint64_t>(
                                    fileBytes.size()));
                        QObject::connect(
                            buttons,
                            &QDialogButtonBox::rejected,
                            &dialog,
                            &QDialog::reject);
                        QObject::connect(
                            disassembleButton,
                            &QPushButton::clicked,
                            &dialog,
                            [&dialog,
                                sourcePath,
                                &fileBytes,
                                &analysis]()
                            {
                                const qsizetype entryOffset =
                                    static_cast<qsizetype>(
                                        analysis
                                            .entryPointFileOffset);
                                const qsizetype codeLength =
                                    std::min<qsizetype>(
                                        64 * 1024,
                                        static_cast<qsizetype>(
                                            fileBytes.size())
                                            - entryOffset);
                                const QByteArray codeBytes(
                                    reinterpret_cast<const char*>(
                                        fileBytes.data()
                                        + static_cast<std::size_t>(
                                            entryOffset)),
                                    codeLength);
                                ks::ui::KernelDisassemblyDialog
                                    disassembly(&dialog);
                                disassembly.setSnapshot(
                                    codeBytes,
                                    analysis.imageBase
                                        + analysis.entryPointRva,
                                    analysis.isPe64
                                        ? ks::ui::
                                            DisassemblyArchitecture::
                                                X64
                                        : ks::ui::
                                            DisassemblyArchitecture::
                                                X86,
                                    QStringLiteral(
                                        "原始文件 %1 的 PE 入口点")
                                        .arg(sourcePath));
                                disassembly.exec();
                            });
                        layout->addWidget(buttons);
                        ks::ui::ApplyDetailDialogChrome(&dialog);
                        dialog.exec();
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::resolveCurrentFile()
    {
        if (m_busy)
        {
            return;
        }
        const QString filePath = m_filePathEdit->text().trimmed();
        if (filePath.isEmpty())
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件物理区间"),
                QStringLiteral("请先选择一个文件。"));
            return;
        }

        m_busy = true;
        m_extentButton->setEnabled(false);
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, filePath]()
        {
            FileExtentResult result =
                DiskFileSystemForensics::resolveFileExtents(filePath);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyExtentResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::reverseLookupCurrentCluster()
    {
        if (m_busy)
        {
            return;
        }
        std::uint64_t cluster = 0;
        if (!parseUnsignedAddress(m_clusterEdit->text(), cluster))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("簇号反查"),
                QStringLiteral("簇号格式无效。"));
            return;
        }

        const QString volumePath = m_volumePathEdit->text().trimmed();
        m_busy = true;
        m_reverseButton->setEnabled(false);
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, volumePath, cluster]()
        {
            ReverseClusterResult result =
                DiskFileSystemForensics::reverseLookupCluster(
                    volumePath,
                    cluster);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyReverseResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::scanDeletedEntries()
    {
        if (m_busy)
        {
            return;
        }
        const std::optional<DiskForensicsSelection> selection =
            m_selectionProvider ? m_selectionProvider() : std::nullopt;
        if (!selection.has_value())
        {
            QMessageBox::information(
                this,
                QStringLiteral("删除目录项取证"),
                QStringLiteral("请先在磁盘图或分区表中选择一个有效分区。"));
            return;
        }

        m_busy = true;
        m_deletedScanButton->setEnabled(false);
        m_deletedEraseButton->setEnabled(false);
        m_deletedSummaryLabel->setText(
            QStringLiteral("正在扫描 %1 的原始目录项 ...")
                .arg(selection->displayText));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selectionValue = *selection]()
        {
            DeletedEntryScanResult result =
                DiskDeletedEntryForensics::scan(
                    selectionValue.diskIndex,
                    selectionValue.backend,
                    selectionValue.partitionOffset,
                    selectionValue.partitionLength,
                    selectionValue.logicalSectorSize);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis,
                    selectionValue,
                    result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyDeletedResult(
                            selectionValue,
                            std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::eraseSelectedDeletedEntry()
    {
        if (m_busy || !m_deletedSelection.has_value())
        {
            return;
        }
        const int row = m_deletedTable->currentRow();
        if (row < 0 || row >= static_cast<int>(m_deletedEntries.size()))
        {
            return;
        }
        const DeletedDirectoryEntry entry =
            m_deletedEntries[static_cast<std::size_t>(row)];
        const DiskForensicsSelection selection = *m_deletedSelection;
        if (!entry.exactExtents || !entry.clustersCurrentlyFree)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral(
                    "该条目没有同时通过簇链/连续标志、分区边界和当前空闲状态校验，不能擦除。"));
            return;
        }
        if ((selection.capabilityFlags
                & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral("系统磁盘上的删除区间擦除被永久阻止。"));
            return;
        }
        if ((selection.capabilityFlags
                & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) == 0U)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral(
                    "目标磁盘必须先在 Windows 磁盘管理中切换为“脱机”。"
                    "这样可以避免文件系统缓存或重新分配与原始写入竞争。"));
            return;
        }

        std::uint64_t totalBytes = 0;
        for (const DeletedFileExtent& extent : entry.extents)
        {
            totalBytes += extent.lengthBytes;
        }
        const QMessageBox::StandardButton warningResult =
            QMessageBox::warning(
                this,
                QStringLiteral("不可逆精确区间擦除"),
                QStringLiteral(
                    "即将对离线磁盘中的 %1 个精确物理区间写零并逐块回读校验，"
                    "共 %2 字节。该操作不可撤销，且删除文件数据将无法恢复。\n\n"
                    "条目：%3/%4\n证据：%5")
                    .arg(entry.extents.size())
                    .arg(static_cast<qulonglong>(totalBytes))
                    .arg(entry.directoryPath)
                    .arg(entry.name)
                    .arg(entry.evidenceText),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
        if (warningResult != QMessageBox::Yes)
        {
            return;
        }

        // 最终确认改为直接点击：不再要求输入确认短语，默认聚焦“否”避免误触。
        const auto confirmation = QMessageBox::warning(
            this,
            QStringLiteral("精确区间擦除"),
            QStringLiteral("确认对该文件的物理区间写零？数据将被永久抹除且无法恢复。"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmation != QMessageBox::Yes)
        {
            return;
        }

        m_busy = true;
        m_deletedScanButton->setEnabled(false);
        m_deletedEraseButton->setEnabled(false);
        m_deletedSummaryLabel->setText(
            QStringLiteral("正在写零并回读校验 %1/%2 ...")
                .arg(entry.directoryPath)
                .arg(entry.name));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selection, entry]()
        {
            ExtentEraseResult result =
                DiskDeletedEntryForensics::eraseExactFreeExtents(
                    selection.diskIndex,
                    selection.backend,
                    selection.logicalSectorSize,
                    KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE |
                        KSWORD_ARK_RAW_DISK_FLAG_FUA,
                    entry);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyEraseResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::applyProbeResult(
        DiskForensicsSelection selection,
        FileSystemProbeResult result)
    {
        m_busy = false;
        m_probeButton->setEnabled(true);
        m_probeTable->setRowCount(0);
        m_rawTable->setRowCount(0);
        m_rawEntries.clear();
        m_rawSelection.reset();
        m_rawFileSystem = ForensicFileSystemKind::Unknown;
        m_rawUpButton->setEnabled(false);
        m_rawListButton->setEnabled(false);
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        if (!result.success)
        {
            m_probeSummaryLabel->setText(
                QStringLiteral("探测失败：%1").arg(result.errorText));
            m_rawSummaryLabel->setText(
                QStringLiteral("原始目录浏览不可用：分区探测未成功。"));
            return;
        }

        m_probeSummaryLabel->setText(
            QStringLiteral(
                "%1 | 扇区=%2 B | 块/簇=%3 B | 容量=%4 B | 能力：%5")
                .arg(result.name)
                .arg(result.logicalSectorSize)
                .arg(result.blockSize)
                .arg(static_cast<qulonglong>(result.totalBytes))
                .arg(result.capabilityText));
        m_probeTable->setRowCount(
            static_cast<int>(result.fields.size()));
        for (int row = 0; row < static_cast<int>(result.fields.size()); ++row)
        {
            const FileSystemProbeField& field =
                result.fields[static_cast<std::size_t>(row)];
            m_probeTable->setItem(row, 0, readOnlyItem(field.name));
            m_probeTable->setItem(row, 1, readOnlyItem(field.value));
            auto* offsetItem = readOnlyItem(hexOffset(field.absoluteOffset));
            offsetItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(field.absoluteOffset));
            m_probeTable->setItem(row, 2, offsetItem);
            m_probeTable->setItem(
                row,
                3,
                readOnlyItem(QString::number(field.sizeBytes)));
            m_probeTable->setItem(row, 4, readOnlyItem(field.detail));
        }
        m_probeTable->resizeColumnsToContents();

        if (supportsRawBrowser(result.kind))
        {
            m_rawSelection = std::move(selection);
            m_rawFileSystem = result.kind;
            m_rawPathEdit->setText(QStringLiteral("\\"));
            m_rawListButton->setEnabled(true);
            m_rawSummaryLabel->setText(
                QStringLiteral(
                    "%1 已就绪：可直接读取未挂载分区的目录树、文件数据和物理区段。")
                    .arg(result.name));
        }
        else
        {
            m_rawSummaryLabel->setText(
                QStringLiteral(
                    "%1 使用现有专用取证入口；此浏览器面向 ReFS、Ext、"
                    "BtrFS、APFS 与 HFS/HFS+。")
                    .arg(result.name));
        }
    }

    void DiskFileSystemForensicsPanel::applyRawDirectoryResult(
        DiskForensicsSelection selection,
        RawDirectoryResult result)
    {
        m_busy = false;
        m_rawTable->setRowCount(0);
        m_rawEntries.clear();
        m_rawPreviewButton->setEnabled(false);
        m_rawExportButton->setEnabled(false);
        m_rawPeAction->setEnabled(false);
        if (!result.success)
        {
            m_rawUpButton->setEnabled(
                m_rawPathEdit->text().trimmed() != QStringLiteral("\\"));
            m_rawListButton->setEnabled(
                m_rawSelection.has_value()
                && supportsRawBrowser(m_rawFileSystem));
            m_rawSummaryLabel->setText(
                QStringLiteral("原始目录解析失败：%1")
                    .arg(result.errorText));
            return;
        }

        m_rawSelection = std::move(selection);
        m_rawFileSystem = result.fileSystem;
        m_rawPathEdit->setText(result.canonicalPath);
        m_rawEntries = std::move(result.entries);
        m_rawUpButton->setEnabled(
            result.canonicalPath != QStringLiteral("\\"));
        m_rawListButton->setEnabled(true);
        m_rawSummaryLabel->setText(
            QStringLiteral(
                "%1 | 目录对象=%2 | 扫描记录=%3 | 返回=%4%5")
                .arg(result.fileSystemName)
                .arg(static_cast<qulonglong>(
                    result.directoryObjectId))
                .arg(static_cast<qulonglong>(
                    result.scannedRecords))
                .arg(m_rawEntries.size())
                .arg(result.truncated
                    ? QStringLiteral("（已达到显示上限）")
                    : QString()));
        m_rawTable->setRowCount(
            static_cast<int>(m_rawEntries.size()));
        for (int row = 0;
             row < static_cast<int>(m_rawEntries.size());
             ++row)
        {
            const RawFileEntry& entry =
                m_rawEntries[static_cast<std::size_t>(row)];
            m_rawTable->setItem(row, 0, readOnlyItem(entry.name));
            m_rawTable->setItem(
                row,
                1,
                readOnlyItem(
                    DiskRawFileSystemBrowser::objectTypeText(
                        entry.type)));
            m_rawTable->setItem(
                row,
                2,
                readOnlyItem(QString::number(entry.fileSizeBytes)));
            m_rawTable->setItem(
                row,
                3,
                readOnlyItem(
                    QString::number(entry.allocatedSizeBytes)));
            m_rawTable->setItem(
                row,
                4,
                readOnlyItem(QString::number(entry.objectId)));
            auto* metadataItem =
                readOnlyItem(hexOffset(entry.metadataOffset));
            metadataItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(entry.metadataOffset));
            m_rawTable->setItem(row, 5, metadataItem);

            QStringList extentTexts;
            std::uint64_t firstPhysical = 0;
            bool firstPhysicalExact = false;
            for (const RawFileExtent& extent : entry.extents)
            {
                if (!firstPhysicalExact
                    && extent.physicalMappingExact
                    && !extent.sparse)
                {
                    firstPhysical = extent.absoluteOffset;
                    firstPhysicalExact = true;
                }
                QString state;
                if (extent.sparse)
                {
                    state = QStringLiteral("稀疏");
                }
                else if (extent.unwritten)
                {
                    state = QStringLiteral("未写入");
                }
                else if (extent.compressed)
                {
                    state = QStringLiteral("压缩");
                }
                extentTexts.push_back(
                    QStringLiteral("%1:%2+%3%4")
                        .arg(hexOffset(extent.logicalOffset))
                        .arg(extent.physicalMappingExact
                            ? hexOffset(extent.absoluteOffset)
                            : QStringLiteral("-"))
                        .arg(static_cast<qulonglong>(
                            extent.lengthBytes))
                        .arg(state.isEmpty()
                            ? QString()
                            : QStringLiteral("[%1]").arg(state)));
            }
            if (entry.extentsTruncated)
            {
                extentTexts.push_back(
                    QStringLiteral("…[物理映射未完整展开]"));
            }
            auto* physicalItem = readOnlyItem(
                firstPhysicalExact
                    ? hexOffset(firstPhysical)
                    : QStringLiteral("-"));
            physicalItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(firstPhysical));
            physicalItem->setData(
                Qt::UserRole + 1,
                firstPhysicalExact);
            m_rawTable->setItem(row, 6, physicalItem);
            m_rawTable->setItem(
                row,
                7,
                readOnlyItem(extentTexts.isEmpty()
                    ? QStringLiteral("-")
                    : extentTexts.join(QStringLiteral("; "))));
        }
        m_rawTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyRawReadResult(
        RawFileReadResult result)
    {
        m_busy = false;
        m_rawListButton->setEnabled(m_rawSelection.has_value());
        m_rawUpButton->setEnabled(
            m_rawPathEdit->text().trimmed() != QStringLiteral("\\"));
        const int row = m_rawTable->currentRow();
        const bool fileSelected =
            row >= 0
            && row < static_cast<int>(m_rawEntries.size())
            && m_rawEntries[static_cast<std::size_t>(row)].type
                != RawFileObjectType::Directory;
        m_rawPreviewButton->setEnabled(fileSelected);
        m_rawExportButton->setEnabled(fileSelected);
        m_rawPeAction->setEnabled(fileSelected);
        if (!result.success)
        {
            m_rawSummaryLabel->setText(
                QStringLiteral("原始文件读取失败：%1")
                    .arg(result.errorText));
            QMessageBox::warning(
                this,
                QStringLiteral("原始文件预览"),
                result.errorText);
            return;
        }

        m_rawSummaryLabel->setText(
            QStringLiteral(
                "已读取 %1：%2 字节，文件总长 %3 字节。")
                .arg(result.filePath)
                .arg(result.bytes.size())
                .arg(static_cast<qulonglong>(
                    result.fileSizeBytes)));
        QMessageBox preview(this);
        preview.setIcon(QMessageBox::Information);
        preview.setWindowTitle(QStringLiteral("原始文件预览"));
        preview.setText(
            QStringLiteral("%1\n读取 %2 字节；十六进制内容见详细信息。")
                .arg(result.filePath)
                .arg(result.bytes.size()));
        preview.setDetailedText(bytePreview(result.bytes));
        preview.exec();
    }

    void DiskFileSystemForensicsPanel::applyRawExportResult(
        RawFileExportResult result)
    {
        m_busy = false;
        m_rawListButton->setEnabled(m_rawSelection.has_value());
        m_rawUpButton->setEnabled(
            m_rawPathEdit->text().trimmed() != QStringLiteral("\\"));
        const int row = m_rawTable->currentRow();
        const bool fileSelected =
            row >= 0
            && row < static_cast<int>(m_rawEntries.size())
            && m_rawEntries[static_cast<std::size_t>(row)].type
                != RawFileObjectType::Directory;
        m_rawPreviewButton->setEnabled(fileSelected);
        m_rawExportButton->setEnabled(fileSelected);
        m_rawPeAction->setEnabled(fileSelected);
        if (!result.success)
        {
            m_rawSummaryLabel->setText(
                QStringLiteral("原始文件导出失败：%1")
                    .arg(result.errorText));
            QMessageBox::warning(
                this,
                QStringLiteral("导出原始文件"),
                result.errorText);
            return;
        }
        m_rawSummaryLabel->setText(
            QStringLiteral(
                "导出完成：%1 → %2（%3 字节）")
                .arg(result.filePath)
                .arg(result.destinationPath)
                .arg(static_cast<qulonglong>(
                    result.bytesWritten)));
        QMessageBox::information(
            this,
            QStringLiteral("导出原始文件"),
            m_rawSummaryLabel->text());
    }

    void DiskFileSystemForensicsPanel::applyExtentResult(
        FileExtentResult result)
    {
        m_busy = false;
        m_extentButton->setEnabled(true);
        m_extentTable->setRowCount(0);
        if (!result.success)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("文件物理区间"),
                result.errorText);
            return;
        }

        m_extentTable->setRowCount(
            static_cast<int>(result.extents.size()));
        for (int row = 0; row < static_cast<int>(result.extents.size()); ++row)
        {
            const PhysicalFileExtent& extent =
                result.extents[static_cast<std::size_t>(row)];
            m_extentTable->setItem(
                row,
                0,
                readOnlyItem(extent.diskNumber >= 0
                    ? QStringLiteral("PhysicalDrive%1").arg(extent.diskNumber)
                    : QStringLiteral("-")));
            m_extentTable->setItem(row, 1, readOnlyItem(hexOffset(extent.fileOffset)));
            m_extentTable->setItem(row, 2, readOnlyItem(QString::number(extent.startingVcn)));
            m_extentTable->setItem(row, 3, readOnlyItem(extent.sparse ? QStringLiteral("Sparse") : QString::number(extent.startingLcn)));
            auto* physicalItem = readOnlyItem(extent.physicalMappingExact
                ? hexOffset(extent.physicalOffset)
                : QStringLiteral("-"));
            physicalItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(extent.physicalOffset));
            physicalItem->setData(
                Qt::UserRole + 1,
                extent.physicalMappingExact);
            m_extentTable->setItem(row, 4, physicalItem);
            m_extentTable->setItem(row, 5, readOnlyItem(QString::number(extent.lengthBytes)));
            m_extentTable->setItem(
                row,
                6,
                readOnlyItem(extent.sparse
                    ? QStringLiteral("稀疏区间")
                    : (extent.physicalMappingExact
                        ? QStringLiteral("可跳转")
                        : QStringLiteral("多区间卷，仅返回卷内 LCN"))));
        }
        m_extentTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyReverseResult(
        ReverseClusterResult result)
    {
        m_busy = false;
        m_reverseButton->setEnabled(true);
        m_reverseTable->setRowCount(0);
        if (!result.success)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("簇号反查"),
                result.errorText);
            return;
        }

        m_reverseTable->setRowCount(
            static_cast<int>(result.entries.size()));
        for (int row = 0; row < static_cast<int>(result.entries.size()); ++row)
        {
            const ReverseClusterEntry& entry =
                result.entries[static_cast<std::size_t>(row)];
            m_reverseTable->setItem(row, 0, readOnlyItem(QString::number(entry.cluster)));
            m_reverseTable->setItem(row, 1, readOnlyItem(QString::number(entry.clusterCount)));
            m_reverseTable->setItem(row, 2, readOnlyItem(entry.streamPath));
        }
        m_reverseTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyDeletedResult(
        DiskForensicsSelection selection,
        DeletedEntryScanResult result)
    {
        m_busy = false;
        m_deletedScanButton->setEnabled(true);
        m_deletedEraseButton->setEnabled(false);
        m_deletedTable->setRowCount(0);
        m_deletedEntries.clear();
        m_deletedSelection.reset();
        if (!result.success)
        {
            m_deletedSummaryLabel->setText(
                QStringLiteral("删除项扫描失败：%1").arg(result.errorText));
            return;
        }

        m_deletedSummaryLabel->setText(result.summaryText);
        m_deletedSelection = std::move(selection);
        m_deletedEntries = std::move(result.entries);
        m_deletedTable->setRowCount(
            static_cast<int>(m_deletedEntries.size()));
        for (int row = 0;
             row < static_cast<int>(m_deletedEntries.size());
             ++row)
        {
            const DeletedDirectoryEntry& entry =
                m_deletedEntries[static_cast<std::size_t>(row)];
            m_deletedTable->setItem(row, 0, readOnlyItem(entry.name));
            m_deletedTable->setItem(
                row,
                1,
                readOnlyItem(entry.directoryPath));
            m_deletedTable->setItem(
                row,
                2,
                readOnlyItem(QString::number(entry.fileSizeBytes)));
            m_deletedTable->setItem(
                row,
                3,
                readOnlyItem(QString::number(entry.firstCluster)));
            m_deletedTable->setItem(
                row,
                4,
                readOnlyItem(hexOffset(entry.directoryEntryOffset)));

            QStringList extentTexts;
            for (const DeletedFileExtent& extent : entry.extents)
            {
                extentTexts.push_back(
                    QStringLiteral("%1+%2")
                        .arg(hexOffset(extent.physicalOffset))
                        .arg(static_cast<qulonglong>(extent.lengthBytes)));
            }
            m_deletedTable->setItem(
                row,
                5,
                readOnlyItem(extentTexts.isEmpty()
                    ? QStringLiteral("-")
                    : extentTexts.join(QStringLiteral("; "))));
            m_deletedTable->setItem(
                row,
                6,
                readOnlyItem(entry.exactExtents
                        && entry.clustersCurrentlyFree
                        && !entry.directory
                    ? QStringLiteral("离线磁盘可擦除")
                    : QStringLiteral("只读取证")));
            m_deletedTable->setItem(
                row,
                7,
                readOnlyItem(entry.evidenceText));
        }
        m_deletedTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyEraseResult(
        ExtentEraseResult result)
    {
        m_busy = false;
        m_deletedScanButton->setEnabled(true);
        m_deletedEraseButton->setEnabled(false);
        if (!result.success)
        {
            m_deletedSummaryLabel->setText(
                QStringLiteral("精确区间擦除失败：%1")
                    .arg(result.errorText));
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                result.errorText);
            return;
        }

        m_deletedSummaryLabel->setText(
            QStringLiteral(
                "精确区间擦除完成：%1 个区间，%2 字节均已写零并回读验证。请重新扫描刷新分配状态。")
                .arg(result.extentsErased)
                .arg(static_cast<qulonglong>(result.bytesErased)));
        QMessageBox::information(
            this,
            QStringLiteral("精确区间擦除"),
            m_deletedSummaryLabel->text());
    }
}
