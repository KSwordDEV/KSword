#include "ScannerDock.h"
#include "../UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/VisibleTableWidget.h"

#include "Internationalization/LanguageManager.h"
#include "ksword/scanner/atomic_file_patch.h"
#include "ksword/scanner/binary_scanner.h"

#include <QAbstractItemView>
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <functional>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QGroupBox>
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QStyle>
#include <QShowEvent>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>
#include <QUuid>

#include <limits>
#include <mutex>
#include <utility>
#include <vector>

namespace {
const ks::ui::PageNavigationTabDefinition kScannerNavigation[] = {
    {"analysis", "", "scanner.tab.analysis", "可视化分析", true},
    {"inspection", "", "scanner.tab.inspection", "结构化扫描", false},
    {"editor", "", "scanner.tab.editor", "安全字节编辑", false}
};
}

// ScannerAsyncState 作用：把 worker 的回投目标放在共享互斥状态中。
// 析构函数先清空 owner；worker 只有在同一把锁保护下才能提交 queued 调用，
// 从而消除 QPointer check/data 以及应用退出阶段的接收者竞态。
struct ScannerAsyncState
{
    std::mutex mutex;
    ScannerDock* owner = nullptr;
};

namespace
{
    class ScannerTableModel final : public QAbstractTableModel
    {
    public:
        using Value = std::function<QString(int, int)>;
        using Header = std::function<QString(int)>;
        ScannerTableModel(const int rows, const int columns, Value value, Header header, QObject* parent)
            : QAbstractTableModel(parent), m_rows(rows), m_columns(columns),
              m_value(std::move(value)), m_header(std::move(header)) {}
        int rowCount(const QModelIndex& parent = {}) const override
        { return parent.isValid() ? 0 : m_rows; }
        int columnCount(const QModelIndex& parent = {}) const override
        { return parent.isValid() ? 0 : m_columns; }
        QVariant data(const QModelIndex& index, const int role) const override
        {
            if (!index.isValid() || index.row() >= m_rows || index.column() >= m_columns ||
                (role != Qt::DisplayRole && role != Qt::ToolTipRole)) return {};
            return m_value(index.row(), index.column());
        }
        QVariant headerData(const int section, const Qt::Orientation orientation, const int role) const override
        {
            return orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < m_columns
                ? QVariant(m_header(section)) : QVariant();
        }
        void refreshLanguage()
        {
            if (m_columns > 0) emit headerDataChanged(Qt::Horizontal, 0, m_columns - 1);
            if (m_rows > 0 && m_columns > 0)
                emit dataChanged(index(0, 0), index(m_rows - 1, m_columns - 1), {Qt::DisplayRole, Qt::ToolTipRole});
        }
    private:
        int m_rows;
        int m_columns;
        Value m_value;
        Header m_header;
    };

    // fromUtf8 作用：将扫描后端的 UTF-8 文本安全转换为 Qt 字符串。
    // 参数 value：后端文本；返回值：可直接显示的 QString。
    QString fromUtf8(const std::string& value)
    {
        return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
    }

    // bytesToHexPreview 作用：限制确认框中的字节预览长度，避免超大文本卡住 UI。
    // 参数 bytes：待预览字节；返回值：大写十六进制摘要。
    QString bytesToHexPreview(const QByteArray& bytes)
    {
        constexpr qsizetype kPreviewBytes = 128; // kPreviewBytes：确认框最多展示的字节数。
        const QByteArray preview = bytes.left(kPreviewBytes).toHex(' ').toUpper(); // preview：十六进制前缀。
        if (bytes.size() <= kPreviewBytes)
        {
            return QString::fromLatin1(preview);
        }
        return QStringLiteral("%1 ... (%2 bytes)")
            .arg(QString::fromLatin1(preview))
            .arg(bytes.size());
    }

    // parseOffset 作用：解析十进制或 0x 前缀的十六进制文件偏移。
    // 参数 text：用户输入；offsetOut：成功时的无符号偏移；返回值：是否有效。
    bool parseOffset(const QString& text, std::uint64_t& offsetOut)
    {
        QString normalized = text.trimmed(); // normalized：去除首尾空白后的偏移文本。
        int base = 10; // base：Qt 数值转换所用进制。
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized.remove(0, 2);
            base = 16;
        }

        bool ok = false; // ok：数值转换是否完整成功。
        const qulonglong value = normalized.toULongLong(&ok, base); // value：解析出的文件偏移。
        if (!ok || normalized.isEmpty())
        {
            return false;
        }
        offsetOut = static_cast<std::uint64_t>(value);
        return true;
    }

    // parseReplacementBytes 作用：接受常见分隔符并严格解析偶数个十六进制字符。
    // 参数 text：用户输入；bytesOut：解析结果；返回值：是否得到非空字节。
    bool parseReplacementBytes(const QString& text, QByteArray& bytesOut)
    {
        // tokens：只在明确分隔符处拆分，0x 仅允许作为每个 token 的前缀。
        const QStringList tokens = text.split(
            QRegularExpression(QStringLiteral("[\\s,:;_\\-]+")),
            Qt::SkipEmptyParts);
        QString normalized; // normalized：验证后拼接的连续十六进制文本。
        for (QString token : tokens)
        {
            if (token.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                token.remove(0, 2);
            }
            if (token.isEmpty() ||
                token.contains(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]"))))
            {
                return false;
            }
            normalized += token;
        }
        if (normalized.isEmpty() ||
            (normalized.size() % 2) != 0)
        {
            return false;
        }

        bytesOut = QByteArray::fromHex(normalized.toLatin1());
        return !bytesOut.isEmpty() && bytesOut.size() * 2 == normalized.size();
    }

    // toByteVector 作用：把 Qt 字节数组复制为无符号后端缓冲区。
    // 参数 bytes：Qt 数据；返回值：独立持有内容的 std::vector。
    std::vector<std::uint8_t> toByteVector(const QByteArray& bytes)
    {
        const auto* begin = reinterpret_cast<const std::uint8_t*>(bytes.constData()); // begin：Qt 缓冲区首地址。
        return std::vector<std::uint8_t>(begin, begin + bytes.size());
    }

}

ScannerDock::ScannerDock(QWidget* parent)
    : QWidget(parent)
{
    m_asyncState = std::make_shared<ScannerAsyncState>();
    m_asyncState->owner = this;
    setObjectName(QStringLiteral("ScannerDock"));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    buildUi();
    retranslateUi();
    setStatus("scanner.status.ready", "请选择 PE、ELF、Mach-O 或 ISO9660 镜像开始扫描。");
    // 独立方形宿主下由整页承担过渡；嵌入杂项主框时共享层保留外层唯一过渡。
    ks::ui::StyleWorkspaceContentFrame(this, 8);
}

ScannerDock::~ScannerDock()
{
    ++m_scanGeneration;
    ++m_patchGeneration;
    if (m_asyncState)
    {
        std::lock_guard<std::mutex> lock(m_asyncState->mutex);
        m_asyncState->owner = nullptr;
    }
}

void ScannerDock::buildUi()
{
    // rootLayout：承载路径工具条、状态提示与两大功能页。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(0); // 扫描来源、状态与结果导航组成连续的工作区头部。

    // pathLayout：把路径输入、文件选择和扫描动作排在同一行。
    auto* pathToolbar = new QWidget(this); // 文件目标和扫描动作作为一个紧凑操作区。
    auto* pathStack = new QVBoxLayout(pathToolbar); // 来源行与扫描状态共用页头底面。
    pathStack->setContentsMargins(6, 4, 6, 6);
    pathStack->setSpacing(6);
    auto* pathLayout = new QHBoxLayout();
    pathLayout->setContentsMargins(0, 0, 0, 0);
    pathLayout->setSpacing(6);
    pathStack->addLayout(pathLayout);
    m_pathLabel = new QLabel(this);
    m_pathEdit = new QLineEdit(this);
    // 文件目标在参数滚动区之外，必须独立登记输入底色，不能只统一行高。
    ks::ui::StyleStandaloneInput(m_pathEdit);
    m_pathEdit->setObjectName(QStringLiteral("scanner_target_path"));
    m_pathEdit->setClearButtonEnabled(true);
    m_browseButton = new QPushButton(this);
    m_scanButton = new QPushButton(this);
    m_browseButton->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    m_scanButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    pathLayout->addWidget(m_pathLabel);
    pathLayout->addWidget(m_pathEdit, 1);
    pathLayout->addWidget(m_browseButton);
    pathLayout->addWidget(m_scanButton);
    ks::ui::NormalizeToolbarRow(pathLayout);
    ks::ui::StylePrimaryToolbar(pathToolbar);
    ks::ui::ApplyFlatButtonTheme(m_browseButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    ks::ui::ApplyFlatButtonTheme(m_scanButton, ks::ui::FlatButtonTone::Accent);
    rootLayout->addWidget(pathToolbar);

    // m_statusLabel：允许复制诊断状态，长路径会自动换行。
    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setTextFormat(Qt::PlainText);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    pathStack->addWidget(m_statusLabel);
    m_resultSourceLabel = new QLabel(this);
    m_resultSourceLabel->setTextFormat(Qt::PlainText);
    m_resultSourceLabel->setWordWrap(true);
    m_resultSourceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_resultSourceLabel->hide();
    pathStack->addWidget(m_resultSourceLabel);

    // m_mainTabs：将只读检查与高风险编辑明确分离，避免误触。
    m_mainTabs = new QTabWidget(this);
    m_mainTabs->setDocumentMode(true);
    ks::ui::StyleJoinedResultTabs(m_mainTabs, pathToolbar);
    rootLayout->addWidget(m_mainTabs, 1);
    buildAnalysisUi();

    // inspectionLayout：只承载本次结果的动态标签集合。
    m_inspectionPage = new QWidget(m_mainTabs);
    auto* inspectionLayout = new QVBoxLayout(m_inspectionPage);
    inspectionLayout->setContentsMargins(0, 0, 0, 0);
    m_resultTabs = new QTabWidget(m_inspectionPage);
    m_resultTabs->setDocumentMode(true);
    ks::ui::StylePageTabsContentFrame(m_resultTabs);
    inspectionLayout->addWidget(m_resultTabs);
    m_navigationTabs.add(navigationDefinition(1), m_mainTabs, m_inspectionPage);

    // 编辑页没有独立结果面板，保留单栏；参数正文滚动，确认动作固定在底部。
    m_editorPage = new QWidget(m_mainTabs);
    QFont editorFont = m_editorPage->font(); // 与参数工作区一致提高阅读下限，保留用户字体单位。
    if (editorFont.pixelSize() > 0)
    {
        editorFont.setPixelSize(qMax(14, editorFont.pixelSize()));
    }
    else
    {
        editorFont.setPointSizeF(qMax(10.0, editorFont.pointSizeF()));
    }
    m_editorPage->setFont(editorFont);
    auto* editorLayout = new QVBoxLayout(m_editorPage);
    editorLayout->setContentsMargins(16, 16, 16, 16);
    editorLayout->setSpacing(16);
    auto* parameterScroll = new QScrollArea(m_editorPage);
    parameterScroll->setWidgetResizable(true);
    parameterScroll->setFrameShape(QFrame::NoFrame);
    parameterScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* parameterBody = new QWidget(parameterScroll);
    parameterBody->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    auto* parameterLayout = new QVBoxLayout(parameterBody);
    parameterLayout->setContentsMargins(0, 0, 0, 0);
    parameterLayout->setSpacing(16);
    parameterScroll->setWidget(parameterBody);
    editorLayout->addWidget(parameterScroll, 1);

    // editForm：只收集等长替换所需的偏移与新字节，不提供插入/删除入口。
    auto* editGroup = new QGroupBox(m_editorPage); // 参数与确认动作分区，但继续在同页完整显示。
    ks::i18n::LanguageManager::instance().bindText(editGroup,
        QStringLiteral("scanner.edit.parameters"), QStringLiteral("替换参数"));
    auto* editForm = new QFormLayout(editGroup);
    editForm->setHorizontalSpacing(16);
    editForm->setVerticalSpacing(8);
    editForm->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    editForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    editForm->setRowWrapPolicy(QFormLayout::WrapAllRows);
    m_offsetLabel = new QLabel(m_editorPage);
    m_offsetEdit = new QLineEdit(m_editorPage);
    m_offsetEdit->setPlaceholderText(QStringLiteral("0x00000000"));
    m_replacementLabel = new QLabel(m_editorPage);
    m_replacementEdit = new QLineEdit(m_editorPage);
    m_replacementEdit->setPlaceholderText(QStringLiteral("90 90 90 90"));
    editForm->addRow(m_offsetLabel, m_offsetEdit);
    editForm->addRow(m_replacementLabel, m_replacementEdit);
    ks::ui::NormalizeToolbarControl(m_offsetEdit);
    ks::ui::NormalizeToolbarControl(m_replacementEdit);
    ks::ui::StyleParameterSection(editGroup);
    editGroup->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    parameterLayout->addWidget(editGroup);

    m_backupCheckBox = new QCheckBox(m_editorPage);
    m_backupCheckBox->setChecked(true);
    parameterLayout->addWidget(m_backupCheckBox);

    m_riskCheckBox = new QCheckBox(m_editorPage);
    m_riskCheckBox->setChecked(false);
    parameterLayout->addWidget(m_riskCheckBox);
    parameterLayout->addStretch();
    ks::ui::StyleParameterFields(parameterBody); // 风险原勾选对象保持可见，并按实际宽度换行。

    auto* applyLayout = new QHBoxLayout();
    applyLayout->addStretch(1);
    m_applyPatchButton = new QPushButton(m_editorPage);
    m_applyPatchButton->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    applyLayout->addWidget(m_applyPatchButton);
    ks::ui::NormalizeToolbarRow(applyLayout);
    ks::ui::ApplyFlatButtonTheme(m_applyPatchButton, ks::ui::FlatButtonTone::Danger);
    editorLayout->addLayout(applyLayout);
    m_navigationTabs.add(navigationDefinition(2), m_mainTabs, m_editorPage);

    // 所有按钮和回车动作都通过 ScannerDock 方法进入同一套校验流程。
    connect(m_browseButton, &QPushButton::clicked, this, [this]() { chooseFile(); });
    connect(m_scanButton, &QPushButton::clicked, this, [this]() { beginScan(); });
    connect(m_pathEdit, &QLineEdit::returnPressed, this, [this]() { beginScan(); });
    connect(m_pathEdit, &QLineEdit::textEdited, this, [this]() { updateSelectedTarget(); });
    connect(m_applyPatchButton, &QPushButton::clicked, this, [this]() { beginPatch(); });
}

QString ScannerDock::translated(const char* key, const char* fallback) const
{
    return ks::i18n::text(
        QString::fromLatin1(key),
        QString::fromUtf8(fallback));
}

void ScannerDock::retranslateUi()
{
    retranslateAnalysisUi();
    m_pathLabel->setText(translated("scanner.path.label", "文件路径"));
    m_pathEdit->setPlaceholderText(translated(
        "scanner.path.placeholder",
        "选择要进行结构化解析和攻击路径检测的二进制文件或镜像"));
    m_browseButton->setText(translated("scanner.action.browse", "浏览…"));
    m_scanButton->setText(translated("scanner.action.scan", "扫描"));
    m_browseButton->setToolTip(translated(
        "scanner.action.browse.tooltip",
        "选择要扫描或安全编辑的普通文件"));
    m_scanButton->setToolTip(translated(
        "scanner.action.scan.tooltip",
        "在后台只读解析 PE、ELF、Mach-O 或 ISO9660/Joliet 结构与攻击路径"));
    m_mainTabs->setTabText(
        m_mainTabs->indexOf(m_inspectionPage),
        ks::ui::PageNavigationTabDescriptor(navigationDefinition(1)).title);
    m_mainTabs->setTabText(
        m_mainTabs->indexOf(m_editorPage),
        ks::ui::PageNavigationTabDescriptor(navigationDefinition(2)).title);
    m_offsetLabel->setText(translated("scanner.editor.offset", "文件偏移"));
    m_replacementLabel->setText(translated("scanner.editor.replacement", "替换字节（十六进制）"));
    m_replacementEdit->setToolTip(translated(
        "scanner.editor.replacement.tooltip",
        "只支持等长替换：字节数必须与原始内容完全一致，不能插入或删除。"));
    m_backupCheckBox->setText(translated(
        "scanner.editor.create_backup",
        "应用前创建独立备份（推荐）"));
    m_backupCheckBox->setToolTip(translated(
        "scanner.editor.create_backup.tooltip",
        "备份是同目录下带时间戳的独立副本，不会覆盖之前的备份。"));
    m_riskCheckBox->setText(translated(
        "scanner.editor.risk_ack",
        "我已核对目标、偏移和字节，并理解修改二进制文件的风险"));
    m_riskCheckBox->setToolTip(translated(
        "scanner.editor.risk_ack.tooltip",
        "从释放文件锁到原子替换之间仍有极短竞态，其它进程的并发写入可能破坏快照校验。"));
    m_applyPatchButton->setText(translated("scanner.editor.apply", "核对并应用"));
    m_applyPatchButton->setToolTip(translated(
        "scanner.editor.apply.tooltip",
        "比较当前字节，最终确认后原子替换目标文件"));
    refreshStatus();
    refreshResultSource();

    if (m_lastResult)
    {
        m_resultLanguageDirty = true;
        prepareResultPresentation();
    }
}

void ScannerDock::showEvent(QShowEvent* event)
{
    prepareResultPresentation();
    QWidget::showEvent(event);
}

void ScannerDock::prepareResultPresentation()
{
    if (!isVisible() || !m_lastResult) return;
    if (m_resultPresentationDirty)
    {
        renderResult(*m_lastResult);
        m_resultPresentationDirty = false;
        m_resultLanguageDirty = false;
    }
    else if (m_resultLanguageDirty)
    {
        refreshResultLanguage();
        m_resultLanguageDirty = false;
    }
}

void ScannerDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
    else if (event != nullptr && (event->type() == QEvent::PaletteChange ||
        event->type() == QEvent::ApplicationPaletteChange))
    {
        retranslateAnalysisUi();
    }
}

void ScannerDock::chooseFile()
{
    const QPointer<ScannerDock> guard(this);
    const QString selectedPath = QFileDialog::getOpenFileName(
        this,
        translated("scanner.dialog.choose_file", "选择二进制文件"),
        m_pathEdit->text().trimmed(),
        translated(
            "scanner.dialog.file_filter",
            "二进制与镜像 (*.exe *.dll *.sys *.efi *.elf *.so *.dylib *.o *.bin *.img *.iso);;所有文件 (*.*)"));
    if (!guard || selectedPath.isEmpty())
    {
        return;
    }
    m_pathEdit->setText(QDir::toNativeSeparators(selectedPath));
    updateSelectedTarget();
}

void ScannerDock::updateSelectedTarget()
{
    if (m_scanBusy || m_patchBusy) return;
    m_riskCheckBox->setChecked(false);
    if (m_pathEdit->text().trimmed().isEmpty()) {
        setStatus("scanner.status.ready", "请选择 PE、ELF、Mach-O 或 ISO9660 镜像开始扫描。");
        return;
    }
    setStatus(
        "scanner.status.target_selected",
        "目标已设置；点击“扫描”或按 Enter 开始。选择文件不会自动扫描。");
}

void ScannerDock::refreshResultSource()
{
    m_resultSourceLabel->setVisible(bool(m_lastResult));
    if (m_lastResult) {
        m_resultSourceLabel->setText(translated(
            "scanner.result.source_path",
            "当前显示的扫描结果来自：%1").arg(m_lastScannedPath));
    }
}

void ScannerDock::beginScan()
{
    if (m_scanBusy || m_patchBusy)
    {
        return;
    }

    // fileInfo：启动线程前先排除空路径、目录和不存在的目标。
    const QString path = QDir::toNativeSeparators(m_pathEdit->text().trimmed());
    const QFileInfo fileInfo(path);
    if (path.isEmpty() || !fileInfo.exists() || !fileInfo.isFile())
    {
        QMessageBox::warning(
            this,
            translated("scanner.dialog.invalid_file.title", "无法扫描"),
            translated("scanner.dialog.invalid_file.body", "请选择一个存在的普通文件。"));
        return;
    }

    m_pathEdit->setText(path);
    setScanBusy(true);
    setStatus(
        "scanner.status.scanning",
        "正在扫描：%1",
        QStringList{ path });

    // generation：只有最新一代结果可以回写，避免旧扫描覆盖新目标。
    const std::uint64_t generation = ++m_scanGeneration;
    const std::wstring nativePath = path.toStdWString();
    const std::shared_ptr<ScannerAsyncState> asyncState = m_asyncState;
    QThreadPool::globalInstance()->start(
        [asyncState, generation, path, nativePath]()
        {
            auto result = std::make_shared<ks::scanner::BinaryScanResult>(
                [&nativePath]() {
                    ks::scanner::ScanOptions options;
                    options.retainInputSnapshot = true;
                    return ks::scanner::ScanBinaryFile(nativePath, options);
                }());
            std::lock_guard<std::mutex> lock(asyncState->mutex);
            ScannerDock* receiver = asyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [asyncState, generation, path, result = std::move(result)]()
                {
                    ScannerDock* owner = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(asyncState->mutex);
                        owner = asyncState->owner;
                    }
                    if (owner != nullptr)
                    {
                        owner->finishScan(generation, path, result);
                    }
                },
                Qt::QueuedConnection);
        });
}

void ScannerDock::finishScan(
    const std::uint64_t generation,
    const QString& scannedPath,
    std::shared_ptr<ks::scanner::BinaryScanResult> result)
{
    if (generation != m_scanGeneration.load() || !result)
    {
        return;
    }

    setScanBusy(false);
    m_lastResult = std::move(result);
    m_lastScannedPath = scannedPath;
    refreshResultSource();
    m_resultPresentationDirty = true;
    prepareResultPresentation();

    if (m_lastResult->success && m_lastResult->attackPath.matched)
    {
        setStatus(
            "scanner.status.attack_detected",
            "扫描完成并检测到 EXIT / GhostSystemDriver 攻击路径：%1，评分 %2/100。",
            QStringList{
                scannedPath,
                QString::number(m_lastResult->attackPath.score)
            });
    }
    else if (m_lastResult->success)
    {
        setStatus(
            "scanner.status.success",
            "扫描完成：%1，格式 %2，大小 %3 字节。",
            QStringList{
                scannedPath,
                QString::fromLatin1(ks::scanner::FormatName(m_lastResult->format)),
                QString::number(m_lastResult->fileSize)
            });
    }
    else if (m_lastResult->recognized)
    {
        setStatus(
            "scanner.status.malformed",
            "已识别格式，但文件结构无效或不完整：%1",
            QStringList{ scannedPath });
    }
    else
    {
        setStatus(
            "scanner.status.unsupported",
            "未识别为受支持的 PE、ELF、Mach-O 或 ISO9660 文件：%1",
            QStringList{ scannedPath });
    }
}

QTableWidget* ScannerDock::createReadOnlyTable(QWidget* parent) const
{
    auto* table = new QTableWidget(parent);
    // 单文件解析结果是静态证据：保留复制/导出，不提供现场快照和对比工具。
    ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setAlternatingRowColors(true);
    table->setWordWrap(false);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionsMovable(true);
    table->horizontalHeader()->setStretchLastSection(true);
    return table;
}

void ScannerDock::clearResultTabs()
{
    for (const auto& page : m_resultNavigationSchema) m_navigationTabs.remove(page.id);
    m_resultNavigationSchema.clear();
    while (m_resultTabs->count() > 0)
    {
        QWidget* page = m_resultTabs->widget(0);
        m_resultTabs->removeTab(0);
        delete page;
    }
}

void ScannerDock::renderResult(const ks::scanner::BinaryScanResult& result)
{
    renderAnalysisResult();
    clearResultTabs();
    auto retired = std::move(m_presentedResult);
    m_presentedResult = m_lastResult;
    if (retired) QThreadPool::globalInstance()->start([retired = std::move(retired)]() {});

    auto* summaryTable = createReadOnlyTable(m_resultTabs);
    // 摘要字段只是短属性表，复制单元格即可，无需再占一行操作栏。
    ks::ui::SetTableActionBarMode(summaryTable, ks::ui::TableActionBarMode::None);
    summaryTable->setColumnCount(2);
    summaryTable->setHorizontalHeaderLabels({
        translated("scanner.column.field", "字段"),
        translated("scanner.column.value", "值")
    });

    // summaryFields：先放格式中立元数据，再追加后端专属摘要并去除重复三项。
    std::vector<ks::scanner::BinaryField> summaryFields{
        { "Format", ks::scanner::FormatName(result.format) },
        { "Byte order", ks::scanner::ByteOrderName(result.byteOrder) },
        { "File size", std::to_string(result.fileSize) }
    };
    for (const ks::scanner::BinaryField& field : result.summary)
    {
        const QString normalizedName = fromUtf8(field.name).trimmed().toLower(); // normalizedName：用于摘要去重的字段名。
        if (normalizedName == QStringLiteral("format") ||
            normalizedName == QStringLiteral("byte order") ||
            normalizedName == QStringLiteral("file size"))
        {
            continue;
        }
        summaryFields.push_back(field);
    }
    summaryTable->setRowCount(static_cast<int>(summaryFields.size()));
    for (int row = 0; row < summaryTable->rowCount(); ++row)
    {
        const auto& field = summaryFields[static_cast<std::size_t>(row)];
        summaryTable->setItem(row, 0, new QTableWidgetItem(localizedColumnTitle(field.name)));
        summaryTable->item(row, 0)->setData(Qt::UserRole, row);
        summaryTable->setItem(
            row,
            1,
            new QTableWidgetItem(ks::i18n::sourceText(fromUtf8(field.value))));
    }
    summaryTable->resizeColumnsToContents();
    addResultNavigationTab(summaryTable, translated("scanner.result.summary", "摘要"));

    if (!result.attackPath.evidence.empty())
    {
        addResultNavigationTab(
            createAttackPathPage(result),
            translated("scanner.result.attack_path", "攻击路径"));
    }

    auto* headerTable = createReadOnlyTable(m_resultTabs);
    ks::ui::SetTableActionBarMode(headerTable, ks::ui::TableActionBarMode::None);
    headerTable->setColumnCount(2);
    headerTable->setHorizontalHeaderLabels({
        translated("scanner.column.field", "字段"),
        translated("scanner.column.value", "值")
    });
    headerTable->setRowCount(static_cast<int>(result.headers.size()));
    for (int row = 0; row < headerTable->rowCount(); ++row)
    {
        const auto& field = result.headers[static_cast<std::size_t>(row)];
        headerTable->setItem(row, 0, new QTableWidgetItem(localizedColumnTitle(field.name)));
        headerTable->item(row, 0)->setData(Qt::UserRole, row);
        headerTable->setItem(
            row,
            1,
            new QTableWidgetItem(ks::i18n::sourceText(fromUtf8(field.value))));
    }
    headerTable->resizeColumnsToContents();
    addResultNavigationTab(headerTable, translated("scanner.result.headers", "文件头"));

    const auto snapshot = m_lastResult;
    for (std::size_t tableIndex = 0; tableIndex < result.tables.size(); ++tableIndex)
    {
        const auto& sourceTable = result.tables[tableIndex];
        auto* table = new ks::ui::TableActionTableView(m_resultTabs);
        ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setAlternatingRowColors(true);
        table->setWordWrap(false);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionsMovable(true);
        table->horizontalHeader()->setStretchLastSection(true);
        auto* model = new ScannerTableModel(static_cast<int>(sourceTable.rows.size()),
            static_cast<int>(sourceTable.columns.size()),
            [this, snapshot, tableIndex](const int row, const int column) {
                const auto& source = snapshot->tables[tableIndex];
                const auto& values = source.rows[static_cast<std::size_t>(row)];
                return column < static_cast<int>(values.size())
                    ? localizedTableValue(source.id, column, values[static_cast<std::size_t>(column)]) : QString();
            },
            [this, snapshot, tableIndex](const int column) {
                return localizedColumnTitle(snapshot->tables[tableIndex].columns[static_cast<std::size_t>(column)]);
            }, table);
        auto* proxy = new QSortFilterProxyModel(table);
        proxy->setSourceModel(model);
        proxy->setDynamicSortFilter(false);
        table->setModel(proxy);
        table->horizontalHeader()->setSectionsClickable(true);
        // A source row stays the same section after a user sort.
        connect(table->horizontalHeader(), &QHeaderView::sectionClicked, table,
            [table, proxy](const int column) {
                const auto* header = table->horizontalHeader();
                const auto order = proxy->sortColumn() == column &&
                    header->sortIndicatorOrder() == Qt::AscendingOrder ? Qt::DescendingOrder : Qt::AscendingOrder;
                proxy->sort(column, order);
                table->horizontalHeader()->setSortIndicator(column, order);
                table->horizontalHeader()->setSortIndicatorShown(true);
            });
        // Bound automatic measurement to a small sample; all rows remain available to copy/export.
        table->horizontalHeader()->setResizeContentsPrecision(64);
        table->resizeColumnsToContents();
        if (sourceTable.id == "sections" &&
            (result.format == ks::scanner::BinaryFormat::Pe32 || result.format == ks::scanner::BinaryFormat::Pe32Plus))
        {
            connect(table, &QTableView::doubleClicked, this, [this, proxy, snapshot](const QModelIndex& index) {
                if (snapshot != m_lastResult || !index.isValid()) return;
                const auto sourceIndex = proxy->mapToSource(index);
                const auto regionIndex = static_cast<std::size_t>(sourceIndex.row()) + 1;
                if (regionIndex >= snapshot->mappedRegions.size()) return;
                const auto& region = snapshot->mappedRegions[regionIndex];
                if (region.fileSize != 0)
                    navigateAnalysisOffset(region.fileOffset,
                        (region.characteristics & 0x20000000U) != 0 && snapshot->x86Compatible);
            });
        }
        QString title = localizedTableTitle(sourceTable.id, sourceTable.title);
        if (sourceTable.truncated) title += translated("scanner.result.truncated_suffix", "（已截断）");
        QWidget* page = createStructuredTablePage(table, static_cast<int>(sourceTable.columns.size()));
        page->setProperty("scanner_source_table_index", static_cast<int>(tableIndex));
        addResultNavigationTab(page, title);
    }

    auto* diagnosticsTable = createReadOnlyTable(m_resultTabs);
    diagnosticsTable->setColumnCount(4);
    diagnosticsTable->setHorizontalHeaderLabels({
        translated("scanner.column.severity", "级别"),
        translated("scanner.column.code", "代码"),
        translated("scanner.column.message", "说明"),
        translated("scanner.column.offset", "偏移")
    });
    diagnosticsTable->setRowCount(static_cast<int>(result.diagnostics.size()));
    for (int row = 0; row < diagnosticsTable->rowCount(); ++row)
    {
        const auto& diagnostic = result.diagnostics[static_cast<std::size_t>(row)];
        diagnosticsTable->setItem(
            row,
            0,
            new QTableWidgetItem(diagnosticSeverityText(static_cast<int>(diagnostic.severity))));
        diagnosticsTable->setItem(row, 1, new QTableWidgetItem(fromUtf8(diagnostic.code)));
        diagnosticsTable->setItem(
            row,
            2,
            new QTableWidgetItem(
                localizedDiagnosticMessage(diagnostic.code, diagnostic.message)));
        diagnosticsTable->setItem(
            row,
            3,
            new QTableWidgetItem(
                diagnostic.hasOffset
                    ? QStringLiteral("0x%1").arg(diagnostic.offset, 0, 16).toUpper()
                    : QString()));
    }
    for (int row = 0; row < diagnosticsTable->rowCount(); ++row)
        diagnosticsTable->item(row, 0)->setData(Qt::UserRole, row);
    diagnosticsTable->resizeColumnsToContents();
    addResultNavigationTab(
        diagnosticsTable,
        translated("scanner.result.diagnostics", "诊断"));
}

void ScannerDock::refreshResultLanguage()
{
    if (!m_presentedResult || m_presentedResult != m_lastResult || m_resultTabs->count() == 0) return;
    const auto& result = *m_presentedResult;
    // Translation changes display roles without replacing views, selection, columns or the analysis snapshot.
    for (auto* model : m_resultTabs->findChildren<QAbstractItemModel*>())
        if (auto* scannerModel = dynamic_cast<ScannerTableModel*>(model)) scannerModel->refreshLanguage();
    for (auto* button : m_resultTabs->findChildren<QPushButton*>())
        if (button->property("scanner_column_group").toBool())
            button->setToolTip(translated("scanner.column_view.tooltip",
                "列组 %1：显示一组互补字段；可在表头右键自定义列。").arg(button->text()));
    int tab = 0;
    auto* summary = qobject_cast<QTableWidget*>(m_resultTabs->widget(tab));
    m_resultTabs->setTabText(tab++, translated("scanner.result.summary", "摘要"));
    std::vector<ks::scanner::BinaryField> summaryFields{
        {"Format", ks::scanner::FormatName(result.format)},
        {"Byte order", ks::scanner::ByteOrderName(result.byteOrder)},
        {"File size", std::to_string(result.fileSize)}};
    for (const auto& field : result.summary)
    {
        const QString name = fromUtf8(field.name).trimmed().toLower();
        if (name != QStringLiteral("format") && name != QStringLiteral("byte order") && name != QStringLiteral("file size"))
            summaryFields.push_back(field);
    }
    const QStringList fieldHeaders{translated("scanner.column.field", "字段"), translated("scanner.column.value", "值")};
    if (summary)
    {
        summary->setHorizontalHeaderLabels(fieldHeaders);
        for (int row = 0; row < summary->rowCount(); ++row)
        {
            const int sourceRow = summary->item(row, 0)->data(Qt::UserRole).toInt();
            if (sourceRow < 0 || sourceRow >= static_cast<int>(summaryFields.size())) continue;
            const auto& field = summaryFields[static_cast<std::size_t>(sourceRow)];
            summary->item(row, 0)->setText(localizedColumnTitle(field.name));
            summary->item(row, 1)->setText(ks::i18n::sourceText(fromUtf8(field.value)));
        }
    }
    if (!result.attackPath.evidence.empty())
    {
        auto* page = m_resultTabs->widget(tab);
        m_resultTabs->setTabText(tab++, translated("scanner.result.attack_path", "攻击路径"));
        auto* label = page->findChild<QLabel*>();
        if (label) label->setText((result.attackPath.matched
            ? translated("scanner.attack.verdict.detected", "检测到 EXIT / GhostSystemDriver 攻击路径：评分 %1/100，规则 %2。")
            : translated("scanner.attack.verdict.below_threshold", "发现相关静态证据，但未达到攻击路径阈值：评分 %1/100，规则 %2。"))
            .arg(result.attackPath.score).arg(fromUtf8(result.attackPath.ruleId)));
        auto* table = page->findChild<QTableWidget*>();
        if (table)
        {
            table->setHorizontalHeaderLabels({translated("scanner.column.severity", "级别"),
                translated("scanner.attack.column.stage", "阶段"), translated("scanner.attack.column.evidence", "静态证据"),
                translated("scanner.attack.column.artifact", "对象"), QStringLiteral("MITRE ATT&CK"),
                translated("scanner.attack.column.score", "评分"), translated("scanner.column.offset", "偏移")});
            for (int row = 0; row < table->rowCount(); ++row)
            {
                const int sourceRow = table->item(row, 0)->data(Qt::UserRole).toInt();
                if (sourceRow < 0 || sourceRow >= static_cast<int>(result.attackPath.evidence.size())) continue;
                const auto& evidence = result.attackPath.evidence[static_cast<std::size_t>(sourceRow)];
                table->item(row, 0)->setText(attackPathSeverityText(static_cast<int>(evidence.severity)));
                table->item(row, 1)->setText(attackPathStageText(evidence.stage));
                table->item(row, 2)->setText(attackPathEvidenceText(evidence.code));
                if (!evidence.hasOffset) table->item(row, 6)->setText(translated("scanner.attack.offset.decoded", "解码后对象"));
            }
        }
    }
    auto* headers = qobject_cast<QTableWidget*>(m_resultTabs->widget(tab));
    m_resultTabs->setTabText(tab++, translated("scanner.result.headers", "文件头"));
    if (headers)
    {
        headers->setHorizontalHeaderLabels(fieldHeaders);
        for (int row = 0; row < headers->rowCount(); ++row)
        {
            const int sourceRow = headers->item(row, 0)->data(Qt::UserRole).toInt();
            if (sourceRow < 0 || sourceRow >= static_cast<int>(result.headers.size())) continue;
            const auto& field = result.headers[static_cast<std::size_t>(sourceRow)];
            headers->item(row, 0)->setText(localizedColumnTitle(field.name));
            headers->item(row, 1)->setText(ks::i18n::sourceText(fromUtf8(field.value)));
        }
    }
    for (const auto& source : result.tables)
    {
        QString title = localizedTableTitle(source.id, source.title);
        if (source.truncated) title += translated("scanner.result.truncated_suffix", "（已截断）");
        m_resultTabs->setTabText(tab++, title);
    }
    auto* diagnostics = qobject_cast<QTableWidget*>(m_resultTabs->widget(tab));
    m_resultTabs->setTabText(tab, translated("scanner.result.diagnostics", "诊断"));
    if (diagnostics)
    {
        diagnostics->setHorizontalHeaderLabels({translated("scanner.column.severity", "级别"),
            translated("scanner.column.code", "代码"), translated("scanner.column.message", "说明"), translated("scanner.column.offset", "偏移")});
        for (int row = 0; row < diagnostics->rowCount(); ++row)
        {
            const int sourceRow = diagnostics->item(row, 0)->data(Qt::UserRole).toInt();
            if (sourceRow < 0 || sourceRow >= static_cast<int>(result.diagnostics.size())) continue;
            const auto& diagnostic = result.diagnostics[static_cast<std::size_t>(sourceRow)];
            diagnostics->item(row, 0)->setText(diagnosticSeverityText(static_cast<int>(diagnostic.severity)));
            diagnostics->item(row, 2)->setText(localizedDiagnosticMessage(diagnostic.code, diagnostic.message));
        }
    }
}

void ScannerDock::beginPatch()
{
    if (m_patchBusy || m_scanBusy)
    {
        return;
    }

    // fileInfo：UI 先拒绝目录和符号链接；后端还会拒绝所有重解析点。
    const QString path = QDir::toNativeSeparators(m_pathEdit->text().trimmed());
    const QFileInfo fileInfo(path);
    if (path.isEmpty() || !fileInfo.exists() || !fileInfo.isFile() || fileInfo.isSymLink())
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.invalid_target.title", "无法编辑"),
            translated(
                "scanner.editor.invalid_target.body",
                "目标必须是存在的普通文件，不能是目录或符号链接。"));
        return;
    }

    std::uint64_t offset = 0;
    if (!parseOffset(m_offsetEdit->text(), offset))
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.invalid_offset.title", "偏移无效"),
            translated(
                "scanner.editor.invalid_offset.body",
                "请输入十进制偏移，或以 0x 开头的十六进制偏移。"));
        return;
    }

    // replacementBytes：解析结果必须非空、等长覆盖且不超过后端硬上限。
    QByteArray replacementBytes;
    if (!parseReplacementBytes(m_replacementEdit->text(), replacementBytes))
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.invalid_bytes.title", "替换字节无效"),
            translated(
                "scanner.editor.invalid_bytes.body",
                "请输入偶数个十六进制字符；可使用空格、逗号、冒号或短横线分隔。"));
        return;
    }

    constexpr qsizetype kUiPatchLimit = 16 * 1024 * 1024;
    if (replacementBytes.size() > kUiPatchLimit)
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.patch_too_large.title", "修改范围过大"),
            translated(
                "scanner.editor.patch_too_large.body",
                "单次修改不能超过 16 MiB。"));
        return;
    }
    if (!m_riskCheckBox->isChecked())
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.ack_required.title", "需要风险确认"),
            translated(
                "scanner.editor.ack_required.body",
                "请先核对目标和修改内容，并勾选风险确认。"));
        return;
    }

    // target/expectedBytes：确认前读取当前字节，提交时仍由后端再次比较。
    QFile target(path);
    if (!target.open(QIODevice::ReadOnly))
    {
        QMessageBox::critical(
            this,
            translated("scanner.editor.read_failed.title", "无法读取目标"),
            translated("scanner.editor.read_failed.body", "无法打开目标文件进行修改前核对。"));
        return;
    }
    const std::uint64_t fileSize = static_cast<std::uint64_t>(target.size());
    const std::uint64_t patchSize = static_cast<std::uint64_t>(replacementBytes.size());
    if (offset > fileSize || patchSize > fileSize - offset ||
        offset > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
        !target.seek(static_cast<qint64>(offset)))
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.range_invalid.title", "修改范围越界"),
            translated(
                "scanner.editor.range_invalid.body",
                "偏移和替换字节长度超出了当前文件范围。"));
        return;
    }
    const QByteArray expectedBytes = target.read(replacementBytes.size());
    target.close();
    if (expectedBytes.size() != replacementBytes.size())
    {
        QMessageBox::critical(
            this,
            translated("scanner.editor.read_failed.title", "无法读取目标"),
            translated("scanner.editor.read_failed.body", "无法打开目标文件进行修改前核对。"));
        return;
    }
    if (expectedBytes == replacementBytes)
    {
        QMessageBox::information(
            this,
            translated("scanner.editor.no_change.title", "无需修改"),
            translated("scanner.editor.no_change.body", "目标范围已经包含相同字节。"));
        return;
    }

    // backupPath：每次修改使用新的 UTC 时间戳文件，绝不静默覆盖旧备份。
    const bool createBackup = m_backupCheckBox->isChecked();
    const QString backupPath = createBackup
        ? QStringLiteral("%1.ksword.%2.bak")
            .arg(
                path,
                QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmsszzz")))
        : QString();
    const QString confirmation = translated(
        "scanner.editor.confirm.body",
        "即将修改：%1\n偏移：0x%2\n长度：%3 字节\n当前：%4\n替换：%5\n备份：%6\n\n提交前会再次核对当前字节和整文件快照；Windows 仍存在释放文件锁到原子替换间的极短竞态。修改后请重新扫描确认。是否继续？")
        .arg(path)
        .arg(offset, 0, 16)
        .arg(replacementBytes.size())
        .arg(bytesToHexPreview(expectedBytes))
        .arg(bytesToHexPreview(replacementBytes))
        .arg(
            createBackup
                ? backupPath
                : translated("scanner.editor.no_backup", "不创建备份"));
    const QMessageBox::StandardButton decision = QMessageBox::warning(
        this,
        translated("scanner.editor.confirm.title", "最终确认：修改二进制文件"),
        confirmation,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (decision != QMessageBox::Yes)
    {
        return;
    }

    // options：把当前字节作为 compare-before-write 前置条件交给原子写入后端。
    ks::scanner::AtomicPatchOptions options;
    options.createBackup = createBackup;
    options.overwriteBackup = false;
    options.rejectReparsePoints = true;
    options.expectedBytes = toByteVector(expectedBytes);
    if (createBackup)
    {
        options.backupPath = backupPath.toStdWString();
    }

    setPatchBusy(true);
    setStatus(
        "scanner.status.patching",
        "正在安全写入并校验：%1",
        QStringList{ path });

    // generation：写入完成前锁定相关控件，过期回调不得更新当前页面。
    const std::uint64_t generation = ++m_patchGeneration;
    const std::wstring nativePath = path.toStdWString();
    std::vector<std::uint8_t> replacement = toByteVector(replacementBytes);
    const std::shared_ptr<ScannerAsyncState> asyncState = m_asyncState;
    QThreadPool::globalInstance()->start(
        [asyncState,
         generation,
         path,
         nativePath,
         offset,
         replacement = std::move(replacement),
         options = std::move(options)]() mutable
        {
            auto result = std::make_shared<ks::scanner::AtomicPatchResult>(
                ks::scanner::PatchFileAtOffsetAtomic(
                    nativePath,
                    offset,
                    replacement,
                    options));
            std::lock_guard<std::mutex> lock(asyncState->mutex);
            ScannerDock* receiver = asyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [asyncState, generation, path, result = std::move(result)]()
                {
                    ScannerDock* owner = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(asyncState->mutex);
                        owner = asyncState->owner;
                    }
                    if (owner != nullptr)
                    {
                        owner->finishPatch(generation, path, result);
                    }
                },
                Qt::QueuedConnection);
        });
}

void ScannerDock::finishPatch(
    const std::uint64_t generation,
    const QString& patchedPath,
    std::shared_ptr<ks::scanner::AtomicPatchResult> result)
{
    if (generation != m_patchGeneration.load() || !result)
    {
        return;
    }

    setPatchBusy(false);
    if (!result->success)
    {
        const QString detail = QString::fromStdWString(result->errorText);
        const QString errorText = result->systemError != 0
            ? translated(
                "scanner.editor.failed_with_code",
                "%1\n系统错误：%2")
                .arg(detail)
                .arg(result->systemError)
            : detail;
        setStatus(
            "scanner.status.patch_failed",
            "安全写入失败：%1",
            QStringList{ patchedPath });
        QMessageBox::critical(
            this,
            translated("scanner.editor.failed.title", "修改失败"),
            errorText.isEmpty()
                ? translated("scanner.editor.failed.unknown", "未能原子替换目标文件。")
                : errorText);
        return;
    }

    const QString backupPath = QString::fromStdWString(result->backupPath);
    m_riskCheckBox->setChecked(false);
    setStatus(
        "scanner.status.patch_success",
        "修改已原子提交：%1",
        QStringList{ patchedPath });
    QString successText = backupPath.isEmpty()
        ? translated(
            "scanner.editor.success.no_backup",
            "修改已提交。此次操作未创建备份。")
        : translated(
            "scanner.editor.success.with_backup",
            "修改已提交。\n原文件备份：%1")
            .arg(backupPath);
    if (result->recoveredAfterReplaceFailure)
    {
        successText += QStringLiteral("\n\n") + translated(
            "scanner.editor.success.recovered",
            "Windows 原子替换曾进入部分完成状态；KSword 已将完整刷新后的替换文件恢复到目标路径并核对修改范围。请立即重新扫描确认文件。");
        QMessageBox::warning(
            this,
            translated("scanner.editor.success.title", "修改完成"),
            successText);
    }
    else
    {
        QMessageBox::information(
            this,
            translated("scanner.editor.success.title", "修改完成"),
            successText);
    }

    if (QDir::toNativeSeparators(m_pathEdit->text().trimmed())
        .compare(patchedPath, Qt::CaseInsensitive) == 0)
    {
        beginScan();
    }
}

void ScannerDock::setStatus(
    const char* key,
    const char* fallback,
    const QStringList& arguments)
{
    m_statusKey = QString::fromLatin1(key);
    m_statusFallback = QString::fromUtf8(fallback);
    m_statusArguments = arguments;
    refreshStatus();
}

void ScannerDock::refreshStatus()
{
    if (m_statusLabel == nullptr || m_statusKey.isEmpty())
    {
        return;
    }
    QString text = ks::i18n::text(m_statusKey, m_statusFallback);
    for (const QString& argument : m_statusArguments)
    {
        text = text.arg(argument);
    }
    m_statusLabel->setText(text);
}

void ScannerDock::setScanBusy(const bool busy)
{
    m_scanBusy = busy;
    m_scanButton->setEnabled(!busy && !m_patchBusy);
    m_browseButton->setEnabled(!busy && !m_patchBusy);
    m_applyPatchButton->setEnabled(!busy && !m_patchBusy);
    // 扫描期间锁定路径，保证路径栏、后台快照和最终结果始终指向同一文件。
    m_pathEdit->setEnabled(!busy && !m_patchBusy);
}

void ScannerDock::setPatchBusy(const bool busy)
{
    m_patchBusy = busy;
    m_scanButton->setEnabled(!busy && !m_scanBusy);
    m_browseButton->setEnabled(!busy && !m_scanBusy);
    m_applyPatchButton->setEnabled(!busy);
    m_pathEdit->setEnabled(!busy && !m_scanBusy);
    m_offsetEdit->setEnabled(!busy);
    m_replacementEdit->setEnabled(!busy);
    m_backupCheckBox->setEnabled(!busy);
    m_riskCheckBox->setEnabled(!busy);
}

const ks::ui::PageNavigationTabDefinition& ScannerDock::navigationDefinition(const int index)
{
    return kScannerNavigation[index];
}
void ScannerDock::addResultNavigationTab(QWidget* page, const QString& title)
{
    const QString id = QStringLiteral("result:") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QByteArray idBytes = id.toUtf8();
    const QByteArray titleBytes = title.toUtf8();
    const ks::ui::PageNavigationTabDefinition definition{idBytes.constData(), "inspection", "", titleBytes.constData(),
        m_resultNavigationSchema.isEmpty()};
    m_navigationTabs.add(definition, m_resultTabs, page);
    m_resultTabs->setTabText(m_resultTabs->indexOf(page), title);
    m_resultNavigationSchema.append(ks::ui::PageNavigationTabDescriptor(definition));
}
ks::ui::PageNavigationCatalog ScannerDock::navigationCatalog(const ScannerDock* existing)
{
    ks::ui::PageNavigationCatalog schema;
    for (int index = 0; index < 3; ++index)
    {
        schema.append(ks::ui::PageNavigationTabDescriptor(navigationDefinition(index)));
        if (index == 1 && existing) schema += existing->m_resultNavigationSchema;
    }
    if (existing) schema = existing->m_navigationTabs.describe(std::move(schema));
    // 子目录由原编辑器拥有，不送入本页Tab表重写状态。
    auto children = ks::ui::SnapshotWorkbenchWidget::navigationCatalog(existing ? existing->m_analysisEditor : nullptr);
    for (auto& child : children)
    {
        child.id.prepend(QStringLiteral("analysis:"));
        child.parentId = child.parentId.isEmpty() ? QStringLiteral("analysis") : QStringLiteral("analysis:") + child.parentId;
    }
    for (qsizetype index = children.size(); index > 0; --index) schema.insert(1, children[index - 1]);
    return schema;
}
QWidget* ScannerDock::activateNavigationDescriptor(const QString& id)
{
    const QString prefix = QStringLiteral("analysis:");
    if (!id.startsWith(prefix)) return m_navigationTabs.activate(id, navigationCatalog(this));
    const QPointer<ScannerDock> self(this);
    const QPointer<QWidget> root(m_analysisPage);
    const QPointer<ks::ui::SnapshotWorkbenchWidget> editor(m_analysisEditor);
    const auto permitted = [self, &id](bool current) {
        if (!self) return false;
        const auto resolved = ks::ui::ResolvePageNavigationCatalog(navigationCatalog(self), QString());
        if (!resolved) return false;
        for (const auto& page : *resolved)
            if (page.page.id == id) return page.page.visible && page.page.enabled && (!current || page.page.current);
        return false;
    };
    if (!root || !editor || !permitted(false)) return nullptr;
    if (!m_navigationTabs.activate(QStringLiteral("analysis"), navigationCatalog(this))) return nullptr;
    if (!self || !root || !editor || self->m_analysisPage != root || self->m_analysisEditor != editor || !permitted(false)) return nullptr;
    const QPointer<QWidget> target(editor->activateNavigationDescriptor(id.mid(prefix.size())));
    if (!self || !root || !editor || !target || self->m_analysisPage != root || self->m_analysisEditor != editor
        || !self->m_mainTabs || self->m_mainTabs->currentWidget() != root || !permitted(true)) return nullptr;
    return target.data();
}
namespace { const bool kScannerNavigationRegistered =
    ks::ui::RegisterTypedPageNavigationCatalog<ScannerDock>(QStringLiteral("misc.scanner")); }
