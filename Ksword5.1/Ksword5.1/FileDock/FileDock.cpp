#include "FileDock.h"
#include "FilePropertyTableModel.h"
#include "NtfsSearchPage.h"
#include "DiskSpacePage.h"
#include "../UI/TableContextMenu.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeBinding.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/AsyncOperation.h"
#include "../UI/AsyncCleanupRegistry.h"
#include "../UI/ResultTableHost.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/UI_All.h"
#include "FilePropertyPeAnalyzer.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/DetailPresentation.h"
#include "DriverFileSystemParser.h"
#include "IrpFileSystemParser.h"
#include "FileHandleUsageScanner.h"
#include "../Internationalization/LanguageManager.h"
#include "../MainWindow.h"
#include "../MiscDock/DiskEditor/StorageControllerResearchDialog.h"

// ============================================================
// FileDock.cpp
// 说明：
// - 该文件实现双栏资源管理器核心交互；
// - 支持导航、过滤、排序、基础文件操作与文件详情展示。
// ============================================================

#include "../theme.h"
#include "../UI/CodeTextEdit.h"
#include "../UI/MemoryWorkbench/HexView.h"
#include "../UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableInteractionSupport.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../KernelDock/KernelCleanImageBaseline.h"
#include "../PluginHost.h"
#include "../ksword/file/file_handle_tools.h"
#include "../ksword/file/file_metadata_transaction.h"
#include "../ksword/file/file.h"
#include "../ksword/process/process_run_as.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QAbstractTableModel>
#include <QAction>
#include <QByteArray>
#include <QButtonGroup>
#include <QClipboard>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QCryptographicHash>
#include <QCollator>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include "../UI/SecondaryPageLayout.h"
#include <QDir>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QEvent>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QFileDialog>
#include <QFileSystemModel>
#include <QFileIconProvider>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHash>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QImage>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListView>
#include <QMenu>
#include <QMessageBox>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrentRun>
#include <QMetaObject>
#include <QMimeDatabase>
#include <QMimeType>
#include <QModelIndex>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPersistentModelIndex>
#include <QPair>
#include <QTextEdit>
#include <QPointer>
#include <QPalette>
#include <QScopedValueRollback>
#include <QProgressBar>
#include <QProgressDialog>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScreen>
#include <QScrollArea>
#include <QScrollBar>
#include <QSaveFile>
#include <QSet>
#include <QShortcut>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QStorageInfo>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStringList>
#include <QStackedWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeView>
#include <QTimeZone>
#include <QUrl>
#include <QUuid>
#include <QVector>
#include <QVBoxLayout>
#include <QWindow>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <io.h>
#include <Shellapi.h>
#include <winioctl.h>
#include <Wbemidl.h>
#include <fltUser.h>
#include <atlbase.h>
#include <comdef.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <cctype>
#include <cmath>
#include <functional>
#include <map>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>

#include <Aclapi.h>
#include <Softpub.h>
#include <Sddl.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "FltLib.lib")

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x100UL)
#endif

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x5000UL
#endif

#ifndef SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP 0x1UL
#endif

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010L
#endif

// Recovery snapshots contain values only. The table and its row projection stay on the GUI thread.
struct FileRecoverySnapshot
{
    std::vector<ks::file::NtfsDeletedFileEntry> entries;
    QString volumeRoot;
    std::uint64_t revision = 0;
    int residentReady = 0;
    int nonResidentReady = 0;
    int safelyRecoverable = 0;
    int highIntegrity = 0;
};

namespace
{
    // isDeletedFileSafelyRecoverable 作用：
    // - 统一判断扫描结果是否可进入恢复流程；
    // - 非驻留数据只有完整度与 runlist 均通过扫描校验时才返回 true。
    bool isDeletedFileSafelyRecoverable(
        const ks::file::NtfsDeletedFileEntry& entryValue)
    {
        return entryValue.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::Resident ||
            entryValue.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::NonResidentIntact;
    }

    // deletedFileRecoveryCapabilityText 作用：
    // - 将底层恢复能力转换为表格可读文本；
    // - 文本明确说明非驻留数据必须导出到其它卷。
    QString deletedFileRecoveryCapabilityText(
        const ks::file::NtfsDeletedFileEntry& entryValue)
    {
        // Canonical search labels are immutable values shared by all candidates. Display
        // translation remains in model::data() on the GUI thread.
        static const std::array<QString, 5> labels{ QStringLiteral("仅元数据"),
            QStringLiteral("Resident 可恢复"), QStringLiteral("非驻留完整可恢复（需其它卷）"),
            QStringLiteral("非驻留簇已复用或完整度未知"), QStringLiteral("压缩、加密或跨记录流暂不支持") };
        const int capability = static_cast<int>(entryValue.recoveryCapability);
        return labels[capability >= 0 && capability < static_cast<int>(labels.size())
            ? static_cast<std::size_t>(capability) : 0U];
    }

    struct RecoveryProjection
    {
        std::vector<int> rows;
        std::vector<int> sourceToView;
    };

    QString recoverySizeText(std::uint64_t sizeBytes)
    {
        static const std::array<const char*, 5> units{ "B", "KB", "MB", "GB", "TB" };
        double value = static_cast<double>(sizeBytes);
        std::size_t unit = 0;
        while (value >= 1024.0 && unit + 1 < units.size()) { value /= 1024.0; ++unit; }
        return unit == 0
            ? QStringLiteral("%1 %2").arg(static_cast<qulonglong>(sizeBytes)).arg(units[unit])
            : QStringLiteral("%1 %2").arg(QString::number(value, 'f', 2)).arg(units[unit]);
    }

    QString recoveryCellText(const ks::file::NtfsDeletedFileEntry& entry, int column)
    {
        switch (column)
        {
        case 0: return entry.fileName;
        case 1: return entry.pathHint;
        case 2: return recoverySizeText(entry.sizeBytes);
        case 3: return entry.modifiedTime.isValid()
            ? entry.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QStringLiteral("-");
        case 4: return QStringLiteral("%1 / seq %2")
            .arg(static_cast<qulonglong>(entry.fileReference)).arg(entry.sequenceNumber);
        case 5: return entry.estimatedIntegrityPercent >= 0
            ? QStringLiteral("%1%").arg(entry.estimatedIntegrityPercent) : QStringLiteral("未知");
        case 6: return deletedFileRecoveryCapabilityText(entry)
            + (entry.hasOriginalName ? QString() : QStringLiteral(" / 缺名"));
        default: return {};
        }
    }

    struct RecoveryProjectionRequest
    {
        std::shared_ptr<const FileRecoverySnapshot> snapshot;
        QString query;
        bool regex = false;
        int sortColumn = -1;
        Qt::SortOrder sortOrder = Qt::AscendingOrder;
    };

    struct RecoveryProjectionResult
    {
        RecoveryProjectionRequest request;
        std::shared_ptr<const RecoveryProjection> projection;
    };

    RecoveryProjectionResult buildRecoveryProjection(const RecoveryProjectionRequest& request,
        const ks::ui::AsyncOperationToken& token)
    {
        RecoveryProjectionResult result{ request, {} };
        auto projection = std::make_shared<RecoveryProjection>();
        const auto& entries = request.snapshot->entries;
        projection->rows.reserve(entries.size());
        QRegularExpression expression;
        if (request.regex && !request.query.isEmpty())
            expression = QRegularExpression(request.query, QRegularExpression::CaseInsensitiveOption);
        const auto matches = [&request, &expression](const QString& text)
        { return request.regex ? expression.match(text).hasMatch()
            : text.contains(request.query, Qt::CaseInsensitive); };
        for (std::size_t row = 0; row < entries.size(); ++row)
        {
            if ((row & 127U) == 0 && token.isCanceled()) return result;
            const auto& entry = entries[row];
            bool matched = request.query.isEmpty();
            if (!matched)
            {
                // Keep field boundaries: regex cannot match across name/path/capability.
                // Names and paths already belong to the immutable scan snapshot.
                matched = matches(entry.fileName) || matches(entry.pathHint)
                    || matches(deletedFileRecoveryCapabilityText(entry));
            }
            if (matched) projection->rows.push_back(static_cast<int>(row));
        }
        if (request.sortColumn >= 0 && request.sortColumn < 7)
        {
            // Precompute display sort keys once; never format cells in a GUI comparator.
            std::vector<QString> keys(entries.size());
            for (int row : projection->rows)
            {
                if (token.isCanceled()) return result;
                keys[static_cast<std::size_t>(row)] = recoveryCellText(entries[static_cast<std::size_t>(row)], request.sortColumn);
            }
            std::stable_sort(projection->rows.begin(), projection->rows.end(),
                [&keys, order = request.sortOrder](int left, int right)
                {
                    const int compared = QString::localeAwareCompare(keys[static_cast<std::size_t>(left)], keys[static_cast<std::size_t>(right)]);
                    return order == Qt::AscendingOrder ? compared < 0 : compared > 0;
                });
        }
        if (token.isCanceled()) return result;
        projection->sourceToView.assign(entries.size(), -1);
        for (std::size_t row = 0; row < projection->rows.size(); ++row)
            projection->sourceToView[static_cast<std::size_t>(projection->rows[row])] = static_cast<int>(row);
        result.projection = std::move(projection);
        return result;
    }

    struct RecoverySnapshotDeleter
    {
        void operator()(const FileRecoverySnapshot* snapshot) const
        {
            // A delayed filter/menu closure may own the final reference after model retirement.
            // Always destroy the large values on the pool, regardless of that last owner's thread.
            QThreadPool::globalInstance()->start(QRunnable::create([snapshot]() { delete snapshot; }));
        }
    };

    std::shared_ptr<FileRecoverySnapshot> makeRecoverySnapshot()
    { return { new FileRecoverySnapshot, RecoverySnapshotDeleter{} }; }

    void retireRecoverySnapshot(std::shared_ptr<const FileRecoverySnapshot> snapshot)
    {
        if (snapshot) QThreadPool::globalInstance()->start(QRunnable::create(
            [snapshot = std::move(snapshot)]() mutable { snapshot.reset(); }));
    }

    class DeletedRecoveryModel final : public QAbstractTableModel
    {
    public:
        explicit DeletedRecoveryModel(QObject* parent) : QAbstractTableModel(parent) {}
        ~DeletedRecoveryModel() override { retireRecoverySnapshot(std::move(m_snapshot)); }
        std::function<void(int, Qt::SortOrder)> sortRequested;
        const std::shared_ptr<const FileRecoverySnapshot>& snapshot() const { return m_snapshot; }
        int sourceRow(int row) const
        { return m_projection && row >= 0 && row < rowCount() ? m_projection->rows[static_cast<std::size_t>(row)] : -1; }
        int viewRow(int source) const
        { return m_projection && source >= 0 && source < static_cast<int>(m_projection->sourceToView.size())
            ? m_projection->sourceToView[static_cast<std::size_t>(source)] : -1; }
        const ks::file::NtfsDeletedFileEntry* entry(int row) const
        {
            const int source = sourceRow(row);
            return source >= 0 ? &m_snapshot->entries[static_cast<std::size_t>(source)] : nullptr;
        }
        void publish(std::shared_ptr<const FileRecoverySnapshot> snapshot,
            std::shared_ptr<const RecoveryProjection> projection)
        {
            const QPointer<DeletedRecoveryModel> lifetime(this);
            beginResetModel();
            if (!lifetime) return;
            auto retired = std::move(m_snapshot);
            m_snapshot = std::move(snapshot);
            m_projection = std::move(projection);
            const bool changedSnapshot = retired != m_snapshot;
            endResetModel();
            if (changedSnapshot) retireRecoverySnapshot(std::move(retired));
        }
        int rowCount(const QModelIndex& parent = {}) const override
        { return parent.isValid() || !m_projection ? 0 : static_cast<int>(m_projection->rows.size()); }
        int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 7; }
        QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override
        {
            static const QStringList headers{ QStringLiteral("文件名"), QStringLiteral("路径提示"),
                QStringLiteral("大小"), QStringLiteral("修改时间"), QStringLiteral("记录号"),
                QStringLiteral("完整度"), QStringLiteral("恢复能力") };
            if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < headers.size())
                return ks::i18n::displayText(headers[section]);
            return QAbstractTableModel::headerData(section, orientation, role);
        }
        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
        {
            if (!index.isValid() || index.model() != this || index.column() < 0 || index.column() >= 7) return {};
            const auto* value = entry(index.row());
            if (!value) return {};
            if (role == Qt::ToolTipRole && index.column() == 0 && !value->hasOriginalName)
                return ks::i18n::displayText(QStringLiteral("该条目原始文件名已丢失，当前名称为系统生成的占位名。"));
            if (role != Qt::DisplayRole) return {};
            const QString text = recoveryCellText(*value, index.column());
            return index.column() >= 5 ? ks::i18n::displayText(text) : text;
        }
        void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override
        { if (sortRequested) sortRequested(column, order); }
    private:
        std::shared_ptr<const FileRecoverySnapshot> m_snapshot;
        std::shared_ptr<const RecoveryProjection> m_projection;
    };

    // localVolumeRootForPath 作用：
    // - 从本地绝对路径提取“C:\”形式卷根；
    // - UNC/网络路径返回空字符串，不会被误判为源卷。
    QString localVolumeRootForPath(const QString& pathText)
    {
        const QString nativePath =
            QDir::toNativeSeparators(QDir::cleanPath(pathText.trimmed()));
        if (nativePath.size() < 2 || nativePath[1] != QChar(':'))
        {
            return QString();
        }
        return nativePath.left(2).toUpper() + QStringLiteral("\\");
    }

    // safeRecoveryFileName 作用：
    // - 把来自 MFT 的原始名称转换为可由 Win32 普通文件 API 创建的叶名称；
    // - 过滤路径分隔符、ADS 冒号、控制字符、尾随点/空格和 DOS 保留设备名；
    // - 返回空字符串表示调用方应改用 deleted_<MFT>.bin 占位名。
    QString safeRecoveryFileName(const QString& requestedFileName)
    {
        QString safeFileName = requestedFileName.trimmed();
        constexpr qsizetype MaximumRecoveryFileNameLength = 180;
        const QString invalidCharacterSet =
            QStringLiteral("<>:\"/\\|?*");
        for (qsizetype characterIndex = 0;
             characterIndex < safeFileName.size();
             ++characterIndex)
        {
            const QChar characterValue = safeFileName.at(characterIndex);
            if (characterValue.unicode() < 0x20U ||
                invalidCharacterSet.contains(characterValue))
            {
                safeFileName[characterIndex] = QChar('_');
            }
        }

        while (safeFileName.endsWith(QChar('.')) ||
               safeFileName.endsWith(QChar(' ')))
        {
            safeFileName.chop(1);
        }
        if (safeFileName.size() > MaximumRecoveryFileNameLength)
        {
            safeFileName.truncate(MaximumRecoveryFileNameLength);
            if (!safeFileName.isEmpty() &&
                safeFileName.back().isHighSurrogate())
            {
                safeFileName.chop(1);
            }
        }

        const QString deviceBaseName =
            safeFileName.section(QChar('.'), 0, 0).toUpper();
        const bool isReservedDeviceName =
            deviceBaseName == QStringLiteral("CON") ||
            deviceBaseName == QStringLiteral("PRN") ||
            deviceBaseName == QStringLiteral("AUX") ||
            deviceBaseName == QStringLiteral("NUL") ||
            (deviceBaseName.size() == 4 &&
             (deviceBaseName.startsWith(QStringLiteral("COM")) ||
              deviceBaseName.startsWith(QStringLiteral("LPT"))) &&
             deviceBaseName.back() >= QChar('1') &&
             deviceBaseName.back() <= QChar('9'));
        if (isReservedDeviceName)
        {
            safeFileName.prepend(QChar('_'));
        }
        if (safeFileName == QStringLiteral(".") ||
            safeFileName == QStringLiteral(".."))
        {
            safeFileName.clear();
        }
        return safeFileName;
    }

    // uniqueRecoveryTargetPath 作用：
    // - 为批量恢复生成不覆盖现有文件、也不互相冲突的输出路径；
    // - 冲突时在扩展名前附加 MFT 记录号及递增序号。
    QString uniqueRecoveryTargetPath(
        const QString& outputDirectory,
        const QString& requestedFileName,
        const std::uint64_t fileReference,
        QSet<QString>& reservedPathSet)
    {
        QString safeFileName = safeRecoveryFileName(requestedFileName);
        if (safeFileName.isEmpty() ||
            safeFileName == QStringLiteral(".") ||
            safeFileName == QStringLiteral(".."))
        {
            safeFileName = QStringLiteral("deleted_%1.bin")
                .arg(static_cast<qulonglong>(fileReference));
        }

        const QFileInfo nameInfo(safeFileName);
        const QString baseName = nameInfo.completeBaseName().isEmpty()
            ? safeFileName
            : nameInfo.completeBaseName();
        const QString suffixText = nameInfo.completeSuffix();
        QString candidatePath = QDir(outputDirectory).filePath(safeFileName);
        int collisionIndex = 0;
        while (QFileInfo::exists(candidatePath) ||
               reservedPathSet.contains(candidatePath.toCaseFolded()))
        {
            ++collisionIndex;
            const QString collisionName = suffixText.isEmpty()
                ? QStringLiteral("%1_mft%2_%3")
                    .arg(baseName)
                    .arg(static_cast<qulonglong>(fileReference))
                    .arg(collisionIndex)
                : QStringLiteral("%1_mft%2_%3.%4")
                    .arg(baseName)
                    .arg(static_cast<qulonglong>(fileReference))
                    .arg(collisionIndex)
                    .arg(suffixText);
            candidatePath = QDir(outputDirectory).filePath(collisionName);
        }
        reservedPathSet.insert(candidatePath.toCaseFolded());
        return candidatePath;
    }

    struct DriverDeleteTarget
    {
        QString path;
        bool isDirectory = false;
    };

    enum class UnlockOperationMode
    {
        CloseHandleR3 = 0,
        TerminateProcessR3,
        TerminateProcessR0
    };

    struct UnlockProcessCandidate
    {
        std::uint32_t processId = 0U;
        std::uint64_t processCreationTime = 0U;
        QString processName;
        QString processImagePath;
        QStringList matchedTargetList;
        QStringList matchRuleList;
        std::size_t matchCount = 0U;
        bool isCurrentProcess = false;
        bool isCriticalProcess = false;
    };

    struct UnlockHandleCandidate
    {
        std::uint32_t processId = 0U;
        std::uint64_t processCreationTime = 0U;
        QString processName;
        QString processImagePath;
        std::uint64_t handleValue = 0U;
        std::uint32_t grantedAccess = 0U;
        QString matchedTargetPath;
        bool matchedByDirectoryRule = false;
        QString matchRuleText;
        QString objectName;
        QString enumerationSource;
        bool isCurrentProcess = false;
        bool isCriticalProcess = false;
    };

    struct UnlockSelectionResult
    {
        bool accepted = false;
        UnlockOperationMode operationMode = UnlockOperationMode::CloseHandleR3;
        std::vector<std::uint32_t> selectedProcessIdList;
        std::vector<UnlockHandleCandidate> selectedHandleList;
    };

    // installFileTableCopyMenu 作用：
    // - 输入：FileDock 内临时弹窗或工具页表格；
    // - 处理：安装只读复制当前行右键菜单；
    // - 返回：无。前置声明用于上方文件解锁选择弹窗复用后文 helper。
    void installFileTableCopyMenu(QTableWidget* tableWidget, int processIdColumn = -1);

    // UnlockSelectionSharedState：
    // - 作用：在线程与 UI 队列之间传递解锁器选择结果；
    // - 说明：使用 shared_ptr 托管，避免 FileDock 析构时队列中的 UI 回调访问已释放栈变量。
    struct UnlockSelectionSharedState
    {
        std::mutex mutex;                         // mutex：保护 completed 与 result 的互斥锁。
        std::condition_variable condition;        // condition：通知后台线程 UI 选择已完成。
        bool completed = false;                   // completed：标记 UI 选择流程是否已经写入结果。
        UnlockSelectionResult result;             // result：保存用户选择的操作方式及句柄/PID 目标。
    };

    struct FileIntegrityLevelPreset
    {
        DWORD rid;              // rid：S-1-16-* Mandatory Label 的最后一级 RID。
        const char* nameText;   // nameText：菜单与日志中的稳定英文名。
        const char* detailText; // detailText：面向用户的中文说明。
    };

    const FileIntegrityLevelPreset FileIntegrityLevelPresets[] =
    {
        { SECURITY_MANDATORY_UNTRUSTED_RID, "Untrusted", "不受信任完整性" },
        { SECURITY_MANDATORY_LOW_RID, "Low", "低完整性" },
        { SECURITY_MANDATORY_MEDIUM_RID, "Medium", "中完整性" },
        { SECURITY_MANDATORY_MEDIUM_PLUS_RID, "MediumPlus", "中高完整性" },
        { SECURITY_MANDATORY_HIGH_RID, "High", "高完整性" },
        { SECURITY_MANDATORY_SYSTEM_RID, "System", "系统完整性" }
    };

    // isSupportedFileMandatoryIntegrityRid 作用：
    // - 输入：integrityRid 为准备写入文件/目录 Mandatory Label 的 S-1-16-* RID；
    // - 处理：只允许 Windows 文件对象可接受的 MIC 等级。ProtectedProcess/SecureProcess
    //   属于令牌/进程语义，写入文件 SACL 会被内核安全 API 拒绝为 STATUS_INVALID_LABEL；
    // - 返回：true 表示可继续调用 R0/R3 写 LABEL_SECURITY_INFORMATION，false 表示前端应直接拒绝。
    bool isSupportedFileMandatoryIntegrityRid(const DWORD integrityRid)
    {
        for (const FileIntegrityLevelPreset& preset : FileIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return true;
            }
        }
        return false;
    }

    // formatFileWin32Error 作用：
    // - 输入：stepText 表示失败步骤，errorCode 为 Win32 错误码；
    // - 处理：生成稳定错误文本，避免不同系统语言下 FormatMessage 文案不一致；
    // - 返回：可直接展示和写入日志的 QString。
    QString formatFileWin32Error(const QString& stepText, const DWORD errorCode)
    {
        return QStringLiteral("%1 failed, error=%2").arg(stepText).arg(errorCode);
    }

    // enableFileContextPrivilege 作用：
    // - 输入：privilegeName 为当前进程令牌中的特权名，例如 SeSecurityPrivilege；
    // - 处理：临时启用当前进程 Token 上已有特权，不具备该特权时静默失败；
    // - 返回：true 表示 AdjustTokenPrivileges 成功启用，false 表示无法启用。
    bool enableFileContextPrivilege(const wchar_t* privilegeName)
    {
        if (privilegeName == nullptr)
        {
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        const BOOL adjustOk = ::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr);
        const DWORD adjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        return adjustOk != FALSE && adjustError == ERROR_SUCCESS;
    }

    // allocateFileMandatoryIntegritySid 作用：
    // - 输入：integrityRid 为 Mandatory Label RID；
    // - 处理：构造 S-1-16-integrityRid SID，调用者负责 FreeSid；
    // - 返回：成功时 true 并写入 sidOut，失败时 false 并输出 detailText。
    bool allocateFileMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        QString* detailText)
    {
        if (sidOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("sidOut is null");
            }
            return false;
        }
        *sidOut = nullptr;

        SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        if (::AllocateAndInitializeSid(
            &mandatoryLabelAuthority,
            1,
            integrityRid,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            sidOut) == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(
                    QStringLiteral("AllocateAndInitializeSid"),
                    ::GetLastError());
            }
            return false;
        }
        return true;
    }

    // fileIntegrityNameFromRid 作用：
    // - 输入：Mandatory Label RID；
    // - 处理：优先匹配菜单预设，否则退化为十六进制 RID；
    // - 返回：用于菜单、提示框和日志的短名称。
    QString fileIntegrityNameFromRid(const DWORD integrityRid)
    {
        for (const FileIntegrityLevelPreset& preset : FileIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return QString::fromLatin1(preset.nameText);
            }
        }
        return QStringLiteral("RID=0x%1").arg(integrityRid, 0, 16).toUpper();
    }

    // queryFileIntegrityRid 作用：
    // - 输入：filePath 为文件或目录路径；
    // - 处理：读取 LABEL_SECURITY_INFORMATION，扫描 SYSTEM_MANDATORY_LABEL_ACE_TYPE；
    // - 返回：成功时 true 并写入 ridOut；没有显式标签时按 Windows 默认 Medium 处理。
    bool queryFileIntegrityRid(
        const QString& filePath,
        DWORD* ridOut,
        bool* implicitMediumOut,
        QString* detailText)
    {
        if (ridOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("ridOut is null");
            }
            return false;
        }
        *ridOut = 0;
        if (implicitMediumOut != nullptr)
        {
            *implicitMediumOut = false;
        }

        (void)enableFileContextPrivilege(SE_SECURITY_NAME);

        std::wstring pathBuffer = QDir::toNativeSeparators(filePath).toStdWString();
        PACL labelAcl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        const DWORD queryResult = ::GetNamedSecurityInfoW(
            pathBuffer.data(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            &labelAcl,
            &securityDescriptor);
        if (queryResult != ERROR_SUCCESS)
        {
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(
                    QStringLiteral("GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)"),
                    queryResult);
            }
            return false;
        }

        bool foundLabel = false;
        DWORD foundRid = SECURITY_MANDATORY_MEDIUM_RID;
        if (labelAcl != nullptr)
        {
            ACL_SIZE_INFORMATION aclSizeInfo{};
            if (::GetAclInformation(
                labelAcl,
                &aclSizeInfo,
                static_cast<DWORD>(sizeof(aclSizeInfo)),
                AclSizeInformation) != FALSE)
            {
                for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
                {
                    LPVOID acePointer = nullptr;
                    if (::GetAce(labelAcl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                    {
                        continue;
                    }

                    const ACE_HEADER* aceHeader = reinterpret_cast<const ACE_HEADER*>(acePointer);
                    if (aceHeader->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                    {
                        continue;
                    }

                    const ACCESS_ALLOWED_ACE* mandatoryAce =
                        reinterpret_cast<const ACCESS_ALLOWED_ACE*>(acePointer);
                    PSID labelSid = const_cast<DWORD*>(&mandatoryAce->SidStart);
                    if (labelSid == nullptr ||
                        ::IsValidSid(labelSid) == FALSE ||
                        *::GetSidSubAuthorityCount(labelSid) == 0)
                    {
                        continue;
                    }

                    foundRid = *::GetSidSubAuthority(
                        labelSid,
                        static_cast<DWORD>(*::GetSidSubAuthorityCount(labelSid) - 1));
                    foundLabel = true;
                    break;
                }
            }
        }

        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }

        *ridOut = foundRid;
        if (!foundLabel && implicitMediumOut != nullptr)
        {
            *implicitMediumOut = true;
        }
        if (detailText != nullptr)
        {
            *detailText = foundLabel
                ? QStringLiteral("explicit label=%1").arg(fileIntegrityNameFromRid(foundRid))
                : QStringLiteral("no explicit mandatory label; using implicit Medium");
        }
        return true;
    }

    // setFileIntegrityLevelByPath 作用：
    // - 输入：filePath 为文件或目录路径，integrityRid 为目标 Mandatory Label RID；
    // - 处理：构造只包含 Mandatory Label ACE 的 ACL，并通过 LABEL_SECURITY_INFORMATION 写入；
    // - 返回：ERROR_SUCCESS 表示写入成功，失败时 detailText 包含 Win32 诊断。
    DWORD setFileIntegrityLevelByPath(
        const QString& filePath,
        const DWORD integrityRid,
        QString* detailText)
    {
        if (!isSupportedFileMandatoryIntegrityRid(integrityRid))
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("unsupported file mandatory label RID=0x%1; "
                    "ProtectedProcess/SecureProcess labels are token-only and cannot be written to file objects")
                    .arg(integrityRid, 0, 16);
            }
            return ERROR_INVALID_PARAMETER;
        }

        (void)enableFileContextPrivilege(SE_SECURITY_NAME);
        (void)enableFileContextPrivilege(SE_RESTORE_NAME);

        PSID integritySid = nullptr;
        QString sidDetailText;
        if (!allocateFileMandatoryIntegritySid(integrityRid, &integritySid, &sidDetailText))
        {
            DWORD sidError = ::GetLastError();
            if (sidError == ERROR_SUCCESS)
            {
                sidError = ERROR_INVALID_SID;
            }
            if (detailText != nullptr)
            {
                *detailText = sidDetailText;
            }
            return sidError;
        }

        const DWORD sidLength = ::GetLengthSid(integritySid);
        const DWORD aclBytes = static_cast<DWORD>(
            sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLength);
        PACL labelAcl = reinterpret_cast<PACL>(::LocalAlloc(LPTR, aclBytes));
        if (labelAcl == nullptr)
        {
            const DWORD allocError = ::GetLastError();
            ::FreeSid(integritySid);
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("LocalAlloc(ACL)"), allocError);
            }
            return allocError;
        }

        DWORD result = ERROR_SUCCESS;
        if (::InitializeAcl(labelAcl, aclBytes, ACL_REVISION) == FALSE)
        {
            result = ::GetLastError();
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("InitializeAcl"), result);
            }
        }
        else if (::AddMandatoryAce(
            labelAcl,
            ACL_REVISION,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            integritySid) == FALSE)
        {
            result = ::GetLastError();
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("AddMandatoryAce"), result);
            }
        }
        else
        {
            std::wstring pathBuffer = QDir::toNativeSeparators(filePath).toStdWString();
            result = ::SetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                nullptr,
                labelAcl);
            if (detailText != nullptr)
            {
                *detailText = result == ERROR_SUCCESS
                    ? QStringLiteral("已写入文件完整性：%1，RID=0x%2，路径=%3")
                        .arg(fileIntegrityNameFromRid(integrityRid))
                        .arg(integrityRid, 0, 16)
                        .arg(QDir::toNativeSeparators(filePath))
                    : formatFileWin32Error(
                        QStringLiteral("SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)"),
                        result);
            }
        }

        ::LocalFree(labelAcl);
        ::FreeSid(integritySid);
        return result;
    }

    // resolveVisibleDialogParent 作用：
    // - 为文件解锁器选择一个可见父窗口；
    // - Shell 右键会使用隐藏 FileDock 宿主，不能直接把弹窗挂在隐藏控件上。
    QWidget* resolveVisibleDialogParent(QWidget* const preferredParent)
    {
        QWidget* candidate = preferredParent;
        if (candidate != nullptr)
        {
            QWidget* const topLevel = candidate->window();
            if (topLevel != nullptr)
            {
                candidate = topLevel;
            }
        }
        if (candidate != nullptr && candidate->isVisible())
        {
            return candidate;
        }
        if (QWidget* const activeWindow = QApplication::activeWindow(); activeWindow != nullptr)
        {
            return activeWindow;
        }
        const QWidgetList topLevelWidgetList = QApplication::topLevelWidgets();
        for (QWidget* const widget : topLevelWidgetList)
        {
            if (widget != nullptr && widget->isVisible())
            {
                return widget;
            }
        }
        return preferredParent;
    }

    int calculateFileStandaloneWindowMaxWidth(
        QWidget* candidateParent,
        QWidget* fallbackWindow,
        const double ratio,
        const int fallbackWidth)
    {
        // 输入：
        // - candidateParent：优先参考的客户区控件；
        // - fallbackWindow：当前独立窗口，用于屏幕回退；
        // - ratio：客户区宽度比例；
        // - fallbackWidth：回退宽度。
        // 处理：
        // - 优先使用父控件 contentsRect 宽度；
        // - 父控件不可用时使用活动窗口客户区；
        // - 最后使用屏幕可用区域宽度。
        // 返回：按比例计算出的最大宽度；仅在完全无法判断时使用回退宽度。
        int clientWidth = 0;
        if (candidateParent != nullptr && candidateParent->contentsRect().width() > 0)
        {
            clientWidth = candidateParent->contentsRect().width();
        }

        if (clientWidth <= 0)
        {
            QWidget* activeWindow = QApplication::activeWindow();
            if (activeWindow != nullptr &&
                activeWindow != fallbackWindow &&
                activeWindow->contentsRect().width() > 0)
            {
                clientWidth = activeWindow->contentsRect().width();
            }
        }

        QScreen* targetScreen = nullptr;
        if (candidateParent != nullptr && candidateParent->windowHandle() != nullptr)
        {
            targetScreen = candidateParent->windowHandle()->screen();
        }
        if (targetScreen == nullptr && fallbackWindow != nullptr && fallbackWindow->windowHandle() != nullptr)
        {
            targetScreen = fallbackWindow->windowHandle()->screen();
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (clientWidth <= 0 && targetScreen != nullptr)
        {
            clientWidth = targetScreen->availableGeometry().width();
        }

        const int boundedFallbackWidth = std::max(1, fallbackWidth);
        if (clientWidth <= 0 || ratio <= 0.0)
        {
            return boundedFallbackWidth;
        }
        return std::max(1, static_cast<int>(std::floor(static_cast<double>(clientWidth) * ratio)));
    }

    void applyFileStandaloneWindowWidthLimit(
        QWidget* window,
        QWidget* candidateParent,
        const QSize& preferredSize,
        const double ratio)
    {
        // 输入：
        // - window：待约束的文件属性窗口；
        // - candidateParent：客户区宽度来源；
        // - preferredSize：原始设计尺寸；
        // - ratio：最大宽度比例。
        // 处理：设置 maximumWidth 并裁剪初始 resize 宽度。
        // 返回：无。
        if (window == nullptr)
        {
            return;
        }

        const int maxWidth = calculateFileStandaloneWindowMaxWidth(
            candidateParent,
            window,
            ratio,
            preferredSize.width());
        window->setMaximumWidth(maxWidth);
        window->resize(std::min(preferredSize.width(), maxWidth), preferredSize.height());
    }

    // buildOpaqueStandaloneDialogStyle 作用：
    // - 生成独立弹窗不透明样式；
    // - 前置声明用于供解锁器选择对话框在 helper 正式定义前调用。
    QString buildOpaqueStandaloneDialogStyle(const QString& dialogObjectName);

    QString unlockOperationModeToText(const UnlockOperationMode mode)
    {
        if (mode == UnlockOperationMode::CloseHandleR3)
        {
            return QStringLiteral("R3 关闭句柄");
        }
        return mode == UnlockOperationMode::TerminateProcessR0
            ? QStringLiteral("R0 结束进程")
            : QStringLiteral("R3 结束进程");
    }

    QString formatHandleValueText(const std::uint64_t handleValue)
    {
        if (handleValue == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(handleValue), 0, 16)
            .toUpper();
    }

    void appendUniqueText(QStringList& list, const QString& text)
    {
        const QString normalizedText = text.trimmed();
        if (!normalizedText.isEmpty() && !list.contains(normalizedText))
        {
            list.push_back(normalizedText);
        }
    }

    // QueryNtQueryInformationFilePtr：动态解析 NtQueryInformationFile，避免 FileDock 额外依赖
    // 其它 user-mode 模块。
    using NtQueryInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

    // queryBitLockerVolumeText：前置声明，供卷快照辅助函数先调用。
    QString queryBitLockerVolumeText(const QString& driveLetter);

    // FileVolumeAuditSnapshot：汇总卷、存储和 BitLocker 状态的轻量只读模型。
    struct FileVolumeAuditSnapshot
    {
        QString volumeRoot;
        QString mountPointsText;
        QString devicePathText;
        QString fsNameText;
        QString labelText;
        QString storageText;
        QString bitLockerText;
        QString volumeStackText;
        QString filterText;
    };

    // VolumePathFromAnyPath：把任意本地路径压缩成卷根目录（例如 C:\）。
    QString volumePathFromAnyPath(const QString& pathText)
    {
        const QString normalizedPath = QDir::toNativeSeparators(pathText).trimmed();
        if (normalizedPath.isEmpty())
        {
            return QString();
        }

        std::array<wchar_t, MAX_PATH + 4U> buffer{};
        const BOOL ok = ::GetVolumePathNameW(
            normalizedPath.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (ok == FALSE)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    // buildMountPointsText：读取卷对应的 DOS 挂载点列表，失败时返回空。
    QString buildMountPointsText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        DWORD requiredChars = 0;
        ::GetVolumePathNamesForVolumeNameW(
            volumeRoot.toStdWString().c_str(),
            nullptr,
            0,
            &requiredChars);
        if (requiredChars == 0)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(static_cast<std::size_t>(requiredChars) + 2U, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(
            volumeRoot.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &requiredChars) == FALSE)
        {
            return QString();
        }

        QStringList paths;
        const wchar_t* cursor = buffer.data();
        while (cursor != nullptr && *cursor != L'\0')
        {
            const QString pathText = QString::fromWCharArray(cursor);
            if (!pathText.isEmpty())
            {
                paths << pathText;
            }
            cursor += pathText.size() + 1;
        }
        return paths.join(QStringLiteral(", "));
    }

    // buildVolumeDevicePathText：把卷名解析为设备路径（例如 \Device\HarddiskVolumeX）。
    QString buildVolumeDevicePathText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        QString dosName = volumeRoot;
        if (dosName.endsWith(QChar('\\')))
        {
            dosName.chop(1);
        }

        std::array<wchar_t, 1024U> buffer{};
        const DWORD chars = ::QueryDosDeviceW(
            dosName.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (chars == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    // buildVolumeInfoText：读取卷标、文件系统和基本属性。
    QString buildVolumeInfoText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        std::array<wchar_t, MAX_PATH + 1U> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1U> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fsFlags = 0;
        if (::GetVolumeInformationW(
            volumeRoot.toStdWString().c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &fsFlags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) == FALSE)
        {
            return QString();
        }

        return QStringLiteral("Label=%1 | FS=%2 | Serial=0x%3 | Flags=0x%4")
            .arg(QString::fromWCharArray(labelBuffer.data()))
            .arg(QString::fromWCharArray(fsBuffer.data()))
            .arg(serialNumber, 8, 16, QChar('0'))
            .arg(fsFlags, 8, 16, QChar('0'))
            .toUpper();
    }

    // queryVolumeLabelAndFileSystemText：只读取卷标与文件系统名称，供 Storage/FVE 页复用。
    // 输入：volumeRoot 为卷根路径（例如 C:\）；labelOut/fileSystemOut 接收读取结果。
    // 返回：读取成功时为 true；失败时保持输出为空。
    bool queryVolumeLabelAndFileSystemText(
        const QString& volumeRoot,
        QString& labelOut,
        QString& fileSystemOut)
    {
        labelOut.clear();
        fileSystemOut.clear();
        if (volumeRoot.trimmed().isEmpty())
        {
            return false;
        }

        std::array<wchar_t, MAX_PATH + 1U> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1U> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fsFlags = 0;
        if (::GetVolumeInformationW(
            volumeRoot.toStdWString().c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &fsFlags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) == FALSE)
        {
            return false;
        }

        labelOut = QString::fromWCharArray(labelBuffer.data()).trimmed();
        fileSystemOut = QString::fromWCharArray(fsBuffer.data()).trimmed();
        return true;
    }

    // buildStorageDescriptorText：读取存储设备描述符。
    QString buildStorageDescriptorText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        HANDLE handleValue = ::CreateFileW(
            volumeRoot.toStdWString().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            return QStringLiteral("CreateFile=%1").arg(::GetLastError());
        }

        QString result;
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        std::array<std::uint8_t, 1024U> buffer{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &returnedBytes,
            nullptr) != FALSE
            && returnedBytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
            result = QStringLiteral("BusType=%1 | Removable=%2 | RawSize=%3")
                .arg(static_cast<unsigned long>(descriptor->BusType))
                .arg(descriptor->RemovableMedia ? QStringLiteral("是") : QStringLiteral("否"))
                .arg(returnedBytes);
        }
        ::CloseHandle(handleValue);
        return result;
    }

    // buildVolumeStackText：把卷根、设备路径、文件系统拼成稳定的只读“卷栈”摘要。
    // 输入：volumeRoot/devicePathText/fsText 均为可空的可见状态文本。
    // 返回：适合 UI 展示的单行或多行链式摘要。
    QString buildVolumeStackText(
        const QString& volumeRoot,
        const QString& devicePathText,
        const QString& fsText,
        const QString& mountPointsText)
    {
        QStringList parts;
        appendUniqueText(parts, volumeRoot);
        appendUniqueText(parts, devicePathText);
        appendUniqueText(parts, fsText);
        appendUniqueText(parts, mountPointsText);
        if (parts.isEmpty())
        {
            return QString();
        }
        return parts.join(QStringLiteral(" -> "));
    }

    // buildBitLockerStatusText：只读查询 BitLocker 可见状态，失败后给降级说明。
    QString buildBitLockerStatusText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QStringLiteral("BitLocker: <unknown>");
        }

        return queryBitLockerVolumeText(volumeRoot.left(2));
    }

    // queryFileVolumeAuditSnapshot：汇总 FileDock 三个新页所需的卷/存储/FVE 视图。
    FileVolumeAuditSnapshot queryFileVolumeAuditSnapshot(const QString& filePath)
    {
        FileVolumeAuditSnapshot snapshot{};
        snapshot.volumeRoot = volumePathFromAnyPath(filePath);
        if (snapshot.volumeRoot.isEmpty())
        {
            return snapshot;
        }

        snapshot.mountPointsText = buildMountPointsText(snapshot.volumeRoot);
        snapshot.devicePathText = buildVolumeDevicePathText(snapshot.volumeRoot);
        QString volumeLabelText;
        QString fileSystemText;
        if (queryVolumeLabelAndFileSystemText(snapshot.volumeRoot, volumeLabelText, fileSystemText))
        {
            snapshot.labelText = volumeLabelText;
            snapshot.fsNameText = fileSystemText;
        }
        snapshot.volumeStackText = buildVolumeStackText(
            snapshot.volumeRoot,
            snapshot.devicePathText,
            snapshot.fsNameText,
            snapshot.mountPointsText);
        const QString volumeInfoText = buildVolumeInfoText(snapshot.volumeRoot);
        const QString storageDescriptorText = buildStorageDescriptorText(snapshot.volumeRoot);
        snapshot.storageText = QStringList{ volumeInfoText, storageDescriptorText }.join(QStringLiteral(" | "));
        snapshot.bitLockerText = buildBitLockerStatusText(snapshot.volumeRoot);
        snapshot.filterText = QStringLiteral("仅只读枚举，不做卸载/绕过/修改。");
        return snapshot;
    }

    // openReadOnlyFileHandle：以只读、共享最大化方式打开文件或目录。
    HANDLE openReadOnlyFileHandle(const QString& pathText, const bool directoryHint)
    {
        const QString normalizedPath = QDir::toNativeSeparators(pathText).trimmed();
        if (normalizedPath.isEmpty())
        {
            return INVALID_HANDLE_VALUE;
        }

        DWORD flags = FILE_ATTRIBUTE_NORMAL;
        if (directoryHint)
        {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }

        return ::CreateFileW(
            normalizedPath.toStdWString().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            flags,
            nullptr);
    }

    // queryFileStandardInfoText：读取 DeletePending / 文件大小 / 链接数等标准信息。
    bool queryFileStandardInfoText(
        HANDLE fileHandle,
        QString& detailsOut,
        QString& statusOut)
    {
        detailsOut.clear();
        statusOut.clear();
        if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE)
        {
            statusOut = QStringLiteral("句柄无效");
            return false;
        }

        FILE_STANDARD_INFO standardInfo{};
        if (::GetFileInformationByHandleEx(
            fileHandle,
            FileStandardInfo,
            &standardInfo,
            static_cast<DWORD>(sizeof(standardInfo))) == FALSE)
        {
            statusOut = QStringLiteral("GetFileInformationByHandleEx(FileStandardInfo) 失败，Win32=%1")
                .arg(::GetLastError());
            return false;
        }

        detailsOut = QStringLiteral("DeletePending: %1\n")
            .arg(standardInfo.DeletePending ? QStringLiteral("是") : QStringLiteral("否"));
        detailsOut += QStringLiteral("Directory: %1\n")
            .arg(standardInfo.Directory ? QStringLiteral("是") : QStringLiteral("否"));
        detailsOut += QStringLiteral("AllocationSize: %1\n")
            .arg(static_cast<qlonglong>(standardInfo.AllocationSize.QuadPart));
        detailsOut += QStringLiteral("EndOfFile: %1\n")
            .arg(static_cast<qlonglong>(standardInfo.EndOfFile.QuadPart));
        detailsOut += QStringLiteral("NumberOfLinks: %1\n")
            .arg(static_cast<unsigned long>(standardInfo.NumberOfLinks));
        detailsOut += QStringLiteral("采集句柄 ShareAccess: READ|WRITE|DELETE\n");
        statusOut = QStringLiteral("OK");
        return true;
    }



    // readUtf16FieldAtOffset：从返回缓冲中读取 UTF-16 偏移字段，供 FltLib 枚举结构解析。
    // 输入：buffer/bytesReturned 指向完整返回缓冲；fieldOffset/fieldLength 为字节级字段位置。
    // 返回：成功时返回去尾空白后的字符串；失败返回空字符串。
    QString readUtf16FieldAtOffset(
        const void* buffer,
        const std::size_t bytesReturned,
        const USHORT fieldOffset,
        const USHORT fieldLength)
    {
        if (buffer == nullptr || bytesReturned == 0U || fieldLength == 0U)
        {
            return QString();
        }
        const std::size_t startOffset = static_cast<std::size_t>(fieldOffset);
        const std::size_t lengthBytes = static_cast<std::size_t>(fieldLength);
        if (startOffset >= bytesReturned || (startOffset + lengthBytes) > bytesReturned)
        {
            return QString();
        }
        const auto* charBuffer = reinterpret_cast<const wchar_t*>(
            static_cast<const std::uint8_t*>(buffer) + startOffset);
        return QString::fromWCharArray(charBuffer, static_cast<int>(lengthBytes / sizeof(wchar_t))).trimmed();
    }

    // filterFilesystemTypeToText：把 FLT_FILESYSTEM_TYPE 枚举转成可读文本。
    // 输入：filesystemType 为 FltUser 返回的文件系统类型。
    // 返回：对应文件系统名称；未知枚举保留数值。
    QString filterFilesystemTypeToText(const FLT_FILESYSTEM_TYPE filesystemType)
    {
        switch (filesystemType)
        {
        case FLT_FSTYPE_UNKNOWN: return QStringLiteral("Unknown");
        case FLT_FSTYPE_RAW: return QStringLiteral("RAW");
        case FLT_FSTYPE_NTFS: return QStringLiteral("NTFS");
        case FLT_FSTYPE_FAT: return QStringLiteral("FAT");
        case FLT_FSTYPE_CDFS: return QStringLiteral("CDFS");
        case FLT_FSTYPE_UDFS: return QStringLiteral("UDFS");
        case FLT_FSTYPE_LANMAN: return QStringLiteral("LANMAN");
        case FLT_FSTYPE_WEBDAV: return QStringLiteral("WebDAV");
        case FLT_FSTYPE_RDPDR: return QStringLiteral("RDPDR");
        case FLT_FSTYPE_NFS: return QStringLiteral("NFS");
        case FLT_FSTYPE_MS_NETWARE: return QStringLiteral("MS_NETWARE");
        case FLT_FSTYPE_NETWARE: return QStringLiteral("NETWARE");
        case FLT_FSTYPE_BSUDF: return QStringLiteral("BsUDF");
        case FLT_FSTYPE_MUP: return QStringLiteral("MUP");
        case FLT_FSTYPE_RSFX: return QStringLiteral("RsFx");
        case FLT_FSTYPE_ROXIO_UDF1: return QStringLiteral("RoxioUDF1");
        case FLT_FSTYPE_ROXIO_UDF2: return QStringLiteral("RoxioUDF2");
        case FLT_FSTYPE_ROXIO_UDF3: return QStringLiteral("RoxioUDF3");
        case FLT_FSTYPE_TACIT: return QStringLiteral("Tacit");
        case FLT_FSTYPE_FS_REC: return QStringLiteral("FsRec");
        case FLT_FSTYPE_INCD: return QStringLiteral("InCD");
        case FLT_FSTYPE_INCD_FAT: return QStringLiteral("InCDFat");
        case FLT_FSTYPE_EXFAT: return QStringLiteral("exFAT");
        case FLT_FSTYPE_PSFS: return QStringLiteral("PSFS");
        case FLT_FSTYPE_GPFS: return QStringLiteral("GPFS");
        case FLT_FSTYPE_NPFS: return QStringLiteral("NPFS");
        case FLT_FSTYPE_MSFS: return QStringLiteral("MSFS");
        case FLT_FSTYPE_CSVFS: return QStringLiteral("CSVFS");
        case FLT_FSTYPE_REFS: return QStringLiteral("ReFS");
        case FLT_FSTYPE_OPENAFS: return QStringLiteral("OpenAFS");
        case FLT_FSTYPE_CIMFS: return QStringLiteral("CIMFS");
        default:
            return QStringLiteral("Type=%1").arg(static_cast<int>(filesystemType));
        }
    }

    // appendMinifilterRecordText：把单条 Filter 枚举记录压成可读文本。
    // 输入：buffer/bytesReturned 为 FilterFindFirst/Next 返回数据。
    // 返回：无；直接追加到 content。
    void appendMinifilterRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer);
        const bool isMinifilter = (record->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
        const QString filterName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
        const QString altitude = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterAltitudeBufferOffset, record->Type.MiniFilter.FilterAltitudeLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterAltitudeBufferOffset, record->Type.LegacyFilter.FilterAltitudeLength);
        const QString recordKind = isMinifilter ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter");

        content += QStringLiteral("名称: %1\n").arg(filterName.isEmpty() ? QStringLiteral("<unknown>") : filterName);
        content += QStringLiteral("类型: %1\n").arg(recordKind);
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        if (isMinifilter)
        {
            content += QStringLiteral("FrameID: %1\n").arg(record->Type.MiniFilter.FrameID);
            content += QStringLiteral("NumberOfInstances: %1\n").arg(record->Type.MiniFilter.NumberOfInstances);
        }
        content += QStringLiteral("Altitude: %1\n").arg(altitude.isEmpty() ? QStringLiteral("<unknown>") : altitude);
    }

    // enumerateMinifilterText：只读枚举 Filter 列表并生成摘要文本。
    // 输入：无。
    // 返回：包含 Filter 名称、Altitude、FrameID 和实例数的可见文本。
    QString enumerateMinifilterText()
    {
        QString content;
        content += QStringLiteral("[Minifilter]\n");
        content += QStringLiteral("枚举来源: FilterFindFirst / FilterFindNext\n");
        content += QStringLiteral("展示字段: FilterName, Altitude, FrameID, NumberOfInstances, Flags\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE enumHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterFindFirst(
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &enumHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        auto appendRecord = [&](const QString& prefixText)
        {
            content += prefixText;
            appendMinifilterRecordText(content, buffer.data(), bytesReturned);
            content += QStringLiteral("\n");
        };

        appendRecord(QStringLiteral("\n"));

        for (;;)
        {
            bytesReturned = 0;
            hr = ::FilterFindNext(
                enumHandle,
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                appendRecord(QStringLiteral(""));
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (enumHandle != nullptr)
        {
            ::FilterFindClose(enumHandle);
        }
        return content;
    }

    // appendInstanceRecordText：把单条 Instance 枚举记录压成可读文本。
    // 输入：buffer/bytesReturned 为 FilterInstanceFindFirst/Next 返回数据。
    // 返回：无；直接追加到 content。
    void appendInstanceRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(INSTANCE_AGGREGATE_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const INSTANCE_AGGREGATE_STANDARD_INFORMATION*>(buffer);
        const bool isMinifilter = (record->Flags & FLTFL_IASI_IS_MINIFILTER) != 0;
        const QString instanceName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.InstanceNameBufferOffset, record->Type.MiniFilter.InstanceNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, 0, 0);
        const QString altitude = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.AltitudeBufferOffset, record->Type.MiniFilter.AltitudeLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.AltitudeBufferOffset, record->Type.LegacyFilter.AltitudeLength);
        const QString volumeName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.VolumeNameBufferOffset, record->Type.MiniFilter.VolumeNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.VolumeNameBufferOffset, record->Type.LegacyFilter.VolumeNameLength);
        const QString filterName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);

        content += QStringLiteral("实例名: %1\n").arg(instanceName.isEmpty() ? QStringLiteral("<unknown>") : instanceName);
        content += QStringLiteral("类型: %1\n").arg(isMinifilter ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter"));
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        if (isMinifilter)
        {
            content += QStringLiteral("FrameID: %1\n").arg(record->Type.MiniFilter.FrameID);
            content += QStringLiteral("VolumeFileSystemType: %1\n")
                .arg(filterFilesystemTypeToText(record->Type.MiniFilter.VolumeFileSystemType));
        }
        content += QStringLiteral("Altitude: %1\n").arg(altitude.isEmpty() ? QStringLiteral("<unknown>") : altitude);
        content += QStringLiteral("VolumeName: %1\n").arg(volumeName.isEmpty() ? QStringLiteral("<unknown>") : volumeName);
        content += QStringLiteral("FilterName: %1\n").arg(filterName.isEmpty() ? QStringLiteral("<unknown>") : filterName);
    }

    // enumerateInstanceText：枚举全部 minifilter/legacy instance，给出 Volume 关联摘要。
    // 输入：无。
    // 返回：实例列表的只读文本。
    QString enumerateInstanceText()
    {
        QString content;
        content += QStringLiteral("[Instance]\n");
        content += QStringLiteral("枚举来源: FilterInstanceFindFirst / FilterInstanceFindNext\n");
        content += QStringLiteral("展示字段: InstanceName, Altitude, VolumeName, FilterName, VolumeFileSystemType\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE findHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterFindFirst(
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &findHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 无法先枚举 Filter 列表 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        for (;;)
        {
            const auto* filterRecord = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer.data());
            const bool isMinifilter = (filterRecord->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
            const QString filterName = isMinifilter
                ? readUtf16FieldAtOffset(buffer.data(), bytesReturned, filterRecord->Type.MiniFilter.FilterNameBufferOffset, filterRecord->Type.MiniFilter.FilterNameLength)
                : readUtf16FieldAtOffset(buffer.data(), bytesReturned, filterRecord->Type.LegacyFilter.FilterNameBufferOffset, filterRecord->Type.LegacyFilter.FilterNameLength);
            if (!filterName.isEmpty())
            {
                content += QStringLiteral("\n[Filter] %1\n").arg(filterName);
            }

            HANDLE instanceHandle = nullptr;
            std::vector<std::uint8_t> instanceBuffer(16U * 1024U, 0U);
            DWORD instanceBytesReturned = 0;
            if (!filterName.isEmpty())
            {
                for (;;)
                {
                    hr = ::FilterInstanceFindFirst(
                        filterName.toStdWString().c_str(),
                        InstanceAggregateStandardInformation,
                        instanceBuffer.data(),
                        static_cast<DWORD>(instanceBuffer.size()),
                        &instanceBytesReturned,
                        &instanceHandle);
                    if (SUCCEEDED(hr))
                    {
                        break;
                    }
                    if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                    {
                        instanceBuffer.resize(instanceBuffer.size() * 2U);
                        continue;
                    }
                    break;
                }
                if (SUCCEEDED(hr))
                {
                    for (;;)
                    {
                        content += QStringLiteral("  - ");
                        appendInstanceRecordText(content, instanceBuffer.data(), instanceBytesReturned);
                        content += QStringLiteral("\n");

                        instanceBytesReturned = 0;
                        hr = ::FilterInstanceFindNext(
                            instanceHandle,
                            InstanceAggregateStandardInformation,
                            instanceBuffer.data(),
                            static_cast<DWORD>(instanceBuffer.size()),
                            &instanceBytesReturned);
                        if (SUCCEEDED(hr))
                        {
                            continue;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                        {
                            break;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                        {
                            instanceBuffer.resize(instanceBuffer.size() * 2U);
                            continue;
                        }
                        content += QStringLiteral("  ! 继续枚举实例失败 HRESULT=0x%1\n")
                            .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                        break;
                    }
                }
                else
                {
                    content += QStringLiteral("  ! FilterInstanceFindFirst 失败 HRESULT=0x%1\n")
                        .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                }
            }

            bytesReturned = 0;
            hr = ::FilterFindNext(
                findHandle,
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举 Filter 失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (findHandle != nullptr)
        {
            ::FilterFindClose(findHandle);
        }
        return content;
    }

    // appendVolumeRecordText：把单条 Volume 枚举记录压成可读文本。
    // 输入：buffer/bytesReturned 为 FilterVolumeFindFirst/Next 返回数据。
    // 返回：无；直接追加到 content。
    void appendVolumeRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(FILTER_VOLUME_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer);
        const QString volumeName = readUtf16FieldAtOffset(
            buffer,
            bytesReturned,
            offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName),
            record->FilterVolumeNameLength);
        content += QStringLiteral("卷名: %1\n").arg(volumeName.isEmpty() ? QStringLiteral("<unknown>") : volumeName);
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        content += QStringLiteral("FrameID: %1\n").arg(record->FrameID);
        content += QStringLiteral("FileSystemType: %1\n").arg(filterFilesystemTypeToText(record->FileSystemType));
    }

    // enumerateVolumeText：枚举 FilterManager 公开 Volume 列表并给出卷栈关联摘要。
    // 输入：无。
    // 返回：Volume 列表与可见状态文本。
    QString enumerateVolumeText()
    {
        QString content;
        content += QStringLiteral("[Volume]\n");
        content += QStringLiteral("枚举来源: FilterVolumeFindFirst / FilterVolumeFindNext\n");
        content += QStringLiteral("展示字段: VolumeName, FileSystemType, FrameID, Flags, AttachedInstances\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE volumeHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterVolumeFindFirst(
                FilterVolumeStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &volumeHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        for (;;)
        {
            content += QStringLiteral("\n");
            appendVolumeRecordText(content, buffer.data(), bytesReturned);

            const auto* volumeRecord = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer.data());
            const QString volumeName = readUtf16FieldAtOffset(
                buffer.data(),
                bytesReturned,
                offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName),
                volumeRecord->FilterVolumeNameLength);
            if (!volumeName.isEmpty())
            {
                HANDLE instanceHandle = nullptr;
                std::vector<std::uint8_t> instanceBuffer(16U * 1024U, 0U);
                DWORD instanceBytesReturned = 0;
                if (!volumeName.isEmpty())
                {
                    for (;;)
                    {
                        hr = ::FilterVolumeInstanceFindFirst(
                            volumeName.toStdWString().c_str(),
                            InstanceAggregateStandardInformation,
                            instanceBuffer.data(),
                            static_cast<DWORD>(instanceBuffer.size()),
                            &instanceBytesReturned,
                            &instanceHandle);
                        if (SUCCEEDED(hr))
                        {
                            break;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                        {
                            instanceBuffer.resize(instanceBuffer.size() * 2U);
                            continue;
                        }
                        break;
                    }
                    if (SUCCEEDED(hr))
                    {
                        content += QStringLiteral("AttachedInstances:\n");
                        for (;;)
                        {
                            content += QStringLiteral("  - ");
                            appendInstanceRecordText(content, instanceBuffer.data(), instanceBytesReturned);
                            content += QStringLiteral("\n");

                            instanceBytesReturned = 0;
                            hr = ::FilterVolumeInstanceFindNext(
                                instanceHandle,
                                InstanceAggregateStandardInformation,
                                instanceBuffer.data(),
                                static_cast<DWORD>(instanceBuffer.size()),
                                &instanceBytesReturned);
                            if (SUCCEEDED(hr))
                            {
                                continue;
                            }
                            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                            {
                                break;
                            }
                            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                            {
                                instanceBuffer.resize(instanceBuffer.size() * 2U);
                                continue;
                            }
                            content += QStringLiteral("  ! 继续枚举卷实例失败 HRESULT=0x%1\n")
                                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                            break;
                        }
                    }
                    else
                    {
                        content += QStringLiteral("AttachedInstances: FilterVolumeInstanceFindFirst 失败 HRESULT=0x%1\n")
                            .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                    }
                }
            }

            bytesReturned = 0;
            hr = ::FilterVolumeFindNext(
                volumeHandle,
                FilterVolumeStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举 Volume 失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (volumeHandle != nullptr)
        {
            ::FilterVolumeFindClose(volumeHandle);
        }
        return content;
    }

    // queryBitLockerVolumeText 作用：
    // - 用途：给出 Win32_EncryptableVolume 视角的 BitLocker 只读状态文本；
    // - 入参：driveLetter 为目标盘符（例如 C:）；
    // - 返回：可直接展示的状态文本。
    // 说明：这里原本会 CoInitializeEx + CoCreateInstance(CLSID_WbemLocator) +
    // ConnectServer(ROOT\CIMV2\Security\MicrosoftVolumeEncryption) + CoSetProxyBlanket，
    // 但把 SELECT 语句拼出来之后从来没有 ExecQuery，最终仍旧只输出下面这一句降级文本；
    // 也就是说整条 WMI 连接链（冷启动要拉起 provider host，几百毫秒到数秒）是白付的成本。
    // 在真正实现 ExecQuery 之前直接返回同一句降级文本，不再连接 WMI；
    // BitLocker 的真实可见状态由 Storage 页的“R0 审计补充 / BitLocker FVE”段落给出。
    QString queryBitLockerVolumeText(const QString& driveLetter)
    {
        if (driveLetter.trimmed().isEmpty())
        {
            return QStringLiteral("BitLocker: <无盘符>");
        }

        return QStringLiteral("BitLocker WMI: 查询语句已准备，当前版本保留降级文本展示。");
    }

    bool isCriticalProcessName(const QString& processName)
    {
        const QString normalizedName = processName.trimmed().toLower();
        if (normalizedName.isEmpty())
        {
            return false;
        }

        static const std::set<QString> criticalNameSet =
        {
            QStringLiteral("smss.exe"),
            QStringLiteral("csrss.exe"),
            QStringLiteral("wininit.exe"),
            QStringLiteral("services.exe"),
            QStringLiteral("lsass.exe"),
            QStringLiteral("winlogon.exe")
        };
        return criticalNameSet.find(normalizedName) != criticalNameSet.end();
    }

    // isPathReparsePoint：
    // - 作用：判断目标路径是否为重解析点（符号链接/Junction 等）；
    // - 用于目录递归删除时避免误跟进到链接目标。
    bool isPathReparsePoint(const QString& path)
    {
        const std::wstring nativePathText = QDir::toNativeSeparators(path).toStdWString();
        if (nativePathText.empty())
        {
            return false;
        }

        const DWORD fileAttributes = ::GetFileAttributesW(nativePathText.c_str());
        if (fileAttributes == INVALID_FILE_ATTRIBUTES)
        {
            return false;
        }
        return (fileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
    }

    QString formatWin32ErrorText(const std::uint32_t errorCode)
    {
        if (errorCode == ERROR_SUCCESS)
        {
            return QStringLiteral("0");
        }

        wchar_t* messageBuffer = nullptr;
        const DWORD chars = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (chars > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(chars)).trimmed();
        }
        if (messageBuffer != nullptr)
        {
            ::LocalFree(messageBuffer);
        }
        return messageText.isEmpty()
            ? QString::number(errorCode)
            : QStringLiteral("%1 (%2)").arg(errorCode).arg(messageText);
    }

    QString formatReparseTagText(const std::uint32_t tagValue)
    {
        return QStringLiteral("0x%1")
            .arg(tagValue, 8, 16, QChar('0'))
            .toUpper();
    }

    ks::file::ReparsePointQueryResult queryReparsePointForUi(const QString& path)
    {
        const QString nativePathText = QDir::toNativeSeparators(path).trimmed();
        if (nativePathText.isEmpty())
        {
            ks::file::ReparsePointQueryResult result{};
            result.errorText = L"路径为空。";
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        const DWORD attributes = ::GetFileAttributesW(nativePathText.toStdWString().c_str());
        const bool directoryHint = attributes != INVALID_FILE_ATTRIBUTES
            && ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U);
        return ks::file::QueryReparsePointInfo(nativePathText.toStdWString(), directoryHint);
    }

    QString reparseKindMarkerForPath(const QString& path)
    {
        const QString nativePathText = QDir::toNativeSeparators(path).trimmed();
        if (nativePathText.isEmpty())
        {
            return QString();
        }

        const DWORD attributes = ::GetFileAttributesW(nativePathText.toStdWString().c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U)
        {
            return QString();
        }

        const ks::file::ReparsePointQueryResult result = queryReparsePointForUi(nativePathText);
        const QString kindText = QString::fromStdWString(result.kindName).trimmed();
        return kindText.isEmpty() ? QStringLiteral("UNKNOWN_REPARSE") : kindText;
    }

    QString reparseTargetFromResult(const ks::file::ReparsePointQueryResult& result)
    {
        QString targetText = QString::fromStdWString(result.resolvedTargetPath).trimmed();
        if (targetText.isEmpty())
        {
            targetText = QString::fromStdWString(result.printName).trimmed();
        }
        if (targetText.isEmpty())
        {
            targetText = QString::fromStdWString(result.substituteName).trimmed();
        }
        return QDir::toNativeSeparators(targetText);
    }

    QString formatReparsePointText(const QString& path)
    {
        const ks::file::ReparsePointQueryResult result = queryReparsePointForUi(path);
        QString content;
        content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(path));

        if (!result.pathOpened)
        {
            content += QStringLiteral("状态: 无法打开目标（使用 FILE_FLAG_OPEN_REPARSE_POINT）\n");
            content += QStringLiteral("Win32错误: %1\n").arg(formatWin32ErrorText(result.win32Error));
            content += QStringLiteral("原因: %1\n").arg(QString::fromStdWString(result.errorText));
            return content;
        }

        if (!result.querySucceeded)
        {
            content += QStringLiteral("状态: FSCTL_GET_REPARSE_POINT 查询失败\n");
            content += QStringLiteral("是否重解析点: %1\n").arg(result.isReparsePoint ? QStringLiteral("是") : QStringLiteral("否"));
            content += QStringLiteral("Win32错误: %1\n").arg(formatWin32ErrorText(result.win32Error));
            content += QStringLiteral("原因: %1\n").arg(QString::fromStdWString(result.errorText));
            return content;
        }

        content += QStringLiteral("状态: OK\n");
        content += QStringLiteral("Reparse Tag: %1\n").arg(formatReparseTagText(result.tag));
        content += QStringLiteral("Tag名称: %1\n").arg(QString::fromStdWString(result.tagName));
        content += QStringLiteral("类型标记: %1\n").arg(QString::fromStdWString(result.kindName));
        content += QStringLiteral("Microsoft Tag: %1\n").arg(result.isMicrosoftTag ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("Name Surrogate: %1\n").arg(result.isNameSurrogate ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("是否相对链接: %1\n").arg(result.isRelative ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("Substitute Name: %1\n").arg(QString::fromStdWString(result.substituteName));
        content += QStringLiteral("Print Name: %1\n").arg(QString::fromStdWString(result.printName));
        content += QStringLiteral("解析目标路径: %1\n").arg(reparseTargetFromResult(result));
        content += QStringLiteral("原始信息: %1\n").arg(QString::fromStdWString(result.rawPayloadText));
        content += QStringLiteral("Raw Hex Preview: %1\n").arg(QString::fromStdWString(result.rawHexPreview));
        if (!result.errorText.empty())
        {
            content += QStringLiteral("解析提示: %1\n").arg(QString::fromStdWString(result.errorText));
        }
        return content;
    }

    // 展示需求只由面板视口发布。data() 只读缓存，不为排序、复制或尺寸计算入队。
    struct FileVisualDemand
    {
        QString path;
        QPersistentModelIndex index;
        int pathRole = Qt::UserRole;

        bool operator==(const FileVisualDemand& other) const
        {
            return path == other.path && index == other.index && pathRole == other.pathRole;
        }
    };

    constexpr int FileVisualDemandLimit = 512;

    // 同批、同父项、连续行共用通知；隐藏/过期需求不会产生展示通知。
    void notifyFileVisualRows(QAbstractItemModel* model, const QVector<QModelIndex>& changed,
        const int firstColumn, const int lastColumn, const QList<int>& roles)
    {
        QPointer<QAbstractItemModel> guard(model);
        QHash<QPersistentModelIndex, QVector<int>> groups;
        for (const QModelIndex& index : changed)
            groups[QPersistentModelIndex(index.parent())].push_back(index.row());
        for (auto it = groups.begin(); it != groups.end(); ++it)
        {
            auto& rows = it.value();
            std::sort(rows.begin(), rows.end());
            rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
            for (qsizetype begin = 0; begin < rows.size();)
            {
                qsizetype end = begin;
                while (end + 1 < rows.size() && rows[end + 1] == rows[end] + 1)
                    ++end;
                emit model->dataChanged(model->index(rows[begin], firstColumn, it.key()),
                    model->index(rows[end], lastColumn, it.key()), roles);
                if (!guard)
                    return;
                begin = end + 1;
            }
        }
    }

    template<class Result, class Cached = Result>
    class AsyncFileVisualCache final : public QObject
    {
    public:
        using Canceled = std::function<bool()>;
        using Query = std::function<Result(const QString&, const Canceled&)>;
        using Convert = std::function<Cached(Result, const QModelIndex&)>;

        AsyncFileVisualCache(QObject* parent, const int batchSize, Query query, Convert convert,
            std::function<void(const QVector<QModelIndex>&)> changed)
            : QObject(parent), m_batchSize(batchSize), m_query(std::move(query)),
              m_convert(std::move(convert)), m_changed(std::move(changed)), m_timer(this),
              m_dispatcher(std::make_shared<ks::ui::AsyncUiDispatcher>(this))
        {
            m_timer.setSingleShot(true);
            connect(&m_timer, &QTimer::timeout, this, [this]() { startBatch(); });
        }

        ~AsyncFileVisualCache() override
        {
            m_dispatcher->close();
            m_epoch->fetch_add(1);
        }

        const Cached* lookup(const QString& path) const
        {
            const auto cached = m_cache.constFind(path);
            return cached == m_cache.cend() ? nullptr : &cached.value();
        }

        void setDemand(const QVector<FileVisualDemand>& requested)
        {
            QVector<FileVisualDemand> demand;
            QSet<QString> paths;
            demand.reserve(std::min<qsizetype>(requested.size(), FileVisualDemandLimit));
            for (const auto& item : requested)
            {
                if (!valid(item) || paths.contains(item.path))
                    continue;
                paths.insert(item.path);
                demand.push_back(item);
                if (demand.size() == FileVisualDemandLimit)
                    break;
            }
            if (demand == m_demand)
                return;
            m_demand = std::move(demand);
            m_demandPaths = std::move(paths);
            m_epoch->fetch_add(1);
            rebuildPending();
        }

        void reset()
        {
            ++m_generation;
            m_epoch->fetch_add(1);
            m_timer.stop();
            m_cache.clear();
            m_cacheOrder.clear();
            m_demand.clear();
            m_demandPaths.clear();
            m_pending.clear();
        }

    private:
        static bool valid(const FileVisualDemand& item)
        {
            return item.index.isValid() && !item.path.isEmpty()
                && item.index.data(item.pathRole).toString() == item.path;
        }

        void rebuildPending()
        {
            m_pending.clear();
            // 新视口顺序覆盖旧队列；当前有界批次完成后立即处理最新项。
            for (const auto& item : m_demand)
                if (!m_cache.contains(item.path) && !m_inFlight.contains(item.path) && valid(item))
                    m_pending.push_back(item);
            if (!m_running && !m_pending.isEmpty() && !m_timer.isActive())
                m_timer.start(0);
            else if (m_pending.isEmpty())
                m_timer.stop();
        }

        void cacheResult(const QString& path, Cached value)
        {
            if (!m_cache.contains(path) && m_cache.size() >= FileVisualDemandLimit)
            {
                // 优先淘汰旧视口结果，不能在稳定的 512 项需求中反复淘汰可见项。
                auto victim = std::find_if(m_cacheOrder.begin(), m_cacheOrder.end(),
                    [this](const QString& key) { return !m_demandPaths.contains(key); });
                if (victim == m_cacheOrder.end())
                    victim = m_cacheOrder.begin();
                m_cache.remove(*victim);
                m_cacheOrder.erase(victim);
            }
            if (!m_cache.contains(path))
                m_cacheOrder.push_back(path);
            m_cache.insert(path, std::move(value)); // 查询失败/空标记同样缓存。
        }

        void startBatch()
        {
            if (m_running || m_pending.isEmpty())
                return;
            QVector<FileVisualDemand> batch;
            const int count = std::min<int>(m_batchSize, static_cast<int>(m_pending.size()));
            batch.reserve(count);
            for (int i = 0; i < count; ++i)
            {
                batch.push_back(m_pending[i]);
                m_inFlight.insert(m_pending[i].path);
            }
            m_pending.remove(0, count);
            m_running = true;
            const int generation = m_generation;
            const auto epoch = m_epoch;
            const auto expectedEpoch = epoch->load();
            const auto dispatcher = m_dispatcher;
            const Query query = m_query;
            // 持久索引只在 UI 回调中读取；worker 只使用路径与共享取消代次。
            QStringList paths;
            for (const auto& item : batch)
                paths.push_back(item.path);
            QPointer<AsyncFileVisualCache> guard(this);
            QThreadPool::globalInstance()->start(QRunnable::create(
                [guard, dispatcher, generation, epoch, expectedEpoch, batch, paths, query]() {
                    const Canceled canceled = [epoch, expectedEpoch]() {
                        return epoch->load() != expectedEpoch;
                    };
                    QHash<QString, Result> results;
                    for (const QString& path : paths)
                    {
                        if (canceled())
                            break;
                        Result result = query(path, canceled);
                        if (canceled())
                            break;
                        results.insert(path, std::move(result));
                    }
                    dispatcher->post([guard, generation, batch, results = std::move(results)]() mutable {
                        if (!guard)
                            return;
                        guard->m_running = false;
                        for (const auto& item : batch)
                            guard->m_inFlight.remove(item.path);
                        QVector<QModelIndex> changed;
                        if (guard->m_generation == generation)
                        {
                            for (const auto& item : batch)
                            {
                                auto result = results.find(item.path);
                                if (result == results.end() || !valid(item))
                                    continue;
                                guard->cacheResult(item.path,
                                    guard->m_convert(std::move(result.value()), item.index));
                                if (guard->m_demandPaths.contains(item.path))
                                    changed.push_back(item.index);
                            }
                        }
                        guard->rebuildPending();
                        if (!changed.isEmpty())
                            guard->m_changed(changed);
                    });
                }));
        }

        int m_batchSize;
        Query m_query;
        Convert m_convert;
        std::function<void(const QVector<QModelIndex>&)> m_changed;
        QTimer m_timer;
        QHash<QString, Cached> m_cache;
        QStringList m_cacheOrder;
        QVector<FileVisualDemand> m_demand;
        QSet<QString> m_demandPaths;
        QVector<FileVisualDemand> m_pending;
        QSet<QString> m_inFlight;
        std::shared_ptr<std::atomic<quint64>> m_epoch = std::make_shared<std::atomic<quint64>>(0);
        std::shared_ptr<ks::ui::AsyncUiDispatcher> m_dispatcher;
        int m_generation = 0;
        bool m_running = false;
    };

    class AsyncReparseMarkerCache final
    {
    public:
        AsyncReparseMarkerCache(QObject* parent,
            std::function<void(const QVector<QModelIndex>&)> changed)
            : m_cache(parent, 32,
                [](const QString& path, const auto&) { return reparseKindMarkerForPath(path); },
                [](QString value, const QModelIndex&) { return value; }, std::move(changed)) {}

        QString marker(const QString& path) const
        {
            const QString* value = m_cache.lookup(path);
            return value ? *value : QString();
        }
        void setDemand(const QVector<FileVisualDemand>& demand) { m_cache.setDemand(demand); }
        void reset() { m_cache.reset(); }

    private:
        AsyncFileVisualCache<QString> m_cache;
    };

    struct FilePresentation
    {
        QImage icon;
        QString type;
    };

    FilePresentation queryFilePresentation(const QString& path,
        const std::function<bool()>& canceled)
    {
        FilePresentation result;
        const HRESULT comResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const QString nativePath = QDir::toNativeSeparators(path);
        SHFILEINFOW shellInfo{};
        if (::SHGetFileInfoW(reinterpret_cast<const wchar_t*>(nativePath.utf16()), 0,
            &shellInfo, sizeof(shellInfo), SHGFI_ICON | SHGFI_SMALLICON) && shellInfo.hIcon)
        {
            result.icon = QImage::fromHICON(shellInfo.hIcon);
            ::DestroyIcon(shellInfo.hIcon);
        }
        if (SUCCEEDED(comResult))
            ::CoUninitialize();

        // Shell 已开始的调用允许安全结束，隐藏/换视口后不再启动下一次阻塞调用。
        if (canceled())
            return result;
        // MIME 数据库初始化、名称匹配及内容嗅探全部在工作线程。
        const QMimeType mime = QMimeDatabase().mimeTypeForFile(path);
        result.type = mime.comment();
        if (result.type.isEmpty())
            result.type = mime.name();
        return result;
    }

    // QPixmap 仅在 UI 回填创建；未富化项保持 QFileSystemModel 的原缓存值。
    class AsyncFilePresentationCache final
    {
    public:
        explicit AsyncFilePresentationCache(QObject* parent)
            : m_cache(parent, 8, queryFilePresentation,
                [](FilePresentation result, const QModelIndex& index) {
                    CachedPresentation cached;
                    if (!result.icon.isNull())
                        cached.icon = QIcon(QPixmap::fromImage(result.icon));
                    const auto* fs = qobject_cast<const QFileSystemModel*>(index.model());
                    if (fs && !fs->isDir(index) && !result.type.isEmpty())
                        cached.type = result.type;
                    return cached;
                }, [parent](const QVector<QModelIndex>& changed) {
                    notifyFileVisualRows(static_cast<QAbstractItemModel*>(parent), changed, 0, 2,
                        { Qt::DecorationRole, Qt::DisplayRole });
                }) {}

        QVariant value(const QString& path, const int role) const
        {
            const auto* value = m_cache.lookup(path);
            return value ? (role == Qt::DecorationRole ? value->icon : value->type) : QVariant();
        }
        void setDemand(const QVector<FileVisualDemand>& demand) { m_cache.setDemand(demand); }
        void reset() { m_cache.reset(); }

    private:
        struct CachedPresentation { QVariant icon; QVariant type; };
        AsyncFileVisualCache<FilePresentation, CachedPresentation> m_cache;
    };

    // Qt 6.9 在 UI 线程为目录整批结果调用 icon/type；这条路径只读已 stat 的
    // QFileInfo 并返回占位值，不能调用 Windows Shell 或初始化 MIME 数据库。
    class FastFileIconProvider final : public QFileIconProvider
    {
    public:
        FastFileIconProvider()
            : m_directoryIcon(QApplication::style()->standardIcon(QStyle::SP_DirIcon)),
              m_fileIcon(QApplication::style()->standardIcon(QStyle::SP_FileIcon))
        {
        }

        QIcon icon(const QFileInfo& info) const override
        {
            // Qt gatherer 已在后台 stat() 过这个 QFileInfo。
            return info.isDir() ? m_directoryIcon : m_fileIcon;
        }

        QString type(const QFileInfo& info) const override
        {
            if (!info.isFile())
                return QFileIconProvider::type(info);

            const QString suffix = info.suffix().toUpper();
            return suffix.isEmpty() ? ks::i18n::displayText(QStringLiteral("文件")) : suffix;
        }

    private:
        QIcon m_directoryIcon;
        QIcon m_fileIcon;
    };

    class ReparseAwareFileSystemModel final : public QFileSystemModel
    {
    public:
        explicit ReparseAwareFileSystemModel(QObject* parent = nullptr)
            : QFileSystemModel(parent), m_presentation(this), m_markers(this, [this](const QVector<QModelIndex>& changed) {
                notifyFileVisualRows(this, changed, 0, 2, { Qt::DisplayRole, Qt::ToolTipRole });
            })
        {
            setIconProvider(&m_iconProvider);
            connect(this, &QFileSystemModel::directoryLoaded, this,
                [this](const QString&) { m_markers.reset(); m_presentation.reset(); });
            connect(this, &QAbstractItemModel::modelReset, this,
                [this]() { m_markers.reset(); m_presentation.reset(); });
            connect(this, &QFileSystemModel::fileRenamed, this,
                [this](const QString&, const QString&, const QString&) { m_markers.reset(); m_presentation.reset(); });
        }

        void setVisualDemand(const QVector<FileVisualDemand>& demand)
        {
            m_markers.setDemand(demand);
            m_presentation.setDemand(demand);
        }

        QVariant data(const QModelIndex& index, const int role = Qt::DisplayRole) const override
        {
            QVariant baseValue = QFileSystemModel::data(index, role);
            if (!index.isValid())
            {
                return baseValue;
            }

            if ((role == Qt::DecorationRole && index.column() == 0)
                || (role == Qt::DisplayRole && index.column() == 2 && !isDir(index)))
            {
                const QVariant enriched = m_presentation.value(filePath(index), role);
                if (enriched.isValid())
                    baseValue = enriched;
            }

            if (role != Qt::DisplayRole && role != Qt::ToolTipRole)
            {
                return baseValue;
            }

            if (index.column() != 0 && index.column() != 2)
            {
                return baseValue.metaType().id() == QMetaType::QString
                    ? QVariant(ks::i18n::displayText(baseValue.toString())) : baseValue;
            }

            QVariant localizedBaseValue = baseValue;
            if (role == Qt::DisplayRole &&
                (index.column() == 1 || index.column() == 2) &&
                baseValue.metaType().id() == QMetaType::QString)
            {
                localizedBaseValue = ks::i18n::displayText(baseValue.toString());
            }

            const QString markerText = m_markers.marker(filePath(index));
            if (markerText.isEmpty())
            {
                return localizedBaseValue;
            }
            const QString localizedMarkerText = ks::i18n::displayText(markerText);

            if (role == Qt::ToolTipRole)
            {
                QString toolTipText = baseValue.toString();
                if (!toolTipText.isEmpty())
                {
                    toolTipText += QLatin1Char('\n');
                }
                toolTipText += ks::i18n::displayText(QStringLiteral("重解析点: %1"))
                    .arg(localizedMarkerText);
                return toolTipText;
            }

            if (index.column() == 0)
            {
                return QStringLiteral("%1 [%2]").arg(baseValue.toString(), localizedMarkerText);
            }
            if (index.column() == 2)
            {
                const QString typeText = localizedBaseValue.toString().trimmed();
                return typeText.isEmpty()
                    ? localizedMarkerText
                    : QStringLiteral("%1 / %2").arg(localizedMarkerText, typeText);
            }
            return localizedBaseValue;
        }

        QVariant headerData(
            const int section,
            const Qt::Orientation orientation,
            const int role = Qt::DisplayRole) const override
        {
            const QVariant baseValue = QFileSystemModel::headerData(section, orientation, role);
            if (orientation == Qt::Horizontal
                && role == Qt::DisplayRole
                && baseValue.metaType().id() == QMetaType::QString)
            {
                return ks::i18n::displayText(baseValue.toString());
            }
            return baseValue;
        }

    private:
        FastFileIconProvider m_iconProvider;
        AsyncFilePresentationCache m_presentation;
        AsyncReparseMarkerCache m_markers;
    };

    // ExplorerFileSortProxyModel：
    // - 目录始终排在文件之前；
    // - 名称列使用大小写不敏感的自然排序（例如 item2 排在 item10 之前）；
    // - 同一名称的大小写变体再用大小写敏感比较稳定排序。
    // QFileSystemModel 的默认排序与 QSortFilterProxyModel 的字符串比较在不同
    // Qt/文件系统后端下可能产生不同结果，因此这里把资源管理器的默认规则固定
    // 在 FileDock 自己的代理层。
    class ExplorerFileSortProxyModel final : public QSortFilterProxyModel
    {
    public:
        explicit ExplorerFileSortProxyModel(QObject* parent = nullptr)
            : QSortFilterProxyModel(parent)
        {
            m_collator.setCaseSensitivity(Qt::CaseInsensitive);
            m_collator.setNumericMode(true);
        }

    protected:
        bool lessThan(
            const QModelIndex& left,
            const QModelIndex& right) const override
        {
            // QSortFilterProxyModel::lessThan 接收的是源模型索引，不能再次
            // mapToSource；重复映射会得到无效索引并退回 Qt 默认字符串排序。
            if (!left.isValid() || !right.isValid())
            {
                return QSortFilterProxyModel::lessThan(left, right);
            }

            const bool leftIsDirectory = isDirectory(left);
            const bool rightIsDirectory = isDirectory(right);
            if (leftIsDirectory != rightIsDirectory)
            {
                return leftIsDirectory;
            }

            if (left.column() == 0)
            {
                const QString leftName = displayName(left);
                const QString rightName = displayName(right);
                const int naturalCompare = m_collator.compare(leftName, rightName);
                if (naturalCompare != 0)
                {
                    return naturalCompare < 0;
                }

                const int stableCompare = QString::compare(
                    leftName,
                    rightName,
                    Qt::CaseSensitive);
                if (stableCompare != 0)
                {
                    return stableCompare < 0;
                }
            }

            if (const auto* fs = qobject_cast<QFileSystemModel*>(sourceModel()))
            {
                // 直接读 QFileSystemModel 的元数据缓存，不经过 DisplayRole/重解析标记。
                if (left.column() == 1)
                    return fs->size(left) < fs->size(right);
                if (left.column() == 2)
                    return QString::compare(fs->type(left), fs->type(right),
                        Qt::CaseInsensitive) < 0;
                if (left.column() == 3)
                    return fs->lastModified(left) < fs->lastModified(right);
            }
            else
            {
                if (left.column() == 1)
                    return left.data(Qt::UserRole).toULongLong() <
                        right.data(Qt::UserRole).toULongLong();
                if (left.column() == 2)
                    return QString::compare(left.data(Qt::UserRole).toString(),
                        right.data(Qt::UserRole).toString(), Qt::CaseInsensitive) < 0;
                if (left.column() == 3)
                    return left.data(Qt::UserRole).toDateTime() <
                        right.data(Qt::UserRole).toDateTime();
            }
            return QSortFilterProxyModel::lessThan(left, right);
        }

    private:
        bool isDirectory(const QModelIndex& sourceIndex) const
        {
            QAbstractItemModel* const source =
                const_cast<QAbstractItemModel*>(sourceModel());
            if (QFileSystemModel* const fileSystemModel =
                    qobject_cast<QFileSystemModel*>(source))
            {
                return fileSystemModel->isDir(sourceIndex);
            }

            return sourceIndex.siblingAtColumn(0)
                .data(Qt::UserRole + 1)
                .toBool();
        }

        QString displayName(const QModelIndex& sourceIndex) const
        {
            QAbstractItemModel* const source =
                const_cast<QAbstractItemModel*>(sourceModel());
            if (QFileSystemModel* const fileSystemModel =
                    qobject_cast<QFileSystemModel*>(source))
            {
                return fileSystemModel->fileName(sourceIndex);
            }

            return sourceIndex.siblingAtColumn(0).data(Qt::DisplayRole).toString();
        }

        QCollator m_collator;
    };

    // 刷新同一目录时按可见文件恢复视口。仅在 FileDock 的刷新入口启用，
    // 不改变全局样式、普通导航或其他表格的刷新策略。
    class FileRefreshScrollState final : public QObject
    {
    public:
        FileRefreshScrollState(QAbstractItemView* view, QString directory,
            std::function<bool()> isCurrent)
            : QObject(view), m_view(view), m_directory(std::move(directory)),
              m_isCurrent(std::move(isCurrent)), m_timer(this)
        {
            constexpr char stateName[] = "file_refresh_scroll_state";
            auto* previous = dynamic_cast<FileRefreshScrollState*>(
                view->findChild<QObject*>(QLatin1String(stateName), Qt::FindDirectChildrenOnly));
            if (previous && !previous->m_cancelled && previous->m_isCurrent())
            {
                // 连续刷新时模型可能已清空，沿用尚未恢复的视口而非重新保存表头。
                m_vertical = previous->m_vertical;
                m_horizontal = previous->m_horizontal;
                m_anchorPath = previous->m_anchorPath;
                m_anchorTop = previous->m_anchorTop;
            }
            else
            {
                m_vertical = view->verticalScrollBar()->value();
                m_horizontal = view->horizontalScrollBar()->value();
                QModelIndex anchor;
                // 图标网格的左上角可能是空隙，仅在视口顶端有界查找。
                for (int y = 0; y < std::min(128, view->viewport()->height()) && !anchor.isValid(); y += 8)
                    for (int x = 8; x < view->viewport()->width() && !anchor.isValid(); x += 32)
                        anchor = view->indexAt(QPoint(x, y));
                if (anchor.isValid())
                {
                    anchor = anchor.siblingAtColumn(0);
                    m_anchorPath = indexPath(anchor);
                    m_anchorTop = view->visualRect(anchor).top();
                }
            }
            delete previous;
            setObjectName(QLatin1String(stateName));
            m_model = view->model();
            m_timer.setSingleShot(true);
            connect(&m_timer, &QTimer::timeout, this, [this]() { restore(); });
            connect(view->verticalScrollBar(), &QScrollBar::rangeChanged, this,
                [this](int, int) { schedule(); });
            // 用户在等待期间主动滚动/操作时，旧位置不再覆盖新的意图。
            connect(view->verticalScrollBar(), &QScrollBar::actionTriggered, this,
                [this](int) { finish(); });
            connect(view->horizontalScrollBar(), &QScrollBar::actionTriggered, this,
                [this](int) { finish(); });
            view->installEventFilter(this);
            view->viewport()->installEventFilter(this);
        }

        void waitForModel(QAbstractItemModel* source)
        {
            if (auto* fs = qobject_cast<QFileSystemModel*>(source))
            {
                connect(fs, &QFileSystemModel::directoryLoaded, this, [this](const QString& path) {
                    if (!m_isCurrent())
                        finish();
                    else if (samePath(path, m_directory))
                    {
                        m_ready = true;
                        schedule();
                    }
                });
            }
            else
            {
                connect(source, &QAbstractItemModel::modelReset, this, [this]() {
                    m_ready = true;
                    schedule();
                });
            }
        }

    protected:
        bool eventFilter(QObject* object, QEvent* event) override
        {
            switch (event->type())
            {
            case QEvent::Wheel:
            case QEvent::MouseButtonPress:
            case QEvent::KeyPress:
                finish();
                break;
            case QEvent::Show:
            case QEvent::Resize:
                schedule();
                break;
            default:
                break;
            }
            return QObject::eventFilter(object, event);
        }

    private:
        static bool samePath(const QString& a, const QString& b)
        {
            return QDir::fromNativeSeparators(a).compare(
                QDir::fromNativeSeparators(b), Qt::CaseInsensitive) == 0;
        }

        static QString indexPath(QModelIndex index)
        {
            if (const auto* proxy = qobject_cast<const QSortFilterProxyModel*>(index.model()))
                index = proxy->mapToSource(index);
            if (const auto* fs = qobject_cast<const QFileSystemModel*>(index.model()))
                return fs->filePath(index);
            return index.data(Qt::UserRole).toString();
        }

        void schedule()
        {
            if (!m_cancelled && m_ready && !m_timer.isActive())
                m_timer.start(0);
        }

        void finish()
        {
            m_cancelled = true;
            m_timer.stop();
            deleteLater();
        }

        void restore()
        {
            if (!m_view || !m_model || !m_isCurrent() || m_view->model() != m_model)
            {
                finish();
                return;
            }
            if (!m_view->isVisible())
                return; // 隐藏面板等到 Show 后再恢复，不强制布局整个图标列表。

            const QModelIndex root = m_view->rootIndex();
            const int rows = m_model->rowCount(root);
            if (!m_resolved)
            {
                // 只读模型中的路径缓存，不能通过 QFileSystemModel::index(path) 查盘。
                for (int row = 0; row < rows && !m_anchorPath.isEmpty(); ++row)
                {
                    const QModelIndex index = m_model->index(row, 0, root);
                    if (samePath(indexPath(index), m_anchorPath))
                    {
                        m_anchor = index;
                        break;
                    }
                }
                m_resolved = true;
            }
            if (m_anchor.isValid())
            {
                if (m_view->visualRect(m_anchor).isEmpty())
                {
                    // QListView::Batched 尚未布局到该项，继续让 Qt 分批完成。
                    m_timer.start(16);
                    return;
                }
                m_view->scrollTo(m_anchor, QAbstractItemView::PositionAtTop);
                if (m_view->verticalScrollMode() == QAbstractItemView::ScrollPerPixel)
                {
                    auto* bar = m_view->verticalScrollBar();
                    bar->setValue(bar->value() + m_view->visualRect(m_anchor).top() - m_anchorTop);
                }
            }
            else
            {
                if (rows > 0 && m_view->visualRect(m_model->index(rows - 1, 0, root)).isEmpty())
                {
                    m_timer.start(16);
                    return;
                }
                // 原文件已删除或被筛掉时，滚动条自动将旧位置夹到新的合法范围。
                m_view->verticalScrollBar()->setValue(m_vertical);
            }
            m_view->horizontalScrollBar()->setValue(m_horizontal);
            finish();
        }

        QPointer<QAbstractItemView> m_view;
        QPointer<QAbstractItemModel> m_model;
        QString m_directory;
        std::function<bool()> m_isCurrent;
        QTimer m_timer;
        QString m_anchorPath;
        QPersistentModelIndex m_anchor;
        int m_vertical = 0;
        int m_horizontal = 0;
        int m_anchorTop = 0;
        bool m_ready = false;
        bool m_resolved = false;
        bool m_cancelled = false;
    };

    // buildDriverNtPath：
    // - 作用：把 Win32 路径转成驱动可直接使用的 NT 路径；
    // - 规则：普通盘符路径转成 \??\C:\...，UNC 路径转成 \??\UNC\...
    QString buildDriverNtPath(const QString& path)
    {
        const QString nativePathText = QDir::toNativeSeparators(path).trimmed();
        if (nativePathText.isEmpty())
        {
            return QString();
        }
        if (nativePathText.startsWith(QStringLiteral("\\??\\")))
        {
            return nativePathText;
        }
        if (nativePathText.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + nativePathText.mid(4);
        }
        if (nativePathText.startsWith(QStringLiteral("\\Device\\")))
        {
            return nativePathText;
        }
        if (nativePathText.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + nativePathText.mid(2);
        }
        return QStringLiteral("\\??\\") + nativePathText;
    }

    // buildLiteralNameFilterPattern：
    // - 作用：把关键字转成 QFileSystemModel::setNameFilters 可用的“包含匹配”通配符；
    // - 说明：对 *, ?, [, ] 做转义，避免用户输入被当作通配符语法。
    QString buildLiteralNameFilterPattern(const QString& keywordText)
    {
        QString escapedKeyword = keywordText;
        escapedKeyword.replace(QStringLiteral("["), QStringLiteral("[[]"));
        escapedKeyword.replace(QStringLiteral("]"), QStringLiteral("[]]"));
        escapedKeyword.replace(QStringLiteral("*"), QStringLiteral("[*]"));
        escapedKeyword.replace(QStringLiteral("?"), QStringLiteral("[?]"));
        return QStringLiteral("*%1*").arg(escapedKeyword);
    }

    // queryShortPathText：
    // - 作用：查询目标路径对应的 Win32 短路径（8.3）；
    // - 失败时返回空字符串，调用方可决定是否走原名兜底。
    QString queryShortPathText(const QString& path)
    {
        const std::wstring nativePathText = QDir::toNativeSeparators(path).toStdWString();
        if (nativePathText.empty())
        {
            return QString();
        }

        const DWORD requiredChars = ::GetShortPathNameW(nativePathText.c_str(), nullptr, 0);
        if (requiredChars == 0)
        {
            return QString();
        }

        QVector<wchar_t> shortPathBuffer(static_cast<int>(requiredChars) + 2, L'\0');
        const DWORD copiedChars = ::GetShortPathNameW(
            nativePathText.c_str(),
            shortPathBuffer.data(),
            static_cast<DWORD>(shortPathBuffer.size()));
        if (copiedChars == 0 || copiedChars >= static_cast<DWORD>(shortPathBuffer.size()))
        {
            return QString();
        }
        return QString::fromWCharArray(shortPathBuffer.data(), static_cast<int>(copiedChars));
    }

    QString normalizeFileDockPath(const QString& path)
    {
        return QDir::toNativeSeparators(QDir::cleanPath(path.trimmed()));
    }

    bool pathEqualsCaseInsensitive(const QString& left, const QString& right)
    {
        return normalizeFileDockPath(left).compare(
            normalizeFileDockPath(right),
            Qt::CaseInsensitive) == 0;
    }

    void closeWin32Handle(HANDLE& handleValue)
    {
        if (handleValue != nullptr && handleValue != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(handleValue);
            handleValue = INVALID_HANDLE_VALUE;
        }
    }

    QString oplockCompletionText(const bool completionOk, const unsigned long completionError)
    {
        if (completionOk)
        {
            return QStringLiteral("已触发/完成");
        }
        if (completionError == ERROR_OPERATION_ABORTED)
        {
            return QStringLiteral("已取消");
        }
        if (completionError == ERROR_HANDLE_EOF)
        {
            return QStringLiteral("目标句柄已关闭");
        }
        return QStringLiteral("完成失败，Win32=%1").arg(completionError);
    }

    // openKswordArkDriverHandle：
    // - 作用：通过 ArkDriverClient 连接 KswordARK 控制设备；
    // - 返回 move-only 句柄对象，避免 Dock 直接 CloseHandle。
    ksword::ark::DriverHandle openKswordArkDriverHandle(std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        const ksword::ark::DriverClient driverClient;
        ksword::ark::DriverHandle driverHandle = driverClient.open();
        if (driverHandle.isValid())
        {
            return driverHandle;
        }

        if (detailTextOut != nullptr)
        {
            const DWORD lastError = ::GetLastError();
            std::ostringstream oss;
            oss << "open KswordARK driver failed, error=" << lastError;
            *detailTextOut = oss.str();
        }
        return driverHandle;
    }

    // deletePathByR0Driver：
    // - 作用：向 ArkDriverClient 发送“删除单一路径”IOCTL；
    // - 参数 isDirectory 用于驱动端选择目录/文件打开语义。
    bool deletePathByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const QString& path,
        const bool isDirectory,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid driver handle";
            }
            return false;
        }

        const QString driverNtPath = buildDriverNtPath(path);
        if (driverNtPath.isEmpty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "empty path";
            }
            return false;
        }

        const std::wstring ntPathText = driverNtPath.toStdWString();
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.deletePath(driverHandle, ntPathText, isDirectory);
        if (detailTextOut != nullptr)
        {
            std::ostringstream oss;
            oss << "path=" << QDir::toNativeSeparators(path).toStdString()
                << ", directory=" << (isDirectory ? 1 : 0)
                << ", bytesReturned=" << result.bytesReturned;
            if (result.ok)
            {
                oss << ", ioctl=ok";
            }
            else
            {
                oss << ", ioctl=fail, error=" << result.win32Error;
                if (!result.message.empty())
                {
                    oss << ", detail=" << result.message;
                }
            }
            *detailTextOut = oss.str();
        }
        return result.ok;
    }

    bool shouldFallbackFileIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported)
    {
        // 输入：ArkDriverClient 的通信结果和 unsupported 标记。
        // 处理：只把驱动未装载、旧驱动缺 IOCTL 或请求无法通过当前 R0 协议发送归类为 R3 fallback。
        // 返回：true 表示可尝试 R3；R0 已返回语义失败时返回 false，避免掩盖 ZwSetSecurityObject 失败原因。
        if (io.ok)
        {
            return false;
        }
        if (unsupported)
        {
            return true;
        }

        return io.win32Error == ERROR_FILE_NOT_FOUND ||
            io.win32Error == ERROR_PATH_NOT_FOUND ||
            io.win32Error == ERROR_SERVICE_DOES_NOT_EXIST ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED ||
            io.win32Error == ERROR_INVALID_PARAMETER;
    }

    DWORD setFileIntegrityLevelByR0ThenR3(
        const QString& filePath,
        const DWORD integrityRid,
        QString* const detailText)
    {
        // 输入：Win32/Qt 文件路径和 Mandatory Label RID。
        // 处理：先将路径转换为驱动 NT 路径并调用 R0；驱动不可用/旧驱动时回退 SetNamedSecurityInfoW。
        // 返回：ERROR_SUCCESS 表示 R0 或 fallback R3 成功；失败时返回 Win32 或 NTSTATUS 数值并写入 detailText。
        if (!isSupportedFileMandatoryIntegrityRid(integrityRid))
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("unsupported file mandatory label RID=0x%1; "
                    "file objects only support Untrusted/Low/Medium/MediumPlus/High/System")
                    .arg(integrityRid, 0, 16);
            }
            return ERROR_INVALID_PARAMETER;
        }

        const QString driverNtPath = buildDriverNtPath(filePath);
        if (driverNtPath.isEmpty())
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("empty path");
            }
            return ERROR_INVALID_PARAMETER;
        }

        const QFileInfo fileInfo(filePath);
        const bool isDirectory = fileInfo.isDir();
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::FileIntegrityResult r0Result =
            driverClient.setFileIntegrity(driverNtPath.toStdWString(), isDirectory, integrityRid);
        const bool r0Applied = r0Result.io.ok &&
            r0Result.status == KSWORD_ARK_FILE_INTEGRITY_STATUS_APPLIED &&
            r0Result.lastStatus >= 0;
        if (r0Applied)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("R0 ok: %1, ntPath=%2")
                    .arg(QString::fromStdString(r0Result.io.message))
                    .arg(driverNtPath);
            }
            return ERROR_SUCCESS;
        }

        if (shouldFallbackFileIntegrityToR3(r0Result.io, r0Result.unsupported))
        {
            QString r3DetailText;
            const DWORD r3Result = setFileIntegrityLevelByPath(
                filePath,
                integrityRid,
                &r3DetailText);
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("R0 unavailable/unsupported: %1 | R3 %2: %3")
                    .arg(QString::fromStdString(r0Result.io.message))
                    .arg(r3Result == ERROR_SUCCESS ? QStringLiteral("ok") : QStringLiteral("failed"))
                    .arg(r3DetailText.isEmpty() ? QStringLiteral("no detail") : r3DetailText);
            }
            return r3Result;
        }

        if (detailText != nullptr)
        {
            *detailText = QStringLiteral("R0 failed: %1, status=%2, nt=0x%3, win32=%4, ntPath=%5")
                .arg(QString::fromStdString(r0Result.io.message))
                .arg(r0Result.status)
                .arg(static_cast<unsigned long>(r0Result.lastStatus), 0, 16)
                .arg(r0Result.io.win32Error)
                .arg(driverNtPath);
        }
        if (!r0Result.io.ok)
        {
            return r0Result.io.win32Error == ERROR_SUCCESS
                ? ERROR_GEN_FAILURE
                : r0Result.io.win32Error;
        }
        return r0Result.lastStatus == 0
            ? ERROR_GEN_FAILURE
            : static_cast<DWORD>(r0Result.lastStatus);
    }

    // terminateProcessByR0Driver：
    // - 作用：复用同一个 ArkDriverClient 句柄发送结束进程 IOCTL；
    // - 返回值：true=驱动返回成功，false=驱动返回失败或句柄无效。
    bool terminateProcessByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const std::uint32_t processId,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid driver handle";
            }
            return false;
        }

        if (processId == 0U || processId <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.terminateProcess(
            driverHandle,
            processId,
            static_cast<long>(0xC0000005u));
        if (detailTextOut != nullptr)
        {
            *detailTextOut = result.message;
        }
        return result.ok;
    }

    bool terminateProcessByR3(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (processId == 0U || processId <= 4U || processId == static_cast<std::uint32_t>(::GetCurrentProcessId()))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        // 用扫描时的创建时间复核 PID，并通过同一个已验证句柄结束进程。
        // 持有该句柄期间旧进程对象不会销毁，因此 PID 不能被复用到另一个进程。
        HANDLE processHandle = nullptr;
        std::string identityDetailText;
        if (!ks::file::OpenProcessForVerifiedAction(
                processId,
                expectedCreationTime,
                PROCESS_TERMINATE | SYNCHRONIZE,
                processHandle,
                identityDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = identityDetailText;
            }
            return false;
        }

        const BOOL terminateResult = ::TerminateProcess(processHandle, static_cast<UINT>(0xC0000005U));
        const DWORD terminateError = terminateResult == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(processHandle);
        const bool terminateOk = terminateResult != FALSE;

        if (detailTextOut != nullptr)
        {
            std::ostringstream oss;
            oss << "pid=" << processId;
            if (terminateOk)
            {
                oss << ", TerminateProcess=ok";
            }
            else
            {
                oss << ", TerminateProcess=fail, error=" << terminateError;
            }
            *detailTextOut = oss.str();
        }
        return terminateOk;
    }

    // showUnlockSelectionDialog：
    // - 作用：展示文件解锁器扫描结果，并让用户选择关闭句柄或结束进程；
    // - 参数 parent：父窗口，用于模态弹窗归属；
    // - 参数 processCandidateList：按 PID 聚合后的占用进程列表；
    // - 参数 handleCandidateList：按 PID+Handle 展开的可关闭句柄列表；
    // - 返回：用户确认的操作模式与选中目标；取消时 accepted=false。
    UnlockSelectionResult showUnlockSelectionDialog(
        QWidget* const parent,
        const std::vector<UnlockProcessCandidate>& processCandidateList,
        const std::vector<UnlockHandleCandidate>& handleCandidateList)
    {
        UnlockSelectionResult result;
        if (processCandidateList.empty() && handleCandidateList.empty())
        {
            return result;
        }

        QDialog dialog(parent);
        dialog.setObjectName(QStringLiteral("FileUnlockerSelectionDialog"));
        dialog.setStyleSheet(buildOpaqueStandaloneDialogStyle(dialog.objectName()));
        dialog.setWindowTitle(QStringLiteral("文件解锁器 - 选择操作目标"));
        ks::ui::StyleSecondaryWindow(&dialog);
        dialog.resize(1080, 680);

        QVBoxLayout* const rootLayout = new QVBoxLayout(&dialog);
        ks::ui::StyleSecondaryContentLayout(rootLayout);
        QLabel* const tipLabel = new QLabel(
            QStringLiteral("已扫描到以下占用来源。建议先关闭选中句柄；若仍无法删除/重命名，再改用结束进程兜底。未勾选的目标不会处理。"),
            &dialog);
        tipLabel->setWordWrap(true);
        rootLayout->addWidget(tipLabel);

        QHBoxLayout* const modeLayout = new QHBoxLayout();
        QLabel* const modeLabel = new QLabel(QStringLiteral("操作方式："), &dialog);
        QComboBox* const modeComboBox = new QComboBox(&dialog);
        const bool hasClosableHandle = std::any_of(
            handleCandidateList.begin(),
            handleCandidateList.end(),
            [](const UnlockHandleCandidate& candidate) {
                return candidate.handleValue != 0U
                    && candidate.processCreationTime != 0U
                    && !candidate.matchedTargetPath.trimmed().isEmpty()
                    && candidate.processId > 4U
                    && !candidate.isCurrentProcess
                    && !candidate.isCriticalProcess;
            });
        modeComboBox->addItem(QStringLiteral("关闭选中句柄(R3，推荐先尝试)"));
        modeComboBox->addItem(QStringLiteral("结束选中进程(R3)"));
        modeComboBox->addItem(QStringLiteral("结束选中进程(R0，更强力)"));
        if (!hasClosableHandle)
        {
            modeComboBox->setCurrentIndex(1);
        }
        modeLayout->addWidget(modeLabel);
        modeLayout->addWidget(modeComboBox, 1);
        ks::ui::NormalizeToolbarRow(modeLayout);
        rootLayout->addLayout(modeLayout);

        QStackedWidget* const tableStack = new QStackedWidget(&dialog);
        QTableWidget* const handleTable = new ks::ui::VisibleTableWidget(static_cast<int>(handleCandidateList.size()), 7, &dialog);
        // 解锁对话框只确认本轮操作目标，隐藏与确认无关的通用快照栏。
        ks::ui::SetTableActionBarMode(handleTable, ks::ui::TableActionBarMode::None);
        handleTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("选择"),
            QStringLiteral("PID"),
            QStringLiteral("进程名"),
            QStringLiteral("Handle"),
            QStringLiteral("GrantedAccess"),
            QStringLiteral("命中路径"),
            QStringLiteral("说明") });
        handleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        handleTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        handleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        handleTable->verticalHeader()->setVisible(false);
        handleTable->horizontalHeader()->setStretchLastSection(true);
        installFileTableCopyMenu(handleTable, 1);

        QTableWidget* const processTable = new ks::ui::VisibleTableWidget(static_cast<int>(processCandidateList.size()), 6, &dialog);
        ks::ui::SetTableActionBarMode(processTable, ks::ui::TableActionBarMode::None);
        processTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("选择"),
            QStringLiteral("PID"),
            QStringLiteral("进程名"),
            QStringLiteral("命中数"),
            QStringLiteral("命中路径"),
            QStringLiteral("说明") });
        processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        processTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        processTable->verticalHeader()->setVisible(false);
        processTable->horizontalHeader()->setStretchLastSection(true);
        installFileTableCopyMenu(processTable, 1);

        auto makeTableItem = [](const QString& text, const bool enabled) {
            QTableWidgetItem* const item = new QTableWidgetItem(text);
            item->setFlags(enabled
                ? (Qt::ItemIsSelectable | Qt::ItemIsEnabled)
                : Qt::ItemIsSelectable);
            return item;
            };

        for (int row = 0; row < static_cast<int>(handleCandidateList.size()); ++row)
        {
            const UnlockHandleCandidate& candidate = handleCandidateList[static_cast<std::size_t>(row)];
            const bool canCloseHandle = candidate.handleValue != 0U
                && candidate.processCreationTime != 0U
                && !candidate.matchedTargetPath.trimmed().isEmpty()
                && !candidate.isCurrentProcess
                && !candidate.isCriticalProcess
                && candidate.processId > 4U;

            QTableWidgetItem* const checkItem = new QTableWidgetItem();
            checkItem->setCheckState(Qt::Unchecked);
            checkItem->setData(Qt::UserRole, row);
            checkItem->setFlags(canCloseHandle
                ? (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable | Qt::ItemIsEnabled)
                : (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable));
            handleTable->setItem(row, 0, checkItem);

            QStringList noteList;
            appendUniqueText(noteList, candidate.objectName);
            appendUniqueText(noteList, candidate.processImagePath);
            appendUniqueText(noteList, candidate.matchRuleText);
            appendUniqueText(noteList, candidate.enumerationSource);
            if (candidate.handleValue == 0U)
            {
                noteList.push_back(QStringLiteral("无句柄值：该来源可能是进程映像/模块映射，不能用 R3 关闭句柄处理"));
            }
            if (candidate.isCurrentProcess)
            {
                noteList.push_back(QStringLiteral("已保护：当前 Ksword 进程，不可关闭句柄"));
            }
            if (candidate.isCriticalProcess)
            {
                noteList.push_back(QStringLiteral("已保护：关键系统进程，不可关闭句柄"));
            }
            if (candidate.processCreationTime == 0U || candidate.matchedTargetPath.trimmed().isEmpty())
            {
                noteList.push_back(QStringLiteral("身份不可验证：请重新扫描后再操作"));
            }

            handleTable->setItem(row, 1, makeTableItem(QString::number(candidate.processId), canCloseHandle));
            handleTable->setItem(row, 2, makeTableItem(candidate.processName.isEmpty() ? QStringLiteral("Unknown") : candidate.processName, canCloseHandle));
            handleTable->setItem(row, 3, makeTableItem(formatHandleValueText(candidate.handleValue), canCloseHandle));
            handleTable->setItem(row, 4, makeTableItem(formatHandleValueText(candidate.grantedAccess), canCloseHandle));
            handleTable->setItem(row, 5, makeTableItem(candidate.matchedTargetPath, canCloseHandle));
            handleTable->setItem(row, 6, makeTableItem(noteList.join(QStringLiteral("\n")), canCloseHandle));
        }

        for (int row = 0; row < static_cast<int>(processCandidateList.size()); ++row)
        {
            const UnlockProcessCandidate& candidate = processCandidateList[static_cast<std::size_t>(row)];
            const bool protectedProcess = candidate.isCurrentProcess
                || candidate.isCriticalProcess
                || candidate.processCreationTime == 0U;

            QTableWidgetItem* const checkItem = new QTableWidgetItem();
            checkItem->setCheckState(Qt::Unchecked);
            checkItem->setData(Qt::UserRole, static_cast<qulonglong>(candidate.processId));
            checkItem->setFlags(protectedProcess
                ? (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable)
                : (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable | Qt::ItemIsEnabled));
            processTable->setItem(row, 0, checkItem);

            auto makeTextItem = [protectedProcess](const QString& text) {
                QTableWidgetItem* const item = new QTableWidgetItem(text);
                item->setFlags(protectedProcess
                    ? Qt::ItemIsSelectable
                    : (Qt::ItemIsSelectable | Qt::ItemIsEnabled));
                return item;
                };

            QStringList noteList;
            appendUniqueText(noteList, candidate.processImagePath);
            for (const QString& ruleText : candidate.matchRuleList)
            {
                appendUniqueText(noteList, ruleText);
            }
            if (candidate.isCurrentProcess)
            {
                noteList.push_back(QStringLiteral("已保护：当前 Ksword 进程，不可选择"));
            }
            if (candidate.isCriticalProcess)
            {
                noteList.push_back(QStringLiteral("已保护：关键系统进程，不可选择"));
            }
            if (candidate.processCreationTime == 0U)
            {
                noteList.push_back(QStringLiteral("身份不可验证：请重新扫描后再操作"));
            }

            processTable->setItem(row, 1, makeTextItem(QString::number(candidate.processId)));
            processTable->setItem(row, 2, makeTextItem(candidate.processName.isEmpty() ? QStringLiteral("Unknown") : candidate.processName));
            processTable->setItem(row, 3, makeTextItem(QString::number(candidate.matchCount)));
            processTable->setItem(row, 4, makeTextItem(candidate.matchedTargetList.join(QStringLiteral("\n"))));
            processTable->setItem(row, 5, makeTextItem(noteList.join(QStringLiteral("\n"))));
        }

        handleTable->resizeColumnsToContents();
        processTable->resizeColumnsToContents();
        tableStack->addWidget(handleTable);
        tableStack->addWidget(processTable);
        tableStack->setCurrentIndex(modeComboBox->currentIndex() == 0 ? 0 : 1);
        rootLayout->addWidget(tableStack, 1);

        QDialogButtonBox* const buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        QPushButton* const selectAllButton = buttonBox->addButton(QStringLiteral("全选当前可操作项"), QDialogButtonBox::ActionRole);
        QPushButton* const clearButton = buttonBox->addButton(QStringLiteral("清空选择"), QDialogButtonBox::ActionRole);
        buttonBox->button(QDialogButtonBox::Ok)->setText(modeComboBox->currentIndex() == 0
            ? QStringLiteral("关闭选中句柄")
            : QStringLiteral("执行选中操作"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        // 目标选择与执行入口固定在底部，保留业务按钮的角色与信号。
        ks::ui::StyleSecondaryButtonBox(buttonBox);
        ks::ui::StyleSecondaryFooter(buttonBox);
        rootLayout->addWidget(buttonBox);

        auto collectSelectedHandles = [&handleTable, &handleCandidateList]() {
            std::vector<UnlockHandleCandidate> selectedHandleList;
            for (int row = 0; row < handleTable->rowCount(); ++row)
            {
                QTableWidgetItem* const item = handleTable->item(row, 0);
                if (item == nullptr
                    || !(item->flags() & Qt::ItemIsEnabled)
                    || item->checkState() != Qt::Checked)
                {
                    continue;
                }
                selectedHandleList.push_back(handleCandidateList[static_cast<std::size_t>(row)]);
            }
            return selectedHandleList;
            };

        auto collectSelectedIds = [&processTable, &processCandidateList]() {
            std::vector<std::uint32_t> selectedProcessIdList;
            for (int row = 0; row < processTable->rowCount(); ++row)
            {
                QTableWidgetItem* const item = processTable->item(row, 0);
                if (item == nullptr
                    || !(item->flags() & Qt::ItemIsEnabled)
                    || item->checkState() != Qt::Checked)
                {
                    continue;
                }
                selectedProcessIdList.push_back(processCandidateList[static_cast<std::size_t>(row)].processId);
            }
            return selectedProcessIdList;
            };

        auto setCheckedForTable = [](QTableWidget* const targetTable, const Qt::CheckState checkState) {
            for (int row = 0; row < targetTable->rowCount(); ++row)
            {
                QTableWidgetItem* const item = targetTable->item(row, 0);
                if (item != nullptr && (item->flags() & Qt::ItemIsEnabled))
                {
                    item->setCheckState(checkState);
                }
            }
            };
        QObject::connect(selectAllButton, &QPushButton::clicked, [&modeComboBox, &handleTable, &processTable, &setCheckedForTable]() {
            setCheckedForTable(modeComboBox->currentIndex() == 0 ? handleTable : processTable, Qt::Checked);
            });
        QObject::connect(clearButton, &QPushButton::clicked, [&modeComboBox, &handleTable, &processTable, &setCheckedForTable]() {
            setCheckedForTable(modeComboBox->currentIndex() == 0 ? handleTable : processTable, Qt::Unchecked);
            });
        QObject::connect(modeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [&tableStack, &buttonBox](const int modeIndex) {
                tableStack->setCurrentIndex(modeIndex == 0 ? 0 : 1);
                buttonBox->button(QDialogButtonBox::Ok)->setText(modeIndex == 0
                    ? QStringLiteral("关闭选中句柄")
                    : QStringLiteral("执行选中操作"));
            });
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, [&dialog, &modeComboBox, &collectSelectedHandles, &collectSelectedIds]() {
            if (modeComboBox->currentIndex() == 0 && collectSelectedHandles().empty())
            {
                return;
            }
            if (modeComboBox->currentIndex() != 0 && collectSelectedIds().empty())
            {
                return;
            }
            dialog.accept();
            });

        if (dialog.exec() != QDialog::Accepted)
        {
            return result;
        }

        result.accepted = true;
        result.operationMode = modeComboBox->currentIndex() == 0
            ? UnlockOperationMode::CloseHandleR3
            : (modeComboBox->currentIndex() == 2
                ? UnlockOperationMode::TerminateProcessR0
                : UnlockOperationMode::TerminateProcessR3);
        if (result.operationMode == UnlockOperationMode::CloseHandleR3)
        {
            result.selectedHandleList = collectSelectedHandles();
        }
        else
        {
            result.selectedProcessIdList = collectSelectedIds();
        }
        return result;
    }

    // 强制删除档要在展开每一层之前修权限，声明前置到这里，定义仍在多权限删除小节内。
    DWORD takeOwnershipAndGrantFullControl(
        const QString& path,
        bool isDirectory,
        QString* detailTextOut);
    bool clearDeleteBlockingAttributes(const QString& path);

    // appendDriverDeleteTargetsPostOrder：
    // - 作用：把目录展开成“子项先删、目录后删”的后序列表；
    // - 说明：重解析点目录不递归进入，只删除链接本身；
    // - repairPermissionBeforeEnumerate：强制删除档专用。目录 DACL 拒绝列举时
    //   entryInfoList 只会返回空列表，展开结果会把非空目录当成空目录，
    //   所以必须在枚举每一层之前先接管所有权并授权，否则后面删除必然失败。
    bool appendDriverDeleteTargetsPostOrder(
        const QString& rootPath,
        std::vector<DriverDeleteTarget>& targetsOut,
        QString& errorTextOut,
        const bool repairPermissionBeforeEnumerate = false)
    {
        const QFileInfo rootInfo(rootPath);
        const bool rootExists = rootInfo.exists() || rootInfo.isSymLink();
        if (!rootExists)
        {
            errorTextOut = QStringLiteral("路径不存在：%1").arg(QDir::toNativeSeparators(rootPath));
            return false;
        }

        const bool isDirectory = rootInfo.isDir();
        const bool isReparsePoint = isPathReparsePoint(rootPath);
        if (isDirectory && !isReparsePoint)
        {
            if (repairPermissionBeforeEnumerate)
            {
                QString repairDetailText;
                (void)takeOwnershipAndGrantFullControl(rootPath, true, &repairDetailText);
                (void)clearDeleteBlockingAttributes(rootPath);
            }

            const QFileInfoList childInfoList = QDir(rootPath).entryInfoList(
                QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System,
                QDir::DirsFirst | QDir::Name);
            for (const QFileInfo& childInfo : childInfoList)
            {
                if (!appendDriverDeleteTargetsPostOrder(
                        childInfo.absoluteFilePath(),
                        targetsOut,
                        errorTextOut,
                        repairPermissionBeforeEnumerate))
                {
                    return false;
                }
            }
        }

        targetsOut.push_back(DriverDeleteTarget{ rootPath, isDirectory });
        return true;
    }

    // ============================================================
    // 多权限递归删除（issue #155）
    // - 七个档位共用同一套“后序展开 + 逐项删除”的语义，差别只在权限/后端手段；
    // - R0 档优先让驱动在内核内部展开，避免 R3 枚举被目录 DACL 拒绝。
    // ============================================================

    // FileDeleteBatchStats：一批删除的统计与失败明细。
    struct FileDeleteBatchStats
    {
        std::uint64_t recycledCount = 0U;            // 成功移入回收站的项数。
        std::uint64_t deletedFileCount = 0U;         // 永久删除的文件数。
        std::uint64_t deletedDirectoryCount = 0U;    // 永久删除的目录数。
        std::uint64_t pendingRebootCount = 0U;       // 登记为重启后删除的项数。
        std::uint64_t failedCount = 0U;              // 失败项数。
        std::uint64_t skippedReparseCount = 0U;      // 只删链接本身、未跟进目标的重解析点数。
        std::uint64_t permissionRepairCount = 0U;    // 触发过“接管所有权 + 授权”的项数。
        bool driverUnavailable = false;              // R0 档：驱动设备打不开。
        bool driverRecursionUnsupported = false;     // R0 档：旧驱动不支持内核递归，已回退 R3 展开。
        QStringList errors;                          // 失败明细，用于日志与提示。
        QStringList permanentlyDeleted;              // 回收站档中被降级为永久删除的项。
    };

    // clearDeleteBlockingAttributes：
    // - 作用：清掉只读/隐藏/系统属性，这三者会直接让 DeleteFileW/RemoveDirectoryW 失败；
    // - 返回：true 表示属性已可删除（本来就正常也算成功）。
    bool clearDeleteBlockingAttributes(const QString& path)
    {
        const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        const DWORD attributes = ::GetFileAttributesW(nativePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            return false;
        }

        constexpr DWORD kBlockingAttributes =
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        if ((attributes & kBlockingAttributes) == 0U)
        {
            return true;
        }

        DWORD newAttributes = attributes & ~kBlockingAttributes;
        if (newAttributes == 0U)
        {
            newAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        return ::SetFileAttributesW(nativePath.c_str(), newAttributes) != FALSE;
    }

    // allocateBuiltinAdministratorsSid：
    // - 作用：构造 BUILTIN\Administrators（S-1-5-32-544）SID，调用方用 LocalFree 释放。
    PSID allocateBuiltinAdministratorsSid()
    {
        PSID administratorsSid = nullptr;
        if (::ConvertStringSidToSidW(L"S-1-5-32-544", &administratorsSid) == FALSE)
        {
            return nullptr;
        }
        return administratorsSid;
    }

    // takeOwnershipAndGrantFullControl：
    // - 作用：把目标的所有者改为 BUILTIN\Administrators，并追加一条完全控制 ACE；
    // - 说明：这是“强制删除”与 R3 兜底重试的权限手段，不改变文件内容；
    // - 返回：Win32 错误码，ERROR_SUCCESS 表示所有者与 DACL 都已写入。
    DWORD takeOwnershipAndGrantFullControl(
        const QString& path,
        const bool isDirectory,
        QString* const detailTextOut)
    {
        // 接管所有权需要 SeTakeOwnershipPrivilege；把所有者设成 Administrators 而不是
        // 当前账户还需要 SeRestorePrivilege，两者都只在管理员令牌里存在。
        (void)enableFileContextPrivilege(SE_TAKE_OWNERSHIP_NAME);
        (void)enableFileContextPrivilege(SE_RESTORE_NAME);
        (void)enableFileContextPrivilege(SE_BACKUP_NAME);
        (void)enableFileContextPrivilege(SE_SECURITY_NAME);

        PSID administratorsSid = allocateBuiltinAdministratorsSid();
        if (administratorsSid == nullptr)
        {
            const DWORD sidError = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatFileWin32Error(QStringLiteral("ConvertStringSidToSidW(S-1-5-32-544)"), sidError);
            }
            return sidError == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : sidError;
        }

        std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        DWORD ownerResult = ::SetNamedSecurityInfoW(
            nativePath.data(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            administratorsSid,
            nullptr,
            nullptr,
            nullptr);

        PACL oldDacl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        DWORD daclResult = ::GetNamedSecurityInfoW(
            nativePath.data(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &oldDacl,
            nullptr,
            &securityDescriptor);

        PACL newDacl = nullptr;
        if (daclResult == ERROR_SUCCESS)
        {
            EXPLICIT_ACCESS_W explicitAccess{};
            explicitAccess.grfAccessPermissions = FILE_ALL_ACCESS;
            explicitAccess.grfAccessMode = GRANT_ACCESS;
            // 目录让新 ACE 向下继承，这样后续枚举与逐项删除才不会再被子项的继承规则挡住。
            explicitAccess.grfInheritance = isDirectory
                ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
                : NO_INHERITANCE;
            explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            explicitAccess.Trustee.ptstrName = reinterpret_cast<LPWSTR>(administratorsSid);

            daclResult = ::SetEntriesInAclW(1, &explicitAccess, oldDacl, &newDacl);
            if (daclResult == ERROR_SUCCESS)
            {
                daclResult = ::SetNamedSecurityInfoW(
                    nativePath.data(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr,
                    nullptr,
                    newDacl,
                    nullptr);
            }
        }

        if (newDacl != nullptr)
        {
            ::LocalFree(newDacl);
        }
        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }
        ::LocalFree(administratorsSid);

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("takeOwner=%1, grantDacl=%2")
                .arg(ownerResult)
                .arg(daclResult);
        }

        if (ownerResult != ERROR_SUCCESS)
        {
            return ownerResult;
        }
        return daclResult;
    }

    // removeSinglePathByWin32：
    // - 作用：按目录/文件语义执行一次 Win32 删除；重解析点目录只删链接本身；
    // - 返回：true 表示已删除，失败时通过 lastErrorOut 输出 Win32 错误码。
    bool removeSinglePathByWin32(
        const QString& path,
        const bool isDirectory,
        DWORD* const lastErrorOut)
    {
        const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        const BOOL removeOk = isDirectory
            ? ::RemoveDirectoryW(nativePath.c_str())
            : ::DeleteFileW(nativePath.c_str());
        if (removeOk != FALSE)
        {
            return true;
        }

        if (lastErrorOut != nullptr)
        {
            *lastErrorOut = ::GetLastError();
        }
        return false;
    }

    // schedulePathDeleteOnReboot：
    // - 作用：把目标登记到 PendingFileRenameOperations，由会话管理器在下次启动时删除；
    // - 说明：需要管理员权限；目录必须在登记序列里排在其子项之后才能删成功。
    bool schedulePathDeleteOnReboot(const QString& path, DWORD* const lastErrorOut)
    {
        const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        if (::MoveFileExW(nativePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE)
        {
            return true;
        }

        if (lastErrorOut != nullptr)
        {
            *lastErrorOut = ::GetLastError();
        }
        return false;
    }

    // deleteExpandedTargetByR3：
    // - 输入：单个后序展开目标、是否允许提权修复；
    // - 处理：先清属性直删，失败且允许提权时接管所有权并授权后重试；
    // - 返回：true 表示已删除，失败时把可诊断的错误文本写入 errorTextOut。
    bool deleteExpandedTargetByR3(
        const DriverDeleteTarget& target,
        const bool allowPermissionRepair,
        bool* const permissionRepairedOut,
        QString* const errorTextOut)
    {
        if (permissionRepairedOut != nullptr)
        {
            *permissionRepairedOut = false;
        }

        (void)clearDeleteBlockingAttributes(target.path);

        DWORD lastError = ERROR_SUCCESS;
        if (removeSinglePathByWin32(target.path, target.isDirectory, &lastError))
        {
            return true;
        }

        if (!allowPermissionRepair)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除失败：%1（error=%2）")
                    .arg(QDir::toNativeSeparators(target.path))
                    .arg(lastError);
            }
            return false;
        }

        QString repairDetailText;
        const DWORD repairResult =
            takeOwnershipAndGrantFullControl(target.path, target.isDirectory, &repairDetailText);
        if (permissionRepairedOut != nullptr)
        {
            *permissionRepairedOut = true;
        }

        (void)clearDeleteBlockingAttributes(target.path);
        DWORD retryError = ERROR_SUCCESS;
        if (removeSinglePathByWin32(target.path, target.isDirectory, &retryError))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("强制删除失败：%1（首次 error=%2，接管所有权=%3[%4]，重试 error=%5）")
                .arg(QDir::toNativeSeparators(target.path))
                .arg(lastError)
                .arg(repairResult)
                .arg(repairDetailText)
                .arg(retryError);
        }
        return false;
    }

    // expandDeleteTargetsForBatch：
    // - 作用：把用户选中的路径展开成后序删除序列；
    // - 说明：强制删除档在枚举每一层之前接管所有权，否则目录拒绝列举时根本枚举不到子项。
    std::vector<DriverDeleteTarget> expandDeleteTargetsForBatch(
        const std::vector<QString>& paths,
        const bool repairPermissionWhileExpanding,
        FileDeleteBatchStats& statsInOut)
    {
        std::vector<DriverDeleteTarget> targets;
        for (const QString& path : paths)
        {
            if (repairPermissionWhileExpanding)
            {
                const QFileInfo rootInfo(path);
                QString repairDetailText;
                (void)takeOwnershipAndGrantFullControl(path, rootInfo.isDir(), &repairDetailText);
                (void)clearDeleteBlockingAttributes(path);
            }

            QString errorText;
            if (!appendDriverDeleteTargetsPostOrder(
                    path,
                    targets,
                    errorText,
                    repairPermissionWhileExpanding))
            {
                statsInOut.failedCount += 1U;
                statsInOut.errors.push_back(errorText);
            }
        }
        return targets;
    }

    // appendDriverDeleteFailureDetail：
    // - 作用：立即保存 R0 失败回执及现有解锁器入口提示；
    // - 说明：全系统占用诊断由用户按需触发，不能阻塞失败结果展示。
    void appendDriverDeleteFailureDetail(
        const bool isDirectory,
        const QString& baseDetailText,
        FileDeleteBatchStats& statsInOut)
    {
        QStringList errorLines;
        errorLines.push_back(baseDetailText);

        if (!isDirectory)
        {
            errorLines.push_back(
                QStringLiteral("可使用“文件解锁器”检查占用，或另行选择“重启后删除”；不会自动结束进程或关闭句柄。"));
        }

        statsInOut.errors.push_back(errorLines.join(QStringLiteral(" | ")));
    }

    // deleteTreeByDriverPerNode：
    // - 作用：旧驱动不支持内核递归时的回退路径，由 R3 展开后序序列逐项调用单点删除 IOCTL；
    // - 说明：这条路径受 R3 枚举权限限制，目录拒绝列举时会失败，属于预期降级。
    void deleteTreeByDriverPerNode(
        ksword::ark::DriverHandle& driverHandle,
        const QString& rootPath,
        FileDeleteBatchStats& statsInOut)
    {
        std::vector<DriverDeleteTarget> targets;
        QString expandErrorText;
        if (!appendDriverDeleteTargetsPostOrder(rootPath, targets, expandErrorText))
        {
            statsInOut.failedCount += 1U;
            statsInOut.errors.push_back(expandErrorText);
            return;
        }

        for (const DriverDeleteTarget& target : targets)
        {
            std::string detailText;
            if (deletePathByR0Driver(driverHandle, target.path, target.isDirectory, &detailText))
            {
                if (target.isDirectory)
                {
                    statsInOut.deletedDirectoryCount += 1U;
                }
                else
                {
                    statsInOut.deletedFileCount += 1U;
                }
                continue;
            }

            statsInOut.failedCount += 1U;
            appendDriverDeleteFailureDetail(
                target.isDirectory,
                QString::fromStdString(detailText),
                statsInOut);
        }
    }

    // describeDriverDeleteResponse：把 R0 统计响应转成一行可读诊断文本。
    QString describeDriverDeleteResponse(
        const QString& path,
        const ksword::ark::DeletePathResult& driverResult)
    {
        const KSWORD_ARK_DELETE_PATH_RESPONSE& response = driverResult.response;
        QString failedPathText;
        if (response.failedPathLengthChars > 0U)
        {
            failedPathText = QString::fromWCharArray(
                response.failedPath,
                static_cast<int>(response.failedPathLengthChars));
        }

        return QStringLiteral(
            "驱动删除未完成：%1（state=%2, files=%3, dirs=%4, failed=%5, visited=%6, depth=%7, "
            "responseFlags=0x%8, lastStatus=0x%9, firstFailed=%10）")
            .arg(QDir::toNativeSeparators(path))
            .arg(response.deleteStatus)
            .arg(response.deletedFileCount)
            .arg(response.deletedDirectoryCount)
            .arg(response.failedCount)
            .arg(response.visitedCount)
            .arg(response.maxDepthReached)
            .arg(response.responseFlags, 0, 16)
            .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(response.lastStatus)), 0, 16)
            .arg(failedPathText.isEmpty()
                ? QStringLiteral("-")
                : QDir::toNativeSeparators(failedPathText)) +
            (driverResult.responseV2
                ? QStringLiteral("（open=0x%1, disposition=0x%2, verify=0x%3, outcome=%4）")
                    .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(response.openStatus)), 0, 16)
                    .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(response.dispositionStatus)), 0, 16)
                    .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(response.verifyStatus)), 0, 16)
                    .arg(response.outcome)
                : QString());
    }

    // runDriverDeleteBatch：R0 档执行体。
    // - 目录优先交给驱动在内核内递归展开，这样目录 DACL 拒绝列举也能删干净；
    // - 仅底层方案可在旧驱动拒绝递归标志时回退 R3 展开；IRP/POSIX 必须安全失败，
    //   避免用户选中的后端被静默替换。
    FileDeleteBatchStats runDriverDeleteBatch(
        const std::vector<QString>& paths,
        const ksword::ark::FileDeleteBackend backend,
        const std::function<void(float)>& progressCallback)
    {
        FileDeleteBatchStats stats;

        std::string openDriverDetailText;
        ksword::ark::DriverHandle driverHandle = openKswordArkDriverHandle(&openDriverDetailText);
        if (!driverHandle.isValid())
        {
            stats.driverUnavailable = true;
            stats.failedCount += static_cast<std::uint64_t>(paths.size());
            stats.errors.push_back(
                QStringLiteral("无法连接 KswordARK 驱动设备：%1")
                    .arg(QString::fromStdString(openDriverDetailText)));
            return stats;
        }

        const ksword::ark::DriverClient driverClient;
        const std::size_t totalCount = paths.size();
        for (std::size_t index = 0; index < totalCount; ++index)
        {
            const QString& path = paths[index];
            const QFileInfo pathInfo(path);
            const bool isDirectory = pathInfo.isDir();
            const bool isReparsePointPath = isPathReparsePoint(path);
            const bool wantRecursive = isDirectory && !isReparsePointPath;
            if (backend == ksword::ark::FileDeleteBackend::IgnoreSharePosix && isDirectory)
            {
                stats.failedCount += 1U;
                stats.errors.push_back(QStringLiteral("共享检查增强模式只支持单文件：%1")
                    .arg(QDir::toNativeSeparators(path)));
                continue;
            }

            const QString driverNtPath = buildDriverNtPath(path);
            if (driverNtPath.isEmpty())
            {
                stats.failedCount += 1U;
                stats.errors.push_back(
                    QStringLiteral("NT 路径转换失败：%1").arg(QDir::toNativeSeparators(path)));
            }
            else
            {
                const auto deleteBeginTime = std::chrono::steady_clock::now();
                const ksword::ark::DeletePathResult driverResult = driverClient.deletePathEx(
                    driverHandle,
                    driverNtPath.toStdWString(),
                    isDirectory,
                    wantRecursive,
                    true,
                    backend);
                const auto ioElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - deleteBeginTime).count();
                {
                    kLogEvent event;
                    (driverResult.io.ok &&
                        driverResult.response.deleteStatus == KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED
                        ? dbg : warn) << event
                        << "[FileDock] R0 delete response, path="
                        << QDir::toNativeSeparators(path).toStdString()
                        << ", backend=" << static_cast<int>(backend)
                        << ", ioElapsedMs=" << ioElapsedMs
                        << ", ioOk=" << driverResult.io.ok
                        << ", responseV2=" << driverResult.responseV2
                        << eol;
                }

                if (driverResult.unsupported)
                {
                    if (backend == ksword::ark::FileDeleteBackend::Native)
                    {
                        stats.driverRecursionUnsupported = true;
                        deleteTreeByDriverPerNode(driverHandle, path, stats);
                    }
                    else
                    {
                        stats.failedCount += 1U;
                        const QString backendText =
                            backend == ksword::ark::FileDeleteBackend::Irp
                                ? QStringLiteral("IRP")
                                : (backend == ksword::ark::FileDeleteBackend::IgnoreSharePosix
                                    ? QStringLiteral("POSIX·忽略共享检查")
                                    : QStringLiteral("POSIX"));
                        stats.errors.push_back(QStringLiteral(
                            "当前 KswordARK 驱动不支持 R0 %1 删除后端，请重新部署本次构建的驱动：%2")
                            .arg(backendText)
                            .arg(QDir::toNativeSeparators(path)));
                    }
                }
                else if (!driverResult.io.ok)
                {
                    stats.failedCount += 1U;
                    appendDriverDeleteFailureDetail(
                        isDirectory,
                        QStringLiteral("驱动删除失败：%1（%2）")
                            .arg(QDir::toNativeSeparators(path))
                            .arg(QString::fromStdString(driverResult.io.message)),
                        stats);
                }
                else
                {
                    const KSWORD_ARK_DELETE_PATH_RESPONSE& response = driverResult.response;
                    if (!driverResult.responseV2)
                    {
                        stats.failedCount += 1U;
                        stats.errors.push_back(QStringLiteral("旧版驱动未提供路径移除复核结果，请部署新版驱动后确认：%1")
                            .arg(QDir::toNativeSeparators(path)));
                        continue;
                    }
                    stats.deletedFileCount += response.deletedFileCount;
                    stats.deletedDirectoryCount += response.deletedDirectoryCount;
                    stats.failedCount += response.failedCount;
                    stats.skippedReparseCount += response.skippedReparseCount;
                    if (response.deleteStatus != KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED)
                    {
                        if (response.failedCount == 0U)
                        {
                            // 限额截断这类情况本身没有失败节点，但结果并不完整，必须计一次失败。
                            stats.failedCount += 1U;
                        }
                        appendDriverDeleteFailureDetail(
                            isDirectory,
                            describeDriverDeleteResponse(path, driverResult),
                            stats);
                    }
                }
            }

            if (progressCallback)
            {
                progressCallback(
                    5.0f + (static_cast<float>(index + 1) / static_cast<float>(totalCount)) * 90.0f);
            }
        }

        driverHandle.reset();
        return stats;
    }

    // runFileDeleteBatch：
    // - 输入：选中路径集合、权限档位与进度回调；
    // - 处理：按档位选择删除手段，目录在任何一档都按后序序列处理；
    // - 返回：统计与失败明细，由 UI 线程汇总展示。
    FileDeleteBatchStats runFileDeleteBatch(
        const std::vector<QString>& paths,
        const FileDeleteMode mode,
        const std::function<void(float)>& progressCallback)
    {
        FileDeleteBatchStats stats;
        if (paths.empty())
        {
            return stats;
        }

        if (mode == FileDeleteMode::DriverR0Native)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::Native,
                progressCallback);
        }
        if (mode == FileDeleteMode::DriverR0Irp)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::Irp,
                progressCallback);
        }
        if (mode == FileDeleteMode::DriverR0Posix)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::Posix,
                progressCallback);
        }
        if (mode == FileDeleteMode::DriverR0IgnoreSharePosix)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::IgnoreSharePosix,
                progressCallback);
        }

        if (mode == FileDeleteMode::RecycleBin)
        {
            // QFile::moveToTrash 内部要用 Shell 的 IFileOperation，必须在本线程自备
            // COM 套间；RPC_E_CHANGED_MODE 表示已有套间，此时不能再配对 CoUninitialize。
            const HRESULT comInitResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            const bool comUninitializeNeeded = SUCCEEDED(comInitResult);

            const std::size_t totalCount = paths.size();
            for (std::size_t index = 0; index < totalCount; ++index)
            {
                const QString& path = paths[index];
                bool removeOk = QFile::moveToTrash(path);
                if (removeOk)
                {
                    stats.recycledCount += 1U;
                }
                else
                {
                    // 回收站不可用（网络位置、可移动磁盘、回收站停用等）时降级为永久删除，
                    // 这一步会改变可逆性，所以必须单独记账并在收尾时如实告诉用户。
                    const QFileInfo pathInfo(path);
                    if (pathInfo.isDir())
                    {
                        if (isPathReparsePoint(path))
                        {
                            removeOk = (::RemoveDirectoryW(
                                QDir::toNativeSeparators(path).toStdWString().c_str()) != FALSE);
                            if (removeOk)
                            {
                                stats.skippedReparseCount += 1U;
                            }
                        }
                        else
                        {
                            removeOk = QDir(path).removeRecursively();
                        }
                        if (removeOk)
                        {
                            stats.deletedDirectoryCount += 1U;
                        }
                    }
                    else
                    {
                        removeOk = QFile::remove(path);
                        if (removeOk)
                        {
                            stats.deletedFileCount += 1U;
                        }
                    }

                    if (removeOk)
                    {
                        stats.permanentlyDeleted.push_back(path);
                    }
                    else
                    {
                        stats.failedCount += 1U;
                        stats.errors.push_back(
                            QStringLiteral("删除失败：%1").arg(QDir::toNativeSeparators(path)));
                    }
                }

                if (progressCallback)
                {
                    progressCallback(
                        5.0f + (static_cast<float>(index + 1) / static_cast<float>(totalCount)) * 90.0f);
                }
            }

            if (comUninitializeNeeded)
            {
                ::CoUninitialize();
            }
            return stats;
        }

        const bool forceMode = (mode == FileDeleteMode::ForceR3);
        const bool pendingRebootMode = (mode == FileDeleteMode::PendingReboot);
        if (pendingRebootMode)
        {
            // 会话管理器在启动早期按登记顺序执行删除，写入这张表需要 SeRestorePrivilege。
            (void)enableFileContextPrivilege(SE_RESTORE_NAME);
            (void)enableFileContextPrivilege(SE_BACKUP_NAME);
        }

        const std::vector<DriverDeleteTarget> targets =
            expandDeleteTargetsForBatch(paths, forceMode, stats);
        const std::size_t totalTargetCount = targets.size();
        for (std::size_t index = 0; index < totalTargetCount; ++index)
        {
            const DriverDeleteTarget& target = targets[index];
            const bool targetIsReparsePoint = target.isDirectory && isPathReparsePoint(target.path);

            if (pendingRebootMode)
            {
                DWORD scheduleError = ERROR_SUCCESS;
                if (schedulePathDeleteOnReboot(target.path, &scheduleError))
                {
                    stats.pendingRebootCount += 1U;
                }
                else
                {
                    stats.failedCount += 1U;
                    stats.errors.push_back(
                        QStringLiteral("登记重启后删除失败：%1（error=%2）")
                            .arg(QDir::toNativeSeparators(target.path))
                            .arg(scheduleError));
                }
            }
            else
            {
                bool permissionRepaired = false;
                QString errorText;
                if (deleteExpandedTargetByR3(target, forceMode, &permissionRepaired, &errorText))
                {
                    if (target.isDirectory)
                    {
                        stats.deletedDirectoryCount += 1U;
                    }
                    else
                    {
                        stats.deletedFileCount += 1U;
                    }
                    if (targetIsReparsePoint)
                    {
                        stats.skippedReparseCount += 1U;
                    }
                }
                else
                {
                    stats.failedCount += 1U;
                    stats.errors.push_back(errorText);
                }

                if (permissionRepaired)
                {
                    stats.permissionRepairCount += 1U;
                }
            }

            if (progressCallback)
            {
                progressCallback(
                    5.0f + (static_cast<float>(index + 1) / static_cast<float>(totalTargetCount)) * 90.0f);
            }
        }

        return stats;
    }

    // 手动解析模型列定义：名称/大小/类型/修改时间/完整路径/是否目录。
    enum class ManualModelColumn : int
    {
        Name = 0,
        Size = 1,
        Type = 2,
        ModifiedTime = 3,
        FullPath = 4,
        IsDirectory = 5,
        Count = 6
    };

    // manualFsTypeToText 作用：手动解析结果类型转可读文本。
    QString manualFsTypeToText(const ks::file::ManualFsType fsType)
    {
        switch (fsType)
        {
        case ks::file::ManualFsType::Ntfs:
            return QStringLiteral("NTFS");
        case ks::file::ManualFsType::Fat32:
            return QStringLiteral("FAT32");
        case ks::file::ManualFsType::ExFat:
            return QStringLiteral("exFAT");
        default:
            return QStringLiteral("Unknown");
        }
    }

    template<class Value, class Enqueue>
    std::shared_ptr<Value> makeBackgroundRetiredValue(Enqueue enqueue)
    {
        return std::shared_ptr<Value>(new Value,
            [enqueue = std::move(enqueue)](Value* value) mutable {
                enqueue([value]() { delete value; });
            });
    }

    struct ManualDirectoryParsePayload
    {
        QDateTime sampledAt;
        std::vector<ks::file::ManualDirectoryEntry> entries;
        QStringList suspiciousNames;
        QSet<QString> suspiciousNameSet;
        QStringList retiredPanelNames;
    };

    // 直接发布后台枚举快照，避免在 UI 上为 N 行创建 6N 个 QStandardItem。
    // 类型/图标/时间等展示内容只为视图请求的单元格生成。
    class ManualDirectoryModel final : public QAbstractTableModel
    {
    public:
        using Entries = std::vector<ks::file::ManualDirectoryEntry>;

        explicit ManualDirectoryModel(std::function<QString(std::uint64_t)> sizeText,
            QObject* parent = nullptr)
            : QAbstractTableModel(parent), m_sizeText(std::move(sizeText)),
              m_directoryIcon(QApplication::style()->standardIcon(QStyle::SP_DirIcon)),
              m_fileIcon(QApplication::style()->standardIcon(QStyle::SP_FileIcon)),
              m_markers(this, [this](const QVector<QModelIndex>& changed) {
                  notifyFileVisualRows(this, changed, 2, 2, { Qt::DisplayRole, Qt::ToolTipRole });
              })
        {
        }

        void setSnapshot(std::shared_ptr<const Entries> entries, QSet<QString> suspiciousNames = {})
        {
            beginResetModel();
            auto retired = std::move(m_entries);
            auto retiredNames = std::move(m_suspiciousNames);
            m_entries = std::move(entries);
            m_suspiciousNames = std::move(suspiciousNames);
            m_markers.reset();
            endResetModel();
            if (retired || !retiredNames.isEmpty())
            {
                // 刷新大目录时，旧快照中大量字符串的销毁也放到后台。
                QThreadPool::globalInstance()->start(QRunnable::create(
                    [retired = std::move(retired), retiredNames = std::move(retiredNames)]() mutable {
                        retired.reset();
                        retiredNames.clear();
                    }));
            }
        }

        void setVisualDemand(const QVector<FileVisualDemand>& demand) { m_markers.setDemand(demand); }

        int rowCount(const QModelIndex& parent = {}) const override
        {
            return parent.isValid() || !m_entries ? 0 : static_cast<int>(
                std::min<std::size_t>(m_entries->size(), std::numeric_limits<int>::max()));
        }

        int columnCount(const QModelIndex& parent = {}) const override
        {
            return parent.isValid() ? 0 : static_cast<int>(ManualModelColumn::Count);
        }

        QVariant headerData(int section, Qt::Orientation orientation,
            int role = Qt::DisplayRole) const override
        {
            if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
            {
                static const QStringList headers{ QStringLiteral("名称"), QStringLiteral("大小"),
                    QStringLiteral("类型"), QStringLiteral("修改时间"),
                    QStringLiteral("完整路径"), QStringLiteral("目录标记") };
                return section >= 0 && section < headers.size()
                    ? QVariant(ks::i18n::displayText(headers[section])) : QVariant();
            }
            return QAbstractTableModel::headerData(section, orientation, role);
        }

        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
        {
            if (!index.isValid() || index.row() < 0 || index.row() >= rowCount())
            {
                return {};
            }
            const auto& entry = (*m_entries)[static_cast<std::size_t>(index.row())];
            const auto column = static_cast<ManualModelColumn>(index.column());
            if (role == Qt::UserRole + 1 && column == ManualModelColumn::Name)
                return entry.isDirectory;
            if (role == Qt::UserRole)
            {
                switch (column)
                {
                case ManualModelColumn::Name: return entry.absolutePath;
                case ManualModelColumn::Size: return QVariant::fromValue<qulonglong>(entry.sizeBytes);
                case ManualModelColumn::Type: return entry.typeText;
                case ManualModelColumn::ModifiedTime: return entry.modifiedTime;
                default: return {};
                }
            }
            if (role == Qt::DecorationRole && column == ManualModelColumn::Name)
                return entry.isDirectory ? m_directoryIcon : m_fileIcon;
            if ((role == Qt::BackgroundRole || role == Qt::ToolTipRole) &&
                m_suspiciousNames.contains(entry.name.toCaseFolded()))
            {
                if (role == Qt::ToolTipRole)
                    return ks::i18n::displayText(QStringLiteral(
                        "该条目只有绕过过滤层或直读 $MFT 才能看到，常规目录枚举视图中不存在。"));
                QColor highlightColor(KswordTheme::AccentHex(KswordTheme::AccentRole::Orange));
                highlightColor.setAlpha(72);
                return QBrush(highlightColor);
            }
            if (role != Qt::DisplayRole)
                return {};
            switch (column)
            {
            case ManualModelColumn::Name: return entry.name;
            case ManualModelColumn::Size:
                return entry.isDirectory ? QStringLiteral("-") : m_sizeText(entry.sizeBytes);
            case ManualModelColumn::Type:
            {
                const QString marker = m_markers.marker(entry.absolutePath);
                const QString typeText = ks::i18n::displayText(entry.typeText);
                return marker.isEmpty() ? typeText :
                    QStringLiteral("%1 / %2").arg(ks::i18n::displayText(marker), typeText);
            }
            case ManualModelColumn::ModifiedTime:
                return entry.modifiedTime.isValid()
                    ? entry.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                    : QStringLiteral("-");
            case ManualModelColumn::FullPath: return QDir::toNativeSeparators(entry.absolutePath);
            case ManualModelColumn::IsDirectory:
                return entry.isDirectory ? QStringLiteral("1") : QStringLiteral("0");
            default: return {};
            }
        }

    private:
        std::shared_ptr<const Entries> m_entries;
        QSet<QString> m_suspiciousNames;
        std::function<QString(std::uint64_t)> m_sizeText;
        QIcon m_directoryIcon;
        QIcon m_fileIcon;
        AsyncReparseMarkerCache m_markers;
    };

    // 原委托继续拥有绘制、编辑、提示和尺寸语义；观察器只接收 Qt 已选择的可见索引。
    class FileVisualDemandDelegate final : public QAbstractItemDelegate
    {
    public:
        FileVisualDemandDelegate(QAbstractItemDelegate* original, QObject* parent,
            std::function<void(const QModelIndex&, const QRect&)> painted)
            : QAbstractItemDelegate(parent), m_original(original), m_fallback(this),
              m_painted(std::move(painted))
        {
            for (QAbstractItemDelegate* delegate : { original, static_cast<QAbstractItemDelegate*>(&m_fallback) })
            {
                if (!delegate)
                    continue;
                connect(delegate, &QAbstractItemDelegate::commitData, this, &QAbstractItemDelegate::commitData);
                connect(delegate, &QAbstractItemDelegate::closeEditor, this, &QAbstractItemDelegate::closeEditor);
                connect(delegate, &QAbstractItemDelegate::sizeHintChanged, this, &QAbstractItemDelegate::sizeHintChanged);
            }
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            m_painted(index, option.rect);
            target()->paint(painter, option, index);
        }
        QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override
            { return target()->sizeHint(option, index); }
        QWidget* createEditor(QWidget* parent, const QStyleOptionViewItem& option, const QModelIndex& index) const override
            { return target()->createEditor(parent, option, index); }
        void destroyEditor(QWidget* editor, const QModelIndex& index) const override
            { target()->destroyEditor(editor, index); }
        void setEditorData(QWidget* editor, const QModelIndex& index) const override
            { target()->setEditorData(editor, index); }
        void setModelData(QWidget* editor, QAbstractItemModel* model, const QModelIndex& index) const override
            { target()->setModelData(editor, model, index); }
        void updateEditorGeometry(QWidget* editor, const QStyleOptionViewItem& option, const QModelIndex& index) const override
            { target()->updateEditorGeometry(editor, option, index); }
        bool editorEvent(QEvent* event, QAbstractItemModel* model,
            const QStyleOptionViewItem& option, const QModelIndex& index) override
            { return target()->editorEvent(event, model, option, index); }
        bool helpEvent(QHelpEvent* event, QAbstractItemView* view,
            const QStyleOptionViewItem& option, const QModelIndex& index) override
            { return target()->helpEvent(event, view, option, index); }
        QList<int> paintingRoles() const override { return target()->paintingRoles(); }
        bool eventFilter(QObject* object, QEvent* event) override
            { return static_cast<QObject*>(target())->eventFilter(object, event); }

    private:
        QAbstractItemDelegate* target() const { return m_original ? m_original.data() : &m_fallback; }
        QPointer<QAbstractItemDelegate> m_original;
        mutable QStyledItemDelegate m_fallback;
        std::function<void(const QModelIndex&, const QRect&)> m_painted;
    };

    // 每面板只观察自己的两种视图。复用 Qt 的可见项绘制，不额外扫描模型或强迫 Batched 布局。
    class FileVisualDemandScheduler final : public QObject
    {
    public:
        FileVisualDemandScheduler(QTreeView* tree, QListView* list,
            QSortFilterProxyModel* fsProxy, QSortFilterProxyModel* manualProxy, QObject* parent,
            std::function<void(const QVector<FileVisualDemand>&)> publish)
            : QObject(parent), m_publish(std::move(publish)), m_timer(this)
        {
            m_views[0].view = tree;
            m_views[1].view = list;
            m_timer.setSingleShot(true);
            connect(&m_timer, &QTimer::timeout, this, [this]() { publishDemand(); });
            for (auto& state : m_views)
            {
                auto* view = state.view.data();
                view->installEventFilter(this);
                view->viewport()->installEventFilter(this);
                connect(view->verticalScrollBar(), &QScrollBar::valueChanged, this, [this]() { invalidate(); });
                connect(view->horizontalScrollBar(), &QScrollBar::valueChanged, this, [this]() { invalidate(); });
                ensureDelegate(state);
            }
            connect(tree, &QTreeView::expanded, this, [this]() { invalidate(); });
            connect(tree, &QTreeView::collapsed, this, [this]() { invalidate(); });
            for (auto* proxy : { fsProxy, manualProxy })
            {
                connect(proxy, &QAbstractItemModel::modelReset, this, [this]() { invalidate(); });
                connect(proxy, &QAbstractItemModel::layoutChanged, this, [this]() { invalidate(); });
                connect(proxy, &QAbstractItemModel::rowsInserted, this, [this]() { invalidate(); });
                connect(proxy, &QAbstractItemModel::rowsRemoved, this, [this]() { invalidate(); });
            }
            connect(fsProxy, &QAbstractProxyModel::sourceModelChanged, this,
                [this, fsProxy]() { watchFileSystemSource(fsProxy); invalidate(); });
            watchFileSystemSource(fsProxy);
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event->type() == QEvent::Hide)
                invalidate(false); // 立即清需求；已开始的阻塞调用允许安全结束。
            else if (event->type() == QEvent::Show || event->type() == QEvent::Resize
                || event->type() == QEvent::LayoutRequest || event->type() == QEvent::FontChange)
                invalidate();
            else if (event->type() == QEvent::Paint)
            {
                for (auto& state : m_views)
                    if (state.view && watched == state.view->viewport())
                        ensureDelegate(state);
            }
            return false;
        }

    private:
        struct ViewState
        {
            QPointer<QAbstractItemView> view;
            QPointer<FileVisualDemandDelegate> delegate;
            QVector<FileVisualDemand> demand;
            QSet<QString> paths;
        };

        void watchFileSystemSource(QSortFilterProxyModel* proxy)
        {
            if (m_fsSource)
                disconnect(m_fsSource, nullptr, this, nullptr);
            m_fsSource = qobject_cast<QFileSystemModel*>(proxy->sourceModel());
            if (m_fsSource)
            {
                connect(m_fsSource, &QFileSystemModel::directoryLoaded, this, [this]() { invalidate(); });
                connect(m_fsSource, &QFileSystemModel::fileRenamed, this, [this]() { invalidate(); });
            }
        }

        void ensureDelegate(ViewState& state)
        {
            if (state.view->itemDelegate() == state.delegate && state.delegate)
                return;
            QPointer<FileVisualDemandScheduler> guard(this);
            QAbstractItemView* const view = state.view;
            auto* replacement = new FileVisualDemandDelegate(view->itemDelegate(), view,
                [guard, view](const QModelIndex& index, const QRect& rect) {
                    if (guard)
                        guard->observe(view, index, rect);
                });
            state.delegate = replacement;
            view->setItemDelegate(replacement);
        }

        void invalidate(const bool repaint = true)
        {
            bool hadDemand = false;
            for (auto& state : m_views)
            {
                hadDemand = hadDemand || !state.demand.isEmpty();
                state.demand.clear();
                state.paths.clear();
                // 滚动优化可能只重画露出的条带；需求重建必须覆盖当前完整视口。
                if (repaint && state.view && state.view->isVisible())
                    state.view->viewport()->update();
            }
            if (hadDemand)
                m_publish({});
            m_timer.stop();
        }

        void observe(QAbstractItemView* view, const QModelIndex& viewIndex, const QRect& rect)
        {
            if (!view->isVisible() || !rect.intersects(view->viewport()->rect()))
                return;
            ViewState& state = m_views[view == m_views[0].view ? 0 : 1];
            if (state.demand.size() >= FileVisualDemandLimit)
                return;
            QModelIndex source = viewIndex.siblingAtColumn(0);
            while (const auto* proxy = qobject_cast<const QAbstractProxyModel*>(source.model()))
                source = proxy->mapToSource(source);
            if (!source.isValid())
                return;
            const bool fs = qobject_cast<const QFileSystemModel*>(source.model()) != nullptr;
            const int pathRole = fs ? QFileSystemModel::FilePathRole : Qt::UserRole;
            const QString path = source.data(pathRole).toString();
            if (path.isEmpty() || state.paths.contains(path))
                return;
            state.paths.insert(path);
            state.demand.push_back({ path, QPersistentModelIndex(source), pathRole });
            if (!m_timer.isActive())
                m_timer.start(0);
        }

        void publishDemand()
        {
            for (const auto& state : m_views)
            {
                if (state.view && state.view->isVisible() && state.view->viewport()->isVisible())
                {
                    m_publish(state.demand);
                    return;
                }
            }
            m_publish({});
        }

        std::array<ViewState, 2> m_views;
        QPointer<QFileSystemModel> m_fsSource;
        std::function<void(const QVector<FileVisualDemand>&)> m_publish;
        QTimer m_timer;
    };

    // buildSuspiciousNameSet 作用：把疑似隐藏项名单折叠大小写后转成集合，
    // 避免在逐行回填时做 O(n) 线性查找。
    QSet<QString> buildSuspiciousNameSet(const QStringList& names,
        const ks::file::DirectoryCancellationCallback& canceled = {})
    {
        QSet<QString> nameSet;
        nameSet.reserve(names.size() + 8);
        for (const QString& nameText : names)
        {
            if (canceled && canceled()) break;
            nameSet.insert(nameText.toCaseFolded());
        }
        return nameSet;
    }

    // 统一按钮样式，保持与主界面蓝色主题一致。
    QString buildBlueButtonStyle()
    {
        return ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}");
    }

    // 统一输入控件样式。
    QString buildBlueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QTextEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus{"
            "  border:1px solid %1;}")
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            + KswordTheme::ThemedComboBoxStyle();
    }

    // buildContextMenuStyle 作用：
    // - 为 FileDock 文件列表右键菜单生成独立主题样式；
    // - 修复浅色主题下菜单背景错误保持黑色，导致文字不可见的问题。
    QString buildContextMenuStyle()
    {
        const QString disabledTextColor = KswordTheme::TextDisabledColorHex();

        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  padding:3px 16px 3px 12px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%6;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "  background:transparent;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:2px 6px;"
            "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(disabledTextColor)
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    void installFileTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installFileTableCopyMenu：
        // - 输入：FileDock 内临时弹窗或工具页表格；
        // - 处理：右键选中当前行，并把该行所有列按 TSV 复制到剪贴板；
        // - 返回：无。只读复制，不触发删除、恢复、关闭句柄等动作。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget, processIdColumn](const QPoint& localPosition)
        {
            const auto clickedIndex = tableWidget->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu menu(tableWidget);
            menu.setStyleSheet(buildContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            const QTableWidgetItem* processIdItem =
                processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() && tableWidget->currentRow() >= 0
                ? tableWidget->item(tableWidget->currentRow(), processIdColumn)
                : nullptr;
            bool processIdOk = false;
            const quint32 processId = processIdItem != nullptr
                ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && processId != 0U);
            }

            QAction* selectedAction = menu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int rowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList fields;
            fields.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                fields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(fields.join(QLatin1Char('\t')));
        });
    }

    // installFileTreeCopyMenu 作用：
    // - 输入 treeWidget：FileDock 内以树表展示的只读结果；
    // - 处理：右键选中当前行，并把该行所有列按 TSV 复制到剪贴板；
    // - 返回：无。只读复制，不执行解锁、关闭句柄、删除文件等动作。
    void installFileTreeCopyMenu(QTreeWidget* treeWidget, const int processIdColumn)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(treeWidget, &QTreeWidget::customContextMenuRequested, treeWidget, [treeWidget, processIdColumn](const QPoint& localPosition)
        {
            QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
            if (clickedItem != nullptr)
            {
                treeWidget->setCurrentItem(clickedItem);
            }

            QMenu menu(treeWidget);
            menu.setStyleSheet(buildContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            copyRowAction->setEnabled(treeWidget->currentItem() != nullptr);
            QTreeWidgetItem* const processIdItem = treeWidget->currentItem();
            bool processIdOk = false;
            const quint32 processId =
                processIdItem != nullptr && processIdColumn >= 0 && processIdColumn < treeWidget->columnCount()
                ? processIdItem->text(processIdColumn).trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            openProcessAction->setEnabled(processIdOk && processId != 0U);

            QAction* selectedAction = menu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            QTreeWidgetItem* currentItem = treeWidget->currentItem();
            if (clipboardObject == nullptr || currentItem == nullptr)
            {
                return;
            }

            QStringList fields;
            fields.reserve(treeWidget->columnCount());
            for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
            {
                fields.push_back(currentItem->text(columnIndex));
            }
            clipboardObject->setText(fields.join(QLatin1Char('\t')));
        });
    }

    // buildOpaqueStandaloneDialogStyle 作用：
    // - 为“独立弹窗”覆盖父级 Dock 透明样式，防止浅色主题下出现黑底；
    // - 强制编辑区/表格区使用 palette(base) 作为不透明背景。
    QString buildOpaqueStandaloneDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTabWidget::pane{"
            "  background-color:palette(window) !important;"
            "  border:1px solid palette(mid) !important;"
            "}"
            "QDialog#%1 QPlainTextEdit,"
            "QDialog#%1 QTextEdit,"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
    }

    // buildFileDetailDialogPalette：
    // - 为文件属性窗口建立与进程属性窗口相同的 Window/Surface/Base 分层；
    // - 显式设置 Base，避免 CodeEditor 和表格在不同主题下各自回退到系统颜色。
    QPalette buildFileDetailDialogPalette(const QWidget* const fallbackWidget)
    {
        QPalette palette = qApp != nullptr
            ? qApp->palette()
            : (fallbackWidget != nullptr ? fallbackWidget->palette() : QPalette());
        palette.setColor(QPalette::Window, KswordTheme::WindowColor());
        palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
        palette.setColor(QPalette::Button, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Mid, KswordTheme::BorderColor());
        palette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        palette.setColor(
            QPalette::HighlightedText,
            KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
        palette.setColor(QPalette::Disabled, QPalette::WindowText, KswordTheme::TextDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::Text, KswordTheme::TextDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, KswordTheme::TextDisabledColor());
        return palette;
    }

    // applyFileDetailSurfacePalette：
    // - 为独立窗口及其页面强制不透明 Surface；
    // - 防止透明子页露出 WindowColor，而编辑器/表格使用 Base 导致底色断层。
    void applyFileDetailSurfacePalette(QWidget* const widget, const QPalette& palette)
    {
        if (widget == nullptr)
        {
            return;
        }
        if (widget->palette() != palette)
        {
            widget->setPalette(palette); // 惰性页接入不再给所有已完成页面重复广播换肤事件。
        }
        widget->setAutoFillBackground(true);
        widget->setAttribute(Qt::WA_StyledBackground, true);
    }

    // buildFileDetailDialogStyle：
    // - 文件属性窗口复用进程属性的“Window 外层 + Surface 内容页 + 左侧导航”视觉层次；
    // - 所有可读文本容器、表头和滚动区域均显式使用 Surface，避免同窗内文字底色不一致。
    QString buildFileDetailDialogStyle()
    {
        return QStringLiteral(
            "QDialog#FileDetailDialogRoot{"
            "  background:%1;"
            "  color:%2;"
            "}"
            // GroupBox由共享DetailDialogChrome提供新版卡片结构，不再覆盖成框线标题。
            "QDialog#FileDetailDialogRoot QLineEdit,"
            "QDialog#FileDetailDialogRoot QPlainTextEdit,"
            "QDialog#FileDetailDialogRoot QTextEdit{"
            "  background:%8;"
            "  color:%2;"
            "  border:0;"
            "  border-radius:5px;"
            "  padding:0 6px;"
            "  selection-background-color:%5;"
            "  selection-color:%7;"
            "}"
            "QDialog#FileDetailDialogRoot QTableWidget,"
            "QDialog#FileDetailDialogRoot QTreeWidget{"
            "  background:%4;"
            "  alternate-background-color:%6;"
            "  color:%2;"
            "  border:none;"
            "  gridline-color:transparent;"
            "}"
            "QDialog#FileDetailDialogRoot QTableCornerButton::section,"
            "QDialog#FileDetailDialogRoot QHeaderView::section{"
            "  background:%4;"
            "  color:%2;"
            "  border:none;border-bottom:1px solid %3;"
            "  padding:4px;"
            "  font-weight:400;"
            "}"
            "QDialog#FileDetailDialogRoot QTabWidget::pane{"
            "  border:none;"
            "  background:%1;"
            "}"
            "QWidget#FileDetailTabNavigation{"
            "  background:%1;"
            "  border:none;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton{border-radius:7px;padding:8px;text-align:left;}"
            "QFrame#FileMetadataSaveBar{background:%1;border-top:1px solid %3;}"
            "QScrollArea#FileDetailNavigationScroll{background:%1;border:none;}"
            "QScrollArea#FileDetailNavigationScroll QWidget#qt_scrollarea_viewport{background:%1;}"
            "QDialog#FileDetailDialogRoot QPushButton{border-radius:5px;padding:0 10px;}"
            "QDialog#FileDetailDialogRoot QProgressBar{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  text-align:center;"
            "}"
            "QDialog#FileDetailDialogRoot QProgressBar::chunk{"
            "  background:%5;"
            "  border-radius:2px;"
            "}")
            .arg(KswordTheme::WindowColorHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::ControlAccentHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::OnAccentDynamicHex())
            .arg(KswordTheme::ControlInputSurfaceColor().name())
            + ks::ui::BuildDetailDialogChromeStyle(QStringLiteral("FileDetailDialogRoot"))
            // 文件详情只接管按钮，其他控件与导航几何继续保留原页面规则。
            + ks::ui::BuildFlatButtonStyle().replace(QStringLiteral("QPushButton"),
                QStringLiteral("QDialog#FileDetailDialogRoot QPushButton"))
                .replace(QStringLiteral("QToolButton"), QStringLiteral("QDialog#FileDetailDialogRoot QToolButton"));
    }

    // buildLogPreviewText 作用：
    // - 把多行结果压缩成单条日志预览文本，避免批量错误把日志面板刷满；
    // - 参数 sourceLines：原始明细文本集合；参数 maxLineCount：最多保留的行数；
    // - 返回：适合直接写入日志的 QString。
    QString buildLogPreviewText(const QStringList& sourceLines, const int maxLineCount = 8)
    {
        if (sourceLines.isEmpty())
        {
            return QStringLiteral("(空)");
        }

        QStringList previewLines;
        const int sourceLineCount = static_cast<int>(sourceLines.size());
        const int previewCount = sourceLineCount < maxLineCount
            ? sourceLineCount
            : maxLineCount;
        previewLines.reserve(previewCount + 1);
        for (int index = 0; index < previewCount; ++index)
        {
            previewLines.push_back(sourceLines[index]);
        }
        if (sourceLines.size() > previewCount)
        {
            previewLines.push_back(
                QStringLiteral("... 其余 %1 行省略").arg(sourceLines.size() - previewCount));
        }
        return previewLines.join(QStringLiteral("\n"));
    }

    // 面包屑按钮样式：视觉上“嵌入输入框”，并保留轻量 hover 提示。
    QString buildBreadcrumbButtonStyle()
    {
        // 路径段保留轻量尺寸，但使用可读纯色底面而非透明按钮。
        return ks::ui::BuildFlatButtonStyle()
            + QStringLiteral("QToolButton{padding:0 4px;border-radius:3px;}");
    }

    // 递归复制目录：用于跨面板复制目录场景。
    bool copyDirectoryRecursively(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        if (isPathReparsePoint(sourcePath))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                .arg(QDir::toNativeSeparators(sourcePath));
            return false;
        }

        QDir sourceDir(sourcePath);
        if (!sourceDir.exists())
        {
            errorTextOut = QStringLiteral("源目录不存在: %1").arg(sourcePath);
            return false;
        }

        QDir targetDir;
        if (!targetDir.mkpath(targetPath))
        {
            errorTextOut = QStringLiteral("创建目标目录失败: %1").arg(targetPath);
            return false;
        }

        const QFileInfoList entries = sourceDir.entryInfoList(
            QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System);
        for (const QFileInfo& info : entries)
        {
            const QString src = info.absoluteFilePath();
            const QString dst = QDir(targetPath).filePath(info.fileName());

            if (info.isSymLink() || isPathReparsePoint(src))
            {
                errorTextOut = ks::i18n::displayText(QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                    .arg(QDir::toNativeSeparators(src));
                return false;
            }

            if (info.isDir())
            {
                if (!copyDirectoryRecursively(src, dst, errorTextOut))
                {
                    return false;
                }
            }
            else
            {
                if (!QFile::copy(src, dst))
                {
                    errorTextOut = QStringLiteral("复制文件失败: %1 -> %2").arg(src, dst);
                    return false;
                }
            }
        }

        return true;
    }

    // copyFileTransactionally 作用：先写同目录临时文件，完整落盘后再替换目标；失败时保留旧目标。
    bool copyFileTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        QFile sourceFile(sourcePath);
        if (!sourceFile.open(QIODevice::ReadOnly))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("打开源文件失败: %1 (%2)"))
                .arg(sourcePath, sourceFile.errorString());
            return false;
        }

        QSaveFile targetFile(targetPath);
        // 禁止 direct-write fallback，避免临时文件创建失败时直接截断现有目标。
        targetFile.setDirectWriteFallback(false);
        if (!targetFile.open(QIODevice::WriteOnly))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("创建目标临时文件失败: %1 (%2)"))
                .arg(targetPath, targetFile.errorString());
            return false;
        }

        QByteArray copyBuffer(1024 * 1024, Qt::Uninitialized);
        while (true)
        {
            const qint64 bytesRead = sourceFile.read(copyBuffer.data(), copyBuffer.size());
            if (bytesRead < 0)
            {
                targetFile.cancelWriting();
                errorTextOut = ks::i18n::displayText(QStringLiteral("读取源文件失败: %1 (%2)"))
                    .arg(sourcePath, sourceFile.errorString());
                return false;
            }
            if (bytesRead == 0)
            {
                break;
            }
            if (targetFile.write(copyBuffer.data(), bytesRead) != bytesRead)
            {
                targetFile.cancelWriting();
                errorTextOut = ks::i18n::displayText(QStringLiteral("写入目标临时文件失败: %1 (%2)"))
                    .arg(targetPath, targetFile.errorString());
                return false;
            }
        }

        targetFile.setPermissions(QFileInfo(sourcePath).permissions());
        if (!targetFile.commit())
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("提交目标文件失败: %1 (%2)"))
                .arg(targetPath, targetFile.errorString());
            return false;
        }
        return true;
    }

    // uniqueSiblingTransactionPath 作用：为目录替换生成同卷临时路径，保证 rename 可回滚。
    QString uniqueSiblingTransactionPath(const QString& targetPath, const QString& roleText)
    {
        const QFileInfo targetInfo(targetPath);
        const QString transactionName = QStringLiteral("-ksword-%1-%2-%3")
            .arg(
                roleText,
                targetInfo.fileName(),
                QUuid::createUuid().toString(QUuid::WithoutBraces));
        return targetInfo.dir().filePath(transactionName);
    }

    // removeTransactionPath 作用：清理本次事务创建的文件或目录，不跟随其它目标路径。
    bool removeTransactionPath(const QString& path)
    {
        const QFileInfo pathInfo(path);
        if (!pathInfo.exists() && !pathInfo.isSymLink())
        {
            return true;
        }
        if (pathInfo.isDir() && !pathInfo.isSymLink())
        {
            return QDir(path).removeRecursively();
        }
        return QFile::remove(path);
    }

    // copyDirectoryTransactionally 作用：完整复制到同级 staging，再以 backup 回滚方式替换目标目录。
    bool copyDirectoryTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        const QString stagingPath = uniqueSiblingTransactionPath(targetPath, QStringLiteral("staging"));
        const QString backupPath = uniqueSiblingTransactionPath(targetPath, QStringLiteral("backup"));
        const bool targetExisted = QFileInfo::exists(targetPath);

        if (!copyDirectoryRecursively(sourcePath, stagingPath, errorTextOut))
        {
            removeTransactionPath(stagingPath);
            return false;
        }

        QDir renameDir;
        if (targetExisted && !renameDir.rename(targetPath, backupPath))
        {
            removeTransactionPath(stagingPath);
            errorTextOut = ks::i18n::displayText(QStringLiteral("备份现有目标目录失败: %1 -> %2"))
                .arg(targetPath, backupPath);
            return false;
        }

        if (!renameDir.rename(stagingPath, targetPath))
        {
            const bool rollbackOk = !targetExisted || renameDir.rename(backupPath, targetPath);
            removeTransactionPath(stagingPath);
            errorTextOut = rollbackOk
                ? ks::i18n::displayText(QStringLiteral("提交目标目录失败，旧目标已恢复: %1")).arg(targetPath)
                : ks::i18n::displayText(QStringLiteral("提交目标目录失败且旧目标恢复失败: %1，备份位于 %2"))
                    .arg(targetPath, backupPath);
            return false;
        }

        if (targetExisted && !removeTransactionPath(backupPath))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("目录已替换，但旧目标备份清理失败: %1"))
                .arg(backupPath);
            return false;
        }
        return true;
    }

    // runCommandCaptureText：
    // - 作用：同步执行 cmd 命令并返回标准输出/错误输出合并文本。
    // - 参数 commandText：传入 cmd /C 后执行的命令字符串。
    // - 参数 outputTextOut：返回执行输出文本，便于错误提示。
    // - 参数 exitCodeOut：返回进程退出码，调用方用于判断成功/失败。
    bool runCommandCaptureText(const QString& commandText, QString& outputTextOut, int& exitCodeOut)
    {
        QProcess process;
        process.setProgram(QStringLiteral("cmd.exe"));
        process.setArguments(QStringList{ QStringLiteral("/C"), commandText });
        process.start();
        process.waitForFinished(-1);

        const QByteArray stdOutBytes = process.readAllStandardOutput();
        const QByteArray stdErrBytes = process.readAllStandardError();
        outputTextOut = QString::fromLocal8Bit(stdOutBytes + stdErrBytes).trimmed();
        exitCodeOut = process.exitCode();
        return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    }

    // openCommandPromptInDirectory：
    // - 作用：用 Win32 CreateProcessW 显式创建一个新控制台 cmd.exe，并把工作目录设置为目标路径；
    // - 参数 workPath：要作为 cmd 当前目录的文件夹路径；会转换为 Windows 原生分隔符；
    // - 参数 errorCodeOut：返回 CreateProcessW 失败时的 GetLastError，成功时为 ERROR_SUCCESS；
    // - 返回：true 表示 cmd 进程已创建；false 表示创建失败。
    bool openCommandPromptInDirectory(const QString& workPath, DWORD* const errorCodeOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }

        const QString nativeWorkPath = QDir::toNativeSeparators(workPath);
        std::wstring commandLineText = L"cmd.exe /K";
        std::wstring currentDirectoryText = nativeWorkPath.toStdWString();
        if (currentDirectoryText.empty())
        {
            currentDirectoryText = QDir::toNativeSeparators(QDir::homePath()).toStdWString();
        }

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};

        const BOOL createOk = ::CreateProcessW(
            nullptr,
            commandLineText.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            currentDirectoryText.c_str(),
            &startupInfo,
            &processInfo);
        if (createOk == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        if (processInfo.hThread != nullptr)
        {
            ::CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            ::CloseHandle(processInfo.hProcess);
        }
        return true;
    }

    // takeOwnershipBySystemCommand：
    // - 作用：对目标路径执行 takeown 与 icacls，获取所有权并授权管理员组完全控制。
    // - 参数 targetPath：待处理文件/目录路径。
    // - 参数 detailTextOut：输出步骤详情（失败时用于提示）。
    // - 返回：全部步骤成功时返回 true。
    bool takeOwnershipBySystemCommand(const QString& targetPath, QString& detailTextOut)
    {
        const QFileInfo info(targetPath);
        const QString quotedPath = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(targetPath));
        const QString takeOwnCommand = info.isDir()
            ? QStringLiteral("takeown /F %1 /A /R /D Y").arg(quotedPath)
            : QStringLiteral("takeown /F %1 /A").arg(quotedPath);
        const QString grantCommand = info.isDir()
            ? QStringLiteral("icacls %1 /grant *S-1-5-32-544:F /T /C").arg(quotedPath)
            : QStringLiteral("icacls %1 /grant *S-1-5-32-544:F /C").arg(quotedPath);

        QString firstOutput;
        int firstExitCode = -1;
        const bool takeOwnOk = runCommandCaptureText(takeOwnCommand, firstOutput, firstExitCode);

        QString secondOutput;
        int secondExitCode = -1;
        const bool grantOk = runCommandCaptureText(grantCommand, secondOutput, secondExitCode);

        detailTextOut = QStringLiteral(
            "目标: %1\n"
            "takeown命令: %2\n"
            "takeown退出码: %3\n"
            "takeown输出:\n%4\n\n"
            "icacls命令: %5\n"
            "icacls退出码: %6\n"
            "icacls输出:\n%7")
            .arg(QDir::toNativeSeparators(targetPath))
            .arg(takeOwnCommand)
            .arg(firstExitCode)
            .arg(firstOutput.isEmpty() ? QStringLiteral("<无输出>") : firstOutput)
            .arg(grantCommand)
            .arg(secondExitCode)
            .arg(secondOutput.isEmpty() ? QStringLiteral("<无输出>") : secondOutput);
        return takeOwnOk && grantOk;
    }

    // sidUseToText 作用：
    // - 把 SID_NAME_USE 枚举转换为可读文本；
    // - 用于 ACL 列表中显示主体类型（用户/组/域等）。
    QString sidUseToText(const SID_NAME_USE sidUse)
    {
        switch (sidUse)
        {
        case SidTypeUser: return QStringLiteral("User");
        case SidTypeGroup: return QStringLiteral("Group");
        case SidTypeDomain: return QStringLiteral("Domain");
        case SidTypeAlias: return QStringLiteral("Alias");
        case SidTypeWellKnownGroup: return QStringLiteral("WellKnownGroup");
        case SidTypeDeletedAccount: return QStringLiteral("DeletedAccount");
        case SidTypeInvalid: return QStringLiteral("Invalid");
        case SidTypeUnknown: return QStringLiteral("Unknown");
        case SidTypeComputer: return QStringLiteral("Computer");
        case SidTypeLabel: return QStringLiteral("Label");
        default: return QStringLiteral("Other");
        }
    }

    // sidToStringText 作用：
    // - 把 PSID 转换为标准字符串形式（S-1-5-...）；
    // - 失败时返回包含错误信息的占位文本。
    QString sidToStringText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("<空SID>");
        }
        LPWSTR sidStringBuffer = nullptr;
        if (::ConvertSidToStringSidW(sidValue, &sidStringBuffer) == FALSE || sidStringBuffer == nullptr)
        {
            return QStringLiteral("<SID转换失败 code=%1>").arg(::GetLastError());
        }
        QString sidText = QString::fromWCharArray(sidStringBuffer);
        ::LocalFree(sidStringBuffer);
        return sidText;
    }

    // sidToAccountText 作用：
    // - 通过 LookupAccountSidW 解析 SID 的域名与账户名；
    // - 解析失败时保留错误码，便于权限审计定位。
    QString sidToAccountText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("<空SID>");
        }

        wchar_t accountBuffer[256] = {};
        wchar_t domainBuffer[256] = {};
        DWORD accountSize = static_cast<DWORD>(std::size(accountBuffer));
        DWORD domainSize = static_cast<DWORD>(std::size(domainBuffer));
        SID_NAME_USE sidUse = SidTypeUnknown;
        if (::LookupAccountSidW(
            nullptr,
            sidValue,
            accountBuffer,
            &accountSize,
            domainBuffer,
            &domainSize,
            &sidUse) == FALSE)
        {
            return QStringLiteral("<账户解析失败 code=%1>").arg(::GetLastError());
        }

        const QString accountText = QString::fromWCharArray(accountBuffer);
        const QString domainText = QString::fromWCharArray(domainBuffer);
        if (domainText.isEmpty())
        {
            return QStringLiteral("%1 (%2)").arg(accountText, sidUseToText(sidUse));
        }
        return QStringLiteral("%1\\%2 (%3)").arg(domainText, accountText, sidUseToText(sidUse));
    }

    // aceTypeToText 作用：
    // - 把 ACE_HEADER::AceType 转换为可读文本；
    // - 未覆盖类型保留原始数值，避免信息丢失。
    QString aceTypeToText(const BYTE aceType)
    {
        switch (aceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE: return QStringLiteral("ACCESS_ALLOWED");
        case ACCESS_DENIED_ACE_TYPE: return QStringLiteral("ACCESS_DENIED");
        case SYSTEM_AUDIT_ACE_TYPE: return QStringLiteral("SYSTEM_AUDIT");
        case SYSTEM_ALARM_ACE_TYPE: return QStringLiteral("SYSTEM_ALARM");
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE: return QStringLiteral("ACCESS_ALLOWED_OBJECT");
        case ACCESS_DENIED_OBJECT_ACE_TYPE: return QStringLiteral("ACCESS_DENIED_OBJECT");
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE: return QStringLiteral("SYSTEM_AUDIT_OBJECT");
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE: return QStringLiteral("MANDATORY_LABEL");
        default:
            return QStringLiteral("ACE_%1").arg(aceType);
        }
    }

    // aceFlagsToText 作用：
    // - 解析 ACE 继承/审计标志位；
    // - 返回以“|”分隔的复合文本。
    QString aceFlagsToText(const BYTE aceFlags)
    {
        QStringList flagList;
        if ((aceFlags & OBJECT_INHERIT_ACE) != 0) flagList << QStringLiteral("OBJECT_INHERIT");
        if ((aceFlags & CONTAINER_INHERIT_ACE) != 0) flagList << QStringLiteral("CONTAINER_INHERIT");
        if ((aceFlags & NO_PROPAGATE_INHERIT_ACE) != 0) flagList << QStringLiteral("NO_PROPAGATE");
        if ((aceFlags & INHERIT_ONLY_ACE) != 0) flagList << QStringLiteral("INHERIT_ONLY");
        if ((aceFlags & INHERITED_ACE) != 0) flagList << QStringLiteral("INHERITED");
        if ((aceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) != 0) flagList << QStringLiteral("AUDIT_SUCCESS");
        if ((aceFlags & FAILED_ACCESS_ACE_FLAG) != 0) flagList << QStringLiteral("AUDIT_FAIL");
        return flagList.isEmpty() ? QStringLiteral("None") : flagList.join('|');
    }

    // accessMaskToText 作用：
    // - 把文件系统访问掩码拆解为常见权限名；
    // - 既保留 GENERIC_*，也保留 FILE_* 细粒度权限。
    QString accessMaskToText(const DWORD accessMask)
    {
        QStringList rightList;
        if ((accessMask & GENERIC_ALL) != 0) rightList << QStringLiteral("GENERIC_ALL");
        if ((accessMask & GENERIC_READ) != 0) rightList << QStringLiteral("GENERIC_READ");
        if ((accessMask & GENERIC_WRITE) != 0) rightList << QStringLiteral("GENERIC_WRITE");
        if ((accessMask & GENERIC_EXECUTE) != 0) rightList << QStringLiteral("GENERIC_EXECUTE");
        if ((accessMask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) rightList << QStringLiteral("FILE_ALL_ACCESS");
        if ((accessMask & FILE_GENERIC_READ) == FILE_GENERIC_READ) rightList << QStringLiteral("FILE_GENERIC_READ");
        if ((accessMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) rightList << QStringLiteral("FILE_GENERIC_WRITE");
        if ((accessMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) rightList << QStringLiteral("FILE_GENERIC_EXECUTE");
        if ((accessMask & FILE_READ_DATA) != 0) rightList << QStringLiteral("READ_DATA");
        if ((accessMask & FILE_WRITE_DATA) != 0) rightList << QStringLiteral("WRITE_DATA");
        if ((accessMask & FILE_APPEND_DATA) != 0) rightList << QStringLiteral("APPEND_DATA");
        if ((accessMask & FILE_EXECUTE) != 0) rightList << QStringLiteral("EXECUTE");
        if ((accessMask & FILE_READ_ATTRIBUTES) != 0) rightList << QStringLiteral("READ_ATTRIBUTES");
        if ((accessMask & FILE_WRITE_ATTRIBUTES) != 0) rightList << QStringLiteral("WRITE_ATTRIBUTES");
        if ((accessMask & FILE_READ_EA) != 0) rightList << QStringLiteral("READ_EA");
        if ((accessMask & FILE_WRITE_EA) != 0) rightList << QStringLiteral("WRITE_EA");
        if ((accessMask & DELETE) != 0) rightList << QStringLiteral("DELETE");
        if ((accessMask & READ_CONTROL) != 0) rightList << QStringLiteral("READ_CONTROL");
        if ((accessMask & WRITE_DAC) != 0) rightList << QStringLiteral("WRITE_DAC");
        if ((accessMask & WRITE_OWNER) != 0) rightList << QStringLiteral("WRITE_OWNER");
        if ((accessMask & SYNCHRONIZE) != 0) rightList << QStringLiteral("SYNCHRONIZE");
        return rightList.isEmpty() ? QStringLiteral("None") : rightList.join('|');
    }

    struct FileSecurityAceRow
    {
        QString scopeText;       // scopeText：ACE 来源范围，当前主要为 DACL/SACL。
        QString typeText;        // typeText：ACE 类型文本，例如 ACCESS_ALLOWED。
        QString flagsText;       // flagsText：继承/审计标志文本。
        DWORD mask = 0;          // mask：原始访问掩码，用于显示和后续编辑定位。
        QString rightsText;      // rightsText：mask 拆解后的常见文件权限名。
        QString sidText;         // sidText：字符串 SID，便于稳定定位。
        QString accountText;     // accountText：LookupAccountSidW 解析出的账户名。
        DWORD aceIndex = 0;      // aceIndex：ACL 内 ACE 序号。
        bool canEdit = false;    // canEdit：当前 UI 是否允许对该 ACE 执行删除/替换。
    };

    struct FileSecuritySnapshot
    {
        bool descriptorOk = false;        // descriptorOk：Owner/Group/DACL 是否读取成功。
        bool saclOk = false;              // saclOk：SACL 是否读取成功。
        DWORD descriptorError = ERROR_SUCCESS; // descriptorError：读取 Owner/Group/DACL 的 Win32 错误码。
        DWORD saclError = ERROR_SUCCESS;       // saclError：读取 SACL 的 Win32 错误码。
        QString ownerSidText;             // ownerSidText：Owner SID 字符串。
        QString ownerAccountText;         // ownerAccountText：Owner 账户文本。
        QString groupSidText;             // groupSidText：Primary Group SID 字符串。
        QString groupAccountText;         // groupAccountText：Primary Group 账户文本。
        ks::ui::FieldDocument details; // 安全描述符的字段快照。
        std::vector<FileSecurityAceRow> aceRows; // aceRows：表格化 ACE 列表。
    };

    // appendAclRows：
    // - 输入 scopeText/aclValue：ACL 名称与 Windows ACL 指针。
    // - 处理：解析支持的 ACE 结构并转换为 UI 表格行；未知 ACE 仍进入文本明细。
    // - 返回：无，解析出的行追加到 rowsOut。
    void appendAclRows(const QString& scopeText, PACL aclValue, std::vector<FileSecurityAceRow>& rowsOut)
    {
        if (aclValue == nullptr)
        {
            return;
        }

        ACL_SIZE_INFORMATION aclSizeInfo{};
        if (::GetAclInformation(
            aclValue,
            &aclSizeInfo,
            static_cast<DWORD>(sizeof(aclSizeInfo)),
            AclSizeInformation) == FALSE)
        {
            return;
        }

        for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
        {
            LPVOID acePointer = nullptr;
            if (::GetAce(aclValue, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
            {
                continue;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            DWORD accessMask = 0;
            PSID aceSid = nullptr;
            bool editableAce = false;

            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                editableAce = scopeText == QStringLiteral("DACL") && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                break;
            }
            case ACCESS_DENIED_ACE_TYPE:
            {
                ACCESS_DENIED_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                editableAce = scopeText == QStringLiteral("DACL") && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                break;
            }
            case SYSTEM_AUDIT_ACE_TYPE:
            {
                SYSTEM_AUDIT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            {
                ACCESS_ALLOWED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
            {
                ACCESS_DENIED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            {
                SYSTEM_AUDIT_OBJECT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            default:
                break;
            }

            FileSecurityAceRow row;
            row.scopeText = scopeText;
            row.typeText = aceTypeToText(aceHeader->AceType);
            row.flagsText = aceFlagsToText(aceHeader->AceFlags);
            row.mask = accessMask;
            row.rightsText = accessMaskToText(accessMask);
            row.sidText = sidToStringText(aceSid);
            row.accountText = sidToAccountText(aceSid);
            row.aceIndex = aceIndex;
            row.canEdit = editableAce && aceSid != nullptr;
            rowsOut.push_back(row);
        }
    }

    // createReadonlyTableItem：
    // - 输入 cellText：待展示文本。
    // - 处理：创建不可编辑表格单元格，避免权限表误触编辑。
    // - 返回：新建 QTableWidgetItem，由表格接管生命周期。
    QTableWidgetItem* createReadonlyTableItem(const QString& cellText)
    {
        QTableWidgetItem* item = new QTableWidgetItem(cellText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // formatAccessMaskHex：
    // - 输入 accessMask：Win32 文件访问掩码。
    // - 处理：统一格式化为 8 位十六进制。
    // - 返回：0x 前缀大写文本。
    QString formatAccessMaskHex(const DWORD accessMask)
    {
        return QStringLiteral("0x%1")
            .arg(accessMask, 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // appendAclText 作用：
    // - 解析 ACL 中每一条 ACE，输出类型、标志、掩码、SID 与账户名；
    // - titleText 用于区分 DACL 与 SACL 段落。
    void appendAclDocument(const QString& titleText, PACL aclValue, ks::ui::FieldDocument& contentOut)
    {
        contentOut.section(titleText);
        if (aclValue == nullptr)
        {
            contentOut.field(QStringLiteral("ACL"), QStringLiteral("<null>"));
            return;
        }

        ACL_SIZE_INFORMATION aclSizeInfo{};
        if (::GetAclInformation(
            aclValue,
            &aclSizeInfo,
            static_cast<DWORD>(sizeof(aclSizeInfo)),
            AclSizeInformation) == FALSE)
        {
            contentOut.field(QStringLiteral("读取 ACL 信息失败"), QString::number(::GetLastError()));
            return;
        }

        contentOut.field(QStringLiteral("ACE数量"), QString::number(aclSizeInfo.AceCount));
        for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
        {
            LPVOID acePointer = nullptr;
            if (::GetAce(aclValue, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
            {
                contentOut.field(QStringLiteral("ACE[%1]").arg(aceIndex), QString::number(::GetLastError()));
                continue;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            DWORD accessMask = 0;
            PSID aceSid = nullptr;

            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_ACE_TYPE:
            {
                ACCESS_DENIED_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_ACE_TYPE:
            {
                SYSTEM_AUDIT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            {
                ACCESS_ALLOWED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
            {
                ACCESS_DENIED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            {
                SYSTEM_AUDIT_OBJECT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            default:
                break;
            }

            contentOut.section(QStringLiteral("%1 / ACE[%2]").arg(titleText).arg(aceIndex));
            contentOut.field(QStringLiteral("类型"), aceTypeToText(aceHeader->AceType));
            contentOut.field(QStringLiteral("标志"), aceFlagsToText(aceHeader->AceFlags));
            contentOut.field(QStringLiteral("Mask"), formatAccessMaskHex(accessMask));
            contentOut.field(QStringLiteral("权限"), accessMaskToText(accessMask));
            contentOut.field(QStringLiteral("SID"), sidToStringText(aceSid));
            contentOut.field(QStringLiteral("账户"), sidToAccountText(aceSid));
        }
    }

    // 简单文件详情对话框：按 Tab 展示通用/安全/哈希/签名/PE/字符串/十六进制。
    class FileDetailDialog final : public QDialog
    {
    public:
        explicit FileDetailDialog(
            const QString& filePath,
            QWidget* parent = nullptr,
            const QString& initialTabKey = QString())
            : FileDetailDialog(QStringList{ filePath }, parent, initialTabKey)
        {
        }

        explicit FileDetailDialog(
            const QStringList& filePaths,
            QWidget* parent = nullptr,
            const QString& initialTabKey = QString())
            : QDialog(parent)
            , m_filePaths(filePaths)
            , m_filePath(filePaths.value(0))
            , m_batchMode(filePaths.size() > 1)
            , m_initialTabKey(initialTabKey.trimmed().toLower())
        {
            // 文件属性拥有完整根主题，普通弹窗兜底只安装共享结构，不参与根配色竞争。
            setProperty("ksword_detail_theme_owner", true);
            QStringList normalizedPaths;
            QSet<QString> seenPaths;
            for (const QString& candidatePath : m_filePaths)
            {
                const QString normalizedPath = QDir::cleanPath(
                    QDir::toNativeSeparators(candidatePath.trimmed()));
                const QString identityKey = normalizedPath.toLower();
                if (!normalizedPath.isEmpty() && !seenPaths.contains(identityKey))
                {
                    seenPaths.insert(identityKey);
                    normalizedPaths.push_back(normalizedPath);
                }
            }
            m_filePaths = normalizedPaths;
            m_filePath = m_filePaths.value(0);
            m_batchMode = m_filePaths.size() > 1;
            m_hashCancelRequested = std::make_shared<std::atomic_bool>(false);
            m_usageScanCancelRequested = std::make_shared<std::atomic_bool>(false);
            // 文件属性与进程属性同为独立、非模态详情窗；不要继承隐藏 Dock 的子窗口外观。
            setWindowFlag(Qt::Window, true);
            setWindowModality(Qt::NonModal);
            setAttribute(Qt::WA_DeleteOnClose, true);
            setObjectName(QStringLiteral("FileDetailDialogRoot"));
            setWindowTitle(m_batchMode
                ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(m_filePaths.size())
                : QStringLiteral("文件属性 - %1").arg(QFileInfo(m_filePath).fileName()));
            ks::ui::applyResponsiveWindowGeometry(this, parent, QSize(1160, 800), QSize(640, 480));

            // 采用与进程属性相同的左侧导航结构：QTabWidget 继续承载现有懒加载逻辑，
            // 仅隐藏原生顶栏并改由可翻译的垂直导航按钮驱动。
            QVBoxLayout* dialogLayout = new QVBoxLayout(this);
            dialogLayout->setContentsMargins(0, 0, 0, 0);
            dialogLayout->setSpacing(0);
            // 对象摘要属于整个详情窗口，不再只塞在常规信息页中。
            dialogLayout->addWidget(buildIdentityHeader());
            QHBoxLayout* rootLayout = new QHBoxLayout();
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->setSpacing(0);
            dialogLayout->addLayout(rootLayout, 1);

            m_tabNavigation = new QWidget(this);
            m_tabNavigation->setObjectName(QStringLiteral("FileDetailTabNavigation"));
            QVBoxLayout* navigationLayout = new QVBoxLayout(m_tabNavigation);
            navigationLayout->setContentsMargins(10, 16, 10, 16);
            navigationLayout->setSpacing(5);

            QScrollArea* navigationScroll = new QScrollArea(this);
            navigationScroll->setObjectName(QStringLiteral("FileDetailNavigationScroll"));
            navigationScroll->setWidgetResizable(true);
            navigationScroll->setFrameShape(QFrame::NoFrame);
            navigationScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            navigationScroll->setWidget(m_tabNavigation);
            ks::ui::ConfigureDetailNavigation(navigationScroll, m_tabNavigation);

            m_tabWidget = new QTabWidget(this);
            // 已由文件详情的分组侧栏管理，共享框架不得再给同一个Tab套第二个导航壳。
            m_tabWidget->setProperty("ksword_detail_tabs", true);
            m_tabWidget->setMinimumSize(0, 0);
            m_tabWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
            if (auto* pageStack = m_tabWidget->findChild<QStackedWidget*>())
            {
                pageStack->setMinimumSize(0, 0);
                pageStack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
            }
            m_tabWidget->tabBar()->hide();
            m_tabNavigationButtonGroup = new QButtonGroup(this);
            m_tabNavigationButtonGroup->setExclusive(true);
            rootLayout->addWidget(navigationScroll);
            rootLayout->addWidget(m_tabWidget, 1);

            m_tabWidget->addTab(buildGeneralTab(), QStringLiteral("常规信息"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("metadata")), QStringLiteral("元数据编辑"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("reparse")), QStringLiteral("重解析点 / 符号链接"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("security")), QStringLiteral("安全与权限"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("hash")), QStringLiteral("哈希与完整性"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("usage")), QStringLiteral("文件占用与解锁"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("fileobject")), QStringLiteral("FileObject / Section / ControlArea"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("storage")), QStringLiteral("Storage / MountMgr / FVE"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("filters")), QStringLiteral("Minifilter / Instance / Volume"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("signature")), QStringLiteral("数字签名"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("pe")), QStringLiteral("PE信息"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("dependencies")), QStringLiteral("依赖 DLL"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("strings")), QStringLiteral("字符串"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("hex")), QStringLiteral("十六进制"));
            // addTab 会让 Qt 重新显示 tabBar，必须在页面齐备后再次隐藏。
            m_tabWidget->tabBar()->hide();

            const QList<QPair<QString, QString>> detailTabTranslations{
                {QStringLiteral("file.detail.tab.general"), QStringLiteral("常规信息")},
                {QStringLiteral("file.detail.tab.metadata"), QStringLiteral("元数据编辑")},
                {QStringLiteral("file.detail.tab.reparse"), QStringLiteral("重解析点 / 符号链接")},
                {QStringLiteral("file.detail.tab.security"), QStringLiteral("安全与权限")},
                {QStringLiteral("file.detail.tab.hash"), QStringLiteral("哈希与完整性")},
                {QStringLiteral("file.detail.tab.usage"), QStringLiteral("文件占用与解锁")},
                {QStringLiteral("file.detail.tab.fileobject"), QStringLiteral("FileObject / Section / ControlArea")},
                {QStringLiteral("file.detail.tab.storage"), QStringLiteral("Storage / MountMgr / FVE")},
                {QStringLiteral("file.detail.tab.filters"), QStringLiteral("Minifilter / Instance / Volume")},
                {QStringLiteral("file.detail.tab.signature"), QStringLiteral("数字签名")},
                {QStringLiteral("file.detail.tab.pe"), QStringLiteral("PE信息")},
                {QStringLiteral("file.detail.tab.dependencies"), QStringLiteral("依赖 DLL")},
                {QStringLiteral("file.detail.tab.strings"), QStringLiteral("字符串")},
                {QStringLiteral("file.detail.tab.hex"), QStringLiteral("十六进制")}
            };
            for (int tabIndex = 0; tabIndex < detailTabTranslations.size(); ++tabIndex)
            {
                const auto& translation = detailTabTranslations.at(tabIndex);
                ks::i18n::LanguageManager::instance().bindTab(
                    m_tabWidget,
                    m_tabWidget->widget(tabIndex),
                    translation.first,
                    translation.second);
            }

            const QList<QString> navigationIconPathList{
                QStringLiteral(":/Icon/process_details.svg"),
                QStringLiteral(":/Icon/process_copy_cell.svg"),
                QStringLiteral(":/Icon/file_nav_forward.svg"),
                QStringLiteral(":/Icon/file_owner.svg"),
                QStringLiteral(":/Icon/process_performance.svg"),
                QStringLiteral(":/Icon/process_main.svg"),
                QStringLiteral(":/Icon/process_details.svg"),
                QStringLiteral(":/Icon/disk_storage.svg"),
                QStringLiteral(":/Icon/filter_funnel.svg"),
                QStringLiteral(":/Icon/process_critical.svg"),
                QStringLiteral(":/Icon/process_list.svg"),
                QStringLiteral(":/Icon/process_copy_row.svg"),
                QStringLiteral(":/Icon/file_find.svg"),
                QStringLiteral(":/Icon/process_copy_cell.svg")
            };
            for (int tabIndex = 0; tabIndex < detailTabTranslations.size(); ++tabIndex)
            {
                const auto& translation = detailTabTranslations.at(tabIndex);
                QToolButton* navigationButton = new QToolButton(m_tabNavigation);
                // 单按钮绑定优先于详情壳的高特异性侧栏QSS，保证普通态也有纯色底。
                ks::ui::ApplyDetailNavigationButtonTheme(navigationButton);
                navigationButton->setCheckable(true);
                navigationButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
                navigationButton->setIcon(QIcon(navigationIconPathList.value(tabIndex)));
                navigationButton->setIconSize(QSize(18, 18));
                navigationButton->setMinimumHeight(38);
                navigationButton->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
                ks::i18n::LanguageManager::instance().bindText(
                    navigationButton,
                    translation.first,
                    translation.second);
                ks::i18n::LanguageManager::instance().bindToolTip(
                    navigationButton,
                    translation.first,
                    translation.second);
                m_tabNavigationButtonGroup->addButton(navigationButton, tabIndex);
                m_tabNavigationButtons.push_back(navigationButton);
                navigationLayout->addWidget(navigationButton);
                connect(navigationButton, &QToolButton::clicked, this, [this, tabIndex]()
                    {
                        if (m_tabWidget != nullptr)
                        {
                            m_tabWidget->setCurrentIndex(tabIndex);
                        }
                    });
            }
            if (m_batchMode)
            {
                const QSet<int> batchEnabledTabs{ 0, 1, 4 };
                for (int tabIndex = 0; tabIndex < m_tabNavigationButtons.size(); ++tabIndex)
                {
                    QToolButton* const navigationButton = m_tabNavigationButtons.at(tabIndex);
                    if (navigationButton == nullptr || batchEnabledTabs.contains(tabIndex))
                    {
                        continue;
                    }
                    navigationButton->setEnabled(false);
                    m_tabWidget->setTabEnabled(tabIndex, false);
                    navigationButton->setToolTip(ks::i18n::sourceText(QStringLiteral(
                        "批量模式下此分析页不可用。请只选择一个目标后打开该页。")));
                }
                QLabel* batchHintLabel = new QLabel(
                    ks::i18n::sourceText(QStringLiteral(
                        "批量模式：常规信息显示汇总，哈希与元数据编辑支持批量处理；其余单文件分析页已禁用。")),
                    m_tabNavigation);
                batchHintLabel->setWordWrap(true);
                batchHintLabel->setObjectName(QStringLiteral("FileDetailBatchHint"));
                navigationLayout->addWidget(batchHintLabel);
            }
            navigationLayout->addStretch(1);
            // 文件信息、可信度、内容、内核链路与写操作分组，点击仍按原 Tab 索引路由。
            using NavKind = ks::ui::DetailNavigationKind;
            ks::ui::SetDetailTabGroups(m_tabWidget, {
                {NavKind::General, {0, 2}}, {NavKind::Security, {3, 4, 9}},
                {NavKind::Content, {10, 11, 12, 13}}, {NavKind::Internals, {6, 7, 8}},
                {NavKind::Interaction, {1, 5}}});
            ks::ui::ArrangeDetailNavigationGroups(m_tabNavigation, m_tabWidget, m_tabNavigationButtonGroup);

            QFrame* saveBar = new QFrame(this);
            saveBar->setObjectName(QStringLiteral("FileMetadataSaveBar"));
            QHBoxLayout* saveLayout = new QHBoxLayout(saveBar);
            saveLayout->setContentsMargins(8, 6, 8, 6);
            m_backupBeforeSaveCheck = new QCheckBox(
                ks::i18n::sourceText(QStringLiteral("创建备份再修改")), saveBar);
            m_backupBeforeSaveCheck->setChecked(true);
            m_pendingChangesLabel = new QLabel(
                ks::i18n::sourceText(QStringLiteral("● 暂无待保存修改")), saveBar);
            m_pendingChangesLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            m_discardPendingButton = new QPushButton(
                ks::i18n::sourceText(QStringLiteral("放弃暂存")), saveBar);
            m_saveAllButton = new QPushButton(
                ks::i18n::sourceText(QStringLiteral("保存全部修改")), saveBar);
            m_saveAllButton->setDefault(true);
            m_discardPendingButton->setEnabled(false);
            m_saveAllButton->setEnabled(false);
            saveLayout->addWidget(m_backupBeforeSaveCheck);
            saveLayout->addWidget(m_pendingChangesLabel, 1);
            saveLayout->addWidget(m_discardPendingButton);
            saveLayout->addWidget(m_saveAllButton);
            QPushButton* closeButton = new QPushButton(ks::i18n::sourceText(QStringLiteral("关闭")), saveBar);
            saveLayout->addWidget(closeButton);
            ks::ui::NormalizeToolbarRow(saveLayout);
            connect(closeButton, &QPushButton::clicked, this, &QWidget::close);
            dialogLayout->addWidget(saveBar, 0);
            connect(m_discardPendingButton, &QPushButton::clicked, this,
                [this]() { discardPendingChanges(); });
            connect(m_saveAllButton, &QPushButton::clicked, this,
                [this]() { saveAllPendingChanges(); });

            connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](const int tabIndex)
                {
                    if (tabIndex >= 0 && tabIndex < m_tabNavigationButtons.size())
                    {
                        QToolButton* const navigationButton = m_tabNavigationButtons.at(tabIndex);
                        if (navigationButton != nullptr)
                        {
                            navigationButton->setChecked(true);
                        }
                    }
                    activateDeferredTab(m_tabWidget, tabIndex);
                });
            const int initialTabIndex = m_initialTabKey == QStringLiteral("usage") ? 5
                : m_initialTabKey == QStringLiteral("pe") ? 10
                : m_initialTabKey == QStringLiteral("hex") ? 13 : -1;
            if (initialTabIndex >= 0)
            {
                m_tabWidget->setCurrentIndex(initialTabIndex);
            }
            else if (!m_tabNavigationButtons.isEmpty())
            {
                m_tabNavigationButtons.front()->setChecked(true);
            }
            ks::ui::ConfigureDetailDialogRoot(this);
            // 统一框架接管真实页面与后续懒加载子控件，业务仍保留原 Tab 和异步数据源。
            ks::ui::InstallDetailWindowFramework(this);
            applyThemeStyle();
        }

        ~FileDetailDialog() override
        {
            // 关闭即销毁的属性窗不能留下继续跑全系统枚举的任务；两个后台入口
            // 都只共享原子取消标记，不在析构线程等待，也不访问已经释放的控件。
            if (m_hashCancelRequested != nullptr)
            {
                m_hashCancelRequested->store(true);
            }
            if (m_savePreflightCancel != nullptr) m_savePreflightCancel->store(true);
            if (m_generalReadCancel != nullptr) m_generalReadCancel->store(true);
            if (m_stagingSnapshotCancel != nullptr) m_stagingSnapshotCancel->store(true);
            if (m_peReadCancel) m_peReadCancel->store(true);
            if (m_dependencyReadCancel) m_dependencyReadCancel->store(true);
            for (const auto& state : m_metadataReadStates)
                if (state != nullptr && state->cancel != nullptr) state->cancel->store(true);
            if (m_usageScanCancelRequested != nullptr)
            {
                m_usageScanCancelRequested->store(true);
            }
        }

    protected:
        void closeEvent(QCloseEvent* event) override
        {
            if (event == nullptr)
            {
                return;
            }
            if (m_transactionBusy && m_savePreflightCancel == nullptr)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("正在保存文件元数据")),
                    ks::i18n::sourceText(QStringLiteral(
                        "保存事务仍在运行。请等待逐操作结果返回后再关闭窗口。")));
                event->ignore();
                return;
            }
            if (m_savePreflightCancel != nullptr) m_savePreflightCancel->store(true);
            if (pendingTargetCount() > 0)
            {
                const QMessageBox::StandardButton choice = QMessageBox::question(
                    this,
                    ks::i18n::sourceText(QStringLiteral("放弃暂存修改")),
                    ks::i18n::sourceText(QStringLiteral(
                        "仍有尚未写入的暂存修改。关闭窗口将放弃这些修改，文件不会变化。是否关闭？")),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No);
                if (choice != QMessageBox::Yes)
                {
                    event->ignore();
                    return;
                }
            }
            QDialog::closeEvent(event);
        }

        void changeEvent(QEvent* event) override
        {
            QDialog::changeEvent(event);
            if (event == nullptr || m_themeStyleApplying)
            {
                return;
            }
            if (event->type() == QEvent::LanguageChange)
            {
                setWindowTitle(m_batchMode
                    ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(m_filePaths.size())
                    : ks::i18n::displayText(QStringLiteral("文件属性 - %1"))
                        .arg(QFileInfo(m_filePath).fileName()));
                refreshGeneralTab();
                if (m_signatureLanguageRefresh) m_signatureLanguageRefresh();
                return;
            }
            if (event->type() == QEvent::ApplicationPaletteChange ||
                event->type() == QEvent::PaletteChange)
            {
                applyThemeStyle();
            }
        }

    private:
        void applyThemeStyle()
        {
            if (m_themeStyleApplying)
            {
                return;
            }
            QScopedValueRollback<bool> applying(m_themeStyleApplying, true); // 根主题事件重入只执行一轮。

            const QPalette dialogPalette = buildFileDetailDialogPalette(this);
            QPalette surfacePalette = dialogPalette;
            // 页根保持窗口底色，只有明确卡片使用 Surface，防止滚动区再抬亮整块背景。
            surfacePalette.setColor(QPalette::Window, KswordTheme::WindowColor());
            surfacePalette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
            applyFileDetailSurfacePalette(this, dialogPalette);
            const QString style = buildFileDetailDialogStyle();
            if (styleSheet() != style)
            {
                setStyleSheet(style);
            }

            QPalette navigationPalette = surfacePalette;
            navigationPalette.setColor(QPalette::Window, KswordTheme::WindowColor());
            applyFileDetailSurfacePalette(m_tabNavigation, navigationPalette);
            applyFileDetailSurfacePalette(m_tabWidget, surfacePalette);
            if (m_tabWidget != nullptr)
            {
                for (int tabIndex = 0; tabIndex < m_tabWidget->count(); ++tabIndex)
                {
                    applyFileDetailSurfacePalette(m_tabWidget->widget(tabIndex), surfacePalette);
                }
            }

        }

        struct HashCalculationResult
        {
            bool openOk = false;       // openOk：文件是否成功打开。
            bool cancelled = false;    // cancelled：用户是否取消。
            qint64 totalBytes = 0;     // totalBytes：文件总大小。
            qint64 readBytes = 0;      // readBytes：实际读取字节数。
            qint64 elapsedMs = 0;      // elapsedMs：耗时毫秒。
            QStringList hashValues;     // hashValues：按 commonHashNames 顺序排列的摘要。
            QFileDevice::FileError fileError = QFileDevice::NoError; // fileError：稳定、与系统 UI 语言无关的错误码。
        };

        // 所有算法共享同一轮分块读取；单文件与批量页面使用同一组算法。
        static QStringList commonHashNames()
        {
            return {QStringLiteral("MD5"), QStringLiteral("SHA-1"),
                QStringLiteral("SHA-224"), QStringLiteral("SHA-256"),
                QStringLiteral("SHA-384"), QStringLiteral("SHA-512"),
                QStringLiteral("SHA3-256"), QStringLiteral("BLAKE2b-512")};
        }

        struct CommonFileHashes
        {
            std::vector<std::unique_ptr<QCryptographicHash>> hashes;

            CommonFileHashes()
            {
                constexpr std::array<QCryptographicHash::Algorithm, 8> algorithms{
                    QCryptographicHash::Md5, QCryptographicHash::Sha1,
                    QCryptographicHash::Sha224, QCryptographicHash::Sha256,
                    QCryptographicHash::Sha384, QCryptographicHash::Sha512,
                    QCryptographicHash::RealSha3_256, QCryptographicHash::Blake2b_512};
                for (const auto algorithm : algorithms)
                    hashes.push_back(QCryptographicHash::supportsAlgorithm(algorithm)
                        ? std::make_unique<QCryptographicHash>(algorithm) : nullptr);
            }

            void addData(const QByteArray& bytes)
            {
                for (const auto& hash : hashes)
                    if (hash != nullptr) hash->addData(bytes);
            }

            QStringList results() const
            {
                QStringList values;
                for (const auto& hash : hashes)
                    values.append(hash != nullptr
                        ? QString::fromLatin1(hash->result().toHex())
                        : ks::i18n::sourceText(QStringLiteral("算法不可用")));
                return values;
            }
        };

        struct PrintableStringMatch
        {
            qint64 offset = 0;
            QString encoding;
            QString text;
        };

        struct PrintableStringsPreview
        {
            QVector<PrintableStringMatch> matches;
            qint64 matchedCount = 0;
            qint64 scannedBytes = 0;
            qint64 fileBytes = 0;
            bool cancelled = false;
            QString errorText;
        };

        struct StringScanControl
        {
            quint64 generation = 0;
            std::shared_ptr<std::atomic_bool> cancel;
        };

        struct FileMetadataSnapshot
        {
            bool ok = false;                 // ok：是否成功打开目标并读取 FileBasicInfo。
            DWORD win32Error = ERROR_SUCCESS; // win32Error：失败步骤的 Win32 错误码。
            FILE_BASIC_INFO basicInfo{};     // basicInfo：四个时间戳与完整属性位快照。
            bool identityAvailable = false;  // identityAvailable：卷序列号与文件索引是否可用于复核。
            DWORD volumeSerialNumber = 0U;   // volumeSerialNumber：文件所在卷身份。
            std::uint64_t fileIndex = 0U;    // fileIndex：同一卷内稳定文件身份。
        };

        struct FileMetadataUpdateRequest
        {
            std::array<bool, 4> updateTime{};       // updateTime：逐项决定是否写入对应时间。
            std::array<LARGE_INTEGER, 4> timeValue{}; // timeValue：本地编辑值转换后的 FILETIME 100ns。
            bool updateAttributes = false;         // updateAttributes：可编辑属性位是否发生变化。
            DWORD editableAttributes = 0U;         // editableAttributes：六个允许编辑的属性位。
            bool validateIdentity = false;         // validateIdentity：写入前是否必须匹配初始文件身份。
            DWORD expectedVolumeSerialNumber = 0U; // expectedVolumeSerialNumber：初始卷身份。
            std::uint64_t expectedFileIndex = 0U;  // expectedFileIndex：初始文件索引。
        };

        struct FileMetadataUpdateResult
        {
            bool ok = false;                  // ok：写入调用与回读是否都成功。
            bool verificationMatched = false; // verificationMatched：回读值是否匹配请求。
            DWORD win32Error = ERROR_SUCCESS; // win32Error：失败时保留稳定错误码。
            FileMetadataSnapshot snapshot;   // snapshot：写入后的实际 FileBasicInfo。
        };

        static const std::array<DWORD, 6>& editableFileAttributeMasks()
        {
            // 只开放 SetFileInformationByHandle(FileBasicInfo) 可直接、可逆切换的属性。
            // DIRECTORY/REPARSE_POINT/COMPRESSED/ENCRYPTED/SPARSE 等结构性位必须走各自专用 API。
            static const std::array<DWORD, 6> masks{
                FILE_ATTRIBUTE_READONLY,
                FILE_ATTRIBUTE_HIDDEN,
                FILE_ATTRIBUTE_SYSTEM,
                FILE_ATTRIBUTE_ARCHIVE,
                FILE_ATTRIBUTE_TEMPORARY,
                FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
            };
            return masks;
        }

        static DWORD editableFileAttributeMask()
        {
            DWORD mask = 0U;
            for (const DWORD attributeMask : editableFileAttributeMasks())
            {
                mask |= attributeMask;
            }
            return mask;
        }

        static HANDLE openFileMetadataHandle(
            const QString& filePath,
            const DWORD desiredAccess,
            DWORD& errorOut)
        {
            // OPEN_REPARSE_POINT 保证叶节点是链接时修改链接自身，而不是静默跟随到目标。
            // BACKUP_SEMANTICS 同时允许目录句柄；共享删除避免与资源管理器产生不必要冲突。
            const std::wstring nativePath = QDir::toNativeSeparators(filePath).toStdWString();
            if (nativePath.empty())
            {
                errorOut = ERROR_INVALID_PARAMETER;
                return INVALID_HANDLE_VALUE;
            }

            HANDLE fileHandle = ::CreateFileW(
                nativePath.c_str(),
                desiredAccess,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            errorOut = fileHandle == INVALID_HANDLE_VALUE ? ::GetLastError() : ERROR_SUCCESS;
            return fileHandle;
        }

        static FileMetadataSnapshot readFileMetadataSnapshot(
            const QString& filePath,
            const DWORD desiredAccess = FILE_READ_ATTRIBUTES)
        {
            FileMetadataSnapshot snapshot;
            HANDLE fileHandle = openFileMetadataHandle(filePath, desiredAccess, snapshot.win32Error);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return snapshot;
            }

            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &snapshot.basicInfo,
                    sizeof(snapshot.basicInfo)) == FALSE)
            {
                snapshot.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return snapshot;
            }

            snapshot.ok = true;
            snapshot.win32Error = ERROR_SUCCESS;
            BY_HANDLE_FILE_INFORMATION identityInfo{};
            if (::GetFileInformationByHandle(fileHandle, &identityInfo) != FALSE)
            {
                snapshot.identityAvailable = true;
                snapshot.volumeSerialNumber = identityInfo.dwVolumeSerialNumber;
                snapshot.fileIndex =
                    (static_cast<std::uint64_t>(identityInfo.nFileIndexHigh) << 32U) |
                    static_cast<std::uint64_t>(identityInfo.nFileIndexLow);
            }
            closeWin32Handle(fileHandle);
            return snapshot;
        }

        static QDateTime fileMetadataTimeToLocalDateTime(const LARGE_INTEGER timeValue)
        {
            // Windows 时间从 1601-01-01 UTC 起按 100ns 计数；Qt 使用 1970-01-01 毫秒。
            constexpr qint64 WindowsEpochOffset100ns = 116444736000000000LL;
            if (timeValue.QuadPart <= 0)
            {
                return {};
            }
            const qint64 millisecondsSinceUnixEpoch =
                (timeValue.QuadPart - WindowsEpochOffset100ns) / 10000LL;
            return QDateTime::fromMSecsSinceEpoch(millisecondsSinceUnixEpoch, QTimeZone::UTC).toLocalTime();
        }

        static LARGE_INTEGER localDateTimeToFileMetadataTime(const QDateTime& dateTime)
        {
            constexpr qint64 WindowsEpochOffset100ns = 116444736000000000LL;
            LARGE_INTEGER timeValue{};
            if (!dateTime.isValid())
            {
                return timeValue;
            }
            timeValue.QuadPart =
                dateTime.toUTC().toMSecsSinceEpoch() * 10000LL + WindowsEpochOffset100ns;
            return timeValue;
        }

        static std::array<LARGE_INTEGER, 4> fileMetadataTimes(const FILE_BASIC_INFO& basicInfo)
        {
            return {
                basicInfo.CreationTime,
                basicInfo.LastAccessTime,
                basicInfo.LastWriteTime,
                basicInfo.ChangeTime
            };
        }

        static FileMetadataUpdateResult writeFileMetadata(
            const QString& filePath,
            const FileMetadataUpdateRequest& request)
        {
            FileMetadataUpdateResult result;
            HANDLE fileHandle = openFileMetadataHandle(
                filePath,
                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                result.win32Error);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return result;
            }

            FILE_BASIC_INFO currentInfo{};
            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &currentInfo,
                    sizeof(currentInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }

            BY_HANDLE_FILE_INFORMATION identityInfo{};
            const bool identityAvailable =
                ::GetFileInformationByHandle(fileHandle, &identityInfo) != FALSE;
            const std::uint64_t currentFileIndex = identityAvailable
                ? ((static_cast<std::uint64_t>(identityInfo.nFileIndexHigh) << 32U) |
                    static_cast<std::uint64_t>(identityInfo.nFileIndexLow))
                : 0U;
            if (request.validateIdentity)
            {
                if (!identityAvailable)
                {
                    result.win32Error = ::GetLastError();
                    closeWin32Handle(fileHandle);
                    return result;
                }
                if (identityInfo.dwVolumeSerialNumber != request.expectedVolumeSerialNumber ||
                    currentFileIndex != request.expectedFileIndex)
                {
                    result.win32Error = ERROR_FILE_INVALID;
                    closeWin32Handle(fileHandle);
                    return result;
                }
            }

            // 在同一句柄上二次读取后基于最新值合并，避免编辑页停留期间外部属性变化被覆盖。
            // FILE_BASIC_INFO 中值为 0 的时间字段与 FileAttributes 都表示“不修改”，因此只填入
            // 用户明确选择的时间；属性无变化时也保持 0，避免重写加密/压缩等结构性状态。
            FILE_BASIC_INFO updatedInfo{};
            if (request.updateTime[0]) updatedInfo.CreationTime = request.timeValue[0];
            if (request.updateTime[1]) updatedInfo.LastAccessTime = request.timeValue[1];
            if (request.updateTime[2]) updatedInfo.LastWriteTime = request.timeValue[2];
            if (request.updateTime[3]) updatedInfo.ChangeTime = request.timeValue[3];
            if (request.updateAttributes)
            {
                updatedInfo.FileAttributes = currentInfo.FileAttributes;
                updatedInfo.FileAttributes &= ~editableFileAttributeMask();
                updatedInfo.FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
                updatedInfo.FileAttributes |=
                    request.editableAttributes & editableFileAttributeMask();
                if (updatedInfo.FileAttributes == 0U)
                {
                    updatedInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                }
            }

            if (::SetFileInformationByHandle(
                    fileHandle,
                    FileBasicInfo,
                    &updatedInfo,
                    sizeof(updatedInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }

            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &result.snapshot.basicInfo,
                    sizeof(result.snapshot.basicInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }
            closeWin32Handle(fileHandle);

            result.snapshot.ok = true;
            result.snapshot.win32Error = ERROR_SUCCESS;
            result.snapshot.identityAvailable = identityAvailable;
            result.snapshot.volumeSerialNumber = identityAvailable
                ? identityInfo.dwVolumeSerialNumber
                : 0U;
            result.snapshot.fileIndex = currentFileIndex;
            result.ok = true;
            result.win32Error = ERROR_SUCCESS;
            result.verificationMatched = true;
            const std::array<LARGE_INTEGER, 4> actualTimes =
                fileMetadataTimes(result.snapshot.basicInfo);
            for (std::size_t timeIndex = 0; timeIndex < request.updateTime.size(); ++timeIndex)
            {
                if (request.updateTime[timeIndex] &&
                    actualTimes[timeIndex].QuadPart != request.timeValue[timeIndex].QuadPart)
                {
                    // FAT/exFAT 等文件系统可能按自身粒度舍入时间；写入仍成功，但 UI 必须展示回读值。
                    result.verificationMatched = false;
                }
            }
            if (request.updateAttributes &&
                (result.snapshot.basicInfo.FileAttributes & editableFileAttributeMask()) !=
                    (request.editableAttributes & editableFileAttributeMask()))
            {
                result.verificationMatched = false;
            }
            return result;
        }

        static QString formatHexValue(const quint64 value, const int digitCount)
        {
            // 用途：统一 0x 前缀的十六进制写法。
            // 说明：只把数字部分转大写。对整串调用 toUpper() 会连前缀一起变成 "0X"，
            //       和 WinDbg、微软文档里的写法对不上，复制出去还要手工改。
            // 入参 value：待格式化的值；digitCount：补零到的最少位数，<=0 表示不补零。
            // 返回：例如 0x0000A020。
            QString digitsText = QString::number(value, 16).toUpper();
            if (digitCount > 0)
            {
                digitsText = digitsText.rightJustified(digitCount, QLatin1Char('0'));
            }
            return QStringLiteral("0x%1").arg(digitsText);
        }

        static QString formatHex64(const std::uint64_t value)
        {
            // 用途：统一格式化 R0 诊断地址。
            // 返回：0x 前缀、数字部分大写的十六进制字符串。
            return formatHexValue(static_cast<quint64>(value), 0);
        }

        static QString formatNtStatus(const long status)
        {
            // 用途：NTSTATUS 同时显示十六进制和十进制，便于对照 WinDbg。
            // 返回：例如 0xC0000034 (-1073741772)。
            return QStringLiteral("%1 (%2)")
                .arg(formatHexValue(static_cast<quint64>(static_cast<std::uint32_t>(status)), 8))
                .arg(status);
        }

        static QString formatAuditBool(const bool value)
        {
            // 用途：把 R0 审计布尔值统一转成中文，避免各页混用 true/false。
            // 返回：是/否，供 IO 状态、truncated、unsupported 字段使用。
            return value ? QStringLiteral("是") : QStringLiteral("否");
        }

        static QString friendlyFileIoMessage(const std::string& messageText)
        {
            // 用途：把 ArkDriverClient 的原始 io.message 翻译成文件页可读说明。
            // 输入：messageText 为 wrapper 返回的 UTF-8/ASCII 诊断文本。
            // 返回：中文说明；仅用于 UI 展示，不改变原始 IO 状态字段。
            if (messageText.empty())
            {
                return QStringLiteral("无额外驱动消息");
            }

            const QString rawText = QString::fromStdString(messageText).trimmed();
            if (rawText.isEmpty())
            {
                return QStringLiteral("无额外驱动消息");
            }
            if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该文件审计入口");
            }
            if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
                rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
            {
                return QStringLiteral("当前驱动版本尚未提供该文件审计入口");
            }
            if (rawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
                rawText.contains(QStringLiteral("entrySize"), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动返回数据格式不完整，已保留当前页面其它只读证据");
            }
            if (rawText == QStringLiteral("empty nt path"))
            {
                return QStringLiteral("缺少可传递给驱动的 NT 路径，R0 文件信息查询已跳过");
            }
            if (rawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动已返回结构化文件审计数据");
            }
            return rawText;
        }

        static QString fixedWideAuditText(const wchar_t* const textBuffer, const std::size_t maxChars)
        {
            // 用途：读取 shared/driver 固定宽字符数组，避免 UI 猜测协议字段。
            // 输入：textBuffer 为协议字段首地址，maxChars 为数组容量。
            // 返回：遇到 NUL 截断后的 QString；空字段返回 <empty>。
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return QStringLiteral("<empty>");
            }

            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != L'\0')
            {
                ++length;
            }
            if (length == 0U)
            {
                return QStringLiteral("<empty>");
            }
            return QString::fromWCharArray(textBuffer, static_cast<int>(length));
        }

        template <std::size_t CharCount>
        static QString fixedWideAuditText(const wchar_t (&textBuffer)[CharCount])
        {
            // 用途：固定数组重载，调用方不需要重复写 std::size。
            // 返回：固定 UTF-16 字段的安全显示文本。
            return fixedWideAuditText(textBuffer, CharCount);
        }

        static QString fileTimeToText(const std::int64_t fileTimeValue)
        {
            // 用途：把 Windows FILETIME 语义的 100ns 时间戳转为本地时间文本。
            // 返回：可读时间；0 表示不可用。
            if (fileTimeValue <= 0)
            {
                return QStringLiteral("<Unavailable>");
            }

            constexpr std::int64_t windowsToUnix100Ns = 116444736000000000LL;
            const std::int64_t unixMilliseconds = (fileTimeValue - windowsToUnix100Ns) / 10000LL;
            if (unixMilliseconds <= 0)
            {
                return QStringLiteral("<Invalid:%1>").arg(fileTimeValue);
            }
            // Qt 6.9 已废弃 Qt::TimeSpec 重载；这里显式使用 UTC 时区，
            // 再转换为本地时间，保持 FILETIME 展示语义不变。
            return QDateTime::fromMSecsSinceEpoch(unixMilliseconds, QTimeZone::UTC)
                .toLocalTime()
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        }

        static QString fileAttributesToText(const std::uint32_t attributes)
        {
            // 用途：拆解 FILE_ATTRIBUTE_*，让 R0 和 R3 属性差异可读。
            // 返回：属性名列表；无显式位时返回 NORMAL/0。
            QStringList parts;
            if ((attributes & FILE_ATTRIBUTE_READONLY) != 0U) parts << QStringLiteral("READONLY");
            if ((attributes & FILE_ATTRIBUTE_HIDDEN) != 0U) parts << QStringLiteral("HIDDEN");
            if ((attributes & FILE_ATTRIBUTE_SYSTEM) != 0U) parts << QStringLiteral("SYSTEM");
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) parts << QStringLiteral("DIRECTORY");
            if ((attributes & FILE_ATTRIBUTE_ARCHIVE) != 0U) parts << QStringLiteral("ARCHIVE");
            if ((attributes & FILE_ATTRIBUTE_DEVICE) != 0U) parts << QStringLiteral("DEVICE");
            if ((attributes & FILE_ATTRIBUTE_NORMAL) != 0U) parts << QStringLiteral("NORMAL");
            if ((attributes & FILE_ATTRIBUTE_TEMPORARY) != 0U) parts << QStringLiteral("TEMPORARY");
            if ((attributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0U) parts << QStringLiteral("SPARSE_FILE");
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) parts << QStringLiteral("REPARSE_POINT");
            if ((attributes & FILE_ATTRIBUTE_COMPRESSED) != 0U) parts << QStringLiteral("COMPRESSED");
            if ((attributes & FILE_ATTRIBUTE_OFFLINE) != 0U) parts << QStringLiteral("OFFLINE");
            if ((attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) != 0U) parts << QStringLiteral("NOT_CONTENT_INDEXED");
            if ((attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0U) parts << QStringLiteral("ENCRYPTED");
            if ((attributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) != 0U) parts << QStringLiteral("INTEGRITY_STREAM");
            if ((attributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) != 0U) parts << QStringLiteral("NO_SCRUB_DATA");
            if (parts.isEmpty())
            {
                parts << QStringLiteral("0");
            }
            return QStringLiteral("0x%1 (%2)")
                .arg(attributes, 8, 16, QChar('0'))
                .arg(parts.join(QStringLiteral("|")))
                .toUpper();
        }

        static QString fileInfoStatusText(const std::uint32_t status)
        {
            // 用途：把共享协议状态码翻译为 UI 文本。
            // 返回：状态名称。
            switch (status)
            {
            case KSWORD_ARK_FILE_INFO_STATUS_OK:
                return QStringLiteral("OK");
            case KSWORD_ARK_FILE_INFO_STATUS_PARTIAL:
                return QStringLiteral("Partial");
            case KSWORD_ARK_FILE_INFO_STATUS_OPEN_FAILED:
                return QStringLiteral("Open Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_BASIC_FAILED:
                return QStringLiteral("Basic Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_STANDARD_FAILED:
                return QStringLiteral("Standard Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED:
                return QStringLiteral("Object Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_NAME_FAILED:
                return QStringLiteral("Name Failed");
            default:
                return QStringLiteral("Unavailable");
            }
        }

        static ksword::ark::FileInfoQueryResult queryR0FileInfo(const QFileInfo& info, const QString& ntPathText)
        {
            // 用途：通过 ArkDriverClient 调用 R0 文件基础信息查询。
            // 返回：驱动不可用时 ok=false，常规页自动回退 R3 展示。
            ksword::ark::FileInfoQueryResult result{};
            if (ntPathText.trimmed().isEmpty())
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_PARAMETER;
                result.io.message = "empty nt path";
                return result;
            }

            unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL;
            if (info.isDir())
            {
                flags |= KSWORD_ARK_QUERY_FILE_INFO_FLAG_DIRECTORY;
            }

            const ksword::ark::DriverClient driverClient;
            return driverClient.queryFileInfo(ntPathText.toStdWString(), flags);
        }

        // formatFileSizeText 作用：
        // - 文件大小同时给出易读单位和精确字节数，避免只有一串数字要用户自己数位数；
        // - 不足 1KB 时没有换算价值，只给字节数。
        // 入参 sizeBytes：字节数。
        // 返回：例如“1.21 MB（1268736 字节）”。
        static QString formatFileSizeText(const qulonglong sizeBytes)
        {
            static const std::array<const char*, 5> unitNames{ "B", "KB", "MB", "GB", "TB" };
            double scaledValue = static_cast<double>(sizeBytes);
            std::size_t unitIndex = 0;
            while (scaledValue >= 1024.0 && (unitIndex + 1) < unitNames.size())
            {
                scaledValue /= 1024.0;
                ++unitIndex;
            }
            if (unitIndex == 0)
            {
                return ks::i18n::displayText(QStringLiteral("%1 字节")).arg(sizeBytes);
            }
            return ks::i18n::displayText(QStringLiteral("%1 %2（%3 字节）"))
                .arg(QString::number(scaledValue, 'f', 2))
                .arg(QString::fromLatin1(unitNames[unitIndex]))
                .arg(sizeBytes);
        }

        // fileAttributeFlagRows 作用：
        // - 输入 attributes：FILE_ATTRIBUTE_* 位集合；
        // - 处理：只展开已置位的属性，逐位给出 Win32 常量名和中文含义；
        //   原先这些位被压成一个 A|B|C 串，除了记得住常量名的人谁都读不出来；
        // - 返回：常量名/含义对的列表；一位都没置位时返回空列表，由调用方补一行说明。
        static QList<QPair<QString, QString>> fileAttributeFlagRows(const std::uint32_t attributes)
        {
            QList<QPair<QString, QString>> flagRows;
            const auto appendFlag =
                [&flagRows, attributes](
                    const std::uint32_t mask,
                    const QString& nameText,
                    const QString& descriptionText)
                {
                    if ((attributes & mask) != 0U)
                    {
                        flagRows.append(QPair<QString, QString>(nameText, descriptionText));
                    }
                };

            appendFlag(FILE_ATTRIBUTE_READONLY, QStringLiteral("READONLY"), QStringLiteral("只读，写入前要先去掉该属性"));
            appendFlag(FILE_ATTRIBUTE_HIDDEN, QStringLiteral("HIDDEN"), QStringLiteral("隐藏，资源管理器默认不显示"));
            appendFlag(FILE_ATTRIBUTE_SYSTEM, QStringLiteral("SYSTEM"), QStringLiteral("系统文件，属于操作系统的一部分"));
            appendFlag(FILE_ATTRIBUTE_DIRECTORY, QStringLiteral("DIRECTORY"), QStringLiteral("目录"));
            appendFlag(FILE_ATTRIBUTE_ARCHIVE, QStringLiteral("ARCHIVE"), QStringLiteral("存档位，备份程序据此判断是否需要重新备份"));
            appendFlag(FILE_ATTRIBUTE_DEVICE, QStringLiteral("DEVICE"), QStringLiteral("设备，保留给系统使用"));
            appendFlag(FILE_ATTRIBUTE_NORMAL, QStringLiteral("NORMAL"), QStringLiteral("没有其它属性"));
            appendFlag(FILE_ATTRIBUTE_TEMPORARY, QStringLiteral("TEMPORARY"), QStringLiteral("临时文件，系统会尽量把内容留在内存里"));
            appendFlag(FILE_ATTRIBUTE_SPARSE_FILE, QStringLiteral("SPARSE_FILE"), QStringLiteral("稀疏文件，全零区段不实际占用磁盘"));
            appendFlag(FILE_ATTRIBUTE_REPARSE_POINT, QStringLiteral("REPARSE_POINT"), QStringLiteral("重解析点，符号链接和装载点由它实现"));
            appendFlag(FILE_ATTRIBUTE_COMPRESSED, QStringLiteral("COMPRESSED"), QStringLiteral("NTFS 压缩"));
            appendFlag(FILE_ATTRIBUTE_OFFLINE, QStringLiteral("OFFLINE"), QStringLiteral("内容已转到离线存储，访问会明显变慢"));
            appendFlag(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, QStringLiteral("NOT_CONTENT_INDEXED"), QStringLiteral("不建内容索引，Windows 搜索不检索正文"));
            appendFlag(FILE_ATTRIBUTE_ENCRYPTED, QStringLiteral("ENCRYPTED"), QStringLiteral("EFS 加密"));
            appendFlag(FILE_ATTRIBUTE_INTEGRITY_STREAM, QStringLiteral("INTEGRITY_STREAM"), QStringLiteral("ReFS 完整性流，写入时带校验和"));
            appendFlag(FILE_ATTRIBUTE_NO_SCRUB_DATA, QStringLiteral("NO_SCRUB_DATA"), QStringLiteral("排除在 ReFS 数据完整性扫描之外"));
            return flagRows;
        }

        struct GeneralFileSnapshot
        {
            ks::ui::FieldDocument document;
            QFileInfo info;
            QString ntPath;
        };

        static GeneralFileSnapshot readGeneralFileSnapshot(const QString& path)
        {
            using ks::ui::FieldDocument;
            const QFileInfo info(path);
            const QString ntPathText = buildDriverNtPath(info.absoluteFilePath());
            const auto nativePath = QDir::toNativeSeparators(info.absoluteFilePath()).toStdWString();
            const DWORD attributes = ::GetFileAttributesW(nativePath.c_str());
            const DWORD attributeError = attributes == INVALID_FILE_ATTRIBUTES ? ::GetLastError() : ERROR_SUCCESS;
            FieldDocument doc;
            doc.section(QStringLiteral("基本信息"));
            doc.field(QStringLiteral("文件名"), info.fileName());
            doc.field(QStringLiteral("扩展名"), info.suffix());
            doc.field(QStringLiteral("大小"), formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, info.size()))));
            const QString timeFormat = QStringLiteral("yyyy-MM-dd HH:mm:ss");
            doc.field(QStringLiteral("创建时间"), info.birthTime().toString(timeFormat));
            doc.field(QStringLiteral("修改时间"), info.lastModified().toString(timeFormat));
            doc.field(QStringLiteral("访问时间"), info.lastRead().toString(timeFormat));
            doc.field(QStringLiteral("可执行"), info.isExecutable() ? QStringLiteral("是") : QStringLiteral("否"), true);
            doc.field(QStringLiteral("隐藏"), info.isHidden() ? QStringLiteral("是") : QStringLiteral("否"), true);
            doc.field(QStringLiteral("可写"), info.isWritable() ? QStringLiteral("是") : QStringLiteral("否"), true);
            doc.field(QStringLiteral("重解析点"), (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                ? QStringLiteral("是（首屏只判断属性位，不追踪链接目标）") : QStringLiteral("否"), true);
            doc.section(QStringLiteral("路径"));
            doc.field(QStringLiteral("Win32 路径"), QDir::toNativeSeparators(info.absoluteFilePath()));
            doc.field(QStringLiteral("NT 路径"), ntPathText.isEmpty()
                ? QStringLiteral("<转换失败>") : ntPathText, ntPathText.isEmpty());
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                doc.field(QStringLiteral("状态"), QStringLiteral("不存在或不可访问"), true);
                doc.field(QStringLiteral("Win32 错误码"), formatWin32ErrorText(attributeError));
            }
            return { std::move(doc), info, ntPathText };
        }

        void startGeneralFileSnapshotLoad()
        {
            if (m_generalPropertyView == nullptr) return;
            m_generalR3Loaded = false;
            m_generalR0Loaded = false;
            ++m_generalR0LoadGeneration;
            const quint64 generation = ++m_generalR3LoadGeneration;
            const QString path = m_filePath;
            refreshGeneralTab();
            const QPointer<FileDetailDialog> guardThis(this);
            QThreadPool::globalInstance()->start(QRunnable::create([guardThis, path, generation]()
                {
                    const auto snapshot = readGeneralFileSnapshot(path);
                    QMetaObject::invokeMethod(qApp, [guardThis, path, generation, snapshot]()
                        {
                            if (guardThis == nullptr || guardThis->m_filePath != path ||
                                guardThis->m_generalR3LoadGeneration != generation) return;
                            guardThis->m_generalR3Document = snapshot.document;
                            guardThis->m_generalNtPathText = snapshot.ntPath;
                            guardThis->m_generalR3Loaded = true;
                            guardThis->refreshGeneralTab();
                            guardThis->startR0FileInfoLoad(snapshot.info, snapshot.ntPath);
                        }, Qt::QueuedConnection);
                }));
        }

        void refreshGeneralTab()
        {
            if (m_generalPropertyView == nullptr) return;
            if (!m_generalR3Loaded)
            {
                ks::ui::FieldDocument loading;
                loading.note(QStringLiteral("● 正在后台读取文件元数据..."));
                loading.field(QStringLiteral("目标"), QDir::toNativeSeparators(m_filePath));
                m_generalPropertyView->setDocument(loading);
                return;
            }
            auto doc = m_generalR3Document;
            doc.field(QStringLiteral("查询来源"), !m_generalR0Loaded
                ? QStringLiteral("R3 QFileInfo（R0 信息正在后台加载）")
                : (m_generalR0Info.io.ok ? QStringLiteral("R3 QFileInfo + R0 KswordARK")
                    : QStringLiteral("R3 QFileInfo（R0 不可用）")), true);
            doc.section(QStringLiteral("内核视图（R0）"));
            if (!m_generalR0Loaded)
                doc.field(QStringLiteral("状态"), QStringLiteral("正在后台查询，属性窗口不会等待驱动返回"), true);
            else if (!m_generalR0Info.io.ok)
            {
                doc.field(QStringLiteral("状态"), QStringLiteral("不可用"), true);
                doc.field(QStringLiteral("原因"), friendlyFileIoMessage(m_generalR0Info.io.message), true);
                doc.field(QStringLiteral("Win32 错误码"), QString::number(m_generalR0Info.io.win32Error));
            }
            else
            {
                const auto& r0 = m_generalR0Info;
                if (!r0.objectName.empty()) doc.field(QStringLiteral("R0 对象名"), QString::fromStdWString(r0.objectName));
                doc.field(QStringLiteral("大小（EndOfFile）"), formatFileSizeText(r0.endOfFile));
                doc.field(QStringLiteral("磁盘占用（分配大小）"), formatFileSizeText(r0.allocationSize));
                doc.field(QStringLiteral("创建时间"), fileTimeToText(r0.creationTime));
                doc.field(QStringLiteral("最后访问"), fileTimeToText(r0.lastAccessTime));
                doc.field(QStringLiteral("最后写入"), fileTimeToText(r0.lastWriteTime));
                doc.field(QStringLiteral("元数据变更（ChangeTime）"), fileTimeToText(r0.changeTime));
                doc.field(QStringLiteral("R0 说明"), friendlyFileIoMessage(r0.io.message), true);
                doc.section(QStringLiteral("文件属性位"));
                doc.field(QStringLiteral("属性"), formatHexValue(r0.fileAttributes, 8));
                const auto flags = fileAttributeFlagRows(r0.fileAttributes);
                if (flags.isEmpty()) doc.note(QStringLiteral("无置位属性"));
                for (const auto& flag : flags) doc.field(flag.first, flag.second, true);
                doc.section(QStringLiteral("驱动诊断"));
                doc.field(QStringLiteral("协议版本"), QString::number(r0.version));
                doc.field(QStringLiteral("查询状态"), QStringLiteral("%1 (%2)").arg(fileInfoStatusText(r0.queryStatus)).arg(r0.queryStatus));
                doc.field(QStringLiteral("字段标志"), formatHexValue(r0.fieldFlags, 8));
                doc.field(QStringLiteral("OpenStatus"), formatNtStatus(r0.openStatus));
                doc.field(QStringLiteral("BasicStatus"), formatNtStatus(r0.basicStatus));
                doc.field(QStringLiteral("StandardStatus"), formatNtStatus(r0.standardStatus));
                doc.field(QStringLiteral("ObjectStatus"), formatNtStatus(r0.objectStatus));
                doc.field(QStringLiteral("NameStatus"), formatNtStatus(r0.nameStatus));
                doc.field(QStringLiteral("FileObject"), formatHex64(r0.fileObjectAddress));
                doc.field(QStringLiteral("SectionObjectPointers"), formatHex64(r0.sectionObjectPointersAddress));
                doc.field(QStringLiteral("DataSectionObject"), formatHex64(r0.dataSectionObjectAddress));
                doc.field(QStringLiteral("ImageSectionObject"), formatHex64(r0.imageSectionObjectAddress));
            }
            for (auto& section : doc.nodes)
                if (section.name == QStringLiteral("驱动诊断")) section.initiallyExpanded = false;
            m_generalPropertyView->setDocument(doc);
        }

        void startHashCalculation(
            ks::ui::StructuredFieldView* textEditorWidget,
            QProgressBar* progressBar,
            QPushButton* startButton,
            QPushButton* cancelButton)
        {
            // 用途：启动多算法后台流式计算。
            // 处理：每块读取后检查取消标记并异步更新进度。
            // 返回：无；结果通过 QueuedConnection 回填 UI。
            if (textEditorWidget == nullptr || progressBar == nullptr ||
                startButton == nullptr || cancelButton == nullptr)
            {
                return;
            }

            if (m_hashCancelRequested == nullptr)
            {
                m_hashCancelRequested = std::make_shared<std::atomic_bool>(false);
            }
            m_hashCancelRequested->store(false);

            startButton->setEnabled(false);
            cancelButton->setEnabled(true);
            cancelButton->setText(QStringLiteral("取消"));
            progressBar->setValue(0);
            ks::ui::FieldDocument loading;
            loading.note(QStringLiteral("正在计算常用哈希，请等待..."));
            loading.field(QStringLiteral("目标"), QDir::toNativeSeparators(m_filePath));
            textEditorWidget->setDocument(loading);

            const QString filePathSnapshot = m_filePath;
            const auto cancelFlag = m_hashCancelRequested;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<ks::ui::StructuredFieldView> editorGuard(textEditorWidget);
            QPointer<QProgressBar> progressGuard(progressBar);
            QPointer<QPushButton> startGuard(startButton);
            QPointer<QPushButton> cancelGuard(cancelButton);

            auto* task = QRunnable::create([guardThis, editorGuard, progressGuard, startGuard, cancelGuard, filePathSnapshot, cancelFlag]()
                {
                    HashCalculationResult result{};
                    const auto beginTime = std::chrono::steady_clock::now();
                    QFile file(filePathSnapshot);
                    result.totalBytes = QFileInfo(filePathSnapshot).size();

                    if (!file.open(QIODevice::ReadOnly))
                    {
                        result.fileError = file.error();
                    }
                    else
                    {
                        result.openOk = true;
                        CommonFileHashes hashes;
                        constexpr qint64 chunkBytes = 1024 * 1024;
                        auto lastProgressTime = std::chrono::steady_clock::now();

                        while (!file.atEnd())
                        {
                            if (cancelFlag != nullptr && cancelFlag->load())
                            {
                                result.cancelled = true;
                                break;
                            }

                            const QByteArray chunk = file.read(chunkBytes);
                            if (chunk.isEmpty())
                            {
                                if (file.error() != QFileDevice::NoError)
                                {
                                    result.fileError = file.error();
                                }
                                break;
                            }

                            hashes.addData(chunk);
                            result.readBytes += chunk.size();

                            const auto nowTime = std::chrono::steady_clock::now();
                            const bool shouldReport =
                                std::chrono::duration_cast<std::chrono::milliseconds>(nowTime - lastProgressTime).count() >= 100;
                            if (shouldReport)
                            {
                                lastProgressTime = nowTime;
                                const int progressValue = result.totalBytes > 0
                                    ? static_cast<int>((result.readBytes * 1000LL) / result.totalBytes)
                                    : 1000;
                                QMetaObject::invokeMethod(
                                    qApp,
                                    [guardThis, progressGuard, progressValue]()
                                    {
                                        if (guardThis != nullptr && progressGuard != nullptr)
                                        {
                                            progressGuard->setValue(std::min(progressValue, 1000));
                                        }
                                    },
                                    Qt::QueuedConnection);
                            }
                        }

                        if (!result.cancelled && result.fileError == QFileDevice::NoError)
                        {
                            result.hashValues = hashes.results();
                        }
                        file.close();
                    }

                    result.elapsedMs = static_cast<qint64>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - beginTime).count());

                    QMetaObject::invokeMethod(
                        qApp,
                        [guardThis, editorGuard, progressGuard, startGuard, cancelGuard, result]()
                        {
                            if (guardThis == nullptr || editorGuard == nullptr ||
                                progressGuard == nullptr || startGuard == nullptr ||
                                cancelGuard == nullptr)
                            {
                                return;
                            }

                            startGuard->setEnabled(true);
                            cancelGuard->setEnabled(false);
                            cancelGuard->setText(QStringLiteral("取消"));
                            progressGuard->setValue(result.totalBytes > 0
                                ? static_cast<int>((result.readBytes * 1000LL) / result.totalBytes)
                                : 1000);

                            const double elapsedSeconds = std::max(0.001, static_cast<double>(result.elapsedMs) / 1000.0);
                            const double speedMiB = (static_cast<double>(result.readBytes) / (1024.0 * 1024.0)) / elapsedSeconds;

                            ks::ui::FieldDocument doc;
                            doc.section(QStringLiteral("哈希与完整性"));
                            doc.field(QStringLiteral("算法"), commonHashNames().join(QStringLiteral(", ")));
                            doc.field(QStringLiteral("来源"), QStringLiteral("用户态流式读取(QCryptographicHash)"), true);
                            doc.field(QStringLiteral("文件"), QDir::toNativeSeparators(guardThis->m_filePath));
                            doc.field(QStringLiteral("总大小"), formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, result.totalBytes))));
                            doc.field(QStringLiteral("已读取"), formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, result.readBytes))));
                            doc.field(QStringLiteral("耗时"), QStringLiteral("%1 ms").arg(result.elapsedMs));
                            doc.field(QStringLiteral("速度"), QStringLiteral("%1 MiB/s").arg(QString::number(speedMiB, 'f', 2)));
                            doc.field(QStringLiteral("是否取消"), result.cancelled ? QStringLiteral("是") : QStringLiteral("否"), true);
                            if (result.fileError != QFileDevice::NoError)
                                doc.field(QStringLiteral("QFile错误码"), QString::number(static_cast<int>(result.fileError)));
                            doc.section(QStringLiteral("摘要"));
                            const auto names = commonHashNames();
                            for (qsizetype index = 0; index < result.hashValues.size(); ++index)
                                doc.field(names.at(index), result.hashValues.at(index));
                            editorGuard->setDocument(doc);
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void requestHashCancel(QPushButton* cancelButton)
        {
            // 用途：设置哈希取消标记。
            // 返回：无；后台线程在下一次块边界观察该标记。
            if (m_hashCancelRequested != nullptr)
            {
                m_hashCancelRequested->store(true);
            }
            if (cancelButton != nullptr)
            {
                cancelButton->setEnabled(false);
                cancelButton->setText(QStringLiteral("正在取消..."));
            }
        }

        struct UsageSelection
        {
            std::uint32_t processId = 0;
            std::uint64_t processCreationTime = 0;
            std::uint64_t handleValue = 0;
            std::uint64_t objectAddress = 0;
            QString processName;
            QString matchedTargetPath;
            bool matchedByDirectoryRule = false;
        };

        static constexpr int usageProcessIdRole = Qt::UserRole;
        static constexpr int usageProcessCreationTimeRole = Qt::UserRole + 1;
        static constexpr int usageHandleValueRole = Qt::UserRole + 2;
        static constexpr int usageMatchedTargetPathRole = Qt::UserRole + 3;
        static constexpr int usageDirectoryMatchRole = Qt::UserRole + 4;
        static constexpr int usageObjectAddressRole = Qt::UserRole + 5;

        static bool readUsageSelection(QTableView* table, UsageSelection& selectionOut)
        {
            // 用途：从当前行取回扫描时的 PID/创建时间/句柄身份。
            // 这些隐藏字段必须与可见行一起保存，操作前才能拒绝 PID 复用或陈旧句柄。
            if (table == nullptr || !table->currentIndex().isValid())
            {
                return false;
            }

            const QModelIndex item = table->model()->index(table->currentIndex().row(), 0);
            selectionOut.processId = item.data(usageProcessIdRole).toUInt();
            selectionOut.processCreationTime =
                item.data(usageProcessCreationTimeRole).toULongLong();
            selectionOut.handleValue = item.data(usageHandleValueRole).toULongLong();
            selectionOut.objectAddress = item.data(usageObjectAddressRole).toULongLong();
            selectionOut.processName = item.sibling(item.row(), 1).data().toString();
            selectionOut.matchedTargetPath = item.data(usageMatchedTargetPathRole).toString();
            selectionOut.matchedByDirectoryRule = item.data(usageDirectoryMatchRole).toBool();
            return selectionOut.processId != 0U;
        }

        void closeSelectedUsageHandle(
            QTableView* table,
            QLabel* statusLabel,
            QPushButton* refreshButton)
        {
            if (m_usageCloseInProgress) { return; }
            UsageSelection selection;
            if (!readUsageSelection(table, selection))
            {
                return;
            }
            if (selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                selection.processCreationTime == 0U || selection.handleValue == 0U ||
                isCriticalProcessName(selection.processName))
            {
                return;
            }

            std::string detailText;
            const bool closeOk = ks::file::CloseRemoteHandle(
                selection.processId,
                selection.handleValue,
                selection.processCreationTime,
                selection.matchedTargetPath.toStdWString(),
                selection.matchedByDirectoryRule,
                detailText);
            if (!closeOk)
            {
                if (statusLabel != nullptr)
                {
                    statusLabel->setText(QString::fromStdString(detailText));
                }
                return;
            }

            statusLabel->setText(QStringLiteral("● 句柄已关闭，正在重新扫描占用状态..."));
            refreshUsageTable(table, statusLabel, refreshButton);
        }

        void closeSelectedUsageHandleR0(
            QTableView* table, QLabel* statusLabel, QPushButton* refreshButton,
            const QList<QPushButton*>& actionButtons)
        {
            // Copy the selected identity before the confirmation's nested event loop.
            UsageSelection selection;
            if (m_usageCloseInProgress || m_usageScanInProgress ||
                !readUsageSelection(table, selection) || selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                isCriticalProcessName(selection.processName) || selection.processCreationTime == 0U ||
                selection.objectAddress == 0U || selection.handleValue == 0U ||
                selection.handleValue >= 0x80000000ULL)
            {
                return;
            }
            QPointer<FileDetailDialog> guard(this);
            const QString title = ks::i18n::sourceText(QStringLiteral("关闭句柄（R0）"));
            const QString confirmation = ks::i18n::sourceText(QStringLiteral(
                "确认由 R0 关闭选中的文件句柄？\nPID=%1\nHandle=%2\n文件=%3"))
                .arg(selection.processId).arg(formatHex64(selection.handleValue)).arg(selection.matchedTargetPath);
            const auto answer = QMessageBox::question(this, title, confirmation,
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (guard == nullptr || answer != QMessageBox::Yes || m_usageCloseInProgress || m_usageScanInProgress)
                return;

            m_usageCloseInProgress = true;
            table->setEnabled(false);
            refreshButton->setEnabled(false);
            for (QPushButton* button : actionButtons) { button->setEnabled(false); }
            statusLabel->setText(ks::i18n::sourceText(QStringLiteral("● 正在由 R0 关闭选中的文件句柄...")));

            // Only value identity crosses into the worker; DriverClient owns all device access.
            auto* watcher = new QFutureWatcher<ksword::ark::IoResult>(this);
            connect(watcher, &QFutureWatcher<ksword::ark::IoResult>::finished, this,
                [this, watcher, table, statusLabel, refreshButton, title]()
                {
                    const auto result = watcher->result();
                    watcher->deleteLater();
                    m_usageCloseInProgress = false;
                    table->setEnabled(true);
                    refreshButton->setEnabled(true);
                    // Refresh failures too: close may have succeeded while process resume failed.
                    refreshUsageTable(table, statusLabel, refreshButton);
                    if (!result.ok)
                    {
                        QMessageBox::warning(this, title,
                            ks::i18n::sourceText(QStringLiteral("句柄关闭操作未完整完成。\n%1"))
                                .arg(QString::fromStdString(result.message)));
                    }
                });
            watcher->setFuture(QtConcurrent::run([selection]()
                {
                    return ksword::ark::DriverClient().closeHandle(selection.processId, selection.handleValue,
                        selection.processCreationTime, selection.objectAddress);
                }));
        }

        void terminateSelectedUsageProcess(
            QTableView* table,
            QLabel* statusLabel,
            QPushButton* refreshButton,
            const bool useKernelDriver)
        {
            if (m_usageCloseInProgress) { return; }
            UsageSelection selection;
            if (!readUsageSelection(table, selection))
            {
                return;
            }
            if (selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                selection.processCreationTime == 0U ||
                isCriticalProcessName(selection.processName))
            {
                return;
            }

            std::string detailText;
            bool terminateOk = false;
            if (useKernelDriver)
            {
                // 先持有已校验创建时间的进程句柄，防止驱动按 PID 查找时命中复用后的新进程。
                HANDLE verifiedProcessHandle = nullptr;
                if (ks::file::OpenProcessForVerifiedAction(
                        selection.processId,
                        selection.processCreationTime,
                        SYNCHRONIZE,
                        verifiedProcessHandle,
                        detailText))
                {
                    ksword::ark::DriverHandle driverHandle = openKswordArkDriverHandle(&detailText);
                    if (driverHandle.isValid())
                    {
                        terminateOk = terminateProcessByR0Driver(driverHandle, selection.processId, &detailText);
                    }
                    ::CloseHandle(verifiedProcessHandle);
                }
            }
            else
            {
                terminateOk = terminateProcessByR3(
                    selection.processId,
                    selection.processCreationTime,
                    &detailText);
            }

            if (!terminateOk)
            {
                if (statusLabel != nullptr)
                {
                    statusLabel->setText(QString::fromStdString(detailText));
                }
                return;
            }

            statusLabel->setText(QStringLiteral("● 进程已结束，正在重新扫描占用状态..."));
            refreshUsageTable(table, statusLabel, refreshButton);
        }

        void refreshUsageTable(QTableView* table, QLabel* statusLabel, QPushButton* refreshButton)
        {
            if (m_usageCloseInProgress || !table || !statusLabel || !refreshButton) return;
            const QPointer<FileDetailDialog> owner(this);
            const QPointer<QTableView> tableGuard(table);
            const QPointer<QLabel> statusGuard(statusLabel);
            const QPointer<QPushButton> refreshGuard(refreshButton);
            const QPointer<QProgressBar> progressGuard(m_usageScanProgressBar);
            m_usageScanCancelRequested->store(true);
            const auto cancel = m_usageScanCancelRequested = std::make_shared<std::atomic_bool>(false);
            m_usageScanInProgress = true;
            m_usageRetryAfterR0Start = false;
            m_usageR0StartedDuringScan = false;
            propertyTableModel(table)->invalidateRequest();
            refreshButton->setEnabled(false);
            if (!owner || !tableGuard || !statusGuard) return;
            statusLabel->setText(QStringLiteral("● 正在扫描文件占用..."));
            if (!owner || !tableGuard) return;
            if (progressGuard)
            {
                progressGuard->setRange(0, 100);
                progressGuard->setValue(0);
                progressGuard->setFormat(QStringLiteral("%p%"));
            }
            const QString path = m_filePath;
            QThreadPool::globalInstance()->start(QRunnable::create([owner, tableGuard, statusGuard, refreshGuard, progressGuard, cancel, path]()
                {
                    const QFileInfo info(path);
                    if (!info.exists())
                    {
                        QMetaObject::invokeMethod(qApp, [owner, tableGuard, statusGuard, refreshGuard, cancel]()
                            {
                                if (!owner || !tableGuard || !statusGuard || !refreshGuard || cancel->load()) return;
                                owner->m_usageScanInProgress = false;
                                propertyTableModel(tableGuard)->setSnapshot(ks::fileui::makePropertyTableSnapshot(),
                                    [owner, statusGuard, refreshGuard, cancel]()
                                    {
                                        if (!owner || !statusGuard || !refreshGuard || cancel->load()) return;
                                        statusGuard->setText(QStringLiteral("● 目标不存在，无法扫描占用。"));
                                        if (refreshGuard) refreshGuard->setEnabled(true);
                                    });
                            }, Qt::QueuedConnection);
                        return;
                    }
                    auto scanResult = filedock::handleusage::scanHandleUsageByPaths({info.absoluteFilePath()}, 0, true,
                        [cancel]() { return cancel->load(); },
                        [owner, progressGuard, cancel](const QString&, float progress)
                            {
                                if (cancel->load()) return;
                                const int percentage = static_cast<int>(std::clamp(progress, 0.0f, 100.0f));
                                QMetaObject::invokeMethod(qApp, [owner, progressGuard, cancel, percentage]()
                                    { if (owner && progressGuard && !cancel->load()) progressGuard->setValue(percentage); }, Qt::QueuedConnection);
                            });
                    if (cancel->load()) return;
                    auto rows = ks::fileui::makePropertyTableSnapshot();
                    rows->rows.reserve(scanResult.entries.size());
                    for (const auto& entry : scanResult.entries)
                    {
                        if (cancel->load()) return;
                        const QString source = entry.enumerationSource.trimmed().isEmpty() ? QStringLiteral("R3 DuplicateHandle") : entry.enumerationSource;
                        const QString rule = entry.matchRuleText.trimmed().isEmpty()
                            ? (entry.matchedByDirectoryRule ? QStringLiteral("目录前缀") : QStringLiteral("精确")) : entry.matchRuleText;
                        rows->append({ks::fileui::propertyRowKey({QString::number(entry.processId), QString::number(entry.processCreationTime),
                            QString::number(entry.handleValue), QString::number(entry.objectAddress), entry.matchedTargetPath, entry.objectName, source, rule}),
                            {QString::number(entry.processId), entry.processName,
                                entry.handleValue == 0 ? QStringLiteral("-") : formatHex64(entry.handleValue),
                                entry.grantedAccess == 0 ? QStringLiteral("-") : QStringLiteral("0x%1").arg(entry.grantedAccess, 8, 16, QChar('0')).toUpper(),
                                entry.objectName, entry.matchedTargetPath, QStringLiteral("%1 | %2").arg(source, rule)},
                            {{usageProcessIdRole, static_cast<qulonglong>(entry.processId)},
                             {usageProcessCreationTimeRole, static_cast<qulonglong>(entry.processCreationTime)},
                             {usageHandleValueRole, static_cast<qulonglong>(entry.handleValue)},
                             {usageMatchedTargetPathRole, entry.matchedTargetPath},
                             {usageDirectoryMatchRole, entry.matchedByDirectoryRule},
                             {usageObjectAddressRole, static_cast<qulonglong>(entry.objectAddress)}}, {6}});
                    }
                    // All consumed evidence is in rows; only scan totals/diagnostics/flags go to the UI.
                    scanResult.entries.clear();
                    const auto summary = std::shared_ptr<filedock::handleusage::HandleUsageScanResult>(
                        new filedock::handleusage::HandleUsageScanResult(std::move(scanResult)),
                        [](auto* value) { QThreadPool::globalInstance()->start(QRunnable::create([value]() { delete value; })); });
                    QMetaObject::invokeMethod(qApp, [owner, tableGuard, statusGuard, refreshGuard, progressGuard, cancel, rows, summary]()
                        {
                            if (!owner || !tableGuard || !statusGuard || !refreshGuard || cancel->load()) return;
                            propertyTableModel(tableGuard)->setSnapshot(rows, [owner, tableGuard, statusGuard, refreshGuard, progressGuard, cancel, summary]()
                                {
                                    if (!owner || !tableGuard || !statusGuard || !refreshGuard || cancel->load()) return;
                                    QString status = QStringLiteral("● 扫描完成 %1 ms | 总句柄:%2 | 文件句柄:%3 | 命中:%4")
                                        .arg(summary->elapsedMs).arg(summary->totalHandleCount).arg(summary->fileLikeHandleCount).arg(summary->matchedHandleCount);
                                    if (summary->fileHandleScanIncomplete)
                                        status += ks::i18n::sourceText(QStringLiteral(" | 扫描不完整：部分文件句柄路径查询超时或阻塞。"));
                                    if (!summary->diagnosticText.trimmed().isEmpty()) status += QStringLiteral(" | 存在诊断；详情已写入日志。");
                                    statusGuard->setText(status);
                                    if (!owner) return;
                                    if (progressGuard) progressGuard->setValue(100);
                                    if (refreshGuard) refreshGuard->setEnabled(true);
                                });
                            if (!owner || cancel->load()) return;
                            // Collection completion and the R0 retry remain active while the display is hidden.
                            owner->m_usageScanInProgress = false;
                            if (!summary->diagnosticText.trimmed().isEmpty())
                            {
                                kLogEvent event;
                                warn << event << "[FileDetailDialog] usage scan completed with diagnostics, matchedHandleCount="
                                    << summary->matchedHandleCount << ", diagnostic=" << summary->diagnosticText.toStdString() << eol;
                            }
                            if (!summary->r3HandleFallbackUsed)
                            {
                                owner->m_usageRetryAfterR0Start = false;
                                owner->m_usageR0StartedDuringScan = false;
                            }
                            else if (owner->m_usageR0StartedDuringScan)
                            {
                                owner->m_usageR0StartedDuringScan = false;
                                QMetaObject::invokeMethod(qApp, [owner, tableGuard, statusGuard, refreshGuard, cancel]()
                                    {
                                        if (owner && tableGuard && statusGuard && refreshGuard && !cancel->load())
                                            owner->refreshUsageTable(tableGuard, statusGuard, refreshGuard);
                                    }, Qt::QueuedConnection);
                            }
                            else owner->m_usageRetryAfterR0Start = true;
                        }, Qt::QueuedConnection);
                }));
        }

        void startR0FileInfoLoad(const QFileInfo& info, const QString& ntPathText)
        {
            // 用途：后台读取 R0 文件基础信息，避免常规页构建时阻塞属性窗口打开。
            // 输入：info/ntPathText 为查询目标；界面数据由成员保存，便于语言切换时完整重绘。
            // 处理：工作线程调用 ArkDriverClient；UI 线程保存结果并按当前语言重建正文。
            // 返回：无；对话框关闭或控件释放后自动丢弃结果。
            if (m_generalPropertyView == nullptr)
            {
                return;
            }

            const std::uint64_t loadGeneration = ++m_generalR0LoadGeneration;
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, info, ntPathText, loadGeneration]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const ksword::ark::FileInfoQueryResult r0Info =
                        FileDetailDialog::queryR0FileInfo(info, ntPathText);
                    QMetaObject::invokeMethod(
                        qApp,
                        [guardThis, r0Info, loadGeneration]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->m_generalR0LoadGeneration != loadGeneration)
                            {
                                return;
                            }

                            guardThis->m_generalR0Info = r0Info;
                            guardThis->m_generalR0Loaded = true;
                            guardThis->refreshGeneralTab();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        static FileSecuritySnapshot loadFileSecuritySnapshot(const QString& nativePath)
        {
            // 用途：读取 Owner/Group/DACL/SACL 并生成权限页快照。
            // 输入：nativePath 为 Windows 本机路径；调用者确保在后台线程执行。
            // 处理：同步调用 Windows 安全 API，同时保留旧文本明细和新表格行。
            // 返回：FileSecuritySnapshot；读取失败时 detailText 包含错误码，aceRows 可为空。
            FileSecuritySnapshot snapshot;
            ks::ui::FieldDocument content;
            std::wstring nativePathBuffer = nativePath.toStdWString();

            PSID ownerSid = nullptr;
            PSID groupSid = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            const DWORD queryMask = OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION;
            const DWORD queryResult = ::GetNamedSecurityInfoW(
                nativePathBuffer.data(),
                SE_FILE_OBJECT,
                queryMask,
                &ownerSid,
                &groupSid,
                &dacl,
                nullptr,
                &securityDescriptor);
            snapshot.descriptorError = queryResult;
            if (queryResult != ERROR_SUCCESS)
            {
                content.field(QStringLiteral("深层安全描述符读取失败"), QString::number(queryResult));
            }
            else
            {
                snapshot.descriptorOk = true;
                snapshot.ownerSidText = sidToStringText(ownerSid);
                snapshot.ownerAccountText = sidToAccountText(ownerSid);
                snapshot.groupSidText = sidToStringText(groupSid);
                snapshot.groupAccountText = sidToAccountText(groupSid);

                content.section(QStringLiteral("Owner"));
                content.field(QStringLiteral("SID"), snapshot.ownerSidText);
                content.field(QStringLiteral("账户"), snapshot.ownerAccountText);

                content.section(QStringLiteral("Primary Group"));
                content.field(QStringLiteral("SID"), snapshot.groupSidText);
                content.field(QStringLiteral("账户"), snapshot.groupAccountText);

                appendAclDocument(QStringLiteral("DACL"), dacl, content);
                appendAclRows(QStringLiteral("DACL"), dacl, snapshot.aceRows);
                ::LocalFree(securityDescriptor);
            }

            PSID saclOwnerSid = nullptr;
            PSID saclGroupSid = nullptr;
            PACL sacl = nullptr;
            PSECURITY_DESCRIPTOR saclDescriptor = nullptr;
            const DWORD saclResult = ::GetNamedSecurityInfoW(
                nativePathBuffer.data(),
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION,
                &saclOwnerSid,
                &saclGroupSid,
                nullptr,
                &sacl,
                &saclDescriptor);
            snapshot.saclError = saclResult;
            if (saclResult == ERROR_SUCCESS)
            {
                snapshot.saclOk = true;
                appendAclDocument(QStringLiteral("SACL"), sacl, content);
                appendAclRows(QStringLiteral("SACL"), sacl, snapshot.aceRows);
                ::LocalFree(saclDescriptor);
            }
            else
            {
                content.section(QStringLiteral("SACL"));
                content.field(QStringLiteral("读取失败（通常需要 SeSecurityPrivilege）"), QString::number(saclResult));
            }

            content.note(QStringLiteral("说明：Mask 显示为十六进制，权限列为常见位标志拆解。"));
            snapshot.details = content;
            return snapshot;
        }

        void populateSecurityWidgets(
            QTableWidget* aceTable,
            ks::ui::StructuredFieldView* detailEditor,
            QLabel* statusLabel,
            const ks::ui::FieldDocument& baseContent,
            const FileSecuritySnapshot& snapshot,
            const std::uint64_t generation)
        {
            // 用途：把后台读取的权限快照回填到权限页 UI。
            // 输入：aceTable/detailEditor/statusLabel 为目标控件，snapshot 为读取结果。
            // 处理：表格展示可编辑 DACL ACE，字段视图保留完整描述符和错误码。
            // 返回：无；控件为空时跳过对应更新。
            if (generation != m_securityLoadGeneration) return;
            if (aceTable != nullptr &&
                ks::ui::IsTableUiCommitBlockedByContextMenu({ aceTable }))
            {
                const auto snapshotGuard = std::make_shared<FileSecuritySnapshot>(snapshot);
                const QPointer<FileDetailDialog> safeThis(this);
                const QPointer<QTableWidget> tableGuard(aceTable);
                const QPointer<ks::ui::StructuredFieldView> editorGuard(detailEditor);
                const QPointer<QLabel> statusGuard(statusLabel);
                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    this,
                    QStringLiteral("file-detail-security-snapshot"),
                    { aceTable },
                    [safeThis, tableGuard, editorGuard, statusGuard, baseContent, snapshotGuard, generation]()
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->populateSecurityWidgets(
                                tableGuard,
                                editorGuard,
                                statusGuard,
                                baseContent,
                                *snapshotGuard,
                                generation);
                        }
                    }))
                {
                    return;
                }
            }

            if (aceTable != nullptr)
            {
                aceTable->setSortingEnabled(false);
                aceTable->setRowCount(static_cast<int>(snapshot.aceRows.size()));
                for (int rowIndex = 0; rowIndex < static_cast<int>(snapshot.aceRows.size()); ++rowIndex)
                {
                    const FileSecurityAceRow& row = snapshot.aceRows[static_cast<std::size_t>(rowIndex)];
                    aceTable->setItem(rowIndex, 0, createReadonlyTableItem(row.scopeText));
                    aceTable->setItem(rowIndex, 1, createReadonlyTableItem(QString::number(row.aceIndex)));
                    aceTable->setItem(rowIndex, 2, createReadonlyTableItem(row.typeText));
                    aceTable->setItem(rowIndex, 3, createReadonlyTableItem(row.accountText));
                    aceTable->setItem(rowIndex, 4, createReadonlyTableItem(row.sidText));
                    aceTable->setItem(rowIndex, 5, createReadonlyTableItem(formatAccessMaskHex(row.mask)));
                    aceTable->setItem(rowIndex, 6, createReadonlyTableItem(row.rightsText));
                    aceTable->setItem(rowIndex, 7, createReadonlyTableItem(row.flagsText));
                    aceTable->setItem(rowIndex, 8, createReadonlyTableItem(row.canEdit ? QStringLiteral("可编辑") : QStringLiteral("只读展示")));
                    for (int columnIndex = 0; columnIndex < aceTable->columnCount(); ++columnIndex)
                    {
                        QTableWidgetItem* item = aceTable->item(rowIndex, columnIndex);
                        if (item == nullptr)
                        {
                            continue;
                        }
                        item->setData(Qt::UserRole + 1, row.scopeText);
                        item->setData(Qt::UserRole + 2, static_cast<qulonglong>(row.aceIndex));
                        item->setData(Qt::UserRole + 3, row.sidText);
                        item->setData(Qt::UserRole + 4, row.typeText);
                        item->setData(Qt::UserRole + 5, static_cast<qulonglong>(row.mask));
                        item->setData(Qt::UserRole + 6, row.canEdit);
                    }
                }
                aceTable->setSortingEnabled(true);
                aceTable->resizeColumnsToContents();
            }

            if (detailEditor != nullptr)
            {
                auto doc = baseContent;
                doc.nodes += snapshot.details.nodes;
                detailEditor->setDocument(doc);
            }

            if (statusLabel != nullptr)
            {
                const QString daclState = snapshot.descriptorOk
                    ? QStringLiteral("DACL 已读取")
                    : QStringLiteral("DACL 读取失败:%1").arg(snapshot.descriptorError);
                const QString saclState = snapshot.saclOk
                    ? QStringLiteral("SACL 已读取")
                    : QStringLiteral("SACL 只读失败:%1").arg(snapshot.saclError);
                statusLabel->setText(QStringLiteral("● %1；%2；ACE=%3")
                    .arg(daclState)
                    .arg(saclState)
                    .arg(snapshot.aceRows.size()));
            }
        }

        void startSecurityDeepLoad(
            QTableWidget* aceTable,
            ks::ui::StructuredFieldView* detailEditor,
            QLabel* statusLabel,
            const ks::ui::FieldDocument& baseContent,
            const QString& nativePath)
        {
            // 用途：后台执行深层 ACL/SACL 解析并刷新权限页字段。
            // 输入：baseContent 为快速权限摘要，nativePath 为目标路径。
            // 处理：工作线程读取安全描述符，UI 线程更新表格、状态和字段快照。
            // 返回：无；控件失效时丢弃结果。
            if (aceTable == nullptr || detailEditor == nullptr || statusLabel == nullptr)
            {
                return;
            }

            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTableWidget> tableGuard(aceTable);
            QPointer<ks::ui::StructuredFieldView> editorGuard(detailEditor);
            QPointer<QLabel> statusGuard(statusLabel);
            const auto generation = ++m_securityLoadGeneration;
            auto* task = QRunnable::create([guardThis, tableGuard, editorGuard, statusGuard, baseContent, nativePath, generation]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    const FileSecuritySnapshot snapshot = FileDetailDialog::loadFileSecuritySnapshot(nativePath);
                    QMetaObject::invokeMethod(
                        qApp,
                        [guardThis, tableGuard, editorGuard, statusGuard, baseContent, snapshot, generation]()
                        {
                            if (guardThis != nullptr)
                            {
                                guardThis->populateSecurityWidgets(
                                    tableGuard,
                                    editorGuard,
                                    statusGuard,
                                    baseContent,
                                    snapshot,
                                    generation);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        DWORD maskFromSecurityPreset(const int presetIndex)
        {
            // 用途：把权限预设下拉框映射为 Windows 文件访问掩码。
            // 输入：presetIndex 为 QComboBox 当前索引。
            // 处理：优先覆盖常见文件安全页语义，减少用户手工拼位需求。
            // 返回：FILE_* / 标准权限组合掩码。
            switch (presetIndex)
            {
            case 0:
                return FILE_GENERIC_READ;
            case 1:
                return FILE_GENERIC_WRITE;
            case 2:
                return FILE_GENERIC_READ | FILE_GENERIC_WRITE;
            case 3:
                return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
            case 4:
                return FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
            case 5:
                return FILE_ALL_ACCESS;
            default:
                return FILE_GENERIC_READ;
            }
        }

        DWORD maskFromSecurityChecks(
            QCheckBox* readCheck,
            QCheckBox* writeCheck,
            QCheckBox* executeCheck,
            QCheckBox* deleteCheck,
            QCheckBox* writeDacCheck,
            QCheckBox* writeOwnerCheck)
        {
            // 用途：把高级复选框合成为访问掩码。
            // 输入：各权限复选框控件，可为空。
            // 处理：只采纳勾选的权限位；未勾选时返回 0。
            // 返回：访问掩码。
            DWORD mask = 0;
            if (readCheck != nullptr && readCheck->isChecked()) mask |= FILE_GENERIC_READ;
            if (writeCheck != nullptr && writeCheck->isChecked()) mask |= FILE_GENERIC_WRITE;
            if (executeCheck != nullptr && executeCheck->isChecked()) mask |= FILE_GENERIC_EXECUTE;
            if (deleteCheck != nullptr && deleteCheck->isChecked()) mask |= DELETE;
            if (writeDacCheck != nullptr && writeDacCheck->isChecked()) mask |= WRITE_DAC;
            if (writeOwnerCheck != nullptr && writeOwnerCheck->isChecked()) mask |= WRITE_OWNER;
            return mask;
        }

        DWORD inheritanceFlagsFromCombo(const int inheritIndex)
        {
            // 用途：把继承范围下拉框映射为 EXPLICIT_ACCESS 继承标志。
            // 输入：inheritIndex 为 QComboBox 当前索引。
            // 处理：文件默认不继承，目录可选择子对象继承。
            // 返回：NO_INHERITANCE / SUB_CONTAINERS_AND_OBJECTS_INHERIT 等标志。
            switch (inheritIndex)
            {
            case 1:
                return SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            case 2:
                return SUB_OBJECTS_ONLY_INHERIT;
            case 3:
                return SUB_CONTAINERS_ONLY_INHERIT;
            default:
                return NO_INHERITANCE;
            }
        }

        bool extractAceSidAndType(LPVOID acePointer, BYTE* aceTypeOut, PSID* sidOut)
        {
            // 用途：从常见 ACE 结构取出 AceType 与 SID 指针。
            // 输入：acePointer 来自 GetAce。
            // 处理：只解析当前 UI 支持删除的 DACL ACE 类型。
            // 返回：成功解析返回 true；未知类型返回 false。
            if (acePointer == nullptr || aceTypeOut == nullptr || sidOut == nullptr)
            {
                return false;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            *aceTypeOut = aceHeader->AceType;
            *sidOut = nullptr;
            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
                *sidOut = reinterpret_cast<PSID>(&reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer)->SidStart);
                return true;
            case ACCESS_DENIED_ACE_TYPE:
                *sidOut = reinterpret_cast<PSID>(&reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer)->SidStart);
                return true;
            default:
                return false;
            }
        }

        DWORD applySecurityAceChange(
            const QString& accountText,
            const DWORD accessMask,
            const ACCESS_MODE accessMode,
            const DWORD inheritanceFlags,
            QString& detailTextOut)
        {
            // 用途：添加或设置一个 DACL ACE。
            // 输入：accountText 为账户名或 SID 字符串，accessMask 为权限掩码，accessMode 为允许/拒绝模式。
            // 处理：读取现有 DACL，调用 SetEntriesInAclW 合成新 DACL，再写回文件对象。
            // 返回：Win32 错误码；ERROR_SUCCESS 表示写入成功。
            const QString normalizedAccount = accountText.trimmed();
            if (normalizedAccount.isEmpty())
            {
                detailTextOut = QStringLiteral("账户不能为空。可填写 DOMAIN\\User、BUILTIN\\Administrators 或 S-1-...。");
                return ERROR_INVALID_PARAMETER;
            }
            if (accessMask == 0)
            {
                detailTextOut = QStringLiteral("权限掩码为 0，未执行写入。");
                return ERROR_INVALID_PARAMETER;
            }

            std::wstring pathBuffer = QDir::toNativeSeparators(m_filePath).toStdWString();
            PACL oldDacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            DWORD result = ::GetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &oldDacl,
                nullptr,
                &securityDescriptor);
            if (result != ERROR_SUCCESS)
            {
                detailTextOut = QStringLiteral("读取现有 DACL 失败，code=%1。").arg(result);
                return result;
            }

            std::wstring accountBuffer = normalizedAccount.toStdWString();
            PSID trusteeSid = nullptr;
            const bool accountLooksLikeSid = normalizedAccount.startsWith(QStringLiteral("S-"), Qt::CaseInsensitive);
            if (accountLooksLikeSid)
            {
                if (::ConvertStringSidToSidW(accountBuffer.c_str(), &trusteeSid) == FALSE || trusteeSid == nullptr)
                {
                    result = ::GetLastError();
                    if (securityDescriptor != nullptr)
                    {
                        ::LocalFree(securityDescriptor);
                    }
                    detailTextOut = QStringLiteral("SID 字符串解析失败，code=%1，SID=%2。")
                        .arg(result)
                        .arg(normalizedAccount);
                    return result;
                }
            }

            EXPLICIT_ACCESS_W explicitAccess{};
            explicitAccess.grfAccessPermissions = accessMask;
            explicitAccess.grfAccessMode = accessMode;
            explicitAccess.grfInheritance = inheritanceFlags;
            explicitAccess.Trustee.TrusteeForm = accountLooksLikeSid ? TRUSTEE_IS_SID : TRUSTEE_IS_NAME;
            explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            explicitAccess.Trustee.ptstrName = accountLooksLikeSid
                ? reinterpret_cast<LPWSTR>(trusteeSid)
                : accountBuffer.data();

            PACL newDacl = nullptr;
            result = ::SetEntriesInAclW(1, &explicitAccess, oldDacl, &newDacl);
            if (result == ERROR_SUCCESS)
            {
                result = ::SetNamedSecurityInfoW(
                    pathBuffer.data(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr,
                    nullptr,
                    newDacl,
                    nullptr);
            }

            if (newDacl != nullptr)
            {
                ::LocalFree(newDacl);
            }
            if (trusteeSid != nullptr)
            {
                ::LocalFree(trusteeSid);
            }
            if (securityDescriptor != nullptr)
            {
                ::LocalFree(securityDescriptor);
            }

            detailTextOut = result == ERROR_SUCCESS
                ? QStringLiteral("已写入 DACL：账户=%1，模式=%2，Mask=%3，继承标志=0x%4。")
                    .arg(normalizedAccount)
                    .arg(accessMode == DENY_ACCESS ? QStringLiteral("拒绝") : QStringLiteral("允许/设置"))
                    .arg(formatAccessMaskHex(accessMask))
                    .arg(inheritanceFlags, 0, 16)
                : QStringLiteral("写入 DACL 失败，code=%1。账户=%2，Mask=%3。")
                    .arg(result)
                    .arg(normalizedAccount)
                    .arg(formatAccessMaskHex(accessMask));
            return result;
        }

        DWORD deleteSelectedDaclAce(QTableWidget* aceTable, QString& detailTextOut)
        {
            // 用途：删除权限表中当前选中的非继承 DACL ACE。
            // 输入：aceTable 为权限页 ACE 表格，当前行保存 SID/类型/序号元数据。
            // 处理：读取现有 DACL，复制除目标 ACE 外的原始 ACE 字节，最后 SetNamedSecurityInfoW 写回。
            // 返回：Win32 错误码；ERROR_SUCCESS 表示删除成功。
            if (aceTable == nullptr || aceTable->currentRow() < 0)
            {
                detailTextOut = QStringLiteral("请先在 DACL 表格中选择一条可编辑 ACE。");
                return ERROR_INVALID_PARAMETER;
            }

            const int rowIndex = aceTable->currentRow();
            QTableWidgetItem* firstItem = aceTable->item(rowIndex, 0);
            if (firstItem == nullptr)
            {
                detailTextOut = QStringLiteral("选中行无元数据，无法删除。");
                return ERROR_INVALID_PARAMETER;
            }

            const QString scopeText = firstItem->data(Qt::UserRole + 1).toString();
            const DWORD selectedAceIndex = firstItem->data(Qt::UserRole + 2).toUInt();
            const QString selectedSidText = firstItem->data(Qt::UserRole + 3).toString();
            const QString selectedTypeText = firstItem->data(Qt::UserRole + 4).toString();
            const bool canEdit = firstItem->data(Qt::UserRole + 6).toBool();
            if (scopeText != QStringLiteral("DACL") || !canEdit)
            {
                detailTextOut = QStringLiteral("当前 ACE 只能展示，不能由此按钮修改。继承 ACE、SACL 和对象 ACE 需要在来源对象或审计页处理。");
                return ERROR_ACCESS_DENIED;
            }

            std::wstring pathBuffer = QDir::toNativeSeparators(m_filePath).toStdWString();
            PACL oldDacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            DWORD result = ::GetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &oldDacl,
                nullptr,
                &securityDescriptor);
            if (result != ERROR_SUCCESS)
            {
                detailTextOut = QStringLiteral("读取现有 DACL 失败，code=%1。").arg(result);
                return result;
            }
            if (oldDacl == nullptr)
            {
                if (securityDescriptor != nullptr)
                {
                    ::LocalFree(securityDescriptor);
                }
                detailTextOut = QStringLiteral("当前 DACL 为空，无法删除 ACE。");
                return ERROR_NOT_FOUND;
            }

            ACL_SIZE_INFORMATION aclSizeInfo{};
            if (::GetAclInformation(oldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation) == FALSE)
            {
                result = ::GetLastError();
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("读取 ACL 信息失败，code=%1。").arg(result);
                return result;
            }

            DWORD newAclBytes = sizeof(ACL);
            bool targetFound = false;
            for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
            {
                LPVOID acePointer = nullptr;
                if (::GetAce(oldDacl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                {
                    result = ::GetLastError();
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("读取 ACE[%1] 失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }

                ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
                BYTE aceType = 0;
                PSID aceSid = nullptr;
                const bool sidOk = extractAceSidAndType(acePointer, &aceType, &aceSid);
                const bool isTarget = sidOk
                    && aceIndex == selectedAceIndex
                    && aceTypeToText(aceType) == selectedTypeText
                    && sidToStringText(aceSid) == selectedSidText
                    && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                if (isTarget)
                {
                    targetFound = true;
                    continue;
                }
                newAclBytes += aceHeader->AceSize;
            }

            if (!targetFound)
            {
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("未在当前 DACL 中找到匹配 ACE，可能权限已被其它进程修改。请刷新后重试。");
                return ERROR_NOT_FOUND;
            }

            PACL newDacl = reinterpret_cast<PACL>(::LocalAlloc(LPTR, newAclBytes));
            if (newDacl == nullptr)
            {
                result = ::GetLastError();
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("分配新 DACL 失败，code=%1。").arg(result);
                return result;
            }

            const DWORD aclRevision = oldDacl->AclRevision;
            if (::InitializeAcl(newDacl, newAclBytes, aclRevision) == FALSE)
            {
                result = ::GetLastError();
                ::LocalFree(newDacl);
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("初始化新 DACL 失败，code=%1。").arg(result);
                return result;
            }

            for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
            {
                LPVOID acePointer = nullptr;
                if (::GetAce(oldDacl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                {
                    result = ::GetLastError();
                    ::LocalFree(newDacl);
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("复制 ACE[%1] 前读取失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }

                ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
                BYTE aceType = 0;
                PSID aceSid = nullptr;
                const bool sidOk = extractAceSidAndType(acePointer, &aceType, &aceSid);
                const bool isTarget = sidOk
                    && aceIndex == selectedAceIndex
                    && aceTypeToText(aceType) == selectedTypeText
                    && sidToStringText(aceSid) == selectedSidText
                    && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                if (isTarget)
                {
                    continue;
                }
                if (::AddAce(newDacl, aclRevision, MAXDWORD, acePointer, aceHeader->AceSize) == FALSE)
                {
                    result = ::GetLastError();
                    ::LocalFree(newDacl);
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("复制 ACE[%1] 到新 DACL 失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }
            }

            result = ::SetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                newDacl,
                nullptr);
            ::LocalFree(newDacl);
            ::LocalFree(securityDescriptor);

            detailTextOut = result == ERROR_SUCCESS
                ? QStringLiteral("已删除 ACE[%1]：%2 | %3。").arg(selectedAceIndex).arg(selectedTypeText, selectedSidText)
                : QStringLiteral("删除 ACE 写回失败，code=%1。").arg(result);
            return result;
        }

        static QPair<QString, QString> signatureTrustPresentation(
            const ks::file::metadata::SignatureInspection& signature)
        {
            switch (signature.trustStatus)
            {
            case ERROR_SUCCESS:
                return {QStringLiteral("签名有效，受信任"), QStringLiteral("文件签名通过本机 Windows 信任验证。")};
            case TRUST_E_NOSIGNATURE:
                if (signature.embedded)
                    return {QStringLiteral("签名无法识别"), QStringLiteral("存在证书表，但未能识别可验证的文件签名。")};
                if (signature.catalog)
                    return {QStringLiteral("Catalog 签名待验证"), QStringLiteral("已找到 Catalog 文件，文件签名验证未通过；Catalog 信任状态尚未确认。")};
                return {QStringLiteral("未签名"), QStringLiteral("未找到可验证的文件签名。")};
            case TRUST_E_BAD_DIGEST:
                return {QStringLiteral("签名摘要不匹配"), QStringLiteral("文件内容与签名摘要不一致，可能已被修改或损坏。")};
            case CERT_E_UNTRUSTEDROOT:
            case CERT_E_CHAINING:
            case TRUST_E_SUBJECT_NOT_TRUSTED:
                return {QStringLiteral("不受信任"), QStringLiteral("签名未通过本机信任策略，或无法构建受信任的证书链。")};
            case CERT_E_EXPIRED:
                return {QStringLiteral("证书已过期或尚未生效"), QStringLiteral("证书在验证所采用的时间点不处于有效期内。")};
            case CERT_E_REVOKED:
                return {QStringLiteral("证书已吊销"), QStringLiteral("签名证书已被吊销，验证未通过。")};
            case CRYPT_E_REVOCATION_OFFLINE:
            case CERT_E_REVOCATION_FAILURE:
                return {QStringLiteral("吊销状态无法确认"), QStringLiteral("本机缓存不足以完成吊销检查，不能确认签名受信任。")};
            default:
                return {QStringLiteral("签名验证失败"), QStringLiteral("无法完成签名信任验证，请展开详细信息查看状态码与证据。")};
            }
        }

        static ks::ui::FieldDocument signatureEvidenceDocument(
            const ksword::ark::ImageSignatureQueryResult& result)
        {
            ks::ui::FieldDocument doc;
            doc.section(QStringLiteral("R0 内核原始证据"));
            doc.field(QStringLiteral("source"), QStringLiteral("R0 direct PE Security Directory (WinTrust not used)"));
            doc.field(QStringLiteral("communication.ok"), result.io.ok ? QStringLiteral("true") : QStringLiteral("false"));
            doc.field(QStringLiteral("communication.win32_error"), QString::number(result.io.win32Error));
            doc.field(QStringLiteral("communication.bytes_returned"), QString::number(result.io.bytesReturned));
            doc.field(QStringLiteral("communication.unsupported"), result.unsupported ? QStringLiteral("true") : QStringLiteral("false"));
            doc.field(QStringLiteral("communication.detail"), QString::fromStdString(result.io.message));
            if (!result.io.ok) return doc;
            const auto& r = result.response;
            doc.field(QStringLiteral("protocol.version"), QString::number(r.version));
            doc.field(QStringLiteral("protocol.size"), QString::number(r.size));
            doc.field(QStringLiteral("query.status"), QString::number(r.queryStatus));
            doc.field(QStringLiteral("file.size"), QString::number(r.fileSize));
            doc.field(QStringLiteral("certificate_table.count"), QString::number(r.certificateCount));
            doc.field(QStringLiteral("certificate_table.returned_count"), QString::number(r.returnedCertificateCount));
            doc.field(QStringLiteral("certificate_table.pkcs7_count"), QString::number(r.pkcs7CertificateCount));
            doc.field(QStringLiteral("certificate_table.nested_signature_oid_count"), QString::number(r.nestedSignatureCount));
            doc.field(QStringLiteral("certificate_table.bytes_scanned"), QString::number(r.certificateBytesScanned));
            doc.field(QStringLiteral("ci.cached_signing_level"), QString::number(r.signingLevel));
            doc.field(QStringLiteral("query.flags"), formatHex64(static_cast<std::uint64_t>(r.requestFlags)));
            doc.field(QStringLiteral("query.field_flags"), formatHex64(static_cast<std::uint64_t>(r.fieldFlags)));
            doc.field(QStringLiteral("pe.structural_flags"), formatHex64(static_cast<std::uint64_t>(r.structuralFlags)));
            doc.field(QStringLiteral("status.open"), formatNtStatus(r.openStatus));
            doc.field(QStringLiteral("status.file_size"), formatNtStatus(r.fileSizeStatus));
            doc.field(QStringLiteral("status.file_object"), formatNtStatus(r.objectStatus));
            doc.field(QStringLiteral("status.pe_parse"), formatNtStatus(r.parseStatus));
            doc.field(QStringLiteral("status.certificate_table"), formatNtStatus(r.certificateStatus));
            doc.field(QStringLiteral("status.cached_signing_level"), formatNtStatus(r.signingLevelStatus));
            doc.field(QStringLiteral("status.loaded_module_match"), formatNtStatus(r.loadedModuleStatus));
            doc.field(QStringLiteral("pe.header_offset"), formatHex64(static_cast<std::uint64_t>(r.peHeaderOffset)));
            doc.field(QStringLiteral("pe.machine"), formatHex64(static_cast<std::uint64_t>(r.peMachine)));
            doc.field(QStringLiteral("pe.optional_magic"), formatHex64(static_cast<std::uint64_t>(r.optionalHeaderMagic)));
            doc.field(QStringLiteral("pe.size_of_headers"), formatHex64(static_cast<std::uint64_t>(r.sizeOfHeaders)));
            doc.field(QStringLiteral("certificate_table.file_offset"), formatHex64(static_cast<std::uint64_t>(r.certificateTableOffset)));
            doc.field(QStringLiteral("certificate_table.size"), formatHex64(static_cast<std::uint64_t>(r.certificateTableSize)));
            doc.field(QStringLiteral("loaded.expected_base"), formatHex64(static_cast<std::uint64_t>(r.expectedModuleBase)));
            doc.field(QStringLiteral("loaded.matched_base"), formatHex64(static_cast<std::uint64_t>(r.matchedModuleBase)));
            doc.field(QStringLiteral("loaded.matched_size"), formatHex64(static_cast<std::uint64_t>(r.matchedModuleSize)));
            doc.field(QStringLiteral("ci.cached_signing_flags"), formatHex64(static_cast<std::uint64_t>(r.signingLevelFlags)));
            doc.field(QStringLiteral("ci.thumbprint_algorithm"), formatHex64(static_cast<std::uint64_t>(r.thumbprintAlgorithm)));
            doc.field(QStringLiteral("pe.certificate_table_present"), (r.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_CERTIFICATE_TABLE) != 0UL ? QStringLiteral("true") : QStringLiteral("false"));
            doc.field(QStringLiteral("pe.nested_signature_oid_present"), (r.structuralFlags & KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_NESTED_SIGNATURE_PRESENT) != 0UL ? QStringLiteral("true") : QStringLiteral("false"));
            doc.field(QStringLiteral("loaded.module_base_match"), (r.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE) != 0UL ? QStringLiteral("true") : QStringLiteral("false"));
            doc.field(QStringLiteral("loaded.module_name_match"), (r.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH) != 0UL ? QStringLiteral("true") : QStringLiteral("false"));
            doc.field(QStringLiteral("ci.cached_signing_level_present"), (r.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SIGNING_LEVEL) != 0UL ? QStringLiteral("true") : QStringLiteral("false"));
            QStringList findings;
            const auto appendFinding = [&findings, &r](unsigned long flag, const QString& name)
                { if ((r.structuralFlags & flag) != 0UL) findings.append(name); };
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_UNALIGNED, QStringLiteral("cert_table_unaligned"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OUT_OF_RANGE, QStringLiteral("cert_table_out_of_range"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_HEADER_TRUNCATED, QStringLiteral("entry_header_truncated"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_LENGTH_INVALID, QStringLiteral("entry_length_invalid"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_RANGE_INVALID, QStringLiteral("entry_range_invalid"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_REVISION, QStringLiteral("unknown_revision"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_TYPE, QStringLiteral("unknown_certificate_type"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_OUTPUT_TRUNCATED, QStringLiteral("entry_output_truncated"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_TRAILING_BYTES, QStringLiteral("trailing_bytes"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_PADDING_NONZERO, QStringLiteral("certificate_padding_nonzero"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_SCAN_LIMIT_REACHED, QStringLiteral("scan_limit_reached"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_NESTED_SIGNATURE_PRESENT, QStringLiteral("nested_signature_oid_present"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_MULTIPLE_PKCS7_ENTRIES, QStringLiteral("multiple_pkcs7_entries"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERTIFICATE_READ_FAILED, QStringLiteral("certificate_read_failed"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH, QStringLiteral("loaded_name_mismatch"));
            appendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OVERLAPS_HEADERS, QStringLiteral("cert_table_overlaps_headers"));
            doc.field(QStringLiteral("pe.structural_findings"), findings.isEmpty() ? QStringLiteral("none") : findings.join(QLatin1Char(',')));
            const auto thumbprintSize = std::min<std::size_t>(r.thumbprintSize, sizeof(r.thumbprint));
            const QByteArray thumbprint(reinterpret_cast<const char*>(r.thumbprint), static_cast<qsizetype>(thumbprintSize));
            doc.field(QStringLiteral("ci.thumbprint"), thumbprint.isEmpty() ? QStringLiteral("<unavailable>") : QString::fromLatin1(thumbprint.toHex()));
            const auto entryCount = std::min<std::size_t>(r.returnedCertificateCount, KSWORD_ARK_IMAGE_SIGNATURE_MAX_ENTRIES);
            for (std::size_t index = 0; index < entryCount; ++index)
            {
                const auto& entry = r.certificates[index];
                doc.section(QStringLiteral("certificate[%1]").arg(index));
                doc.field(QStringLiteral("file_offset"), formatHex64(static_cast<std::uint64_t>(entry.fileOffset)));
                doc.field(QStringLiteral("length"), formatHex64(static_cast<std::uint64_t>(entry.length)));
                doc.field(QStringLiteral("aligned_length"), formatHex64(static_cast<std::uint64_t>(entry.alignedLength)));
                doc.field(QStringLiteral("revision"), formatHex64(static_cast<std::uint64_t>(entry.revision)));
                doc.field(QStringLiteral("type"), formatHex64(static_cast<std::uint64_t>(entry.certificateType)));
                doc.field(QStringLiteral("flags"), formatHex64(static_cast<std::uint64_t>(entry.flags)));
                doc.field(QStringLiteral("content_fnv1a64_noncrypto"), formatHex64(static_cast<std::uint64_t>(entry.contentHashFnv1a64)));
                doc.field(QStringLiteral("read_status"), formatNtStatus(entry.readStatus));
                doc.field(QStringLiteral("nested_signature_oid_count"), QString::number(entry.nestedSignatureCount));
                doc.field(QStringLiteral("content_bytes_scanned"), QString::number(entry.contentBytesScanned));
            }
            return doc;
        }

        void startSignatureLoad(QWidget* page, QLabel* stateLabel, QLabel* hintLabel,
            const QVector<QPointer<QLabel>>& values, ks::ui::StructuredFieldView* evidenceEditor)
        {
            const QString filePathSnapshot = m_filePath;
            const QString ntPathSnapshot = buildDriverNtPath(filePathSnapshot);
            const QPointer<QWidget> pageGuard(page);
            const QPointer<FileDetailDialog> dialogGuard(this);
            const QPointer<QLabel> stateGuard(stateLabel), hintGuard(hintLabel);
            const QPointer<ks::ui::StructuredFieldView> evidenceGuard(evidenceEditor);
            auto* task = QRunnable::create([pageGuard, dialogGuard, stateGuard, hintGuard, values, evidenceGuard,
                filePathSnapshot, ntPathSnapshot]()
                {
                    const auto signature = ks::file::metadata::inspectSignature(filePathSnapshot);
                    if (pageGuard == nullptr) return;
                    QMetaObject::invokeMethod(qApp, [pageGuard, dialogGuard, stateGuard, hintGuard, values, signature]()
                        {
                            if (pageGuard == nullptr || stateGuard == nullptr || hintGuard == nullptr) return;
                            if (dialogGuard == nullptr) return;
                            dialogGuard->m_signatureLanguageRefresh = [stateGuard, hintGuard, values, signature]()
                            {
                                if (stateGuard == nullptr || hintGuard == nullptr) return;
                            const auto presentation = signatureTrustPresentation(signature);
                            stateGuard->setText(ks::i18n::sourceText(presentation.first));
                            hintGuard->setText(ks::i18n::sourceText(presentation.second));
                            ks::ui::ApplyStatusRole(stateGuard, signature.trustStatus == ERROR_SUCCESS
                                ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
                            const QString unavailable = ks::i18n::sourceText(QStringLiteral("未获取到"));
                            const QString yes = ks::i18n::sourceText(QStringLiteral("是"));
                            const QString no = ks::i18n::sourceText(QStringLiteral("否"));
                            const QStringList texts{
                                signature.issuer.isEmpty() ? unavailable : signature.issuer,
                                signature.signer.isEmpty() ? unavailable : signature.signer,
                                signature.signingTime.isEmpty()
                                    ? ks::i18n::sourceText(QStringLiteral("未获取到可信时间戳")) : signature.signingTime,
                                signature.embedded ? yes : no,
                                signature.catalog ? yes : no,
                                signature.catalogPath.isEmpty() ? unavailable : signature.catalogPath,
                                signature.sha256Fingerprint.isEmpty() ? unavailable : signature.sha256Fingerprint,
                                signature.validFrom.isEmpty() ? unavailable : signature.validFrom,
                                signature.validUntil.isEmpty() ? unavailable : signature.validUntil,
                                signature.timestampSigner.isEmpty() ? unavailable : signature.timestampSigner,
                                QStringLiteral("0x%1").arg(static_cast<quint32>(signature.trustStatus), 8, 16, QLatin1Char('0')),
                                signature.chainStatus.isEmpty() ? unavailable : signature.chainStatus};
                            for (qsizetype index = 0; index < values.size(); ++index)
                                if (values.at(index) != nullptr) values.at(index)->setText(texts.at(index));
                            };
                            dialogGuard->m_signatureLanguageRefresh();
                        }, Qt::QueuedConnection);

                    // R3 结果先回填，内核查询慢或不可用时不阻挡签名摘要。
                    ks::ui::FieldDocument evidence;
                    if (ntPathSnapshot.isEmpty())
                        evidence.note(QStringLiteral("无法生成供内核使用的 NT 路径。"));
                    else
                        evidence = signatureEvidenceDocument(ksword::ark::DriverClient().queryImageSignature(ntPathSnapshot.toStdWString()));
                    if (pageGuard == nullptr) return;
                    QMetaObject::invokeMethod(qApp, [pageGuard, dialogGuard, evidenceGuard, evidence]()
                        {
                            if (pageGuard != nullptr && dialogGuard != nullptr && evidenceGuard != nullptr)
                                evidenceGuard->setDocument(evidence);
                        }, Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        static QThreadPool& peAnalysisPool()
        {
            static QThreadPool* pool = []() { auto* value = new QThreadPool(qApp); value->setMaxThreadCount(2); return value; }();
            return *pool;
        }

        void startPeAnalysisLoad(ks::ui::StructuredFieldView* textEditorWidget)
        {
            // 用途：后台执行 PE 深度解析，返回分组字段快照。
            // 输入：textEditorWidget 为 PE 信息页显示目标。
            // 处理：调用 FilePropertyPeAnalyzer，避免 Import/Export/Directory 解析卡住 UI。
            // 返回：无。
            if (textEditorWidget == nullptr)
            {
                return;
            }

            if (m_peReadCancel) m_peReadCancel->store(true);
            const auto cancel = m_peReadCancel = std::make_shared<std::atomic_bool>(false);
            const QPointer<FileDetailDialog> guardThis(this);
            const QPointer<ks::ui::StructuredFieldView> editorGuard(textEditorWidget);
            connect(textEditorWidget, &QObject::destroyed, [cancel]() { cancel->store(true); });
            ks::ui::FieldDocument loading;
            loading.note(QStringLiteral("PE 信息加载中..."));
            loading.field(QStringLiteral("目标"), QDir::toNativeSeparators(m_filePath));
            textEditorWidget->setDocument(loading);
            if (!guardThis || !editorGuard) return;
            const QString filePathSnapshot = m_filePath;
            auto* task = QRunnable::create([guardThis, editorGuard, filePathSnapshot, cancel]()
                {
                    if (cancel->load()) return;
                    const auto peDocument = std::shared_ptr<const ks::ui::FieldDocument>(
                        new ks::ui::FieldDocument(file_dock_detail::buildPeAnalysisDocument(filePathSnapshot, cancel)),
                        [](const auto* value) { QThreadPool::globalInstance()->start(QRunnable::create([value]() { delete value; })); });
                    if (cancel->load()) return;
                    QMetaObject::invokeMethod(
                        qApp,
                        [guardThis, editorGuard, peDocument, filePathSnapshot, cancel]()
                        {
                            if (guardThis != nullptr && editorGuard != nullptr && !cancel->load() && guardThis->m_filePath == filePathSnapshot)
                            {
                                editorGuard->setDocument(*peDocument);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            peAnalysisPool().start(task);
        }

        static PrintableStringsPreview extractPrintableStringsPreview(
            const QString& filePath, const QString& query, const bool useRegex,
            const bool caseSensitive, const int minimumLength, const bool scanAscii,
            const bool scanUtf16, const std::shared_ptr<std::atomic_bool>& cancel,
            const std::function<void(qint64, qint64)>& progress = {})
        {
            PrintableStringsPreview result;
            QRegularExpression expression(query, caseSensitive ? QRegularExpression::NoPatternOption
                : QRegularExpression::CaseInsensitiveOption);
            if (useRegex && !expression.isValid())
            {
                result.errorText = ks::i18n::sourceText(QStringLiteral("正则表达式无效：%1"))
                    .arg(expression.errorString());
                return result;
            }
            QFile file(filePath);
            if (!file.open(QIODevice::ReadOnly))
            {
                result.errorText = file.errorString();
                return result;
            }
            result.fileBytes = file.size();
            struct Run { QString text; qint64 start = 0; qint64 lastMatch = -1; };
            Run ascii, utf16[2];
            constexpr qsizetype maxCandidateChars = 65536;
            constexpr qsizetype maxRows = 20000;
            const Qt::CaseSensitivity sensitivity = caseSensitive ? Qt::CaseSensitive : Qt::CaseInsensitive;
            const auto emitRun = [&](Run& run, const int width, const QString& encoding)
                {
                    if (run.text.size() < minimumLength) return;
                    qsizetype matchPosition = 0;
                    // 超长连续字符串分段时保留重叠，避免普通搜索跨片段丢失；不重复同一命中。
                    const qsizetype searchFrom = run.lastMatch >= run.start
                        ? static_cast<qsizetype>((run.lastMatch - run.start) / width + 1) : 0;
                    if (!query.isEmpty())
                    {
                        matchPosition = useRegex ? expression.match(run.text, searchFrom).capturedStart()
                            : run.text.indexOf(query, searchFrom, sensitivity);
                        if (matchPosition < 0) return;
                    }
                    const qint64 offset = run.start + matchPosition * width;
                    run.lastMatch = offset;
                    ++result.matchedCount;
                    if (result.matches.size() < maxRows)
                    {
                        const qsizetype previewStart = std::max<qsizetype>(0, matchPosition - 128);
                        result.matches.append({offset, encoding, run.text.mid(previewStart, 1024)});
                    }
                };
            const auto feed = [&](Run& run, const QChar character, const bool printable,
                const qint64 offset, const int width, const QString& encoding)
                {
                    if (!printable)
                    {
                        emitRun(run, width, encoding);
                        run.text.clear();
                        run.lastMatch = -1;
                        return;
                    }
                    if (run.text.isEmpty()) run.start = offset;
                    run.text.append(character);
                    if (run.text.size() >= maxCandidateChars)
                    {
                        emitRun(run, width, encoding);
                        const qsizetype overlap = query.isEmpty() ? 0
                            : std::min<qsizetype>(maxCandidateChars - 1, std::max<qsizetype>(4096, query.size()));
                        const qsizetype consumed = run.text.size() - overlap;
                        run.text.remove(0, consumed);
                        run.start += consumed * width;
                    }
                };
            QElapsedTimer progressTimer;
            progressTimer.start();
            unsigned char previousByte = 0;
            while (!file.atEnd())
            {
                if (cancel != nullptr && cancel->load()) { result.cancelled = true; break; }
                const QByteArray bytes = file.read(1024 * 1024);
                if (bytes.isEmpty())
                {
                    if (file.error() != QFileDevice::NoError) result.errorText = file.errorString();
                    break;
                }
                for (qsizetype index = 0; index < bytes.size(); ++index)
                {
                    if ((index & 4095) == 0 && cancel != nullptr && cancel->load())
                    {
                        result.cancelled = true;
                        break;
                    }
                    const auto byte = static_cast<unsigned char>(bytes.at(index));
                    const qint64 offset = result.scannedBytes;
                    if (scanAscii)
                        feed(ascii, QChar::fromLatin1(static_cast<char>(byte)), byte >= 0x20 && byte <= 0x7e,
                            offset, 1, QStringLiteral("ASCII"));
                    if (scanUtf16 && offset > 0)
                    {
                        const QChar character(static_cast<ushort>(previousByte | (static_cast<unsigned int>(byte) << 8)));
                        feed(utf16[(offset - 1) & 1], character, character.isPrint(), offset - 1, 2,
                            QStringLiteral("UTF-16LE"));
                    }
                    previousByte = byte;
                    ++result.scannedBytes;
                }
                if (result.cancelled) break;
                if (progress && progressTimer.elapsed() >= 500)
                {
                    progress(result.scannedBytes, result.fileBytes);
                    progressTimer.restart();
                }
            }
            if (scanAscii) emitRun(ascii, 1, QStringLiteral("ASCII"));
            if (scanUtf16)
                for (Run& run : utf16) emitRun(run, 2, QStringLiteral("UTF-16LE"));
            return result;
        }

        static QString dependencyRowsToClipboardText(QTableView* table, const bool dllOnly)
        {
            // 用途：把依赖 DLL 表格选中行转换为剪贴板文本。
            // 输入：table 为依赖页表格，dllOnly 控制只复制 DLL 名称还是整行。
            // 返回：以换行分隔的文本；没有选中行时返回空字符串。
            if (table == nullptr)
            {
                return QString();
            }

            std::set<int> selectedRows;
            if (table->selectionModel() != nullptr)
            {
                const QModelIndexList rowIndexes = table->selectionModel()->selectedRows();
                for (const QModelIndex& index : rowIndexes)
                {
                    selectedRows.insert(index.row());
                }
            }
            if (selectedRows.empty() && table->currentIndex().row() >= 0)
            {
                selectedRows.insert(table->currentIndex().row());
            }

            QStringList lines;
            QStringList seenDllNames;
            for (const int rowIndex : selectedRows)
            {
                if (rowIndex < 0 || rowIndex >= table->model()->rowCount())
                {
                    continue;
                }
                if (dllOnly)
                {
                    const QString dllName = propertyCell(table, rowIndex, 0).toString().trimmed();
                    if (!dllName.isEmpty() && !seenDllNames.contains(dllName, Qt::CaseInsensitive))
                    {
                        seenDllNames.push_back(dllName);
                        lines.push_back(dllName);
                    }
                    continue;
                }

                QStringList columns;
                for (int columnIndex = 0; columnIndex < table->model()->columnCount(); ++columnIndex)
                {
                    columns.push_back(propertyCell(table, rowIndex, columnIndex).toString());
                }
                lines.push_back(columns.join('\t'));
            }
            return lines.join('\n');
        }

        void populateDependencyTable(QTableView* table, QLabel* statusLabel, const file_dock_detail::PeDependencyResult& result, const qint64 elapsedMs)
        {
            // 用途：把后台解析出的依赖 DLL 结果填入表格。
            // 输入：table/statusLabel 为 UI 控件，result 为结构化导入表，elapsedMs 为解析耗时。
            // 处理：批量禁用排序和刷新，减少大量导入项时的 UI 抖动。
            // 返回：无。
            if (table == nullptr || statusLabel == nullptr)
            {
                return;
            }

            constexpr int kMaxDisplayedDependencyRows = 20000;
            const int totalRowCount = static_cast<int>(result.rows.size());
            const int displayedRowCount = std::min(totalRowCount, kMaxDisplayedDependencyRows);

            if (!result.success)
            {
                statusLabel->setText(result.isPe
                    ? QStringLiteral("● PE 解析失败，未能读取依赖 DLL。耗时 %1 ms").arg(elapsedMs)
                    : QStringLiteral("● 不适用：目标不是 PE 文件。耗时 %1 ms").arg(elapsedMs));
                return;
            }
            if (!result.errorText.trimmed().isEmpty() && result.rows.isEmpty())
            {
                statusLabel->setText(QStringLiteral("● %1 耗时 %2 ms").arg(result.errorText.trimmed()).arg(elapsedMs));
                return;
            }
            QString statusText = QStringLiteral("● 加载完成 %1 ms | DLL:%2 | 导入项:%3")
                .arg(elapsedMs)
                .arg(result.dllNames.size())
                .arg(result.rows.size());
            if (displayedRowCount < totalRowCount)
            {
                statusText += QStringLiteral(" | 表格仅显示前 %1 行").arg(displayedRowCount);
            }
            statusLabel->setText(statusText);
        }

        void startDependencyLoad(QTableView* table, QLabel* statusLabel, ks::ui::StructuredFieldView* detailEditor)
        {
            // 用途：后台读取 EXE/DLL Import Directory 并展示依赖 DLL。
            // 输入：table/statusLabel/detailEditor 为依赖页 UI 控件。
            // 处理：工作线程解析 PE；UI 线程填表和显示错误详情，失败不阻塞不崩溃。
            // 返回：无。
            if (table == nullptr || statusLabel == nullptr || detailEditor == nullptr)
            {
                return;
            }

            if (m_dependencyReadCancel) m_dependencyReadCancel->store(true);
            const auto cancel = m_dependencyReadCancel = std::make_shared<std::atomic_bool>(false);
            const QPointer<FileDetailDialog> guardThis(this);
            const QPointer<QTableView> tableGuard(table);
            const QPointer<QLabel> statusGuard(statusLabel);
            const QPointer<ks::ui::StructuredFieldView> detailGuard(detailEditor);
            connect(table, &QObject::destroyed, [cancel]() { cancel->store(true); });
            propertyTableModel(table)->invalidateRequest();
            statusLabel->setText(QStringLiteral("● 正在后台读取 Import Directory..."));
            if (!guardThis || !tableGuard || !statusGuard || !detailGuard) return;
            ks::ui::FieldDocument loading;
            loading.note(QStringLiteral("依赖 DLL 加载中..."));
            loading.field(QStringLiteral("目标"), QDir::toNativeSeparators(m_filePath));
            detailEditor->setDocument(loading);
            if (!guardThis || !tableGuard || !statusGuard || !detailGuard) return;
            const QString filePathSnapshot = m_filePath;
            auto* task = QRunnable::create([guardThis, tableGuard, statusGuard, detailGuard, filePathSnapshot, cancel]()
                {
                    const auto beginTime = std::chrono::steady_clock::now();
                    const file_dock_detail::PeDependencyResult result =
                        file_dock_detail::analyzePeDependencies(filePathSnapshot, cancel);
                    if (cancel->load()) return;
                    const qint64 elapsedMs = static_cast<qint64>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - beginTime).count());

                    auto rows = ks::fileui::makePropertyTableSnapshot();
                    rows->rows.reserve(std::min<qsizetype>(result.rows.size(), 20000));
                    for (qsizetype index = 0; index < result.rows.size() && index < 20000; ++index)
                    {
                        if (cancel->load()) return;
                        const auto& row = result.rows.at(index);
                        const QString functionText = row.importMode == QStringLiteral("Ordinal")
                            ? QStringLiteral("#%1").arg(row.ordinalText)
                            : (row.functionName.trimmed().isEmpty() ? QStringLiteral("-") : row.functionName);
                        rows->append({ks::fileui::propertyRowKey({row.dllName, row.thunkRvaText, row.importMode, functionText}),
                            {row.dllName, functionText, row.hintText, row.importMode, row.thunkRvaText, row.diagnosticText}, {}});
                    }
                    ks::ui::FieldDocument document;
                    document.field(QStringLiteral("目标"), QDir::toNativeSeparators(filePathSnapshot));
                    if (!result.errorText.trimmed().isEmpty()) document.note(result.errorText.trimmed());
                    document.section(QStringLiteral("依赖 DLL 名称"));
                    for (qsizetype index = 0; index < result.dllNames.size(); ++index)
                    {
                        if (cancel->load()) return;
                        document.field(QString::number(index + 1), result.dllNames.at(index));
                    }
                    const auto resultSnapshot = std::shared_ptr<file_dock_detail::PeDependencyResult>(new file_dock_detail::PeDependencyResult(result),
                        [](file_dock_detail::PeDependencyResult* value) { QThreadPool::globalInstance()->start(QRunnable::create([value]() { delete value; })); });
                    QMetaObject::invokeMethod(
                        qApp,
                        [guardThis, tableGuard, statusGuard, detailGuard, resultSnapshot, rows, document, elapsedMs, cancel, filePathSnapshot]()
                        {
                            if (guardThis == nullptr || tableGuard == nullptr ||
                                statusGuard == nullptr || detailGuard == nullptr || cancel->load() || guardThis->m_filePath != filePathSnapshot)
                            {
                                return;
                            }

                            const auto commitSnapshot =
                                [guardThis, tableGuard, statusGuard, detailGuard, resultSnapshot, document, elapsedMs, cancel, filePathSnapshot]()
                            {
                                if (guardThis == nullptr || tableGuard == nullptr ||
                                    statusGuard == nullptr || detailGuard == nullptr || cancel->load() || guardThis->m_filePath != filePathSnapshot)
                                {
                                    return;
                                }

                                guardThis->populateDependencyTable(
                                    tableGuard,
                                    statusGuard,
                                    *resultSnapshot,
                                    elapsedMs);
                                if (!guardThis || !detailGuard) return;
                                detailGuard->setDocument(document);
                            };

                            propertyTableModel(tableGuard)->setSnapshot(rows, commitSnapshot);

                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            peAnalysisPool().start(task);
        }

        void setMetadataEditorBusy(const bool busy)
        {
            m_metadataEditorBusy = busy;
            const bool editorEnabled = m_metadataHasSnapshot && !busy;
            for (std::size_t timeIndex = 0; timeIndex < m_metadataTimeChecks.size(); ++timeIndex)
            {
                if (m_metadataTimeChecks[timeIndex] != nullptr)
                {
                    m_metadataTimeChecks[timeIndex]->setEnabled(editorEnabled);
                }
                if (m_metadataTimeEdits[timeIndex] != nullptr)
                {
                    const bool timeSelected = m_metadataTimeChecks[timeIndex] != nullptr &&
                        m_metadataTimeChecks[timeIndex]->isChecked();
                    m_metadataTimeEdits[timeIndex]->setEnabled(editorEnabled && timeSelected);
                }
            }
            for (QCheckBox* const attributeCheck : m_metadataAttributeChecks)
            {
                if (attributeCheck != nullptr)
                {
                    attributeCheck->setEnabled(editorEnabled);
                }
            }
            if (m_metadataRefreshButton != nullptr)
            {
                m_metadataRefreshButton->setEnabled(!busy);
            }
            if (m_metadataApplyButton != nullptr)
            {
                m_metadataApplyButton->setEnabled(editorEnabled);
            }
        }

        void applyMetadataSnapshotToEditor(const FileMetadataSnapshot& snapshot)
        {
            if (!snapshot.ok)
            {
                return;
            }

            m_metadataApplyingSnapshot = true;
            m_metadataSnapshot = snapshot;
            m_metadataHasSnapshot = true;
            const std::array<LARGE_INTEGER, 4> timeValues = fileMetadataTimes(snapshot.basicInfo);
            for (std::size_t timeIndex = 0; timeIndex < timeValues.size(); ++timeIndex)
            {
                if (m_metadataTimeChecks[timeIndex] != nullptr)
                {
                    m_metadataTimeChecks[timeIndex]->setChecked(false);
                }
                if (m_metadataTimeEdits[timeIndex] != nullptr)
                {
                    QDateTime dateTime = fileMetadataTimeToLocalDateTime(timeValues[timeIndex]);
                    if (!dateTime.isValid())
                    {
                        dateTime = QDateTime::currentDateTime();
                    }
                    m_metadataTimeEdits[timeIndex]->setDateTime(dateTime);
                }
            }

            const auto& attributeMasks = editableFileAttributeMasks();
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeMasks.size();
                 ++attributeIndex)
            {
                if (m_metadataAttributeChecks[attributeIndex] != nullptr)
                {
                    m_metadataAttributeChecks[attributeIndex]->setChecked(
                        (snapshot.basicInfo.FileAttributes & attributeMasks[attributeIndex]) != 0U);
                    m_metadataAttributeTouched[attributeIndex] = false;
                }
            }
            m_metadataApplyingSnapshot = false;
            setMetadataEditorBusy(false);
        }

        static FileMetadataSnapshot metadataSnapshotForEditor(
            const ks::file::metadata::FileSnapshot& snapshot)
        {
            FileMetadataSnapshot editorSnapshot;
            editorSnapshot.ok = snapshot.ok;
            editorSnapshot.win32Error = snapshot.win32Error;
            editorSnapshot.basicInfo = snapshot.basicInfo;
            editorSnapshot.identityAvailable = snapshot.identity.available;
            editorSnapshot.volumeSerialNumber = snapshot.identity.volumeSerialNumber;
            editorSnapshot.fileIndex = snapshot.identity.fileIndex;
            return editorSnapshot;
        }

        void applyBatchMetadataSnapshotsToEditor(
            const QList<ks::file::metadata::FileSnapshot>& snapshots)
        {
            if (snapshots.isEmpty())
            {
                return;
            }
            applyMetadataSnapshotToEditor(metadataSnapshotForEditor(snapshots.front()));
            if (!m_batchMode)
            {
                return;
            }

            m_metadataApplyingSnapshot = true;
            const auto& attributeMasks = editableFileAttributeMasks();
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeMasks.size();
                 ++attributeIndex)
            {
                QCheckBox* const attributeCheck = m_metadataAttributeChecks[attributeIndex];
                if (attributeCheck == nullptr)
                {
                    continue;
                }
                const DWORD attributeMask = attributeMasks[attributeIndex];
                const bool firstValue =
                    (snapshots.front().basicInfo.FileAttributes & attributeMask) != 0U;
                const bool allSame = std::all_of(
                    snapshots.cbegin(),
                    snapshots.cend(),
                    [attributeMask, firstValue](const ks::file::metadata::FileSnapshot& item)
                    {
                        return ((item.basicInfo.FileAttributes & attributeMask) != 0U) == firstValue;
                    });
                attributeCheck->setTristate(true);
                attributeCheck->setCheckState(
                    allSame
                        ? (firstValue ? Qt::Checked : Qt::Unchecked)
                        : Qt::PartiallyChecked);
                m_metadataAttributeTouched[attributeIndex] = false;
            }
            m_metadataApplyingSnapshot = false;
        }

        void refreshMetadataEditor()
        {
            if (m_metadataStatusLabel == nullptr || m_metadataEditorBusy || m_stagingSnapshotBusy || m_transactionBusy)
            {
                return;
            }

            if (pendingTargetCount() > 0)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral(
                        "存在尚未保存的暂存修改。请先保存或放弃暂存，再重新读取。")));
                return;
            }

            m_metadataHasSnapshot = false;
            setMetadataEditorBusy(true);
            m_metadataStatusLabel->setText(
                ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据...")));
            const std::uint64_t operationGeneration = ++m_metadataOperationGeneration;
            const QStringList filePathSnapshots = m_filePaths;
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, filePathSnapshots, operationGeneration]()
                {
                    QList<ks::file::metadata::FileSnapshot> snapshots;
                    snapshots.reserve(filePathSnapshots.size());
                    for (const QString& filePath : filePathSnapshots)
                    {
                        snapshots.push_back(ks::file::metadata::readFileSnapshot(filePath));
                    }
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, snapshots, filePathSnapshots, operationGeneration]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->m_metadataOperationGeneration != operationGeneration)
                            {
                                return;
                            }
                            QList<ks::file::metadata::FileSnapshot> successfulSnapshots;
                            QList<ks::file::metadata::TargetPatch> targetPatches;
                            int failedCount = 0;
                            DWORD firstError = ERROR_SUCCESS;
                            for (qsizetype index = 0; index < snapshots.size(); ++index)
                            {
                                const ks::file::metadata::FileSnapshot& snapshot = snapshots.at(index);
                                if (!snapshot.ok)
                                {
                                    ++failedCount;
                                    if (firstError == ERROR_SUCCESS) firstError = snapshot.win32Error;
                                    continue;
                                }
                                successfulSnapshots.push_back(snapshot);
                                ks::file::metadata::TargetPatch patch;
                                patch.originalPath = filePathSnapshots.value(index);
                                patch.snapshot = snapshot;
                                targetPatches.push_back(patch);
                            }

                            guardThis->m_pendingPatches = targetPatches;
                            guardThis->m_metadataHasSnapshot = !successfulSnapshots.isEmpty();
                            if (successfulSnapshots.isEmpty())
                            {
                                guardThis->setMetadataEditorBusy(false);
                                guardThis->m_metadataStatusLabel->setText(
                                    ks::i18n::displayText(QStringLiteral("● 元数据读取失败：%1"))
                                        .arg(formatWin32ErrorText(firstError)));
                                guardThis->updatePendingSaveUi();
                                return;
                            }

                            guardThis->applyBatchMetadataSnapshotsToEditor(successfulSnapshots);
                            if (guardThis->m_metadataStatusLabel != nullptr)
                            {
                                guardThis->m_metadataStatusLabel->setText(failedCount == 0
                                    ? ks::i18n::sourceText(QStringLiteral(
                                        "● 已读取 %1 个目标。编辑内容只会暂存，底部保存前文件不会变化。"))
                                        .arg(successfulSnapshots.size())
                                    : ks::i18n::sourceText(QStringLiteral(
                                        "● 已读取 %1 个目标，%2 个目标读取失败。失败目标不会进入保存事务。"))
                                        .arg(successfulSnapshots.size())
                                        .arg(failedCount));
                            }
                            guardThis->updatePendingSaveUi();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void applyMetadataEditorChanges()
        {
            if (!m_metadataHasSnapshot || m_metadataEditorBusy)
            {
                return;
            }

            const std::array<QString, 4> timeNames{
                QStringLiteral("创建时间"),
                QStringLiteral("最后访问时间"),
                QStringLiteral("最后写入时间"),
                QStringLiteral("元数据变更时间（ChangeTime）")
            };
            std::array<bool, 4> updateTime{};
            std::array<LARGE_INTEGER, 4> timeValues{};
            bool hasTimeChange = false;
            for (std::size_t timeIndex = 0; timeIndex < updateTime.size(); ++timeIndex)
            {
                if (m_metadataTimeChecks[timeIndex] == nullptr ||
                    m_metadataTimeEdits[timeIndex] == nullptr ||
                    !m_metadataTimeChecks[timeIndex]->isChecked())
                {
                    continue;
                }
                const QDateTime editedDateTime = m_metadataTimeEdits[timeIndex]->dateTime();
                if (!editedDateTime.isValid())
                {
                    QMessageBox::warning(
                        this,
                        ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                        ks::i18n::sourceText(QStringLiteral("%1不是有效的日期时间。"))
                            .arg(ks::i18n::sourceText(timeNames[timeIndex])));
                    return;
                }
                updateTime[timeIndex] = true;
                timeValues[timeIndex] = localDateTimeToFileMetadataTime(editedDateTime);
                hasTimeChange = true;
            }

            const auto& attributeMasks = editableFileAttributeMasks();
            const bool hasAttributeChange = std::any_of(
                m_metadataAttributeTouched.cbegin(),
                m_metadataAttributeTouched.cend(),
                [](const bool touched) { return touched; });
            if (!hasTimeChange && !hasAttributeChange)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral("没有需要暂存的基础元数据改动。")));
                return;
            }

            for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                patch.basic.updateTime = updateTime;
                patch.basic.timeValue = timeValues;
                patch.basic.updateAttributes = hasAttributeChange;
                DWORD editableAttributes =
                    patch.snapshot.basicInfo.FileAttributes & editableFileAttributeMask();
                for (std::size_t attributeIndex = 0;
                     attributeIndex < attributeMasks.size();
                     ++attributeIndex)
                {
                    if (!m_metadataAttributeTouched[attributeIndex] ||
                        m_metadataAttributeChecks[attributeIndex] == nullptr)
                    {
                        continue;
                    }
                    if (m_metadataAttributeChecks[attributeIndex]->checkState() == Qt::Checked)
                    {
                        editableAttributes |= attributeMasks[attributeIndex];
                    }
                    else
                    {
                        editableAttributes &= ~attributeMasks[attributeIndex];
                    }
                }
                patch.basic.editableAttributes = editableAttributes;
            }

            if (m_metadataStatusLabel != nullptr)
            {
                m_metadataStatusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "● 基础元数据已暂存。点击窗口底部“保存全部修改”后才会写入文件。")));
            }
            updatePendingSaveUi();
        }

        int pendingTargetCount() const
        {
            return static_cast<int>(std::count_if(
                m_pendingPatches.cbegin(),
                m_pendingPatches.cend(),
                [](const ks::file::metadata::TargetPatch& patch)
                {
                    return !patch.empty();
                }));
        }

        struct MetadataReadValue
        {
            DWORD error = ERROR_SUCCESS;
            QString text;
            QByteArray bytes;
            QString name;
            int format = -1;
            bool needEa = false;
        };

        class MetadataReadState final : public QObject
        {
        public:
            explicit MetadataReadState(QObject* parent) : QObject(parent) {}
            ~MetadataReadState() override { if (cancel != nullptr) cancel->store(true); }
            quint64 generation = 0;
            bool active = false;
            bool projecting = false;
            bool readOnly = false;
            bool undoEnabled = false;
            bool layoutEnabled = true;
            int revision = 0;
            QString toolTip;
            QVector<QPair<QPointer<QObject>, QVariant>> projectionInputs;
            std::shared_ptr<std::atomic_bool> cancel;
            QPointer<QPushButton> button;
            QPointer<QPlainTextEdit> editor;
        };

        static QThreadPool& metadataReadPool()
        {
            // The application owns the read queue; closing a page never waits for OS I/O.
            static QThreadPool* pool = []()
                {
                    auto* value = new QThreadPool(qApp);
                    value->setMaxThreadCount(2);
                    return value;
                }();
            return *pool;
        }

        static QString formatMetadataHex(const QByteArray& bytes,
            const std::shared_ptr<std::atomic_bool>& cancel)
        {
            static constexpr char digits[] = "0123456789ABCDEF";
            QByteArray text;
            if (!bytes.isEmpty()) text.reserve(bytes.size() * 3 - 1);
            for (qsizetype index = 0; index < bytes.size(); ++index)
            {
                if (index % 256 == 0 && cancel->load()) return {};
                if (index > 0) text.append(index % 256 == 0 ? '\n' : ' ');
                const auto byte = static_cast<unsigned char>(bytes.at(index));
                text.append(digits[byte >> 4]);
                text.append(digits[byte & 15]);
            }
            return QString::fromLatin1(text);
        }

        static bool sameMetadataReadIdentity(
            const ks::file::metadata::FileSnapshot& before,
            const ks::file::metadata::FileSnapshot& after)
        {
            return before.ok && after.ok && before.identity.available && after.identity.available &&
                before.identity.volumeSerialNumber == after.identity.volumeSerialNumber &&
                before.identity.fileIndex == after.identity.fileIndex &&
                before.basicInfo.LastWriteTime.QuadPart == after.basicInfo.LastWriteTime.QuadPart &&
                before.basicInfo.ChangeTime.QuadPart == after.basicInfo.ChangeTime.QuadPart;
        }

        bool metadataReadBusy() const
        {
            for (const auto& state : m_metadataReadStates)
                if (state != nullptr && state->active) return true;
            return false;
        }

        void finishMetadataRead(MetadataReadState* state)
        {
            if (state == nullptr) return;
            const QPointer<FileDetailDialog> owner(this);
            const QPointer<MetadataReadState> stateGuard(state);
            state->active = false;
            if (state->projecting && state->editor != nullptr)
            {
                const QPointer<QPlainTextEdit> editor(state->editor);
                const bool readOnly = state->readOnly;
                const bool undoEnabled = state->undoEnabled;
                const bool layoutEnabled = state->layoutEnabled;
                state->projecting = false;
                editor->setReadOnly(readOnly);
                if (owner == nullptr || stateGuard == nullptr || editor == nullptr) return;
                editor->setUndoRedoEnabled(undoEnabled);
                if (owner == nullptr || stateGuard == nullptr || editor == nullptr) return;
                editor->document()->setLayoutEnabled(layoutEnabled);
            }
            if (owner == nullptr || stateGuard == nullptr) return;
            if (state->button != nullptr)
            {
                const QPointer<QPushButton> button(state->button);
                const QString toolTip = state->toolTip;
                const bool enabled = !m_transactionBusy;
                button->setToolTip(toolTip);
                if (owner == nullptr || stateGuard == nullptr || button == nullptr) return;
                button->setEnabled(enabled);
            }
            if (owner != nullptr) updatePendingSaveUi();
        }

        static ks::file::metadata::FileSnapshot metadataReadSnapshot(const QString& path, bool followTarget)
        {
            ks::file::metadata::FileSnapshot result;
            const auto native = QDir::toNativeSeparators(path).toStdWString();
            const HANDLE handle = ::CreateFileW(native.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | (followTarget ? 0U : FILE_FLAG_OPEN_REPARSE_POINT), nullptr);
            if (handle == INVALID_HANDLE_VALUE) { result.win32Error = ::GetLastError(); return result; }
            BY_HANDLE_FILE_INFORMATION identity{};
            const BOOL basicOk = ::GetFileInformationByHandleEx(handle, FileBasicInfo, &result.basicInfo, sizeof(result.basicInfo));
            const DWORD basicError = basicOk ? ERROR_SUCCESS : ::GetLastError();
            const BOOL identityOk = ::GetFileInformationByHandle(handle, &identity);
            result.win32Error = !basicOk ? basicError : (identityOk ? ERROR_SUCCESS : ::GetLastError());
            ::CloseHandle(handle);
            result.ok = basicOk && identityOk;
            result.identity.available = identityOk;
            result.identity.volumeSerialNumber = identity.dwVolumeSerialNumber;
            result.identity.fileIndex = (static_cast<quint64>(identity.nFileIndexHigh) << 32U) | identity.nFileIndexLow;
            return result;
        }

        template <typename Work, typename Apply>
        void runMetadataRead(QWidget* output, QPushButton* button, const QString& path,
            Work work, Apply apply, bool followTarget = false)
        {
            if (output == nullptr || button == nullptr || m_transactionBusy || m_stagingSnapshotBusy) return;
            auto state = m_metadataReadStates.value(output);
            if (state == nullptr)
            {
                state = new MetadataReadState(output);
                m_metadataReadStates.insert(output, state);
                if (auto* editor = qobject_cast<QPlainTextEdit*>(output))
                {
                    const QPointer<QPlainTextEdit> editorGuard(editor);
                    connect(editor->document(), &QTextDocument::contentsChange, state,
                        [state, editorGuard](int, int removed, int added)
                        {
                            if (state == nullptr || editorGuard == nullptr || state->projecting || (removed == 0 && added == 0)) return;
                            // Undo/retyping can revisit a Qt document revision; a real
                            // edit always invalidates both the old read and raw-byte cache.
                            editorGuard->setProperty("ks_file_metadata_original_bytes", QVariant());
                            editorGuard->setProperty("ks_file_metadata_incomplete", false);
                            if (state->active && state->cancel != nullptr) state->cancel->store(true);
                        });
                }
            }
            if (state->active) return;
            state->active = true;
            state->cancel = std::make_shared<std::atomic_bool>(false);
            state->button = button;
            state->toolTip = button->toolTip();
            const auto cancel = state->cancel;
            const quint64 generation = ++state->generation;
            const QStringList paths = m_filePaths;
            const QPointer<FileDetailDialog> owner(this);
            const QPointer<QWidget> outputGuard(output);
            const QPointer<QPushButton> buttonGuard(button);
            button->setEnabled(false);
            if (owner == nullptr || outputGuard == nullptr || state == nullptr) return;
            if (buttonGuard == nullptr) { finishMetadataRead(state); return; }
            button->setToolTip(ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据...")));
            if (owner == nullptr || outputGuard == nullptr || state == nullptr) return;
            updatePendingSaveUi();
            if (owner == nullptr || outputGuard == nullptr || state == nullptr) return;
            metadataReadPool().start(QRunnable::create(
                [owner, outputGuard, state, cancel, generation, paths, path, followTarget, work = std::move(work), apply = std::move(apply)]()
                {
                    auto result = std::shared_ptr<MetadataReadValue>(new MetadataReadValue(), [](MetadataReadValue* value)
                        { QThreadPool::globalInstance()->start(QRunnable::create([value]() { delete value; })); });
                    const auto before = metadataReadSnapshot(path, followTarget);
                    if (!cancel->load())
                    {
                        if (!before.ok) result->error = before.win32Error;
                        else
                        {
                            *result = work(cancel);
                            if (!cancel->load() && result->error == ERROR_SUCCESS)
                            {
                                const auto after = metadataReadSnapshot(path, followTarget);
                                if (!sameMetadataReadIdentity(before, after)) result->error = ERROR_FILE_INVALID;
                            }
                        }
                    }
                    QMetaObject::invokeMethod(qApp,
                        [owner, outputGuard, state, cancel, generation, paths, result, apply]()
                        {
                            if (owner == nullptr || outputGuard == nullptr || state == nullptr || state->generation != generation) return;
                            if (cancel->load() || owner->m_filePaths != paths)
                            {
                                owner->finishMetadataRead(state);
                                return;
                            }
                            // A true return keeps the read active until full document publication ends.
                            if (!apply(*result, state) && owner != nullptr && state != nullptr)
                                owner->finishMetadataRead(state);
                        }, Qt::QueuedConnection);
                }));
        }

        static qsizetype metadataTextSliceLength(const QString& text, const qsizetype offset)
        {
            if (offset < 0 || offset >= text.size()) return 0;
            qsizetype count = std::min<qsizetype>(8192, text.size() - offset);
            if (offset + count < text.size() && text.at(offset + count - 1).isHighSurrogate()) --count;
            return count;
        }

        void continueMetadataTextProjection(const QPointer<MetadataReadState>& state,
            const std::shared_ptr<const MetadataReadValue>& result, qsizetype offset)
        {
            if (state == nullptr || state->editor == nullptr || !state->active) return;
            const QPointer<FileDetailDialog> owner(this);
            const QPointer<QPlainTextEdit> editor(state->editor);
            if (state->cancel->load() || editor->document()->revision() != state->revision ||
                !stagingInputsUnchanged(state->projectionInputs, stagingWidgetValue))
            {
                // A partial document is never a replacement payload. Preserve changed
                // parameter intent and require a fresh complete read or explicit new text.
                editor->clear();
                if (owner == nullptr || state == nullptr || editor == nullptr) return;
                editor->setProperty("ks_file_metadata_incomplete", true);
                finishMetadataRead(state);
                return;
            }
            QElapsedTimer budget;
            budget.start();
            do
            {
                const qsizetype count = metadataTextSliceLength(result->text, offset);
                QTextCursor cursor(editor->document());
                cursor.movePosition(QTextCursor::End);
                cursor.insertText(result->text.mid(offset, count));
                if (owner == nullptr || state == nullptr || editor == nullptr) return;
                offset += count;
                state->revision = editor->document()->revision();
            } while (offset < result->text.size() && budget.nsecsElapsed() < 4'000'000);
            if (offset < result->text.size())
            {
                QTimer::singleShot(0, this, [owner, state, result, offset]()
                    { if (owner != nullptr) owner->continueMetadataTextProjection(state, result, offset); });
                return;
            }
            editor->setProperty("ks_file_metadata_incomplete", false);
            editor->setProperty("ks_file_metadata_original_bytes", result->bytes);
            editor->setProperty("ks_file_metadata_original_revision", state->revision);
            editor->setProperty("ks_file_metadata_original_format", result->format);
            QTextCursor first(editor->document());
            first.movePosition(QTextCursor::Start);
            editor->setTextCursor(first);
            if (owner != nullptr && state != nullptr) finishMetadataRead(state);
            if (owner != nullptr && editor != nullptr)
                editor->setProperty("ks_file_metadata_original_revision", editor->document()->revision());
        }

        void publishMetadataText(QPlainTextEdit* editor, MetadataReadState* state, const MetadataReadValue& value, const QList<QObject*>& inputs = {})
        {
            const QPointer<FileDetailDialog> owner(this);
            const QPointer<MetadataReadState> stateGuard(state);
            const QPointer<QPlainTextEdit> editorGuard(editor);
            state->editor = editor;
            state->projecting = true;
            state->readOnly = editor->isReadOnly();
            state->undoEnabled = editor->isUndoRedoEnabled();
            state->layoutEnabled = editor->document()->isLayoutEnabled();
            editor->setReadOnly(true);
            if (owner == nullptr || stateGuard == nullptr || editorGuard == nullptr) return;
            editor->setUndoRedoEnabled(false);
            if (owner == nullptr || stateGuard == nullptr || editorGuard == nullptr) return;
            editor->document()->setLayoutEnabled(false);
            if (owner == nullptr || stateGuard == nullptr || editorGuard == nullptr) return;
            editor->setProperty("ks_file_metadata_original_bytes", QVariant());
            editor->setProperty("ks_file_metadata_incomplete", true);
            if (!editor->property("ks_file_metadata_text_wrap_mode").isValid())
                editor->setProperty("ks_file_metadata_text_wrap_mode", static_cast<int>(editor->lineWrapMode()));
            editor->setLineWrapMode(value.format == 1 ? QPlainTextEdit::NoWrap :
                static_cast<QPlainTextEdit::LineWrapMode>(editor->property("ks_file_metadata_text_wrap_mode").toInt()));
            if (owner == nullptr || stateGuard == nullptr || editorGuard == nullptr) return;
            editor->clear();
            if (owner == nullptr || stateGuard == nullptr || editorGuard == nullptr) return;
            state->revision = editor->document()->revision();
            state->projectionInputs.clear();
            for (QObject* input : inputs)
            {
                const auto value = stagingWidgetValue(input);
                if (value.isValid()) state->projectionInputs.push_back({input, value});
            }
            auto snapshot = std::shared_ptr<const MetadataReadValue>(new MetadataReadValue(value), [](const MetadataReadValue* retired)
                { QThreadPool::globalInstance()->start(QRunnable::create([retired]() { delete retired; })); });
            QTimer::singleShot(0, this, [owner, stateGuard, snapshot]()
                { if (owner != nullptr) owner->continueMetadataTextProjection(stateGuard, snapshot, 0); });
        }

        using StagingInputValue = QPair<QPointer<QObject>, QVariant>;

        static QVariant stagingWidgetValue(QObject* object)
        {
            if (auto* edit = qobject_cast<QPlainTextEdit*>(object)) return edit->document()->revision();
            if (auto* date = qobject_cast<QDateTimeEdit*>(object)) return date->dateTime();
            if (auto* spin = qobject_cast<QSpinBox*>(object)) return spin->value();
            if (auto* combo = qobject_cast<QComboBox*>(object))
                return QVariantList{ combo->currentIndex(), combo->currentData() };
            if (auto* line = qobject_cast<QLineEdit*>(object))
            {
                if (qobject_cast<QAbstractSpinBox*>(line->parentWidget()) != nullptr ||
                    qobject_cast<QComboBox*>(line->parentWidget()) != nullptr) return {};
                return line->text();
            }
            if (auto* check = qobject_cast<QCheckBox*>(object)) return static_cast<int>(check->checkState());
            if (auto* button = qobject_cast<QAbstractButton*>(object))
                return button->isCheckable() ? QVariant(button->isChecked()) : QVariant();
            if (auto* table = qobject_cast<QTableView*>(object))
            {
                const auto current = table->currentIndex();
                QVariantList value{ QVariant::fromValue<qulonglong>(reinterpret_cast<quintptr>(table->model())),
                    current.row(), current.column() };
                if (current.isValid())
                {
                    for (int column = 0; column < table->model()->columnCount(); ++column)
                        value.push_back(current.sibling(current.row(), column).data());
                    const auto first = current.sibling(current.row(), 0);
                    for (int role = Qt::UserRole + 3; role <= Qt::UserRole + 6; ++role) value.push_back(first.data(role));
                }
                return value;
            }
            return {};
        }

        static bool stagingInputsUnchanged(const QVector<StagingInputValue>& inputs,
            const std::function<QVariant(QObject*)>& value)
        {
            for (const auto& input : inputs)
                if (input.first == nullptr || value(input.first) != input.second) return false;
            return true;
        }

        struct StagingSnapshotResult
        {
            QList<ks::file::metadata::TargetPatch> patches;
            QString failedPath;
            DWORD error = ERROR_SUCCESS;
            bool cancelled = false;
        };

        static StagingSnapshotResult collectStagingSnapshots(const QStringList& paths,
            const std::shared_ptr<std::atomic_bool>& cancel,
            const std::function<ks::file::metadata::FileSnapshot(const QString&)>& read)
        {
            StagingSnapshotResult result;
            result.patches.reserve(paths.size());
            for (const QString& path : paths)
            {
                if (cancel->load()) { result.cancelled = true; result.patches.clear(); return result; }
                const auto snapshot = read(path);
                if (!snapshot.ok)
                {
                    result.failedPath = path;
                    result.error = snapshot.win32Error;
                    result.patches.clear();
                    return result;
                }
                ks::file::metadata::TargetPatch patch;
                patch.originalPath = path;
                patch.snapshot = snapshot;
                result.patches.push_back(std::move(patch));
            }
            if (cancel->load()) { result.cancelled = true; result.patches.clear(); }
            return result;
        }

        bool ensurePendingPatchesForStaging()
        {
            if (metadataReadBusy() || m_stagingSnapshotBusy || m_transactionBusy)
            {
                QMessageBox::information(this, ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据...")));
                return false;
            }
            if (!m_pendingPatches.isEmpty()) return true;
            const QPointer<QAbstractButton> intent(qobject_cast<QAbstractButton*>(sender()));
            if (intent == nullptr) return false;
            QVector<StagingInputValue> inputs;
            QWidget* const scope = m_tabWidget != nullptr ? m_tabWidget->currentWidget() : this;
            if (scope != nullptr)
            {
                // A one-shot explicit staging snapshot, not a theme or paint observer.
                for (QWidget* widget : scope->findChildren<QWidget*>())
                {
                    if (!widget->isVisibleTo(scope)) continue;
                    const QVariant value = stagingWidgetValue(widget);
                    if (value.isValid()) inputs.push_back({ widget, value });
                }
            }
            m_stagingSnapshotBusy = true;
            m_stagingSnapshotCancel = std::make_shared<std::atomic_bool>(false);
            const auto cancel = m_stagingSnapshotCancel;
            const auto generation = ++m_metadataOperationGeneration;
            const auto paths = m_filePaths;
            setMetadataEditorBusy(true);
            if (m_tabWidget != nullptr) m_tabWidget->setEnabled(false);
            if (m_tabNavigation != nullptr) m_tabNavigation->setEnabled(false);
            updatePendingSaveUi();
            const QPointer<FileDetailDialog> owner(this);
            metadataReadPool().start(QRunnable::create([owner, intent, paths, cancel, generation, inputs]()
                {
                    auto result = std::shared_ptr<const StagingSnapshotResult>(
                        new StagingSnapshotResult(collectStagingSnapshots(paths, cancel,
                            [](const QString& path) { return ks::file::metadata::readFileSnapshot(path); })),
                        [](const StagingSnapshotResult* retired)
                        { QThreadPool::globalInstance()->start(QRunnable::create([retired]() { delete retired; })); });
                    QMetaObject::invokeMethod(qApp, [owner, intent, paths, cancel, generation, inputs, result]()
                        {
                            if (owner == nullptr || owner->m_metadataOperationGeneration != generation) return;
                            owner->m_stagingSnapshotBusy = false;
                            owner->m_stagingSnapshotCancel.reset();
                            owner->setMetadataEditorBusy(false);
                            if (owner == nullptr) return;
                            if (owner->m_tabWidget != nullptr) owner->m_tabWidget->setEnabled(true);
                            if (owner == nullptr) return;
                            if (owner->m_tabNavigation != nullptr) owner->m_tabNavigation->setEnabled(true);
                            if (owner == nullptr) return;
                            owner->updatePendingSaveUi();
                            if (owner == nullptr) return;
                            if (cancel->load() || result->cancelled || owner->m_filePaths != paths || intent == nullptr) return;
                            if (result->error != ERROR_SUCCESS)
                            {
                                QMessageBox::warning(owner, ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                                    ks::i18n::sourceText(QStringLiteral("无法读取目标快照：%1\n%2"))
                                        .arg(QDir::toNativeSeparators(result->failedPath)).arg(formatWin32ErrorText(result->error)));
                                return;
                            }
                            if (!stagingInputsUnchanged(inputs, stagingWidgetValue))
                            {
                                QMessageBox::information(owner, ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                                    ks::i18n::sourceText(QStringLiteral("暂存输入已变化，请检查当前内容后重新暂存。")));
                                return;
                            }
                            owner->m_pendingPatches = result->patches;
                            if (!result->patches.isEmpty()) intent->click();
                        }, Qt::QueuedConnection);
                }));
            return false;
        }


        int pendingOperationCount() const
        {
            int count = 0;
            for (const ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                if (patch.empty()) continue;
                if (patch.basic.updateAttributes ||
                    std::any_of(patch.basic.updateTime.cbegin(), patch.basic.updateTime.cend(),
                        [](const bool value) { return value; })) ++count;
                if (patch.rename) ++count;
                if (patch.setShortName) ++count;
                if (patch.caseSensitive != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (!patch.shellProperties.empty()) ++count;
                count += patch.streams.size();
                count += patch.extendedAttributes.size();
                if (!patch.security.empty()) ++count;
                if (patch.compression != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.sparse != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.encryption != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.integrityStream != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.objectId.update) ++count;
                count += patch.hardLinkPaths.size();
                if (patch.reparse.update) ++count;
                count += patch.peResources.size();
                if (patch.signatureDisposition ==
                    ks::file::metadata::SignatureDisposition::RemoveEmbedded) ++count;
            }
            return count;
        }

        void updatePendingSaveUi()
        {
            const int targetCount = pendingTargetCount();
            const int operationCount = pendingOperationCount();
            const bool reading = m_stagingSnapshotBusy || metadataReadBusy();
            if (m_pendingChangesLabel != nullptr)
            {
                m_pendingChangesLabel->setText(reading
                    ? ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据..."))
                    : targetCount > 0
                    ? ks::i18n::sourceText(QStringLiteral(
                        "● 已暂存：%1 个目标，%2 类操作。文件尚未发生变化。"))
                        .arg(targetCount)
                        .arg(operationCount)
                    : ks::i18n::sourceText(QStringLiteral("● 暂无待保存修改")));
            }
            if (m_saveAllButton != nullptr)
            {
                m_saveAllButton->setEnabled(targetCount > 0 && !m_transactionBusy && !reading);
            }
            if (m_discardPendingButton != nullptr)
            {
                m_discardPendingButton->setEnabled(targetCount > 0 && !m_transactionBusy && !reading);
            }
        }

        void resetPatchKeepingSnapshot(ks::file::metadata::TargetPatch& patch)
        {
            const QString originalPath = patch.originalPath;
            const ks::file::metadata::FileSnapshot snapshot = patch.snapshot;
            patch = {};
            patch.originalPath = originalPath;
            patch.snapshot = snapshot;
        }

        void discardPendingChanges()
        {
            if (m_transactionBusy || m_stagingSnapshotBusy || metadataReadBusy())
            {
                return;
            }
            for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                resetPatchKeepingSnapshot(patch);
            }
            m_metadataApplyingSnapshot = true;
            for (QCheckBox* const timeCheck : m_metadataTimeChecks)
            {
                if (timeCheck != nullptr) timeCheck->setChecked(false);
            }
            m_metadataApplyingSnapshot = false;
            m_metadataAttributeTouched.fill(false);
            if (m_metadataStatusLabel != nullptr)
            {
                m_metadataStatusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("● 已放弃全部暂存修改，文件未发生变化。")));
            }
            updatePendingSaveUi();
            if (m_metadataHasSnapshot)
            {
                QList<ks::file::metadata::FileSnapshot> snapshots;
                for (const ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                {
                    if (patch.snapshot.ok) snapshots.push_back(patch.snapshot);
                }
                applyBatchMetadataSnapshotsToEditor(snapshots);
            }
        }

        static QString transactionOperationText(const QString& operation)
        {
            if (operation == QStringLiteral("identity")) return QStringLiteral("身份复核");
            if (operation == QStringLiteral("backup")) return QStringLiteral("创建备份");
            if (operation == QStringLiteral("backup-required")) return QStringLiteral("备份要求");
            if (operation == QStringLiteral("basic")) return QStringLiteral("基础属性与时间");
            if (operation == QStringLiteral("rename")) return QStringLiteral("重命名");
            if (operation == QStringLiteral("short-name")) return QStringLiteral("8.3 短文件名");
            if (operation == QStringLiteral("case-sensitive")) return QStringLiteral("目录大小写敏感");
            if (operation == QStringLiteral("shell-properties")) return QStringLiteral("Shell 属性");
            if (operation.startsWith(QStringLiteral("ads:"))) return QStringLiteral("ADS：%1").arg(operation.mid(4));
            if (operation.startsWith(QStringLiteral("ea:"))) return QStringLiteral("EA：%1").arg(operation.mid(3));
            if (operation == QStringLiteral("security-sddl")) return QStringLiteral("安全描述符 SDDL");
            if (operation == QStringLiteral("security-ace")) return QStringLiteral("新增或修改 ACE");
            if (operation == QStringLiteral("security-remove-ace")) return QStringLiteral("删除 ACE");
            if (operation == QStringLiteral("compression")) return QStringLiteral("NTFS 压缩");
            if (operation == QStringLiteral("sparse")) return QStringLiteral("稀疏文件");
            if (operation == QStringLiteral("encryption")) return QStringLiteral("EFS 加密");
            if (operation == QStringLiteral("integrity-stream")) return QStringLiteral("Integrity Stream");
            if (operation == QStringLiteral("object-id")) return QStringLiteral("Object ID");
            if (operation.startsWith(QStringLiteral("hard-link:"))) return QStringLiteral("硬链接：%1").arg(operation.mid(10));
            if (operation == QStringLiteral("reparse")) return QStringLiteral("重解析点原始数据");
            if (operation == QStringLiteral("pe-resources")) return QStringLiteral("PE 资源");
            if (operation == QStringLiteral("signature-remove")) return QStringLiteral("清除嵌入式签名");
            if (operation == QStringLiteral("rollback")) return QStringLiteral("失败回滚");
            if (operation == QStringLiteral("readback")) return QStringLiteral("写后回读");
            return operation;
        }

        using FileDetailRows = QVector<QStringList>;

        static std::shared_ptr<FileDetailRows> makeFileDetailRows()
        {
            // A canceled/closed display callback can be the last owner too.
            // Keep destruction of a large uncommitted snapshot off the GUI thread.
            return std::shared_ptr<FileDetailRows>(new FileDetailRows(), [](FileDetailRows* rows)
                {
                    QThreadPool::globalInstance()->start(QRunnable::create([rows]() { delete rows; }));
                });
        }

        // The transaction owns complete immutable display rows before GUI delivery.
        // A view asks only for visible cells; no per-operation QWidget items exist.
        class FileDetailRowsModel final : public QAbstractTableModel
        {
        public:
            FileDetailRowsModel(std::shared_ptr<const FileDetailRows> rows, QObject* parent,
                QStringList headers = {}, QSet<int> translatedColumns = { 1, 2 })
                : QAbstractTableModel(parent), m_rows(std::move(rows)),
                  m_headers(headers.isEmpty() ? QStringList{ QStringLiteral("目标"), QStringLiteral("操作"),
                    QStringLiteral("结果"), QStringLiteral("错误"), QStringLiteral("详情"),
                    QStringLiteral("备份") } : std::move(headers)), m_translatedColumns(std::move(translatedColumns))
            {
                if (parent != nullptr) parent->installEventFilter(this);
            }

            void setSnapshot(std::shared_ptr<const FileDetailRows> rows)
            {
                const QPointer<FileDetailRowsModel> lifetime(this);
                beginResetModel();
                if (lifetime == nullptr) return;
                auto retired = std::move(m_rows);
                m_rows = std::move(rows);
                endResetModel();
                if (retired != nullptr)
                    QThreadPool::globalInstance()->start(QRunnable::create(
                        [retired = std::move(retired)]() mutable { retired.reset(); }));
            }

            ~FileDetailRowsModel() override
            {
                if (m_rows != nullptr)
                    QThreadPool::globalInstance()->start(QRunnable::create(
                        [retired = std::move(m_rows)]() mutable { retired.reset(); }));
            }

            int rowCount(const QModelIndex& parent = {}) const override
            {
                return parent.isValid() || m_rows == nullptr ? 0 : static_cast<int>(m_rows->size());
            }

            int columnCount(const QModelIndex& parent = {}) const override
            {
                return parent.isValid() ? 0 : static_cast<int>(m_headers.size());
            }

            QVariant data(const QModelIndex& index, const int role = Qt::DisplayRole) const override
            {
                if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() ||
                    index.column() < 0 || index.column() >= columnCount() ||
                    (role != Qt::DisplayRole && role != Qt::ToolTipRole))
                {
                    return {};
                }
                const QString value = m_rows->at(index.row()).value(index.column());
                return m_translatedColumns.contains(index.column()) ? ks::i18n::displayText(value) : value;
            }

            QVariant headerData(const int section, const Qt::Orientation orientation,
                const int role = Qt::DisplayRole) const override
            {
                if (orientation == Qt::Horizontal && role == Qt::DisplayRole &&
                    section >= 0 && section < columnCount())
                {
                    return ks::i18n::displayText(m_headers.at(section));
                }
                return QAbstractTableModel::headerData(section, orientation, role);
            }

        protected:
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (event != nullptr && event->type() == QEvent::LanguageChange)
                {
                    emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1);
                    if (rowCount() > 0)
                        emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1), { Qt::DisplayRole, Qt::ToolTipRole });
                }
                return QAbstractTableModel::eventFilter(watched, event);
            }

        private:
            std::shared_ptr<const FileDetailRows> m_rows;
            QStringList m_headers;
            QSet<int> m_translatedColumns;
        };

        static std::shared_ptr<const FileDetailRows> transactionDisplayRows(
            const ks::file::metadata::TransactionResult& result)
        {
            auto rows = makeFileDetailRows();
            qsizetype rowCount = 0;
            for (const auto& target : result.targets) rowCount += target.operations.size();
            rows->reserve(rowCount);
            for (const ks::file::metadata::TargetResult& target : result.targets)
            {
                const QString path = QDir::toNativeSeparators(target.originalPath);
                const QString backup = QDir::toNativeSeparators(target.backupPath);
                for (const ks::file::metadata::OperationResult& operation : target.operations)
                {
                    rows->push_back(QStringList{ path, transactionOperationText(operation.operation),
                        operation.ok
                            ? (operation.verified ? QStringLiteral("成功并验证") : QStringLiteral("成功，未验证"))
                            : QStringLiteral("失败"),
                        operation.ok ? QStringLiteral("0") : QStringLiteral("%1 · %2")
                            .arg(operation.win32Error).arg(formatWin32ErrorText(operation.win32Error)),
                        operation.detail, backup });
                }
            }
            return rows;
        }

        static QString transactionTargetKey(const QString& path)
        {
            return QDir::cleanPath(path).toCaseFolded();
        }

        // Match against the original target catalog, never against a path already
        // renamed by another result. Failed targets retain their exact pending patch.
        static void reconcileTransactionResults(
            const ks::file::metadata::TransactionResult& result,
            QList<ks::file::metadata::TargetPatch>& pendingPatches, QStringList& paths)
        {
            QHash<QString, qsizetype> resultByTarget;
            resultByTarget.reserve(result.targets.size());
            for (qsizetype index = 0; index < result.targets.size(); ++index)
            {
                const QString key = transactionTargetKey(result.targets.at(index).originalPath);
                if (!resultByTarget.contains(key)) resultByTarget.insert(key, index);
            }
            QHash<QString, QString> finalPathByTarget;
            finalPathByTarget.reserve(pendingPatches.size());
            for (ks::file::metadata::TargetPatch& pendingPatch : pendingPatches)
            {
                const QString key = transactionTargetKey(pendingPatch.originalPath);
                const auto found = resultByTarget.constFind(key);
                if (found == resultByTarget.cend()) continue;
                const auto& target = result.targets.at(found.value());
                if (!target.ok) continue;
                finalPathByTarget.insert(key, target.finalPath);
                pendingPatch = {};
                pendingPatch.originalPath = target.finalPath;
                pendingPatch.snapshot = target.finalSnapshot;
            }
            for (QString& path : paths)
            {
                const auto found = finalPathByTarget.constFind(transactionTargetKey(path));
                if (found != finalPathByTarget.cend()) path = found.value();
            }
        }

        static void installValueTableCopyMenu(QTableView* table)
        {
            table->setContextMenuPolicy(Qt::CustomContextMenu);
            connect(table, &QTableView::customContextMenuRequested, table,
                [table](const QPoint& localPosition)
                {
                    const QModelIndex clicked = table->indexAt(localPosition);
                    if (clicked.isValid()) table->setCurrentIndex(clicked);
                    const QPersistentModelIndex selected(table->currentIndex());
                    const QPointer<QTableView> tableGuard(table);
                    QMenu menu;
                    menu.setPalette(table->palette());
                    menu.setStyleSheet(buildContextMenuStyle());
                    connect(table, &QObject::destroyed, &menu, &QMenu::close);
                    QAction* copy = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                        QStringLiteral("复制当前行"));
                    ks::ui::SetTableContextActionRole(copy, ks::ui::TableContextActionRole::CopyRows);
                    copy->setEnabled(selected.isValid());
                    if (menu.exec(table->viewport()->mapToGlobal(localPosition)) != copy ||
                        tableGuard == nullptr || !selected.isValid()) return;
                    QStringList values;
                    for (int column = 0; column < table->model()->columnCount(); ++column)
                        values.push_back(selected.sibling(selected.row(), column).data().toString());
                    if (QClipboard* clipboard = QApplication::clipboard())
                        clipboard->setText(values.join(QLatin1Char('\t')));
                });
        }

        void showTransactionResults(const ks::file::metadata::TransactionResult& result,
            std::shared_ptr<const FileDetailRows> rows)
        {
            QDialog* dialog = new QDialog(this);
            dialog->setAttribute(Qt::WA_DeleteOnClose, true);
            dialog->setWindowTitle(ks::i18n::sourceText(QStringLiteral("文件元数据保存结果")));
            dialog->resize(1080, 560);
            QVBoxLayout* layout = new QVBoxLayout(dialog);

            QLabel* summaryLabel = new QLabel(result.ok
                ? ks::i18n::sourceText(QStringLiteral("● 全部目标保存并回读完成。"))
                : ks::i18n::sourceText(QStringLiteral(
                    "● 部分目标保存失败。失败目标已尽可能回滚，请查看逐操作结果。")),
                dialog);
            summaryLabel->setWordWrap(true);
            layout->addWidget(summaryLabel);

            QTableView* table = new ks::ui::TableActionTableView(dialog);
            // 保存结果是一次事务报告，仅保留紧凑复制/导出入口。
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            auto* model = new FileDetailRowsModel(std::move(rows), table);
            auto* proxy = new QSortFilterProxyModel(table);
            proxy->setDynamicSortFilter(false);
            proxy->setSourceModel(model);
            table->setProperty("ks_i18n_preserve_model_data", true);
            table->setModel(proxy);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setAlternatingRowColors(true);
            ks::ui::SetTableColumnAutoFitEnabled(table, false);
            if (table->horizontalHeader() != nullptr)
            {
                table->horizontalHeader()->setResizeContentsPrecision(64);
                table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
                table->horizontalHeader()->setStretchLastSection(true);
                table->horizontalHeader()->setSortIndicator(-1, Qt::AscendingOrder);
            }
            table->setSortingEnabled(true);
            installValueTableCopyMenu(table);
            layout->addWidget(table, 1);
            QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
            connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
            layout->addWidget(buttons);
            dialog->show();
        }

        void setTransactionBusy(const bool busy)
        {
            m_transactionBusy = busy;
            if (m_backupBeforeSaveCheck != nullptr) m_backupBeforeSaveCheck->setEnabled(!busy);
            if (m_tabNavigation != nullptr) m_tabNavigation->setEnabled(!busy);
            if (m_tabWidget != nullptr) m_tabWidget->setEnabled(!busy);
            setMetadataEditorBusy(busy);
            updatePendingSaveUi();
        }

        void saveAllPendingChanges()
        {
            if (m_transactionBusy || m_stagingSnapshotBusy || metadataReadBusy())
            {
                return;
            }
            QList<ks::file::metadata::TargetPatch> patches;
            for (const ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                if (!patch.empty()) patches.push_back(patch);
            }
            if (patches.isEmpty())
            {
                return;
            }

            const auto cancel = std::make_shared<std::atomic_bool>(false);
            m_savePreflightCancel = cancel;
            const quint64 generation = ++m_savePreflightGeneration;
            setTransactionBusy(true);
            auto* progress = new QDialog(this);
            progress->setAttribute(Qt::WA_DeleteOnClose, true);
            progress->setWindowTitle(ks::i18n::sourceText(QStringLiteral("数字签名")));
            progress->setWindowModality(Qt::NonModal);
            auto* progressLayout = new QVBoxLayout(progress);
            auto* progressText = new QLabel(ks::i18n::text(
                QStringLiteral("driver.signature.pending.detail"),
                QStringLiteral("数字签名信任链等待后台验证。")), progress);
            progressText->setWordWrap(true);
            progressLayout->addWidget(progressText);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, progress);
            progressLayout->addWidget(buttons);
            connect(buttons, &QDialogButtonBox::rejected, progress, &QDialog::reject);
            connect(progress, &QDialog::finished, this, [this, cancel](int)
                {
                    if (m_savePreflightCancel != cancel) return;
                    cancel->store(true);
                    ++m_savePreflightGeneration;
                    m_savePreflightCancel.reset();
                    setTransactionBusy(false);
                });
            const QPointer<FileDetailDialog> guardThis(this);
            const QPointer<QDialog> progressGuard(progress);
            progress->show();
            QThreadPool::globalInstance()->start(QRunnable::create(
                [guardThis, progressGuard, patches, cancel, generation]()
                {
                    const auto preflight = inspectSaveSignatures(patches, cancel,
                        [](const QString& path) { return ks::file::metadata::inspectSignature(path); });
                    QMetaObject::invokeMethod(qApp,
                        [guardThis, progressGuard, patches, cancel, generation, preflight]() mutable
                        {
                            if (guardThis == nullptr ||
                                guardThis->m_savePreflightGeneration != generation ||
                                guardThis->m_savePreflightCancel != cancel) return;
                            guardThis->m_savePreflightCancel.reset();
                            if (progressGuard != nullptr) progressGuard->close();
                            if (guardThis == nullptr) return;
                            guardThis->setTransactionBusy(false);
                            if (guardThis != nullptr && !cancel->load() && !preflight.cancelled)
                                guardThis->continueSaveAfterSignaturePreflight(
                                    std::move(patches), preflight.signedTargetWillChange,
                                    preflight.hasCatalogSignature);
                        }, Qt::QueuedConnection);
                }));
        }

        struct SaveSignaturePreflight
        {
            bool signedTargetWillChange = false;
            bool hasCatalogSignature = false;
            bool cancelled = false;
        };

        static SaveSignaturePreflight inspectSaveSignatures(
            const QList<ks::file::metadata::TargetPatch>& patches,
            const std::shared_ptr<std::atomic_bool>& cancel,
            const std::function<ks::file::metadata::SignatureInspection(const QString&)>& inspect)
        {
            SaveSignaturePreflight result;
            for (const auto& patch : patches)
            {
                if (cancel->load()) { result.cancelled = true; return result; }
                if (patch.snapshot.directory) continue;
                const auto signature = inspect(patch.originalPath);
                if (cancel->load()) { result.cancelled = true; return result; }
                result.signedTargetWillChange = result.signedTargetWillChange || signature.embedded || signature.catalog;
                result.hasCatalogSignature = result.hasCatalogSignature || signature.catalog;
            }
            return result;
        }

        void continueSaveAfterSignaturePreflight(
            QList<ks::file::metadata::TargetPatch> patches,
            const bool signedTargetWillChange, const bool hasCatalogSignature)
        {
            const QPointer<FileDetailDialog> lifetime(this);
            bool requiresBackup = std::any_of(patches.cbegin(), patches.cend(),
                [](const auto& patch) { return patch.highRisk(); });
            if (requiresBackup &&
                (m_backupBeforeSaveCheck == nullptr || !m_backupBeforeSaveCheck->isChecked()))
            {
                QMessageBox::warning(
                    this,
                    ks::i18n::sourceText(QStringLiteral("必须创建备份")),
                    ks::i18n::sourceText(QStringLiteral(
                        "暂存内容包含高风险操作。EA 原始数据、Object ID、重解析点、PE 资源和签名清除必须勾选“创建备份再修改”。")));
                return;
            }

            if (signedTargetWillChange)
            {
                QPointer<QMessageBox> signaturePrompt = new QMessageBox(this);
                signaturePrompt->setIcon(QMessageBox::Warning);
                signaturePrompt->setWindowTitle(
                    ks::i18n::sourceText(QStringLiteral("已签名文件将被修改")));
                signaturePrompt->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "修改已签名文件后，Authenticode 验证可能失效。请选择签名数据处理方式。")) +
                    (hasCatalogSignature
                        ? QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral(
                            "检测到 Catalog 签名。Catalog 只能显示失效状态，无法从文件本身删除。"))
                        : QString()));
                QPushButton* removeButton = signaturePrompt->addButton(
                    ks::i18n::sourceText(QStringLiteral("清除嵌入式签名并继续")),
                    QMessageBox::AcceptRole);
                QPushButton* preserveButton = signaturePrompt->addButton(
                    ks::i18n::sourceText(QStringLiteral("保留签名数据并继续")),
                    QMessageBox::DestructiveRole);
                QPushButton* cancelButton = signaturePrompt->addButton(
                    QMessageBox::Cancel);
                signaturePrompt->setDefaultButton(cancelButton);
                signaturePrompt->exec();
                if (lifetime == nullptr || signaturePrompt == nullptr) return;
                signaturePrompt->deleteLater();
                if (signaturePrompt->clickedButton() == cancelButton)
                {
                    return;
                }
                if (signaturePrompt->clickedButton() == removeButton)
                {
                    for (ks::file::metadata::TargetPatch& patch : patches)
                    {
                        if (patch.snapshot.embeddedSignature)
                        {
                            patch.signatureDisposition =
                                ks::file::metadata::SignatureDisposition::RemoveEmbedded;
                        }
                    }
                }
                else if (signaturePrompt->clickedButton() != preserveButton)
                {
                    return;
                }
            }

            requiresBackup = std::any_of(
                patches.cbegin(),
                patches.cend(),
                [](const ks::file::metadata::TargetPatch& patch) { return patch.highRisk(); });
            if (requiresBackup &&
                (m_backupBeforeSaveCheck == nullptr || !m_backupBeforeSaveCheck->isChecked()))
            {
                QMessageBox::warning(
                    this,
                    ks::i18n::sourceText(QStringLiteral("必须创建备份")),
                    ks::i18n::sourceText(QStringLiteral(
                        "当前签名处理或高风险修改要求先创建备份。请勾选“创建备份再修改”。")));
                return;
            }

            const QMessageBox::StandardButton confirmation = QMessageBox::question(
                this,
                ks::i18n::sourceText(QStringLiteral("确认保存全部修改")),
                ks::i18n::sourceText(QStringLiteral(
                    "将保存 %1 个目标、%2 类暂存操作。保存前会重新校验文件身份，随后备份、写入并回读。是否继续？"))
                    .arg(patches.size())
                    .arg(pendingOperationCount()),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (lifetime == nullptr || confirmation != QMessageBox::Yes)
            {
                return;
            }

            setTransactionBusy(true);
            if (m_pendingChangesLabel != nullptr)
            {
                m_pendingChangesLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("● 正在后台保存、回读并生成逐操作结果...")));
            }
            ks::file::metadata::TransactionOptions options;
            options.createBackup = m_backupBeforeSaveCheck != nullptr &&
                m_backupBeforeSaveCheck->isChecked();
            QPointer<FileDetailDialog> guardThis(this);
            const auto pendingPatches = m_pendingPatches;
            const auto originalPaths = m_filePaths;
            auto* task = QRunnable::create([guardThis, patches, options, pendingPatches, originalPaths]()
                {
                    const ks::file::metadata::TransactionResult result =
                        ks::file::metadata::executeTransaction(patches, options);
                    auto updatedPending = pendingPatches;
                    auto updatedPaths = originalPaths;
                    reconcileTransactionResults(result, updatedPending, updatedPaths);
                    const auto rows = transactionDisplayRows(result);
                    // Accepted transactions finish independently of the page. Only
                    // the queued GUI callback may dereference the dialog guard.
                    QMetaObject::invokeMethod(
                        qApp,
                        [guardThis, result, updatedPending, updatedPaths, rows]()
                        {
                            if (guardThis == nullptr) return;
                            guardThis->m_pendingPatches = updatedPending;
                            guardThis->m_filePaths = updatedPaths;
                            guardThis->m_filePath = updatedPaths.value(0);
                            if (guardThis->m_batchMode)
                                guardThis->startBatchGeneralFileSnapshotLoad(
                                    guardThis->m_generalBatchTable, guardThis->m_generalBatchSummary);
                            guardThis->setTransactionBusy(false);
                            guardThis->showTransactionResults(result, rows);
                            guardThis->updatePendingSaveUi();
                            if (result.ok)
                            {
                                guardThis->setWindowTitle(guardThis->m_batchMode
                                    ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项"))
                                        .arg(guardThis->m_filePaths.size())
                                    : ks::i18n::displayText(QStringLiteral("文件属性 - %1"))
                                        .arg(QFileInfo(guardThis->m_filePath).fileName()));
                                if (guardThis->m_metadataStatusLabel != nullptr)
                                {
                                    guardThis->m_metadataStatusLabel->setText(
                                        ks::i18n::sourceText(QStringLiteral(
                                            "● 所有暂存修改已保存并完成写后回读。")));
                                }
                                guardThis->m_generalR0Loaded = false;
                                if (!guardThis->m_batchMode)
                                {
                                    guardThis->startGeneralFileSnapshotLoad();
                                }
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        QWidget* buildDeferredTab(const QString& lazyKey)
        {
            // 用途：创建文件属性窗口的轻量占位页。
            // 处理：只保存 lazyKey 和提示文本，不读取文件、不启动外部进程；
            // 返回：首次切换到该页时由 activateDeferredTab 替换为真实页面。
            QWidget* page = new QWidget(this);
            page->setProperty("ks_file_detail_lazy_key", lazyKey);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QLabel* loadingLabel = new QLabel(page);
            loadingLabel->setWordWrap(true);
            loadingLabel->setText(QStringLiteral(
                "该页面将在首次打开时加载。\n"
                "这样文件属性窗口可以先快速弹出，PE/签名/字符串等重型分析不会阻塞首屏。"));
            layout->addWidget(loadingLabel, 0);
            layout->addStretch(1);
            return page;
        }

        void activateDeferredTab(QTabWidget* tabWidget, const int tabIndex)
        {
            // 用途：首次选中懒加载页时，用真实页面替换占位页。
            // 输入 tabWidget/tabIndex：当前属性窗口 Tab 容器和被激活的索引。
            // 处理：根据 lazyKey 创建对应页面；重型页面内部继续走后台线程。
            // 返回：无；已加载页面不会重复替换。
            if (tabWidget == nullptr || tabIndex < 0)
            {
                return;
            }

            QWidget* placeholderPage = tabWidget->widget(tabIndex);
            if (placeholderPage == nullptr)
            {
                return;
            }
            const QString lazyKey = placeholderPage
                ->property("ks_file_detail_lazy_key")
                .toString()
                .trimmed()
                .toLower();
            if (lazyKey.isEmpty())
            {
                return;
            }

            const QPointer<QTabWidget> tabGuard(tabWidget);
            const QPointer<QWidget> placeholderGuard(placeholderPage);
            ks::ui::scheduleDeferredTabActivation(
                this,
                tabWidget,
                tabIndex,
                placeholderPage,
                [this, tabGuard, placeholderGuard, tabIndex, lazyKey]()
                {
                    if (tabGuard.isNull() || placeholderGuard.isNull() ||
                        tabGuard->currentIndex() != tabIndex ||
                        tabGuard->widget(tabIndex) != placeholderGuard.data())
                    {
                        return;
                    }

                    QWidget* realPage = nullptr;
                    if (lazyKey == QStringLiteral("metadata"))
                    {
                        realPage = buildMetadataTab();
                    }
                    else if (lazyKey == QStringLiteral("metadata_name"))
                    {
                        realPage = buildMetadataNameAndFilesystemPage(tabGuard.data());
                    }
                    else if (lazyKey == QStringLiteral("metadata_shell"))
                    {
                        realPage = buildMetadataShellPropertyPage(tabGuard.data());
                    }
                    else if (lazyKey == QStringLiteral("metadata_ads"))
                    {
                        realPage = buildMetadataAdsPage(tabGuard.data());
                    }
                    else if (lazyKey == QStringLiteral("metadata_ea"))
                    {
                        realPage = buildMetadataEaPage(tabGuard.data());
                    }
                    else if (lazyKey == QStringLiteral("metadata_security"))
                    {
                        realPage = buildMetadataSecurityPage(tabGuard.data());
                    }
                    else if (lazyKey == QStringLiteral("metadata_pe"))
                    {
                        realPage = buildMetadataPeAndReparsePage(tabGuard.data());
                    }
                    else if (lazyKey == QStringLiteral("security"))
                    {
                        realPage = buildSecurityTab();
                    }
                    else if (lazyKey == QStringLiteral("reparse"))
                    {
                        realPage = buildReparseTab();
                    }
                    else if (lazyKey == QStringLiteral("hash"))
                    {
                        realPage = buildHashTab();
                    }
                    else if (lazyKey == QStringLiteral("usage"))
                    {
                        realPage = buildUsageTab();
                    }
                    else if (lazyKey == QStringLiteral("fileobject"))
                    {
                        realPage = buildFileObjectTab();
                    }
                    else if (lazyKey == QStringLiteral("storage"))
                    {
                        realPage = buildStorageTab();
                    }
                    else if (lazyKey == QStringLiteral("filters"))
                    {
                        realPage = buildFilterTopologyTab();
                    }
                    else if (lazyKey == QStringLiteral("signature"))
                    {
                        realPage = buildSignatureTab();
                    }
                    else if (lazyKey == QStringLiteral("pe"))
                    {
                        realPage = buildPeTab();
                    }
                    else if (lazyKey == QStringLiteral("dependencies"))
                    {
                        realPage = buildDependencyTab();
                    }
                    else if (lazyKey == QStringLiteral("strings"))
                    {
                        realPage = buildStringsTab();
                    }
                    else if (lazyKey == QStringLiteral("hex"))
                    {
                        realPage = buildHexTab();
                    }

                    if (realPage == nullptr || tabGuard.isNull() || placeholderGuard.isNull() ||
                        tabGuard->widget(tabIndex) != placeholderGuard.data())
                    {
                        if (realPage != nullptr)
                        {
                            realPage->deleteLater();
                        }
                        return;
                    }

                    ks::ui::ScopedWidgetThemePreparation prepareTheme(tabGuard.data());
                    const QString titleText = tabGuard->tabText(tabIndex);
                    // 编辑表单由共享详情框架按页面内部用途适配；禁止在整个 Tab 外再套滚动区。
                    tabGuard->removeTab(tabIndex);
                    tabGuard->insertTab(tabIndex, realPage, titleText);
                    // 新建的懒加载页也必须立即拿到 Surface 调色板，不能回退到系统 Base。
                    realPage->setMinimumSize(0, 0);
                    realPage->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
                    // Only the outer detail navigation owns a hidden tab bar.
                    // Metadata keeps its original seven visible inner tabs.
                    if (tabGuard.data() == m_tabWidget)
                    {
                        tabGuard->tabBar()->hide();
                    }
                    ks::ui::InstallDetailWindowFramework(this);
                    applyThemeStyle();
                    tabGuard->setCurrentIndex(tabIndex);
                    placeholderGuard->deleteLater();
                });
        }

        // 创建全宽对象摘要；文件位置与复制动作在切换任何详情页时仍可达。
        QWidget* buildIdentityHeader()
        {
            const QString title = m_batchMode
                ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(m_filePaths.size())
                : QFileInfo(m_filePath).fileName();
            QWidget* header = ks::ui::CreateDetailSummaryHeader(this, title,
                QDir::toNativeSeparators(m_filePath), QIcon(QStringLiteral(":/Icon/process_details.svg")));
            const QPointer<QLabel> imageGuard(qobject_cast<QLabel*>(header->layout()->itemAt(0)->widget()));
            const QPointer<FileDetailDialog> guardThis(this);
            const QString path = m_filePath;
            QThreadPool::globalInstance()->start(QRunnable::create([guardThis, imageGuard, path]()
                {
                    const HRESULT comResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
                    const QString nativePath = QDir::toNativeSeparators(path);
                    SHFILEINFOW shellInfo{};
                    QImage image;
                    if (::SHGetFileInfoW(reinterpret_cast<const wchar_t*>(nativePath.utf16()), 0,
                        &shellInfo, sizeof(shellInfo), SHGFI_ICON | SHGFI_LARGEICON) && shellInfo.hIcon)
                    {
                        image = QImage::fromHICON(shellInfo.hIcon);
                        ::DestroyIcon(shellInfo.hIcon);
                    }
                    if (SUCCEEDED(comResult)) ::CoUninitialize();
                    QMetaObject::invokeMethod(qApp, [guardThis, imageGuard, path, image]()
                        {
                            if (guardThis == nullptr || imageGuard == nullptr ||
                                guardThis->m_filePath != path || image.isNull()) return;
                            imageGuard->setPixmap(QIcon(QPixmap::fromImage(image)).pixmap(48, 48));
                        }, Qt::QueuedConnection);
                }));
            auto* actions = qobject_cast<QHBoxLayout*>(header->layout());
            auto* location = new QPushButton(ks::i18n::sourceText(QStringLiteral("打开所在位置")), header);
            auto* copyPath = new QPushButton(ks::i18n::sourceText(QStringLiteral("复制路径")), header);
            location->setIcon(QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
            copyPath->setIcon(QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")));
            for (QPushButton* button : {location, copyPath})
            {
                button->setToolTip(button->text());
                ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
                    ks::ui::FlatButtonAppearance::Solid);
                ks::ui::NormalizeToolbarControl(button);
                actions->addWidget(button);
            }
            connect(location, &QPushButton::clicked, this, [this]()
            {
                QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(m_filePath).absolutePath()));
            });
            connect(copyPath, &QPushButton::clicked, this, [this]()
            {
                if (auto* clipboard = QApplication::clipboard())
                {
                    clipboard->setText(m_batchMode ? m_filePaths.join(QLatin1Char('\n'))
                        : QDir::toNativeSeparators(m_filePath));
                }
            });
            return header;
        }

        void startBatchGeneralFileSnapshotLoad(QTableView* table, QLabel* summary)
        {
            if (table == nullptr || summary == nullptr || m_generalBatchRowsModel == nullptr) return;
            if (m_generalReadCancel != nullptr) m_generalReadCancel->store(true);
            summary->setText(ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据...")));
            const QStringList paths = m_filePaths;
            const auto cancel = std::make_shared<std::atomic_bool>(false);
            m_generalReadCancel = cancel;
            const QPointer<FileDetailDialog> guardThis(this);
            const QPointer<QTableView> tableGuard(table);
            const QPointer<QLabel> summaryGuard(summary);
            const QPointer<FileDetailRowsModel> modelGuard(m_generalBatchRowsModel);
            QThreadPool::globalInstance()->start(QRunnable::create([guardThis, tableGuard, summaryGuard, modelGuard, paths, cancel]()
                {
                    auto rows = makeFileDetailRows();
                    rows->reserve(paths.size());
                    quint64 totalSize = 0;
                    int directoryCount = 0;
                    int fileCount = 0;
                    for (const QString& path : paths)
                    {
                        if (cancel->load()) return;
                        const QFileInfo info(path);
                        const bool exists = info.exists();
                        if (exists && info.isDir()) ++directoryCount;
                        if (exists && info.isFile())
                        {
                            ++fileCount;
                            totalSize += static_cast<quint64>(std::max<qint64>(0, info.size()));
                        }
                        const auto nativePath = QDir::toNativeSeparators(path).toStdWString();
                        const DWORD attributes = ::GetFileAttributesW(nativePath.c_str());
                        rows->push_back(QStringList{ QDir::toNativeSeparators(path),
                            info.isDir() ? QStringLiteral("目录") : (info.isFile() ? QStringLiteral("文件") : QStringLiteral("其它")),
                            info.isFile() ? formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, info.size()))) : QStringLiteral("-"),
                            attributes == INVALID_FILE_ATTRIBUTES ? QStringLiteral("-") : fileAttributesToText(attributes),
                            info.lastModified().isValid() ? info.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QStringLiteral("-"),
                            exists ? QStringLiteral("可访问") : QStringLiteral("不存在或不可访问") });
                    }
                    QMetaObject::invokeMethod(qApp,
                        [guardThis, tableGuard, summaryGuard, modelGuard, paths, cancel, rows, totalSize, directoryCount, fileCount]()
                        {
                            const auto commitSnapshot =
                                [guardThis, tableGuard, summaryGuard, modelGuard, paths, cancel, rows, totalSize, directoryCount, fileCount]()
                                {
                                    if (guardThis == nullptr || tableGuard == nullptr || summaryGuard == nullptr || modelGuard == nullptr ||
                                        cancel->load() || guardThis->m_filePaths != paths) return;
                                    modelGuard->setSnapshot(rows);
                                    if (guardThis == nullptr || tableGuard == nullptr || summaryGuard == nullptr || modelGuard == nullptr ||
                                        cancel->load() || guardThis->m_filePaths != paths) return;
                                    summaryGuard->setText(ks::i18n::sourceText(QStringLiteral(
                                        "已选择 %1 项：文件 %2，目录 %3，文件总大小 %4。"))
                                        .arg(paths.size()).arg(fileCount).arg(directoryCount).arg(formatFileSizeText(totalSize)));
                                };
                            if (guardThis == nullptr || tableGuard == nullptr || summaryGuard == nullptr || modelGuard == nullptr ||
                                cancel->load() || guardThis->m_filePaths != paths) return;
                            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                                guardThis.data(), QStringLiteral("file-detail-general-snapshot"),
                                { tableGuard.data() }, commitSnapshot)) return;
                            commitSnapshot();
                        }, Qt::QueuedConnection);
                }));
        }

        QWidget* buildGeneralTab()
        {
            if (m_batchMode)
            {
                QWidget* page = new QWidget(this);
                QVBoxLayout* layout = new QVBoxLayout(page);
                QTableView* table = new ks::ui::TableActionTableView(page);
                ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
                table->setSelectionBehavior(QAbstractItemView::SelectRows);
                table->setSelectionMode(QAbstractItemView::ExtendedSelection);
                table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                table->setAlternatingRowColors(true);
                table->setProperty("ks_i18n_preserve_model_data", true);
                QLabel* summary = new QLabel(ks::i18n::sourceText(
                    QStringLiteral("● 正在后台读取文件元数据...")), page);
                summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
                layout->addWidget(summary);
                installValueTableCopyMenu(table);
                ks::ui::SetTableColumnAutoFitEnabled(table, false);
                if (table->horizontalHeader() != nullptr)
                {
                    table->horizontalHeader()->setResizeContentsPrecision(64);
                    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
                    table->horizontalHeader()->setStretchLastSection(true);
                    table->horizontalHeader()->setSortIndicator(-1, Qt::AscendingOrder);
                }
                layout->addWidget(table, 1);
                auto* model = new FileDetailRowsModel(std::make_shared<const FileDetailRows>(), table,
                    { QStringLiteral("目标"), QStringLiteral("类型"), QStringLiteral("大小"),
                      QStringLiteral("属性"), QStringLiteral("修改时间"), QStringLiteral("状态") }, {1, 2, 3, 5});
                auto* proxy = new QSortFilterProxyModel(table);
                proxy->setDynamicSortFilter(false);
                proxy->setSourceModel(model);
                table->setModel(proxy);
                table->setSortingEnabled(true);
                m_generalBatchTable = table;
                m_generalBatchSummary = summary;
                m_generalBatchRowsModel = model;
                startBatchGeneralFileSnapshotLoad(table, summary);
                return page;
            }

            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            m_generalPropertyView = new ks::ui::StructuredFieldView(page);
            m_generalR0Info = {};
            layout->addWidget(m_generalPropertyView, 1);
            startGeneralFileSnapshotLoad();
            return page;
        }

        static QComboBox* buildChangeStateCombo(QWidget* parent)
        {
            QComboBox* combo = new QComboBox(parent);
            combo->addItem(QStringLiteral("不修改"),
                static_cast<int>(ks::file::metadata::ChangeState::Unchanged));
            combo->addItem(QStringLiteral("启用"),
                static_cast<int>(ks::file::metadata::ChangeState::Enabled));
            combo->addItem(QStringLiteral("禁用"),
                static_cast<int>(ks::file::metadata::ChangeState::Disabled));
            return combo;
        }

        static ks::file::metadata::ChangeState changeStateFromCombo(const QComboBox* combo)
        {
            return combo == nullptr
                ? ks::file::metadata::ChangeState::Unchanged
                : static_cast<ks::file::metadata::ChangeState>(combo->currentData().toInt());
        }

        static QByteArray parseMetadataHexText(const QString& text, bool* okOut)
        {
            QString normalized = text;
            normalized.remove(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]")));
            const bool valid = (normalized.size() % 2) == 0;
            if (okOut != nullptr) *okOut = valid;
            return valid ? QByteArray::fromHex(normalized.toLatin1()) : QByteArray();
        }

        static QByteArray metadataEditorBytes(
            const QPlainTextEdit* editor,
            const QComboBox* formatCombo,
            bool* okOut)
        {
            if (editor == nullptr)
            {
                if (okOut != nullptr) *okOut = false;
                return {};
            }
            if (editor->property("ks_file_metadata_incomplete").toBool())
            {
                if (okOut != nullptr) *okOut = false;
                return {};
            }
            const QVariant original = editor->property("ks_file_metadata_original_bytes");
            const int format = formatCombo == nullptr ? 0 : formatCombo->currentIndex();
            if (original.isValid() &&
                editor->property("ks_file_metadata_original_revision").toInt() == editor->document()->revision() &&
                editor->property("ks_file_metadata_original_format").toInt() == format)
            {
                if (okOut != nullptr) *okOut = true;
                return original.toByteArray();
            }
            if (formatCombo != nullptr && formatCombo->currentIndex() == 1)
            {
                return parseMetadataHexText(editor->toPlainText(), okOut);
            }
            if (okOut != nullptr) *okOut = true;
            return editor->toPlainText().toUtf8();
        }

        static QTableView* createPropertyTable(QWidget* parent, QStringList headers, const QString& key)
        {
            auto* table = new ks::ui::TableActionTableView(parent);
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            auto* model = new ks::fileui::PropertyTableModel(std::move(headers), table,
                [](const QString& value) { return ks::i18n::displayText(value); });
            table->setModel(model);
            new ks::fileui::PropertyTableCommitHost(table, model, parent, key);
            table->setProperty("ksword_detail_preserve_model_data", true);
            table->setProperty("ks_i18n_preserve_model_data", true);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setAlternatingRowColors(true);
            table->setWordWrap(false);
            table->verticalHeader()->hide();
            table->horizontalHeader()->setStretchLastSection(true);
            for (int column = 0; column < model->columnCount(); ++column) table->setColumnWidth(column, column == 0 ? 220 : 160);
            table->setSortingEnabled(true);
            return table;
        }
        static ks::fileui::PropertyTableModel* propertyTableModel(QTableView* table)
        {
            return table == nullptr ? nullptr : static_cast<ks::fileui::PropertyTableModel*>(table->model());
        }
        static QVariant propertyCell(QTableView* table, int row, int column, int role = Qt::DisplayRole)
        {
            return table->model()->index(row, column).data(role);
        }

        void refreshMetadataStreamTable(QTableView* table) { refreshMetadataBinaryTable(table, false); }

        void refreshMetadataEaTable(QTableView* table) { refreshMetadataBinaryTable(table, true); }

        void refreshMetadataBinaryTable(QTableView* table, bool ea)
        {
            if (table == nullptr) return;
            const auto generation = table->property("ks_file_metadata_list_generation").toULongLong() + 1;
            table->setProperty("ks_file_metadata_list_generation", generation);
            propertyTableModel(table)->invalidateRequest();
            const QStringList paths = m_filePaths;
            const QPointer<FileDetailDialog> owner(this);
            const QPointer<QTableView> tableGuard(table);
            QThreadPool::globalInstance()->start(QRunnable::create([owner, tableGuard, paths, generation, ea]()
                {
                    auto snapshot = ks::fileui::makePropertyTableSnapshot();
                    for (const QString& path : paths)
                    {
                        DWORD error = ERROR_SUCCESS;
                        if (ea)
                        {
                            const auto entries = ks::file::metadata::enumerateExtendedAttributes(path, &error);
                            if (error == ERROR_SUCCESS) for (const auto& entry : entries)
                                snapshot->append({ ks::fileui::propertyRowKey({path, entry.name}),
                                    {path, entry.name, QString::number(entry.value.size()),
                                        QString::fromLatin1(entry.value.left(64).toHex(' ').toUpper())}, {} });
                        }
                        else
                        {
                            const auto streams = ks::file::metadata::enumerateStreams(path, &error);
                            if (error == ERROR_SUCCESS) for (const auto& stream : streams)
                                snapshot->append({ ks::fileui::propertyRowKey({path, stream.name}),
                                    {path, stream.name, QString::number(stream.size)}, {} });
                        }
                        if (error != ERROR_SUCCESS)
                            snapshot->append({ks::fileui::propertyRowKey({path, QStringLiteral("<读取失败>")}),
                                ea ? QStringList{path, QStringLiteral("<读取失败>"), QString::number(error), {}}
                                   : QStringList{path, QStringLiteral("<读取失败>"), QString::number(error)}, {}, {1}});
                    }
                    QMetaObject::invokeMethod(qApp, [owner, tableGuard, paths, generation, snapshot]()
                        {
                            if (!owner || !tableGuard || owner->m_filePaths != paths ||
                                tableGuard->property("ks_file_metadata_list_generation").toULongLong() != generation) return;
                            propertyTableModel(tableGuard)->setSnapshot(snapshot);
                        }, Qt::QueuedConnection);
                }));
        }

        QWidget* buildMetadataNameAndFilesystemPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QFormLayout* form = new QFormLayout();

            QCheckBox* renameCheck = new QCheckBox(QStringLiteral("暂存重命名"), page);
            QLineEdit* renameEdit = new QLineEdit(page);
            renameEdit->setText(m_batchMode ? QString() : QFileInfo(m_filePath).fileName());
            renameEdit->setEnabled(!m_batchMode);
            renameCheck->setEnabled(!m_batchMode);
            form->addRow(renameCheck, renameEdit);

            QCheckBox* shortNameCheck = new QCheckBox(QStringLiteral("设置 8.3 短文件名"), page);
            QLineEdit* shortNameEdit = new QLineEdit(page);
            shortNameEdit->setPlaceholderText(QStringLiteral("例如 SAMPLE~1.TXT；留空可清除短名"));
            shortNameEdit->setEnabled(!m_batchMode);
            shortNameCheck->setEnabled(!m_batchMode);
            form->addRow(shortNameCheck, shortNameEdit);

            QComboBox* caseSensitiveCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("目录大小写敏感"), caseSensitiveCombo);
            QComboBox* compressionCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("NTFS 压缩"), compressionCombo);
            QComboBox* sparseCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("稀疏文件"), sparseCombo);
            QComboBox* encryptionCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("EFS 加密"), encryptionCombo);
            QComboBox* integrityCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("Integrity Stream"), integrityCombo);

            QComboBox* objectIdAction = new QComboBox(page);
            objectIdAction->addItems(QStringList{
                QStringLiteral("不修改"),
                QStringLiteral("设置 Object ID"),
                QStringLiteral("删除 Object ID") });
            QLineEdit* objectIdEdit = new QLineEdit(page);
            objectIdEdit->setPlaceholderText(QStringLiteral("16 字节或完整 64 字节十六进制"));
            QHBoxLayout* objectIdLayout = new QHBoxLayout();
            objectIdLayout->addWidget(objectIdAction);
            objectIdLayout->addWidget(objectIdEdit, 1);
            ks::ui::NormalizeToolbarRow(objectIdLayout);
            form->addRow(QStringLiteral("Object ID"), objectIdLayout);

            auto* hardLinksEdit = new CodeTextEdit(page);
            hardLinksEdit->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            hardLinksEdit->setLineNumbersVisible(false);
            hardLinksEdit->setCompactMode(true);
            hardLinksEdit->setPlaceholderText(QStringLiteral("每行一个要创建的硬链接完整路径；仅单文件模式可用"));
            hardLinksEdit->setMaximumHeight(70);
            hardLinksEdit->setEnabled(!m_batchMode);
            form->addRow(QStringLiteral("新增硬链接"), hardLinksEdit);
            layout->addLayout(form);

            QHBoxLayout* hardLinkQueryLayout = new QHBoxLayout();
            QPushButton* queryHardLinksButton = new QPushButton(QStringLiteral("枚举现有硬链接"), page);
            QLabel* hardLinkQueryResult = new QLabel(QStringLiteral("-"), page);
            hardLinkQueryResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
            hardLinkQueryResult->setWordWrap(true);
            queryHardLinksButton->setEnabled(!m_batchMode);
            hardLinkQueryLayout->addWidget(queryHardLinksButton);
            hardLinkQueryLayout->addWidget(hardLinkQueryResult, 1);
            ks::ui::NormalizeToolbarRow(hardLinkQueryLayout);
            layout->addLayout(hardLinkQueryLayout);

            QLabel* hint = new QLabel(QStringLiteral(
                "压缩、稀疏、EFS、Integrity Stream、Object ID 均通过公开 Win32/FSCTL 在 R3 完成。"
                "文件长度、有效数据长度、分配大小仍保持只读。"), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存名称与文件系统修改"), page);
            ks::ui::NormalizeToolbarControl(stageButton);
            layout->addWidget(stageButton, 0, Qt::AlignRight);
            layout->addStretch(1);

            connect(queryHardLinksButton, &QPushButton::clicked, this,
                [this, queryHardLinksButton, hardLinkQueryResult]()
                {
                    const QString path = m_filePath;
                    runMetadataRead(hardLinkQueryResult, queryHardLinksButton, path,
                        [path](const auto&)
                        {
                            MetadataReadValue result;
                            const auto links = ks::file::metadata::enumerateHardLinks(path, &result.error);
                            result.text = links.join(QStringLiteral(" | "));
                            return result;
                        },
                        [this, hardLinkQueryResult](const MetadataReadValue& result, MetadataReadState*)
                        {
                            hardLinkQueryResult->setText(result.error == ERROR_SUCCESS ? result.text
                                : QStringLiteral("枚举失败：%1").arg(formatWin32ErrorText(result.error)));
                            return false;
                        });
                });

            connect(stageButton, &QPushButton::clicked, this,
                [this, renameCheck, renameEdit, shortNameCheck, shortNameEdit,
                 caseSensitiveCombo, compressionCombo, sparseCombo, encryptionCombo,
                 integrityCombo, objectIdAction, objectIdEdit, hardLinksEdit]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QByteArray objectIdBytes;
                    if (objectIdAction->currentIndex() == 1)
                    {
                        bool objectIdOk = false;
                        objectIdBytes = parseMetadataHexText(objectIdEdit->text(), &objectIdOk);
                        if (!objectIdOk || (objectIdBytes.size() != 16 && objectIdBytes.size() != 64))
                        {
                            QMessageBox::warning(this, QStringLiteral("Object ID"),
                                QStringLiteral("Object ID 必须是 16 字节或完整 64 字节十六进制。"));
                            return;
                        }
                    }
                    const QStringList hardLinkPaths = hardLinksEdit->toPlainText()
                        .split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.rename = !m_batchMode && renameCheck->isChecked();
                        patch.newName = renameEdit->text().trimmed();
                        patch.setShortName = !m_batchMode && shortNameCheck->isChecked();
                        patch.shortName = shortNameEdit->text().trimmed();
                        patch.caseSensitive = patch.snapshot.directory
                            ? changeStateFromCombo(caseSensitiveCombo)
                            : ks::file::metadata::ChangeState::Unchanged;
                        patch.compression = changeStateFromCombo(compressionCombo);
                        patch.sparse = patch.snapshot.directory
                            ? ks::file::metadata::ChangeState::Unchanged
                            : changeStateFromCombo(sparseCombo);
                        patch.encryption = changeStateFromCombo(encryptionCombo);
                        patch.integrityStream = changeStateFromCombo(integrityCombo);
                        patch.objectId.update = objectIdAction->currentIndex() != 0;
                        patch.objectId.remove = objectIdAction->currentIndex() == 2;
                        patch.objectId.objectId = objectIdBytes;
                        patch.hardLinkPaths = m_batchMode ? QStringList() : hardLinkPaths;
                    }
                    updatePendingSaveUi();
                });
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QWidget* buildMetadataShellPropertyPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QGridLayout* grid = new QGridLayout();
            struct ShellRow
            {
                QCheckBox* update = nullptr;
                QLineEdit* editor = nullptr;
            };
            const QStringList labels{
                QStringLiteral("标题"),
                QStringLiteral("主题"),
                QStringLiteral("作者（分号分隔）"),
                QStringLiteral("标签 / 关键字（分号分隔）"),
                QStringLiteral("注释"),
                QStringLiteral("版权") };
            std::array<ShellRow, 6> rows{};
            for (int index = 0; index < static_cast<int>(rows.size()); ++index)
            {
                rows[static_cast<std::size_t>(index)].update =
                    new QCheckBox(QStringLiteral("修改"), page);
                rows[static_cast<std::size_t>(index)].editor = new QLineEdit(page);
                grid->addWidget(rows[static_cast<std::size_t>(index)].update, index, 0);
                grid->addWidget(new QLabel(labels.at(index), page), index, 1);
                grid->addWidget(rows[static_cast<std::size_t>(index)].editor, index, 2);
            }
            QCheckBox* ratingCheck = new QCheckBox(QStringLiteral("修改"), page);
            QSpinBox* ratingSpin = new QSpinBox(page);
            ratingSpin->setRange(0, 99);
            grid->addWidget(ratingCheck, 6, 0);
            grid->addWidget(new QLabel(QStringLiteral("评分（0-99）"), page), 6, 1);
            grid->addWidget(ratingSpin, 6, 2);
            grid->setColumnStretch(2, 1);
            layout->addLayout(grid);

            QLabel* status = new QLabel(QStringLiteral("可从第一个目标读取当前 Shell 属性。"), page);
            status->setWordWrap(true);
            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取当前值"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 Shell 属性"), page);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addWidget(status);
            layout->addLayout(actions);
            ks::ui::NormalizeToolbarRow(actions);
            layout->addStretch(1);

            connect(loadButton, &QPushButton::clicked, this, [this, rows, ratingSpin, status]()
                {
                    status->setText(QStringLiteral("● 正在后台读取 Shell 属性..."));
                    const QString path = m_filePath;
                    QPointer<FileDetailDialog> dialogGuard(this);
                    QPointer<QLabel> statusGuard(status);
                    auto* task = QRunnable::create([dialogGuard, statusGuard, path, rows, ratingSpin]()
                        {
                            const ks::file::metadata::ShellProperties properties =
                                ks::file::metadata::readShellProperties(path);
                            if (dialogGuard == nullptr) return;
                            QMetaObject::invokeMethod(dialogGuard.data(),
                                [dialogGuard, statusGuard, properties, rows, ratingSpin]()
                                {
                                    if (dialogGuard == nullptr || statusGuard == nullptr) return;
                                    if (!properties.ok)
                                    {
                                        statusGuard->setText(QStringLiteral("● Shell 属性读取失败：%1")
                                            .arg(formatWin32ErrorText(properties.win32Error)));
                                        return;
                                    }
                                    const QStringList values{
                                        properties.title,
                                        properties.subject,
                                        properties.authors.join(QStringLiteral("; ")),
                                        properties.keywords.join(QStringLiteral("; ")),
                                        properties.comment,
                                        properties.copyright };
                                    for (int index = 0; index < values.size(); ++index)
                                    {
                                        if (rows[static_cast<std::size_t>(index)].editor != nullptr)
                                        {
                                            rows[static_cast<std::size_t>(index)].editor->setText(values.at(index));
                                        }
                                    }
                                    ratingSpin->setValue(static_cast<int>(properties.rating));
                                    statusGuard->setText(QStringLiteral("● 已读取第一个目标的当前值。"));
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                });
            connect(stageButton, &QPushButton::clicked, this, [this, rows, ratingCheck, ratingSpin, status]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        auto& shell = patch.shellProperties;
                        shell.updateTitle = rows[0].update->isChecked();
                        shell.title = rows[0].editor->text();
                        shell.updateSubject = rows[1].update->isChecked();
                        shell.subject = rows[1].editor->text();
                        shell.updateAuthors = rows[2].update->isChecked();
                        shell.authors = rows[2].editor->text().split(QLatin1Char(';'), Qt::SkipEmptyParts);
                        shell.updateKeywords = rows[3].update->isChecked();
                        shell.keywords = rows[3].editor->text().split(QLatin1Char(';'), Qt::SkipEmptyParts);
                        shell.updateComment = rows[4].update->isChecked();
                        shell.comment = rows[4].editor->text();
                        shell.updateCopyright = rows[5].update->isChecked();
                        shell.copyright = rows[5].editor->text();
                        shell.updateRating = ratingCheck->isChecked();
                        shell.rating = static_cast<quint32>(ratingSpin->value());
                    }
                    status->setText(QStringLiteral("● Shell 属性已暂存。"));
                    updatePendingSaveUi();
                });
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QWidget* buildMetadataAdsPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QTableView* table = createPropertyTable(page, QStringList{
                QStringLiteral("目标"), QStringLiteral("数据流"), QStringLiteral("字节数") }, QStringLiteral("file-detail-ads"));
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            installValueTableCopyMenu(table);
            layout->addWidget(table, 1);

            QGridLayout* editorLayout = new QGridLayout();
            QLineEdit* nameEdit = new QLineEdit(page);
            nameEdit->setPlaceholderText(QStringLiteral("例如 Zone.Identifier"));
            QComboBox* formatCombo = new QComboBox(page);
            formatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            QCheckBox* removeCheck = new QCheckBox(QStringLiteral("删除该数据流"), page);
            auto* dataEdit = new CodeTextEdit(page);
            dataEdit->setMaximumHeight(120);
            editorLayout->addWidget(new QLabel(QStringLiteral("流名称"), page), 0, 0);
            editorLayout->addWidget(nameEdit, 0, 1);
            editorLayout->addWidget(formatCombo, 0, 2);
            editorLayout->addWidget(removeCheck, 0, 3);
            editorLayout->addWidget(dataEdit, 1, 0, 1, 4);
            layout->addLayout(editorLayout);

            QGroupBox* zoneGroup = new QGroupBox(QStringLiteral("Zone.Identifier 结构化编辑"), page);
            QFormLayout* zoneLayout = new QFormLayout(zoneGroup);
            QSpinBox* zoneIdSpin = new QSpinBox(zoneGroup);
            zoneIdSpin->setRange(0, 4);
            zoneIdSpin->setValue(3);
            QLineEdit* referrerEdit = new QLineEdit(zoneGroup);
            QLineEdit* hostEdit = new QLineEdit(zoneGroup);
            QPushButton* buildZoneButton = new QPushButton(QStringLiteral("生成结构化内容"), zoneGroup);
            zoneLayout->addRow(QStringLiteral("ZoneId"), zoneIdSpin);
            zoneLayout->addRow(QStringLiteral("ReferrerUrl"), referrerEdit);
            zoneLayout->addRow(QStringLiteral("HostUrl"), hostEdit);
            zoneLayout->addRow(QString(), buildZoneButton);
            layout->addWidget(zoneGroup);

            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新数据流"), page);
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取选中流"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 ADS 操作"), page);
            actions->addWidget(refreshButton);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            ks::ui::NormalizeToolbarRow(actions);
            ks::ui::NormalizeToolbarControl(buildZoneButton);

            connect(refreshButton, &QPushButton::clicked, this,
                [this, table]() { refreshMetadataStreamTable(table); });
            connect(buildZoneButton, &QPushButton::clicked, this,
                [nameEdit, formatCombo, dataEdit, zoneIdSpin, referrerEdit, hostEdit]()
                {
                    nameEdit->setText(QStringLiteral("Zone.Identifier"));
                    formatCombo->setCurrentIndex(0);
                    QString content = QStringLiteral("[ZoneTransfer]\r\nZoneId=%1\r\n")
                        .arg(zoneIdSpin->value());
                    if (!referrerEdit->text().trimmed().isEmpty())
                        content += QStringLiteral("ReferrerUrl=%1\r\n").arg(referrerEdit->text().trimmed());
                    if (!hostEdit->text().trimmed().isEmpty())
                        content += QStringLiteral("HostUrl=%1\r\n").arg(hostEdit->text().trimmed());
                    dataEdit->setPlainText(content);
                });
            connect(loadButton, &QPushButton::clicked, this, [this, table, loadButton, nameEdit, formatCombo, dataEdit]()
                {
                    const int row = table->currentIndex().row();
                    if (row < 0) return;
                    const QString path = propertyCell(table, row, 0).toString();
                    const QString name = propertyCell(table, row, 1).toString();
                    const QString inputName = nameEdit->text();
                    const int revision = dataEdit->document()->revision();
                    runMetadataRead(dataEdit, loadButton, path,
                        [path, name](const auto& cancel)
                        {
                            MetadataReadValue result;
                            result.bytes = ks::file::metadata::readStream(path, name, &result.error);
                            result.name = name;
                            const bool printable = std::all_of(result.bytes.cbegin(), result.bytes.cend(), [](char value)
                                { const auto byte = static_cast<unsigned char>(value); return byte == '\r' || byte == '\n' || byte == '\t' || byte >= 0x20U; });
                            result.format = printable ? 0 : 1;
                            if (result.error == ERROR_SUCCESS && !cancel->load())
                                result.text = printable ? QString::fromUtf8(result.bytes) : formatMetadataHex(result.bytes, cancel);
                            return result;
                        },
                        [this, table, nameEdit, formatCombo, dataEdit, path, name, inputName, revision](const MetadataReadValue& result, MetadataReadState* state)
                        {
                            const int selected = table->currentIndex().row();
                            if (dataEdit->document()->revision() != revision || nameEdit->text() != inputName || selected < 0 ||
                                propertyCell(table, selected, 0).toString() != path || propertyCell(table, selected, 1).toString() != name) return false;
                            if (result.error != ERROR_SUCCESS)
                            {
                                QMessageBox::warning(this, QStringLiteral("ADS"),
                                    QStringLiteral("读取数据流失败：%1").arg(formatWin32ErrorText(result.error)));
                                return false;
                            }
                            nameEdit->setText(name);
                            formatCombo->setCurrentIndex(result.format);
                            publishMetadataText(dataEdit, state, result, {table, nameEdit, formatCombo});
                            return true;
                        }, true);
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, nameEdit, formatCombo, removeCheck, dataEdit]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QString name = nameEdit->text().trimmed();
                    if (name.startsWith(QLatin1Char(':'))) name.remove(0, 1);
                    if (name.endsWith(QStringLiteral(":$DATA"), Qt::CaseInsensitive)) name.chop(6);
                    if (name.isEmpty() || name.compare(QStringLiteral("$DATA"), Qt::CaseInsensitive) == 0)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"),
                            QStringLiteral("默认数据流保持只读。请输入命名数据流名称。"));
                        return;
                    }
                    bool dataOk = true;
                    const QByteArray data = removeCheck->isChecked()
                        ? QByteArray()
                        : metadataEditorBytes(dataEdit, formatCombo, &dataOk);
                    if (!dataOk)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"), QStringLiteral("十六进制数据格式无效。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.streams.erase(std::remove_if(patch.streams.begin(), patch.streams.end(),
                            [&name](const ks::file::metadata::NamedBinaryPatch& item)
                            {
                                return item.name.compare(name, Qt::CaseInsensitive) == 0;
                            }), patch.streams.end());
                        ks::file::metadata::NamedBinaryPatch stream;
                        stream.name = name;
                        stream.action = removeCheck->isChecked()
                            ? ks::file::metadata::BinaryPatchAction::Remove
                            : ks::file::metadata::BinaryPatchAction::Replace;
                        stream.data = data;
                        patch.streams.push_back(stream);
                    }
                    updatePendingSaveUi();
                });
            QMetaObject::invokeMethod(page, [this, table]() { refreshMetadataStreamTable(table); },
                Qt::QueuedConnection);
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QWidget* buildMetadataEaPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QTableView* table = createPropertyTable(page, QStringList{
                QStringLiteral("目标"), QStringLiteral("EA 名称"),
                QStringLiteral("字节数"), QStringLiteral("值预览") }, QStringLiteral("file-detail-ea"));
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            installValueTableCopyMenu(table);
            layout->addWidget(table, 1);

            QLineEdit* nameEdit = new QLineEdit(page);
            nameEdit->setPlaceholderText(QStringLiteral("EA 名称，最长 255 字节"));
            QComboBox* formatCombo = new QComboBox(page);
            formatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            QCheckBox* needEaCheck = new QCheckBox(QStringLiteral("FILE_NEED_EA"), page);
            QCheckBox* removeCheck = new QCheckBox(QStringLiteral("删除该 EA"), page);
            auto* dataEdit = new CodeTextEdit(page);
            dataEdit->setMaximumHeight(120);
            QHBoxLayout* header = new QHBoxLayout();
            header->addWidget(nameEdit, 1);
            header->addWidget(formatCombo);
            header->addWidget(needEaCheck);
            header->addWidget(removeCheck);
            ks::ui::NormalizeToolbarRow(header);
            layout->addLayout(header);
            layout->addWidget(dataEdit);

            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新 EA"), page);
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取选中 EA"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 EA 操作"), page);
            actions->addWidget(refreshButton);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            ks::ui::NormalizeToolbarRow(actions);
            connect(refreshButton, &QPushButton::clicked, this,
                [this, table]() { refreshMetadataEaTable(table); });
            connect(loadButton, &QPushButton::clicked, this,
                [this, table, loadButton, nameEdit, formatCombo, dataEdit, needEaCheck]()
                {
                    const int row = table->currentIndex().row();
                    if (row < 0) return;
                    const QString path = propertyCell(table, row, 0).toString();
                    const QString name = propertyCell(table, row, 1).toString();
                    const QString inputName = nameEdit->text();
                    const int revision = dataEdit->document()->revision();
                    const bool needEa = needEaCheck->isChecked();
                    runMetadataRead(dataEdit, loadButton, path,
                        [path, name](const auto& cancel)
                        {
                            MetadataReadValue result;
                            const auto entries = ks::file::metadata::enumerateExtendedAttributes(path, &result.error);
                            const auto found = std::find_if(entries.cbegin(), entries.cend(), [&name](const auto& item) { return item.name == name; });
                            if (result.error == ERROR_SUCCESS && found == entries.cend()) result.error = ERROR_NOT_FOUND;
                            if (result.error == ERROR_SUCCESS && !cancel->load())
                            {
                                result.name = found->name;
                                result.needEa = found->needEa;
                                result.bytes = found->value;
                                result.format = 1;
                                result.text = formatMetadataHex(result.bytes, cancel);
                            }
                            return result;
                        },
                        [this, table, nameEdit, formatCombo, dataEdit, needEaCheck, path, name, inputName, revision, needEa](const MetadataReadValue& result, MetadataReadState* state)
                        {
                            const int selected = table->currentIndex().row();
                            if (dataEdit->document()->revision() != revision || nameEdit->text() != inputName || needEaCheck->isChecked() != needEa || selected < 0 ||
                                propertyCell(table, selected, 0).toString() != path || propertyCell(table, selected, 1).toString() != name) return false;
                            if (result.error != ERROR_SUCCESS)
                            {
                                QMessageBox::warning(this, QStringLiteral("EA"),
                                    QStringLiteral("读取 EA 失败：%1").arg(formatWin32ErrorText(result.error)));
                                return false;
                            }
                            nameEdit->setText(result.name);
                            needEaCheck->setChecked(result.needEa);
                            formatCombo->setCurrentIndex(1);
                            publishMetadataText(dataEdit, state, result, {table, nameEdit, formatCombo, needEaCheck});
                            return true;
                        });
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, nameEdit, formatCombo, dataEdit, needEaCheck, removeCheck]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    const QString name = nameEdit->text().trimmed();
                    if (name.isEmpty() || name.toUtf8().size() > 255)
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"), QStringLiteral("EA 名称无效。"));
                        return;
                    }
                    bool dataOk = true;
                    const QByteArray data = removeCheck->isChecked()
                        ? QByteArray()
                        : metadataEditorBytes(dataEdit, formatCombo, &dataOk);
                    if (!dataOk || data.size() > 65535)
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"),
                            QStringLiteral("EA 值必须是不超过 65535 字节的有效数据。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.extendedAttributes.erase(
                            std::remove_if(patch.extendedAttributes.begin(), patch.extendedAttributes.end(),
                                [&name](const ks::file::metadata::NamedBinaryPatch& item)
                                {
                                    return item.name.compare(name, Qt::CaseInsensitive) == 0;
                                }),
                            patch.extendedAttributes.end());
                        ks::file::metadata::NamedBinaryPatch ea;
                        ea.name = name;
                        ea.needEa = needEaCheck->isChecked();
                        ea.action = removeCheck->isChecked()
                            ? ks::file::metadata::BinaryPatchAction::Remove
                            : ks::file::metadata::BinaryPatchAction::Replace;
                        ea.data = data;
                        patch.extendedAttributes.push_back(ea);
                    }
                    updatePendingSaveUi();
                });
            QMetaObject::invokeMethod(page, [this, table]() { refreshMetadataEaTable(table); },
                Qt::QueuedConnection);
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QWidget* buildMetadataSecurityPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QLabel* hint = new QLabel(QStringLiteral(
                "可编辑 Owner、Primary Group、DACL、SACL、Mandatory Integrity 与继承保护。"
                "SDDL 会在保存事务中通过 Windows 安全 API 写入。"), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            auto* sddlEdit = new CodeTextEdit(page);
            sddlEdit->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            sddlEdit->setLineNumbersVisible(false);
            sddlEdit->setCompactMode(true);
            sddlEdit->setPlaceholderText(QStringLiteral("例如 O:...G:...D:...S:..."));
            layout->addWidget(sddlEdit, 1);
            QHBoxLayout* scopes = new QHBoxLayout();
            QCheckBox* ownerCheck = new QCheckBox(QStringLiteral("Owner"), page);
            QCheckBox* groupCheck = new QCheckBox(QStringLiteral("Primary Group"), page);
            QCheckBox* daclCheck = new QCheckBox(QStringLiteral("DACL"), page);
            QCheckBox* saclCheck = new QCheckBox(QStringLiteral("SACL / Mandatory Label"), page);
            QCheckBox* protectDaclCheck = new QCheckBox(QStringLiteral("保护 DACL 继承"), page);
            QCheckBox* protectSaclCheck = new QCheckBox(QStringLiteral("保护 SACL 继承"), page);
            daclCheck->setChecked(true);
            scopes->addWidget(ownerCheck);
            scopes->addWidget(groupCheck);
            scopes->addWidget(daclCheck);
            scopes->addWidget(saclCheck);
            scopes->addWidget(protectDaclCheck);
            scopes->addWidget(protectSaclCheck);
            scopes->addStretch(1);
            ks::ui::NormalizeToolbarRow(scopes);
            layout->addLayout(scopes);
            QHBoxLayout* effectiveLayout = new QHBoxLayout();
            QLineEdit* effectiveTrusteeEdit = new QLineEdit(page);
            effectiveTrusteeEdit->setPlaceholderText(QStringLiteral(
                "账户或 SID，例如 BUILTIN\\Users / Everyone / S-1-5-32-545"));
            QPushButton* effectiveButton = new QPushButton(QStringLiteral("检查有效权限"), page);
            QLabel* effectiveResult = new QLabel(QStringLiteral("Mask: -"), page);
            effectiveResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
            effectiveLayout->addWidget(effectiveTrusteeEdit, 1);
            effectiveLayout->addWidget(effectiveButton);
            effectiveLayout->addWidget(effectiveResult);
            ks::ui::NormalizeToolbarRow(effectiveLayout);
            layout->addLayout(effectiveLayout);
            QLabel* status = new QLabel(QStringLiteral("可从第一个目标读取 Owner、Group 与 DACL SDDL。"), page);
            status->setWordWrap(true);
            layout->addWidget(status);
            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取当前 SDDL"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存安全描述符"), page);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            // 编辑器保持多行高度，只对动作行应用等高指标。
            ks::ui::NormalizeToolbarRow(actions);
            connect(loadButton, &QPushButton::clicked, this, [this, sddlEdit, status]()
                {
                    status->setText(QStringLiteral("● 正在后台读取安全描述符..."));
                    const QString path = m_filePath;
                    QPointer<QPlainTextEdit> editorGuard(sddlEdit);
                    QPointer<QLabel> statusGuard(status);
                    auto* task = QRunnable::create([path, editorGuard, statusGuard]()
                        {
                            DWORD error = ERROR_SUCCESS;
                            const QString sddl =
                                ks::file::metadata::readSecurityDescriptorSddl(path, &error);
                            if (editorGuard == nullptr || statusGuard == nullptr) return;
                            QMetaObject::invokeMethod(editorGuard.data(),
                                [editorGuard, statusGuard, sddl, error]()
                                {
                                    if (editorGuard == nullptr || statusGuard == nullptr) return;
                                    if (error != ERROR_SUCCESS)
                                    {
                                        statusGuard->setText(QStringLiteral("● SDDL 读取失败：%1")
                                            .arg(formatWin32ErrorText(error)));
                                        return;
                                    }
                                    editorGuard->setPlainText(sddl);
                                    statusGuard->setText(QStringLiteral("● 当前 SDDL 已读取。"));
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                });
            connect(effectiveButton, &QPushButton::clicked, this,
                [this, effectiveButton, effectiveTrusteeEdit, effectiveResult]()
                {
                    const QString path = m_filePath;
                    const QString trustee = effectiveTrusteeEdit->text();
                    runMetadataRead(effectiveResult, effectiveButton, path,
                        [path, trustee](const auto&)
                        {
                            MetadataReadValue result;
                            DWORD mask = 0;
                            result.error = ks::file::metadata::queryEffectiveAccessMask(path, trustee, &mask);
                            result.text = QStringLiteral("Mask: 0x%1 · %2").arg(mask, 8, 16, QLatin1Char('0')).arg(accessMaskToText(mask));
                            return result;
                        },
                        [effectiveTrusteeEdit, effectiveResult, trustee](const MetadataReadValue& result, MetadataReadState*)
                        {
                            if (effectiveTrusteeEdit->text() != trustee) return false;
                            effectiveResult->setText(result.error == ERROR_SUCCESS ? result.text
                                : QStringLiteral("检查失败：%1").arg(formatWin32ErrorText(result.error)));
                            return false;
                        });
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, sddlEdit, ownerCheck, groupCheck, daclCheck, saclCheck,
                 protectDaclCheck, protectSaclCheck, status]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    SECURITY_INFORMATION information = 0U;
                    if (ownerCheck->isChecked()) information |= OWNER_SECURITY_INFORMATION;
                    if (groupCheck->isChecked()) information |= GROUP_SECURITY_INFORMATION;
                    if (daclCheck->isChecked()) information |= DACL_SECURITY_INFORMATION;
                    if (saclCheck->isChecked()) information |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
                    if (protectDaclCheck->isChecked())
                        information |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
                    if (protectSaclCheck->isChecked())
                        information |= SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION;
                    if (information == 0U || sddlEdit->toPlainText().trimmed().isEmpty())
                    {
                        QMessageBox::warning(this, QStringLiteral("安全描述符"),
                            QStringLiteral("请填写 SDDL 并至少选择一个写入范围。"));
                        return;
                    }
                    PSECURITY_DESCRIPTOR descriptor = nullptr;
                    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddlEdit->toPlainText().trimmed().toStdWString().c_str(),
                        SDDL_REVISION_1, &descriptor, nullptr) == FALSE)
                    {
                        QMessageBox::warning(this, QStringLiteral("安全描述符"),
                            QStringLiteral("SDDL 格式无效：%1")
                                .arg(formatWin32ErrorText(::GetLastError())));
                        return;
                    }
                    ::LocalFree(descriptor);
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.security.replaceSddl = true;
                        patch.security.sddl = sddlEdit->toPlainText().trimmed();
                        patch.security.securityInformation = information;
                    }
                    status->setText(QStringLiteral("● 安全描述符已暂存。"));
                    updatePendingSaveUi();
                });
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QWidget* buildMetadataPeAndReparsePage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QGroupBox* reparseGroup = new QGroupBox(QStringLiteral("重解析点原始缓冲"), page);
            QVBoxLayout* reparseLayout = new QVBoxLayout(reparseGroup);
            QHBoxLayout* reparseActions = new QHBoxLayout();
            QComboBox* reparseAction = new QComboBox(reparseGroup);
            reparseAction->addItems(QStringList{
                QStringLiteral("不修改"),
                QStringLiteral("写入原始缓冲"),
                QStringLiteral("删除重解析点") });
            QPushButton* loadReparseButton = new QPushButton(QStringLiteral("读取当前原始缓冲"), reparseGroup);
            reparseActions->addWidget(reparseAction);
            reparseActions->addWidget(loadReparseButton);
            reparseActions->addStretch(1);
            ks::ui::NormalizeToolbarRow(reparseActions);
            auto* reparseEdit = new CodeTextEdit(reparseGroup);
            reparseEdit->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            reparseEdit->setPlaceholderText(QStringLiteral("完整 REPARSE_DATA_BUFFER 十六进制，包含 Tag/Length/Reserved"));
            reparseEdit->setMaximumHeight(100);
            reparseLayout->addLayout(reparseActions);
            reparseLayout->addWidget(reparseEdit);
            layout->addWidget(reparseGroup);

            QGroupBox* resourceGroup = new QGroupBox(QStringLiteral("PE 资源编辑"), page);
            QGridLayout* resourceLayout = new QGridLayout(resourceGroup);
            QComboBox* resourcePreset = new QComboBox(resourceGroup);
            resourcePreset->addItems(QStringList{
                QStringLiteral("VERSIONINFO（RT_VERSION #16）"),
                QStringLiteral("Manifest（RT_MANIFEST #24）"),
                QStringLiteral("其它资源") });
            QLineEdit* resourceTypeEdit = new QLineEdit(QStringLiteral("#16"), resourceGroup);
            QLineEdit* resourceNameEdit = new QLineEdit(QStringLiteral("#1"), resourceGroup);
            QSpinBox* resourceLanguageSpin = new QSpinBox(resourceGroup);
            resourceLanguageSpin->setRange(0, 65535);
            QComboBox* resourceFormatCombo = new QComboBox(resourceGroup);
            resourceFormatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            resourceFormatCombo->setCurrentIndex(1);
            QCheckBox* removeResourceCheck = new QCheckBox(QStringLiteral("删除该资源"), resourceGroup);
            QPushButton* loadResourceButton = new QPushButton(QStringLiteral("读取当前资源"), resourceGroup);
            auto* resourceDataEdit = new CodeTextEdit(resourceGroup);
            resourceDataEdit->setMaximumHeight(110);
            resourceLayout->addWidget(resourcePreset, 0, 0);
            resourceLayout->addWidget(new QLabel(QStringLiteral("类型"), resourceGroup), 0, 1);
            resourceLayout->addWidget(resourceTypeEdit, 0, 2);
            resourceLayout->addWidget(new QLabel(QStringLiteral("名称 / ID"), resourceGroup), 0, 3);
            resourceLayout->addWidget(resourceNameEdit, 0, 4);
            resourceLayout->addWidget(new QLabel(QStringLiteral("语言 ID"), resourceGroup), 1, 0);
            resourceLayout->addWidget(resourceLanguageSpin, 1, 1);
            resourceLayout->addWidget(resourceFormatCombo, 1, 2);
            resourceLayout->addWidget(removeResourceCheck, 1, 3);
            resourceLayout->addWidget(loadResourceButton, 1, 4);
            resourceLayout->addWidget(resourceDataEdit, 2, 0, 1, 5);
            resourceLayout->setHorizontalSpacing(8);
            resourceLayout->setVerticalSpacing(8);
            ks::ui::NormalizeToolbarControl(loadResourceButton);
            layout->addWidget(resourceGroup);

            QCheckBox* clearSignatureCheck = new QCheckBox(
                QStringLiteral("保存时清除嵌入式 Authenticode 签名（Catalog 签名不会被删除）"), page);
            layout->addWidget(clearSignatureCheck);
            QLabel* warning = new QLabel(QStringLiteral(
                "原始重解析点、PE 资源和签名清除属于高风险操作，必须启用底部备份选项。"
                "VERSIONINFO 可用原始十六进制编辑，Manifest 可用 UTF-8 文本编辑，其它资源支持原始字节。"), page);
            warning->setWordWrap(true);
            layout->addWidget(warning);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存重解析点 / PE / 签名操作"), page);
            ks::ui::NormalizeToolbarControl(stageButton);
            layout->addWidget(stageButton, 0, Qt::AlignRight);
            layout->addStretch(1);

            connect(resourcePreset, &QComboBox::currentIndexChanged, this,
                [resourceTypeEdit, resourceNameEdit, resourceFormatCombo](const int index)
                {
                    if (index == 0)
                    {
                        resourceTypeEdit->setText(QStringLiteral("#16"));
                        resourceNameEdit->setText(QStringLiteral("#1"));
                        resourceFormatCombo->setCurrentIndex(1);
                    }
                    else if (index == 1)
                    {
                        resourceTypeEdit->setText(QStringLiteral("#24"));
                        resourceNameEdit->setText(QStringLiteral("#1"));
                        resourceFormatCombo->setCurrentIndex(0);
                    }
                });
            connect(loadReparseButton, &QPushButton::clicked, this, [this, loadReparseButton, reparseEdit]()
                {
                    const QString path = m_filePath;
                    const int revision = reparseEdit->document()->revision();
                    runMetadataRead(reparseEdit, loadReparseButton, path,
                        [path](const auto& cancel)
                        {
                            MetadataReadValue result;
                            result.bytes = ks::file::metadata::readRawReparseData(path, &result.error);
                            result.format = 1;
                            if (result.error == ERROR_SUCCESS && !cancel->load()) result.text = formatMetadataHex(result.bytes, cancel);
                            return result;
                        },
                        [this, reparseEdit, revision](const MetadataReadValue& result, MetadataReadState* state)
                        {
                            if (reparseEdit->document()->revision() != revision) return false;
                            if (result.error != ERROR_SUCCESS)
                            {
                                QMessageBox::warning(this, QStringLiteral("重解析点"),
                                    QStringLiteral("读取原始缓冲失败：%1").arg(formatWin32ErrorText(result.error)));
                                return false;
                            }
                            publishMetadataText(reparseEdit, state, result);
                            return true;
                        });
                });
            connect(loadResourceButton, &QPushButton::clicked, this,
                [this, loadResourceButton, resourceTypeEdit, resourceNameEdit, resourceLanguageSpin, resourceFormatCombo, resourceDataEdit]()
                {
                    const QString path = m_filePath;
                    const QString type = resourceTypeEdit->text();
                    const QString name = resourceNameEdit->text();
                    const int language = resourceLanguageSpin->value();
                    const int format = resourceFormatCombo->currentIndex();
                    const int revision = resourceDataEdit->document()->revision();
                    runMetadataRead(resourceDataEdit, loadResourceButton, path,
                        [path, type, name, language, format](const auto& cancel)
                        {
                            MetadataReadValue result;
                            result.bytes = ks::file::metadata::readPeResource(path, type, name, static_cast<WORD>(language), &result.error);
                            result.format = format;
                            if (result.error == ERROR_SUCCESS && !cancel->load())
                                result.text = format == 0 ? QString::fromUtf8(result.bytes) : formatMetadataHex(result.bytes, cancel);
                            return result;
                        },
                        [this, resourceTypeEdit, resourceNameEdit, resourceLanguageSpin, resourceFormatCombo, resourceDataEdit, type, name, language, format, revision](const MetadataReadValue& result, MetadataReadState* state)
                        {
                            if (resourceTypeEdit->text() != type || resourceNameEdit->text() != name || resourceLanguageSpin->value() != language ||
                                resourceFormatCombo->currentIndex() != format || resourceDataEdit->document()->revision() != revision) return false;
                            if (result.error != ERROR_SUCCESS)
                            {
                                QMessageBox::warning(this, QStringLiteral("PE 资源"),
                                    QStringLiteral("读取资源失败：%1").arg(formatWin32ErrorText(result.error)));
                                return false;
                            }
                            publishMetadataText(resourceDataEdit, state, result, {resourceTypeEdit, resourceNameEdit, resourceLanguageSpin, resourceFormatCombo});
                            return true;
                        }, true);
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, reparseAction, reparseEdit, resourceTypeEdit, resourceNameEdit,
                 resourceLanguageSpin, resourceFormatCombo, removeResourceCheck,
                 resourceDataEdit, clearSignatureCheck]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QByteArray reparseBytes;
                    if (reparseAction->currentIndex() == 1)
                    {
                        bool reparseOk = false;
                        reparseBytes = parseMetadataHexText(reparseEdit->toPlainText(), &reparseOk);
                        if (!reparseOk || reparseBytes.size() < 8 ||
                            reparseBytes.size() > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
                        {
                            QMessageBox::warning(this, QStringLiteral("重解析点"),
                                QStringLiteral("原始重解析缓冲必须是 8 到 16384 字节的有效十六进制。"));
                            return;
                        }
                    }
                    const bool hasResourceInput =
                        !resourceTypeEdit->text().trimmed().isEmpty() &&
                        !resourceNameEdit->text().trimmed().isEmpty() &&
                        (removeResourceCheck->isChecked() || !resourceDataEdit->toPlainText().isEmpty());
                    QByteArray resourceBytes;
                    if (hasResourceInput && !removeResourceCheck->isChecked())
                    {
                        bool resourceOk = false;
                        resourceBytes = metadataEditorBytes(
                            resourceDataEdit, resourceFormatCombo, &resourceOk);
                        if (!resourceOk)
                        {
                            QMessageBox::warning(this, QStringLiteral("PE 资源"),
                                QStringLiteral("资源十六进制格式无效。"));
                            return;
                        }
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.reparse.update = reparseAction->currentIndex() != 0;
                        patch.reparse.remove = reparseAction->currentIndex() == 2;
                        patch.reparse.rawBuffer = reparseBytes;
                        patch.signatureDisposition = clearSignatureCheck->isChecked()
                            ? ks::file::metadata::SignatureDisposition::RemoveEmbedded
                            : ks::file::metadata::SignatureDisposition::Preserve;
                        if (hasResourceInput)
                        {
                            ks::file::metadata::PeResourcePatch resource;
                            resource.type = resourceTypeEdit->text().trimmed();
                            resource.name = resourceNameEdit->text().trimmed();
                            resource.language = static_cast<WORD>(resourceLanguageSpin->value());
                            resource.action = removeResourceCheck->isChecked()
                                ? ks::file::metadata::BinaryPatchAction::Remove
                                : ks::file::metadata::BinaryPatchAction::Replace;
                            resource.data = resourceBytes;
                            patch.peResources.push_back(resource);
                        }
                    }
                    updatePendingSaveUi();
                });
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QWidget* buildMetadataBasicPropertiesPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            layout->setSpacing(10);

            QLabel* targetLabel = new QLabel(
                m_batchMode
                    ? ks::i18n::sourceText(QStringLiteral("批量目标：%1 项"))
                        .arg(m_filePaths.size())
                    : ks::i18n::sourceText(QStringLiteral("目标：%1"))
                        .arg(QDir::toNativeSeparators(m_filePath)),
                page);
            targetLabel->setWordWrap(true);
            targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(targetLabel);

            QLabel* hintLabel = new QLabel(
                ks::i18n::sourceText(QStringLiteral(
                    "时间按本地时区显示，精确到毫秒；只有勾选“修改”的时间字段才会写入。")) +
                QLatin1Char('\n') +
                ks::i18n::sourceText(QStringLiteral(
                    "属性编辑只开放可直接切换的位，目录、重解析点、压缩、加密、稀疏等结构性属性始终保留。")) +
                QLatin1Char('\n') +
                ks::i18n::sourceText(QStringLiteral(
                    "本页按钮只会暂存修改。窗口底部“保存全部修改”是唯一写入入口。")),
                page);
            hintLabel->setWordWrap(true);
            layout->addWidget(hintLabel);

            QGroupBox* timeGroup = new QGroupBox(QStringLiteral("文件时间"), page);
            QGridLayout* timeLayout = new QGridLayout(timeGroup);
            timeLayout->setColumnStretch(2, 1);
            timeLayout->addWidget(new QLabel(QStringLiteral("写入"), timeGroup), 0, 0);
            timeLayout->addWidget(new QLabel(QStringLiteral("字段"), timeGroup), 0, 1);
            timeLayout->addWidget(new QLabel(QStringLiteral("本地时间（含毫秒）"), timeGroup), 0, 2);

            const std::array<QString, 4> timeNames{
                QStringLiteral("创建时间"),
                QStringLiteral("最后访问时间"),
                QStringLiteral("最后写入时间"),
                QStringLiteral("元数据变更时间（ChangeTime）")
            };
            // 0 在 FileBasicInformation 的“设置”语义中表示保持不变，故不允许选择恰好为
            // FILETIME epoch 的 1601-01-01 00:00:00 UTC；从次日开始可避免时区换算后落到 0。
            const QDateTime minimumDateTime(QDate(1601, 1, 2), QTime(0, 0));
            const QDateTime maximumDateTime(QDate(9999, 12, 31), QTime(23, 59, 59, 999));
            for (std::size_t timeIndex = 0; timeIndex < timeNames.size(); ++timeIndex)
            {
                QCheckBox* modifyCheck = new QCheckBox(QStringLiteral("修改"), timeGroup);
                QDateTimeEdit* dateTimeEdit = new QDateTimeEdit(timeGroup);
                dateTimeEdit->setCalendarPopup(true);
                dateTimeEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
                dateTimeEdit->setMinimumDateTime(minimumDateTime);
                dateTimeEdit->setMaximumDateTime(maximumDateTime);
                dateTimeEdit->setEnabled(false);
                m_metadataTimeChecks[timeIndex] = modifyCheck;
                m_metadataTimeEdits[timeIndex] = dateTimeEdit;
                timeLayout->addWidget(modifyCheck, static_cast<int>(timeIndex) + 1, 0);
                timeLayout->addWidget(
                    new QLabel(timeNames[timeIndex], timeGroup),
                    static_cast<int>(timeIndex) + 1,
                    1);
                timeLayout->addWidget(dateTimeEdit, static_cast<int>(timeIndex) + 1, 2);
                connect(modifyCheck, &QCheckBox::toggled, dateTimeEdit,
                    [this, dateTimeEdit](const bool checked)
                    {
                        dateTimeEdit->setEnabled(
                            checked && m_metadataHasSnapshot && !m_metadataEditorBusy);
                    });
            }
            layout->addWidget(timeGroup);

            QGroupBox* attributeGroup = new QGroupBox(QStringLiteral("可编辑文件属性"), page);
            QGridLayout* attributeLayout = new QGridLayout(attributeGroup);
            const std::array<QString, 6> attributeNames{
                QStringLiteral("只读（READONLY）"),
                QStringLiteral("隐藏（HIDDEN）"),
                QStringLiteral("系统（SYSTEM）"),
                QStringLiteral("存档（ARCHIVE）"),
                QStringLiteral("临时（TEMPORARY）"),
                QStringLiteral("不建内容索引（NOT_CONTENT_INDEXED）")
            };
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeNames.size();
                 ++attributeIndex)
            {
                QCheckBox* attributeCheck =
                    new QCheckBox(attributeNames[attributeIndex], attributeGroup);
                m_metadataAttributeChecks[attributeIndex] = attributeCheck;
                attributeLayout->addWidget(
                    attributeCheck,
                    static_cast<int>(attributeIndex / 2),
                    static_cast<int>(attributeIndex % 2));
                connect(attributeCheck, &QCheckBox::checkStateChanged, this,
                    [this, attributeIndex](const Qt::CheckState state)
                    {
                        if (!m_metadataApplyingSnapshot && state != Qt::PartiallyChecked)
                        {
                            m_metadataAttributeTouched[attributeIndex] = true;
                        }
                    });
            }
            layout->addWidget(attributeGroup);
            layout->addStretch(1);
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        QTabWidget* buildMetadataEditorTabs(QWidget* parent)
        {
            QTabWidget* tabs = new QTabWidget(parent);
            ks::ui::StylePageTabs(tabs);
            tabs->addTab(
                buildMetadataBasicPropertiesPage(tabs),
                ks::i18n::sourceText(QStringLiteral("基础属性")));
            tabs->addTab(buildDeferredTab(QStringLiteral("metadata_name")), QStringLiteral("名称与文件系统"));
            tabs->addTab(buildDeferredTab(QStringLiteral("metadata_shell")), QStringLiteral("Shell 属性"));
            tabs->addTab(buildDeferredTab(QStringLiteral("metadata_ads")), QStringLiteral("ADS"));
            tabs->addTab(buildDeferredTab(QStringLiteral("metadata_ea")), QStringLiteral("EA"));
            tabs->addTab(buildDeferredTab(QStringLiteral("metadata_security")), QStringLiteral("安全描述符"));
            tabs->addTab(buildDeferredTab(QStringLiteral("metadata_pe")), QStringLiteral("重解析点 / PE / 签名"));
            connect(tabs, &QTabWidget::currentChanged, this, [this, tabs](const int tabIndex)
                {
                    activateDeferredTab(tabs, tabIndex);
                });
            return tabs;
        }

        QWidget* buildMetadataTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            layout->addWidget(buildMetadataEditorTabs(page), 1);

            QHBoxLayout* actionLayout = new QHBoxLayout();
            m_metadataRefreshButton = new QPushButton(QStringLiteral("重新读取"), page);
            m_metadataApplyButton = new QPushButton(QStringLiteral("暂存基础修改"), page);
            actionLayout->addStretch(1);
            actionLayout->addWidget(m_metadataRefreshButton);
            actionLayout->addWidget(m_metadataApplyButton);
            ks::ui::NormalizeToolbarRow(actionLayout);
            layout->addLayout(actionLayout);

            m_metadataStatusLabel = new QLabel(QStringLiteral("● 等待读取文件元数据。"), page);
            m_metadataStatusLabel->setWordWrap(true);
            layout->addWidget(m_metadataStatusLabel);

            connect(m_metadataRefreshButton, &QPushButton::clicked, this,
                [this]() { refreshMetadataEditor(); });
            connect(m_metadataApplyButton, &QPushButton::clicked, this,
                [this]() { applyMetadataEditorChanges(); });

            m_metadataHasSnapshot = false;
            setMetadataEditorBusy(false);
            if (!m_pendingPatches.isEmpty())
            {
                QList<ks::file::metadata::FileSnapshot> snapshots;
                snapshots.reserve(m_pendingPatches.size());
                for (const auto& patch : m_pendingPatches) snapshots.push_back(patch.snapshot);
                applyBatchMetadataSnapshotsToEditor(snapshots);
            }
            else
            {
                QMetaObject::invokeMethod(page, [this]() { refreshMetadataEditor(); }, Qt::QueuedConnection);
            }
            return page;
        }

        QWidget* buildReparseTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            auto* view = new ks::ui::StructuredFieldView(page);
            layout->addWidget(view, 1);
            const QString pathSnapshot = m_filePath;
            startNativePropertyLoad(view, [pathSnapshot]()
                {
                    ks::ui::FieldDocument document;
                    document.section(QStringLiteral("重解析点 / 符号链接"))
                        .field(QStringLiteral("目标路径"), QDir::toNativeSeparators(pathSnapshot));
                    if (!isPathReparsePoint(pathSnapshot))
                    {
                        document.field(QStringLiteral("状态"),
                            QStringLiteral("当前目标不是 FILE_ATTRIBUTE_REPARSE_POINT。"), true);
                        return document;
                    }
                    const ks::file::ReparsePointQueryResult result = queryReparsePointForUi(pathSnapshot);
                    document.field(QStringLiteral("状态"), !result.pathOpened
                        ? QStringLiteral("无法打开目标（使用 FILE_FLAG_OPEN_REPARSE_POINT）")
                        : (!result.querySucceeded ? QStringLiteral("FSCTL_GET_REPARSE_POINT 查询失败")
                            : QStringLiteral("OK")), true);
                    document.field(QStringLiteral("是否重解析点"), formatAuditBool(result.isReparsePoint), true);
                    if (!result.pathOpened || !result.querySucceeded)
                    {
                        document.field(QStringLiteral("Win32错误"), formatWin32ErrorText(result.win32Error));
                        document.field(QStringLiteral("原因"), QString::fromStdWString(result.errorText));
                        return document;
                    }
                    document.field(QStringLiteral("Reparse Tag"), formatReparseTagText(result.tag))
                        .field(QStringLiteral("Tag名称"), QString::fromStdWString(result.tagName))
                        .field(QStringLiteral("类型标记"), QString::fromStdWString(result.kindName))
                        .field(QStringLiteral("Microsoft Tag"), formatAuditBool(result.isMicrosoftTag), true)
                        .field(QStringLiteral("Name Surrogate"), formatAuditBool(result.isNameSurrogate), true)
                        .field(QStringLiteral("是否相对链接"), formatAuditBool(result.isRelative), true)
                        .field(QStringLiteral("Substitute Name"), QString::fromStdWString(result.substituteName))
                        .field(QStringLiteral("Print Name"), QString::fromStdWString(result.printName))
                        .field(QStringLiteral("解析目标路径"), reparseTargetFromResult(result))
                        .field(QStringLiteral("原始信息"), QString::fromStdWString(result.rawPayloadText))
                        .field(QStringLiteral("Raw Hex Preview"), QString::fromStdWString(result.rawHexPreview));
                    if (!result.errorText.empty())
                        document.field(QStringLiteral("解析提示"), QString::fromStdWString(result.errorText));
                    return document;
                });
            return page;
        }

        QWidget* buildSecurityTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            const QString nativePath = QDir::toNativeSeparators(m_filePath);
            ks::ui::FieldDocument baseContent;
            baseContent.field(QStringLiteral("目标路径"), nativePath);
            baseContent.section(QStringLiteral("快速权限摘要"));
            QFileInfo info(m_filePath);
            baseContent.field(QStringLiteral("Read"), info.isReadable() ? QStringLiteral("允许") : QStringLiteral("拒绝"), true);
            baseContent.field(QStringLiteral("Write"), info.isWritable() ? QStringLiteral("允许") : QStringLiteral("拒绝"), true);
            baseContent.field(QStringLiteral("Execute"), info.isExecutable() ? QStringLiteral("允许") : QStringLiteral("拒绝"), true);
            baseContent.section(QStringLiteral("操作说明"));
            baseContent.note(QStringLiteral("上方表格用于结构化展示 ACE；继承 ACE、SACL、对象 ACE 默认只读展示。"));
            baseContent.note(QStringLiteral("应用 ACE 使用 Windows 安全 API 写 DACL，失败会保留错误码。"));
            baseContent.note(QStringLiteral("删除选中 ACE 只删除非继承 DACL 中精确匹配的当前 ACE。"));

            QGroupBox* operationGroup = new QGroupBox(QStringLiteral("权限编辑"), page);
            QGridLayout* operationLayout = new QGridLayout(operationGroup);

            QLineEdit* accountEdit = new QLineEdit(operationGroup);
            accountEdit->setPlaceholderText(QStringLiteral("账户或 SID，例如 BUILTIN\\Administrators / Everyone / S-1-5-32-544"));
            accountEdit->setStyleSheet(buildBlueInputStyle());

            QComboBox* accessModeCombo = new QComboBox(operationGroup);
            accessModeCombo->setStyleSheet(buildBlueInputStyle());
            accessModeCombo->addItem(QStringLiteral("允许：添加/合并"), static_cast<int>(GRANT_ACCESS));
            accessModeCombo->addItem(QStringLiteral("允许：替换该主体权限"), static_cast<int>(SET_ACCESS));
            accessModeCombo->addItem(QStringLiteral("拒绝：添加/合并"), static_cast<int>(DENY_ACCESS));

            QComboBox* presetCombo = new QComboBox(operationGroup);
            presetCombo->setStyleSheet(buildBlueInputStyle());
            presetCombo->addItems(QStringList{
                QStringLiteral("读取"),
                QStringLiteral("写入"),
                QStringLiteral("读取 + 写入"),
                QStringLiteral("读取 + 执行"),
                QStringLiteral("修改"),
                QStringLiteral("完全控制") });
            presetCombo->setCurrentIndex(4);

            QLineEdit* customMaskEdit = new QLineEdit(operationGroup);
            customMaskEdit->setPlaceholderText(QStringLiteral("可选自定义 Mask，如 0x001F01FF；留空使用预设/复选框"));
            customMaskEdit->setStyleSheet(buildBlueInputStyle());

            QComboBox* inheritanceCombo = new QComboBox(operationGroup);
            inheritanceCombo->setStyleSheet(buildBlueInputStyle());
            inheritanceCombo->addItems(QStringList{
                QStringLiteral("仅当前对象"),
                QStringLiteral("目录和文件继承"),
                QStringLiteral("仅文件继承"),
                QStringLiteral("仅目录继承") });

            QCheckBox* readCheck = new QCheckBox(QStringLiteral("读"), operationGroup);
            QCheckBox* writeCheck = new QCheckBox(QStringLiteral("写"), operationGroup);
            QCheckBox* executeCheck = new QCheckBox(QStringLiteral("执行"), operationGroup);
            QCheckBox* deleteCheck = new QCheckBox(QStringLiteral("删除"), operationGroup);
            QCheckBox* writeDacCheck = new QCheckBox(QStringLiteral("改 DACL"), operationGroup);
            QCheckBox* writeOwnerCheck = new QCheckBox(QStringLiteral("改所有者"), operationGroup);

            QPushButton* applyAceButton = new QPushButton(QStringLiteral("应用 ACE"), operationGroup);
            QPushButton* deleteAceButton = new QPushButton(QStringLiteral("删除选中 ACE"), operationGroup);
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新权限"), operationGroup);
            applyAceButton->setToolTip(
                QStringLiteral("按上面选择的账户和权限，给该文件新增一条访问控制规则（ACE）"));
            deleteAceButton->setToolTip(
                QStringLiteral("删除列表中选中的那条文件访问控制规则（ACE）"));
            ks::ui::ApplyFlatButtonTheme(applyAceButton, ks::ui::FlatButtonTone::Accent);
            ks::ui::ApplyFlatButtonTheme(deleteAceButton, ks::ui::FlatButtonTone::Danger);
            refreshButton->setStyleSheet(buildBlueButtonStyle());

            // ACL 表单采用网格布局，动作保留原强调/危险色并统一高度和留白。
            operationLayout->setHorizontalSpacing(8);
            operationLayout->setVerticalSpacing(8);
            ks::ui::NormalizeToolbarControl(applyAceButton);
            ks::ui::NormalizeToolbarControl(deleteAceButton);
            ks::ui::NormalizeToolbarControl(refreshButton);

            operationLayout->addWidget(new QLabel(QStringLiteral("主体"), operationGroup), 0, 0);
            operationLayout->addWidget(accountEdit, 0, 1, 1, 5);
            operationLayout->addWidget(new QLabel(QStringLiteral("动作"), operationGroup), 1, 0);
            operationLayout->addWidget(accessModeCombo, 1, 1);
            operationLayout->addWidget(new QLabel(QStringLiteral("预设"), operationGroup), 1, 2);
            operationLayout->addWidget(presetCombo, 1, 3);
            operationLayout->addWidget(new QLabel(QStringLiteral("继承"), operationGroup), 1, 4);
            operationLayout->addWidget(inheritanceCombo, 1, 5);
            operationLayout->addWidget(new QLabel(QStringLiteral("权限位"), operationGroup), 2, 0);
            operationLayout->addWidget(readCheck, 2, 1);
            operationLayout->addWidget(writeCheck, 2, 2);
            operationLayout->addWidget(executeCheck, 2, 3);
            operationLayout->addWidget(deleteCheck, 2, 4);
            operationLayout->addWidget(writeDacCheck, 2, 5);
            operationLayout->addWidget(writeOwnerCheck, 3, 1);
            operationLayout->addWidget(new QLabel(QStringLiteral("Mask"), operationGroup), 4, 0);
            operationLayout->addWidget(customMaskEdit, 4, 1, 1, 3);
            operationLayout->addWidget(applyAceButton, 4, 4);
            operationLayout->addWidget(deleteAceButton, 4, 5);
            operationLayout->addWidget(refreshButton, 5, 5);
            layout->addWidget(operationGroup, 0);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 正在读取安全描述符..."), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(statusLabel, 0);

            QSplitter* splitter = new QSplitter(Qt::Vertical, page);
            QTableWidget* aceTable = new ks::ui::VisibleTableWidget(splitter);
            // 单文件 ACL 的编辑表已有专门权限动作，仅保留紧凑复制/导出。
            ks::ui::SetTableActionBarMode(aceTable, ks::ui::TableActionBarMode::Compact);
            aceTable->setColumnCount(9);
            aceTable->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("范围"),
                QStringLiteral("序号"),
                QStringLiteral("类型"),
                QStringLiteral("账户"),
                QStringLiteral("SID"),
                QStringLiteral("Mask"),
                QStringLiteral("权限"),
                QStringLiteral("标志"),
                QStringLiteral("编辑状态")
                });
            aceTable->setAlternatingRowColors(true);
            aceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
            aceTable->setSelectionMode(QAbstractItemView::SingleSelection);
            aceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            aceTable->setSortingEnabled(true);
            if (aceTable->horizontalHeader() != nullptr)
            {
                aceTable->horizontalHeader()->setStretchLastSection(true);
            }
            installFileTableCopyMenu(aceTable);

            auto* detailEditor = new ks::ui::StructuredFieldView(splitter);
            auto loading = baseContent;
            loading.note(QStringLiteral("深层 Owner/Group/DACL/SACL 正在后台加载..."));
            detailEditor->setDocument(loading);

            splitter->addWidget(aceTable);
            splitter->addWidget(detailEditor);
            splitter->setStretchFactor(0, 3);
            splitter->setStretchFactor(1, 2);
            layout->addWidget(splitter, 1);

            const auto syncChecksFromPreset = [this, presetCombo, readCheck, writeCheck, executeCheck, deleteCheck, writeDacCheck, writeOwnerCheck]()
                {
                    const DWORD presetMask = maskFromSecurityPreset(presetCombo->currentIndex());
                    readCheck->setChecked((presetMask & FILE_GENERIC_READ) == FILE_GENERIC_READ);
                    writeCheck->setChecked((presetMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE);
                    executeCheck->setChecked((presetMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE);
                    deleteCheck->setChecked((presetMask & DELETE) != 0);
                    writeDacCheck->setChecked((presetMask & WRITE_DAC) != 0);
                    writeOwnerCheck->setChecked((presetMask & WRITE_OWNER) != 0);
                };
            syncChecksFromPreset();
            connect(presetCombo, &QComboBox::currentIndexChanged, this, [syncChecksFromPreset](int)
                {
                    syncChecksFromPreset();
                });

            const auto refreshSecurityUi = [this, aceTable, detailEditor, statusLabel, baseContent, nativePath]()
                {
                    if (aceTable != nullptr)
                    {
                        aceTable->setRowCount(0);
                    }
                    if (statusLabel != nullptr)
                    {
                        statusLabel->setText(QStringLiteral("● 正在读取安全描述符..."));
                    }
                    if (detailEditor != nullptr)
                    {
                        auto loading = baseContent;
                        loading.note(QStringLiteral("深层 Owner/Group/DACL/SACL 正在后台加载..."));
                        detailEditor->setDocument(loading);
                    }
                    startSecurityDeepLoad(aceTable, detailEditor, statusLabel, baseContent, nativePath);
                };

            connect(refreshButton, &QPushButton::clicked, this, refreshSecurityUi);
            connect(applyAceButton, &QPushButton::clicked, this,
                [this,
                accountEdit,
                accessModeCombo,
                inheritanceCombo,
                customMaskEdit,
                readCheck,
                writeCheck,
                executeCheck,
                deleteCheck,
                writeDacCheck,
                writeOwnerCheck,
                statusLabel]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    DWORD accessMask = maskFromSecurityChecks(
                        readCheck,
                        writeCheck,
                        executeCheck,
                        deleteCheck,
                        writeDacCheck,
                        writeOwnerCheck);
                    const QString customMaskText = customMaskEdit->text().trimmed();
                    if (!customMaskText.isEmpty())
                    {
                        bool parseOk = false;
                        const qulonglong parsedMask = customMaskText.toULongLong(&parseOk, 0);
                        if (!parseOk || parsedMask > 0xFFFFFFFFULL)
                        {
                            QMessageBox::warning(this, QStringLiteral("权限编辑"), QStringLiteral("自定义 Mask 格式无效：%1").arg(customMaskText));
                            return;
                        }
                        accessMask = static_cast<DWORD>(parsedMask);
                    }

                    if (accountEdit->text().trimmed().isEmpty() || accessMask == 0U)
                    {
                        QMessageBox::warning(this, QStringLiteral("权限编辑"),
                            QStringLiteral("请填写主体，并选择至少一个权限位。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        ks::file::metadata::SecurityAcePatch ace;
                        ace.trustee = accountEdit->text().trimmed();
                        ace.accessMask = accessMask;
                        ace.accessMode = static_cast<DWORD>(accessModeCombo->currentData().toInt());
                        ace.inheritance = inheritanceFlagsFromCombo(inheritanceCombo->currentIndex());
                        patch.security.aceChanges.push_back(ace);
                    }
                    if (statusLabel != nullptr)
                        statusLabel->setText(QStringLiteral("● ACE 修改已暂存，尚未写入文件。"));
                    updatePendingSaveUi();
                });

            connect(deleteAceButton, &QPushButton::clicked, this, [this, aceTable, statusLabel]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    const int row = aceTable != nullptr ? aceTable->currentRow() : -1;
                    if (row < 0 || aceTable->item(row, 0) == nullptr)
                    {
                        QMessageBox::information(this, QStringLiteral("删除 ACE"),
                            QStringLiteral("请先选择一条可编辑的非继承 DACL ACE。"));
                        return;
                    }
                    QTableWidgetItem* const item = aceTable->item(row, 0);
                    if (!item->data(Qt::UserRole + 6).toBool())
                    {
                        QMessageBox::information(this, QStringLiteral("删除 ACE"),
                            QStringLiteral("继承 ACE、SACL 与对象 ACE保持只读，不能在此直接删除。"));
                        return;
                    }
                    const QString typeText = item->data(Qt::UserRole + 4).toString();
                    BYTE aceType = 0xFFU;
                    if (typeText == QStringLiteral("ACCESS_ALLOWED")) aceType = ACCESS_ALLOWED_ACE_TYPE;
                    if (typeText == QStringLiteral("ACCESS_DENIED")) aceType = ACCESS_DENIED_ACE_TYPE;
                    if (aceType == 0xFFU)
                    {
                        return;
                    }
                    BYTE aceFlags = 0U;
                    const QString flagsText = aceTable->item(row, 7) != nullptr
                        ? aceTable->item(row, 7)->text()
                        : QString();
                    if (flagsText.contains(QStringLiteral("OBJECT_INHERIT"))) aceFlags |= OBJECT_INHERIT_ACE;
                    if (flagsText.contains(QStringLiteral("CONTAINER_INHERIT"))) aceFlags |= CONTAINER_INHERIT_ACE;
                    if (flagsText.contains(QStringLiteral("NO_PROPAGATE"))) aceFlags |= NO_PROPAGATE_INHERIT_ACE;
                    if (flagsText.contains(QStringLiteral("INHERIT_ONLY"))) aceFlags |= INHERIT_ONLY_ACE;
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        ks::file::metadata::SecurityAceRemoval removal;
                        removal.aceType = aceType;
                        removal.aceFlags = aceFlags;
                        removal.accessMask = static_cast<DWORD>(
                            item->data(Qt::UserRole + 5).toULongLong());
                        removal.sid = item->data(Qt::UserRole + 3).toString();
                        patch.security.aceRemovals.push_back(removal);
                    }
                    if (statusLabel != nullptr)
                        statusLabel->setText(QStringLiteral("● 删除 ACE 操作已暂存，尚未写入文件。"));
                    updatePendingSaveUi();
                });

            QMetaObject::invokeMethod(page, refreshSecurityUi, Qt::QueuedConnection);
            // 此页是明确的编辑参数区，共享输入负责网格字段和长选项，保留原暂存事务。
            ks::ui::StyleParameterFields(page);
            ks::ui::StyleWorkspaceTextViews(page);
            return page;
        }

        class BatchHashRowsModel final : public QAbstractTableModel
        {
        public:
            BatchHashRowsModel(QStringList paths, const QStringList& algorithms, QObject* parent)
                : QAbstractTableModel(parent), m_paths(std::move(paths)),
                  m_headers(QStringList{QStringLiteral("目标"), QStringLiteral("状态")} + algorithms + QStringList{QStringLiteral("错误")})
            {
                if (parent != nullptr) parent->installEventFilter(this);
            }
            ~BatchHashRowsModel() override { retireResults(); }

            quint64 resetPaths(QStringList paths)
            {
                beginResetModel(); m_paths = std::move(paths); retireResults(); ++m_generation; endResetModel();
                return m_generation;
            }
            quint64 generation() const { return m_generation; }
            int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : static_cast<int>(m_paths.size()); }
            int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : static_cast<int>(m_headers.size()); }
            QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override
            {
                return orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < columnCount()
                    ? QVariant(ks::i18n::displayText(m_headers.at(section))) : QAbstractTableModel::headerData(section, orientation, role);
            }
            QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
            {
                if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || index.column() < 0 ||
                    index.column() >= columnCount() || (role != Qt::DisplayRole && role != Qt::ToolTipRole)) return {};
                if (index.column() == 0) return QDir::toNativeSeparators(m_paths.at(index.row()));
                const auto found = m_results.constFind(index.row());
                const QString value = found != m_results.cend() ? found.value().value(index.column() - 1)
                    : (index.column() == 1 ? QStringLiteral("等待") : QString());
                return index.column() == 1 ? ks::i18n::displayText(value) : value;
            }
            void setResult(qsizetype row, const QString& state, const QStringList& hashes, const QString& error)
            {
                if (row < 0 || row >= rowCount()) return;
                QStringList values; values.reserve(columnCount() - 1); values.push_back(state);
                for (int i = 0; i < columnCount() - 3; ++i) values.push_back(hashes.value(i));
                values.push_back(error); m_results.insert(row, std::move(values));
                emit dataChanged(index(static_cast<int>(row), 1), index(static_cast<int>(row), columnCount() - 1));
            }
        protected:
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (event != nullptr && event->type() == QEvent::LanguageChange)
                {
                    emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1);
                    if (rowCount() > 0) emit dataChanged(index(0, 1), index(rowCount() - 1, 1));
                }
                return QAbstractTableModel::eventFilter(watched, event);
            }

        private:
            void retireResults()
            {
                if (m_results.isEmpty()) return;
                QThreadPool::globalInstance()->start(QRunnable::create(
                    [retired = std::move(m_results)]() mutable { retired.clear(); }));
            }
            QStringList m_paths;
            QStringList m_headers;
            QHash<qsizetype, QStringList> m_results;
            quint64 m_generation = 0;
        };

        QWidget* buildHashTab()
        {
            if (m_batchMode)
            {
                QWidget* page = new QWidget(this);
                QVBoxLayout* layout = new QVBoxLayout(page);
                QHBoxLayout* toolbar = new QHBoxLayout();
                QPushButton* startButton = new QPushButton(QStringLiteral("批量计算哈希"), page);
                QPushButton* cancelButton = new QPushButton(QStringLiteral("取消"), page);
                cancelButton->setEnabled(false);
                QLabel* statusLabel = new QLabel(QStringLiteral("● 等待开始批量哈希"), page);
                toolbar->addWidget(startButton);
                toolbar->addWidget(cancelButton);
                toolbar->addWidget(statusLabel, 1);
                ks::ui::NormalizeToolbarRow(toolbar);
                layout->addLayout(toolbar);
                QProgressBar* progress = new QProgressBar(page);
                progress->setRange(0, m_filePaths.size());
                progress->setValue(0);
                layout->addWidget(progress);
                QTableView* table = new ks::ui::TableActionTableView(page);
                ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
                auto* model = new BatchHashRowsModel(m_filePaths, commonHashNames(), table);
                auto* proxy = new QSortFilterProxyModel(table);
                proxy->setDynamicSortFilter(false);
                proxy->setSourceModel(model);
                table->setProperty("ks_i18n_preserve_model_data", true);
                table->setModel(proxy);
                table->setSelectionBehavior(QAbstractItemView::SelectRows);
                table->setSelectionMode(QAbstractItemView::ExtendedSelection);
                table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                table->setAlternatingRowColors(true);
                installValueTableCopyMenu(table);
                if (table->horizontalHeader() != nullptr)
                {
                    table->horizontalHeader()->setStretchLastSection(true);
                    table->horizontalHeader()->setSortIndicator(-1, Qt::AscendingOrder);
                }
                table->setSortingEnabled(true);
                layout->addWidget(table, 1);
                connect(cancelButton, &QPushButton::clicked, this, [this, cancelButton]()
                    {
                        if (m_hashCancelRequested != nullptr)
                            m_hashCancelRequested->store(true);
                        cancelButton->setEnabled(false);
                    });
                connect(startButton, &QPushButton::clicked, this,
                    [this, table, model, progress, statusLabel, startButton, cancelButton]()
                    {
                        m_hashCancelRequested = std::make_shared<std::atomic_bool>(false);
                        const auto cancelRequested = m_hashCancelRequested;
                        const QStringList paths = m_filePaths;
                        const quint64 generation = model->resetPaths(paths);
                        startButton->setEnabled(false);
                        cancelButton->setEnabled(true);
                        progress->setValue(0);
                        statusLabel->setText(QStringLiteral("● 正在后台计算批量哈希..."));
                        QPointer<QTableView> tableGuard(table);
                        QPointer<BatchHashRowsModel> modelGuard(model);
                        QPointer<QProgressBar> progressGuard(progress);
                        QPointer<QLabel> statusGuard(statusLabel);
                        QPointer<QPushButton> startGuard(startButton);
                        QPointer<QPushButton> cancelGuard(cancelButton);
                        auto* task = QRunnable::create(
                            [tableGuard, modelGuard, progressGuard, statusGuard, startGuard, cancelGuard,
                             cancelRequested, paths, generation]()
                            {
                                int completed = 0;
                                for (qsizetype row = 0; row < paths.size(); ++row)
                                {
                                    if (cancelRequested->load()) break;
                                    QString stateText;
                                    QStringList hashValues;
                                    QString errorText;
                                    const QFileInfo info(paths.at(row));
                                    if (!info.isFile())
                                    {
                                        stateText = QStringLiteral("已跳过");
                                        errorText = QStringLiteral("不是普通文件");
                                    }
                                    else
                                    {
                                        QFile file(paths.at(row));
                                        if (!file.open(QIODevice::ReadOnly))
                                        {
                                            stateText = QStringLiteral("失败");
                                            errorText = file.errorString();
                                        }
                                        else
                                        {
                                            CommonFileHashes hashes;
                                            while (!file.atEnd() && !cancelRequested->load())
                                            {
                                                const QByteArray block = file.read(1024 * 1024);
                                                if (block.isEmpty() && file.error() != QFileDevice::NoError) break;
                                                if (block.isEmpty()) break;
                                                hashes.addData(block);
                                            }
                                            if (cancelRequested->load())
                                            {
                                                stateText = QStringLiteral("已取消");
                                            }
                                            else if (file.error() != QFileDevice::NoError)
                                            {
                                                stateText = QStringLiteral("失败");
                                                errorText = file.errorString();
                                            }
                                            else
                                            {
                                                stateText = QStringLiteral("完成");
                                                hashValues = hashes.results();
                                            }
                                        }
                                    }
                                    ++completed;
                                    QMetaObject::invokeMethod(qApp,
                                        [tableGuard, modelGuard, progressGuard, row, completed, stateText, hashValues, errorText, generation]()
                                        {
                                            if (tableGuard == nullptr || modelGuard == nullptr || modelGuard->generation() != generation) return;
                                            modelGuard->setResult(row, stateText, hashValues, errorText);
                                            if (progressGuard != nullptr) progressGuard->setValue(completed);
                                        }, Qt::QueuedConnection);
                                }
                                QMetaObject::invokeMethod(qApp,
                                    [statusGuard, modelGuard, startGuard, cancelGuard, cancelRequested, completed, paths, generation]()
                                    {
                                        if (statusGuard == nullptr || modelGuard == nullptr || modelGuard->generation() != generation) return;
                                        statusGuard->setText(cancelRequested->load()
                                            ? QStringLiteral("● 批量哈希已取消，完成 %1 / %2。")
                                                .arg(completed).arg(paths.size())
                                            : QStringLiteral("● 批量哈希完成，共处理 %1 项。")
                                                .arg(completed));
                                        if (startGuard != nullptr) startGuard->setEnabled(true);
                                        if (cancelGuard != nullptr) cancelGuard->setEnabled(false);
                                    }, Qt::QueuedConnection);
                            });
                        task->setAutoDelete(true);
                        QThreadPool::globalInstance()->start(task);
                    });
                return page;
            }

            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QHBoxLayout* toolbarLayout = new QHBoxLayout();
            QPushButton* startButton = new QPushButton(QStringLiteral("计算常用哈希"), page);
            QPushButton* cancelButton = new QPushButton(QStringLiteral("取消"), page);
            cancelButton->setEnabled(false);
            toolbarLayout->addWidget(startButton, 0);
            toolbarLayout->addWidget(cancelButton, 0);
            toolbarLayout->addStretch(1);
            ks::ui::NormalizeToolbarRow(toolbarLayout);
            layout->addLayout(toolbarLayout);

            QProgressBar* progressBar = new QProgressBar(page);
            progressBar->setRange(0, 1000);
            progressBar->setValue(0);
            layout->addWidget(progressBar, 0);

            auto* textEditorWidget = new ks::ui::StructuredFieldView(page);
            layout->addWidget(textEditorWidget, 1);

            ks::ui::FieldDocument explanation;
            explanation.note(QStringLiteral(
                "常用哈希算法：MD5、SHA-1、SHA-224、SHA-256、SHA-384、SHA-512、SHA3-256、BLAKE2b-512。\n"
                "所有算法共享一次流式读取；取消或读取失败时不展示未完成的摘要。\n"
                "可用 PowerShell Get-FileHash 对比 MD5、SHA1、SHA256、SHA384、SHA512。\n"));
            textEditorWidget->setDocument(explanation);

            connect(startButton, &QPushButton::clicked, this, [this, textEditorWidget, progressBar, startButton, cancelButton]()
                {
                    startHashCalculation(textEditorWidget, progressBar, startButton, cancelButton);
                });
            connect(cancelButton, &QPushButton::clicked, this, [this, cancelButton]()
                {
                    requestHashCancel(cancelButton);
                });
            return page;
        }

        static void installUsageCopyMenu(QTableView* table)
        {
            table->setContextMenuPolicy(Qt::CustomContextMenu);
            connect(table, &QTableView::customContextMenuRequested, table, [table](const QPoint& point)
                {
                    const QModelIndex clicked = table->indexAt(point);
                    if (clicked.isValid()) table->setCurrentIndex(clicked);
                    const QPersistentModelIndex selected(table->currentIndex());
                    const QPointer<QTableView> guard(table);
                    const quint32 pid = selected.sibling(selected.row(), 0).data(usageProcessIdRole).toUInt();
                    QMenu menu;
                    menu.setStyleSheet(buildContextMenuStyle());
                    connect(table, &QObject::destroyed, &menu, &QMenu::close);
                    auto* copy = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
                    ks::ui::SetTableContextActionRole(copy, ks::ui::TableContextActionRole::CopyRows);
                    copy->setEnabled(selected.isValid());
                    auto* open = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("转到进程详细信息"));
                    open->setEnabled(pid != 0);
                    auto* action = menu.exec(table->viewport()->mapToGlobal(point));
                    if (!guard || !selected.isValid()) return;
                    if (action == open) { ks::ui::OpenProcessDetailByPid(pid); return; }
                    if (action != copy || !QApplication::clipboard()) return;
                    QStringList fields;
                    for (int column = 0; column < table->model()->columnCount(); ++column)
                        fields.push_back(selected.sibling(selected.row(), column).data().toString());
                    QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
                });
        }

        QWidget* buildUsageTab()
        {
            // 用途：Phase-10 把现有文件占用扫描结果直接嵌入属性窗口。
            // 处理：这里只创建轻量 UI，不在首次切换 Tab 时自动扫描，避免系统句柄枚举
            //       和结果回填让属性窗口卡顿；用户点击“刷新占用”后再后台扫描。
            //       Scanner 先调用 R0 HandleTable；R0 未启用时由全局入口提示用户，
            //       本轮回落 R3，服务启用成功后属性页再自动重扫一次。
            QWidget* page = new QWidget(this);
            page->setAttribute(Qt::WA_AlwaysShowToolTips);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QHBoxLayout* toolbarLayout = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新占用"), page);
            refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/handle_refresh.svg")));
            refreshButton->setIconSize(QSize(16, 16));
            refreshButton->setToolTip(QStringLiteral("重新扫描当前文件或目录的占用句柄"));

            QPushButton* closeHandleButton = new QPushButton(QStringLiteral("关闭句柄（R3）"), page);
            closeHandleButton->setIcon(QIcon(QStringLiteral(":/Icon/handle_close.svg")));
            closeHandleButton->setIconSize(QSize(16, 16));
            closeHandleButton->setToolTip(QStringLiteral("校验选中记录后，从用户态关闭该远程文件句柄"));
            closeHandleButton->setEnabled(false);

            QPushButton* closeHandleR0Button = new QPushButton(QStringLiteral("关闭句柄（R0）"), page);
            closeHandleR0Button->setIcon(QIcon(QStringLiteral(":/Icon/handle_close.svg")));
            closeHandleR0Button->setIconSize(QSize(16, 16));
            closeHandleR0Button->setToolTip(QStringLiteral("校验进程和对象身份后，由 KswordARK 驱动关闭选中的文件句柄"));
            closeHandleR0Button->setEnabled(false);

            QPushButton* terminateR3Button = new QPushButton(QStringLiteral("结束进程（R3）"), page);
            terminateR3Button->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
            terminateR3Button->setIconSize(QSize(16, 16));
            terminateR3Button->setToolTip(QStringLiteral("校验 PID 和进程创建时间后，从用户态结束占用进程"));
            terminateR3Button->setEnabled(false);

            QPushButton* terminateR0Button = new QPushButton(QStringLiteral("结束进程（R0）"), page);
            terminateR0Button->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
            terminateR0Button->setIconSize(QSize(16, 16));
            terminateR0Button->setToolTip(QStringLiteral("校验 PID 和进程创建时间后，由 KswordARK 驱动结束占用进程"));
            terminateR0Button->setEnabled(false);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 未扫描，点击“刷新占用”开始枚举文件占用。"), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            toolbarLayout->addWidget(refreshButton, 0);
            toolbarLayout->addWidget(closeHandleButton, 0);
            toolbarLayout->addWidget(closeHandleR0Button, 0);
            toolbarLayout->addWidget(terminateR3Button, 0);
            toolbarLayout->addWidget(terminateR0Button, 0);
            toolbarLayout->addStretch(1);
            ks::ui::NormalizeToolbarRow(toolbarLayout);
            layout->addLayout(toolbarLayout);
            layout->addWidget(statusLabel, 0);

            QProgressBar* usageProgressBar = new QProgressBar(page);
            usageProgressBar->setRange(0, 100);
            usageProgressBar->setValue(0);
            usageProgressBar->setFormat(QStringLiteral("%p%"));
            m_usageScanProgressBar = usageProgressBar;
            layout->addWidget(usageProgressBar, 0);

            QTableView* table = createPropertyTable(page, {QStringLiteral("PID"), QStringLiteral("进程名"), QStringLiteral("Handle"), QStringLiteral("GrantedAccess"), QStringLiteral("对象/路径"), QStringLiteral("命中目标"), QStringLiteral("枚举来源")}, QStringLiteral("file-detail-usage"));
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::None);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            installUsageCopyMenu(table);
            layout->addWidget(table, 1);

            connect(refreshButton, &QPushButton::clicked, this, [this, table, statusLabel, refreshButton]()
                {
                    refreshUsageTable(table, statusLabel, refreshButton);
                });
            connect(table->selectionModel(), &QItemSelectionModel::currentChanged, this,
                [this, table, closeHandleButton, closeHandleR0Button, terminateR3Button, terminateR0Button](const QModelIndex& currentItem)
                {
                    const std::uint32_t processId = !currentItem.isValid()
                        ? 0U
                        : currentItem.sibling(currentItem.row(), 0).data(usageProcessIdRole).toUInt();
                    const std::uint64_t creationTime = !currentItem.isValid()
                        ? 0U
                        : currentItem.sibling(currentItem.row(), 0).data(usageProcessCreationTimeRole).toULongLong();
                    const std::uint64_t handleValue = !currentItem.isValid()
                        ? 0U
                        : currentItem.sibling(currentItem.row(), 0).data(usageHandleValueRole).toULongLong();
                    const QString processName = !currentItem.isValid() ? QString() : currentItem.sibling(currentItem.row(), 1).data().toString();
                    const std::uint64_t objectAddress = !currentItem.isValid() ? 0U
                        : currentItem.sibling(currentItem.row(), 0).data(usageObjectAddressRole).toULongLong();
                    const bool processActionAllowed = !m_usageCloseInProgress && processId > 4U &&
                        processId != static_cast<std::uint32_t>(::GetCurrentProcessId()) &&
                        creationTime != 0U && !isCriticalProcessName(processName);
                    closeHandleButton->setEnabled(processActionAllowed && handleValue != 0U);
                    closeHandleR0Button->setEnabled(processActionAllowed && handleValue != 0U &&
                        handleValue < 0x80000000ULL && objectAddress != 0U);
                    QString closeReason = QStringLiteral("校验选中记录后，从用户态关闭该远程文件句柄");
                    if (currentItem.isValid() && handleValue == 0U)
                        closeReason = QStringLiteral("无句柄值：该来源可能是进程映像/模块映射，不能用 R3 关闭句柄处理");
                    else if (processId == static_cast<std::uint32_t>(::GetCurrentProcessId()))
                        closeReason = QStringLiteral("已保护：当前 Ksword 进程，不可关闭句柄");
                    else if (currentItem.isValid() && (processId <= 4U || isCriticalProcessName(processName)))
                        closeReason = QStringLiteral("已保护：关键系统进程，不可关闭句柄");
                    else if (currentItem.isValid() && creationTime == 0U)
                        closeReason = QStringLiteral("无法确认进程身份，请重新扫描后再关闭句柄。");
                    closeHandleButton->setToolTip(ks::i18n::sourceText(closeReason));
                    table->setToolTip(ks::i18n::sourceText(closeReason));
                    QString r0Reason = QStringLiteral("校验进程和对象身份后，由 KswordARK 驱动关闭选中的文件句柄");
                    if (currentItem.isValid() && handleValue == 0U)
                        r0Reason = QStringLiteral("模块或映像映射没有可关闭的文件句柄。");
                    else if (!processActionAllowed) { r0Reason = closeReason; }
                    else if (objectAddress == 0U || handleValue >= 0x80000000ULL)
                        r0Reason = QStringLiteral("缺少可验证的用户句柄对象身份，请启用 R0 后重新扫描。");
                    closeHandleR0Button->setToolTip(ks::i18n::sourceText(r0Reason));
                    terminateR3Button->setEnabled(processActionAllowed);
                    terminateR0Button->setEnabled(processActionAllowed);
                });
            connect(closeHandleButton, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    closeSelectedUsageHandle(table, statusLabel, refreshButton);
                });
            connect(closeHandleR0Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton, closeHandleButton, closeHandleR0Button,
                    terminateR3Button, terminateR0Button]()
                {
                    closeSelectedUsageHandleR0(table, statusLabel, refreshButton,
                        { closeHandleButton, closeHandleR0Button, terminateR3Button, terminateR0Button });
                });
            connect(terminateR3Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    terminateSelectedUsageProcess(table, statusLabel, refreshButton, false);
                });
            connect(terminateR0Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    terminateSelectedUsageProcess(table, statusLabel, refreshButton, true);
                });

            MainWindow* const mainWindow = qobject_cast<MainWindow*>(parentWidget() != nullptr
                ? parentWidget()->window()
                : nullptr);
            if (mainWindow != nullptr)
            {
                connect(mainWindow, &MainWindow::r0DriverServiceStarted, this,
                    [this, table, statusLabel, refreshButton]()
                    {
                        if (m_usageScanInProgress)
                        {
                            m_usageR0StartedDuringScan = true;
                            return;
                        }
                        if (!m_usageRetryAfterR0Start)
                        {
                            return;
                        }
                        m_usageRetryAfterR0Start = false;
                        refreshUsageTable(table, statusLabel, refreshButton);
                    });
            }

            if (m_initialTabKey == QStringLiteral("usage"))
            {
                // 从“文件占用与解锁”入口进入时直接扫描；
                // 普通属性窗口手动切页仍保持按需刷新，避免无意义的全系统枚举。
                QMetaObject::invokeMethod(
                    this,
                    [this, table, statusLabel, refreshButton]()
                    {
                        refreshUsageTable(table, statusLabel, refreshButton);
                    },
                    Qt::QueuedConnection);
            }
            return page;
        }

        // Native documents are collected off the UI thread; no report parser is involved.
        void startNativePropertyLoad(ks::ui::StructuredFieldView* view,
            const std::function<ks::ui::FieldDocument()>& collect)
        {
            if (view == nullptr) return;
            ks::ui::FieldDocument loading;
            loading.field(QStringLiteral("目标路径"), QDir::toNativeSeparators(m_filePath))
                .note(QStringLiteral("正在加载..."));
            view->setDocument(loading);
            const QPointer<ks::ui::StructuredFieldView> viewGuard(view);
            const QPointer<FileDetailDialog> dialogGuard(this);
            auto* task = QRunnable::create([viewGuard, dialogGuard, collect]()
                {
                    const ks::ui::FieldDocument document = collect();
                    QMetaObject::invokeMethod(qApp, [dialogGuard, viewGuard, document]()
                        {
                            if (dialogGuard != nullptr && viewGuard != nullptr) viewGuard->setDocument(document);
                        }, Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        template <typename AuditResult>
        static void appendNativeAuditHeader(ks::ui::FieldDocument& document,
            const QString& title, const AuditResult& result, const std::uint32_t responseFlags,
            const bool explicitTruncated = false)
        {
            document.section(title)
                .field(QStringLiteral("IO状态"), result.io.ok ? QStringLiteral("OK") : QStringLiteral("FAIL"), true)
                .field(QStringLiteral("unsupported"), formatAuditBool(result.unsupported), true)
                .field(QStringLiteral("version"), QString::number(result.version))
                .field(QStringLiteral("status"), QString::number(result.status))
                .field(QStringLiteral("totalCount"), QString::number(result.totalCount))
                .field(QStringLiteral("returnedCount"), QString::number(result.returnedCount))
                .field(QStringLiteral("truncated"), formatAuditBool(explicitTruncated ||
                    result.returnedCount < result.totalCount), true)
                .field(QStringLiteral("entrySize/rowSize"), QString::number(result.entrySize))
                .field(QStringLiteral("responseFlags"), formatHexValue(responseFlags, 8))
                .field(QStringLiteral("lastStatus"), formatNtStatus(result.lastStatus))
                .field(QStringLiteral("win32Error"), QString::number(result.io.win32Error))
                .field(QStringLiteral("bytesReturned"), QString::number(result.io.bytesReturned))
                .field(QStringLiteral("说明"), friendlyFileIoMessage(result.io.message), true);
        }

        static void appendNativeFileInfo(ks::ui::FieldDocument& document,
            const ksword::ark::FileInfoQueryResult& result)
        {
            document.section(QStringLiteral("FileObject / Section / ControlArea"))
                .field(QStringLiteral("IO状态"), result.io.ok ? QStringLiteral("OK") : QStringLiteral("FAIL"), true)
                .field(QStringLiteral("协议版本"), QString::number(result.version))
                .field(QStringLiteral("查询状态"), fileInfoStatusText(result.queryStatus), true)
                .field(QStringLiteral("查询状态码"), QString::number(result.queryStatus))
                .field(QStringLiteral("字段标志"), formatHexValue(result.fieldFlags, 8))
                .field(QStringLiteral("原因"), friendlyFileIoMessage(result.io.message), true)
                .field(QStringLiteral("Win32错误"), QString::number(result.io.win32Error))
                .field(QStringLiteral("OpenStatus"), formatNtStatus(result.openStatus))
                .field(QStringLiteral("BasicStatus"), formatNtStatus(result.basicStatus))
                .field(QStringLiteral("StandardStatus"), formatNtStatus(result.standardStatus))
                .field(QStringLiteral("ObjectStatus"), formatNtStatus(result.objectStatus))
                .field(QStringLiteral("NameStatus"), formatNtStatus(result.nameStatus));
            if (!result.io.ok) return;
            document.field(QStringLiteral("R0 对象名"), QString::fromStdWString(result.objectName))
                .field(QStringLiteral("文件属性"), fileAttributesToText(result.fileAttributes))
                .field(QStringLiteral("AllocationSize"), QString::number(result.allocationSize))
                .field(QStringLiteral("EndOfFile"), QString::number(result.endOfFile))
                .field(QStringLiteral("创建时间"), fileTimeToText(result.creationTime))
                .field(QStringLiteral("最后访问"), fileTimeToText(result.lastAccessTime))
                .field(QStringLiteral("最后写入"), fileTimeToText(result.lastWriteTime))
                .field(QStringLiteral("元数据变更（ChangeTime）"), fileTimeToText(result.changeTime))
                .field(QStringLiteral("FileObject"), formatHex64(result.fileObjectAddress))
                .field(QStringLiteral("SectionObjectPointers"), formatHex64(result.sectionObjectPointersAddress))
                .field(QStringLiteral("DataSectionObject"), formatHex64(result.dataSectionObjectAddress))
                .field(QStringLiteral("ImageSectionObject"), formatHex64(result.imageSectionObjectAddress));
        }

        QWidget* buildFileObjectTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            auto* view = new ks::ui::StructuredFieldView(page);
            layout->addWidget(view, 1);
            const QString pathSnapshot = m_filePath;
            startNativePropertyLoad(view, [pathSnapshot]()
                {
                    ks::ui::FieldDocument document;
                    document.section(QStringLiteral("FileStandardInfo"))
                        .field(QStringLiteral("目标路径"), QDir::toNativeSeparators(pathSnapshot))
                        .note(QStringLiteral("这里只做只读对象/句柄视图，不提供解锁、删除或绕过动作。"));
                    const QFileInfo info(pathSnapshot);
                    HANDLE fileHandle = openReadOnlyFileHandle(pathSnapshot, info.isDir());
                    if (fileHandle == INVALID_HANDLE_VALUE)
                    {
                        document.field(QStringLiteral("打开失败"), QString::number(::GetLastError()));
                        return document;
                    }
                    FILE_STANDARD_INFO standardInfo{};
                    if (::GetFileInformationByHandleEx(fileHandle, FileStandardInfo, &standardInfo,
                        static_cast<DWORD>(sizeof(standardInfo))) == FALSE)
                    {
                        document.field(QStringLiteral("读取失败"), QString::number(::GetLastError()));
                    }
                    else
                    {
                        document.field(QStringLiteral("DeletePending"), formatAuditBool(standardInfo.DeletePending), true)
                            .field(QStringLiteral("Directory"), formatAuditBool(standardInfo.Directory), true)
                            .field(QStringLiteral("AllocationSize"), QString::number(standardInfo.AllocationSize.QuadPart))
                            .field(QStringLiteral("EndOfFile"), QString::number(standardInfo.EndOfFile.QuadPart))
                            .field(QStringLiteral("NumberOfLinks"), QString::number(standardInfo.NumberOfLinks))
                            .field(QStringLiteral("采集句柄 ShareAccess"), QStringLiteral("READ|WRITE|DELETE"));
                    }
                    ::CloseHandle(fileHandle);
                    const QString ntPathText = buildDriverNtPath(pathSnapshot);
                    const ksword::ark::FileInfoQueryResult r0Info = queryR0FileInfo(info, ntPathText);
                    appendNativeFileInfo(document, r0Info);
                    const ksword::ark::FileSectionMappingsQueryResult sectionView =
                        ksword::ark::DriverClient().queryFileSectionMappings(ntPathText.toStdWString(),
                            KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
                            KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
                    document.section(QStringLiteral("ControlArea Cross-View"))
                        .field(QStringLiteral("IO状态"), sectionView.io.ok ? QStringLiteral("OK") : QStringLiteral("FAIL"), true)
                        .field(QStringLiteral("查询状态"), QString::number(sectionView.queryStatus))
                        .field(QStringLiteral("查询说明"), friendlyFileIoMessage(sectionView.io.message), true)
                        .field(QStringLiteral("Win32错误"), QString::number(sectionView.io.win32Error));
                    if (sectionView.io.ok)
                    {
                        document.field(QStringLiteral("FileObject"), formatHex64(sectionView.fileObjectAddress))
                            .field(QStringLiteral("SectionObjectPointers"), formatHex64(sectionView.sectionObjectPointersAddress))
                            .field(QStringLiteral("DataControlArea"), formatHex64(sectionView.dataControlAreaAddress))
                            .field(QStringLiteral("ImageControlArea"), formatHex64(sectionView.imageControlAreaAddress))
                            .field(QStringLiteral("returnedCount"), QString::number(sectionView.returnedCount))
                            .field(QStringLiteral("totalCount"), QString::number(sectionView.totalCount))
                            .note(QStringLiteral("跨视图：R3 文件标准信息给出 DeletePending；R0 侧给出 FileObject / SectionObjectPointers / ControlArea。"));
                    }
                    else
                    {
                        document.note(QStringLiteral("跨视图：当前仅保留 R0 FileInfo 结果，ControlArea 查询降级。"));
                    }
                    document.section(QStringLiteral("Cross-View"))
                        .field(QStringLiteral("R0 FileObject"), formatHex64(r0Info.fileObjectAddress))
                        .field(QStringLiteral("R0 SectionObjectPointers"), formatHex64(r0Info.sectionObjectPointersAddress))
                        .field(QStringLiteral("R0 DataSectionObject"), formatHex64(r0Info.dataSectionObjectAddress))
                        .field(QStringLiteral("R0 ImageSectionObject"), formatHex64(r0Info.imageSectionObjectAddress))
                        .note(QStringLiteral("R3 DeletePending/Share: 通过 FileStandardInfo 和共享只读打开侧写。"))
                        .note(QStringLiteral("R3 Shared flags: 采集句柄使用 READ|WRITE|DELETE 共享，仅用于只读探测。"));
                    return document;
                });
            return page;
        }

        QWidget* buildStorageTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            auto* view = new ks::ui::StructuredFieldView(page);
            layout->addWidget(view, 1);
            const QString pathSnapshot = m_filePath;
            startNativePropertyLoad(view, [pathSnapshot]()
                { return buildStorageAuditDocument(pathSnapshot); });
            return page;
        }

        static ks::ui::FieldDocument buildStorageAuditDocument(const QString& filePathText)
        {
            ks::ui::FieldDocument document;
            const QString volumeRoot = volumePathFromAnyPath(filePathText);
            document.section(QStringLiteral("Storage / MountMgr / FVE"))
                .field(QStringLiteral("目标路径"), QDir::toNativeSeparators(filePathText))
                .field(QStringLiteral("卷根"), volumeRoot)
                .note(QStringLiteral("本页只展示可见状态，不做解锁、卸载、绕过或密钥导出。"))
                .note(QStringLiteral("DeviceObject 在此页以卷设备路径做只读侧写，不触碰内核对象本身。"));
            std::array<wchar_t, MAX_PATH + 1U> volumeName{};
            const bool volumeNameOk = !volumeRoot.isEmpty() &&
                ::GetVolumeNameForVolumeMountPointW(volumeRoot.toStdWString().c_str(),
                    volumeName.data(), static_cast<DWORD>(volumeName.size())) != FALSE;
            const DWORD volumeNameError = volumeNameOk ? ERROR_SUCCESS :
                (volumeRoot.isEmpty() ? ERROR_PATH_NOT_FOUND : ::GetLastError());
            const QString volumeGuid = volumeNameOk ? QString::fromWCharArray(volumeName.data()) : QString();
            QString deviceName = volumeGuid;
            if (deviceName.startsWith(QStringLiteral("\\\\?\\"))) deviceName.remove(0, 4);
            if (deviceName.endsWith(QLatin1Char('\\'))) deviceName.chop(1);
            if (deviceName.isEmpty()) deviceName = volumeRoot.left(2);
            std::array<wchar_t, 32768U> deviceBuffer{};
            const bool devicePathOk = !deviceName.isEmpty() &&
                ::QueryDosDeviceW(deviceName.toStdWString().c_str(), deviceBuffer.data(),
                    static_cast<DWORD>(deviceBuffer.size())) != 0;
            const DWORD devicePathError = devicePathOk ? ERROR_SUCCESS :
                (deviceName.isEmpty() ? ERROR_PATH_NOT_FOUND : ::GetLastError());
            const QString devicePath = devicePathOk ? QString::fromWCharArray(deviceBuffer.data()) : QString();
            const QString mountPoints = buildMountPointsText(volumeGuid);
            document.field(QStringLiteral("Volume GUID"), volumeGuid)
                .field(QStringLiteral("挂载点"), mountPoints)
                .field(QStringLiteral("设备路径"), devicePath)
                .field(QStringLiteral("GetVolumeNameForVolumeMountPointW"), QString::number(volumeNameError))
                .field(QStringLiteral("QueryDosDeviceW"), QString::number(devicePathError));
            std::array<wchar_t, MAX_PATH + 1U> labelBuffer{}, fsBuffer{};
            DWORD serialNumber = 0, maxComponentLength = 0, fsFlags = 0;
            const bool volumeInfoOk = !volumeRoot.isEmpty() &&
                ::GetVolumeInformationW(volumeRoot.toStdWString().c_str(), labelBuffer.data(),
                    static_cast<DWORD>(labelBuffer.size()), &serialNumber, &maxComponentLength, &fsFlags,
                    fsBuffer.data(), static_cast<DWORD>(fsBuffer.size())) != FALSE;
            const DWORD volumeInfoError = volumeInfoOk ? ERROR_SUCCESS :
                (volumeRoot.isEmpty() ? ERROR_PATH_NOT_FOUND : ::GetLastError());
            const QString fsName = volumeInfoOk ? QString::fromWCharArray(fsBuffer.data()) : QString();
            document.field(QStringLiteral("卷栈"), buildVolumeStackText(volumeRoot, devicePath, fsName, mountPoints))
                .section(QStringLiteral("卷信息"))
                .field(QStringLiteral("GetVolumeInformationW"), QString::number(volumeInfoError));
            if (volumeInfoOk)
                document.field(QStringLiteral("卷标"), QString::fromWCharArray(labelBuffer.data()))
                    .field(QStringLiteral("文件系统"), fsName)
                    .field(QStringLiteral("Serial"), formatHexValue(serialNumber, 8))
                    .field(QStringLiteral("Flags"), formatHexValue(fsFlags, 8))
                    .field(QStringLiteral("MaximumComponentLength"), QString::number(maxComponentLength));
            document.section(QStringLiteral("存储描述"));
            QString volumeOpenPath = volumeGuid;
            if (volumeOpenPath.endsWith(QLatin1Char('\\'))) volumeOpenPath.chop(1);
            if (volumeOpenPath.isEmpty() && volumeRoot.size() >= 2)
                volumeOpenPath = QStringLiteral("\\\\.\\") + volumeRoot.left(2);
            HANDLE storageHandle = volumeOpenPath.isEmpty() ? INVALID_HANDLE_VALUE :
                ::CreateFileW(volumeOpenPath.toStdWString().c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
            if (storageHandle == INVALID_HANDLE_VALUE)
            {
                document.field(QStringLiteral("CreateFile"), QString::number(
                    volumeOpenPath.isEmpty() ? ERROR_PATH_NOT_FOUND : ::GetLastError()));
            }
            else
            {
                STORAGE_PROPERTY_QUERY query{};
                query.PropertyId = StorageDeviceProperty;
                query.QueryType = PropertyStandardQuery;
                std::array<std::uint8_t, 1024U> descriptorBytes{};
                DWORD returnedBytes = 0;
                const BOOL queried = ::DeviceIoControl(storageHandle, IOCTL_STORAGE_QUERY_PROPERTY,
                    &query, static_cast<DWORD>(sizeof(query)), descriptorBytes.data(),
                    static_cast<DWORD>(descriptorBytes.size()), &returnedBytes, nullptr);
                const DWORD descriptorError = queried ? ERROR_SUCCESS : ::GetLastError();
                document.field(QStringLiteral("IOCTL_STORAGE_QUERY_PROPERTY"), QString::number(descriptorError))
                    .field(QStringLiteral("RawSize"), QString::number(returnedBytes));
                if (queried && returnedBytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
                {
                    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(descriptorBytes.data());
                    document.field(QStringLiteral("BusType"), QString::number(static_cast<unsigned long>(descriptor->BusType)))
                        .field(QStringLiteral("Removable"), formatAuditBool(descriptor->RemovableMedia), true);
                }
                ::CloseHandle(storageHandle);
            }
            document.section(QStringLiteral("BitLocker"))
                .field(QStringLiteral("BitLocker WMI"),
                    QStringLiteral("查询语句已准备，当前版本保留降级文本展示。"), true);
            const std::wstring volumeAuditPath = (devicePath.isEmpty() ? volumeRoot : devicePath).toStdWString();
            const ksword::ark::DriverClient driverClient;
            const auto volumeStack = driverClient.queryVolumeStackAudit(volumeAuditPath);
            appendNativeAuditHeader(document, QStringLiteral("R0 审计补充 / VolumeStack"),
                volumeStack, volumeStack.responseFlags);
            document.field(QStringLiteral("fvevolPresent"), QString::number(volumeStack.fvevolPresent))
                .field(QStringLiteral("fvevolPosition"), QString::number(volumeStack.fvevolPosition))
                .field(QStringLiteral("fieldFlags"), formatHexValue(volumeStack.fieldFlags, 8));
            for (std::size_t index = 0; index < volumeStack.rows.size(); ++index)
            {
                const auto& row = volumeStack.rows[index];
                document.section(QStringLiteral("VolumeStack #%1").arg(index))
                    .field(QStringLiteral("StackIndex"), QString::number(row.stackIndex))
                    .field(QStringLiteral("Driver"), fixedWideAuditText(row.driverName))
                    .field(QStringLiteral("Volume"), fixedWideAuditText(row.volumeDeviceName))
                    .field(QStringLiteral("Confidence"), QString::number(row.confidence))
                    .field(QStringLiteral("Risk"), formatHexValue(row.riskFlags, 8))
                    .field(QStringLiteral("DeviceObject"), formatHex64(row.deviceObjectAddress))
                    .field(QStringLiteral("DriverObject"), formatHex64(row.driverObjectAddress))
                    .field(QStringLiteral("Attached"), formatHex64(row.attachedDeviceAddress))
                    .field(QStringLiteral("Lower"), formatHex64(row.lowerDeviceAddress))
                    .field(QStringLiteral("Type"), formatHexValue(row.deviceType, 8))
                    .field(QStringLiteral("Characteristics"), formatHexValue(row.deviceCharacteristics, 8))
                    .field(QStringLiteral("Status"), formatNtStatus(row.lastStatus))
                    .field(QStringLiteral("Detail"), fixedWideAuditText(row.detail));
            }
            const auto mountMgr = driverClient.queryMountMgrMappingAudit(volumeAuditPath);
            appendNativeAuditHeader(document, QStringLiteral("R0 审计补充 / MountMgr"),
                mountMgr, mountMgr.responseFlags);
            document.field(QStringLiteral("fieldFlags"), formatHexValue(mountMgr.fieldFlags, 8));
            for (std::size_t index = 0; index < mountMgr.rows.size(); ++index)
            {
                const auto& row = mountMgr.rows[index];
                document.section(QStringLiteral("MountMgr #%1").arg(index))
                    .field(QStringLiteral("Drive"), fixedWideAuditText(row.driveLetter))
                    .field(QStringLiteral("Guid"), fixedWideAuditText(row.volumeGuid))
                    .field(QStringLiteral("NtPath"), fixedWideAuditText(row.ntDevicePath))
                    .field(QStringLiteral("Confidence"), QString::number(row.confidence))
                    .field(QStringLiteral("Risk"), formatHexValue(row.riskFlags, 8))
                    .field(QStringLiteral("Status"), formatNtStatus(row.lastStatus))
                    .field(QStringLiteral("Detail"), fixedWideAuditText(row.detail));
            }
            const auto filesystem = driverClient.queryFilesystemIntegrityAudit(volumeAuditPath);
            appendNativeAuditHeader(document, QStringLiteral("R0 审计补充 / FilesystemIntegrity"),
                filesystem, filesystem.responseFlags);
            document.field(QStringLiteral("fieldFlags"), formatHexValue(filesystem.fieldFlags, 8));
            std::map<std::uint64_t, ks::kernel::CleanImageBaselineResult> baselineCache;
            const auto byteText = [](const std::vector<std::uint8_t>& bytes)
                {
                    return bytes.empty() ? QString() : QString::fromLatin1(
                        QByteArray(reinterpret_cast<const char*>(bytes.data()),
                            static_cast<qsizetype>(bytes.size())).toHex(' ').toUpper());
                };
            for (std::size_t index = 0; index < filesystem.rows.size(); ++index)
            {
                const auto& row = filesystem.rows[index];
                if (row.targetAddress != 0 && baselineCache.find(row.targetAddress) == baselineCache.end())
                    baselineCache.emplace(row.targetAddress,
                        ks::kernel::KernelCleanImageBaseline::compareAddress(row.targetAddress, 16U));
                const auto baseline = row.targetAddress == 0 ? ks::kernel::CleanImageBaselineResult{} :
                    baselineCache.at(row.targetAddress);
                document.section(QStringLiteral("FilesystemIntegrity #%1").arg(index))
                    .field(QStringLiteral("FsKind"), QString::number(row.fileSystemKind))
                    .field(QStringLiteral("SlotType"), QString::number(row.slotType))
                    .field(QStringLiteral("SlotIndex"), QString::number(row.slotIndex))
                    .field(QStringLiteral("Driver"), fixedWideAuditText(row.driverName))
                    .field(QStringLiteral("Owner"), fixedWideAuditText(row.ownerModuleName))
                    .field(QStringLiteral("Confidence"), QString::number(row.confidence))
                    .field(QStringLiteral("Risk"), formatHexValue(row.riskFlags, 8))
                    .field(QStringLiteral("DriverObject"), formatHex64(row.driverObjectAddress))
                    .field(QStringLiteral("DriverStart"), formatHex64(row.driverStart))
                    .field(QStringLiteral("DriverSize"), formatHexValue(row.driverSize, 8))
                    .field(QStringLiteral("SlotAddress"), formatHex64(row.slotAddress))
                    .field(QStringLiteral("Target"), formatHex64(row.targetAddress))
                    .field(QStringLiteral("OwnerBase"), formatHex64(row.ownerModuleBase))
                    .field(QStringLiteral("OwnerSize"), formatHexValue(row.ownerModuleSize, 8))
                    .field(QStringLiteral("Status"), formatNtStatus(row.lastStatus))
                    .field(QStringLiteral("Detail"), fixedWideAuditText(row.detail))
                    .field(QStringLiteral("BaselineScope"), QStringLiteral("TARGET_PROLOGUE_ONLY"))
                    .field(QStringLiteral("CleanImageBaseline"), baseline.available ? QStringLiteral("AVAILABLE") : QStringLiteral("UNAVAILABLE"), true)
                    .field(QStringLiteral("IdentityMatched"), formatAuditBool(baseline.identityMatched), true)
                    .field(QStringLiteral("CodeIntegrityTrusted"), formatAuditBool(baseline.codeIntegrityTrusted), true)
                    .field(QStringLiteral("SigningLevel"), QString::number(baseline.signingLevel))
                    .field(QStringLiteral("Relocated"), formatAuditBool(baseline.relocationApplied), true)
                    .field(QStringLiteral("Differs"), baseline.available ? formatAuditBool(baseline.differs) : QStringLiteral("UNKNOWN"), true)
                    .field(QStringLiteral("Image"), baseline.imagePath)
                    .field(QStringLiteral("RVA"), formatHexValue(baseline.relativeVirtualAddress, 8))
                    .field(QStringLiteral("SHA256"), baseline.imageSha256)
                    .field(QStringLiteral("SigningThumbprint"), baseline.signingThumbprint)
                    .field(QStringLiteral("ObservedBytes"), byteText(baseline.observedBytes))
                    .field(QStringLiteral("CleanBytes"), byteText(baseline.cleanBytes))
                    .field(QStringLiteral("BaselineDetail"), baseline.statusText, true);
            }
            const auto bitlocker = driverClient.queryBitlockerFveAudit(volumeAuditPath);
            appendNativeAuditHeader(document, QStringLiteral("R0 审计补充 / BitLocker FVE"),
                bitlocker, bitlocker.responseFlags);
            document.field(QStringLiteral("fieldFlags"), formatHexValue(bitlocker.fieldFlags, 8));
            for (std::size_t index = 0; index < bitlocker.rows.size(); ++index)
            {
                const auto& row = bitlocker.rows[index];
                document.section(QStringLiteral("BitLocker FVE #%1").arg(index))
                    .field(QStringLiteral("Volume"), fixedWideAuditText(row.volumeDeviceName))
                    .field(QStringLiteral("FvePresent"), QString::number(row.fvevolPresent))
                    .field(QStringLiteral("FvePosition"), QString::number(row.fvevolStackPosition))
                    .field(QStringLiteral("Protection"), QString::number(row.protectionStatus))
                    .field(QStringLiteral("Conversion"), QString::number(row.conversionStatus))
                    .field(QStringLiteral("Lock"), QString::number(row.lockStatus))
                    .field(QStringLiteral("Confidence"), QString::number(row.confidence))
                    .field(QStringLiteral("Risk"), formatHexValue(row.riskFlags, 8))
                    .field(QStringLiteral("TPM"), QString::number(row.keyProtectorTypeCountTpm))
                    .field(QStringLiteral("TPM+PIN"), QString::number(row.keyProtectorTypeCountTpmPin))
                    .field(QStringLiteral("RecoveryPassword"), QString::number(row.keyProtectorTypeCountRecoveryPassword))
                    .field(QStringLiteral("RecoveryKey"), QString::number(row.keyProtectorTypeCountRecoveryKey))
                    .field(QStringLiteral("StartupKey"), QString::number(row.keyProtectorTypeCountStartupKey))
                    .field(QStringLiteral("ClearOrSuspended"), QString::number(row.keyProtectorTypeCountClearOrSuspended))
                    .field(QStringLiteral("Status"), formatNtStatus(row.lastStatus))
                    .field(QStringLiteral("Detail"), fixedWideAuditText(row.detail));
            }
            return document;
        }

        using NativeFilterFirst = std::function<HRESULT(void*, DWORD, DWORD*, HANDLE*)>;
        using NativeFilterNext = std::function<HRESULT(HANDLE, void*, DWORD, DWORD*)>;
        using NativeFilterClose = std::function<void(HANDLE)>;
        using NativeFilterRecord = std::function<void(const void*, std::size_t)>;

        static void enumerateNativeFilterRecords(ks::ui::FieldDocument& document,
            const NativeFilterFirst& first, const NativeFilterNext& next,
            const NativeFilterClose& close, const NativeFilterRecord& append)
        {
            std::vector<std::uint8_t> buffer(16U * 1024U);
            DWORD returnedBytes = 0;
            HANDLE handle = nullptr;
            const auto grow = [&buffer]()
                {
                    constexpr std::size_t maximumRecordBytes = 16U * 1024U * 1024U;
                    if (buffer.size() >= maximumRecordBytes) return false;
                    buffer.resize(buffer.size() * 2U);
                    return true;
                };
            HRESULT status = E_FAIL;
            for (;;)
            {
                status = first(buffer.data(), static_cast<DWORD>(buffer.size()), &returnedBytes, &handle);
                if (SUCCEEDED(status)) break;
                if ((status == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) ||
                    status == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) && grow()) continue;
                if (handle != nullptr) close(handle);
                document.field(QStringLiteral("枚举状态"), formatHexValue(static_cast<std::uint32_t>(status), 8));
                return;
            }
            for (;;)
            {
                if (returnedBytes <= buffer.size())
                {
                    std::size_t offset = 0;
                    while (offset < returnedBytes)
                    {
                        const std::size_t remaining = returnedBytes - offset;
                        if (remaining < sizeof(ULONG))
                        {
                            document.note(QStringLiteral("枚举记录链长度不足，已拒绝读取该记录。"));
                            break;
                        }
                        ULONG nextOffset = 0;
                        std::memcpy(&nextOffset, buffer.data() + offset, sizeof(nextOffset));
                        if (nextOffset != 0 && (nextOffset < sizeof(ULONG) ||
                            nextOffset % 8U != 0 || nextOffset >= remaining))
                        {
                            document.note(QStringLiteral("枚举记录链偏移无效，已拒绝读取该记录。"));
                            break;
                        }
                        append(buffer.data() + offset, nextOffset == 0 ? remaining : nextOffset);
                        if (nextOffset == 0) break;
                        offset += nextOffset;
                    }
                }
                else document.note(QStringLiteral("枚举返回长度超过缓冲区，已拒绝读取该记录。"));
                for (;;)
                {
                    returnedBytes = 0;
                    status = next(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &returnedBytes);
                    if ((status == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) ||
                        status == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) && grow()) continue;
                    break;
                }
                if (FAILED(status)) break;
            }
            if (handle != nullptr) close(handle);
            if (status != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                document.field(QStringLiteral("继续枚举状态"), formatHexValue(static_cast<std::uint32_t>(status), 8));
        }

        static void appendNativeInstance(ks::ui::FieldDocument& document,
            const void* buffer, const std::size_t bytesReturned, const QString& title)
        {
            document.section(title);
            if (buffer == nullptr || bytesReturned < sizeof(INSTANCE_AGGREGATE_STANDARD_INFORMATION))
            {
                document.note(QStringLiteral("实例枚举记录长度不足。"));
                return;
            }
            const auto* record = reinterpret_cast<const INSTANCE_AGGREGATE_STANDARD_INFORMATION*>(buffer);
            const bool mini = (record->Flags & FLTFL_IASI_IS_MINIFILTER) != 0;
            const QString name = mini ? readUtf16FieldAtOffset(buffer, bytesReturned,
                record->Type.MiniFilter.InstanceNameBufferOffset, record->Type.MiniFilter.InstanceNameLength) : QString();
            const QString altitude = mini ? readUtf16FieldAtOffset(buffer, bytesReturned,
                record->Type.MiniFilter.AltitudeBufferOffset, record->Type.MiniFilter.AltitudeLength) :
                readUtf16FieldAtOffset(buffer, bytesReturned,
                    record->Type.LegacyFilter.AltitudeBufferOffset, record->Type.LegacyFilter.AltitudeLength);
            const QString volume = mini ? readUtf16FieldAtOffset(buffer, bytesReturned,
                record->Type.MiniFilter.VolumeNameBufferOffset, record->Type.MiniFilter.VolumeNameLength) :
                readUtf16FieldAtOffset(buffer, bytesReturned,
                    record->Type.LegacyFilter.VolumeNameBufferOffset, record->Type.LegacyFilter.VolumeNameLength);
            const QString filter = mini ? readUtf16FieldAtOffset(buffer, bytesReturned,
                record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength) :
                readUtf16FieldAtOffset(buffer, bytesReturned,
                    record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
            document.field(QStringLiteral("实例名"), name)
                .field(QStringLiteral("类型"), mini ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter"))
                .field(QStringLiteral("Flags"), formatHexValue(record->Flags, 8))
                .field(QStringLiteral("Altitude"), altitude)
                .field(QStringLiteral("VolumeName"), volume)
                .field(QStringLiteral("FilterName"), filter);
            if (mini)
                document.field(QStringLiteral("FrameID"), QString::number(record->Type.MiniFilter.FrameID))
                    .field(QStringLiteral("VolumeFileSystemType"), filterFilesystemTypeToText(record->Type.MiniFilter.VolumeFileSystemType));
        }

        static ks::ui::FieldDocument buildFilterTopologyDocument(const QString& pathSnapshot)
        {
            ks::ui::FieldDocument document;
            document.section(QStringLiteral("Minifilter / Instance / Volume"))
                .field(QStringLiteral("目标路径"), QDir::toNativeSeparators(pathSnapshot))
                .note(QStringLiteral("本页只展示 FilterManager 公开枚举接口与字段定义，不做卸载、绕过或拦截修改。"))
                .field(QStringLiteral("枚举来源"), QStringLiteral("FilterFindFirst / FilterFindNext"));
            QStringList filterNames;
            std::size_t filterIndex = 0;
            enumerateNativeFilterRecords(document,
                [](void* buffer, DWORD size, DWORD* bytes, HANDLE* handle)
                    { return ::FilterFindFirst(FilterAggregateStandardInformation, buffer, size, bytes, handle); },
                [](HANDLE handle, void* buffer, DWORD size, DWORD* bytes)
                    { return ::FilterFindNext(handle, FilterAggregateStandardInformation, buffer, size, bytes); },
                [](HANDLE handle) { ::FilterFindClose(handle); },
                [&document, &filterNames, &filterIndex](const void* buffer, std::size_t bytes)
                {
                    document.section(QStringLiteral("Minifilter #%1").arg(filterIndex++));
                    if (bytes < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION))
                    {
                        document.note(QStringLiteral("过滤器枚举记录长度不足。"));
                        return;
                    }
                    const auto* record = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer);
                    const bool mini = (record->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
                    const QString name = mini ? readUtf16FieldAtOffset(buffer, bytes,
                        record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength) :
                        readUtf16FieldAtOffset(buffer, bytes,
                            record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
                    const QString altitude = mini ? readUtf16FieldAtOffset(buffer, bytes,
                        record->Type.MiniFilter.FilterAltitudeBufferOffset, record->Type.MiniFilter.FilterAltitudeLength) :
                        readUtf16FieldAtOffset(buffer, bytes,
                            record->Type.LegacyFilter.FilterAltitudeBufferOffset, record->Type.LegacyFilter.FilterAltitudeLength);
                    if (!name.isEmpty()) appendUniqueText(filterNames, name);
                    document.field(QStringLiteral("名称"), name)
                        .field(QStringLiteral("类型"), mini ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter"))
                        .field(QStringLiteral("Flags"), formatHexValue(record->Flags, 8))
                        .field(QStringLiteral("Altitude"), altitude);
                    if (mini)
                        document.field(QStringLiteral("FrameID"), QString::number(record->Type.MiniFilter.FrameID))
                            .field(QStringLiteral("NumberOfInstances"), QString::number(record->Type.MiniFilter.NumberOfInstances));
                });
            for (const QString& filterName : filterNames)
            {
                document.section(QStringLiteral("Instance")).field(QStringLiteral("FilterName"), filterName)
                    .field(QStringLiteral("枚举来源"), QStringLiteral("FilterInstanceFindFirst / FilterInstanceFindNext"));
                std::size_t instanceIndex = 0;
                enumerateNativeFilterRecords(document,
                    [&filterName](void* buffer, DWORD size, DWORD* bytes, HANDLE* handle)
                        { return ::FilterInstanceFindFirst(filterName.toStdWString().c_str(),
                            InstanceAggregateStandardInformation, buffer, size, bytes, handle); },
                    [](HANDLE handle, void* buffer, DWORD size, DWORD* bytes)
                        { return ::FilterInstanceFindNext(handle, InstanceAggregateStandardInformation, buffer, size, bytes); },
                    [](HANDLE handle) { ::FilterInstanceFindClose(handle); },
                    [&document, &instanceIndex, &filterName](const void* buffer, std::size_t bytes)
                        { appendNativeInstance(document, buffer, bytes,
                            QStringLiteral("Instance #%1 / %2").arg(instanceIndex++).arg(filterName)); });
            }
            document.section(QStringLiteral("Volume"))
                .field(QStringLiteral("枚举来源"), QStringLiteral("FilterVolumeFindFirst / FilterVolumeFindNext"));
            QStringList volumeNames;
            std::size_t volumeIndex = 0;
            enumerateNativeFilterRecords(document,
                [](void* buffer, DWORD size, DWORD* bytes, HANDLE* handle)
                    { return ::FilterVolumeFindFirst(FilterVolumeStandardInformation, buffer, size, bytes, handle); },
                [](HANDLE handle, void* buffer, DWORD size, DWORD* bytes)
                    { return ::FilterVolumeFindNext(handle, FilterVolumeStandardInformation, buffer, size, bytes); },
                [](HANDLE handle) { ::FilterVolumeFindClose(handle); },
                [&document, &volumeIndex, &volumeNames](const void* buffer, std::size_t bytes)
                {
                    document.section(QStringLiteral("Volume #%1").arg(volumeIndex++));
                    if (bytes < sizeof(FILTER_VOLUME_STANDARD_INFORMATION))
                    {
                        document.note(QStringLiteral("卷枚举记录长度不足。"));
                        return;
                    }
                    const auto* record = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer);
                    const QString name = readUtf16FieldAtOffset(buffer, bytes,
                        offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName), record->FilterVolumeNameLength);
                    if (!name.isEmpty()) appendUniqueText(volumeNames, name);
                    document.field(QStringLiteral("卷名"), name)
                        .field(QStringLiteral("Flags"), formatHexValue(record->Flags, 8))
                        .field(QStringLiteral("FrameID"), QString::number(record->FrameID))
                        .field(QStringLiteral("FileSystemType"), filterFilesystemTypeToText(record->FileSystemType));
                });
            for (const QString& volumeName : volumeNames)
            {
                document.section(QStringLiteral("AttachedInstances")).field(QStringLiteral("VolumeName"), volumeName);
                std::size_t instanceIndex = 0;
                enumerateNativeFilterRecords(document,
                    [&volumeName](void* buffer, DWORD size, DWORD* bytes, HANDLE* handle)
                        { return ::FilterVolumeInstanceFindFirst(volumeName.toStdWString().c_str(),
                            InstanceAggregateStandardInformation, buffer, size, bytes, handle); },
                    [](HANDLE handle, void* buffer, DWORD size, DWORD* bytes)
                        { return ::FilterVolumeInstanceFindNext(handle, InstanceAggregateStandardInformation, buffer, size, bytes); },
                    [](HANDLE handle) { ::FilterVolumeInstanceFindClose(handle); },
                    [&document, &instanceIndex, &volumeName](const void* buffer, std::size_t bytes)
                        { appendNativeInstance(document, buffer, bytes,
                            QStringLiteral("AttachedInstances #%1 / %2").arg(instanceIndex++).arg(volumeName)); });
            }
            const auto inventory = ksword::ark::DriverClient().queryMinifilterInventory();
            appendNativeAuditHeader(document, QStringLiteral("R0 审计补充 / MinifilterInventory"),
                inventory, inventory.responseFlags,
                (inventory.responseFlags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED) != 0U);
            for (std::size_t index = 0; index < inventory.entries.size(); ++index)
            {
                const auto& row = inventory.entries[index];
                document.section(QStringLiteral("MinifilterInventory #%1").arg(index))
                    .field(QStringLiteral("Filter"), fixedWideAuditText(row.filterName))
                    .field(QStringLiteral("Altitude"), fixedWideAuditText(row.altitude))
                    .field(QStringLiteral("Volume"), fixedWideAuditText(row.volumeName))
                    .field(QStringLiteral("Instance"), QString::number(row.instanceCount))
                    .field(QStringLiteral("VolumeBindings"), QString::number(row.volumeBindingInstanceCount))
                    .field(QStringLiteral("Frame"), QString::number(row.frameId))
                    .field(QStringLiteral("FilterObject"), formatHex64(row.filterObject))
                    .field(QStringLiteral("VolumeObject"), formatHex64(row.volumeObject))
                    .field(QStringLiteral("CallbackOwner"), fixedWideAuditText(row.callbackOwnerModule))
                    .field(QStringLiteral("OwnerStatus"), formatNtStatus(row.callbackOwnerStatus))
                    .field(QStringLiteral("FieldFlags"), formatHexValue(row.fieldFlags, 8))
                    .field(QStringLiteral("SourceFlags"), formatHexValue(row.sourceFlags, 8))
                    .field(QStringLiteral("Status"), QString::number(row.status));
            }
            return document;
        }

        QWidget* buildFilterTopologyTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            auto* view = new ks::ui::StructuredFieldView(page);
            layout->addWidget(view, 1);
            const QString pathSnapshot = m_filePath;
            startNativePropertyLoad(view, [pathSnapshot]()
                { return buildFilterTopologyDocument(pathSnapshot); });
            return page;
        }

        QWidget* buildSignatureTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QScrollArea* scroll = new QScrollArea(page);
            scroll->setWidgetResizable(true);
            scroll->setFrameShape(QFrame::NoFrame);
            QWidget* content = new QWidget(scroll);
            QVBoxLayout* contentLayout = new QVBoxLayout(content);
            QGroupBox* summary = new QGroupBox(ks::i18n::sourceText(QStringLiteral("签名概览")), content);
            QVBoxLayout* summaryLayout = new QVBoxLayout(summary);
            QLabel* state = new QLabel(ks::i18n::sourceText(QStringLiteral("正在验证签名...")), summary);
            state->setTextFormat(Qt::PlainText);
            state->setWordWrap(true);
            state->setTextInteractionFlags(Qt::TextSelectableByMouse);
            QFont stateFont = state->font();
            stateFont.setBold(true);
            stateFont.setPointSizeF(stateFont.pointSizeF() + 3.0);
            state->setFont(stateFont);
            ks::ui::ApplyStatusRole(state, ks::ui::StatusRole::Info);
            summaryLayout->addWidget(state);
            QLabel* hint = new QLabel(summary);
            hint->setTextFormat(Qt::PlainText);
            hint->setWordWrap(true);
            summaryLayout->addWidget(hint);
            QFormLayout* summaryForm = new QFormLayout();
            summaryForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
            summaryForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
            QVector<QPointer<QLabel>> values;
            const auto addField = [&values](QFormLayout* form, QWidget* parent, const QString& title)
                {
                    QLabel* name = new QLabel(ks::i18n::sourceText(title), parent);
                    QLabel* value = new QLabel(ks::i18n::sourceText(QStringLiteral("正在读取...")), parent);
                    value->setTextFormat(Qt::PlainText);
                    value->setWordWrap(true);
                    value->setMinimumWidth(0);
                    value->setTextInteractionFlags(Qt::TextSelectableByMouse);
                    form->addRow(name, value);
                    values.append(value);
                };
            addField(summaryForm, summary, QStringLiteral("颁发者"));
            addField(summaryForm, summary, QStringLiteral("签名者"));
            addField(summaryForm, summary, QStringLiteral("签名时间（本地时间）"));
            summaryLayout->addLayout(summaryForm);
            contentLayout->addWidget(summary);

            QToolButton* toggle = new QToolButton(content);
            toggle->setText(ks::i18n::sourceText(QStringLiteral("详细信息与原始证据")));
            toggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
            toggle->setCheckable(true);
            toggle->setArrowType(Qt::RightArrow);
            contentLayout->addWidget(toggle);
            QWidget* details = new QWidget(content);
            QVBoxLayout* detailsLayout = new QVBoxLayout(details);
            detailsLayout->setContentsMargins(0, 0, 0, 0);
            QGroupBox* certificate = new QGroupBox(ks::i18n::sourceText(QStringLiteral("证书与验证详情")), details);
            QFormLayout* detailForm = new QFormLayout(certificate);
            detailForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
            detailForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
            for (const QString& title : QStringList{
                QStringLiteral("嵌入式签名"), QStringLiteral("Catalog 文件已找到"), QStringLiteral("Catalog 路径"),
                QStringLiteral("证书 SHA-256 指纹"), QStringLiteral("证书生效时间"), QStringLiteral("证书到期时间"),
                QStringLiteral("时间戳签名者"), QStringLiteral("Windows 信任验证状态码"), QStringLiteral("签名者链状态码")})
                addField(detailForm, certificate, title);
            QLabel* verificationHint = new QLabel(ks::i18n::sourceText(QStringLiteral(
                "验证使用本机证书与吊销缓存。签名时间来自可信时间戳，证书有效期不是签名时间。")), certificate);
            verificationHint->setWordWrap(true);
            detailForm->addRow(verificationHint);
            detailsLayout->addWidget(certificate);
            QGroupBox* evidenceGroup = new QGroupBox(ks::i18n::sourceText(QStringLiteral("R0 内核原始证据")), details);
            QVBoxLayout* evidenceLayout = new QVBoxLayout(evidenceGroup);
            QLabel* boundary = new QLabel(ks::i18n::sourceText(QStringLiteral(
                "内核证书表和 CI 缓存是独立证据；缺失内核信息不会改写上方 Windows 信任验证结果。")), evidenceGroup);
            boundary->setWordWrap(true);
            evidenceLayout->addWidget(boundary);
            auto* evidence = new ks::ui::StructuredFieldView(evidenceGroup);
            evidence->setMinimumHeight(180);
            ks::ui::FieldDocument loading;
            loading.note(QStringLiteral("正在读取内核证据..."));
            evidence->setDocument(loading);
            evidenceLayout->addWidget(evidence);
            detailsLayout->addWidget(evidenceGroup);
            contentLayout->addWidget(details);
            details->hide();
            connect(toggle, &QToolButton::toggled, details, [toggle, details](bool expanded)
                {
                    toggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
                    details->setVisible(expanded);
                });
            contentLayout->addStretch(1);
            scroll->setWidget(content);
            layout->addWidget(scroll);
            startSignatureLoad(page, state, hint, values, evidence);
            return page;
        }

        QWidget* buildPeTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            auto* view = new ks::ui::StructuredFieldView(page);
            layout->addWidget(view, 1);
            startPeAnalysisLoad(view);
            return page;
        }

        QWidget* buildDependencyTab()
        {
            // 用途：创建“依赖 DLL”页 UI。
            // 处理：表格展示 DLL/函数/Ordinal/Hint/IAT RVA，底部文本显示摘要或错误；
            //      真实 PE Import Directory 解析由后台线程完成。
            // 返回：可嵌入属性窗口的 QWidget。
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 等待加载依赖 DLL"), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(statusLabel, 0);

            QSplitter* splitter = new QSplitter(Qt::Vertical, page);
            splitter->setChildrenCollapsible(false);
            splitter->setMinimumSize(0, 0);
            splitter->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
            QWidget* tablePane = new QWidget(splitter);
            QVBoxLayout* tableLayout = new QVBoxLayout(tablePane);
            tableLayout->setContentsMargins(0, 0, 0, 0);
            QTableView* table = createPropertyTable(tablePane, {QStringLiteral("DLL 名称"), QStringLiteral("函数名 / Ordinal"), QStringLiteral("Hint"), QStringLiteral("导入方式"), QStringLiteral("Thunk/IAT RVA"), QStringLiteral("诊断")}, QStringLiteral("file-detail-dependency"));
            // PE 依赖来自静态文件解析，通用现场快照/对比不适用。
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            table->setMinimumHeight(0);
            table->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
            table->setAlternatingRowColors(true);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSortingEnabled(true);
            table->setContextMenuPolicy(Qt::CustomContextMenu);
            if (table->horizontalHeader() != nullptr)
            {
                table->horizontalHeader()->setStretchLastSection(true);
            }
            tableLayout->addWidget(table);

            // 两个直接子面板各占一块布局空间，也兼容统一详情布局的接管。
            QWidget* detailPane = new QWidget(splitter);
            QVBoxLayout* detailLayout = new QVBoxLayout(detailPane);
            detailLayout->setContentsMargins(0, 0, 0, 0);
            auto* detailEditor = new ks::ui::StructuredFieldView(detailPane);
            detailEditor->setMinimumHeight(0);
            detailEditor->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
            detailLayout->addWidget(detailEditor);
            splitter->addWidget(tablePane);
            splitter->addWidget(detailPane);
            splitter->setStretchFactor(0, 2);
            splitter->setStretchFactor(1, 1);
            splitter->setSizes({400, 200});
            layout->addWidget(splitter, 1);

            connect(table, &QTableView::customContextMenuRequested, this, [table](const QPoint& position)
                {
                    if (table == nullptr)
                    {
                        return;
                    }

                    const QPointer<QTableView> tableGuard(table);
                    QMenu menu;
                    connect(table, &QObject::destroyed, &menu, &QMenu::close);
                    menu.setStyleSheet(buildContextMenuStyle());
                    QAction* copyRowsAction = menu.addAction(QStringLiteral("复制选中行"));
                    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
                    ks::ui::SetTableContextActionRole(copyRowsAction, ks::ui::TableContextActionRole::CopyRows);
                    QAction* copyDllAction = menu.addAction(QStringLiteral("复制 DLL 名称"));
                    QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(position));
                    if (tableGuard == nullptr || selectedAction == nullptr)
                    {
                        return;
                    }
                    if (selectedAction != copyRowsAction && selectedAction != copyDllAction)
                    {
                        return;
                    }

                    const bool dllOnly = selectedAction == copyDllAction;
                    const QString clipboardText = dependencyRowsToClipboardText(table, dllOnly);
                    if (!clipboardText.isEmpty() && QApplication::clipboard() != nullptr)
                    {
                        QApplication::clipboard()->setText(clipboardText);
                    }
                });

            startDependencyLoad(table, statusLabel, detailEditor);
            return page;
        }

        QWidget* buildStringsTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QHBoxLayout* searchBar = new QHBoxLayout();
            QLineEdit* query = new QLineEdit(page);
            query->setClearButtonEnabled(true);
            query->setPlaceholderText(ks::i18n::sourceText(QStringLiteral("查找字符串；留空扫描全部")));
            ks::ui::StyleSearchField(query);
            QCheckBox* regex = new QCheckBox(ks::i18n::sourceText(QStringLiteral("正则表达式")), page);
            QCheckBox* caseSensitive = new QCheckBox(ks::i18n::sourceText(QStringLiteral("区分大小写")), page);
            searchBar->addWidget(query, 1);
            searchBar->addWidget(regex);
            searchBar->addWidget(caseSensitive);
            ks::ui::NormalizeToolbarRow(searchBar);
            layout->addLayout(searchBar);
            QHBoxLayout* options = new QHBoxLayout();
            QComboBox* encoding = new QComboBox(page);
            ks::ui::StylePrimaryCombo(encoding);
            encoding->addItems({QStringLiteral("ASCII"), QStringLiteral("UTF-16LE"), QStringLiteral("ASCII + UTF-16LE")});
            QSpinBox* minimumLength = new QSpinBox(page);
            ks::ui::StyleStandaloneInput(minimumLength);
            minimumLength->setRange(4, 1024);
            minimumLength->setValue(4);
            options->addWidget(encoding);
            options->addWidget(new QLabel(ks::i18n::sourceText(QStringLiteral("最小长度")), page));
            options->addWidget(minimumLength);
            QPushButton* scan = new QPushButton(ks::i18n::sourceText(QStringLiteral("查找 / 扫描全文件")), page);
            QPushButton* cancel = new QPushButton(ks::i18n::sourceText(QStringLiteral("取消")), page);
            cancel->setEnabled(false);
            options->addWidget(scan);
            options->addWidget(cancel);
            options->addStretch();
            ks::ui::NormalizeToolbarRow(options);
            layout->addLayout(options);
            QLabel* status = new QLabel(page);
            status->setTextFormat(Qt::PlainText);
            status->setWordWrap(true);
            layout->addWidget(status);
            QTableView* table = createPropertyTable(page, {QStringLiteral("命中偏移"), QStringLiteral("编码"), QStringLiteral("字符串预览")}, QStringLiteral("file-detail-strings"));
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setWordWrap(false);
            table->setAlternatingRowColors(true);
            table->horizontalHeader()->setStretchLastSection(true);
            table->setMinimumSize(0, 0);
            layout->addWidget(table, 1);
            installValueTableCopyMenu(table);
            QLabel* hint = new QLabel(ks::i18n::sourceText(QStringLiteral(
                "搜索覆盖整个文件，仅显示匹配项。双击可在十六进制页定位；超长字符串分段展示，列表最多显示 20000 条。")), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            const auto control = std::make_shared<StringScanControl>();
            QObject::connect(page, &QObject::destroyed, [control]()
                {
                    if (control->cancel != nullptr) control->cancel->store(true);
                });
            connect(cancel, &QPushButton::clicked, page, [control]()
                {
                    if (control->cancel != nullptr) control->cancel->store(true);
                });
            const QString path = m_filePath;
            const QPointer<QWidget> pageGuard(page);
            const QPointer<QTableView> tableGuard(table);
            const QPointer<QLabel> statusGuard(status);
            const QPointer<QPushButton> cancelGuard(cancel);
            const auto launch = [query, regex, caseSensitive, encoding, minimumLength, control, path,
                pageGuard, tableGuard, statusGuard, cancelGuard]()
                {
                    if (control->cancel != nullptr) control->cancel->store(true);
                    const quint64 generation = ++control->generation;
                    propertyTableModel(tableGuard)->invalidateRequest();
                    if (regex->isChecked())
                    {
                        const QRegularExpression expression(query->text());
                        if (!expression.isValid())
                        {
                            const QString error = expression.errorString();
                            cancelGuard->setEnabled(false);
                            propertyTableModel(tableGuard)->setSnapshot(ks::fileui::makePropertyTableSnapshot(),
                                [tableGuard, statusGuard, generation, control, error]()
                                {
                                    if (tableGuard && statusGuard && generation == control->generation)
                                        statusGuard->setText(ks::i18n::sourceText(QStringLiteral("正则表达式无效：%1")).arg(error));
                                });
                            return;
                        }
                    }
                    control->cancel = std::make_shared<std::atomic_bool>(false);
                    const auto cancelRequested = control->cancel;
                    const QString queryText = query->text();
                    const bool useRegex = regex->isChecked(), sensitive = caseSensitive->isChecked();
                    const int minimum = minimumLength->value(), mode = encoding->currentIndex();
                    propertyTableModel(tableGuard)->invalidateRequest();
                    statusGuard->setText(ks::i18n::sourceText(QStringLiteral("正在扫描整个文件...")));
                    cancelGuard->setEnabled(true);
                    auto* task = QRunnable::create([path, queryText, useRegex, sensitive, minimum, mode,
                        cancelRequested, generation, control, pageGuard, tableGuard, statusGuard, cancelGuard]()
                        {
                            const auto progress = [generation, control, pageGuard, statusGuard](qint64 bytes, qint64 total)
                                {
                                    QMetaObject::invokeMethod(qApp, [generation, control, statusGuard, bytes, total]()
                                        {
                                            if (statusGuard != nullptr && generation == control->generation)
                                                statusGuard->setText(ks::i18n::sourceText(QStringLiteral("正在扫描：%1 / %2 字节"))
                                                    .arg(bytes).arg(total));
                                        }, Qt::QueuedConnection);
                                };
                            const auto result = extractPrintableStringsPreview(path, queryText, useRegex, sensitive,
                                minimum, mode != 1, mode != 0, cancelRequested, progress);
                            auto rows = ks::fileui::makePropertyTableSnapshot();
                            rows->rows.reserve(result.matches.size());
                            for (const auto& match : result.matches)
                                rows->append({ks::fileui::propertyRowKey({QString::number(match.offset), match.encoding}),
                                    {QStringLiteral("0x%1").arg(match.offset, 16, 16, QLatin1Char('0')), match.encoding, match.text},
                                    {{Qt::UserRole, match.offset}}});
                            const auto resultSnapshot = std::shared_ptr<PrintableStringsPreview>(new PrintableStringsPreview(result),
                                [](PrintableStringsPreview* value) { QThreadPool::globalInstance()->start(QRunnable::create([value]() { delete value; })); });
                            QMetaObject::invokeMethod(qApp, [resultSnapshot, rows, generation, control, tableGuard, statusGuard, cancelGuard]()
                                {
                                    if (tableGuard == nullptr || statusGuard == nullptr || cancelGuard == nullptr
                                        || generation != control->generation) return;
                                    propertyTableModel(tableGuard)->setSnapshot(rows, [resultSnapshot, generation, control, tableGuard, statusGuard, cancelGuard]()
                                    {
                                        if (!tableGuard || !statusGuard || !cancelGuard || generation != control->generation) return;
                                        cancelGuard->setEnabled(false);
                                    QString summary = ks::i18n::sourceText(QStringLiteral("已扫描 %1 / %2 字节；命中 %3 条，显示 %4 条。"))
                                        .arg(resultSnapshot->scannedBytes).arg(resultSnapshot->fileBytes).arg(resultSnapshot->matchedCount).arg(resultSnapshot->matches.size());
                                    if (resultSnapshot->cancelled) summary.prepend(ks::i18n::sourceText(QStringLiteral("已取消。")));
                                    if (!resultSnapshot->errorText.isEmpty()) summary += QLatin1Char('\n') + resultSnapshot->errorText;
                                    statusGuard->setText(summary);
                                    });
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                };
            connect(scan, &QPushButton::clicked, page, launch);
            connect(query, &QLineEdit::returnPressed, page, launch);
            connect(table, &QTableView::doubleClicked, this, [this, table](const QModelIndex& index)
                {
                    if (m_tabWidget == nullptr || !index.isValid()) return;
                    m_tabWidget->setProperty("ks_file_detail_hex_offset", propertyCell(table, index.row(), 0, Qt::UserRole));
                    m_tabWidget->setCurrentIndex(13);
                });
            launch();
            return page;
        }

        struct FileHexWindow
        {
            QByteArray bytes;
            qint64 baseOffset = 0;
            qint64 fileBytes = 0;
            QString sourceIdentity;
            QString errorText;
        };

        // 文件详情页负责分页读取，共用快照视图只消费当前完整文件范围。
        static FileHexWindow readHexFileWindow(const QString& path, const qint64 targetOffset,
            const qint64 requestedWindowBytes)
        {
            FileHexWindow result;
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                result.errorText = file.errorString();
                return result;
            }
            const QFileInfo originalInfo(file);
            result.fileBytes = file.size();
            const qint64 originalModified = originalInfo.lastModified().toMSecsSinceEpoch();
            const QString canonicalPath = originalInfo.canonicalFilePath();
            const int fileDescriptor = file.handle();
            const auto nativeHandleValue = fileDescriptor < 0 ? intptr_t{-1} : ::_get_osfhandle(fileDescriptor);
            const HANDLE nativeHandle = reinterpret_cast<HANDLE>(nativeHandleValue);
            BY_HANDLE_FILE_INFORMATION originalNativeInfo{};
            const bool nativeIdentityAvailable = nativeHandle != INVALID_HANDLE_VALUE
                && ::GetFileInformationByHandle(nativeHandle, &originalNativeInfo) != FALSE;
            const auto combineFileParts = [](const DWORD high, const DWORD low)
                { return (static_cast<quint64>(high) << 32U) | static_cast<quint64>(low); };
            if (nativeIdentityAvailable)
            {
                result.sourceIdentity = QStringLiteral("file-id:")
                    + QString::number(originalNativeInfo.dwVolumeSerialNumber, 16) + QLatin1Char(':')
                    + QString::number(combineFileParts(originalNativeInfo.nFileIndexHigh, originalNativeInfo.nFileIndexLow), 16)
                    + QLatin1Char(':') + QString::number(combineFileParts(originalNativeInfo.ftCreationTime.dwHighDateTime,
                        originalNativeInfo.ftCreationTime.dwLowDateTime), 16);
            }
            else if (originalInfo.birthTime().isValid())
            {
                result.sourceIdentity = QStringLiteral("file:")
                    + (canonicalPath.isEmpty() ? originalInfo.absoluteFilePath() : canonicalPath)
                    + QStringLiteral("|created:") + QString::number(originalInfo.birthTime().toMSecsSinceEpoch());
            }
            if (targetOffset < 0 || (result.fileBytes == 0 ? targetOffset != 0 : targetOffset >= result.fileBytes))
            {
                result.errorText = ks::i18n::sourceText(QStringLiteral("偏移超出文件范围：%1（文件大小 %2 字节）"))
                    .arg(targetOffset).arg(result.fileBytes);
                return result;
            }
            const qint64 windowBytes = std::clamp<qint64>(requestedWindowBytes, 4096, 2 * 1024 * 1024);
            result.baseOffset = (targetOffset / windowBytes) * windowBytes;
            if (!file.seek(result.baseOffset))
            {
                result.errorText = file.errorString();
                return result;
            }
            const qint64 expectedBytes = std::min(windowBytes, result.fileBytes - result.baseOffset);
            result.bytes = file.read(expectedBytes);
            if (file.error() != QFileDevice::NoError)
                result.errorText = file.errorString();
            else if (result.bytes.size() != expectedBytes
                || (result.fileBytes > 0 && targetOffset - result.baseOffset >= result.bytes.size()))
                result.errorText = ks::i18n::sourceText(QStringLiteral("读取范围不完整，文件可能已发生变化，请重试。"));
            else
            {
                const QFileInfo currentInfo(file);
                bool metadataChanged = file.size() != result.fileBytes || currentInfo.size() != result.fileBytes
                    || currentInfo.lastModified().toMSecsSinceEpoch() != originalModified;
                if (nativeIdentityAvailable)
                {
                    BY_HANDLE_FILE_INFORMATION currentNativeInfo{};
                    metadataChanged = metadataChanged || ::GetFileInformationByHandle(nativeHandle, &currentNativeInfo) == FALSE;
                    if (!metadataChanged)
                    {
                        metadataChanged = combineFileParts(currentNativeInfo.nFileSizeHigh, currentNativeInfo.nFileSizeLow)
                                != static_cast<quint64>(result.fileBytes)
                            || currentNativeInfo.ftLastWriteTime.dwHighDateTime != originalNativeInfo.ftLastWriteTime.dwHighDateTime
                            || currentNativeInfo.ftLastWriteTime.dwLowDateTime != originalNativeInfo.ftLastWriteTime.dwLowDateTime;
                    }
                }
                if (metadataChanged)
                    result.errorText = ks::i18n::sourceText(QStringLiteral("读取范围不完整，文件可能已发生变化，请重试。"));
            }
            return result;
        }

        QWidget* buildHexTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QHBoxLayout* jumpBar = new QHBoxLayout();
            QLineEdit* offsetEdit = new QLineEdit(page);
            ks::ui::StyleStandaloneInput(offsetEdit);
            offsetEdit->setPlaceholderText(ks::i18n::sourceText(QStringLiteral("文件偏移：0x 十六进制或十进制")));
            offsetEdit->setClearButtonEnabled(true);
            QPushButton* jump = new QPushButton(ks::i18n::sourceText(QStringLiteral("跳转到文件偏移")), page);
            QComboBox* windowSize = new QComboBox(page);
            ks::ui::StylePrimaryCombo(windowSize);
            windowSize->addItem(QStringLiteral("64 KiB"), 64 * 1024);
            windowSize->addItem(QStringLiteral("256 KiB"), 256 * 1024);
            windowSize->addItem(QStringLiteral("1 MiB"), 1024 * 1024);
            windowSize->addItem(QStringLiteral("2 MiB"), 2 * 1024 * 1024);
            jumpBar->addWidget(offsetEdit, 1);
            jumpBar->addWidget(jump);
            jumpBar->addWidget(windowSize);
            ks::ui::NormalizeToolbarRow(jumpBar);
            layout->addLayout(jumpBar);
            QHBoxLayout* navigation = new QHBoxLayout();
            QPushButton* first = new QPushButton(ks::i18n::sourceText(QStringLiteral("文件开头")), page);
            QPushButton* previous = new QPushButton(ks::i18n::sourceText(QStringLiteral("上一范围")), page);
            QPushButton* next = new QPushButton(ks::i18n::sourceText(QStringLiteral("下一范围")), page);
            QPushButton* last = new QPushButton(ks::i18n::sourceText(QStringLiteral("文件末尾")), page);
            QPushButton* find = new QPushButton(ks::i18n::sourceText(QStringLiteral("查找当前范围")), page);
            for (QPushButton* button : {first, previous, next, last, find}) navigation->addWidget(button);
            navigation->addStretch();
            layout->addLayout(navigation);
            ks::ui::NormalizeToolbarRow(navigation);
            QLabel* status = new QLabel(page);
            status->setTextFormat(Qt::PlainText);
            status->setWordWrap(true);
            layout->addWidget(status);
            auto* editor = new ks::ui::SnapshotWorkbenchWidget(page);
            editor->setAddressKind(ks::ui::SnapshotAddressKind::FileOffset);
            editor->setEditable(false);
            editor->hexEditor()->setBytesPerRow(16);
            layout->addWidget(editor, 1);
            QLabel* hint = new QLabel(ks::i18n::sourceText(QStringLiteral(
                "HEX、反汇编和文本共用当前文件范围。可按文件偏移加载任意范围；查找仅针对已加载的数据。反汇编地址为原始文件偏移，不进行 PE RVA / VA 映射。")), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            struct Control { quint64 generation = 0; qint64 requestedOffset = 0; qint64 total = 0; qint64 base = 0; qint64 loaded = 0; };
            const auto control = std::make_shared<Control>();
            const QString path = m_filePath;
            const QPointer<QWidget> pageGuard(page);
            const QPointer<ks::ui::SnapshotWorkbenchWidget> editorGuard(editor);
            const QPointer<QLabel> statusGuard(status);
            const QPointer<QPushButton> previousGuard(previous), nextGuard(next), lastGuard(last), findGuard(find);
            const auto launch = [path, control, pageGuard, editorGuard, statusGuard, previousGuard, nextGuard,
                lastGuard, findGuard, offsetEdit, windowSize](qint64 target)
                {
                    const quint64 generation = ++control->generation;
                    control->requestedOffset = target;
                    offsetEdit->setText(QStringLiteral("0x%1").arg(target, 0, 16));
                    const qint64 windowBytes = windowSize->currentData().toLongLong();
                    previousGuard->setEnabled(false);
                    nextGuard->setEnabled(false);
                    lastGuard->setEnabled(false);
                    findGuard->setEnabled(false);
                    statusGuard->setText(ks::i18n::sourceText(QStringLiteral("正在读取文件偏移 0x%1 附近的数据..."))
                        .arg(target, 0, 16));
                    auto* task = QRunnable::create([path, target, windowBytes, generation, control, pageGuard,
                        editorGuard, statusGuard, previousGuard, nextGuard, lastGuard, findGuard]()
                        {
                            const FileHexWindow result = readHexFileWindow(path, target, windowBytes);
                            // Queue through the application, then inspect page lifetime on
                            // the UI thread; the page can close while the worker reads.
                            QMetaObject::invokeMethod(qApp, [result, target, generation, control, pageGuard,
                                editorGuard, statusGuard, previousGuard, nextGuard, lastGuard, findGuard]()
                                {
                                    if (pageGuard == nullptr || editorGuard == nullptr || statusGuard == nullptr
                                        || generation != control->generation) return;
                                    if (!result.errorText.isEmpty())
                                    {
                                        control->total = result.fileBytes;
                                        control->base = control->loaded = 0;
                                        editorGuard->clear();
                                        if (editorGuard == nullptr || statusGuard == nullptr || generation != control->generation) return;
                                        statusGuard->setText(ks::i18n::sourceText(QStringLiteral("未跳转：%1"))
                                            .arg(result.errorText));
                                    }
                                    else
                                    {
                                        control->total = result.fileBytes;
                                        control->base = result.baseOffset;
                                        control->loaded = result.bytes.size();
                                        // 基址和解码锚点均为文件偏移，绝不附带进程地址上下文。
                                        editorGuard->setSnapshot(result.bytes, static_cast<std::uint64_t>(result.baseOffset),
                                            editorGuard->currentArchitecture(), static_cast<std::uint64_t>(target), result.sourceIdentity);
                                        if (editorGuard == nullptr || statusGuard == nullptr || generation != control->generation) return;
                                        statusGuard->setText(result.bytes.isEmpty()
                                            ? ks::i18n::sourceText(QStringLiteral("文件为空。"))
                                            : ks::i18n::sourceText(QStringLiteral("文件范围 [0x%1, 0x%2)；已加载 %3 字节，文件共 %4 字节。"))
                                                .arg(result.baseOffset, 0, 16).arg(result.baseOffset + result.bytes.size(), 0, 16)
                                                .arg(result.bytes.size()).arg(result.fileBytes));
                                    }
                                    previousGuard->setEnabled(control->base > 0);
                                    nextGuard->setEnabled(control->loaded > 0 && control->base + control->loaded < control->total);
                                    lastGuard->setEnabled(control->total > 0);
                                    findGuard->setEnabled(control->loaded > 0);
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                };
            const auto jumpFromInput = [offsetEdit, statusGuard, launch, control,
                previousGuard, nextGuard, lastGuard, findGuard]()
                {
                    QString text = offsetEdit->text().trimmed();
                    const bool hex = text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive);
                    if (hex) text.remove(0, 2);
                    bool ok = false;
                    const qulonglong value = text.toULongLong(&ok, hex ? 16 : 10);
                    if (!ok || value > static_cast<qulonglong>(std::numeric_limits<qint64>::max()))
                    {
                        ++control->generation;
                        previousGuard->setEnabled(control->base > 0);
                        nextGuard->setEnabled(control->loaded > 0 && control->base + control->loaded < control->total);
                        lastGuard->setEnabled(control->total > 0);
                        findGuard->setEnabled(control->loaded > 0);
                        statusGuard->setText(ks::i18n::sourceText(QStringLiteral("请输入有效文件偏移：十进制，或以 0x 开头的十六进制。")));
                        return;
                    }
                    launch(static_cast<qint64>(value));
                };
            connect(jump, &QPushButton::clicked, page, jumpFromInput);
            connect(offsetEdit, &QLineEdit::returnPressed, page, jumpFromInput);
            connect(first, &QPushButton::clicked, page, [launch]() { launch(0); });
            connect(previous, &QPushButton::clicked, page, [control, windowSize, launch]()
                { launch(std::max<qint64>(0, control->base - windowSize->currentData().toLongLong())); });
            connect(next, &QPushButton::clicked, page, [control, launch]() { launch(control->base + control->loaded); });
            connect(last, &QPushButton::clicked, page, [control, launch]() { launch(std::max<qint64>(0, control->total - 1)); });
            connect(find, &QPushButton::clicked, editor, &ks::ui::SnapshotWorkbenchWidget::openFindPanel);
            connect(windowSize, &QComboBox::currentIndexChanged, page, [control, launch](int) { launch(control->requestedOffset); });
            const QPointer<QTabWidget> tabs(m_tabWidget);
            const auto takePending = [tabs, launch]()
                {
                    if (tabs == nullptr) return false;
                    const QVariant pending = tabs->property("ks_file_detail_hex_offset");
                    if (!pending.isValid()) return false;
                    tabs->setProperty("ks_file_detail_hex_offset", QVariant());
                    launch(pending.toLongLong());
                    return true;
                };
            if (tabs != nullptr)
                connect(tabs, &QTabWidget::currentChanged, page, [takePending](int index)
                    { if (index == 13) takePending(); });
            if (!takePending()) launch(0);
            return page;
        }

    private:
        QStringList m_filePaths; // 当前详情窗口对应的全部目标；单文件模式仅一项。
        QString m_filePath;   // 单文件目标或批量模式第一项，供现有只读分析页复用。
        bool m_batchMode = false; // 多目标时只开放常规汇总、批量哈希与元数据编辑。
        QString m_initialTabKey; // 外部入口指定的初始页；usage 入口会自动扫描。
        QWidget* m_tabNavigation = nullptr; // 文件属性左侧导航容器。
        QTabWidget* m_tabWidget = nullptr; // 继续承载现有的页面与懒加载机制。
        QButtonGroup* m_tabNavigationButtonGroup = nullptr; // 保证左侧导航单选。
        QVector<QToolButton*> m_tabNavigationButtons; // 与 Tab 索引一一对应，供切页时同步选中态。
        ks::ui::StructuredFieldView* m_generalPropertyView = nullptr; // 直接呈现字段快照，不依赖文本编辑器。
        std::function<void()> m_signatureLanguageRefresh; // UI 快照重译不重新验证文件。
        QTableView* m_generalBatchTable = nullptr;
        QLabel* m_generalBatchSummary = nullptr;
        FileDetailRowsModel* m_generalBatchRowsModel = nullptr;
        ks::ui::FieldDocument m_generalR3Document; // R0/语言更新复用同一版R3快照，不重新stat。
        bool m_generalR3Loaded = false;
        quint64 m_generalR3LoadGeneration = 0;
        std::shared_ptr<std::atomic_bool> m_generalReadCancel; // 关闭后不继续遍历批量常规目标。
        QString m_generalNtPathText; // 常规页复用的 NT 路径，避免切换语言时重复查询。
        bool m_generalR0Loaded = false; // R0 文件信息是否已完成后台读取。
        ksword::ark::FileInfoQueryResult m_generalR0Info{}; // 保留原始 R0 数据供双语重绘。
        std::uint64_t m_generalR0LoadGeneration = 0U; // 淘汰元数据写入前发起的旧 R0 查询。
        std::uint64_t m_securityLoadGeneration = 0U; // 权限刷新不能被较早请求或菜单延迟提交覆盖。
        std::array<QCheckBox*, 4> m_metadataTimeChecks{}; // 四个时间字段的逐项写入开关。
        std::array<QDateTimeEdit*, 4> m_metadataTimeEdits{}; // 四个本地时间编辑器。
        std::array<QCheckBox*, 6> m_metadataAttributeChecks{}; // 六个可直接切换的属性位。
        std::array<bool, 6> m_metadataAttributeTouched{}; // 批量混合状态下只写入用户实际切换的属性。
        bool m_metadataApplyingSnapshot = false; // 回填混合状态时不把程序赋值误判为用户修改。
        QPushButton* m_metadataRefreshButton = nullptr; // 重新读取最新 FileBasicInfo。
        QPushButton* m_metadataApplyButton = nullptr; // 把基础元数据改动加入统一暂存事务。
        QLabel* m_metadataStatusLabel = nullptr; // 读取、写入与回读验证状态。
        FileMetadataSnapshot m_metadataSnapshot{}; // 编辑器当前展示的属性快照。
        bool m_metadataHasSnapshot = false; // 防止读取失败后使用未初始化值写入。
        bool m_metadataEditorBusy = false; // 防止重复读取或重复应用。
        std::uint64_t m_metadataOperationGeneration = 0U; // 淘汰关闭/刷新后迟到的后台结果。
        QList<ks::file::metadata::TargetPatch> m_pendingPatches; // 各目标的统一 R3 暂存补丁。
        QCheckBox* m_backupBeforeSaveCheck = nullptr; // 保存前复制目标或生成目录元数据清单。
        QLabel* m_pendingChangesLabel = nullptr; // 底部统一保存栏的待处理摘要。
        QPushButton* m_discardPendingButton = nullptr; // 放弃全部未写入补丁。
        QPushButton* m_saveAllButton = nullptr; // 唯一会触发文件写入的入口。
        QHash<QObject*, QPointer<MetadataReadState>> m_metadataReadStates;
        bool m_stagingSnapshotBusy = false;
        std::shared_ptr<std::atomic_bool> m_stagingSnapshotCancel;
        bool m_transactionBusy = false; // 保存事务运行期间锁定编辑和重复提交。
        std::shared_ptr<std::atomic_bool> m_savePreflightCancel; // 只读签名预检可以取消，不中断已确认的写事务。
        quint64 m_savePreflightGeneration = 0; // 取消/重试后旧签名计划不能进入确认或写入。
        std::shared_ptr<std::atomic_bool> m_hashCancelRequested; // 哈希计算取消标记，后台线程共享。
        std::shared_ptr<std::atomic_bool> m_peReadCancel;
        std::shared_ptr<std::atomic_bool> m_dependencyReadCancel;
        std::shared_ptr<std::atomic_bool> m_usageScanCancelRequested; // 文件占用扫描取消标记，关闭属性窗时置位。
        QProgressBar* m_usageScanProgressBar = nullptr; // 属性页文件占用扫描的阶段进度条。
        bool m_usageScanInProgress = false; // 属性页占用扫描是否仍在后台执行。
        bool m_usageCloseInProgress = false; // R0 关闭期间禁止重入动作和覆盖所选快照。
        bool m_usageRetryAfterR0Start = false; // R3 回落结果是否等待下一次 R0 启动成功后重扫。
        bool m_usageR0StartedDuringScan = false; // R0 是否在当前 R3 回落扫描完成前已经启动。
        bool m_themeStyleApplying = false; // 避免 PaletteChange 触发样式重入。
    };

    // Pure stream accumulator: no QWidget/model/document or filesystem ownership.
    struct FileAnalysisValues
    {
        QCryptographicHash md5{ QCryptographicHash::Md5 };
        QCryptographicHash sha1{ QCryptographicHash::Sha1 };
        QCryptographicHash sha256{ QCryptographicHash::Sha256 };
        std::array<std::uint64_t, 256> buckets{};
        std::uint64_t bytes = 0;

        void consume(const QByteArray& chunk, const bool hash)
        {
            if (hash)
            {
                md5.addData(chunk); sha1.addData(chunk); sha256.addData(chunk);
            }
            else
            {
                for (const unsigned char byte : chunk) ++buckets[byte];
            }
            bytes += static_cast<std::uint64_t>(chunk.size());
        }

        double entropy() const
        {
            double result = 0.0;
            if (bytes == 0) return result;
            for (const auto count : buckets)
            {
                if (count == 0) continue;
                const double probability = static_cast<double>(count) / static_cast<double>(bytes);
                result -= probability * std::log2(probability);
            }
            return result;
        }
    };

    enum class FileAnalysisReadState { Complete, Canceled, Failed };

    template<class Read, class Cancel, class Progress>
    FileAnalysisReadState readFileAnalysisValues(FileAnalysisValues& values, const bool hash,
        Read read, Cancel canceled, Progress progress)
    {
        QByteArray chunk(256 * 1024, Qt::Uninitialized);
        while (!canceled())
        {
            const qint64 bytes = read(chunk.data(), 256 * 1024);
            if (bytes < 0) return FileAnalysisReadState::Failed;
            if (bytes == 0) return canceled() ? FileAnalysisReadState::Canceled : FileAnalysisReadState::Complete;
            chunk.resize(bytes);
            values.consume(chunk, hash);
            chunk.resize(256 * 1024);
            progress(values.bytes);
        }
        return FileAnalysisReadState::Canceled;
    }

    struct FileAnalysisProgress
    {
        std::atomic_bool cancel{ false };
        std::atomic<int> percent{ 0 };
    };

    struct FileAnalysisRequest
    {
        std::vector<QString> paths;
        QString panelName;
        bool hash = true;
        std::shared_ptr<FileAnalysisProgress> progress;
    };

    struct FileAnalysisResult
    {
        int successes = 0;
        int failures = 0;
        bool canceled = false;
    };

    bool sameFileAnalysisIdentity(const BY_HANDLE_FILE_INFORMATION& before,
        const BY_HANDLE_FILE_INFORMATION& after)
    {
        return before.dwVolumeSerialNumber == after.dwVolumeSerialNumber
            && before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow
            && before.nFileSizeHigh == after.nFileSizeHigh && before.nFileSizeLow == after.nFileSizeLow
            && ::CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0;
    }

    // Only value requests/tokens cross the worker boundary. Complete results go to the
    // thread-safe log directly; a large selection cannot become a GUI logging loop.
    FileAnalysisResult analyzeMenuFiles(const FileAnalysisRequest& request,
        const ks::ui::AsyncOperationToken& token)
    {
        FileAnalysisResult result;
        const auto canceled = [&]() { return token.isCanceled() || request.progress->cancel.load(); };
        kLogEvent event;
        for (std::size_t index = 0; index < request.paths.size(); ++index)
        {
            if (canceled()) { result.canceled = true; break; }
            const QString& path = request.paths[index];
            if (!QFileInfo(path).isFile()) continue; // Preserve directory skipping.
            HANDLE handle = ::CreateFileW(path.toStdWString().c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            DWORD failure = handle == INVALID_HANDLE_VALUE ? ::GetLastError() : ERROR_SUCCESS;
            BY_HANDLE_FILE_INFORMATION before{};
            if (failure == ERROR_SUCCESS && !::GetFileInformationByHandle(handle, &before)) failure = ::GetLastError();
            FileAnalysisValues values;
            const auto size = (static_cast<std::uint64_t>(before.nFileSizeHigh) << 32) | before.nFileSizeLow;
            if (failure == ERROR_SUCCESS)
            {
                readFileAnalysisValues(values, request.hash,
                    [handle, &failure](char* buffer, const DWORD capacity) -> qint64
                    {
                        DWORD bytes = 0;
                        if (!::ReadFile(handle, buffer, capacity, &bytes, nullptr))
                        { failure = ::GetLastError(); return -1; }
                        return bytes;
                    }, canceled, [&request, index, size](const std::uint64_t bytes)
                    {
                        const double fraction = size == 0 ? 1.0 : std::min(1.0, static_cast<double>(bytes) / size);
                        request.progress->percent.store(static_cast<int>(99.0 * (index + fraction) / request.paths.size()));
                    });
            }
            BY_HANDLE_FILE_INFORMATION after{};
            if (failure == ERROR_SUCCESS && !canceled())
            {
                if (!::GetFileInformationByHandle(handle, &after)) failure = ::GetLastError();
                else if (values.bytes != size || !sameFileAnalysisIdentity(before, after)) failure = ERROR_FILE_INVALID;
                // The completed handle must still identify the selected pathname.
                HANDLE current = ::CreateFileW(path.toStdWString().c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
                BY_HANDLE_FILE_INFORMATION currentInfo{};
                if (failure == ERROR_SUCCESS && current == INVALID_HANDLE_VALUE) failure = ::GetLastError();
                if (failure == ERROR_SUCCESS && !::GetFileInformationByHandle(current, &currentInfo)) failure = ::GetLastError();
                if (failure == ERROR_SUCCESS && !sameFileAnalysisIdentity(before, currentInfo)) failure = ERROR_FILE_INVALID;
                closeWin32Handle(current);
            }
            closeWin32Handle(handle);
            if (canceled()) { result.canceled = true; break; }
            if (failure != ERROR_SUCCESS)
            {
                ++result.failures;
                warn << event << "[FileDock] file analysis failed, filePath=" << QDir::toNativeSeparators(path).toStdString()
                    << ", error=" << formatWin32ErrorText(failure).toStdString() << eol;
                continue;
            }
            ++result.successes;
            if (request.hash)
            {
                info << event << "[FileDock] 哈希计算结果, filePath=" << QDir::toNativeSeparators(path).toStdString()
                    << ", md5=" << QString::fromLatin1(values.md5.result().toHex()).toStdString()
                    << ", sha1=" << QString::fromLatin1(values.sha1.result().toHex()).toStdString()
                    << ", sha256=" << QString::fromLatin1(values.sha256.result().toHex()).toStdString() << eol;
            }
            else
            {
                info << event << "[FileDock] 熵值计算结果, filePath=" << QDir::toNativeSeparators(path).toStdString()
                    << ", entropy=" << QString::number(values.entropy(), 'f', 4).toStdString() << eol;
            }
        }
        info << event << (request.hash ? "[FileDock] 哈希计算完成, panel=" : "[FileDock] 熵值计算完成, panel=")
            << request.panelName.toStdString() << ", successCount=" << result.successes
            << ", failCount=" << result.failures << ", canceled=" << result.canceled << eol;
        return result;
    }

    // Keep entry/event/OVERLAPPED alive until the actual wait thread ends.
    // No GUI wait, detached waiter or worker-held pointer is destroyed early.
    template<class Entry, class Complete>
    void retireFileOplockEntries(std::vector<std::shared_ptr<Entry>> entries, Complete complete)
    {
        std::thread([entries = std::move(entries), complete = std::move(complete)]() mutable
        {
            for (const auto& entry : entries)
                if (entry && entry->waitThread.joinable()) entry->waitThread.join();
            complete(entries);
        }).detach();
    }

    struct FileMutationRequest
    {
        int kind = 0; // 0 file, 1 directory, 2 rename, 3 integrity.
        std::vector<QString> paths;
        QString destination;
        QString panelName;
        DWORD integrityRid = 0;
        std::shared_ptr<FileAnalysisProgress> progress;
        int progressPid = 0;
    };

    struct FileMutationResult
    {
        std::size_t successCount = 0;
        std::size_t failureCount = 0;
        DWORD privilegeError = ERROR_SUCCESS;
        QString failures;
        bool canceled = false;
    };

    template<class Apply, class Canceled, class Progress>
    FileMutationResult runFileMutationBatch(const std::vector<QString>& paths,
        Apply apply, Canceled canceled, Progress progress)
    {
        FileMutationResult result;
        QStringList failures;
        for (std::size_t index = 0; index < paths.size(); ++index)
        {
            if (canceled()) { result.canceled = true; break; }
            QString detail;
            const DWORD code = apply(paths[index], detail);
            if (code == ERROR_SUCCESS) ++result.successCount;
            else
            {
                ++result.failureCount;
                failures.push_back(QStringLiteral("%1 | code=%2 | %3")
                    .arg(QDir::toNativeSeparators(paths[index])).arg(code).arg(detail));
                if (result.privilegeError == ERROR_SUCCESS && ks::ui::isPrivilegeRequiredError(code))
                    result.privilegeError = code;
            }
            // Cancellation is checked only before the next transaction, never
            // while an already-entered mutation still owns its completion work.
            progress(index + 1, paths.size());
        }
        result.failures = failures.join(QLatin1Char('\n'));
        return result;
    }

    FileMutationResult runFileMutation(const FileMutationRequest& request)
    {
        QElapsedTimer progressTimer;
        progressTimer.start();
        FileMutationResult result = runFileMutationBatch(request.paths,
            [&request](const QString& path, QString& detail) -> DWORD
            {
                DWORD code = ERROR_SUCCESS;
                if (request.kind == 3)
                    code = setFileIntegrityLevelByR0ThenR3(path, request.integrityRid, &detail);
                else if (request.kind == 2)
                {
                    const QFileInfo old(path);
                    const bool ok = old.isDir()
                        ? QDir(old.absolutePath()).rename(old.fileName(), request.destination)
                        : QFile::rename(path, request.destination);
                    if (!ok) code = ERROR_GEN_FAILURE;
                }
                else if (request.kind == 1)
                {
                    if (!QDir().mkpath(request.destination)) code = ERROR_GEN_FAILURE;
                }
                else
                {
                    QFile file(request.destination);
                    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
                    { code = ERROR_GEN_FAILURE; detail = file.errorString(); }
                    file.close();
                }
                kLogEvent event;
                if (code == ERROR_SUCCESS)
                    info << event << "[FileDock] file mutation completed, kind=" << request.kind
                        << ", panel=" << request.panelName.toStdString() << ", path=" << path.toStdString()
                        << ", destination=" << request.destination.toStdString() << ", rid=" << request.integrityRid
                        << ", detail=" << detail.toStdString() << eol;
                else
                    warn << event << "[FileDock] file mutation failed, kind=" << request.kind
                        << ", path=" << path.toStdString() << ", code=" << code << ", detail=" << detail.toStdString() << eol;
                return code;
            },
            [&request]() { return request.progress->cancel.load(); },
            [&request, &progressTimer](std::size_t completed, std::size_t total)
            {
                const int percent = static_cast<int>(95.0 * completed / total);
                request.progress->percent.store(percent);
                if (completed == total || progressTimer.elapsed() >= 100)
                {
                    progressTimer.restart();
                    kPro.set(request.progressPid, "处理中", 0, static_cast<float>(std::max(2, percent)));
                }
            });
        // Accepted writes finish independently of the page. Only an explicit
        // progress-dialog cancel stops the next transaction boundary.
        kPro.finish(request.progressPid,
            result.canceled ? kProgressState::Canceled
                : (result.failureCount == 0 ? kProgressState::Success : kProgressState::Failure),
            result.canceled ? "用户取消" : (result.failureCount == 0 ? "完成" : "失败"));
        return result;
    }

    struct FileNavigationRequest
    {
        QString path;
        QString previous;
    };

    struct FileNavigationResult
    {
        QString path;
        QString parentOfPrevious;
        bool exists = false;
    };

    FileNavigationResult probeFileNavigation(const FileNavigationRequest& request,
        const ks::ui::AsyncOperationToken& token)
    {
        FileNavigationResult result;
        if (token.isCanceled()) return result;
        QDir directory(request.path);
        result.path = QDir::cleanPath(directory.absolutePath());
        result.exists = directory.exists();
        if (!token.isCanceled() && !request.previous.isEmpty())
        {
            QDir previous(request.previous);
            if (previous.cdUp()) result.parentOfPrevious = previous.absolutePath();
        }
        return result;
    }

    struct FileMenuMetadata
    {
        bool integrityKnown = false;
        DWORD integrityRid = 0;
        bool implicitMedium = false;
        QString integrityDetail;
        QStringList links;
        QString locatePath;
        ks::process::RunAsAvailability runAs;
    };

    struct FileMenuMetadataRequest
    {
        std::vector<QString> paths;
        bool executable = false;
    };

    FileMenuMetadata queryFileMenuMetadata(const FileMenuMetadataRequest& request,
        const ks::ui::AsyncOperationToken& token)
    {
        FileMenuMetadata result;
        if (request.paths.empty() || token.isCanceled()) return result;
        result.integrityKnown = queryFileIntegrityRid(request.paths.front(), &result.integrityRid,
            &result.implicitMedium, &result.integrityDetail);
        QSet<QString> linkKeys;
        for (const QString& path : request.paths)
        {
            if (token.isCanceled()) return result;
            if (!isPathReparsePoint(path)) continue;
            const auto reparse = queryReparsePointForUi(path);
            const QString target = reparseTargetFromResult(reparse).trimmed();
            const QString key = target.toCaseFolded();
            if (!target.isEmpty() && !linkKeys.contains(key))
            { linkKeys.insert(key); result.links.push_back(target); }
        }
        if (!token.isCanceled() && request.paths.size() == 1 && !result.links.isEmpty())
        {
            const QFileInfo target(result.links.front());
            result.locatePath = target.isDir() ? target.absoluteFilePath() : target.absolutePath();
            if (!QDir(result.locatePath).exists()) result.locatePath.clear();
        }
        if (!token.isCanceled() && request.executable) result.runAs = ks::process::QueryRunAsAvailability();
        return result;
    }

    struct FileShortNameResult
    {
        QString text;
        int hits = 0;
        int fallbacks = 0;
        bool canceled = false;
    };

    template<class Query, class Canceled>
    FileShortNameResult queryFileShortNames(const std::vector<QString>& paths, Query query, Canceled canceled)
    {
        FileShortNameResult result;
        QStringList lines;
        lines.reserve(static_cast<qsizetype>(paths.size()));
        for (const QString& path : paths)
        {
            if (canceled()) { result.canceled = true; return result; }
            const QString shortPath = query(path);
            QString name;
            if (!shortPath.isEmpty())
            {
                name = QFileInfo(shortPath).fileName().trimmed();
                if (name.isEmpty()) name = QDir::toNativeSeparators(shortPath);
                ++result.hits;
            }
            else
            {
                name = QFileInfo(path).fileName().trimmed();
                if (name.isEmpty()) name = QDir::toNativeSeparators(path);
                ++result.fallbacks;
            }
            lines.push_back(name);
        }
        result.text = lines.join(QLatin1Char('\n'));
        return result;
    }

    // kRecoveryVolumeProbeGenerationProperty 作用：
    // - 用途：记录“这是第几次卷探测请求”，以动态属性挂在恢复页的卷下拉框上；
    // - 入参：无（作为 QObject::property/setProperty 的键使用）；
    // - 返回：无。之所以不放进 FileDock 成员，是为了在不改动 FileDock.h 的前提下
    //   仍然具备“淘汰被新请求取代的旧结果”的能力。
    constexpr const char* const kRecoveryVolumeProbeGenerationProperty =
        "ks_recovery_volume_probe_generation";

    // kFileDeleteInProgressProperty 作用：
    // - 用途：标记“删除任务正在后台执行”，以动态属性挂在 FileDock 上；
    // - 入参：无（作为 QObject::property/setProperty 的键使用）；
    // - 返回：无。语义与 m_transferInProgress 一致，同样只用于防重入。
    constexpr const char* const kFileDeleteInProgressProperty = "ks_file_delete_in_progress";

    // collectNtfsVolumeRootList 作用：
    // - 用途：枚举当前可用于误删扫描的 NTFS 卷根，必须在后台线程调用；
    // - 入参：无；内部自行枚举逻辑盘；
    // - 返回：NTFS 卷根路径列表（原生分隔符，例如 C:\）。
    // 说明：GetVolumeInformationW 在空光驱上会等待介质就绪、在断线的映射网络盘上会等待
    // SMB 会话超时，所以先用 GetDriveTypeW 把光驱、网络映射和无根设备挡掉；同时用
    // SetThreadErrorMode 关闭本线程的“请插入磁盘”系统弹窗，避免后台探测把模态框弹到用户脸上。
    QVector<QString> collectNtfsVolumeRootList()
    {
        QVector<QString> ntfsVolumeRootList;

        DWORD previousThreadErrorMode = 0;
        const bool threadErrorModeChanged =
            ::SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previousThreadErrorMode) != FALSE;

        const QFileInfoList driveInfoList = QDir::drives();
        for (const QFileInfo& driveInfo : driveInfoList)
        {
            const QString volumeRootPath = QDir::toNativeSeparators(driveInfo.absoluteFilePath());
            const UINT driveTypeValue = ::GetDriveTypeW(volumeRootPath.toStdWString().c_str());
            if (driveTypeValue == DRIVE_CDROM
                || driveTypeValue == DRIVE_REMOTE
                || driveTypeValue == DRIVE_NO_ROOT_DIR
                || driveTypeValue == DRIVE_UNKNOWN)
            {
                // 这几类要么必然不是可做误删扫描的本地卷，要么正是把 GetVolumeInformationW
                // 拖到数秒甚至数十秒的元凶，直接跳过，不做后续探测。
                continue;
            }

            const ks::file::ManualFsType fileSystemType =
                ks::file::ManualFileSystemParser::detectFileSystemType(volumeRootPath);
            if (fileSystemType != ks::file::ManualFsType::Ntfs)
            {
                continue;
            }

            ntfsVolumeRootList.push_back(volumeRootPath);
        }

        if (threadErrorModeChanged)
        {
            ::SetThreadErrorMode(previousThreadErrorMode, nullptr);
        }
        return ntfsVolumeRootList;
    }
}

struct FileDock::FileOplockAccessRecord
{
    std::uint32_t processId = 0U;
    QString processName;
    QString processImagePath;
    std::uint64_t hitCount = 0U;
    std::uint64_t handleHitCount = 0U;
    std::uint64_t firstBreakSequence = 0U;
    std::uint64_t lastBreakSequence = 0U;
    std::uint64_t lastHandleValue = 0U;
    std::uint32_t lastGrantedAccess = 0U;
    QString firstSeenText;
    QString lastSeenText;
    QStringList matchedTargetList;
    QStringList matchRuleList;
    QStringList enumerationSourceList;
    QStringList objectNameList;
};

struct FileDock::FileOplockEntry
{
    // Declared first so the lease is the last member destroyed: native handles,
    // joined waiter and complete attribution values retire before exit admission.
    std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> cleanupLease;
    QString path;
    FileOplockLevel level = FileOplockLevel::Level1;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HANDLE eventHandle = nullptr;
    OVERLAPPED overlapped{};
    bool ioPending = false;
    std::thread waitThread;
    std::mutex ioMutex;
    std::mutex accessRecordMutex;
    std::vector<FileOplockAccessRecord> accessRecords;
    QString lastAccessScanDiagnostic;
    std::uint64_t uncapturedBreakCount = 0U;
    std::atomic_bool releaseRequested{ false };
    std::atomic_bool rearmWarningReported{ false };
    std::atomic<std::uint64_t> breakCount{ 0 };

    ~FileOplockEntry()
    {
        closeWin32Handle(fileHandle);
        closeWin32Handle(eventHandle);
    }
};

QString FileDock::fileOplockLevelText(const FileOplockLevel level)
{
    switch (level)
    {
    case FileOplockLevel::Level1:
        return QStringLiteral("Level 1");
    case FileOplockLevel::Level2:
        return QStringLiteral("Level 2");
    case FileOplockLevel::Batch:
        return QStringLiteral("Batch");
    case FileOplockLevel::Filter:
        return QStringLiteral("Filter");
    }
    return QStringLiteral("Level 1");
}

unsigned long FileDock::fileOplockControlCode(const FileOplockLevel level)
{
    switch (level)
    {
    case FileOplockLevel::Level1:
        return FSCTL_REQUEST_OPLOCK_LEVEL_1;
    case FileOplockLevel::Level2:
        return FSCTL_REQUEST_OPLOCK_LEVEL_2;
    case FileOplockLevel::Batch:
        return FSCTL_REQUEST_BATCH_OPLOCK;
    case FileOplockLevel::Filter:
        return FSCTL_REQUEST_FILTER_OPLOCK;
    }
    return FSCTL_REQUEST_OPLOCK_LEVEL_1;
}

bool FileDock::requestFileOplock(FileOplockEntry& entry, unsigned long& requestError)
{
    requestError = ERROR_SUCCESS;
    if (entry.releaseRequested.load())
    {
        requestError = ERROR_OPERATION_ABORTED;
        return false;
    }

    std::lock_guard<std::mutex> lock(entry.ioMutex);
    if (entry.releaseRequested.load())
    {
        requestError = ERROR_OPERATION_ABORTED;
        return false;
    }
    if (entry.fileHandle == nullptr ||
        entry.fileHandle == INVALID_HANDLE_VALUE ||
        entry.eventHandle == nullptr)
    {
        requestError = ERROR_INVALID_HANDLE;
        return false;
    }

    (void)::ResetEvent(entry.eventHandle);
    entry.overlapped = OVERLAPPED{};
    entry.overlapped.hEvent = entry.eventHandle;

    const BOOL requestOk = ::DeviceIoControl(
        entry.fileHandle,
        static_cast<DWORD>(fileOplockControlCode(entry.level)),
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &entry.overlapped);
    requestError = requestOk ? ERROR_SUCCESS : ::GetLastError();
    entry.ioPending = requestOk == FALSE && requestError == ERROR_IO_PENDING;
    if (requestOk != FALSE)
    {
        return false;
    }
    if (requestError == ERROR_IO_PENDING)
    {
        entry.rearmWarningReported.store(false);
        return true;
    }

    return false;
}

bool FileDock::acknowledgeFileOplockBreak(FileOplockEntry& entry, unsigned long& acknowledgeError)
{
    acknowledgeError = ERROR_SUCCESS;
    if (entry.level == FileOplockLevel::Level2 || entry.releaseRequested.load())
    {
        return true;
    }
    if (entry.fileHandle == nullptr || entry.fileHandle == INVALID_HANDLE_VALUE)
    {
        acknowledgeError = ERROR_INVALID_HANDLE;
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL acknowledgeOk = FALSE;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(entry.ioMutex);
        if (entry.releaseRequested.load())
        {
            acknowledgeError = ERROR_OPERATION_ABORTED;
            return false;
        }
        if (entry.fileHandle == nullptr ||
            entry.fileHandle == INVALID_HANDLE_VALUE ||
            entry.eventHandle == nullptr)
        {
            acknowledgeError = ERROR_INVALID_HANDLE;
            return false;
        }

        fileHandle = entry.fileHandle;
        (void)::ResetEvent(entry.eventHandle);
        entry.overlapped = OVERLAPPED{};
        entry.overlapped.hEvent = entry.eventHandle;
        acknowledgeOk = ::DeviceIoControl(
            fileHandle,
            FSCTL_OPLOCK_BREAK_ACK_NO_2,
            nullptr,
            0,
            nullptr,
            0,
            &bytesReturned,
            &entry.overlapped);
        acknowledgeError = acknowledgeOk ? ERROR_SUCCESS : ::GetLastError();
        entry.ioPending = acknowledgeOk == FALSE && acknowledgeError == ERROR_IO_PENDING;
    }

    if (!acknowledgeOk && acknowledgeError == ERROR_IO_PENDING)
    {
        acknowledgeOk = ::GetOverlappedResult(
            fileHandle,
            &entry.overlapped,
            &bytesReturned,
            TRUE);
        acknowledgeError = acknowledgeOk ? ERROR_SUCCESS : ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(entry.ioMutex);
            entry.ioPending = false;
        }
    }

    return acknowledgeOk != FALSE;
}

void FileDock::cancelFileOplockRequest(FileOplockEntry& entry)
{
    std::lock_guard<std::mutex> lock(entry.ioMutex);
    if (entry.fileHandle != nullptr && entry.fileHandle != INVALID_HANDLE_VALUE)
    {
        if (entry.ioPending)
        {
            (void)::CancelIoEx(entry.fileHandle, &entry.overlapped);
        }
    }
    if (!entry.ioPending && entry.eventHandle != nullptr)
    {
        (void)::SetEvent(entry.eventHandle);
    }
}

std::size_t FileDock::recordFileOplockAccessPrograms(
    FileOplockEntry& entry,
    const std::uint64_t breakSequence)
{
    if (entry.path.trimmed().isEmpty() || entry.releaseRequested.load())
    {
        return 0U;
    }

    const std::vector<QString> scanTargets{ entry.path };
    const filedock::handleusage::HandleUsageScanResult scanResult =
        filedock::handleusage::scanHandleUsageByPaths(scanTargets, 0, true,
            [&entry]() { return entry.releaseRequested.load(); });

    const std::uint32_t currentProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
    const QString nowText = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    std::map<std::uint32_t, FileOplockAccessRecord> scanRecordByPid;
    for (const filedock::handleusage::HandleUsageEntry& scanEntry : scanResult.entries)
    {
        if (scanEntry.processId == 0U ||
            scanEntry.processId <= 4U ||
            scanEntry.processId == currentProcessId)
        {
            continue;
        }

        FileOplockAccessRecord& scanRecord = scanRecordByPid[scanEntry.processId];
        if (scanRecord.processId == 0U)
        {
            scanRecord.processId = scanEntry.processId;
            scanRecord.processName = scanEntry.processName.trimmed();
            scanRecord.processImagePath = scanEntry.processImagePath.trimmed();
            scanRecord.firstBreakSequence = breakSequence;
            scanRecord.firstSeenText = nowText;
        }
        if (scanRecord.processName.isEmpty() && !scanEntry.processName.trimmed().isEmpty())
        {
            scanRecord.processName = scanEntry.processName.trimmed();
        }
        if (scanRecord.processImagePath.isEmpty() && !scanEntry.processImagePath.trimmed().isEmpty())
        {
            scanRecord.processImagePath = scanEntry.processImagePath.trimmed();
        }

        scanRecord.lastBreakSequence = breakSequence;
        scanRecord.lastSeenText = nowText;
        scanRecord.handleHitCount += 1U;
        scanRecord.lastHandleValue = scanEntry.handleValue;
        scanRecord.lastGrantedAccess = scanEntry.grantedAccess;
        appendUniqueText(scanRecord.matchedTargetList, scanEntry.matchedTargetPath);
        appendUniqueText(scanRecord.matchRuleList, scanEntry.matchRuleText);
        appendUniqueText(scanRecord.enumerationSourceList, scanEntry.enumerationSource);
        appendUniqueText(scanRecord.objectNameList, scanEntry.objectName);
    }

    std::lock_guard<std::mutex> lock(entry.accessRecordMutex);
    entry.lastAccessScanDiagnostic = scanResult.diagnosticText.trimmed().isEmpty()
        ? QStringLiteral("-")
        : scanResult.diagnosticText.simplified();
    if (scanRecordByPid.empty())
    {
        entry.uncapturedBreakCount += 1U;
        return 0U;
    }

    for (const auto& scanPair : scanRecordByPid)
    {
        const FileOplockAccessRecord& scanRecord = scanPair.second;
        auto existingIterator = std::find_if(
            entry.accessRecords.begin(),
            entry.accessRecords.end(),
            [&scanRecord](const FileOplockAccessRecord& record) {
                return record.processId == scanRecord.processId;
            });

        if (existingIterator == entry.accessRecords.end())
        {
            FileOplockAccessRecord newRecord = scanRecord;
            newRecord.hitCount = 1U;
            entry.accessRecords.push_back(newRecord);
            continue;
        }

        FileOplockAccessRecord& existingRecord = *existingIterator;
        existingRecord.hitCount += 1U;
        existingRecord.handleHitCount += scanRecord.handleHitCount;
        existingRecord.lastBreakSequence = scanRecord.lastBreakSequence;
        existingRecord.lastSeenText = scanRecord.lastSeenText;
        existingRecord.lastHandleValue = scanRecord.lastHandleValue;
        existingRecord.lastGrantedAccess = scanRecord.lastGrantedAccess;
        if (existingRecord.processName.isEmpty() && !scanRecord.processName.isEmpty())
        {
            existingRecord.processName = scanRecord.processName;
        }
        if (existingRecord.processImagePath.isEmpty() && !scanRecord.processImagePath.isEmpty())
        {
            existingRecord.processImagePath = scanRecord.processImagePath;
        }
        for (const QString& text : scanRecord.matchedTargetList)
        {
            appendUniqueText(existingRecord.matchedTargetList, text);
        }
        for (const QString& text : scanRecord.matchRuleList)
        {
            appendUniqueText(existingRecord.matchRuleList, text);
        }
        for (const QString& text : scanRecord.enumerationSourceList)
        {
            appendUniqueText(existingRecord.enumerationSourceList, text);
        }
        for (const QString& text : scanRecord.objectNameList)
        {
            appendUniqueText(existingRecord.objectNameList, text);
        }
    }

    return scanRecordByPid.size();
}

struct FileDock::NavigationPageDefinition
{
    QString id;
    QString parentId;
    QString languageKey;
    QString sourceTitle;
    QStringList sourceSearchTexts;
    QWidget* FileDock::* pageMember;
    void (FileDock::* initialize)();
};

const std::vector<FileDock::NavigationPageDefinition>& FileDock::navigationPageDefinitions()
{
    static const std::vector<NavigationPageDefinition> definitions{
        { QStringLiteral("file.tab.manager"), QString(), QStringLiteral("file.tab.manager"), QStringLiteral("文件管理"),
          { QStringLiteral("后退"),
              QStringLiteral("前进"),
              QStringLiteral("上级目录"),
              QStringLiteral("刷新当前目录"),
              QStringLiteral("输入路径后按回车跳转"),
              QStringLiteral("快速跳转到任意驱动器根目录"),
              QStringLiteral("图标视图"),
              QStringLiteral("列表视图"),
              QStringLiteral("详情视图"),
              QStringLiteral("树形视图"),
              QStringLiteral("切换文件显示模式，默认使用详情视图"),
              QStringLiteral("系统"),
              QStringLiteral("隐藏"),
              QStringLiteral("名称"),
              QStringLiteral("大小"),
              QStringLiteral("修改时间"),
              QStringLiteral("类型"),
              QStringLiteral("Windows API"),
              QStringLiteral("手动解析文件系统"),
              QStringLiteral("R0 驱动解析"),
              QStringLiteral("作为NTFS解析"),
              QStringLiteral("作为FAT32解析"),
              QStringLiteral("作为exFAT解析"),
              QStringLiteral("作为MFT解析"),
              QStringLiteral("R0 IRP 解析"),
              QStringLiteral("切换目录读取方式：Windows API、R3 原始卷手动解析、R0 驱动目录解析，强制按 NTFS/FAT32/exFAT 解析，\n作为MFT解析（仅 NTFS：卷偏移直读 $MFT，禁用一切 WinAPI/FSCTL 回退），\nR0 IRP 解析（内核自建 IRP 把目录查询直发基础文件系统设备，绕过过滤层；\n打开阶段仍走正常路径，只在 CREATE 上做的拦截发现不了）。\n后两种会与常规视图对照，把只有绕过路径可见的条目标为疑似隐藏项。"),
              QStringLiteral("快速过滤"),
              QStringLiteral("路径: -"),
              QStringLiteral("选中: 0"),
              QStringLiteral("磁盘: -"),
              QStringLiteral("解析器: Windows API") }, &FileDock::m_fileManagerPage, &FileDock::initializeManagerPage },
        { QStringLiteral("file.tab.ntfs_index"), QString(), QStringLiteral("file.tab.ntfs_index"), QStringLiteral("快速文件搜索"),
          { QStringLiteral("快速文件搜索"), QStringLiteral("USN 增量更新"),
            QStringLiteral("MFT"), QStringLiteral("NTFS") },
          &FileDock::m_ntfsIndexPage, &FileDock::initializeNtfsIndexPage },
        { QStringLiteral("file.tab.disk_space"), QString(), QStringLiteral("file.tab.disk_space"), QStringLiteral("空间分布"),
          { QStringLiteral("文件空间分布"), QStringLiteral("WinDirStat"), QStringLiteral("扫描文件夹"),
            QStringLiteral("普通文件遍历"), QStringLiteral("MFT") },
          &FileDock::m_diskSpacePage, &FileDock::initializeDiskSpacePage },
        { QStringLiteral("file.tab.storage_controller"), QString(), QStringLiteral("file.tab.storage_controller"), QStringLiteral("存储控制器"),
          { QStringLiteral("KSword Controller / 存储控制器"),
              QStringLiteral("持续风险提示：此页直接驱动专用控制器的 BAR、DMA/队列或 IDE task-file。写入可立即破坏文件系统、分区表和启动数据；控制器重置可使设备离线。仅允许手动绑定的非启动、无挂载卷控制器。expected-hash 条件比较与写后复读不是硬件原子操作，不能消除设备并发写、固件缓存或掉电风险。"),
              QStringLiteral("资源与一致性"),
              QStringLiteral("控制器：未查询"),
              QStringLiteral("ownership=none；coherency=unknown；session=none"),
              QStringLiteral("刷新状态"),
              QStringLiteral("取得独占会话"),
              QStringLiteral("释放会话"),
              QStringLiteral("受控复位"),
              QStringLiteral("取得对该存储控制器的独占访问会话，用于底层 BAR/DMA 操作"),
              QStringLiteral("对存储控制器执行受控复位（可能使设备暂时离线，操作危险）"),
              QStringLiteral("刷新审计"),
              QStringLiteral("事务化原始访问"),
              QStringLiteral("字节偏移"),
              QStringLiteral("字节长度"),
              QStringLiteral("读取结果或待写入 HEX，例如：00 11 22 FF"),
              QStringLiteral("读取并建立条件写快照"),
              QStringLiteral("按快照写入并复读验证"),
              QStringLiteral("读取该区间并建立“条件写”比对快照，供后续按快照安全写入"),
              QStringLiteral("仅当区间内容仍与快照一致时才写入，写完再读回校验，防止误写"),
              QStringLiteral("回滚最近一次写入"),
              QStringLiteral("序号"),
              QStringLiteral("操作"),
              QStringLiteral("偏移"),
              QStringLiteral("长度"),
              QStringLiteral("结果"),
              QStringLiteral("风险"),
              QStringLiteral("进程") }, &FileDock::m_storageControllerPage, &FileDock::initializeStorageControllerPage },
        { QStringLiteral("file.tab.recovery"), QString(), QStringLiteral("file.tab.recovery"), QStringLiteral("文件恢复"),
          { QStringLiteral("选择要扫描误删文件的 NTFS 卷。"),
              QStringLiteral("刷新可扫描卷列表"),
              QStringLiteral("扫描误删"),
              QStringLiteral("解析 NTFS MFT，扫描删除项"),
              QStringLiteral("恢复选中"),
              QStringLiteral("支持 Resident 与完整非驻留数据；非驻留文件必须导出到其它卷，恢复前后都会复核卷位图。"),
              QStringLiteral("查找结果（文件名/路径/恢复能力）"),
              QStringLiteral("按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"),
              QStringLiteral("按正则表达式筛选，例如 \\.docx?$ 只看 doc/docx"),
              QStringLiteral("卷: "),
              QStringLiteral("选择 NTFS 卷后开始扫描，可在此列出仍可恢复的误删文件。"),
              QStringLiteral("开始扫描误删文件"),
              QStringLiteral("请选择NTFS卷并开始扫描。") }, &FileDock::m_fileRecoveryPage, &FileDock::initializeRecoveryPage },
        { QStringLiteral("file.tab.irpbuilder"), QString(), QStringLiteral("file.tab.irpbuilder"), QStringLiteral("IRP 构造"),
          { QStringLiteral("正在加载..."),
              QStringLiteral("0x%1"),
              QStringLiteral("完成"),
              QStringLiteral("请求参数被 R0 拒绝"),
              QStringLiteral("目标打开失败"),
              QStringLiteral("目标栈层不可用"),
              QStringLiteral("内核内存不足"),
              QStringLiteral("该 major 需要额外确认"),
              QStringLiteral("缺少写入确认令牌"),
              QStringLiteral("等待超时，请求已取消"),
              QStringLiteral("IRP 构造失败"),
              QStringLiteral("输出缓冲不足"),
              QStringLiteral("被安全策略拒绝"),
              QStringLiteral("未知状态(%1)"),
              QStringLiteral("目标请求"),
              QStringLiteral("已取消"),
              QStringLiteral("输出被截断"),
              QStringLiteral("0x%1  未知"),
              QStringLiteral("0x%1  %2"),
              QStringLiteral("无法解析数值: %1"),
              QStringLiteral("十六进制输入必须是偶数个字符。"),
              QStringLiteral("十六进制输入含非法字符: %1"),
              QStringLiteral("(无输出数据)"),
              QStringLiteral("目标与请求"),
              QStringLiteral("目标路径，例如 C:\\Windows 或 \\??\\C:\\Windows\\notepad.exe"),
              QStringLiteral("Win32 路径会自动转换为 \\??\\ 命名空间路径；也可直接填 NT 路径。"),
              QStringLiteral("自定义（手工参数）"),
              QStringLiteral("查询文件全部信息"),
              QStringLiteral("读取文件"),
              QStringLiteral("写入文件（填写下方十六进制数据）"),
              QStringLiteral("刷新文件缓冲"),
              QStringLiteral("创建空文件"),
              QStringLiteral("创建目录"),
              QStringLiteral("枚举目录"),
              QStringLiteral("删除（FileDispositionInformation）"),
              QStringLiteral("删除（POSIX / FileDispositionInformationEx）"),
              QStringLiteral("截断为 0 字节"),
              QStringLiteral("设置基本属性为 NORMAL"),
              QStringLiteral("查询卷属性"),
              QStringLiteral("查询安全描述符"),
              QStringLiteral("选择常用操作后自动填写 Major、访问权、InformationClass 与输入结构。预设只填参数、不自动发送；写操作仍需显式勾选确认。"),
              QStringLiteral("浏览..."),
              QStringLiteral("选择要构造的 IRP 主功能码。参数区会按所选 major 自动启停。"),
              QStringLiteral("IRP_MN_* 次功能码，十进制或 0x 前缀十六进制；不适用时填 0。"),
              QStringLiteral("设备栈顶（等价 Zw* 路径，作为对照基线）"),
              QStringLiteral("基础文件系统设备（跳过其上的过滤层）"),
              QStringLiteral("VPB 挂载文件系统设备"),
              QStringLiteral("卷设备本身"),
              QStringLiteral("选择 IRP 投递到设备栈的哪一层。\n选择非栈顶时，连 IRP_MJ_CREATE 都由 R0 自行构造并直发，不经过过滤层。\n注意：手工构造的文件对象缺少 I/O 管理器建立的完整关联，NTFS 在后续\n目录查询等操作上可能回 STATUS_INVALID_PARAMETER，这属于预期现象；\n只想绕过目录查询请改用文件页的“R0 IRP 解析”读取方式。\n目标层不可用时 R0 会回退到栈顶，并在结果里如实标出实际生效的层。"),
              QStringLiteral("等待完成的毫秒数，上限 60000；超时后 R0 会取消 IRP 并等待其排空。"),
              QStringLiteral("常用操作:"),
              QStringLiteral("目标路径:"),
              QStringLiteral("MajorFunction:"),
              QStringLiteral("MinorFunction:"),
              QStringLiteral("目标栈层:"),
              QStringLiteral("超时(ms):"),
              QStringLiteral("IO_STACK_LOCATION 参数"),
              QStringLiteral("CREATE 阶段 ACCESS_MASK；留空时按只读属性访问打开。"),
              QStringLiteral("CREATE 阶段共享位；留空时按读/写/删除全共享打开。"),
              QStringLiteral("1 (FILE_OPEN)"),
              QStringLiteral("CREATE 处置方式：1=FILE_OPEN，2=FILE_CREATE，3=FILE_OPEN_IF 等。"),
              QStringLiteral("CREATE 选项位；R0 会额外补上同步与备份语义。"),
              QStringLiteral("CREATE 文件属性；留空按 FILE_ATTRIBUTE_NORMAL。"),
              QStringLiteral("信息类：QUERY/SET_INFORMATION 用 FILE_INFORMATION_CLASS，\nQUERY/SET_VOLUME_INFORMATION 用 FS_INFORMATION_CLASS，\nDIRECTORY_CONTROL 用目录信息类，POWER 复用为目标电源状态。"),
              QStringLiteral("DEVICE_CONTROL/FILE_SYSTEM_CONTROL 的控制码，低两位决定缓冲方式。"),
              QStringLiteral("QUERY/SET_SECURITY 的 SECURITY_INFORMATION 位。"),
              QStringLiteral("READ/WRITE/LOCK_CONTROL 的起始字节偏移。"),
              QStringLiteral("READ/WRITE 的 Key，或 LOCK_CONTROL 的锁 Key。"),
              QStringLiteral("LOCK_CONTROL 的加锁字节数。"),
              QStringLiteral("期望的输出缓冲长度，上限 256 KiB。"),
              QStringLiteral("DIRECTORY_CONTROL 的文件名通配符，留空表示不限定。"),
              QStringLiteral("DesiredAccess:"),
              QStringLiteral("ShareAccess:"),
              QStringLiteral("CreateDisposition:"),
              QStringLiteral("CreateOptions:"),
              QStringLiteral("FileAttributes:"),
              QStringLiteral("InformationClass:"),
              QStringLiteral("ControlCode:"),
              QStringLiteral("SecurityInformation:"),
              QStringLiteral("ByteOffset:"),
              QStringLiteral("Key:"),
              QStringLiteral("LockLength:"),
              QStringLiteral("OutputBytes:"),
              QStringLiteral("FileName 通配符:"),
              QStringLiteral("标志与输入数据"),
              QStringLiteral("确认写入语义"),
              QStringLiteral("写类 major 必须勾选；勾选后客户端才会附带确认令牌，R0 会二次校验。"),
              QStringLiteral("允许 PnP/电源类请求"),
              QStringLiteral("IRP_MJ_POWER/PNP/SHUTDOWN/SYSTEM_CONTROL/DEVICE_CHANGE 需要额外勾选。\n这些请求正常由系统按状态机下发，手工构造可能让目标驱动进入非法状态。"),
              QStringLiteral("只执行 CREATE"),
              QStringLiteral("只验证打开阶段，不再下发目标 major，用于单独观察 CREATE 是否被拦截。"),
              QStringLiteral("内联输入数据，十六进制，例如 01 00 00 00；留空表示无输入。"),
              QStringLiteral("作为 IRP 数据段的输入内容，上限 64 KiB。\n空白、逗号和短横线会被忽略，方便直接粘贴各种转储格式。"),
              QStringLiteral("构造并发送 IRP"),
              QStringLiteral("尚未发送。写类与 PnP/电源类请求需要先勾选对应确认项。"),
              QStringLiteral("项目"),
              QStringLiteral("值"),
              QStringLiteral("目标驱动写回的数据将以十六进制转储显示。"),
              QStringLiteral("选择 IRP 目标文件"),
              QStringLiteral("已填入查询 FileAllInformation 的安全栈顶预设。"),
              QStringLiteral("已填入从偏移 0 读取 4096 字节的预设，可修改偏移与长度。"),
              QStringLiteral("已填入写入预设；请在下方填写十六进制数据，并勾选写入确认。"),
              QStringLiteral("已填入刷新文件缓冲预设。"),
              QStringLiteral("已填入 FILE_CREATE 空文件预设；目标必须不存在，并需勾选写入确认。"),
              QStringLiteral("已填入 FILE_CREATE 目录预设；目标必须不存在，并需勾选写入确认。"),
              QStringLiteral("已填入 FileIdBothDirectoryInformation 目录枚举预设。"),
              QStringLiteral("已填入传统 IRP 删除预设；目录目标需另勾 FILE_DIRECTORY_FILE，并需写入确认。"),
              QStringLiteral("已填入 IRP POSIX 删除预设；支持情况取决于系统与文件系统，并需写入确认。"),
              QStringLiteral("已填入 FileEndOfFileInformation 截断到 0 字节预设，并需写入确认。"),
              QStringLiteral("已填入 FileBasicInformation 的 NORMAL 属性模板，并需写入确认。"),
              QStringLiteral("已填入 FileFsAttributeInformation 卷属性查询预设。"),
              QStringLiteral("已填入所有者、组与 DACL 安全描述符查询预设。"),
              QStringLiteral("%1 由 PnP/电源管理器按状态机下发，手工构造可能让目标驱动进入非法状态；需要同时勾选写入确认与 PnP/电源允许项。"),
              QStringLiteral("%1 属于写语义，会改变磁盘或设备状态；需要勾选写入确认。"),
              QStringLiteral("%1 为只读语义，可直接发送。"),
              QStringLiteral("正在发送..."),
              QStringLiteral("IRP 构造"),
              QStringLiteral("请先填写目标路径。"),
              QStringLiteral("%1 会改变磁盘或设备状态，请先勾选“确认写入语义”。"),
              QStringLiteral("%1 需要同时勾选“允许 PnP/电源类请求”。"),
              QStringLiteral("即将向文件系统栈手工投递 %1。\n\n这类请求正常只由 PnP/电源管理器按状态机下发，手工构造可能让目标驱动进入非法状态甚至触发系统崩溃。\n\n确认继续？"),
              QStringLiteral("字段 %1 解析失败：%2"),
              QStringLiteral("输入数据解析失败：%1"),
              QStringLiteral("输入数据超出上限 %1 字节。"),
              QStringLiteral("输出缓冲超出上限 %1 字节。"),
              QStringLiteral("正在向 R0 提交 %1 ..."),
              QStringLiteral("当前 KswordARK 驱动不支持自建 IRP 提交，请重新部署本次构建的驱动。"),
              QStringLiteral("R0 通信失败：Win32=%1；%2"),
              QStringLiteral("通信结果"),
              QStringLiteral("失败"),
              QStringLiteral("Win32 错误"),
              QStringLiteral("诊断"),
              QStringLiteral("协议状态"),
              QStringLiteral("执行阶段"),
              QStringLiteral("MajorFunction"),
              QStringLiteral("MinorFunction"),
              QStringLiteral("请求栈层"),
              QStringLiteral("实际栈层"),
              QStringLiteral("栈层提示"),
              QStringLiteral("目标层不可用，R0 已回退到栈顶，本次未绕过过滤层"),
              QStringLiteral("CREATE 状态"),
              QStringLiteral("目标请求状态"),
              QStringLiteral("CLEANUP 状态"),
              QStringLiteral("CLOSE 状态"),
              QStringLiteral("Information"),
              QStringLiteral("%1 (0x%2)"),
              QStringLiteral("输出字节数"),
              QStringLiteral("接收驱动"),
              QStringLiteral("接收设备"),
              QStringLiteral("目标 DEVICE_OBJECT"),
              QStringLiteral("栈顶 DEVICE_OBJECT"),
              QStringLiteral("基础 FS DEVICE_OBJECT"),
              QStringLiteral("VPB DEVICE_OBJECT"),
              QStringLiteral("分发入口"),
              QStringLiteral("目标 StackSize"),
              QStringLiteral("目标 DeviceFlags"),
              QStringLiteral("%1：协议=%2；目标请求=%3；Information=%4；输出 %5 字节") }, &FileDock::m_irpBuilderPage, &FileDock::initializeIrpBuilderPage }
    };
    return definitions;
}

ks::ui::PageNavigationCatalog FileDock::navigationCatalog(const FileDock* const existing)
{
    ks::ui::PageNavigationCatalog catalog;
    const auto& definitions = navigationPageDefinitions();
    catalog.reserve(static_cast<qsizetype>(definitions.size()));
    for (std::size_t ordinal = 0; ordinal < definitions.size(); ++ordinal)
    {
        const auto& definition = definitions[ordinal];
        ks::ui::PageNavigationDescriptor page;
        page.id = definition.id;
        page.parentId = definition.parentId;
        page.title = ks::i18n::text(definition.languageKey, definition.sourceTitle);
        page.current = ordinal == 0;
        for (const auto& text : definition.sourceSearchTexts)
            page.searchTexts.append(ks::i18n::sourceText(text));
        if (existing)
        {
            const auto* tabs = existing->m_rootTabWidget;
            QWidget* const widget = existing->*(definition.pageMember);
            const int index = tabs && widget ? tabs->indexOf(widget) : -1;
            page.visible = index >= 0 && tabs->isTabVisible(index);
            page.enabled = index >= 0 && tabs->isEnabled() && tabs->isTabEnabled(index) && widget->isEnabled();
            page.current = index >= 0 && tabs->currentWidget() == widget;
            if (index >= 0) page.title = tabs->tabText(index);
        }
        catalog.append(std::move(page));
    }
    return catalog;
}

QWidget* FileDock::activateNavigationDescriptor(const QString& id)
{
    const auto catalog = navigationCatalog(this);
    const auto record = std::find_if(catalog.cbegin(), catalog.cend(),
        [&id](const auto& page) { return page.id == id; });
    if (record == catalog.cend() || !record->visible || !record->enabled) return nullptr;
    const auto& definitions = navigationPageDefinitions();
    const auto definition = std::find_if(definitions.cbegin(), definitions.cend(),
        [&id](const auto& page) { return page.id == id; });
    if (definition == definitions.cend()) return nullptr;
    const QPointer<FileDock> self(this);
    const QPointer<QTabWidget> tabs(m_rootTabWidget);
    const QPointer<QWidget> page(this->*(definition->pageMember));
    if (!tabs || !page) return nullptr;
    const int index = tabs->indexOf(page);
    if (index < 0 || !tabs->isTabVisible(index) || !tabs->isTabEnabled(index)) return nullptr;
    tabs->setCurrentIndex(index);
    if (!self || !tabs || !page || tabs->currentWidget() != page) return nullptr;
    ks::ui::PrepareWidgetThemeBindingsForShow(page);
    if (!self || !tabs || !page || tabs->currentWidget() != page) return nullptr;
    const int finalIndex = tabs->indexOf(page);
    if (finalIndex < 0 || !tabs->isTabVisible(finalIndex) || !tabs->isTabEnabled(finalIndex)
        || !page->isEnabled()) return nullptr;
    return page.data();
}

FileDock::FileDock(QWidget* parent)
    : QWidget(parent)
    , m_uiDispatcher(std::make_shared<ks::ui::AsyncUiDispatcher>(this))
{
    // 构造日志：记录文件模块启动。
    kLogEvent event;
    info << event << "[FileDock] 构造开始，初始化双栏资源管理器。" << eol;

    initializeUi();
}

FileDock::~FileDock()
{
    if (m_leftPanel.navigationOperation) m_leftPanel.navigationOperation->close();
    if (m_rightPanel.navigationOperation) m_rightPanel.navigationOperation->close();
    if (m_fileMenuOperation) m_fileMenuOperation->close();
    if (m_shortNameOperation) m_shortNameOperation->close();
    if (m_fileMutationOperation != nullptr) m_fileMutationOperation->close();
    if (m_recoveryFilterTimer) m_recoveryFilterTimer->stop();
    if (m_recoveryScanOperation) m_recoveryScanOperation->close();
    if (m_recoveryProjectionOperation) m_recoveryProjectionOperation->close();
    retireRecoverySnapshot(std::move(m_recoveryPendingSnapshot));
    if (m_fileAnalysisOperation != nullptr) m_fileAnalysisOperation->close();
    if (m_leftPanel.manualParseCanceled) m_leftPanel.manualParseCanceled->store(true);
    if (m_rightPanel.manualParseCanceled) m_rightPanel.manualParseCanceled->store(true);
    m_uiDispatcher->close();
    // 析构阶段先释放持有型 Oplock，再停止解锁器后台线程。
    releaseAllActiveOplocks(false);
    m_unlockerWorkerStopRequested.store(true);
    std::thread workerThread;
    {
        std::lock_guard<std::mutex> lock(m_unlockerWorkerMutex);
        if (m_unlockerWorkerThread.joinable())
        {
            workerThread = std::move(m_unlockerWorkerThread);
        }
    }
    if (workerThread.joinable())
    {
        workerThread.join();
    }
}

void FileDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    const auto refreshPanelView = [](FilePanelWidgets& panel)
        {
            if (panel.fileView != nullptr && panel.fileView->viewport() != nullptr)
            {
                // ReparseAwareFileSystemModel::data() 按当前语言即时生成大小和类型；
                // 主动刷新 viewport，避免等待目录变化或重新启动后才重新取数。
                panel.fileView->viewport()->update();
            }
            if (panel.compactFileView != nullptr && panel.compactFileView->viewport() != nullptr)
            {
                panel.compactFileView->viewport()->update();
            }
        };
    refreshPanelView(m_leftPanel);
    refreshPanelView(m_rightPanel);
    if (m_recoveryTable)
    {
        m_recoveryTable->viewport()->update();
        m_recoveryTable->horizontalHeader()->viewport()->update();
    }
}

bool FileDock::eventFilter(QObject* watched, QEvent* event)
{
    // A projection keeps filtered-out selections by source identity. Normal replacement
    // selection still clears those latent rows, just as QTableWidget did before filtering.
    if (m_recoveryTable && m_recoveryModel && event && !m_recoveryProjectionCommit)
    {
        auto* model = static_cast<DeletedRecoveryModel*>(m_recoveryModel);
        if (watched == m_recoveryTable->viewport() && event->type() == QEvent::MouseButtonPress)
        {
            const auto* mouse = static_cast<QMouseEvent*>(event);
            const auto clicked = m_recoveryTable->indexAt(mouse->position().toPoint());
            if (!(mouse->modifiers() & (Qt::ControlModifier | Qt::ShiftModifier))
                && (mouse->button() == Qt::LeftButton || (mouse->button() == Qt::RightButton
                    && clicked.isValid() && !m_recoveryTable->selectionModel()->isSelected(clicked))))
            {
                for (auto it = m_recoverySelectedSourceRows.begin(); it != m_recoverySelectedSourceRows.end();)
                    if (model->viewRow(*it) < 0) it = m_recoverySelectedSourceRows.erase(it); else ++it;
            }
        }
        if (watched == m_recoveryTable && event->type() == QEvent::KeyPress)
        {
            const auto* key = static_cast<QKeyEvent*>(event);
            if (key->matches(QKeySequence::SelectAll) && model->snapshot())
            {
                m_recoverySelectedSourceRows.clear();
                for (int source = 0; source < static_cast<int>(model->snapshot()->entries.size()); ++source)
                    m_recoverySelectedSourceRows.insert(source);
            }
            else if (!(key->modifiers() & (Qt::ControlModifier | Qt::ShiftModifier))
                && (key->key() == Qt::Key_Escape || key->key() == Qt::Key_Up || key->key() == Qt::Key_Down
                    || key->key() == Qt::Key_Home || key->key() == Qt::Key_End
                    || key->key() == Qt::Key_PageUp || key->key() == Qt::Key_PageDown))
            {
                for (auto it = m_recoverySelectedSourceRows.begin(); it != m_recoverySelectedSourceRows.end();)
                    if (model->viewRow(*it) < 0) it = m_recoverySelectedSourceRows.erase(it); else ++it;
            }
        }
    }

    // 读取方式下拉框吞掉滚轮：它的每一次切换都会触发一轮目录重解析，
    // 纯 MFT / R0 IRP 这两种还是全卷级别的重活。鼠标从列表滚到工具条上时
    // 一次滚动就能连着切好几档，等于连续排队几轮全盘扫描。
    // 切换必须是用户点开下拉框做出的明确选择。
    if (event != nullptr && event->type() == QEvent::Wheel &&
        ((m_leftPanel.readModeCombo != nullptr && watched == m_leftPanel.readModeCombo) ||
         (m_rightPanel.readModeCombo != nullptr && watched == m_rightPanel.readModeCombo)))
    {
        return true;
    }

    // QFileSystemModel/QTreeView 在右键按下阶段会按默认鼠标选择规则更新当前行。
    // 这里提前处理文件列表 viewport 的右键：命中已选中行时保留现有多选集合；
    // 命中未选中行时切换为该单行，保证后续自定义菜单读取 selectedPaths() 一致。
    if (event != nullptr && event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* const mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent != nullptr && mouseEvent->button() == Qt::RightButton)
        {
            FilePanelWidgets* targetPanel = nullptr;
            QAbstractItemView* targetView = nullptr;
            if (m_leftPanel.fileView != nullptr && watched == m_leftPanel.fileView->viewport())
            {
                targetPanel = &m_leftPanel;
                targetView = m_leftPanel.fileView;
            }
            else if (m_rightPanel.fileView != nullptr && watched == m_rightPanel.fileView->viewport())
            {
                targetPanel = &m_rightPanel;
                targetView = m_rightPanel.fileView;
            }
            else if (m_leftPanel.compactFileView != nullptr && watched == m_leftPanel.compactFileView->viewport())
            {
                targetPanel = &m_leftPanel;
                targetView = m_leftPanel.compactFileView;
            }
            else if (m_rightPanel.compactFileView != nullptr && watched == m_rightPanel.compactFileView->viewport())
            {
                targetPanel = &m_rightPanel;
                targetView = m_rightPanel.compactFileView;
            }

            if (targetPanel != nullptr && targetView != nullptr)
            {
                const QModelIndex hitIndex = targetView->indexAt(mouseEvent->pos());
                QItemSelectionModel* const selectionModel = targetView->selectionModel();
                if (hitIndex.isValid() && selectionModel != nullptr)
                {
                    const QModelIndex hitRowIndex = hitIndex.siblingAtColumn(0);
                    const bool hitAlreadySelected =
                        selectionModel->isRowSelected(hitIndex.row(), hitIndex.parent()) ||
                        (hitRowIndex.isValid() && selectionModel->isSelected(hitRowIndex));
                    if (!hitAlreadySelected)
                    {
                        selectionModel->select(hitIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    }
                    // 只更新 current index，不调用 QTreeView::setCurrentIndex()，避免 Qt 按普通点击规则清掉多选集合。
                    selectionModel->setCurrentIndex(hitIndex, QItemSelectionModel::NoUpdate);
                    return true;
                }
            }
        }
    }

    return QWidget::eventFilter(watched, event);
}

void FileDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0); // 文件双栏内容由Tab框架提供等边外沿。
    m_rootLayout->setSpacing(6);

    // 顶层改为竖排 Tab：文件管理 + 文件恢复。
    m_rootTabWidget = new QTabWidget(this);
    m_rootTabWidget->setTabPosition(QTabWidget::West);
    m_rootTabWidget->setDocumentMode(true);
    // 竖向主Tab直接承接ADS方形外壳，内部双栏仍各自保持原有圆角。
    ks::ui::StyleSquarePageTabsFrame(m_rootTabWidget);
    m_rootLayout->addWidget(m_rootTabWidget, 1);

    for (const auto& definition : navigationPageDefinitions())
    {
        (this->*(definition.initialize))();
        QWidget* const page = this->*(definition.pageMember);
        if (!page) continue;
        m_rootTabWidget->addTab(page, ks::i18n::text(definition.languageKey, definition.sourceTitle));
        ks::i18n::LanguageManager::instance().bindTab(
            m_rootTabWidget, page, definition.languageKey, definition.sourceTitle);
    }
}

void FileDock::initializeManagerPage()
{
    m_fileManagerPage = new QWidget(m_rootTabWidget);
    QVBoxLayout* managerLayout = new QVBoxLayout(m_fileManagerPage);
    managerLayout->setContentsMargins(0, 0, 0, 0);
    managerLayout->setSpacing(0);

    m_mainSplitter = new QSplitter(Qt::Horizontal, m_fileManagerPage);
    // 文件管理双栏的分界线必须由用户和可用 viewport 决定：
    // - 不允许某一侧文件列表因长文件名/表头列宽变化把对侧挤开；
    // - 子面板不可折叠，避免极窄窗口下某侧被内容最小宽度吞掉。
    m_mainSplitter->setChildrenCollapsible(false);
    managerLayout->addWidget(m_mainSplitter, 1);

    initializePanel(m_leftPanel, QStringLiteral("左侧面板"));
    initializePanel(m_rightPanel, QStringLiteral("右侧面板"));
    m_mainSplitter->addWidget(m_leftPanel.rootWidget);
    m_mainSplitter->addWidget(m_rightPanel.rootWidget);
    m_mainSplitter->setStretchFactor(0, 1);
    m_mainSplitter->setStretchFactor(1, 1);

}

void FileDock::initializeNtfsIndexPage()
{
    auto* page = new NtfsSearchPage(m_rootTabWidget);
    m_ntfsIndexPage = page;
    connect(page, &NtfsSearchPage::locatePathRequested, this, &FileDock::locateIndexedPath);
}

void FileDock::initializeDiskSpacePage()
{
    auto* page = new DiskSpacePage(m_rootTabWidget);
    m_diskSpacePage = page;
    connect(page, &DiskSpacePage::locatePathRequested, this, &FileDock::locateIndexedPath);
}

void FileDock::locateIndexedPath(const QString& path)
{
    const QString target = QDir::cleanPath(QDir::fromNativeSeparators(path));
    if (target.isEmpty()) return;
    // QFileInfo path decomposition does not query the filesystem. Native existence
    // probing remains in the existing asynchronous navigation worker.
    const QString parent = QFileInfo(target).absolutePath();
    m_rootTabWidget->setCurrentWidget(m_fileManagerPage);
    m_leftPanel.filterEdit->clear();
    m_leftPanel.showHiddenCheck->setChecked(true);
    m_leftPanel.showSystemCheck->setChecked(true);
    navigateToPath(m_leftPanel, parent, true, target);
}

void FileDock::initializeStorageControllerPage()
{
    m_storageControllerPage = new ks::misc::StorageControllerResearchDialog(m_rootTabWidget);
}

void FileDock::initializePanel(FilePanelWidgets& panel, const QString& titleText)
{
    // 记录面板名称，后续日志统一附带“左侧/右侧”标签便于排障定位。
    panel.panelNameText = titleText;

    {
        kLogEvent event;
        info << event
            << "[FileDock] 开始初始化面板, panel="
            << titleText.toStdString()
            << eol;
    }

    panel.rootWidget = new QWidget(m_mainSplitter);
    // 文件面板根容器横向可收缩：
    // - 输入：QSplitter 分配的当前宽度；
    // - 处理：忽略内部文件列表的动态 sizeHint，防止选中文件或目录加载时推动分界线；
    // - 返回：无返回值，实际布局仍由 rootLayout 管理。
    panel.rootWidget->setMinimumWidth(0);
    panel.rootWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    panel.rootLayout = new QVBoxLayout(panel.rootWidget);
    panel.rootLayout->setContentsMargins(4, 4, 4, 4);
    panel.rootLayout->setSpacing(4);

    // 标题栏：区分左右面板。
    QLabel* titleLabel = new QLabel(titleText, panel.rootWidget);
    // 左右面板标题用次级文字定位，强调色留给当前操作与选中项。
    ks::ui::StylePrimarySectionTitle(titleLabel);
    panel.rootLayout->addWidget(titleLabel, 0);

    panel.navWidget = new QWidget(panel.rootWidget);
    panel.navLayout = new QHBoxLayout(panel.navWidget);
    panel.navLayout->setContentsMargins(0, 0, 0, 0);
    panel.navLayout->setSpacing(4);

    panel.backButton = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), panel.navWidget);
    panel.backButton->setToolTip(QStringLiteral("后退"));
    panel.backButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.backButton);

    panel.forwardButton = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), panel.navWidget);
    panel.forwardButton->setToolTip(QStringLiteral("前进"));
    panel.forwardButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.forwardButton);

    panel.upButton = new QPushButton(QIcon(":/Icon/file_nav_up.svg"), QString(), panel.navWidget);
    panel.upButton->setToolTip(QStringLiteral("上级目录"));
    panel.upButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.upButton);

    panel.refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), panel.navWidget);
    panel.refreshButton->setToolTip(QStringLiteral("刷新当前目录"));
    panel.refreshButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.refreshButton);

    // 地址区域采用“堆叠控件”：
    // - 面包屑页：默认显示；
    // - 编辑页：点击空白热区后切换，按 Enter 跳转。
    panel.pathStack = new QStackedWidget(panel.navWidget);
    panel.pathStack->setMinimumWidth(260);

    panel.breadcrumbWidget = new QWidget(panel.pathStack);
    panel.breadcrumbWidget->setObjectName(QStringLiteral("EmbeddedBreadcrumbWidget"));
    panel.breadcrumbWidget->setStyleSheet(QStringLiteral(
        "QWidget#EmbeddedBreadcrumbWidget{"
        "  border:1px solid %1;"
        "  border-radius:3px;"
        "  background:%2;"
        "}").arg(KswordTheme::BorderHex(), KswordTheme::SurfaceHex()));
    panel.breadcrumbLayout = new QHBoxLayout(panel.breadcrumbWidget);
    panel.breadcrumbLayout->setContentsMargins(6, 2, 6, 2);
    panel.breadcrumbLayout->setSpacing(2);

    panel.pathEdit = new QLineEdit(panel.pathStack);
    panel.pathEdit->setPlaceholderText(QStringLiteral("输入路径后按回车跳转"));
    panel.pathEdit->setStyleSheet(buildBlueInputStyle());

    // 驱动器下拉框：
    // - 固定放在地址栏右侧，直接跳转任意盘符根目录；
    // - 解决默认路径体验更偏向当前系统盘的问题。
    panel.driveCombo = new QComboBox(panel.navWidget);
    panel.driveCombo->setStyleSheet(buildBlueInputStyle());
    ks::ui::StylePrimaryCombo(panel.driveCombo);
    panel.driveCombo->setMinimumWidth(92);
    panel.driveCombo->setMaximumWidth(140);
    panel.driveCombo->setToolTip(QStringLiteral("快速跳转到任意驱动器根目录"));

    panel.pathStack->addWidget(panel.breadcrumbWidget);
    panel.pathStack->addWidget(panel.pathEdit);

    panel.navLayout->addWidget(panel.backButton);
    panel.navLayout->addWidget(panel.forwardButton);
    panel.navLayout->addWidget(panel.upButton);
    panel.navLayout->addWidget(panel.refreshButton);
    panel.navLayout->addWidget(panel.pathStack, 1);
    panel.navLayout->addWidget(panel.driveCombo, 0);
    ks::ui::NormalizeToolbarRow(panel.navLayout);
    // 地址堆叠容器是一行面包屑/路径编辑，显式与邻接按钮等高。
    panel.pathStack->setFixedHeight(panel.backButton->height());
    ks::ui::NormalizeToolbarControl(panel.pathEdit, panel.backButton->height());
    panel.rootLayout->addWidget(panel.navWidget, 0);

    panel.toolWidget = new QWidget(panel.rootWidget);
    panel.toolLayout = new QHBoxLayout(panel.toolWidget);
    panel.toolLayout->setContentsMargins(0, 0, 0, 0);
    panel.toolLayout->setSpacing(4);

    panel.viewModeCombo = new QComboBox(panel.toolWidget);
    panel.viewModeCombo->setStyleSheet(buildBlueInputStyle());
    ks::ui::StylePrimaryCombo(panel.viewModeCombo);
    panel.viewModeCombo->addItems(QStringList{ QStringLiteral("图标视图"), QStringLiteral("列表视图"), QStringLiteral("详情视图"), QStringLiteral("树形视图") });
    panel.viewModeCombo->setToolTip(QStringLiteral("切换文件显示模式，默认使用详情视图"));
    panel.viewModeCombo->setCurrentIndex(2);

    panel.showSystemCheck = new QCheckBox(QStringLiteral("系统"), panel.toolWidget);
    panel.showHiddenCheck = new QCheckBox(QStringLiteral("隐藏"), panel.toolWidget);
    panel.showSystemCheck->setChecked(true);
    panel.showHiddenCheck->setChecked(true);

    panel.sortModeCombo = new QComboBox(panel.toolWidget);
    panel.sortModeCombo->setStyleSheet(buildBlueInputStyle());
    ks::ui::StylePrimaryCombo(panel.sortModeCombo);
    panel.sortModeCombo->addItems(QStringList{ QStringLiteral("名称"), QStringLiteral("大小"), QStringLiteral("修改时间"), QStringLiteral("类型") });

    panel.readModeCombo = new QComboBox(panel.toolWidget);
    panel.readModeCombo->setStyleSheet(buildBlueInputStyle());
    ks::ui::StylePrimaryCombo(panel.readModeCombo);
    panel.readModeCombo->addItems(QStringList{
        QStringLiteral("Windows API"),
        QStringLiteral("手动解析文件系统"),
        QStringLiteral("R0 驱动解析"),
        QStringLiteral("作为NTFS解析"),
        QStringLiteral("作为FAT32解析"),
        QStringLiteral("作为exFAT解析"),
        QStringLiteral("作为MFT解析"),
        QStringLiteral("R0 IRP 解析") });
    // 装事件过滤器吞掉滚轮：见 eventFilter 里的说明。
    panel.readModeCombo->installEventFilter(this);
    panel.readModeCombo->setFocusPolicy(Qt::StrongFocus);
    panel.readModeCombo->setToolTip(QStringLiteral(
        "切换目录读取方式：Windows API、R3 原始卷手动解析、"
        "R0 驱动目录解析，强制按 NTFS/FAT32/exFAT 解析，\n"
        "作为MFT解析（仅 NTFS：卷偏移直读 $MFT，禁用一切 WinAPI/FSCTL 回退），\n"
        "R0 IRP 解析（内核自建 IRP 把目录查询直发基础文件系统设备，绕过过滤层；\n"
        "打开阶段仍走正常路径，只在 CREATE 上做的拦截发现不了）。\n"
        "后两种会与常规视图对照，把只有绕过路径可见的条目标为疑似隐藏项。"));

    panel.filterEdit = new QLineEdit(panel.toolWidget);
    // 文件树/列表两种投影共用此过滤框，只更新可读搜索主题。
    ks::ui::StyleSearchField(panel.filterEdit);
    panel.filterEdit->setPlaceholderText(QStringLiteral("快速过滤"));

    panel.toolLayout->addWidget(panel.viewModeCombo, 0);
    panel.toolLayout->addWidget(panel.showSystemCheck, 0);
    panel.toolLayout->addWidget(panel.showHiddenCheck, 0);
    panel.toolLayout->addWidget(panel.sortModeCombo, 0);
    panel.toolLayout->addWidget(panel.readModeCombo, 0);
    panel.toolLayout->addWidget(panel.filterEdit, 1);
    ks::ui::NormalizeToolbarRow(panel.toolLayout);
    // 筛选行与文件结果使用不同层次，保持两行工具和原有列表高度。
    ks::ui::StylePrimaryToolbar(panel.toolWidget);
    panel.toolLayout->setContentsMargins(6, 3, 6, 3);
    panel.rootLayout->addWidget(panel.toolWidget, 0);

    panel.fsModel = new ReparseAwareFileSystemModel(panel.rootWidget);
    panel.fsModel->setReadOnly(false);
    panel.fsModel->setResolveSymlinks(true);
    panel.fsModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    // 关闭“仅灰显不隐藏”行为，确保名称过滤严格只显示匹配项。
    panel.fsModel->setNameFilterDisables(false);

    panel.proxyModel = new ExplorerFileSortProxyModel(panel.rootWidget);
    panel.proxyModel->setSourceModel(panel.fsModel);
    panel.proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    panel.proxyModel->setFilterKeyColumn(0);

    panel.manualModel = new ManualDirectoryModel(&FileDock::formatSizeText, panel.rootWidget);

    panel.manualProxyModel = new ExplorerFileSortProxyModel(panel.rootWidget);
    panel.manualProxyModel->setSourceModel(panel.manualModel);
    panel.manualProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    panel.manualProxyModel->setFilterKeyColumn(static_cast<int>(ManualModelColumn::Name));

    panel.fileViewStack = new QStackedWidget(panel.rootWidget);
    panel.fileViewStack->setMinimumWidth(0);
    panel.fileViewStack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);

    panel.compactFileView = new QListView(panel.fileViewStack);
    panel.compactFileView->setMinimumWidth(0);
    panel.compactFileView->setLayoutMode(QListView::Batched);
    panel.compactFileView->setBatchSize(128);
    panel.compactFileView->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    panel.compactFileView->setModel(panel.proxyModel);
    panel.compactFileView->setModelColumn(0);
    panel.compactFileView->setEditTriggers(QAbstractItemView::EditKeyPressed);
    panel.compactFileView->setContextMenuPolicy(Qt::CustomContextMenu);
    panel.compactFileView->viewport()->installEventFilter(this);
    panel.compactFileView->setDragEnabled(true);
    panel.compactFileView->setAcceptDrops(true);
    panel.compactFileView->setDropIndicatorShown(true);
    panel.compactFileView->setDragDropMode(QAbstractItemView::DragDrop);
    panel.compactFileView->setDefaultDropAction(Qt::MoveAction);
    panel.compactFileView->setDragDropOverwriteMode(false);

    panel.fileView = new QTreeView(panel.fileViewStack);
    // 文件列表由 FileDock 自己管理列宽和滚动行为：
    // - 禁用全局 TableColumnAutoFit，避免 QFileSystemModel 某些长名称/类型列在选择或加载时重算列宽；
    // - 横向 size policy 使用 Ignored，确保 QTreeView 的 header/内容宽度不会反向撑大 QSplitter 子面板。
    panel.fileView->setMinimumWidth(0);
    panel.fileView->setUniformRowHeights(true);
    panel.fileView->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    ks::ui::SetTableColumnAutoFitEnabled(panel.fileView, false);
    panel.fileView->setModel(panel.proxyModel);
    panel.fileView->setEditTriggers(QAbstractItemView::EditKeyPressed);
    panel.fileView->setContextMenuPolicy(Qt::CustomContextMenu);
    panel.fileView->viewport()->installEventFilter(this);
    panel.fileView->setSortingEnabled(true);
    panel.fileView->setDragEnabled(true);
    panel.fileView->setAcceptDrops(true);
    panel.fileView->setDropIndicatorShown(true);
    panel.fileView->setDragDropMode(QAbstractItemView::DragDrop);
    panel.fileView->setDefaultDropAction(Qt::MoveAction);
    panel.fileView->setDragDropOverwriteMode(false);
    panel.fileView->header()->setStretchLastSection(false);
    panel.fileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    // 文件列名回到统一表头角色，不再和选中项争用高饱和强调色。
    panel.fileView->header()->setStyleSheet(QString());
    // 两种控件共享同一个选择模型，切换视图后多选、当前项和右键动作保持一致。
    QItemSelectionModel* compactSelectionModel = panel.compactFileView->selectionModel();
    panel.compactFileView->setSelectionModel(panel.fileView->selectionModel());
    if (compactSelectionModel != nullptr && compactSelectionModel != panel.fileView->selectionModel())
    {
        compactSelectionModel->deleteLater();
    }
    configureFileViewSelection(panel);
    panel.fileViewStack->addWidget(panel.compactFileView);
    panel.fileViewStack->addWidget(panel.fileView);
    panel.fileViewStack->setCurrentWidget(panel.fileView);
    panel.rootLayout->addWidget(panel.fileViewStack, 1);

    new FileVisualDemandScheduler(panel.fileView, panel.compactFileView,
        panel.proxyModel, panel.manualProxyModel, panel.rootWidget,
        [&panel](const QVector<FileVisualDemand>& demand) {
            QVector<FileVisualDemand> fsDemand;
            QVector<FileVisualDemand> manualDemand;
            for (const auto& item : demand)
            {
                if (item.index.model() == panel.fsModel)
                    fsDemand.push_back(item);
                else if (item.index.model() == panel.manualModel)
                    manualDemand.push_back(item);
            }
            static_cast<ReparseAwareFileSystemModel*>(panel.fsModel)->setVisualDemand(fsDemand);
            static_cast<ManualDirectoryModel*>(panel.manualModel)->setVisualDemand(manualDemand);
        });

    panel.statusBar = new QStatusBar(panel.rootWidget);
    panel.pathStatusLabel = new QLabel(QStringLiteral("路径: -"), panel.statusBar);
    panel.selectionStatusLabel = new QLabel(QStringLiteral("选中: 0"), panel.statusBar);
    panel.diskStatusLabel = new QLabel(QStringLiteral("磁盘: -"), panel.statusBar);
    panel.parserStatusLabel = new QLabel(QStringLiteral("解析器: Windows API"), panel.statusBar);
    panel.statusBar->addWidget(panel.pathStatusLabel, 1);
    panel.statusBar->addPermanentWidget(panel.parserStatusLabel, 0);
    panel.statusBar->addPermanentWidget(panel.selectionStatusLabel, 0);
    panel.statusBar->addPermanentWidget(panel.diskStatusLabel, 0);
    panel.rootLayout->addWidget(panel.statusBar, 0);

    // 初始化读取模式并同步模型。
    applyReadModeToPanel(panel);
    initializeConnections(panel);
    refreshDriveCombo(panel);

    // 默认定位到系统根目录。
    const QString defaultPath = QDir::rootPath();
    navigateToPath(panel, defaultPath, true);

    {
        kLogEvent event;
        info << event
            << "[FileDock] 面板初始化完成, panel="
            << panel.panelNameText.toStdString()
            << ", defaultPath="
            << QDir::toNativeSeparators(defaultPath).toStdString()
            << eol;
    }
}

void FileDock::initializeConnections(FilePanelWidgets& panel)
{
    // 返回按钮：回退到上一个历史路径。
    connect(panel.backButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.historyIndex <= 0 || panel.history.empty())
        {
            return;
        }

        panel.historyIndex -= 1;
        const QString targetPath = panel.history.at(static_cast<std::size_t>(panel.historyIndex));
        {
            kLogEvent event;
            info << event
                << "[FileDock] 历史后退, panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, targetPath, false);
    });

    // 前进按钮：进入历史中的下一个路径。
    connect(panel.forwardButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.history.empty())
        {
            return;
        }
        const int nextIndex = panel.historyIndex + 1;
        if (nextIndex < 0 || nextIndex >= static_cast<int>(panel.history.size()))
        {
            return;
        }

        panel.historyIndex = nextIndex;
        const QString targetPath = panel.history.at(static_cast<std::size_t>(panel.historyIndex));
        {
            kLogEvent event;
            info << event
                << "[FileDock] 历史前进, panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, targetPath, false);
    });

    // 上级目录按钮：从当前目录切到 parent。
    connect(panel.upButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.currentPath.isEmpty())
        {
            return;
        }

        const QString parentPath = QDir::cleanPath(QDir(panel.currentPath).absoluteFilePath(QStringLiteral("..")));
        if (!pathEqualsCaseInsensitive(parentPath, panel.currentPath)) navigateToPath(panel, parentPath, true);
    });

    // 刷新按钮：重新加载当前目录。
    connect(panel.refreshButton, &QPushButton::clicked, this, [this, &panel]() {
        kLogEvent event;
        info << event
            << "[FileDock] 手动刷新目录, panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
        refreshPanel(panel);
    });

    // 地址栏回车：按输入路径导航并自动回到面包屑显示模式。
    connect(panel.pathEdit, &QLineEdit::returnPressed, this, [this, &panel]() {
        const QString targetPath = panel.pathEdit->text().trimmed();
        {
            kLogEvent event;
            info << event
                << "[FileDock] 地址栏回车导航, panel="
                << panel.panelNameText.toStdString()
                << ", input="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, targetPath, true);
        setPathEditMode(panel, false);
    });

    // 驱动器下拉框切换：直接跳转到对应盘符根目录。
    connect(panel.driveCombo, &QComboBox::currentIndexChanged, this, [this, &panel](const int indexValue) {
        if (indexValue < 0)
        {
            return;
        }

        const QString targetRootPath = panel.driveCombo->itemData(indexValue).toString();
        if (targetRootPath.trimmed().isEmpty())
        {
            return;
        }

        if (panel.currentPath.compare(targetRootPath, Qt::CaseInsensitive) == 0)
        {
            return;
        }

        kLogEvent event;
        info << event
            << "[FileDock] 驱动器下拉框跳转, panel="
            << panel.panelNameText.toStdString()
            << ", targetRoot="
            << QDir::toNativeSeparators(targetRootPath).toStdString()
            << eol;
        navigateToPath(panel, targetRootPath, true);
    });

    // 编辑完成但未回车时：回退到面包屑，避免长期停留在文本编辑态。
    connect(panel.pathEdit, &QLineEdit::editingFinished, this, [this, &panel]() {
        if (!panel.pathEditMode)
        {
            return;
        }
        if (panel.pathEdit->hasFocus())
        {
            return;
        }
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        setPathEditMode(panel, false);
    });

    // ESC：取消路径编辑并恢复当前路径文本。
    QShortcut* cancelPathEditShortcut = new QShortcut(QKeySequence(Qt::Key_Escape), panel.pathEdit);
    connect(cancelPathEditShortcut, &QShortcut::activated, this, [this, &panel]() {
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        setPathEditMode(panel, false);
        kLogEvent event;
        dbg << event
            << "[FileDock] 取消路径编辑, panel="
            << panel.panelNameText.toStdString()
            << eol;
    });

    // 视图切换：根据当前模式调整列显示与图标大小。
    connect(panel.viewModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        applyPanelFilterAndSort(panel);
    });

    // 系统文件显隐切换。
    connect(panel.showSystemCheck, &QCheckBox::toggled, this, [this, &panel](bool) {
        applyPanelFilterAndSort(panel);
    });

    // 隐藏文件显隐切换。
    connect(panel.showHiddenCheck, &QCheckBox::toggled, this, [this, &panel](bool) {
        applyPanelFilterAndSort(panel);
    });

    // 排序模式切换。
    connect(panel.sortModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        applyPanelFilterAndSort(panel);
    });

    // 读取模式切换：Windows API 与手动解析模型实时切换。
    connect(panel.readModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        panel.manualLoadedPath.clear();
        panel.manualDisplayedPath.clear();
        panel.manualDisplayedReadMode = -1;
        panel.manualSampledAt = {};
        panel.manualLastError.clear();
        panel.manualSourceDetail.clear();
        panel.manualResultPartial = false;
        if (panel.manualModel != nullptr)
        {
            static_cast<ManualDirectoryModel*>(panel.manualModel)->setSnapshot({});
        }
        applyReadModeToPanel(panel);
        refreshPanel(panel);
    });

    // 快速过滤输入：实时更新代理模型。
    connect(panel.filterEdit, &QLineEdit::textChanged, this, [this, &panel](const QString&) {
        applyPanelFilterAndSort(panel);
    });

    // 双击打开：目录进入，文件交给系统默认程序。
    connect(panel.fileView, &QTreeView::doubleClicked, this, [this, &panel](const QModelIndex& proxyIndex) {
        if (!proxyIndex.isValid())
        {
            return;
        }

        const QString path = currentIndexPath(panel);
        if (path.isEmpty())
        {
            return;
        }

        QFileInfo info(path);
        if (info.isDir())
        {
            navigateToPath(panel, path, true);
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    connect(panel.compactFileView, &QListView::doubleClicked, this, [this, &panel](const QModelIndex& proxyIndex) {
        if (!proxyIndex.isValid())
        {
            return;
        }

        const QString path = currentIndexPath(panel);
        if (path.isEmpty())
        {
            return;
        }

        QFileInfo info(path);
        if (info.isDir())
        {
            navigateToPath(panel, path, true);
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });

    connect(panel.compactFileView, &QListView::customContextMenuRequested, this, [this, &panel](const QPoint& pos) {
        showPanelContextMenu(panel, pos);
    });


    // 右键菜单入口。
    connect(panel.fileView, &QTreeView::customContextMenuRequested, this, [this, &panel](const QPoint& pos) {
        showPanelContextMenu(panel, pos);
    });

    // 选中变化时刷新状态栏。
    connect(panel.fileView->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this, &panel](const QItemSelection&, const QItemSelection&) {
        updatePanelStatus(panel);
    });

    // 模型目录加载完成后更新状态栏，提示当前目录数据可见。
    connect(panel.fsModel, &QFileSystemModel::directoryLoaded, this, [this, &panel](const QString&) {
        updatePanelStatus(panel);
        if (!currentModeIsManual(panel) && panel.fileView != nullptr && panel.sortModeCombo != nullptr)
        {
            int sortColumn = 0;
            switch (panel.sortModeCombo->currentIndex())
            {
            case 1:
                sortColumn = 1;
                break;
            case 2:
                sortColumn = 3;
                break;
            case 3:
                sortColumn = 2;
                break;
            default:
                sortColumn = 0;
                break;
            }
            panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);
        }
        selectPendingPath(panel);
    });

    // Alt+D：快速切换到路径编辑模式，行为与常见文件管理器保持一致。
    QShortcut* editPathShortcut = new QShortcut(QKeySequence(Qt::ALT | Qt::Key_D), panel.rootWidget);
    connect(editPathShortcut, &QShortcut::activated, this, [this, &panel]() {
        setPathEditMode(panel, true);
    });

    // Enter 快捷键：打开选中项。
    QShortcut* openShortcut = new QShortcut(QKeySequence(Qt::Key_Return), panel.fileView);
    openShortcut->setContext(Qt::WidgetShortcut);
    connect(openShortcut, &QShortcut::activated, this, [this, &panel]() {
        openSelectedItems(panel);
    });
    QShortcut* openShortcutEnter = new QShortcut(QKeySequence(Qt::Key_Enter), panel.fileView);
    openShortcutEnter->setContext(Qt::WidgetShortcut);
    connect(openShortcutEnter, &QShortcut::activated, this, [this, &panel]() {
        openSelectedItems(panel);
    });

    // F2 重命名快捷键。
    QShortcut* renameShortcut = new QShortcut(QKeySequence(Qt::Key_F2), panel.fileView);
    renameShortcut->setContext(Qt::WidgetShortcut);
    connect(renameShortcut, &QShortcut::activated, this, [this, &panel]() {
        renameSelectedItem(panel);
    });

    // Delete 删除快捷键。
    QShortcut* deleteShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), panel.fileView);
    deleteShortcut->setContext(Qt::WidgetShortcut);
    connect(deleteShortcut, &QShortcut::activated, this, [this, &panel]() {
        deleteSelectedItem(panel);
    });

    // Ctrl+C 必须保持“无副作用”：资源管理器里它只把内容放进剪贴板，
    // 真正落盘要等 Ctrl+V。此前这里绑的是“立即复制到对侧面板”，
    // 按下即写入目标目录且无确认，与用户预期完全相反；Ctrl+X 更是
    // 直接移动源文件。现改为复制所选路径到剪贴板，并解绑 Ctrl+X。
    // 面板间传输仍可用右键菜单的“复制到对侧面板/移动到对侧面板”，
    // 那里的名字已经明确说明了动作与目标。
    QShortcut* copyShortcut = new QShortcut(QKeySequence::Copy, panel.fileView);
    copyShortcut->setContext(Qt::WidgetShortcut);
    connect(copyShortcut, &QShortcut::activated, this, [this, &panel]() {
        copySelectedItemPath(panel);
    });

    // QListView 使用自己的 WidgetShortcut，避免把 Enter/Delete 等按键扩散到地址栏和过滤输入框。
    const auto bindCompactShortcut =
        [this, &panel](const QKeySequence& keySequence, const auto& handler)
        {
            QShortcut* shortcut = new QShortcut(keySequence, panel.compactFileView);
            shortcut->setContext(Qt::WidgetShortcut);
            connect(shortcut, &QShortcut::activated, this, handler);
        };
    bindCompactShortcut(QKeySequence(Qt::Key_Return), [this, &panel]() { openSelectedItems(panel); });
    bindCompactShortcut(QKeySequence(Qt::Key_Enter), [this, &panel]() { openSelectedItems(panel); });
    bindCompactShortcut(QKeySequence(Qt::Key_F2), [this, &panel]() { renameSelectedItem(panel); });
    bindCompactShortcut(QKeySequence(Qt::Key_Delete), [this, &panel]() { deleteSelectedItem(panel); });
    bindCompactShortcut(QKeySequence::Copy, [this, &panel]() { copySelectedItemPath(panel); });

}

void FileDock::navigateToPath(FilePanelWidgets& panel, const QString& pathText, bool recordHistory,
    const QString& selectionPath)
{
    {
        kLogEvent event;
        info << event
            << "[FileDock] 导航请求, panel="
            << panel.panelNameText.toStdString()
            << ", input="
            << QDir::toNativeSeparators(pathText).toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    // 去除空白并标准化路径格式，避免历史里混入重复写法。
    const QString trimmedPath = pathText.trimmed();
    if (trimmedPath.isEmpty())
    {
        kLogEvent event;
        warn << event
            << "[FileDock] 导航取消：输入路径为空, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    QString normalizedPath = QDir::cleanPath(QDir::fromNativeSeparators(trimmedPath));

    // 允许用户直接输入裸盘符（如 D:）后跳转到盘根目录。
    if (normalizedPath.size() == 2
        && normalizedPath.at(1) == QChar(':')
        && normalizedPath.at(0).isLetter())
    {
        normalizedPath += QDir::separator();
    }

    const auto generation = ++panel.navigationGeneration;
    if (!panel.navigationOperation) panel.navigationOperation = new ks::ui::AsyncOperation(this);
    const bool left = &panel == &m_leftPanel;
    panel.pathStatusLabel->setText(ks::i18n::displayText(QStringLiteral("正在加载...")));
    panel.navigationOperation->submit<FileNavigationRequest, FileNavigationResult>(
        { normalizedPath, panel.currentPath }, probeFileNavigation,
        [this, left, recordHistory, generation, selectionPath](const FileNavigationResult& result, std::uint64_t ticket)
        {
            FilePanelWidgets& target = left ? m_leftPanel : m_rightPanel;
            if (target.navigationGeneration != generation) return true;
            const QPointer<FileDock> self(this);
            const auto commit = [self, left, recordHistory, generation, ticket, result, selectionPath]()
            {
                if (!self) return;
                FilePanelWidgets& current = left ? self->m_leftPanel : self->m_rightPanel;
                if (current.navigationGeneration == generation && current.navigationOperation->isCurrent(ticket))
                {
                    if (!result.exists)
                    {
                        self->updatePanelStatus(current);
                        QMessageBox::warning(self, QStringLiteral("路径无效"), QStringLiteral("目录不存在：%1").arg(result.path));
                    }
                    else self->commitFileNavigation(current, result.path, result.parentOfPrevious, recordHistory, selectionPath);
                }
                if (self) current.navigationOperation->completeDeferred(ticket);
            };
            if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this,
                left ? QStringLiteral("file-navigation-left") : QStringLiteral("file-navigation-right"),
                { target.fileView, target.compactFileView }, commit)) return false;
            commit();
            return true;
        },
        [this, left, generation](std::exception_ptr)
        {
            FilePanelWidgets& target = left ? m_leftPanel : m_rightPanel;
            if (target.navigationGeneration == generation) updatePanelStatus(target);
            kLogEvent event; warn << event << "[FileDock] navigation probe failed" << eol;
        });
}

void FileDock::commitFileNavigation(FilePanelWidgets& panel, const QString& normalizedPath,
    const QString& parentOfPrevious, const bool recordHistory, const QString& selectionPath)
{
    const QString previousPath = panel.currentPath;
    panel.pendingSelectionPath.clear();
    if (!previousPath.isEmpty() && pathEqualsCaseInsensitive(parentOfPrevious, normalizedPath))
        panel.pendingSelectionPath = previousPath;
    if (!selectionPath.isEmpty()
        && pathEqualsCaseInsensitive(QFileInfo(selectionPath).absolutePath(), normalizedPath))
        panel.pendingSelectionPath = selectionPath;

    // 根据当前读取模式更新模型根路径。
    if (currentModeIsManual(panel))
    {
        // 手动解析模式使用平铺模型，根索引固定为无效索引。
        panel.fileView->setRootIndex(QModelIndex());
        panel.compactFileView->setRootIndex(QModelIndex());
    }
    else
    {
        const QModelIndex sourceRootIndex = panel.fsModel->setRootPath(normalizedPath);
        const QModelIndex proxyRootIndex = panel.proxyModel->mapFromSource(sourceRootIndex);
        panel.fileView->setRootIndex(proxyRootIndex);
        panel.compactFileView->setRootIndex(proxyRootIndex);
    }
    panel.currentPath = normalizedPath;
    if (!pathEqualsCaseInsensitive(previousPath, normalizedPath))
    {
        panel.manualLastError.clear();
        if (currentModeIsManual(panel) && panel.fileView->selectionModel())
            panel.fileView->selectionModel()->clear();
    }
    panel.pathEdit->setText(QDir::toNativeSeparators(normalizedPath));
    refreshDriveCombo(panel);

    // 记录历史：当用户主动导航时清理“前进分支”再追加。
    if (recordHistory)
    {
        if (panel.historyIndex + 1 < static_cast<int>(panel.history.size()))
        {
            panel.history.erase(
                panel.history.begin() + panel.historyIndex + 1,
                panel.history.end());
        }

        if (panel.history.empty() || panel.history.back() != normalizedPath)
        {
            panel.history.push_back(normalizedPath);
            panel.historyIndex = static_cast<int>(panel.history.size()) - 1;
        }
        else
        {
            panel.historyIndex = static_cast<int>(panel.history.size()) - 1;
        }
    }

    // 同步按钮可用性状态。
    const bool canGoBack = panel.historyIndex > 0;
    const bool canGoForward = panel.historyIndex >= 0
        && (panel.historyIndex + 1) < static_cast<int>(panel.history.size());
    panel.backButton->setEnabled(canGoBack);
    panel.forwardButton->setEnabled(canGoForward);

    // 导航后更新面包屑、过滤排序和状态栏。
    rebuildBreadcrumb(panel);
    setPathEditMode(panel, false);
    applyPanelFilterAndSort(panel);
    selectPendingPath(panel);
    QTimer::singleShot(0, this, [this, &panel]() {
        selectPendingPath(panel);
    });
    updatePanelStatus(panel);

    {
        kLogEvent event;
        info << event
            << "[FileDock] 导航成功, panel="
            << panel.panelNameText.toStdString()
            << ", normalizedPath="
            << QDir::toNativeSeparators(normalizedPath).toStdString()
            << ", historySize="
            << panel.history.size()
            << ", historyIndex="
            << panel.historyIndex
            << eol;
    }
}

void FileDock::refreshPanel(FilePanelWidgets& panel)
{
    {
        kLogEvent event;
        dbg << event
            << "[FileDock] 刷新面板, panel="
            << panel.panelNameText.toStdString()
            << ", currentPath="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    // 没有当前目录时回到系统根路径，保证面板始终可用。
    if (panel.currentPath.isEmpty())
    {
        navigateToPath(panel, QDir::rootPath(), true);
        return;
    }

    QAbstractItemView* const view = panel.fileViewStack != nullptr
        && panel.fileViewStack->currentWidget() == panel.compactFileView
        ? static_cast<QAbstractItemView*>(panel.compactFileView) : panel.fileView;
    const QString refreshedPath = panel.currentPath;
    const QString refreshedFilter = panel.filterEdit->text();
    const int refreshedViewMode = panel.viewModeCombo->currentIndex();
    const int refreshedSortMode = panel.sortModeCombo->currentIndex();
    const int refreshedReadMode = panel.readModeCombo->currentIndex();
    auto* scrollState = new FileRefreshScrollState(view, refreshedPath,
        [this, &panel, refreshedPath, refreshedFilter, refreshedViewMode,
         refreshedSortMode, refreshedReadMode, view]() {
            QAbstractItemView* const activeView = panel.fileViewStack != nullptr
                && panel.fileViewStack->currentWidget() == panel.compactFileView
                ? static_cast<QAbstractItemView*>(panel.compactFileView) : panel.fileView;
            return activeView == view
                && panel.filterEdit->text() == refreshedFilter
                && panel.viewModeCombo->currentIndex() == refreshedViewMode
                && panel.sortModeCombo->currentIndex() == refreshedSortMode
                && panel.readModeCombo->currentIndex() == refreshedReadMode
                && pathEqualsCaseInsensitive(panel.currentPath, refreshedPath);
        });

    // 复用导航逻辑触发模型重载，不写历史避免污染。
    if (currentModeIsManual(panel))
    {
        scrollState->waitForModel(panel.manualModel);
        panel.manualLoadedPath.clear();
    }
    else
    {
        recreateFileSystemModel(panel);
        scrollState->waitForModel(panel.fsModel);
    }
    navigateToPath(panel, panel.currentPath, false);
}

void FileDock::rebuildBreadcrumb(FilePanelWidgets& panel)
{
    if (panel.breadcrumbLayout == nullptr)
    {
        return;
    }

    {
        kLogEvent event;
        dbg << event
            << "[FileDock] 重建面包屑, panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    // 清理旧的面包屑按钮和分隔符，防止布局叠加。
    while (QLayoutItem* item = panel.breadcrumbLayout->takeAt(0))
    {
        if (QWidget* widget = item->widget())
        {
            widget->deleteLater();
        }
        delete item;
    }

    const QString nativePath = QDir::toNativeSeparators(panel.currentPath);
    if (nativePath.isEmpty())
    {
        return;
    }

    int crumbButtonCount = 0;
    QStringList pathParts = nativePath.split(QDir::separator(), Qt::SkipEmptyParts);
    QString runningPath;

    // Windows 驱动器路径（如 C:\）单独处理，保证首段可点击。
    if (nativePath.contains(':'))
    {
        const int colonIndex = nativePath.indexOf(':');
        if (colonIndex >= 0)
        {
            runningPath = nativePath.left(colonIndex + 1) + QDir::separator();
            QString driveText = runningPath;
            driveText.chop(1);

            QToolButton* driveButton = new QToolButton(panel.breadcrumbWidget);
            driveButton->setText(driveText);
            driveButton->setStyleSheet(buildBreadcrumbButtonStyle());
            driveButton->setToolTip(QStringLiteral("跳转到 %1").arg(driveText));
            panel.breadcrumbLayout->addWidget(driveButton, 0);
            crumbButtonCount += 1;
            connect(driveButton, &QToolButton::clicked, this, [this, &panel, runningPath]() {
                kLogEvent event;
                info << event
                    << "[FileDock] 面包屑跳转(盘符), panel="
                    << panel.panelNameText.toStdString()
                    << ", targetPath="
                    << QDir::toNativeSeparators(runningPath).toStdString()
                    << eol;
                navigateToPath(panel, runningPath, true);
            });

            if (!pathParts.isEmpty() && pathParts.front().contains(':'))
            {
                pathParts.removeFirst();
            }
        }
    }
    else if (nativePath.startsWith(QDir::separator()))
    {
        runningPath = QString(QDir::separator());
        QToolButton* rootButton = new QToolButton(panel.breadcrumbWidget);
        rootButton->setText(QStringLiteral("/"));
        rootButton->setStyleSheet(buildBreadcrumbButtonStyle());
        rootButton->setToolTip(QStringLiteral("跳转到根目录"));
        panel.breadcrumbLayout->addWidget(rootButton, 0);
        crumbButtonCount += 1;
        connect(rootButton, &QToolButton::clicked, this, [this, &panel]() {
            kLogEvent event;
            info << event
                << "[FileDock] 面包屑跳转(根目录), panel="
                << panel.panelNameText.toStdString()
                << eol;
            navigateToPath(panel, QString(QDir::separator()), true);
        });
    }

    // 逐段创建路径按钮，支持点击任意层级跳转。
    for (int i = 0; i < pathParts.size(); ++i)
    {
        const QString& part = pathParts.at(i);
        if (part.isEmpty())
        {
            continue;
        }

        if (!runningPath.isEmpty() && !runningPath.endsWith(QDir::separator()))
        {
            runningPath += QDir::separator();
        }
        runningPath += part;

        QLabel* sepLabel = new QLabel(QStringLiteral(">"), panel.breadcrumbWidget);
        sepLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::PrimaryBlueHex));
        panel.breadcrumbLayout->addWidget(sepLabel, 0);

        const QString capturePath = runningPath;
        QToolButton* partButton = new QToolButton(panel.breadcrumbWidget);
        partButton->setText(part);
        partButton->setStyleSheet(buildBreadcrumbButtonStyle());
        partButton->setToolTip(QStringLiteral("跳转到 %1").arg(capturePath));
        panel.breadcrumbLayout->addWidget(partButton, 0);
        crumbButtonCount += 1;
        connect(partButton, &QToolButton::clicked, this, [this, &panel, capturePath]() {
            kLogEvent event;
            info << event
                << "[FileDock] 面包屑跳转(路径段), panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(capturePath).toStdString()
                << eol;
            navigateToPath(panel, capturePath, true);
        });
    }

    // 面包屑末尾添加“透明热区”：
    // - 点击路径按钮=按段回退；
    // - 点击空白区域=切换到文本编辑模式。
    panel.breadcrumbEditTriggerButton = new QPushButton(panel.breadcrumbWidget);
    panel.breadcrumbEditTriggerButton->setFlat(true);
    panel.breadcrumbEditTriggerButton->setCursor(Qt::IBeamCursor);
    panel.breadcrumbEditTriggerButton->setToolTip(QStringLiteral("点击空白区域编辑路径"));
    ks::ui::ApplyFlatButtonTheme(panel.breadcrumbEditTriggerButton);
    panel.breadcrumbLayout->addWidget(panel.breadcrumbEditTriggerButton, 1);
    connect(panel.breadcrumbEditTriggerButton, &QPushButton::clicked, this, [this, &panel]() {
        kLogEvent event;
        info << event
            << "[FileDock] 点击面包屑空白区进入路径编辑, panel="
            << panel.panelNameText.toStdString()
            << eol;
        setPathEditMode(panel, true);
    });

    {
        kLogEvent event;
        dbg << event
            << "[FileDock] 面包屑重建完成, panel="
            << panel.panelNameText.toStdString()
            << ", breadcrumbButtonCount="
            << crumbButtonCount
            << eol;
    }
}

void FileDock::setPathEditMode(FilePanelWidgets& panel, bool editMode)
{
    if (panel.pathStack == nullptr || panel.pathEdit == nullptr || panel.breadcrumbWidget == nullptr)
    {
        return;
    }

    if (panel.pathEditMode == editMode)
    {
        return;
    }

    panel.pathEditMode = editMode;
    if (editMode)
    {
        panel.pathStack->setCurrentWidget(panel.pathEdit);
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        panel.pathEdit->setFocus();
        panel.pathEdit->selectAll();
    }
    else
    {
        panel.pathStack->setCurrentWidget(panel.breadcrumbWidget);
        panel.pathEdit->clearFocus();
    }

    kLogEvent event;
    dbg << event
        << "[FileDock] 地址栏显示模式切换, panel="
        << panel.panelNameText.toStdString()
        << ", mode="
        << (editMode ? "edit" : "breadcrumb")
        << eol;
}

bool FileDock::fileResultActionsReady(const FilePanelWidgets& panel) const
{
    return !currentModeIsManual(panel)
        || (!panel.manualDisplayedPath.isEmpty()
            && pathEqualsCaseInsensitive(panel.manualDisplayedPath, panel.currentPath)
            && panel.readModeCombo && panel.manualDisplayedReadMode == panel.readModeCombo->currentIndex()
            && !panel.manualParseInProgress && !panel.manualParseResultPending
            && panel.manualLastError.isEmpty());
}

void FileDock::updateManualResultStatus(FilePanelWidgets& panel)
{
    if (!currentModeIsManual(panel) || !panel.parserStatusLabel) return;
    const auto translated = [](const char* source) { return ks::i18n::sourceText(QString::fromUtf8(source)); };
    const QString requested = QDir::toNativeSeparators(panel.currentPath);
    const QString method = parseBackendDisplayText(manualParseBackendForPanel(panel));
    const bool loading = panel.manualParseInProgress || panel.manualParseResultPending;
    const bool hasSnapshot = !panel.manualDisplayedPath.isEmpty();
    QString detail = translated("请求：%1；读取方式：%2。").arg(requested, method);
    if (hasSnapshot)
        detail += QLatin1Char('\n') + translated("显示结果：%1；来源：%2；采集于 %3。")
            .arg(QDir::toNativeSeparators(panel.manualDisplayedPath),
                ks::i18n::displayText(panel.manualSourceDetail), panel.manualSampledAt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
    if (!panel.manualLastError.isEmpty())
        detail += QLatin1Char('\n') + translated("读取失败：%1。点击刷新重试，也可切换读取方式或导航到其他目录。")
            .arg(ks::i18n::displayText(panel.manualLastError));
    if (panel.manualResultPartial && hasSnapshot)
        detail += QLatin1Char('\n') + translated("显示的结果不完整。");
    if (!fileResultActionsReady(panel))
        detail += QLatin1Char('\n') + translated("当前结果尚不能用于文件操作；刷新和目录导航仍可用。");
    panel.parserStatusLabel->setToolTip(detail);
    // Keep the status bar compact; the path label shows the immutable source
    // and the tooltip preserves the complete request and failure receipt.
    panel.parserStatusLabel->setText(!panel.manualLastError.isEmpty()
        ? translated("读取失败；点击刷新重试")
        : loading ? translated("正在读取；旧结果操作已暂停")
        : !fileResultActionsReady(panel) ? translated("结果与当前请求不一致")
        : panel.manualResultPartial ? translated("结果不完整")
        : translated("解析器: %1").arg(ks::i18n::displayText(panel.manualSourceDetail)));
    if (hasSnapshot)
        panel.pathStatusLabel->setText(translated("结果路径：%1；请求路径：%2")
            .arg(QDir::toNativeSeparators(panel.manualDisplayedPath), requested));
    panel.pathStatusLabel->setToolTip(detail);
}

void FileDock::updatePanelStatus(FilePanelWidgets& panel)
{
    // 路径状态：直接显示当前目录。
    panel.pathStatusLabel->setText(QStringLiteral("路径: %1").arg(QDir::toNativeSeparators(panel.currentPath)));
    panel.pathStatusLabel->setToolTip(QDir::toNativeSeparators(panel.currentPath));
    if (currentModeIsManual(panel)) updateManualResultStatus(panel);

    // 统计只读枚举模型缓存，不能对每个选中路径重新查盘。
    QModelIndexList selectedRows = panel.fileView->selectionModel()->selectedRows(0);
    if (selectedRows.isEmpty() && panel.fileView->currentIndex().isValid())
        selectedRows.push_back(panel.fileView->currentIndex().siblingAtColumn(0));
    std::uint64_t totalSize = 0;
    const bool manualMode = currentModeIsManual(panel);
    for (const QModelIndex& proxyIndex : selectedRows)
    {
        const QModelIndex sourceIndex = manualMode
            ? panel.manualProxyModel->mapToSource(proxyIndex)
            : panel.proxyModel->mapToSource(proxyIndex);
        if (!sourceIndex.isValid())
            continue;
        if (manualMode)
        {
            if (!sourceIndex.data(Qt::UserRole + 1).toBool())
                totalSize += sourceIndex.siblingAtColumn(1).data(Qt::UserRole).toULongLong();
        }
        else if (!panel.fsModel->isDir(sourceIndex))
        {
            totalSize += static_cast<std::uint64_t>(std::max<qint64>(0, panel.fsModel->size(sourceIndex)));
        }
    }
    const qsizetype selectedCount = selectedRows.size();
    panel.selectionStatusLabel->setText(
        QStringLiteral("选中: %1  大小: %2%3")
        .arg(selectedCount).arg(formatSizeText(totalSize)).arg(QString()));

    const int statusSerial = ++panel.statusRequestSerial;
    if (!panel.statusQueryInProgress)
    {
        panel.statusQueryInProgress = true;
        const QString currentPath = panel.currentPath;
        QString singlePath;
        if (selectedCount == 1)
        {
            const QModelIndex sourceIndex = manualMode
                ? panel.manualProxyModel->mapToSource(selectedRows.front())
                : panel.proxyModel->mapToSource(selectedRows.front());
            singlePath = manualMode ? sourceIndex.data(Qt::UserRole).toString()
                : panel.fsModel->filePath(sourceIndex);
        }
        const bool leftPanel = (&panel == &m_leftPanel);
        QPointer<FileDock> guard(this);
        QThreadPool::globalInstance()->start(QRunnable::create(
            [guard, leftPanel, currentPath, singlePath, statusSerial, selectedCount, totalSize]() {
                QStringList attrs;
                if (!singlePath.isEmpty())
                {
                    const QFileInfo info(singlePath);
                    if (!info.isWritable()) attrs.push_back(QStringLiteral("只读"));
                    if (info.isHidden()) attrs.push_back(QStringLiteral("隐藏"));
                    if (info.isSymLink()) attrs.push_back(QStringLiteral("链接"));
                }
                const QStorageInfo storage(currentPath);
                const bool ready = storage.isValid() && storage.isReady();
                const qint64 available = storage.bytesAvailable();
                const qint64 total = storage.bytesTotal();
                QMetaObject::invokeMethod(qApp,
                    [guard, leftPanel, statusSerial, selectedCount, totalSize, attrs,
                     ready, available, total]() {
                        if (!guard)
                            return;
                        auto& target = leftPanel ? guard->m_leftPanel : guard->m_rightPanel;
                        target.statusQueryInProgress = false;
                        if (target.statusRequestSerial != statusSerial)
                        {
                            // 查询期间选区或路径已变：合并中间请求，只补查当前状态。
                            guard->updatePanelStatus(target);
                            return;
                        }
                        const QString attributeHint = attrs.isEmpty() ? QString() :
                            QStringLiteral(" [%1]").arg(attrs.join(','));
                        target.selectionStatusLabel->setText(
                            QStringLiteral("选中: %1  大小: %2%3")
                            .arg(selectedCount).arg(formatSizeText(totalSize)).arg(attributeHint));
                        target.diskStatusLabel->setText(ready
                            ? QStringLiteral("剩余: %1 / 总计: %2")
                                .arg(formatSizeText(static_cast<std::uint64_t>(std::max<qint64>(0, available))))
                                .arg(formatSizeText(static_cast<std::uint64_t>(std::max<qint64>(0, total))))
                            : QStringLiteral("磁盘: -"));
                    }, Qt::QueuedConnection);
            }));
    }

    // 状态日志去重：只有内容变化时输出，避免选区抖动造成日志风暴。
    const QString statusSignature = QStringLiteral("%1|%2|%3|%4")
        .arg(panel.currentPath)
        .arg(selectedCount)
        .arg(static_cast<qulonglong>(totalSize))
        .arg(panel.diskStatusLabel->text());
    if (statusSignature != panel.lastStatusLogSignature)
    {
        panel.lastStatusLogSignature = statusSignature;
        kLogEvent event;
        dbg << event
            << "[FileDock] 状态栏更新, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << selectedCount
            << ", selectedBytes="
            << static_cast<qulonglong>(totalSize)
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }
}

void FileDock::selectPendingPath(FilePanelWidgets& panel)
{
    if (!fileResultActionsReady(panel)) return;
    if (panel.pendingSelectionPath.isEmpty() ||
        panel.fileView == nullptr ||
        panel.fileView->selectionModel() == nullptr)
    {
        return;
    }

    QModelIndex proxyIndex;
    if (currentModeIsManual(panel))
    {
        if (panel.manualModel == nullptr || panel.manualProxyModel == nullptr)
        {
            return;
        }

        for (int row = 0; row < panel.manualModel->rowCount(); ++row)
        {
            const QModelIndex sourcePathIndex = panel.manualModel->index(
                row,
                static_cast<int>(ManualModelColumn::FullPath));
            if (!sourcePathIndex.isValid() ||
                !pathEqualsCaseInsensitive(
                    sourcePathIndex.data(Qt::DisplayRole).toString(),
                    panel.pendingSelectionPath))
            {
                continue;
            }

            const QModelIndex sourceNameIndex = panel.manualModel->index(
                row,
                static_cast<int>(ManualModelColumn::Name));
            proxyIndex = panel.manualProxyModel->mapFromSource(sourceNameIndex);
            break;
        }
    }
    else if (panel.fsModel != nullptr && panel.proxyModel != nullptr)
    {
        const QModelIndex sourceIndex = panel.fsModel->index(panel.pendingSelectionPath);
        if (sourceIndex.isValid())
        {
            proxyIndex = panel.proxyModel->mapFromSource(sourceIndex);
        }
    }

    // 目录还没有进入代理模型时保留 pendingSelectionPath，等待
    // QFileSystemModel::directoryLoaded 或手动解析异步回填再次尝试。
    if (!proxyIndex.isValid())
    {
        return;
    }

    QItemSelectionModel* const selectionModel = panel.fileView->selectionModel();
    selectionModel->select(
        proxyIndex,
        QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    selectionModel->setCurrentIndex(proxyIndex, QItemSelectionModel::NoUpdate);
    panel.fileView->scrollTo(proxyIndex, QAbstractItemView::EnsureVisible);
    if (panel.compactFileView != nullptr)
    {
        panel.compactFileView->scrollTo(proxyIndex, QAbstractItemView::EnsureVisible);
    }
    panel.pendingSelectionPath.clear();
}

void FileDock::applyPanelFilterAndSort(FilePanelWidgets& panel)
{
    const bool manualMode = currentModeIsManual(panel);
    if (auto* modes = qobject_cast<QStandardItemModel*>(panel.viewModeCombo->model())) {
        if (auto* treeMode = modes->item(3)) {
            treeMode->setEnabled(!manualMode);
            treeMode->setToolTip(manualMode ? ks::i18n::sourceText(QStringLiteral(
                "当前解析方式只提供当前目录列表；树形视图需要 Windows API 模式。")) : QString());
        }
    }
    if (manualMode && panel.viewModeCombo->currentIndex() == 3) {
        const QSignalBlocker blocker(panel.viewModeCombo);
        panel.viewModeCombo->setCurrentIndex(2);
    }
    const int modeIndex = panel.viewModeCombo->currentIndex();
    const QString filterText = panel.filterEdit->text().trimmed();

    // 图标/列表使用 QListView 的真实布局；详情/树形保留 QTreeView 的多列与层级能力。
    const bool compactMode = (modeIndex == 0 || modeIndex == 1);
    if (compactMode)
    {
        panel.fileViewStack->setCurrentWidget(panel.compactFileView);
        panel.compactFileView->setTextElideMode(Qt::ElideMiddle);
        if (modeIndex == 0)
        {
            panel.compactFileView->setViewMode(QListView::IconMode);
            panel.compactFileView->setResizeMode(QListView::Adjust);
            panel.compactFileView->setMovement(QListView::Static);
            panel.compactFileView->setFlow(QListView::LeftToRight);
            panel.compactFileView->setWrapping(true);
            panel.compactFileView->setGridSize(QSize(128, 96));
            panel.compactFileView->setSpacing(6);
            panel.compactFileView->setWordWrap(true);
            panel.compactFileView->setUniformItemSizes(true);
            panel.compactFileView->setIconSize(QSize(48, 48));
        }
        else
        {
            panel.compactFileView->setViewMode(QListView::ListMode);
            panel.compactFileView->setResizeMode(QListView::Adjust);
            panel.compactFileView->setMovement(QListView::Static);
            panel.compactFileView->setFlow(QListView::TopToBottom);
            panel.compactFileView->setWrapping(false);
            panel.compactFileView->setGridSize(QSize());
            panel.compactFileView->setSpacing(2);
            panel.compactFileView->setWordWrap(false);
            panel.compactFileView->setUniformItemSizes(true);
            panel.compactFileView->setIconSize(QSize(20, 20));
        }
    }
    else
    {
        panel.fileViewStack->setCurrentWidget(panel.fileView);
    }

    if (manualMode)
    {
        // 手动模式下仅在“当前路径未加载且未在解析”时才拉起新任务，
        // 避免过滤/排序改动触发同一路径重复全盘扫描。
        const bool loadedMatchesCurrentPath =
            (panel.manualLoadedPath.compare(panel.currentPath, Qt::CaseInsensitive) == 0);
        const bool samePathParsing =
            panel.manualParseInProgress
            && panel.manualParseCanceled && !panel.manualParseCanceled->load()
            && panel.manualParsingReadMode == panel.readModeCombo->currentIndex()
            && (panel.manualParsingPath.compare(panel.currentPath, Qt::CaseInsensitive) == 0);
        if (!loadedMatchesCurrentPath && !samePathParsing)
        {
            requestAsyncManualReload(panel, false);
        }

        if (filterText.isEmpty())
        {
            panel.manualProxyModel->setFilterRegularExpression(QRegularExpression());
        }
        else
        {
            const QString pattern = QStringLiteral(".*%1.*").arg(QRegularExpression::escape(filterText));
            panel.manualProxyModel->setFilterRegularExpression(
                QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption));
        }

        int sortColumn = static_cast<int>(ManualModelColumn::Name);
        switch (panel.sortModeCombo->currentIndex())
        {
        case 1:
            sortColumn = static_cast<int>(ManualModelColumn::Size);
            break;
        case 2:
            sortColumn = static_cast<int>(ManualModelColumn::ModifiedTime);
            break;
        case 3:
            sortColumn = static_cast<int>(ManualModelColumn::Type);
            break;
        default:
            sortColumn = static_cast<int>(ManualModelColumn::Name);
            break;
        }
        panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);

        const bool showDetailColumns = (modeIndex == 2 || modeIndex == 3);
        panel.fileView->setIconSize(modeIndex == 0 ? QSize(32, 32) : QSize(18, 18));
        panel.fileView->setRootIsDecorated(false);
        panel.fileView->setItemsExpandable(false);
        panel.fileView->setIndentation(10);

        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::Size), !showDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::Type), !showDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::ModifiedTime), !showDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::FullPath), true);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::IsDirectory), true);
    }
    else
    {
        // 组合模型过滤标志：按用户勾选决定是否显示隐藏/系统文件。
        QDir::Filters filters = QDir::AllEntries | QDir::NoDotAndDotDot;
        if (panel.showHiddenCheck->isChecked())
        {
            filters |= QDir::Hidden;
        }
        if (panel.showSystemCheck->isChecked())
        {
            filters |= QDir::System;
        }
        panel.fsModel->setFilter(filters);

        if (filterText.isEmpty())
        {
            panel.fsModel->setNameFilters(QStringList());
        }
        else
        {
            panel.fsModel->setNameFilters(QStringList{
                buildLiteralNameFilterPattern(filterText)
                });
        }
        // Windows API 模式改由 QFileSystemModel 执行名称过滤，代理层只保留排序职责。
        panel.proxyModel->setFilterRegularExpression(QRegularExpression());

        int sortColumn = 0;
        switch (panel.sortModeCombo->currentIndex())
        {
        case 1:
            sortColumn = 1;
            break;
        case 2:
            sortColumn = 3;
            break;
        case 3:
            sortColumn = 2;
            break;
        default:
            sortColumn = 0;
            break;
        }
        panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);

        const bool showDetailColumns = (modeIndex == 2 || modeIndex == 3);
        panel.fileView->setIconSize(modeIndex == 0 ? QSize(32, 32) : QSize(18, 18));
        panel.fileView->setRootIsDecorated(modeIndex == 3);
        panel.fileView->setItemsExpandable(modeIndex == 3);
        panel.fileView->setIndentation(modeIndex == 3 ? 18 : 10);
        for (int column = 1; column < panel.fsModel->columnCount(); ++column)
        {
            panel.fileView->setColumnHidden(column, !showDetailColumns);
        }
        if (modeIndex == 1)
        {
            panel.fileView->setRootIsDecorated(false);
            panel.fileView->setItemsExpandable(false);
        }
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(QStringLiteral("解析器: Windows API"));
            panel.parserStatusLabel->setToolTip(QString());
        }
    }

    // 过滤参数日志去重：仅在用户真实调整条件时输出详细参数。
    const QString filterSignature = QStringLiteral("%1|%2|%3|%4|%5|%6")
        .arg(panel.showHiddenCheck->isChecked() ? 1 : 0)
        .arg(panel.showSystemCheck->isChecked() ? 1 : 0)
        .arg(panel.sortModeCombo->currentIndex())
        .arg(panel.viewModeCombo->currentIndex())
        .arg(panel.readModeCombo->currentIndex())
        .arg(panel.filterEdit->text());
    if (filterSignature != panel.lastFilterLogSignature)
    {
        panel.lastFilterLogSignature = filterSignature;
        kLogEvent event;
        info << event
            << "[FileDock] 过滤/排序参数变更, panel="
            << panel.panelNameText.toStdString()
            << ", showHidden="
            << (panel.showHiddenCheck->isChecked() ? "true" : "false")
            << ", showSystem="
            << (panel.showSystemCheck->isChecked() ? "true" : "false")
            << ", sortModeIndex="
            << panel.sortModeCombo->currentIndex()
            << ", viewModeIndex="
            << panel.viewModeCombo->currentIndex()
            << ", readModeIndex="
            << panel.readModeCombo->currentIndex()
            << ", keyword="
            << panel.filterEdit->text().toStdString()
            << eol;
    }

    updatePanelStatus(panel);
}

void FileDock::refreshDriveCombo(FilePanelWidgets& panel)
{
    if (panel.driveCombo == nullptr)
    {
        return;
    }

    const QSignalBlocker blocker(panel.driveCombo);
    panel.driveCombo->clear();

    const QFileInfoList driveList = QDir::drives();
    int selectedIndex = -1;
    for (const QFileInfo& driveInfo : driveList)
    {
        const QString rootPath = QDir::toNativeSeparators(driveInfo.absoluteFilePath());
        QString displayText = rootPath;
        if (displayText.endsWith(QDir::separator()))
        {
            displayText.chop(1);
        }
        panel.driveCombo->addItem(displayText, rootPath);

        if (!panel.currentPath.isEmpty()
            && panel.currentPath.startsWith(driveInfo.absoluteFilePath(), Qt::CaseInsensitive))
        {
            selectedIndex = panel.driveCombo->count() - 1;
        }
    }

    if (selectedIndex >= 0)
    {
        panel.driveCombo->setCurrentIndex(selectedIndex);
    }
}

void FileDock::applyReadModeToPanel(FilePanelWidgets& panel)
{
    if (panel.fileView == nullptr || panel.compactFileView == nullptr || panel.fileViewStack == nullptr)
    {
        return;
    }

    if (currentModeIsManual(panel))
    {
        panel.fileView->setModel(panel.manualProxyModel);
        panel.fileView->setRootIndex(QModelIndex());
        panel.compactFileView->setModel(panel.manualProxyModel);
        panel.compactFileView->setModelColumn(0);
        panel.compactFileView->setRootIndex(QModelIndex());
        panel.showHiddenCheck->setEnabled(false);
        panel.showSystemCheck->setEnabled(false);
        if (panel.parserStatusLabel != nullptr)
        {
            const ManualParseBackend backend = manualParseBackendForPanel(panel);
            if (backend == ManualParseBackend::ManualFs)
            {
                const ks::file::ManualFsType requestedFsType =
                    requestedManualFsTypeForPanel(panel);
                panel.parserStatusLabel->setText(
                    requestedFsType == ks::file::ManualFsType::Unknown
                    ? QStringLiteral("解析器: 手动解析")
                    : QStringLiteral("解析器: %1 (待解析)")
                        .arg(manualFsTypeToText(requestedFsType)));
            }
            else
            {
                panel.parserStatusLabel->setText(
                    QStringLiteral("解析器: %1 (待查询)")
                        .arg(parseBackendDisplayText(backend)));
            }
        }
    }
    else
    {
        if (panel.manualParseCanceled) panel.manualParseCanceled->store(true);
        panel.manualParsePending = false;
        panel.manualParsePendingShowWarning = false;
        panel.manualParseResultPending = false;
        panel.fileView->setModel(panel.proxyModel);
        panel.compactFileView->setModel(panel.proxyModel);
        panel.compactFileView->setModelColumn(0);
        panel.showHiddenCheck->setEnabled(true);
        panel.showSystemCheck->setEnabled(true);
        if (!panel.currentPath.isEmpty())
        {
            const QModelIndex sourceRootIndex = panel.fsModel->setRootPath(panel.currentPath);
            const QModelIndex proxyRootIndex = panel.proxyModel->mapFromSource(sourceRootIndex);
            panel.fileView->setRootIndex(proxyRootIndex);
            panel.compactFileView->setRootIndex(proxyRootIndex);
        }
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(QStringLiteral("解析器: Windows API"));
        }
    }

    configureFileViewSelection(panel);
    panel.fileView->header()->setStretchLastSection(false);
    panel.fileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    QItemSelectionModel* selectionModel = panel.fileView->selectionModel();
    QItemSelectionModel* compactSelectionModel = panel.compactFileView->selectionModel();
    panel.compactFileView->setSelectionModel(panel.fileView->selectionModel());
    if (compactSelectionModel != nullptr && compactSelectionModel != panel.fileView->selectionModel())
    {
        compactSelectionModel->deleteLater();
    }

    if (selectionModel != nullptr)
    {
        QObject::disconnect(selectionModel, nullptr, this, nullptr);
        connect(selectionModel, &QItemSelectionModel::selectionChanged, this, [this, &panel](const QItemSelection&, const QItemSelection&) {
            updatePanelStatus(panel);
        });
    }
}

void FileDock::configureFileViewSelection(FilePanelWidgets& panel)
{
    if (panel.fileView == nullptr)
    {
        return;
    }

    // 文件面板的批量删除、复制、剪切、R0 删除等动作都从 selectedRows(0) 收集路径。
    // 因此无论初始创建还是切换 Windows API/手动解析模型后，都必须保持“整行扩展多选”。
    panel.fileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    panel.fileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    panel.compactFileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    panel.compactFileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
}

void FileDock::recreateFileSystemModel(FilePanelWidgets& panel)
{
    if (panel.rootWidget == nullptr || panel.proxyModel == nullptr)
    {
        return;
    }

    // QFileSystemModel 对目录项元数据有缓存；同一路径 setRootPath() 往往不会重新读取文件大小。
    // 手动刷新时重建模型，保证 size/mtime 等列从磁盘重新枚举，同时代理模型和视图仍沿用原对象。
    QFileSystemModel* const oldModel = panel.fsModel;
    panel.fsModel = new ReparseAwareFileSystemModel(panel.rootWidget);
    panel.fsModel->setReadOnly(false);
    panel.fsModel->setResolveSymlinks(true);
    panel.fsModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    panel.fsModel->setNameFilterDisables(false);
    panel.proxyModel->setSourceModel(panel.fsModel);

    connect(panel.fsModel, &QFileSystemModel::directoryLoaded, this, [this, &panel](const QString&) {
        updatePanelStatus(panel);
    });

    if (oldModel != nullptr)
    {
        oldModel->deleteLater();
    }
}

void FileDock::requestAsyncManualReload(FilePanelWidgets& panel, const bool showWarningMessage)
{
    if (panel.manualModel == nullptr || panel.currentPath.isEmpty() || !currentModeIsManual(panel))
    {
        return;
    }

    // requestedPath：记录本次调用目标路径，避免在异步流程里读取到后续变更值。
    const QString requestedPath = panel.currentPath;
    const ks::file::ManualFsType requestedFsType = requestedManualFsTypeForPanel(panel);
    const int requestedReadMode = panel.readModeCombo != nullptr
        ? panel.readModeCombo->currentIndex()
        : 0;
    const ManualParseBackend parseBackend = manualParseBackendForPanel(panel);
    const bool driverMode = parseBackendIsKernel(parseBackend);
    const QString backendText = parseBackendDisplayText(parseBackend);

    // 路径已经加载且当前没有任务运行时，直接复用结果，避免无意义重复解析。
    if (!panel.manualParseInProgress
        && panel.manualLoadedPath.compare(requestedPath, Qt::CaseInsensitive) == 0
        && panel.manualRequestedFsType == requestedFsType
        && panel.manualRequestedReadMode == requestedReadMode)
    {
        if (panel.manualParseResultPending)
        {
            if (panel.manualParseCanceled) panel.manualParseCanceled->store(true);
            panel.manualParseResultPending = false;
        }
        updateManualResultStatus(panel);
        return;
    }

    const bool sameRequest =
        panel.manualParsingPath.compare(requestedPath, Qt::CaseInsensitive) == 0
        && panel.manualParsingReadMode == requestedReadMode
        && panel.manualParseCanceled && !panel.manualParseCanceled->load();
    if (panel.manualParseResultPending && sameRequest)
    {
        panel.manualParsePendingShowWarning |= showWarningMessage;
        return;
    }

    panel.manualRequestedFsType = requestedFsType;
    panel.manualRequestedReadMode = requestedReadMode;

    // 若已有后台任务在跑，仅在“目标请求发生变化”时登记 pending。
    // 判据必须连读取方式一起比：同一个目录换一种解析方式，结果是完全不同的
    // 两份数据（WinAPI 视图 / 纯 MFT 视图 / IRP 绕过视图）。只比路径会把
    // 换方式的请求当成重复请求丢掉，最终表格里留着旧后端的结果，
    // 下拉框却显示新方式——看起来就是"切了没反应"。
    if (panel.manualParseInProgress)
    {
        const bool samePathRunning =
            (panel.manualParsingPath.compare(requestedPath, Qt::CaseInsensitive) == 0)
            && (panel.manualParsingReadMode == requestedReadMode)
            && panel.manualParseCanceled && !panel.manualParseCanceled->load();
        if (samePathRunning)
        {
            panel.manualParsePendingShowWarning =
                panel.manualParsePendingShowWarning || showWarningMessage;
            return;
        }

        if (panel.manualParseCanceled) panel.manualParseCanceled->store(true);
        panel.manualParsePending = true;
        panel.manualParsePendingShowWarning = panel.manualParsePendingShowWarning || showWarningMessage;

        {
            kLogEvent event;
            dbg << event
                << "[FileDock] 手动解析任务排队, panel="
                << panel.panelNameText.toStdString()
                << ", runningPath="
                << QDir::toNativeSeparators(panel.manualParsingPath).toStdString()
                << ", pendingPath="
                << QDir::toNativeSeparators(requestedPath).toStdString()
                << eol;
        }
        return;
    }

    if (panel.manualParseCanceled) panel.manualParseCanceled->store(true);
    panel.manualParseCanceled = std::make_shared<std::atomic_bool>(false);
    const auto canceled = panel.manualParseCanceled;
    panel.manualParseResultPending = false;
    panel.manualParseInProgress = true;
    panel.manualParsePending = false;
    panel.manualParsePendingShowWarning = false;
    panel.manualParseRequestSerial += 1;
    panel.manualParsingPath = requestedPath;
    panel.manualParsingReadMode = requestedReadMode;
    panel.manualLastError.clear();
    // Selection from another request must never become an action on this
    // request merely because its address bar has already changed.
    if (panel.fileView && panel.fileView->selectionModel()) panel.fileView->selectionModel()->clear();

    // 记录请求上下文：用于后台线程回传时校验“结果是否过期”。
    const int requestSerial = panel.manualParseRequestSerial;
    const QString requestPath = requestedPath;
    const QString panelNameText = panel.panelNameText;
    const bool leftPanelRequest = (&panel == &m_leftPanel);

    // 平铺解析进度条：R3 原始解析与 R0 内核枚举共用同一套异步回填机制。
    const QString parserTaskText = QStringLiteral(" ") + backendText;
    const int progressPid = kPro.add(this, "文件", (panelNameText + parserTaskText).toStdString());
    kPro.set(progressPid, "准备解析目录", 0, 5.0f);

    if (panel.parserStatusLabel != nullptr)
    {
        panel.parserStatusLabel->setText(
            QStringLiteral("解析器: %1中...").arg(backendText));
    }
    updateManualResultStatus(panel);
    if (panel.readModeCombo != nullptr)
    {
        panel.readModeCombo->setEnabled(true);
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 启动异步平铺解析, source="
            << parseBackendLogTag(parseBackend)
            << ", panel="
            << panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(requestPath).toStdString()
            << ", requestSerial="
            << requestSerial
            << eol;
    }

    QPointer<FileDock> safeThis(this);
    const auto dispatcher = m_uiDispatcher;
    std::thread([safeThis, dispatcher, leftPanelRequest, requestPath, requestedFsType, requestedReadMode, parseBackend, driverMode, backendText, panelNameText, showWarningMessage, requestSerial, progressPid, canceled]() {
        kPro.set(
            progressPid,
            (backendText + QStringLiteral("目录中")).toStdString(),
            0,
            35.0f);

        const auto payload = makeBackgroundRetiredValue<ManualDirectoryParsePayload>(
            [](auto dispose) {
                QThreadPool::globalInstance()->start(QRunnable::create(std::move(dispose)));
            });
        auto& parsedEntries = payload->entries;
        ks::file::ManualFsType parsedFsType = ks::file::ManualFsType::Unknown;
        QString parseErrorText;
        // usedWinApiFallback：记录后台解析是否已退回到 Windows API，供 UI 正确显示状态。
        bool usedWinApiFallback = false;
        bool partialResult = false;
        QString sourceDetail;
        auto& suspiciousNames = payload->suspiciousNames;
        const bool parseOk = runManualParseBackend(
            parseBackend,
            requestPath,
            requestedFsType,
            parsedEntries,
            parsedFsType,
            parseErrorText,
            usedWinApiFallback,
            partialResult,
            sourceDetail,
            suspiciousNames,
            [canceled]() { return canceled->load(); });
        payload->sampledAt = QDateTime::currentDateTime();

        kPro.set(progressPid, parseOk ? "生成目录列表中" : "解析失败，整理错误信息", 0, 78.0f);
        if (!canceled->load())
            payload->suspiciousNameSet = buildSuspiciousNameSet(
                suspiciousNames, [canceled]() { return canceled->load(); });

        dispatcher->post(
            [safeThis,
             leftPanelRequest,
             requestPath,
             requestedFsType,
             requestedReadMode,
             parseBackend,
             driverMode,
             backendText,
             panelNameText,
             showWarningMessage,
             requestSerial,
             progressPid,
             parseOk,
             payload,
             canceled,
             parsedFsType,
             parseErrorText,
             usedWinApiFallback,
             partialResult,
             sourceDetail]() mutable {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                FilePanelWidgets& targetPanel = leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                if (targetPanel.manualParseCanceled == canceled)
                {
                    targetPanel.manualParseInProgress = false;
                    targetPanel.manualParseResultPending = true;
                }
                if (canceled->load() || targetPanel.manualParseCanceled != canceled ||
                    targetPanel.manualParseRequestSerial != requestSerial ||
                    targetPanel.currentPath.compare(requestPath, Qt::CaseInsensitive) != 0 ||
                    targetPanel.readModeCombo->currentIndex() != requestedReadMode)
                {
                    // 过期结果直接丢弃，避免“慢任务覆盖新路径数据”。
                    // 运行状态只有在这一批结果确实属于当前那次运行时才清：
                    // 路径不符说明面板已经在跑另一次解析，清了会让它误以为空闲。
                    if (targetPanel.manualParseCanceled == canceled)
                    {
                        targetPanel.manualParseInProgress = false;
                        targetPanel.manualParseResultPending = false;
                        targetPanel.manualParsingPath.clear();
                    }
                    // 读取方式保持可切换；取消只在后端安全边界生效。
                    if (targetPanel.readModeCombo != nullptr &&
                        !targetPanel.manualParseInProgress)
                    {
                        targetPanel.readModeCombo->setEnabled(true);
                    }

                    {
                        kLogEvent event;
                        warn << event
                            << "[FileDock] 丢弃过期平铺解析结果, source="
                            << parseBackendLogTag(parseBackend)
                            << ", panel="
                            << panelNameText.toStdString()
                            << ", path="
                            << QDir::toNativeSeparators(requestPath).toStdString()
                            << ", requestSerial="
                            << requestSerial
                            << ", currentSerial="
                            << targetPanel.manualParseRequestSerial
                            << eol;
                    }

                    kPro.set(progressPid, "结果过期已忽略", 0, 100.0f);

                    if (!targetPanel.manualParseInProgress && targetPanel.manualParsePending)
                    {
                        const bool pendingShowWarning = targetPanel.manualParsePendingShowWarning;
                        targetPanel.manualParsePending = false;
                        targetPanel.manualParsePendingShowWarning = false;
                        safeThis->requestAsyncManualReload(targetPanel, pendingShowWarning);
                    }
                    return;
                }

                const std::shared_ptr<const std::vector<ks::file::ManualDirectoryEntry>> parsedEntriesSnapshot(
                    payload, &payload->entries);
                const auto commitSnapshot =
                    [safeThis,
                     leftPanelRequest,
                     requestPath,
                     requestedFsType,
                     requestedReadMode,
                     parseBackend,
                     driverMode,
                     backendText,
                     panelNameText,
                     showWarningMessage,
                     requestSerial,
                     progressPid,
                     parseOk,
                     parsedEntriesSnapshot,
                     payload,
                     canceled,
                     parsedFsType,
                     parseErrorText,
                     usedWinApiFallback,
                     partialResult,
                     sourceDetail]()
                {
                    if (safeThis.isNull())
                    {
                        kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                        return;
                    }

                    FilePanelWidgets& commitPanel =
                        leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                    if (canceled->load() || commitPanel.manualParseCanceled != canceled ||
                        commitPanel.manualParseRequestSerial != requestSerial ||
                        commitPanel.currentPath.compare(requestPath, Qt::CaseInsensitive) != 0 ||
                        commitPanel.readModeCombo->currentIndex() != requestedReadMode)
                    {
                        if (commitPanel.manualParseCanceled == canceled)
                        {
                            commitPanel.manualParseInProgress = false;
                            commitPanel.manualParseResultPending = false;
                            commitPanel.manualParsingPath.clear();
                            commitPanel.readModeCombo->setEnabled(true);
                            const bool pendingWarning = commitPanel.manualParsePendingShowWarning;
                            commitPanel.manualParsePending = false;
                            commitPanel.manualParsePendingShowWarning = false;
                            safeThis->requestAsyncManualReload(commitPanel, pendingWarning);
                        }
                        kPro.set(progressPid, "结果过期已忽略", 0, 100.0f);
                        return;
                    }

                    const bool warnOnFailure = showWarningMessage || commitPanel.manualParsePendingShowWarning;
                    commitPanel.manualParsePendingShowWarning = false;
                    commitPanel.manualParseInProgress = false;
                    commitPanel.manualParseResultPending = false;
                    commitPanel.manualParsingPath.clear();
                    commitPanel.manualRequestedFsType = requestedFsType;
                    commitPanel.manualRequestedReadMode = requestedReadMode;
                    if (commitPanel.readModeCombo != nullptr)
                    {
                        commitPanel.readModeCombo->setEnabled(true);
                    }


                    commitPanel.lastManualFsType = parsedFsType;

                    if (!parseOk)
                    {
                        commitPanel.manualLastError = parseErrorText.isEmpty()
                            ? QStringLiteral("读取失败，未取得错误详情。") : parseErrorText;
                        // 失败时也记住路径，避免过滤/排序触发连续重试。
                        commitPanel.manualLoadedPath = requestPath;
                        if (commitPanel.parserStatusLabel != nullptr)
                        {
                            commitPanel.parserStatusLabel->setText(
                                QStringLiteral("解析器: %1失败").arg(backendText));
                        }

                        // 原始文件系统枚举需要直接读取卷设备；普通令牌会返回 ERROR_ACCESS_DENIED。
                        // 异步完成回调必须与同步入口一样接入统一提权恢复，否则模式切换只会留下空表。
                        const bool privilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(
                                safeThis.data(),
                                driverMode
                                ? QStringLiteral("%1目录").arg(backendText)
                                : QStringLiteral("读取原始文件系统数据"),
                                parseErrorText);
                        if (warnOnFailure && !privilegePromptHandled)
                        {
                            QMessageBox::warning(
                                safeThis.data(),
                                QStringLiteral("%1失败").arg(backendText),
                                QStringLiteral("路径: %1\n错误: %2")
                                .arg(QDir::toNativeSeparators(requestPath))
                                .arg(parseErrorText));
                        }

                        kLogEvent event;
                        warn << event
                            << "[FileDock] 异步平铺解析失败, source="
                            << parseBackendLogTag(parseBackend)
                            << ", panel="
                            << panelNameText.toStdString()
                            << ", path="
                            << QDir::toNativeSeparators(requestPath).toStdString()
                            << ", error="
                            << parseErrorText.toStdString()
                            << eol;
                    }
                    else
                    {
                        commitPanel.manualDisplayedPath = requestPath;
                        commitPanel.manualDisplayedReadMode = requestedReadMode;
                        commitPanel.manualSampledAt = payload->sampledAt;
                        commitPanel.manualLastError.clear();
                        commitPanel.manualResultPartial = partialResult;
                        commitPanel.manualSourceDetail = sourceDetail.isEmpty() ? backendText : sourceDetail;
                        payload->retiredPanelNames = std::move(commitPanel.manualSuspiciousNames);
                        commitPanel.manualSuspiciousNames = payload->suspiciousNames;
                        static_cast<ManualDirectoryModel*>(commitPanel.manualModel)->setSnapshot(
                            parsedEntriesSnapshot, payload->suspiciousNameSet);
                        commitPanel.fileView->setRootIndex(QModelIndex());
                        commitPanel.compactFileView->setRootIndex(QModelIndex());

                        if (commitPanel.parserStatusLabel != nullptr)
                        {
                            // 异步路径与同步路径保持同一展示规则，并明确标示真实数据来源。
                            if (!sourceDetail.isEmpty())
                            {
                                QString statusText =
                                    QStringLiteral("解析器: %1").arg(sourceDetail);
                                if (!payload->suspiciousNames.isEmpty())
                                {
                                    statusText += QStringLiteral("；疑似隐藏项 %1 个")
                                        .arg(payload->suspiciousNames.size());
                                }
                                commitPanel.parserStatusLabel->setText(statusText);
                            }
                            else if (usedWinApiFallback)
                            {
                                commitPanel.parserStatusLabel->setText(
                                    QStringLiteral("解析器: Windows API 回退 (%1)")
                                    .arg(manualFsTypeToText(parsedFsType)));
                            }
                            else
                            {
                                commitPanel.parserStatusLabel->setText(
                                    QStringLiteral("解析器: %1 (手动)")
                                    .arg(manualFsTypeToText(parsedFsType)));
                            }
                        }
                        commitPanel.manualLoadedPath = requestPath;

                        kLogEvent event;
                        info << event
                            << "[FileDock] 异步平铺解析完成, source="
                            << parseBackendLogTag(parseBackend)
                            << ", panel="
                            << panelNameText.toStdString()
                            << ", fsType="
                            << manualFsTypeToText(parsedFsType).toStdString()
                            << ", rows="
                            << parsedEntriesSnapshot->size()
                            << ", partial="
                            << (partialResult ? "true" : "false")
                            << ", path="
                            << QDir::toNativeSeparators(requestPath).toStdString()
                            << eol;
                    }

                    // 模型回填后重新应用过滤/排序，让视图立即更新到当前条件。
                    safeThis->applyPanelFilterAndSort(commitPanel);
                    safeThis->updateManualResultStatus(commitPanel);
                    safeThis->selectPendingPath(commitPanel);
                    kPro.set(
                        progressPid,
                        (backendText +
                            (parseOk
                                ? QStringLiteral("完成")
                                : QStringLiteral("失败"))).toStdString(),
                        0,
                        100.0f);

                    // 若解析过程中用户又切了目录，完成后立即执行挂起请求。
                    if (!commitPanel.manualParseInProgress && commitPanel.manualParsePending)
                    {
                        const bool pendingShowWarning =
                            commitPanel.manualParsePendingShowWarning;
                        commitPanel.manualParsePending = false;
                        commitPanel.manualParsePendingShowWarning = false;
                        safeThis->requestAsyncManualReload(commitPanel, pendingShowWarning);
                    }
                };

                const QString commitKey = leftPanelRequest
                    ? QStringLiteral("file-manual-model-left")
                    : QStringLiteral("file-manual-model-right");
                if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    commitKey,
                    { targetPanel.fileView },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            [progressPid]()
            {
                kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            });

    }).detach();
}

bool FileDock::currentModeIsManual(const FilePanelWidgets& panel) const
{
    return panel.readModeCombo != nullptr && panel.readModeCombo->currentIndex() >= 1;
}

bool FileDock::currentModeUsesDriver(const FilePanelWidgets& panel) const
{
    // R0 驱动解析与 R0 IRP 解析都由内核应答；其它平铺模式仍在 R3 完成。
    return parseBackendIsKernel(manualParseBackendForPanel(panel));
}

ks::file::ManualFsType FileDock::requestedManualFsTypeForPanel(const FilePanelWidgets& panel) const
{
    if (panel.readModeCombo == nullptr)
    {
        return ks::file::ManualFsType::Unknown;
    }

    switch (panel.readModeCombo->currentIndex())
    {
    case 3:
        return ks::file::ManualFsType::Ntfs;
    case 4:
        return ks::file::ManualFsType::Fat32;
    case 5:
        return ks::file::ManualFsType::ExFat;
    case 6:
        // 纯 MFT 扫描只在 NTFS 上成立，强制按 NTFS 解析。
        return ks::file::ManualFsType::Ntfs;
    default:
        return ks::file::ManualFsType::Unknown;
    }
}

FileDock::ManualParseBackend FileDock::manualParseBackendForPanel(
    const FilePanelWidgets& panel) const
{
    if (panel.readModeCombo == nullptr)
    {
        return ManualParseBackend::WindowsApi;
    }

    switch (panel.readModeCombo->currentIndex())
    {
    case 0:
        return ManualParseBackend::WindowsApi;
    case 2:
        return ManualParseBackend::R0Driver;
    case 6:
        return ManualParseBackend::MftStrict;
    case 7:
        return ManualParseBackend::R0Irp;
    default:
        // 1/3/4/5 都是 R3 手动解析，区别只在强制文件系统类型。
        return ManualParseBackend::ManualFs;
    }
}

bool FileDock::parseBackendIsKernel(const ManualParseBackend backend)
{
    return backend == ManualParseBackend::R0Driver ||
        backend == ManualParseBackend::R0Irp;
}

QString FileDock::parseBackendDisplayText(const ManualParseBackend backend)
{
    switch (backend)
    {
    case ManualParseBackend::R0Driver:
        return QStringLiteral("R0 驱动解析");
    case ManualParseBackend::R0Irp:
        return QStringLiteral("R0 IRP 解析");
    case ManualParseBackend::MftStrict:
        return QStringLiteral("纯 MFT 解析");
    case ManualParseBackend::ManualFs:
        return QStringLiteral("手动解析");
    case ManualParseBackend::WindowsApi:
    default:
        return QStringLiteral("Windows API");
    }
}

const char* FileDock::parseBackendLogTag(const ManualParseBackend backend)
{
    switch (backend)
    {
    case ManualParseBackend::R0Driver:
        return "R0";
    case ManualParseBackend::R0Irp:
        return "R0-IRP";
    case ManualParseBackend::MftStrict:
        return "R3-mft";
    case ManualParseBackend::ManualFs:
        return "R3-manual";
    case ManualParseBackend::WindowsApi:
    default:
        return "WinAPI";
    }
}

bool FileDock::runManualParseBackend(
    const ManualParseBackend backend,
    const QString& pathText,
    const ks::file::ManualFsType requestedFsType,
    std::vector<ks::file::ManualDirectoryEntry>& entriesOut,
    ks::file::ManualFsType& fsTypeOut,
    QString& errorTextOut,
    bool& usedWinApiFallbackOut,
    bool& partialOut,
    QString& sourceDetailOut,
    QStringList& suspiciousNamesOut,
    const ks::file::DirectoryCancellationCallback& canceled)
{
    if (canceled && canceled()) return false;
    usedWinApiFallbackOut = false;
    partialOut = false;
    sourceDetailOut.clear();
    suspiciousNamesOut.clear();

    switch (backend)
    {
    case ManualParseBackend::R0Driver:
        return ks::file::DriverFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &partialOut,
            &sourceDetailOut,
            canceled);

    case ManualParseBackend::R0Irp:
    {
        ks::file::IrpScanDiagnostics diagnostics;
        const bool parseOk = ks::file::IrpFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &partialOut,
            &sourceDetailOut,
            &diagnostics,
            canceled);
        if (parseOk)
        {
            suspiciousNamesOut = diagnostics.bypassOnlyNames;
        }
        return parseOk;
    }

    case ManualParseBackend::MftStrict:
    {
        ks::file::MftScanDiagnostics diagnostics;
        fsTypeOut = ks::file::ManualFsType::Ntfs;
        const bool parseOk = ks::file::ManualFileSystemParser::enumerateDirectoryByMft(
            pathText,
            entriesOut,
            errorTextOut,
            &diagnostics,
            canceled);
        if (!parseOk)
        {
            return false;
        }
        suspiciousNamesOut = diagnostics.mftOnlyNames;
        sourceDetailOut = diagnostics.comparisonAvailable
            ? QStringLiteral("纯 MFT 解析；条目=%1；目录枚举视图=%2；仅 MFT 可见=%3")
                .arg(diagnostics.mftEntryCount)
                .arg(diagnostics.winApiEntryCount)
                .arg(diagnostics.mftOnlyNames.size())
            : QStringLiteral("纯 MFT 解析；条目=%1；未取得目录枚举对照")
                .arg(diagnostics.mftEntryCount);
        return true;
    }

    case ManualParseBackend::ManualFs:
    case ManualParseBackend::WindowsApi:
    default:
        return ks::file::ManualFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &usedWinApiFallbackOut,
            requestedFsType,
            false,
            canceled);
    }
}

void FileDock::initializeRecoveryPage()
{
    m_fileRecoveryPage = new QWidget(m_rootTabWidget);
    QVBoxLayout* recoveryLayout = new QVBoxLayout(m_fileRecoveryPage);
    recoveryLayout->setContentsMargins(6, 6, 6, 6);
    recoveryLayout->setSpacing(6);

    QWidget* toolWidget = new QWidget(m_fileRecoveryPage);
    QHBoxLayout* toolLayout = new QHBoxLayout(toolWidget);
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    m_recoveryVolumeCombo = new QComboBox(toolWidget);
    m_recoveryVolumeCombo->setStyleSheet(buildBlueInputStyle());
    ks::ui::StylePrimaryCombo(m_recoveryVolumeCombo);
    m_recoveryVolumeCombo->setToolTip(QStringLiteral("选择要扫描误删文件的 NTFS 卷。"));

    m_recoveryRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), toolWidget);
    m_recoveryRefreshButton->setToolTip(QStringLiteral("刷新可扫描卷列表"));
    m_recoveryRefreshButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(m_recoveryRefreshButton);

    m_recoveryScanButton = new QPushButton(QIcon(":/Icon/log_track.svg"), QStringLiteral("扫描误删"), toolWidget);
    m_recoveryScanButton->setToolTip(QStringLiteral("解析 NTFS MFT，扫描删除项"));
    m_recoveryScanButton->setStyleSheet(buildBlueButtonStyle());

    m_recoveryExportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("恢复选中"), toolWidget);
    m_recoveryExportButton->setToolTip(QStringLiteral(
        "支持 Resident 与完整非驻留数据；非驻留文件必须导出到其它卷，恢复前后都会复核卷位图。"));
    m_recoveryExportButton->setStyleSheet(buildBlueButtonStyle());

    // 扫描结果动辄上万条，必须能就地查找，否则只能靠滚动条翻找。
    m_recoveryFilterEdit = new QLineEdit(toolWidget);
    ks::ui::StyleSearchField(m_recoveryFilterEdit);
    m_recoveryFilterEdit->setPlaceholderText(QStringLiteral("查找结果（文件名/路径/恢复能力）"));
    m_recoveryFilterEdit->setClearButtonEnabled(true);
    m_recoveryFilterEdit->setToolTip(QStringLiteral(
        "按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"));

    m_recoveryFilterRegexButton = new QToolButton(toolWidget);
    m_recoveryFilterRegexButton->setText(QStringLiteral(".*"));
    m_recoveryFilterRegexButton->setCheckable(true);
    m_recoveryFilterRegexButton->setToolTip(QStringLiteral(
        "按正则表达式筛选，例如 \\.docx?$ 只看 doc/docx"));

    toolLayout->addWidget(new QLabel(QStringLiteral("卷: "), toolWidget), 0);
    toolLayout->addWidget(m_recoveryVolumeCombo, 1);
    toolLayout->addWidget(m_recoveryRefreshButton, 0);
    toolLayout->addWidget(m_recoveryScanButton, 0);
    toolLayout->addWidget(m_recoveryFilterEdit, 1);
    toolLayout->addWidget(m_recoveryFilterRegexButton, 0);
    toolLayout->addWidget(m_recoveryExportButton, 0);
    ks::ui::NormalizeToolbarRow(toolLayout);
    recoveryLayout->addWidget(toolWidget, 0);

    m_recoveryScanOperation = new ks::ui::AsyncOperation(this);
    m_recoveryProjectionOperation = new ks::ui::AsyncOperation(this);
    m_recoveryTable = new ks::ui::TableActionTableView(m_fileRecoveryPage);
    auto* recoveryModel = new DeletedRecoveryModel(m_recoveryTable);
    m_recoveryModel = recoveryModel;
    ks::ui::ResultTableCapabilities capabilities;
    capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
    ks::ui::ResultTableHost::ensure(m_recoveryTable)->bindModel(recoveryModel, {
        {0, QStringLiteral("file-name")}, {1, QStringLiteral("path-hint")},
        {2, QStringLiteral("size")}, {3, QStringLiteral("modified")},
        {4, QStringLiteral("record-sequence")}, {5, QStringLiteral("integrity")},
        {6, QStringLiteral("recovery-capability")} }, capabilities);
    recoveryModel->sortRequested = [this](int column, Qt::SortOrder order)
    {
        m_recoverySortColumn = column;
        m_recoverySortOrder = order;
        applyRecoveryFilter();
    };
    m_recoveryTable->horizontalHeader()->setSectionsClickable(true);
    connect(m_recoveryTable->horizontalHeader(), &QHeaderView::sectionClicked, this, [this, recoveryModel](int column)
    {
        const Qt::SortOrder order = m_recoverySortColumn == column && m_recoverySortOrder == Qt::AscendingOrder
            ? Qt::DescendingOrder : Qt::AscendingOrder;
        m_recoveryTable->horizontalHeader()->setSortIndicator(column, order);
        m_recoveryTable->horizontalHeader()->setSortIndicatorShown(true);
        recoveryModel->sort(column, order);
    });
    m_recoveryTable->viewport()->installEventFilter(this);
    m_recoveryTable->installEventFilter(this);
    connect(m_recoveryTable->selectionModel(), &QItemSelectionModel::selectionChanged, this,
        [this, recoveryModel](const QItemSelection& selected, const QItemSelection& deselected)
        {
            if (m_recoveryProjectionCommit) return;
            for (const auto& range : deselected) for (int row = range.top(); row <= range.bottom(); ++row)
                m_recoverySelectedSourceRows.remove(recoveryModel->sourceRow(row));
            for (const auto& range : selected) for (int row = range.top(); row <= range.bottom(); ++row)
            {
                const int source = recoveryModel->sourceRow(row);
                if (source >= 0) m_recoverySelectedSourceRows.insert(source);
            }
        });
    connect(m_recoveryTable->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this, recoveryModel](const QModelIndex& current, const QModelIndex&)
        {
            if (!m_recoveryProjectionCommit) m_recoveryCurrentSourceRow = recoveryModel->sourceRow(current.row());
        });
    m_recoveryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_recoveryTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_recoveryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_recoveryTable->verticalHeader()->setVisible(false);
    m_recoveryTable->horizontalHeader()->setStretchLastSection(true);
    m_recoveryTable->setAlternatingRowColors(true);
    installRecoveryTableMenu();

    // 结果区用堆叠容器：没有结果时显示居中的引导页，
    // 否则工具条右端那个“扫描误删”按钮在整片空白表格旁边很难被注意到。
    m_recoveryViewStack = new QStackedWidget(m_fileRecoveryPage);

    m_recoveryEmptyPage = new QWidget(m_recoveryViewStack);
    QVBoxLayout* emptyLayout = new QVBoxLayout(m_recoveryEmptyPage);
    emptyLayout->setContentsMargins(24, 24, 24, 24);
    emptyLayout->setSpacing(12);
    emptyLayout->addStretch(1);

    m_recoveryEmptyHintLabel = new QLabel(
        QStringLiteral("选择 NTFS 卷后开始扫描，可在此列出仍可恢复的误删文件。"),
        m_recoveryEmptyPage);
    m_recoveryEmptyHintLabel->setAlignment(Qt::AlignCenter);
    m_recoveryEmptyHintLabel->setWordWrap(true);
    emptyLayout->addWidget(m_recoveryEmptyHintLabel, 0);

    m_recoveryEmptyScanButton = new QPushButton(
        QIcon(":/Icon/log_track.svg"),
        QStringLiteral("开始扫描误删文件"),
        m_recoveryEmptyPage);
    m_recoveryEmptyScanButton->setStyleSheet(buildBlueButtonStyle());
    m_recoveryEmptyScanButton->setMinimumHeight(38);
    m_recoveryEmptyScanButton->setMinimumWidth(200);
    m_recoveryEmptyScanButton->setToolTip(QStringLiteral("解析 NTFS MFT，扫描删除项"));

    QHBoxLayout* emptyButtonLayout = new QHBoxLayout();
    emptyButtonLayout->addStretch(1);
    emptyButtonLayout->addWidget(m_recoveryEmptyScanButton, 0);
    emptyButtonLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(emptyButtonLayout);
    emptyLayout->addLayout(emptyButtonLayout, 0);
    emptyLayout->addStretch(1);

    m_recoveryViewStack->addWidget(m_recoveryEmptyPage);
    m_recoveryViewStack->addWidget(m_recoveryTable);
    m_recoveryViewStack->setCurrentWidget(m_recoveryEmptyPage);
    recoveryLayout->addWidget(m_recoveryViewStack, 1);

    m_recoveryStatusLabel = new QLabel(QStringLiteral("请选择NTFS卷并开始扫描。"), m_fileRecoveryPage);
    recoveryLayout->addWidget(m_recoveryStatusLabel, 0);

    connect(m_recoveryRefreshButton, &QPushButton::clicked, this, [this]() {
        refreshRecoveryVolumeList();
    });
    connect(m_recoveryScanButton, &QPushButton::clicked, this, [this]() {
        scanDeletedFilesForRecovery();
    });
    connect(m_recoveryEmptyScanButton, &QPushButton::clicked, this, [this]() {
        scanDeletedFilesForRecovery();
    });
    connect(m_recoveryExportButton, &QPushButton::clicked, this, [this]() {
        recoverSelectedDeletedFiles();
    });
    m_recoveryFilterTimer = new QTimer(this);
    m_recoveryFilterTimer->setSingleShot(true);
    m_recoveryFilterTimer->setInterval(100);
    connect(m_recoveryFilterTimer, &QTimer::timeout, this, &FileDock::applyRecoveryFilter);
    const auto scheduleFilter = [this]()
    {
        // Invalidate immediately, before debounce: an old result may arrive during typing.
        m_recoveryProjectionOperation->cancel();
        m_recoveryFilterTimer->start();
    };
    connect(m_recoveryFilterEdit, &QLineEdit::textChanged, this,
        [scheduleFilter](const QString&) { scheduleFilter(); });
    connect(m_recoveryFilterRegexButton, &QToolButton::toggled, this,
        [scheduleFilter](bool) { scheduleFilter(); });

    refreshRecoveryVolumeList();
}

void FileDock::applyRecoveryFilter()
{
    if (m_recoveryFilterTimer) m_recoveryFilterTimer->stop();
    if (m_recoveryTable == nullptr || m_recoveryFilterEdit == nullptr || m_recoveryModel == nullptr) return;
    auto* model = static_cast<DeletedRecoveryModel*>(m_recoveryModel);
    if (m_recoveryScanInProgress && !m_recoveryPendingSnapshot) return;
    auto snapshot = m_recoveryPendingSnapshot ? m_recoveryPendingSnapshot : model->snapshot();
    if (!snapshot) return;
    QString query = m_recoveryFilterEdit->text().trimmed();
    bool regex = m_recoveryFilterRegexButton != nullptr && m_recoveryFilterRegexButton->isChecked();
    const bool invalid = !query.isEmpty() && regex
        && !QRegularExpression(query, QRegularExpression::CaseInsensitiveOption).isValid();
    if (invalid)
    {
        m_recoveryProjectionOperation->cancel();
        m_recoveryFilterEdit->setToolTip(QStringLiteral("正则表达式无效，已暂不筛选。"));
        if (!m_recoveryPendingSnapshot && m_recoverySortColumn == m_recoveryAppliedSortColumn
            && m_recoverySortOrder == m_recoveryAppliedSortOrder) return;
        // A newly completed scan uses the last committed predicate while the editor is invalid.
        query = m_recoveryAppliedFilterText;
        regex = m_recoveryAppliedFilterRegex;
    }
    else m_recoveryFilterEdit->setToolTip(QStringLiteral(
        "按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"));

    // Clearing back to the committed predicate needs no model reset or selection replay.
    if (!m_recoveryPendingSnapshot && model->snapshot() == snapshot
        && query == m_recoveryAppliedFilterText && regex == m_recoveryAppliedFilterRegex
        && m_recoverySortColumn == m_recoveryAppliedSortColumn
        && m_recoverySortOrder == m_recoveryAppliedSortOrder) return;

    const RecoveryProjectionRequest request{ snapshot, query, regex,
        m_recoverySortColumn, m_recoverySortOrder };
    m_recoveryProjectionOperation->submit<RecoveryProjectionRequest, RecoveryProjectionResult>(request,
        [](const RecoveryProjectionRequest& value, const ks::ui::AsyncOperationToken& token)
        { return buildRecoveryProjection(value, token); },
        [this](const RecoveryProjectionResult& result, std::uint64_t ticket)
        {
            // Only shared values survive apply; AsyncOperation does not retain this result reference.
            const auto commit = [this, result, ticket]()
            {
                if (!m_recoveryProjectionOperation->isCurrent(ticket))
                { m_recoveryProjectionOperation->completeDeferred(ticket); return; }
                auto* model = static_cast<DeletedRecoveryModel*>(m_recoveryModel);
                const auto expected = m_recoveryPendingSnapshot ? m_recoveryPendingSnapshot : model->snapshot();
                if (!result.projection || expected != result.request.snapshot)
                { m_recoveryProjectionOperation->completeDeferred(ticket); return; }
                const bool newSnapshot = model->snapshot() != result.request.snapshot;
                if (newSnapshot)
                {
                    m_recoverySelectedSourceRows.clear();
                    m_recoveryCurrentSourceRow = -1;
                }
                const QPointer<FileDock> lifetime(this);
                m_recoveryProjectionCommit = true;
                model->publish(result.request.snapshot, result.projection);
                if (!lifetime) return;
                // Preserve selected source identities even while a filter removes them from the view.
                std::vector<int> selectedViewRows;
                selectedViewRows.reserve(static_cast<std::size_t>(m_recoverySelectedSourceRows.size()));
                for (int source : m_recoverySelectedSourceRows)
                {
                    const int row = model->viewRow(source);
                    if (row >= 0) selectedViewRows.push_back(row);
                }
                std::sort(selectedViewRows.begin(), selectedViewRows.end());
                QItemSelection selection;
                for (std::size_t first = 0; first < selectedViewRows.size();)
                {
                    std::size_t last = first;
                    while (last + 1 < selectedViewRows.size() && selectedViewRows[last + 1] == selectedViewRows[last] + 1) ++last;
                    selection.select(model->index(selectedViewRows[first], 0), model->index(selectedViewRows[last], 6));
                    first = last + 1;
                }
                m_recoveryTable->selectionModel()->select(selection, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                const int current = model->viewRow(m_recoveryCurrentSourceRow);
                if (current >= 0) m_recoveryTable->selectionModel()->setCurrentIndex(model->index(current, 0), QItemSelectionModel::NoUpdate);
                m_recoveryProjectionCommit = false;
                m_recoveryAppliedFilterText = result.request.query;
                m_recoveryAppliedFilterRegex = result.request.regex;
                m_recoveryAppliedSortColumn = result.request.sortColumn;
                m_recoveryAppliedSortOrder = result.request.sortOrder;
                if (newSnapshot)
                {
                    const auto& value = *result.request.snapshot;
                    m_recoveryBaseStatusText = QStringLiteral(
                        "扫描完成：%1 项（可安全恢复 %2 项：Resident %3，完整非驻留 %4；完整度≥80%% %5 项）")
                        .arg(value.entries.size()).arg(value.safelyRecoverable).arg(value.residentReady)
                        .arg(value.nonResidentReady).arg(value.highIntegrity);
                    m_recoveryPendingSnapshot.reset();
                    m_recoveryScanInProgress = false;
                    m_recoveryScanButton->setEnabled(!m_recoveryRecoverInProgress);
                    m_recoveryEmptyScanButton->setEnabled(!m_recoveryRecoverInProgress);
                    m_recoveryExportButton->setEnabled(!m_recoveryRecoverInProgress);
                    updateRecoveryViewState(!value.entries.empty(), QStringLiteral(
                        "本次扫描未发现仍可恢复的删除项，可更换卷后重新扫描。"));
                }
                m_recoveryStatusLabel->setText(result.request.query.isEmpty() ? m_recoveryBaseStatusText
                    : QStringLiteral("%1｜筛选出 %2 / %3 项").arg(m_recoveryBaseStatusText)
                        .arg(model->rowCount()).arg(result.request.snapshot->entries.size()));
                m_recoveryProjectionOperation->completeDeferred(ticket);
            };
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this,
                QStringLiteral("file-recovery-projection"), { m_recoveryTable }, commit)) return false;
            commit();
            return true;
        },
        [this](std::exception_ptr)
        {
            if (m_recoveryPendingSnapshot)
            {
                retireRecoverySnapshot(std::move(m_recoveryPendingSnapshot));
                m_recoveryScanInProgress = false;
                m_recoveryScanButton->setEnabled(!m_recoveryRecoverInProgress);
                m_recoveryEmptyScanButton->setEnabled(!m_recoveryRecoverInProgress);
                m_recoveryExportButton->setEnabled(!m_recoveryRecoverInProgress);
                m_recoveryStatusLabel->setText(QStringLiteral("扫描失败"));
            }
        });
}

void FileDock::updateRecoveryViewState(const bool hasResults, const QString& emptyHintText)
{
    if (m_recoveryViewStack == nullptr)
    {
        return;
    }
    if (m_recoveryEmptyHintLabel != nullptr && !emptyHintText.isEmpty())
    {
        m_recoveryEmptyHintLabel->setText(emptyHintText);
    }
    m_recoveryViewStack->setCurrentWidget(
        hasResults
        ? static_cast<QWidget*>(m_recoveryTable)
        : static_cast<QWidget*>(m_recoveryEmptyPage));
}

void FileDock::installRecoveryTableMenu()
{
    // installRecoveryTableMenu：
    // - 输入：删除项结果表格的右键点击；
    // - 处理：在通用的“复制当前行”之外，补上“文件属性”和“恢复选中”，
    //   让这两个主操作不必再去工具条右端找按钮；
    // - 返回：无。属性只读展示，恢复走与工具条按钮完全相同的入口。
    if (m_recoveryTable == nullptr)
    {
        return;
    }

    m_recoveryTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_recoveryTable, &QTableView::customContextMenuRequested, this,
        [this](const QPoint& localPosition)
    {
        if (m_recoveryTable == nullptr)
        {
            return;
        }
        const QModelIndex clickedIndex = m_recoveryTable->indexAt(localPosition);
        // 右键空白处不改变既有多选；点在行上才把当前行切过去。
        if (clickedIndex.isValid() && !m_recoveryTable->selectionModel()->isSelected(clickedIndex))
        {
            m_recoveryTable->selectRow(clickedIndex.row());
        }

        const int currentRow = clickedIndex.isValid()
            ? clickedIndex.row()
            : m_recoveryTable->currentIndex().row();
        const auto* model = static_cast<DeletedRecoveryModel*>(m_recoveryModel);
        const auto snapshot = model->snapshot();
        const auto* entry = model->entry(currentRow);
        const bool hasRow = entry != nullptr;
        const ks::file::NtfsDeletedFileEntry currentItem = hasRow ? *entry : ks::file::NtfsDeletedFileEntry{};
        std::vector<ks::file::NtfsDeletedFileEntry> selectedItems;
        if (snapshot)
        {
            auto selected = m_recoverySelectedSourceRows.values();
            std::sort(selected.begin(), selected.end());
            selectedItems.reserve(static_cast<std::size_t>(selected.size()));
            for (int source : selected) if (source >= 0 && source < static_cast<int>(snapshot->entries.size()))
                selectedItems.push_back(snapshot->entries[static_cast<std::size_t>(source)]);
        }
        const bool hasSelection = !selectedItems.empty();
        QStringList fields;
        if (hasRow) for (int column = 0; column < model->columnCount(); ++column)
            fields.push_back(model->data(model->index(currentRow, column), Qt::DisplayRole).toString());
        const QString copyText = fields.join(QLatin1Char('\t'));

        const QPointer<FileDock> guardThis(this);
        QMenu menu;
        menu.setStyleSheet(buildContextMenuStyle());

        QAction* propertyAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("文件属性"));
        propertyAction->setEnabled(hasRow);

        QAction* recoverAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            QStringLiteral("恢复选中"));
        recoverAction->setEnabled(hasSelection && !m_recoveryRecoverInProgress && !m_recoveryScanInProgress);

        menu.addSeparator();
        QAction* copyRowAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            QStringLiteral("复制当前行"));
        // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
        ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
        copyRowAction->setEnabled(currentRow >= 0);

        QAction* selectedAction =
            menu.exec(m_recoveryTable->viewport()->mapToGlobal(localPosition));
        if (!guardThis || selectedAction == nullptr)
        {
            return;
        }
        if (selectedAction == propertyAction)
        {
            showDeletedFilePropertiesDialog(currentItem);
            return;
        }
        if (selectedAction == recoverAction)
        {
            if (snapshot) recoverDeletedFileEntriesAsync(snapshot->volumeRoot, std::move(selectedItems));
            return;
        }
        if (selectedAction != copyRowAction)
        {
            return;
        }

        if (hasRow) if (QClipboard* clipboardObject = QApplication::clipboard())
            clipboardObject->setText(copyText);
    });
}

void FileDock::showDeletedFilePropertiesDialog(const ks::file::NtfsDeletedFileEntry& entry)
{
    const ks::file::NtfsDeletedFileEntry itemValue = entry;

    QDialog* dialog = new QDialog(this);
    const QPointer<QDialog> guardedDialog(dialog);
    dialog->setObjectName(QStringLiteral("DeletedFilePropertyDialog"));
    dialog->setStyleSheet(buildOpaqueStandaloneDialogStyle(dialog->objectName()));
    dialog->setWindowTitle(QStringLiteral("删除项属性"));
    dialog->resize(620, 460);

    QVBoxLayout* rootLayout = new QVBoxLayout(dialog);

    // 属性用只读表格展示：字段多且需要整段复制，比 QFormLayout 更实用。
    QTableWidget* propertyTable = new ks::ui::VisibleTableWidget(dialog);
    // 单个删除项的属性对话框沿用右键复制，不显示快照操作栏。
    ks::ui::SetTableActionBarMode(propertyTable, ks::ui::TableActionBarMode::None);
    propertyTable->setColumnCount(2);
    propertyTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("属性"),
        QStringLiteral("值") });
    propertyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    propertyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    propertyTable->verticalHeader()->setVisible(false);
    propertyTable->horizontalHeader()->setStretchLastSection(true);
    propertyTable->setAlternatingRowColors(true);
    installFileTableCopyMenu(propertyTable);

    const QString integrityText = (itemValue.estimatedIntegrityPercent >= 0)
        ? QStringLiteral("%1%").arg(itemValue.estimatedIntegrityPercent)
        : QStringLiteral("未知");
    const QString modifiedText = itemValue.modifiedTime.isValid()
        ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
        : QStringLiteral("-");

    const QVector<QPair<QString, QString>> propertyRows{
        { QStringLiteral("文件名"), itemValue.fileName },
        { QStringLiteral("原始文件名是否保留"),
          itemValue.hasOriginalName
          ? QStringLiteral("是")
          : QStringLiteral("否（当前为系统生成的占位名）") },
        { QStringLiteral("路径提示"), itemValue.pathHint },
        { QStringLiteral("大小"),
          QStringLiteral("%1 (%2 字节)")
              .arg(formatSizeText(itemValue.sizeBytes))
              .arg(static_cast<qulonglong>(itemValue.sizeBytes)) },
        { QStringLiteral("修改时间"), modifiedText },
        { QStringLiteral("MFT 记录号"),
          QString::number(static_cast<qulonglong>(itemValue.fileReference)) },
        { QStringLiteral("MFT 序列号"), QString::number(itemValue.sequenceNumber) },
        { QStringLiteral("完整度"), integrityText },
        { QStringLiteral("恢复能力"), deletedFileRecoveryCapabilityText(itemValue) },
        { QStringLiteral("驻留数据已就绪"),
          itemValue.residentDataReady ? QStringLiteral("是") : QStringLiteral("否") },
        { QStringLiteral("是否可安全恢复"),
          isDeletedFileSafelyRecoverable(itemValue)
          ? QStringLiteral("是")
          : QStringLiteral("否（恢复入口会拒绝此项）") },
    };

    propertyTable->setRowCount(propertyRows.size());
    for (int row = 0; row < propertyRows.size(); ++row)
    {
        propertyTable->setItem(row, 0, new QTableWidgetItem(propertyRows[row].first));
        propertyTable->setItem(row, 1, new QTableWidgetItem(propertyRows[row].second));
    }
    propertyTable->resizeColumnToContents(0);
    rootLayout->addWidget(propertyTable, 1);

    QLabel* noteLabel = new QLabel(
        QStringLiteral("以上为扫描时刻的 MFT 快照；恢复前会按记录号和序列号重新校验，不依赖此处的旧数据。"),
        dialog);
    noteLabel->setWordWrap(true);
    noteLabel->setContentsMargins(8, 6, 8, 6);
    rootLayout->addWidget(noteLabel, 0);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    buttonBox->button(QDialogButtonBox::Close)->setText(QStringLiteral("关闭"));
    connect(buttonBox, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    rootLayout->addWidget(buttonBox, 0);

    ks::ui::ApplyDetailDialogChrome(dialog);
    dialog->exec();
    if (guardedDialog) guardedDialog->deleteLater();
}

void FileDock::refreshRecoveryVolumeList()
{
    if (m_recoveryVolumeCombo == nullptr)
    {
        return;
    }

    // 卷探测（GetDriveTypeW + GetVolumeInformationW）会在空光驱、断线映射网络盘上
    // 阻塞数秒到数十秒，而本函数在“文件”页首次构造时就会被调用，留在 UI 线程等于
    // 让整窗在首次点开 Tab 时假死。这里只做“清空列表 + 置灰入口”，真实探测放后台。
    const quint64 requestGeneration =
        m_recoveryVolumeCombo->property(kRecoveryVolumeProbeGenerationProperty).toULongLong() + 1U;
    m_recoveryVolumeCombo->setProperty(
        kRecoveryVolumeProbeGenerationProperty, static_cast<qulonglong>(requestGeneration));

    m_recoveryVolumeCombo->clear();
    m_recoveryVolumeCombo->setEnabled(false);
    if (m_recoveryRefreshButton != nullptr)
    {
        m_recoveryRefreshButton->setEnabled(false);
    }
    if (m_recoveryScanButton != nullptr)
    {
        m_recoveryScanButton->setEnabled(false);
        if (m_recoveryEmptyScanButton != nullptr) { m_recoveryEmptyScanButton->setEnabled(false); }
    }
    if (m_recoveryStatusLabel != nullptr)
    {
        m_recoveryStatusLabel->setText(QStringLiteral("正在刷新..."));
    }

    const QPointer<FileDock> guardedSelf(this);
    QThreadPool::globalInstance()->start(
        [guardedSelf, requestGeneration]()
        {
            // 后台只产出值类型（卷根字符串列表），不触碰任何 QWidget。
            const QVector<QString> ntfsVolumeRootList = collectNtfsVolumeRootList();

            FileDock* const targetDock = guardedSelf.data();
            if (targetDock == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                targetDock,
                [guardedSelf, requestGeneration, ntfsVolumeRootList]()
                {
                    if (guardedSelf.isNull())
                    {
                        return;
                    }

                    FileDock* const dock = guardedSelf.data();
                    if (dock->m_recoveryVolumeCombo == nullptr)
                    {
                        return;
                    }
                    // generation：只接受最后一次刷新请求的结果，淘汰已被取代的旧探测。
                    const quint64 currentGeneration = dock->m_recoveryVolumeCombo
                        ->property(kRecoveryVolumeProbeGenerationProperty)
                        .toULongLong();
                    if (currentGeneration != requestGeneration)
                    {
                        return;
                    }

                    // commitVolumeList：卷列表落地动作，直接提交与弹层收起后的回投共用同一份实现。
                    auto commitVolumeList = [guardedSelf, requestGeneration, ntfsVolumeRootList]()
                    {
                        if (guardedSelf.isNull())
                        {
                            return;
                        }
                        FileDock* const commitDock = guardedSelf.data();
                        if (commitDock->m_recoveryVolumeCombo == nullptr)
                        {
                            return;
                        }
                        // 延迟回投期间可能又发起了新一轮探测，落地前重新校验代次。
                        const quint64 latestGeneration = commitDock->m_recoveryVolumeCombo
                            ->property(kRecoveryVolumeProbeGenerationProperty)
                            .toULongLong();
                        if (latestGeneration != requestGeneration)
                        {
                            return;
                        }

                        commitDock->m_recoveryVolumeCombo->clear();
                        for (const QString& volumeRootPath : ntfsVolumeRootList)
                        {
                            const QString displayText = QStringLiteral("%1 (NTFS)").arg(volumeRootPath);
                            commitDock->m_recoveryVolumeCombo->addItem(displayText, volumeRootPath);
                        }
                        commitDock->m_recoveryVolumeCombo->setEnabled(true);

                        if (commitDock->m_recoveryRefreshButton != nullptr)
                        {
                            commitDock->m_recoveryRefreshButton->setEnabled(true);
                        }
                        // 扫描按钮的禁用权归误删扫描/恢复任务：探测结束不能把它们置灰的状态改回去。
                        if (commitDock->m_recoveryScanButton != nullptr
                            && !commitDock->m_recoveryScanInProgress
                            && !commitDock->m_recoveryRecoverInProgress)
                        {
                            commitDock->m_recoveryScanButton->setEnabled(true);
                            if (commitDock->m_recoveryEmptyScanButton != nullptr) { commitDock->m_recoveryEmptyScanButton->setEnabled(true); }
                        }

                        if (commitDock->m_recoveryStatusLabel != nullptr)
                        {
                            if (commitDock->m_recoveryVolumeCombo->count() == 0)
                            {
                                commitDock->m_recoveryStatusLabel->setText(
                                    QStringLiteral("未检测到可扫描的 NTFS 卷。"));
                            }
                            else
                            {
                                commitDock->m_recoveryStatusLabel->setText(
                                    QStringLiteral("已刷新卷列表，可执行误删扫描。"));
                            }
                        }

                        kLogEvent event;
                        info << event
                            << "[FileDock] 刷新文件恢复卷列表, count="
                            << commitDock->m_recoveryVolumeCombo->count()
                            << eol;
                    };

                    // 卷下拉框展开期间清空重填，会让弹层继续抓着鼠标键盘但内容失效，
                    // 界面表现为点不动；这里推迟到弹层收起后再落地。
                    if (ks::ui::DeferUiCommitIfComboBoxPopupOpen(
                            dock,
                            QStringLiteral("file-recovery-volume-combo-apply"),
                            commitVolumeList))
                    {
                        return;
                    }
                    commitVolumeList();
                },
                Qt::QueuedConnection);
        });
}

void FileDock::scanDeletedFilesForRecovery()
{
    // 对外保留同步入口名，内部改为异步实现，避免阻塞 UI。
    scanDeletedFilesForRecoveryAsync();
}

void FileDock::scanDeletedFilesForRecoveryAsync()
{
    if (m_recoveryVolumeCombo == nullptr || m_recoveryTable == nullptr || m_recoveryStatusLabel == nullptr) return;
    if (m_recoveryScanInProgress || m_recoveryRecoverInProgress || m_recoveryScanOperation->isInFlight()) return;
    if (m_recoveryVolumeCombo->currentIndex() < 0)
    {
        QMessageBox::warning(this, QStringLiteral("文件恢复"), QStringLiteral("请先选择 NTFS 卷。"));
        return;
    }
    struct Request { QString volume; std::uint64_t revision; int progressPid; };
    struct Result { std::shared_ptr<const FileRecoverySnapshot> snapshot; QString error; bool ok = false; };
    const QString volume = m_recoveryVolumeCombo->currentData().toString();
    const int progressPid = kPro.add(this, "文件恢复", "扫描误删");
    const Request request{ volume, ++m_recoverySnapshotRevision, progressPid };
    m_recoveryProjectionOperation->cancel();
    m_recoveryStatusLabel->setText(QStringLiteral("正在扫描：%1").arg(volume));
    m_recoveryScanInProgress = true;
    m_recoveryScanButton->setEnabled(false);
    m_recoveryEmptyScanButton->setEnabled(false);
    m_recoveryExportButton->setEnabled(false);
    kPro.set(progressPid, "准备扫描卷", 0, 5.0f);
    m_recoveryScanOperation->submit<Request, Result>(request,
        [](const Request& value, const ks::ui::AsyncOperationToken& token)
        {
            Result result;
            auto snapshot = makeRecoverySnapshot();
            snapshot->volumeRoot = value.volume;
            snapshot->revision = value.revision;
            result.ok = ks::file::ManualFileSystemParser::enumerateNtfsDeletedFiles(value.volume,
                snapshot->entries, result.error,
                [progressPid = value.progressPid, token](int percent, const QString& stage)
                {
                    if (!token.isCanceled()) kPro.set(progressPid, stage.toStdString(), 0,
                        static_cast<float>(std::clamp(percent, 0, 100)));
                });
            if (!result.ok || token.isCanceled()) return result;
            for (const auto& entry : snapshot->entries)
            {
                if (token.isCanceled()) return result;
                snapshot->residentReady += entry.recoveryCapability == ks::file::NtfsRecoveryCapability::Resident;
                snapshot->nonResidentReady += entry.recoveryCapability == ks::file::NtfsRecoveryCapability::NonResidentIntact;
                snapshot->safelyRecoverable += isDeletedFileSafelyRecoverable(entry);
                snapshot->highIntegrity += entry.estimatedIntegrityPercent >= 80;
            }
            result.snapshot = std::move(snapshot);
            return result;
        },
        [this, request](const Result& result, std::uint64_t)
        {
            if (!result.ok || !result.snapshot)
            {
                m_recoveryScanInProgress = false;
                m_recoveryScanButton->setEnabled(!m_recoveryRecoverInProgress);
                m_recoveryEmptyScanButton->setEnabled(!m_recoveryRecoverInProgress);
                m_recoveryExportButton->setEnabled(!m_recoveryRecoverInProgress);
                m_recoveryStatusLabel->setText(QStringLiteral("扫描失败：%1").arg(result.error));
                updateRecoveryViewState(false, QStringLiteral(
                    "扫描未能完成，可更换卷或确认程序以管理员权限运行后重试。"));
                kLogEvent event;
                err << event << "[FileDock] 扫描误删失败, volume=" << request.volume.toStdString()
                    << ", error=" << result.error.toStdString() << eol;
                kPro.set(request.progressPid, "扫描失败", 0, 100.0f);
                QMessageBox::warning(this, QStringLiteral("扫描失败"), result.error);
                return true;
            }
            // Publication, including the current filter, is a separate pure-value worker.
            // Keep the old model intact until that complete projection passes the menu barrier.
            retireRecoverySnapshot(std::move(m_recoveryPendingSnapshot));
            m_recoveryPendingSnapshot = result.snapshot;
            // The previous table's one-shot header sort was reset by a fresh scan.
            m_recoverySortColumn = -1;
            m_recoverySortOrder = Qt::AscendingOrder;
            m_recoveryTable->horizontalHeader()->setSortIndicatorShown(false);
            applyRecoveryFilter();
            kLogEvent event;
            info << event << "[FileDock] 扫描误删完成, volume=" << request.volume.toStdString()
                << ", total=" << result.snapshot->entries.size() << eol;
            kPro.set(request.progressPid, "扫描完成", 0, 100.0f);
            return true;
        },
        [this, progressPid](std::exception_ptr)
        {
            m_recoveryScanInProgress = false;
            m_recoveryScanButton->setEnabled(!m_recoveryRecoverInProgress);
            m_recoveryEmptyScanButton->setEnabled(!m_recoveryRecoverInProgress);
            m_recoveryExportButton->setEnabled(!m_recoveryRecoverInProgress);
            m_recoveryStatusLabel->setText(QStringLiteral("扫描失败"));
            kPro.set(progressPid, "扫描失败", 0, 100.0f);
        },
        [progressPid](ks::ui::AsyncOperationOutcome outcome)
        {
            if (outcome != ks::ui::AsyncOperationOutcome::Applied && outcome != ks::ui::AsyncOperationOutcome::Failed)
                kPro.set(progressPid, "界面已关闭", 0, 100.0f);
        });
}

void FileDock::recoverSelectedDeletedFiles()
{
    // 对外保留同步入口名，内部改为异步实现，避免阻塞 UI。
    recoverSelectedDeletedFilesAsync();
}

void FileDock::recoverSelectedDeletedFilesAsync()
{
    if (m_recoveryTable == nullptr || m_recoveryRecoverInProgress) return;
    const auto snapshot = static_cast<DeletedRecoveryModel*>(m_recoveryModel)->snapshot();
    if (!snapshot) return;
    auto selected = m_recoverySelectedSourceRows.values();
    std::sort(selected.begin(), selected.end());
    std::vector<ks::file::NtfsDeletedFileEntry> selectedItems;
    selectedItems.reserve(static_cast<std::size_t>(selected.size()));
    for (int source : selected) if (source >= 0 && source < static_cast<int>(snapshot->entries.size()))
        selectedItems.push_back(snapshot->entries[static_cast<std::size_t>(source)]);
    recoverDeletedFileEntriesAsync(snapshot->volumeRoot, std::move(selectedItems));
}

void FileDock::recoverDeletedFileEntriesAsync(const QString& sourceVolume,
    std::vector<ks::file::NtfsDeletedFileEntry> selectedItems)
{
    if (m_recoveryRecoverInProgress || m_recoveryScanInProgress) return;
    if (selectedItems.empty())
    {
        QMessageBox::information(this, QStringLiteral("文件恢复"), QStringLiteral("请先在列表中选择要恢复的条目。"));
        return;
    }
    const QString volumeRoot = sourceVolume;
    const QPointer<FileDock> guardThis(this);
    const QString exportDir = QFileDialog::getExistingDirectory(this,
        QStringLiteral("选择恢复输出目录"), QDir::homePath());
    if (!guardThis || exportDir.isEmpty()) return;
    if (m_recoveryRecoverInProgress || m_recoveryScanInProgress) return;
    const bool hasSafelyRecoverableItem = std::any_of(
        selectedItems.begin(),
        selectedItems.end(),
        [](const ks::file::NtfsDeletedFileEntry& item) {
            return isDeletedFileSafelyRecoverable(item);
        });
    if (!hasSafelyRecoverableItem)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("文件恢复"),
            QStringLiteral("选中项均不满足安全恢复条件；请查看“恢复能力”和“完整度”列。"));
        return;
    }

    const bool hasIntactNonResidentItem = std::any_of(
        selectedItems.begin(),
        selectedItems.end(),
        [](const ks::file::NtfsDeletedFileEntry& item) {
            return item.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::NonResidentIntact;
        });
    const QString sourceVolumeRoot = localVolumeRootForPath(volumeRoot);
    const QString outputVolumeRoot = localVolumeRootForPath(exportDir);
    if (hasIntactNonResidentItem &&
        !sourceVolumeRoot.isEmpty() &&
        sourceVolumeRoot.compare(outputVolumeRoot, Qt::CaseInsensitive) == 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("非驻留恢复需要其它卷"),
            QStringLiteral(
                "选中项包含非驻留文件。不能把恢复结果写回源卷 %1，"
                "因为输出文件分配空间时可能直接覆盖待恢复簇。\n\n"
                "请重新选择其它本地卷或网络目录。")
                .arg(sourceVolumeRoot));
        return;
    }

    m_recoveryRecoverInProgress = true;
    if (m_recoveryScanButton != nullptr)
    {
        m_recoveryScanButton->setEnabled(false);
        if (m_recoveryEmptyScanButton != nullptr) { m_recoveryEmptyScanButton->setEnabled(false); }
    }
    if (m_recoveryExportButton != nullptr)
    {
        m_recoveryExportButton->setEnabled(false);
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 开始恢复选中误删项, volume="
            << QDir::toNativeSeparators(volumeRoot).toStdString()
            << ", selectedRows="
            << selectedItems.size()
            << eol;
    }

    const int progressPid = kPro.add(this, "文件恢复", "恢复选中");
    kPro.set(progressPid, "准备恢复", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    const auto dispatcher = m_uiDispatcher;
    std::thread([safeThis, dispatcher, progressPid, volumeRoot, exportDir, selectedItems]() {
        int successCount = 0;
        QStringList failTextList;
        QSet<QString> reservedTargetPathSet;

        for (std::size_t index = 0; index < selectedItems.size(); ++index)
        {
            const ks::file::NtfsDeletedFileEntry& deletedItem = selectedItems[index];
            QString exportName = deletedItem.fileName.trimmed();
            if (exportName.isEmpty())
            {
                exportName = QStringLiteral("deleted_%1.bin").arg(deletedItem.fileReference);
            }
            const QString targetPath = uniqueRecoveryTargetPath(
                exportDir,
                exportName,
                deletedItem.fileReference,
                reservedTargetPathSet);
            QString errorText;
            const bool ok = ks::file::ManualFileSystemParser::recoverNtfsDeletedFile(
                volumeRoot,
                deletedItem,
                targetPath,
                errorText,
                [progressPid, index, itemCount = selectedItems.size()](
                    const int itemPercent,
                    const QString& stageText) {
                    const float completedItemRatio =
                        static_cast<float>(index) /
                        static_cast<float>(std::max<std::size_t>(itemCount, 1));
                    const float currentItemRatio =
                        (static_cast<float>(std::clamp(itemPercent, 0, 100)) / 100.0f) /
                        static_cast<float>(std::max<std::size_t>(itemCount, 1));
                    const float mappedProgress =
                        5.0f + (completedItemRatio + currentItemRatio) * 90.0f;
                    kPro.set(
                        progressPid,
                        stageText.toStdString(),
                        0,
                        mappedProgress);
                });
            if (ok)
            {
                ++successCount;
            }
            else
            {
                failTextList.push_back(QStringLiteral("%1: %2").arg(exportName, errorText));
            }

            const float progress = 5.0f
                + (static_cast<float>(index + 1) / static_cast<float>(selectedItems.size())) * 90.0f;
            kPro.set(progressPid, "恢复处理中", 0, progress);
        }

        dispatcher->post(
            [safeThis, progressPid, successCount, failTextList]() {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                safeThis->m_recoveryRecoverInProgress = false;
                if (safeThis->m_recoveryScanButton != nullptr)
                {
                    safeThis->m_recoveryScanButton->setEnabled(true);
                    if (safeThis->m_recoveryEmptyScanButton != nullptr) { safeThis->m_recoveryEmptyScanButton->setEnabled(true); }
                }
                if (safeThis->m_recoveryExportButton != nullptr)
                {
                    safeThis->m_recoveryExportButton->setEnabled(true);
                }

                const QString summaryText = QStringLiteral("恢复完成：成功 %1，失败 %2。")
                    .arg(successCount)
                    .arg(failTextList.size());
                safeThis->m_recoveryStatusLabel->setText(summaryText);

                if (failTextList.empty())
                {
                    kLogEvent event;
                    info << event
                        << "[FileDock] 恢复完成, success="
                        << successCount
                        << ", failed=0"
                        << eol;
                    QMessageBox::information(safeThis.data(), QStringLiteral("文件恢复"), summaryText);
                }
                else
                {
                    kLogEvent event;
                    warn << event
                        << "[FileDock] 恢复部分失败, success="
                        << successCount
                        << ", failed="
                        << failTextList.size()
                        << eol;
                    QMessageBox::warning(
                        safeThis.data(),
                        QStringLiteral("文件恢复"),
                        summaryText + QStringLiteral("\n\n失败明细：\n") + failTextList.join('\n'));
                }

                kPro.set(progressPid, "恢复完成", 0, 100.0f);
            },
            [progressPid]()
            {
                kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            });
    }).detach();
}

namespace
{
    // 递归隐藏禁用动作和空子菜单；Qt 同时折叠首尾/连续分隔线。
    bool hideUnavailableFileMenuActions(QMenu& menu)
    {
        menu.setSeparatorsCollapsible(true);
        bool hasVisibleAction = false;
        for (QAction* action : menu.actions())
        {
            if (action->isSeparator()) continue;
            QMenu* child = action->menu();
            const bool childHasActions = child == nullptr || hideUnavailableFileMenuActions(*child);
            const bool visible = action->isVisible() && action->isEnabled() && childHasActions;
            action->setVisible(visible);
            hasVisibleAction = hasVisibleAction || visible;
        }
        return hasVisibleAction;
    }
}

void FileDock::showPanelContextMenu(FilePanelWidgets& panel, const QPoint& localPos)
{
    kLogEvent menuOpenEvent;
    dbg << menuOpenEvent
        << "[FileDock] 打开右键菜单, panel="
        << panel.panelNameText.toStdString()
        << ", localPos=("
        << localPos.x()
        << ","
        << localPos.y()
        << ")"
        << eol;

    // 右键命中行时，优先保证“命中行”与“选中集合”一致。
    // 说明：若命中的是已选中行，则保留原多选；若命中未选中行，则切成该单行。
    QAbstractItemView* menuView =
        (panel.viewModeCombo->currentIndex() <= 1)
        ? static_cast<QAbstractItemView*>(panel.compactFileView)
        : static_cast<QAbstractItemView*>(panel.fileView);
    const QModelIndex hitIndex = menuView->indexAt(localPos);
    QItemSelectionModel* selectionModel = menuView->selectionModel();
    if (hitIndex.isValid() && selectionModel != nullptr)
    {
        const QModelIndex hitRowIndex = hitIndex.siblingAtColumn(0);
        const bool hitAlreadySelected =
            selectionModel->isRowSelected(hitIndex.row(), hitIndex.parent()) ||
            (hitRowIndex.isValid() && selectionModel->isSelected(hitRowIndex));
        if (!hitAlreadySelected)
        {
            selectionModel->select(hitIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        // 右键菜单入口只同步当前焦点，不让 current index 更新反向破坏多选集合。
        selectionModel->setCurrentIndex(hitIndex, QItemSelectionModel::NoUpdate);
    }

    // 右键菜单所使用的数据统一来自“当前选中集合”。
    const std::vector<QString> menuPaths = selectedPaths(panel);
    const bool hasSelection = !menuPaths.empty();
    const bool isSingleSelection = menuPaths.size() == 1;
    const QString firstPath = isSingleSelection ? menuPaths.front() : QString();
    bool hasAnyFile = false;
    std::vector<QString> menuFilePaths;
    QSet<QString> selectedFileKeys;
    if (selectionModel)
    {
        QModelIndexList fileRows = selectionModel->selectedRows(0);
        if (fileRows.isEmpty() && menuView->currentIndex().isValid())
            fileRows.push_back(menuView->currentIndex().siblingAtColumn(0));
        for (const QModelIndex& selected : fileRows)
        {
            const bool manual = currentModeIsManual(panel);
            const QModelIndex source = manual ? panel.manualProxyModel->mapToSource(selected) : panel.proxyModel->mapToSource(selected);
            if (!source.isValid()) continue;
            const bool directory = manual ? source.data(Qt::UserRole + 1).toBool() : panel.fsModel->isDir(source);
            if (!directory)
            {
                const QString path = manual ? source.data(Qt::UserRole).toString() : panel.fsModel->filePath(source);
                selectedFileKeys.insert(path.toCaseFolded());
            }
        }
    }
    for (const auto& path : menuPaths)
        if (selectedFileKeys.contains(path.toCaseFolded())) menuFilePaths.push_back(path);
    hasAnyFile = !menuFilePaths.empty();
    QStringList linkTargetList;
    QString firstLinkTarget;
    QString firstLinkLocatePath;

    // 复制/移动是双栏文件管理器语义：源面板的选中项会直接落到对侧面板。
    // 菜单文案必须把目标面板说清楚，避免用户误解为 Windows 剪贴板“复制/剪切”。
    FilePanelWidgets* const transferTargetPanel = oppositePanelFor(panel);
    const QString transferTargetText = (transferTargetPanel != nullptr)
        ? transferTargetPanel->panelNameText
        : QStringLiteral("对侧面板");
    const QString localizedTransferTargetText = ks::i18n::displayText(transferTargetText);
    const QString copyToPanelText = ks::i18n::displayText(QStringLiteral("复制到%1"))
        .arg(localizedTransferTargetText);
    const QString moveToPanelText = ks::i18n::displayText(QStringLiteral("移动到%1"))
        .arg(localizedTransferTargetText);

    QMenu menu(this);
    menu.setStyleSheet(buildContextMenuStyle());
    QAction* openAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("打开/运行"));
    QMenu* runAsMenu = menu.addMenu(QIcon(":/Icon/process_start.svg"),
        ks::i18n::displayText(QStringLiteral("以特殊权限运行")));
    QAction* runAsSystemAction = runAsMenu->addAction(QStringLiteral("System"));
    QAction* runAsTrustedInstallerAction = runAsMenu->addAction(QStringLiteral("TrustedInstaller"));
    QAction* runAsAdministratorAction = runAsMenu->addAction(
        ks::i18n::displayText(QStringLiteral("管理员")));
    QAction* runAsStandardAction = runAsMenu->addAction(
        ks::i18n::displayText(QStringLiteral("普通用户")));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径(Ctrl+C)"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* copyShortNameAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制短文件名"));
    QAction* copyLinkTargetAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制链接目标"));
    QAction* openLinkTargetAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("打开链接目标"));
    QAction* locateLinkTargetAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("定位链接目标"));
    menu.addSeparator();
    QAction* copyAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), copyToPanelText);
    QAction* cutAction = menu.addAction(QIcon(":/Icon/process_suspend.svg"), moveToPanelText);
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名(F2)"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除(Delete)"));
    // 删除方式按权限强度从低到高排列：越靠下越不可逆、要求的权限越高。
    QMenu* deleteModeMenu = menu.addMenu(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除方式（递归/多权限）"));
    deleteModeMenu->setToolTipsVisible(true);
    QAction* permanentDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("永久删除（R3·当前权限）"));
    permanentDeleteAction->setToolTip(
        QStringLiteral("以当前用户权限递归永久删除，不进回收站；目录按子项先删、目录后删的顺序处理。"));
    QAction* forceDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/file_owner.svg"), QStringLiteral("强制删除（R3·接管所有权）"));
    forceDeleteAction->setToolTip(
        QStringLiteral("清除只读/隐藏/系统属性，必要时接管所有权并授予完全控制后再递归删除；需要管理员权限。"));
    QAction* pendingRebootDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/process_resume.svg"), QStringLiteral("重启后删除（R3·启动时执行）"));
    pendingRebootDeleteAction->setToolTip(
        QStringLiteral("登记 PendingFileRenameOperations，由系统在下次重启早期删除；适合正被占用的目标，需要管理员权限。"));
    // R0 作为顶层快捷入口，避免强制用户再穿过“删除方式”子菜单；三个动作仍共用
    // 统一的不可逆确认、后台递归和统计链路。
    QMenu* r0DeleteMenu = menu.addMenu(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("R0"));
    r0DeleteMenu->setToolTipsVisible(true);
    QAction* driverNativeDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动（底层方案）"));
    driverNativeDeleteAction->setToolTip(QStringLiteral(
        "由 R0 用 ZwCreateFile/ZwSetInformationFile 删除；失败时保留现有的 DispositionEx 兼容重试。"));
    QAction* driverIrpDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(IRP)"));
    driverIrpDeleteAction->setToolTip(QStringLiteral(
        "由 R0 构造 IRP_MJ_SET_INFORMATION/FileDispositionInformation 并投递完整文件系统栈；不回退到底层方案。"));
    QAction* driverPosixDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(POSIX)"));
    driverPosixDeleteAction->setToolTip(QStringLiteral(
        "由 R0 使用 FileDispositionInformationEx 的 POSIX unlink 语义；是否可用取决于系统与文件系统，不回退到其它后端。"));
    QAction* driverIgnoreShareDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(POSIX·忽略共享检查，高风险)"));
    driverIgnoreShareDeleteAction->setToolTip(QStringLiteral(
        "仅单文件；尝试跳过 I/O 管理器共享检查，文件系统仍可能拒绝。"));
    QMenu* addOplockMenu = menu.addMenu(QIcon(":/Icon/plus.svg"), QStringLiteral("添加 Oplock（访问计数）"));
    QAction* addOplockLevel1Action = addOplockMenu->addAction(QStringLiteral("Level 1 - 独占读写缓存，别人访问会计数"));
    QAction* addOplockLevel2Action = addOplockMenu->addAction(QStringLiteral("Level 2 - 共享只读缓存，别人写入会计数"));
    QAction* addOplockBatchAction = addOplockMenu->addAction(QStringLiteral("Batch - 缓存反复打开关闭，访问时计数"));
    QAction* addOplockFilterAction = addOplockMenu->addAction(QStringLiteral("Filter - 扫描器/过滤器用，访问前计数"));
    QAction* showOplockRecordsAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("查看 Oplock 访问记录"));
    QAction* releaseOplockAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("释放当前 Oplock"));
    QAction* releaseAllOplocksAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("释放全部 Oplock"));
    QAction* takeOwnerAction = menu.addAction(QIcon(":/Icon/file_owner.svg"), QStringLiteral("取得所有权"));
    QMenu* fileIntegritySubMenu = menu.addMenu(QIcon(":/Icon/file_owner.svg"), QStringLiteral("文件完整性"));
    fileIntegritySubMenu->setToolTipsVisible(true);
    fileIntegritySubMenu->setEnabled(hasSelection);
    if (hasSelection) fileIntegritySubMenu->setToolTip(ks::i18n::displayText(QStringLiteral("正在加载...")));
    for (const FileIntegrityLevelPreset& preset : FileIntegrityLevelPresets)
    {
        const bool isCurrentLevel = false;
        QAction* integrityAction = fileIntegritySubMenu->addAction(
            QIcon(":/Icon/file_owner.svg"),
            QStringLiteral("%1 %2 - %3")
                .arg(isCurrentLevel ? QStringLiteral("●") : QStringLiteral(" "))
                .arg(QString::fromLatin1(preset.nameText))
                .arg(QString::fromUtf8(preset.detailText)));
        integrityAction->setData(static_cast<unsigned int>(preset.rid));
    }
    menu.addSeparator();
    QAction* newFileAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("新建文件"));
    QAction* newFolderAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建文件夹"));
    QAction* openTerminalAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("在终端中打开"));
    menu.addSeparator();
    QAction* columnAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("选择列..."));
    menu.addSeparator();

    // 分析动作改为顶层菜单，减少层级并提升右键操作效率。
    QAction* hashAction = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("计算哈希值"));
    QAction* signAction = menu.addAction(QIcon(":/Icon/process_critical.svg"), QStringLiteral("检查数字签名"));
    QAction* entropyAction = menu.addAction(QIcon(":/Icon/disk_analyze.svg"), QStringLiteral("计算熵值"));
    QAction* hexAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("十六进制查看"));
    QAction* peAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("在PE查看器中打开"));
    menu.addSeparator();
    QAction* mappedProcessScanAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("扫描映射进程(R0)"));
    QAction* unlockByDriverAction = menu.addAction(
        QIcon(":/Icon/handle_close.svg"),
        ks::i18n::displayText(QStringLiteral("文件解锁器")));
    unlockByDriverAction->setToolTip(QStringLiteral("在文件属性中扫描占用，并提供关闭句柄、R3/R0 结束进程操作"));
    menu.addSeparator();
    QMenu* pluginMenu = menu.addMenu(QIcon(":/Icon/process_start.svg"), QStringLiteral("插件"));
    menu.addSeparator();
    QAction* detailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("属性..."));

    // 结合选中集合动态启用菜单项，保证“多选”和“右键动作”行为一致。
    const bool singleFileOnly = isSingleSelection && hasAnyFile;
    const bool executableSelected = singleFileOnly &&
        QFileInfo(firstPath).suffix().compare(QStringLiteral("exe"), Qt::CaseInsensitive) == 0;
    const ks::process::RunAsAvailability runAsAvailability{ false, false, false, false };
    runAsMenu->setEnabled(executableSelected);
    runAsSystemAction->setEnabled(executableSelected && runAsAvailability.system);
    runAsTrustedInstallerAction->setEnabled(executableSelected && runAsAvailability.trustedInstaller);
    runAsAdministratorAction->setEnabled(executableSelected && runAsAvailability.administrator);
    runAsStandardAction->setEnabled(executableSelected && runAsAvailability.standardUser);
    ks::plugin_host::InvocationContext pluginContext;
    pluginContext.targetKind = ks::plugin_host::TargetKind::File;
    pluginContext.filePath = firstPath;
    ks::plugin_host::populateTargetMenu(pluginMenu, this, pluginContext);
    const bool firstPathHasOplock = singleFileOnly && hasActiveOplockForPath(firstPath);
    const std::uint64_t firstPathOplockBreakCount = firstPathHasOplock
        ? activeOplockBreakCountForPath(firstPath)
        : 0U;
    const std::size_t firstPathOplockAccessProcessCount = firstPathHasOplock
        ? activeOplockAccessProcessCountForPath(firstPath)
        : 0U;
    const std::size_t currentOplockCount = activeOplockCount();
    openAction->setEnabled(hasSelection);
    copyPathAction->setEnabled(hasSelection);
    copyKernelPathAction->setEnabled(hasSelection);
    copyShortNameAction->setEnabled(hasSelection);
    copyLinkTargetAction->setEnabled(!linkTargetList.isEmpty());
    openLinkTargetAction->setEnabled(!firstLinkTarget.isEmpty());
    locateLinkTargetAction->setEnabled(!firstLinkTarget.isEmpty());
    copyAction->setEnabled(hasSelection);
    cutAction->setEnabled(hasSelection);
    const bool mutationBusy = m_fileMutationOperation && m_fileMutationOperation->isInFlight();
    renameAction->setEnabled(isSingleSelection && !mutationBusy);
    newFileAction->setEnabled(!mutationBusy);
    newFolderAction->setEnabled(!mutationBusy);
    fileIntegritySubMenu->setEnabled(hasSelection && !mutationBusy);
    deleteAction->setEnabled(hasSelection);
    deleteModeMenu->setEnabled(hasSelection);
    permanentDeleteAction->setEnabled(hasSelection);
    forceDeleteAction->setEnabled(hasSelection);
    pendingRebootDeleteAction->setEnabled(hasSelection);
    r0DeleteMenu->setEnabled(hasSelection);
    driverNativeDeleteAction->setEnabled(hasSelection);
    driverIrpDeleteAction->setEnabled(hasSelection);
    driverPosixDeleteAction->setEnabled(hasSelection);
    driverIgnoreShareDeleteAction->setEnabled(singleFileOnly);
    unlockByDriverAction->setEnabled(isSingleSelection);
    const bool canAddOplock = singleFileOnly && !firstPathHasOplock
        && !m_releasingOplockPaths.contains(normalizeFileDockPath(firstPath), Qt::CaseInsensitive);
    addOplockMenu->setEnabled(canAddOplock);
    addOplockLevel1Action->setEnabled(canAddOplock);
    addOplockLevel2Action->setEnabled(canAddOplock);
    addOplockBatchAction->setEnabled(canAddOplock);
    addOplockFilterAction->setEnabled(canAddOplock);
    if (firstPathHasOplock)
    {
        showOplockRecordsAction->setText(
            QStringLiteral("查看 Oplock 访问记录（%1 个进程）").arg(firstPathOplockAccessProcessCount));
        releaseOplockAction->setText(
            QStringLiteral("释放当前 Oplock（已触发 %1 次）").arg(firstPathOplockBreakCount));
    }
    showOplockRecordsAction->setEnabled(firstPathHasOplock);
    releaseOplockAction->setEnabled(firstPathHasOplock);
    releaseAllOplocksAction->setEnabled(currentOplockCount > 0U);
    takeOwnerAction->setEnabled(hasSelection);
    detailAction->setEnabled(hasSelection);
    hashAction->setEnabled(hasAnyFile && (m_fileAnalysisOperation == nullptr || !m_fileAnalysisOperation->isInFlight()));
    signAction->setEnabled(hasAnyFile);
    entropyAction->setEnabled(hasAnyFile && (m_fileAnalysisOperation == nullptr || !m_fileAnalysisOperation->isInFlight()));
    hexAction->setEnabled(singleFileOnly);
    peAction->setEnabled(singleFileOnly);
    mappedProcessScanAction->setEnabled(hasAnyFile);
    pluginMenu->setEnabled(singleFileOnly);

    if (!m_fileMenuOperation) m_fileMenuOperation = new ks::ui::AsyncOperation(this);
    const QPointer<QMenu> menuGuard(&menu);
    if (hasSelection)
    {
        m_fileMenuOperation->submit<FileMenuMetadataRequest, FileMenuMetadata>(
            { menuPaths, executableSelected }, queryFileMenuMetadata,
            [menuGuard, fileIntegritySubMenu, runAsMenu, runAsSystemAction, runAsTrustedInstallerAction,
                runAsAdministratorAction, runAsStandardAction, copyLinkTargetAction, openLinkTargetAction,
                locateLinkTargetAction, executableSelected, isSingleSelection, selectionCount = menuPaths.size(), &linkTargetList,
                &firstLinkTarget, &firstLinkLocatePath](const FileMenuMetadata& result, std::uint64_t)
            {
                if (!menuGuard || !menuGuard->isVisible()) return true;
                fileIntegritySubMenu->setToolTip(result.integrityKnown
                    ? (result.implicitMedium ? QStringLiteral("当前未设置显式 Mandatory Label，Windows 按 Medium 处理。")
                        : (selectionCount > 1 ? QStringLiteral("多选时圆点按第一项的文件完整性显示，执行时会批量写入所有选中项。") : QString()))
                    : QStringLiteral("当前文件完整性读取失败：%1").arg(result.integrityDetail));
                for (QAction* action : fileIntegritySubMenu->actions())
                {
                    const DWORD rid = action->data().toUInt();
                    const auto preset = std::find_if(std::begin(FileIntegrityLevelPresets), std::end(FileIntegrityLevelPresets),
                        [rid](const auto& value) { return value.rid == rid; });
                    if (preset == std::end(FileIntegrityLevelPresets)) continue;
                    action->setText(QStringLiteral("%1 %2 - %3")
                        .arg(result.integrityKnown && result.integrityRid == rid ? QStringLiteral("●") : QStringLiteral(" "))
                        .arg(QString::fromLatin1(preset->nameText)).arg(QString::fromUtf8(preset->detailText)));
                }
                linkTargetList = result.links;
                firstLinkTarget = isSingleSelection && !result.links.isEmpty() ? result.links.front() : QString();
                firstLinkLocatePath = result.locatePath;
                const auto available = [](QAction* action, const bool enabled)
                { action->setEnabled(enabled); action->setVisible(enabled); };
                available(copyLinkTargetAction, !linkTargetList.isEmpty());
                available(openLinkTargetAction, !firstLinkTarget.isEmpty());
                available(locateLinkTargetAction, !firstLinkTarget.isEmpty());
                available(runAsSystemAction, executableSelected && result.runAs.system);
                available(runAsTrustedInstallerAction, executableSelected && result.runAs.trustedInstaller);
                available(runAsAdministratorAction, executableSelected && result.runAs.administrator);
                available(runAsStandardAction, executableSelected && result.runAs.standardUser);
                runAsMenu->setEnabled(executableSelected);
                runAsMenu->menuAction()->setVisible(executableSelected);
                hideUnavailableFileMenuActions(*menuGuard);
                return true;
            }, [](std::exception_ptr) { kLogEvent event; warn << event << "[FileDock] menu metadata failed" << eol; });
    }
    connect(&menu, &QMenu::aboutToHide, this, [this]() { if (m_fileMenuOperation) m_fileMenuOperation->cancel(); });
    hideUnavailableFileMenuActions(menu);
    const QPointer<FileDock> self(this);
    QAction* selectedAction = menu.exec(menuView->viewport()->mapToGlobal(localPos));
    if (!self) return;
    if (selectedAction == nullptr)
    {
        kLogEvent menuCancelEvent;
        dbg << menuCancelEvent
            << "[FileDock] 右键菜单取消, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    {
        kLogEvent menuActionEvent;
        info << menuActionEvent
            << "[FileDock] 右键菜单执行动作, panel="
            << panel.panelNameText.toStdString()
            << ", action="
            << selectedAction->text().toStdString()
            << ", selectedCount="
            << menuPaths.size()
            << eol;
    }

    if (selectedAction->parent() == runAsMenu)
    {
        const ks::process::RunAsIdentity identity = selectedAction == runAsSystemAction
            ? ks::process::RunAsIdentity::System
            : selectedAction == runAsTrustedInstallerAction
                ? ks::process::RunAsIdentity::TrustedInstaller
                : selectedAction == runAsAdministratorAction
                    ? ks::process::RunAsIdentity::Administrator
                    : ks::process::RunAsIdentity::StandardUser;
        const QString identityText = selectedAction->text();
        const std::wstring executablePath = QDir::toNativeSeparators(firstPath).toStdWString();
        const QPointer<FileDock> guardedSelf(this);
        const auto dispatcher = m_uiDispatcher;
        QThreadPool::globalInstance()->start([guardedSelf, dispatcher, executablePath, identity, identityText]()
            {
                const auto result = ks::process::RunExecutableAs(executablePath, identity);
                kLogEvent event;
                (result.success ? info : warn) << event
                    << "[FileDock] Run executable as, identity=" << identityText.toStdString()
                    << ", pid=" << result.processId << ", error=" << result.error << eol;
                dispatcher->post([guardedSelf, result, identityText]()
                    {
                        if (guardedSelf.isNull() || result.success || result.error == ERROR_CANCELLED) return;
                        QMessageBox::warning(guardedSelf.data(),
                            ks::i18n::displayText(QStringLiteral("以特殊权限运行")),
                            ks::i18n::displayText(QStringLiteral("无法以 %1 权限运行该程序。\n错误码：%2\n%3"))
                                .arg(identityText).arg(result.error)
                                .arg(ks::i18n::packedSourceText(QString::fromStdWString(result.detail))));
                    });
            });
        return;
    }
    if (selectedAction->parent() == fileIntegritySubMenu)
    {
        const DWORD integrityRid = selectedAction->data().toUInt();
        setSelectedFileIntegrityLevel(
            panel,
            integrityRid,
            fileIntegrityNameFromRid(integrityRid), menuPaths);
        return;
    }
    if (selectedAction == openAction)
    {
        openSelectedItems(panel);
        return;
    }
    if (selectedAction == copyPathAction)
    {
        copySelectedItemPath(panel);
        return;
    }
    if (selectedAction == copyKernelPathAction)
    {
        copySelectedItemKernelPath(panel);
        return;
    }
    if (selectedAction == copyShortNameAction)
    {
        copySelectedItemShortName(panel);
        return;
    }
    if (selectedAction == copyLinkTargetAction)
    {
        QApplication::clipboard()->setText(linkTargetList.join(QStringLiteral("\n")));
        kLogEvent event;
        info << event
            << "[FileDock] 复制链接目标到剪贴板, panel="
            << panel.panelNameText.toStdString()
            << ", count="
            << linkTargetList.size()
            << eol;
        return;
    }
    if (selectedAction == openLinkTargetAction)
    {
        const bool openOk = QDesktopServices::openUrl(QUrl::fromLocalFile(firstLinkTarget));
        if (!openOk)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("打开链接目标"),
                QStringLiteral("无法打开链接目标：%1").arg(QDir::toNativeSeparators(firstLinkTarget)));
        }
        return;
    }
    if (selectedAction == locateLinkTargetAction)
    {
        const QString locatePath = firstLinkLocatePath;
        if (locatePath.trimmed().isEmpty())
        {
            QMessageBox::warning(
                this,
                QStringLiteral("定位链接目标"),
                QStringLiteral("目标所在目录不存在或不可访问：%1").arg(QDir::toNativeSeparators(firstLinkTarget)));
            return;
        }
        navigateToPath(panel, locatePath, true);
        return;
    }
    if (selectedAction == copyAction)
    {
        copySelectedItems(panel);
        return;
    }
    if (selectedAction == cutAction)
    {
        cutSelectedItems(panel);
        return;
    }
    if (selectedAction == renameAction)
    {
        renameSelectedItem(panel);
        return;
    }
    if (selectedAction == deleteAction)
    {
        deleteSelectedItem(panel);
        return;
    }
    if (selectedAction == permanentDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::PermanentR3);
        return;
    }
    if (selectedAction == forceDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::ForceR3);
        return;
    }
    if (selectedAction == pendingRebootDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::PendingReboot);
        return;
    }
    if (selectedAction == driverNativeDeleteAction)
    {
        deleteSelectedItemByDriver(panel);
        return;
    }
    if (selectedAction == driverIrpDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0Irp);
        return;
    }
    if (selectedAction == driverPosixDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0Posix);
        return;
    }
    if (selectedAction == driverIgnoreShareDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0IgnoreSharePosix);
        return;
    }
    if (selectedAction == unlockByDriverAction)
    {
        unlockSelectedItemsByDriver(panel);
        return;
    }
    if (selectedAction == addOplockLevel1Action)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Level1);
        return;
    }
    if (selectedAction == addOplockLevel2Action)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Level2);
        return;
    }
    if (selectedAction == addOplockBatchAction)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Batch);
        return;
    }
    if (selectedAction == addOplockFilterAction)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Filter);
        return;
    }
    if (selectedAction == showOplockRecordsAction)
    {
        showSelectedFileOplockAccessRecords(panel);
        return;
    }
    if (selectedAction == releaseOplockAction)
    {
        releaseSelectedFileOplock(panel);
        return;
    }
    if (selectedAction == releaseAllOplocksAction)
    {
        releaseAllActiveOplocks(true);
        return;
    }
    if (selectedAction == takeOwnerAction)
    {
        takeOwnershipSelectedItems(panel);
        return;
    }
    if (selectedAction == newFileAction)
    {
        createNewFileOrFolder(panel, false);
        return;
    }
    if (selectedAction == newFolderAction)
    {
        createNewFileOrFolder(panel, true);
        return;
    }
    if (selectedAction == openTerminalAction)
    {
        const QString workPath = panel.currentPath.isEmpty() ? QDir::homePath() : panel.currentPath;
        DWORD terminalErrorCode = ERROR_SUCCESS;
        const bool startOk = openCommandPromptInDirectory(workPath, &terminalErrorCode);
        kLogEvent terminalEvent;
        if (!startOk)
        {
            warn << terminalEvent
                << "[FileDock] 在终端中打开失败, panel="
                << panel.panelNameText.toStdString()
                << ", workPath="
                << QDir::toNativeSeparators(workPath).toStdString()
                << ", error="
                << terminalErrorCode
                << eol;
        }
        else
        {
            info << terminalEvent
                << "[FileDock] 在终端中打开完成, panel="
                << panel.panelNameText.toStdString()
                << ", workPath="
                << QDir::toNativeSeparators(workPath).toStdString()
                << eol;
        }
        return;
    }
    if (selectedAction == columnAction)
    {
        showColumnManagerDialog(panel);
        return;
    }
    if (selectedAction == detailAction)
    {
        QStringList detailPaths;
        detailPaths.reserve(static_cast<qsizetype>(menuPaths.size()));
        for (const QString& path : menuPaths) detailPaths.push_back(path);
        showFileDetailDialog(detailPaths);

        kLogEvent detailEvent;
        info << detailEvent
            << "[FileDock] 属性窗口打开完成, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << menuPaths.size()
            << eol;
        return;
    }
    if (selectedAction == hashAction || selectedAction == entropyAction)
    {
        if (!hasAnyFile) return;
        if (m_fileAnalysisOperation == nullptr) m_fileAnalysisOperation = new ks::ui::AsyncOperation(this);
        if (m_fileAnalysisOperation->isInFlight()) return;
        const bool hash = selectedAction == hashAction;
        const QString title = ks::i18n::displayText(hash ? QStringLiteral("计算哈希值") : QStringLiteral("计算熵值"));
        const auto progress = std::make_shared<FileAnalysisProgress>();
        auto* dialog = new QProgressDialog(title, ks::i18n::displayText(QStringLiteral("取消")), 0, 100, this);
        dialog->setWindowTitle(title);
        dialog->setWindowModality(Qt::NonModal);
        dialog->setAutoClose(false);
        dialog->setAutoReset(false);
        dialog->setMinimumDuration(0);
        dialog->setValue(0);
        auto* timer = new QTimer(dialog);
        timer->setInterval(100);
        connect(timer, &QTimer::timeout, dialog, [dialog, progress]()
        {
            const int percent = progress->percent.load();
            if (!progress->cancel.load() && dialog->value() != percent) dialog->setValue(percent);
        });
        connect(dialog, &QProgressDialog::canceled, dialog, [progress]() { progress->cancel.store(true); });
        const QPointer<QProgressDialog> guard(dialog);
        m_fileAnalysisOperation->submit<FileAnalysisRequest, FileAnalysisResult>(
            { menuPaths, panel.panelNameText, hash, progress }, analyzeMenuFiles,
            [guard](const FileAnalysisResult&, std::uint64_t)
            { if (guard) guard->deleteLater(); return true; },
            [guard](std::exception_ptr)
            {
                kLogEvent event; warn << event << "[FileDock] file analysis worker failed" << eol;
                if (guard) guard->deleteLater();
            });
        timer->start();
        dialog->show();
        return;
    }
    if (selectedAction == signAction)
    {
        // 数字签名入口与属性页联动，支持多选逐个打开详情。
        if (!hasAnyFile)
        {
            kLogEvent signEmptyEvent;
            warn << signEmptyEvent
                << "[FileDock] 签名检查取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        constexpr std::size_t kMaxAutoOpenSignCount = 8;
        std::size_t openedCount = 0;
        for (const QString& path : menuFilePaths)
        {
            if (openedCount >= kMaxAutoOpenSignCount)
            {
                break;
            }
            showFileDetailDialog(path);
            openedCount += 1;
        }

        const std::size_t fileSelectionCount = menuFilePaths.size();
        kLogEvent signEvent;
        if (openedCount == kMaxAutoOpenSignCount && fileSelectionCount > kMaxAutoOpenSignCount)
        {
            warn << signEvent
                << "[FileDock] 签名检查已截断打开数量, panel="
                << panel.panelNameText.toStdString()
                << ", openedCount="
                << openedCount
                << ", fileSelectionCount="
                << fileSelectionCount
                << eol;
        }

        info << signEvent
            << "[FileDock] 签名检查完成, panel="
            << panel.panelNameText.toStdString()
            << ", openedCount="
            << openedCount
            << ", fileSelectionCount="
            << fileSelectionCount
            << eol;
        return;
    }
    if (selectedAction == hexAction || selectedAction == peAction)
    {
        if (singleFileOnly)
        {
            showFileDetailDialog(firstPath, selectedAction == hexAction ? QStringLiteral("hex") : QStringLiteral("pe"));
        }
        return;
    }
    if (selectedAction == mappedProcessScanAction)
    {
        openMappedProcessScanWindow(menuPaths);
        return;
    }
}

void FileDock::openSelectedItems(FilePanelWidgets& panel)
{
    // 打开逻辑支持多选：目录与文件分开处理，避免多目录时误切换当前面板路径。
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 打开选中项, panel="
            << panel.panelNameText.toStdString()
            << ", count="
            << paths.size()
            << eol;
    }

    int successCount = 0;
    int failCount = 0;
    QStringList failedPaths;
    for (const QString& path : paths)
    {
        QFileInfo info(path);
        if (info.isDir())
        {
            if (paths.size() == 1)
            {
                navigateToPath(panel, path, true);
                successCount += 1;
            }
            else
            {
                const bool openOk = QDesktopServices::openUrl(QUrl::fromLocalFile(path));
                if (openOk)
                {
                    successCount += 1;
                }
                else
                {
                    failCount += 1;
                    failedPaths.push_back(QDir::toNativeSeparators(path));
                }
            }
            continue;
        }

        const bool openOk = QDesktopServices::openUrl(QUrl::fromLocalFile(path));
        if (openOk)
        {
            successCount += 1;
        }
        else
        {
            failCount += 1;
            failedPaths.push_back(QDir::toNativeSeparators(path));
        }
    }

    kLogEvent resultEvent;
    if (failCount > 0)
    {
        warn << resultEvent
            << "[FileDock] 打开选中项部分失败, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failCount
            << ", failedPreview=\n"
            << buildLogPreviewText(failedPaths).toStdString()
            << eol;
        return;
    }

    info << resultEvent
        << "[FileDock] 打开选中项完成, panel="
        << panel.panelNameText.toStdString()
        << ", successCount="
        << successCount
        << eol;
}

void FileDock::copySelectedItemPath(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    QStringList lines;
    for (const QString& path : paths)
    {
        lines << QDir::toNativeSeparators(path);
    }
    QApplication::clipboard()->setText(lines.join('\n'));

    kLogEvent event;
    info << event
        << "[FileDock] 复制路径到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << eol;
}

void FileDock::copySelectedItemKernelPath(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    QStringList lines;
    lines.reserve(static_cast<int>(paths.size()));
    for (const QString& path : paths)
    {
        const QString kernelPath = buildDriverNtPath(path);
        lines << (kernelPath.isEmpty() ? QDir::toNativeSeparators(path) : kernelPath);
    }
    QApplication::clipboard()->setText(lines.join('\n'));

    kLogEvent event;
    info << event
        << "[FileDock] 复制内核模式地址到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << eol;
}

void FileDock::copySelectedItemShortName(FilePanelWidgets& panel)
{
    const auto paths = selectedPaths(panel);
    if (paths.empty()) return;
    if (!m_shortNameOperation) m_shortNameOperation = new ks::ui::AsyncOperation(this);
    QObject::disconnect(m_shortNameClipboardConnection);
    m_shortNameClipboardConnection = connect(QApplication::clipboard(), &QClipboard::dataChanged,
        m_shortNameOperation, [this]() { m_shortNameOperation->cancel(); });
    const QString panelName = panel.panelNameText;
    m_shortNameOperation->submit<std::vector<QString>, FileShortNameResult>(paths,
        [](const std::vector<QString>& targets, const ks::ui::AsyncOperationToken& token)
        {
            return queryFileShortNames(targets, queryShortPathText, [&token]() { return token.isCanceled(); });
        },
        [this, panelName, count = paths.size()](const FileShortNameResult& result, std::uint64_t)
        {
            QObject::disconnect(m_shortNameClipboardConnection);
            if (!result.canceled) QApplication::clipboard()->setText(result.text);
            kLogEvent event;
            info << event << "[FileDock] 复制短文件名到剪贴板, panel=" << panelName.toStdString()
                << ", count=" << count << ", shortNameHitCount=" << result.hits << ", fallbackCount=" << result.fallbacks << eol;
            return true;
        },
        [this](std::exception_ptr)
        {
            QObject::disconnect(m_shortNameClipboardConnection);
            kLogEvent event; warn << event << "[FileDock] short-name query failed" << eol;
        });
}

void FileDock::copySelectedItems(FilePanelWidgets& panel)
{
    transferSelectedItemsToOppositePanel(panel, false);
}

void FileDock::cutSelectedItems(FilePanelWidgets& panel)
{
    transferSelectedItemsToOppositePanel(panel, true);
}

FileDock::FilePanelWidgets* FileDock::oppositePanelFor(FilePanelWidgets& sourcePanel)
{
    if (&sourcePanel == &m_leftPanel)
    {
        return &m_rightPanel;
    }
    if (&sourcePanel == &m_rightPanel)
    {
        return &m_leftPanel;
    }
    return nullptr;
}

void FileDock::transferSelectedItemsToOppositePanel(FilePanelWidgets& sourcePanel, bool moveItems)
{
    if (m_transferInProgress)
    {
        return;
    }

    const std::vector<QString> selectedItemPaths = selectedPaths(sourcePanel);
    if (selectedItemPaths.empty())
    {
        return;
    }

    FilePanelWidgets* const targetPanel = oppositePanelFor(sourcePanel);
    if (targetPanel == nullptr || targetPanel->currentPath.trimmed().isEmpty())
    {
        kLogEvent event;
        warn << event
            << "[FileDock] 跨面板文件传输取消：无法解析目标面板, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << eol;
        return;
    }

    const QDir targetDir(targetPanel->currentPath);
    if (!targetDir.exists())
    {
        kLogEvent event;
        warn << event
            << "[FileDock] 跨面板文件传输取消：目标目录不存在, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << ", targetPanel="
            << targetPanel->panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(targetPanel->currentPath).toStdString()
            << eol;
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 跨面板文件传输请求, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << ", targetPanel="
            << targetPanel->panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(targetPanel->currentPath).toStdString()
            << ", count="
            << selectedItemPaths.size()
            << ", mode="
            << (moveItems ? "move" : "copy")
            << eol;
    }

    // 复制/剪切在双栏中改为“源面板 -> 对侧面板当前目录”的直接动作，不再经过内部粘贴缓存。
    // 进度标题沿用右键菜单的目标面板文案，避免再出现容易误解的“剪切到对侧”。
    const QString localizedTargetPanelText = ks::i18n::displayText(targetPanel->panelNameText);
    const QString progressTitle = moveItems
        ? ks::i18n::displayText(QStringLiteral("移动到%1")).arg(localizedTargetPanelText)
        : ks::i18n::displayText(QStringLiteral("复制到%1")).arg(localizedTargetPanelText);
    const int progressPid = kPro.add(this, "文件", progressTitle.toStdString());
    kPro.set(progressPid, moveItems ? "准备移动" : "准备复制", 0, 5.0f);
    m_transferInProgress = true;

    const bool sourceWasLeftPanel = &sourcePanel == &m_leftPanel;
    const QString targetDirectoryPath = targetPanel->currentPath;
    const QString sourcePanelNameText = sourcePanel.panelNameText;
    const QString targetPanelNameText = targetPanel->panelNameText;
    const QPointer<FileDock> safeThis(this);
    const auto dispatcher = m_uiDispatcher;

    QThreadPool::globalInstance()->start(
        [safeThis,
            dispatcher,
            selectedItemPaths,
            targetDirectoryPath,
            sourcePanelNameText,
            targetPanelNameText,
            sourceWasLeftPanel,
            moveItems,
            progressPid]()
        {
            QStringList errorLines;
            const QDir workerTargetDir(targetDirectoryPath);
            const std::size_t totalCount = selectedItemPaths.size();

            for (std::size_t i = 0; i < totalCount; ++i)
            {
                const QString sourcePath = selectedItemPaths[i];
                QFileInfo sourceInfo(sourcePath);
                if (isPathReparsePoint(sourcePath))
                {
                    errorLines << ks::i18n::displayText(
                        QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                        .arg(QDir::toNativeSeparators(sourcePath));
                    continue;
                }
                if (!sourceInfo.exists())
                {
                    errorLines << QStringLiteral("源不存在：%1").arg(sourcePath);
                    continue;
                }

                const QString targetPath = workerTargetDir.filePath(sourceInfo.fileName());
                if (QDir::cleanPath(sourcePath).compare(QDir::cleanPath(targetPath), Qt::CaseInsensitive) == 0)
                {
                    errorLines << QStringLiteral("源和目标相同，已跳过：%1").arg(sourcePath);
                    continue;
                }
                if (sourceInfo.isDir())
                {
                    const QString cleanSourceDirPath = QDir::cleanPath(sourceInfo.absoluteFilePath());
                    const QString cleanTargetPath = QDir::cleanPath(targetPath);
                    const QString sourcePrefix = cleanSourceDirPath.endsWith(QLatin1Char('/'))
                        ? cleanSourceDirPath
                        : cleanSourceDirPath + QLatin1Char('/');
                    if (cleanTargetPath.startsWith(sourcePrefix, Qt::CaseInsensitive))
                    {
                        errorLines << QStringLiteral("不能把目录复制或移动到自身子目录：%1 -> %2")
                            .arg(sourcePath, targetPath);
                        continue;
                    }
                }

                bool itemOk = false;
                QString copyErrorText;
                if (moveItems)
                {
                    // 剪切优先尝试同卷重命名，失败再走事务复制和源删除。
                    itemOk = QFile::rename(sourcePath, targetPath);
                    if (!itemOk && sourceInfo.isDir())
                    {
                        itemOk = copyDirectoryTransactionally(sourcePath, targetPath, copyErrorText);
                        if (itemOk && !QDir(sourcePath).removeRecursively())
                        {
                            itemOk = false;
                            copyErrorText = ks::i18n::displayText(
                                QStringLiteral("目标已写入，但删除源目录失败: %1"))
                                .arg(sourcePath);
                        }
                    }
                    else if (!itemOk)
                    {
                        itemOk = copyFileTransactionally(sourcePath, targetPath, copyErrorText);
                        if (itemOk && !QFile::remove(sourcePath))
                        {
                            itemOk = false;
                            copyErrorText = ks::i18n::displayText(
                                QStringLiteral("目标已写入，但删除源文件失败: %1"))
                                .arg(sourcePath);
                        }
                    }
                }
                else if (sourceInfo.isDir())
                {
                    itemOk = copyDirectoryTransactionally(sourcePath, targetPath, copyErrorText);
                }
                else
                {
                    itemOk = copyFileTransactionally(sourcePath, targetPath, copyErrorText);
                }

                if (!itemOk)
                {
                    errorLines << copyErrorText;
                }

                {
                    const float progress = 5.0f +
                        (static_cast<float>(i + 1) / static_cast<float>(totalCount)) * 90.0f;
                    dispatcher->post(
                        [progressPid, moveItems, progress]()
                        {
                            kPro.set(progressPid, moveItems ? "移动处理中" : "复制处理中", 0, progress);
                        });
                }
            }
            dispatcher->post(
                [safeThis,
                    errorLines = std::move(errorLines),
                    sourcePanelNameText,
                    targetPanelNameText,
                    sourceWasLeftPanel,
                    moveItems,
                    progressPid,
                    totalCount]()
                {
                    kPro.set(progressPid, moveItems ? "移动完成" : "复制完成", 0, 100.0f);
                    if (safeThis.isNull())
                    {
                        return;
                    }

                    FileDock* const dock = safeThis.data();
                    dock->m_transferInProgress = false;
                    FilePanelWidgets& completedSourcePanel = sourceWasLeftPanel
                        ? dock->m_leftPanel
                        : dock->m_rightPanel;
                    FilePanelWidgets& completedTargetPanel = sourceWasLeftPanel
                        ? dock->m_rightPanel
                        : dock->m_leftPanel;
                    dock->refreshPanel(completedSourcePanel);
                    dock->refreshPanel(completedTargetPanel);

                    if (!errorLines.isEmpty())
                    {
                        kLogEvent event;
                        warn << event
                            << "[FileDock] 跨面板文件传输部分失败, sourcePanel="
                            << sourcePanelNameText.toStdString()
                            << ", targetPanel="
                            << targetPanelNameText.toStdString()
                            << ", errorCount="
                            << errorLines.size()
                            << ", errorPreview=\n"
                            << buildLogPreviewText(errorLines).toStdString()
                            << eol;
                        return;
                    }

                    kLogEvent event;
                    info << event
                        << "[FileDock] 跨面板文件传输完成, sourcePanel="
                        << sourcePanelNameText.toStdString()
                        << ", targetPanel="
                        << targetPanelNameText.toStdString()
                        << ", totalCount="
                        << totalCount
                        << ", mode="
                        << (moveItems ? "move" : "copy")
                        << eol;
                },
                [progressPid]()
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                });
        });
}

void FileDock::createNewFileOrFolder(FilePanelWidgets& panel, const bool createFolder)
{
    if (m_fileMutationOperation && m_fileMutationOperation->isInFlight()) return;
    const QString directory = panel.currentPath;
    const auto directoryGeneration = panel.navigationGeneration;
    bool ok = false;
    const QString inputName = QInputDialog::getText(this,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件"),
        QStringLiteral("请输入名称："), QLineEdit::Normal,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件.txt"), &ok);
    if (!ok || inputName.trimmed().isEmpty()) return;
    const QString targetPath = QDir(directory).filePath(inputName.trimmed());
    submitFileMutation(panel, { targetPath }, targetPath, 0,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件"),
        createFolder ? 1 : 0, directory, directoryGeneration);
}

void FileDock::renameSelectedItem(FilePanelWidgets& panel)
{
    if (m_fileMutationOperation && m_fileMutationOperation->isInFlight()) return;
    const QString path = currentIndexPath(panel);
    if (path.isEmpty()) return;
    const QString directory = panel.currentPath;
    const auto directoryGeneration = panel.navigationGeneration;
    const QFileInfo old(path); // fileName/absolutePath below are lexical only.
    bool ok = false;
    const QString inputName = QInputDialog::getText(this, QStringLiteral("重命名"),
        QStringLiteral("新名称："), QLineEdit::Normal, old.fileName(), &ok);
    const QString name = inputName.trimmed();
    if (!ok || name.isEmpty() || name == old.fileName()) return;
    const QString destination = QDir(old.absolutePath()).filePath(name);
    submitFileMutation(panel, { path }, destination, 0, QStringLiteral("重命名"), 2,
        directory, directoryGeneration);
}

void FileDock::submitFileMutation(FilePanelWidgets& panel, std::vector<QString> paths,
    const QString& destination, const unsigned long integrityRid, const QString& displayText,
    const int kind, const QString& directory, const std::uint64_t directoryGeneration)
{
    if (!m_fileMutationOperation) m_fileMutationOperation = new ks::ui::AsyncOperation(this);
    if (m_fileMutationOperation->isInFlight()) return; // Never supersede an approved write.
    const bool left = &panel == &m_leftPanel;
    const auto progress = std::make_shared<FileAnalysisProgress>();
    const QString title = ks::i18n::displayText(kind == 3 ? QStringLiteral("设置文件完整性") : displayText);
    const int progressPid = kPro.add(this, "文件", title.toStdString());
    auto* dialog = new QProgressDialog(title, ks::i18n::displayText(QStringLiteral("取消")), 0, 100, this);
    dialog->setWindowTitle(title);
    dialog->setWindowModality(Qt::NonModal);
    dialog->setAutoClose(false); dialog->setAutoReset(false); dialog->setMinimumDuration(0); dialog->setValue(0);
    auto* timer = new QTimer(dialog); timer->setInterval(100);
    connect(timer, &QTimer::timeout, dialog, [dialog, progress]()
    { const int value = progress->percent.load(); if (!progress->cancel.load() && dialog->value() != value) dialog->setValue(value); });
    connect(dialog, &QProgressDialog::canceled, dialog, [progress]() { progress->cancel.store(true); });
    const QPointer<QProgressDialog> guard(dialog);
    const std::uint64_t acceptedTicket = m_fileMutationOperation->submitTransaction<FileMutationRequest, FileMutationResult>(
        { kind, std::move(paths), destination, panel.panelNameText, static_cast<DWORD>(integrityRid), progress, progressPid },
        runFileMutation,
        [this, guard, left, kind, displayText, directory, directoryGeneration, progressPid](const FileMutationResult& result, std::uint64_t)
        {
            if (guard) guard->deleteLater();
            FilePanelWidgets& target = left ? m_leftPanel : m_rightPanel;
            const QPointer<FileDock> refreshOwner(this);
            const auto refresh = [refreshOwner, left, directory, directoryGeneration]()
            {
                if (!refreshOwner) return;
                FilePanelWidgets& current = left ? refreshOwner->m_leftPanel : refreshOwner->m_rightPanel;
                if (current.navigationGeneration == directoryGeneration && pathEqualsCaseInsensitive(current.currentPath, directory))
                    refreshOwner->refreshPanel(current);
            };
            if (target.navigationGeneration == directoryGeneration && pathEqualsCaseInsensitive(target.currentPath, directory))
            {
                // refreshPanel resets/replaces the source model before navigation;
                // defer that whole operation while either original view owns a menu.
                if (!ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this,
                    left ? QStringLiteral("file-mutation-refresh-left") : QStringLiteral("file-mutation-refresh-right"),
                    { target.fileView, target.compactFileView }, refresh)) refresh();
            }
            if (!refreshOwner) return true;
            kPro.set(progressPid, result.canceled ? "用户取消" : "完成", 0, 100.0f);
            if (kind != 3) return true; // Preserve create/rename's existing log-only completion.
            const QString summary = (result.canceled ? ks::i18n::displayText(QStringLiteral("已取消")) + QLatin1Char('\n') : QString())
                + QStringLiteral("文件完整性设置完成：成功 %1，失败 %2，目标=%3。")
                    .arg(result.successCount).arg(result.failureCount).arg(displayText);
            const QPointer<FileDock> self(this);
            const bool privilegeHandled = result.privilegeError != ERROR_SUCCESS && ks::ui::promptForPrivilegeFailure(
                this, QStringLiteral("设置文件完整性级别"), result.privilegeError);
            if (!self) return true;
            if (result.failureCount != 0 && !privilegeHandled)
                QMessageBox::warning(this, QStringLiteral("设置文件完整性"), summary + QStringLiteral("\n\n失败明细：\n") + result.failures);
            else if (result.failureCount == 0)
                QMessageBox::information(this, QStringLiteral("设置文件完整性"), summary);
            return true;
        },
        [guard, progressPid](std::exception_ptr)
        {
            if (guard) guard->deleteLater();
            kPro.set(progressPid, "失败", 0, 100.0f);
            kLogEvent event; warn << event << "[FileDock] file mutation worker failed" << eol;
        },
        [progressPid](const ks::ui::AsyncOperationOutcome outcome)
        {
            // Value-only fallback for rejection, failed launch or lost UI delivery.
            // A worker's real terminal result is never overwritten by this cleanup.
            if (outcome != ks::ui::AsyncOperationOutcome::Applied)
                kPro.finish(progressPid, kProgressState::Failure, "失败");
        });
    if (acceptedTicket == 0)
    {
        if (guard) guard->deleteLater();
        return; // Shutdown admission rejected: no write was accepted or entered.
    }
    if (guard) { timer->start(); guard->show(); }
}

void FileDock::deleteSelectedItem(FilePanelWidgets& panel)
{
    // Delete 快捷键与右键顶层「删除」都走可还原的回收站档，
    // 更强的权限手段统一放在「删除方式」子菜单里显式选择。
    deleteSelectedItemsWithMode(panel, FileDeleteMode::RecycleBin);
}

void FileDock::deleteSelectedItemByDriver(FilePanelWidgets& panel)
{
    deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0Native);
}

void FileDock::deleteSelectedItemsWithMode(FilePanelWidgets& panel, const FileDeleteMode mode)
{
    // 防重入：删除和跨面板传输一样是整批文件系统写操作，收尾还要刷新面板，
    // 期间不能再接受第二次删除请求（否则两批任务会互相刷掉对方的结果）。
    if (property(kFileDeleteInProgressProperty).toBool())
    {
        return;
    }

    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    if (mode == FileDeleteMode::DriverR0IgnoreSharePosix &&
        (paths.size() != 1U || QFileInfo(paths.front()).isDir()))
    {
        return;
    }

    // 档位文案必须把“可逆性 + 权限手段”说清楚：
    // 用户对“删除”的预期来自资源管理器（进回收站、可还原），而下面四档都不可撤销，
    // 不提前说明就等于让不可逆操作伪装成可撤销操作。
    QString modeNameText;
    QString confirmTitleText;
    QString confirmBodyText;
    switch (mode)
    {
    case FileDeleteMode::RecycleBin:
        modeNameText = QStringLiteral("删除到回收站");
        confirmTitleText = QStringLiteral("删除确认");
        confirmBodyText = QStringLiteral(
            "确定要把选中的 %1 项移到回收站吗？\n\n"
            "若某些项无法移入回收站（例如位于网络位置、可移动磁盘，或回收站已停用），"
            "将改为永久删除且无法还原；完成后会告知具体数量。")
            .arg(paths.size());
        break;
    case FileDeleteMode::PermanentR3:
        modeNameText = QStringLiteral("永久删除");
        confirmTitleText = QStringLiteral("永久删除确认");
        confirmBodyText = QStringLiteral(
            "将以当前用户权限永久删除选中的 %1 项，不进入回收站、无法还原。\n\n"
            "目录会按“子项先删、目录后删”的顺序递归删除；符号链接/联接点只删除链接本身，"
            "不会跟进到链接目标。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::ForceR3:
        modeNameText = QStringLiteral("强制删除（接管所有权）");
        confirmTitleText = QStringLiteral("强制删除确认");
        confirmBodyText = QStringLiteral(
            "将对选中的 %1 项执行强制删除：清除只读/隐藏/系统属性，必要时把所有者改为 "
            "BUILTIN\\Administrators 并授予完全控制，然后递归永久删除。\n\n"
            "所有权与访问控制项会被真实修改且不会自动还原，删除本身也无法撤销。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::PendingReboot:
        modeNameText = QStringLiteral("重启后删除");
        confirmTitleText = QStringLiteral("重启后删除确认");
        confirmBodyText = QStringLiteral(
            "将把选中的 %1 项登记到 PendingFileRenameOperations，由系统在下次重启的早期阶段删除。\n\n"
            "适用于正被占用、当前无法删除的目标；登记后文件在重启前仍然存在，"
            "删除结果要等重启后才能确认。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0Native:
        modeNameText = QStringLiteral("R0 驱动（底层方案）");
        confirmTitleText = QStringLiteral("R0 底层删除确认");
        confirmBodyText = QStringLiteral(
            "将通过 KswordARK 驱动的底层 Zw* 方案硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树由 R0 递归展开后序删除，因此目录拒绝列举时也能删干净；失败时会执行现有 DispositionEx 兼容重试。符号链接/联接点只删除链接本身。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0Irp:
        modeNameText = QStringLiteral("R0 驱动(IRP)");
        confirmTitleText = QStringLiteral("R0 IRP 删除确认");
        confirmBodyText = QStringLiteral(
            "将由 KswordARK 驱动构造 IRP_MJ_SET_INFORMATION / FileDispositionInformation，通过完整文件系统栈硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树仍由 R0 后序递归展开；此模式不会回退到底层方案。符号链接/联接点只删除链接本身。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0Posix:
        modeNameText = QStringLiteral("R0 驱动(POSIX)");
        confirmTitleText = QStringLiteral("R0 POSIX 删除确认");
        confirmBodyText = QStringLiteral(
            "将由 KswordARK 驱动使用 FileDispositionInformationEx 的 POSIX unlink 语义，硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树仍由 R0 后序递归展开；支持情况取决于 Windows 版本与文件系统，失败时不会回退到 IRP 或底层方案。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0IgnoreSharePosix:
        modeNameText = QStringLiteral("R0 驱动(POSIX·忽略共享检查)");
        confirmTitleText = QStringLiteral("高风险文件删除确认");
        confirmBodyText = QStringLiteral(
            "将对选中的单个文件尝试跳过 I/O 管理器共享检查，再请求 POSIX 删除。文件系统和过滤驱动仍可能拒绝，且不会自动结束进程或关闭句柄。删除不可撤销。是否继续？");
        break;
    default:
        return;
    }

    {
        kLogEvent requestEvent;
        info << requestEvent
            << "[FileDock] 删除请求, panel="
            << panel.panelNameText.toStdString()
            << ", mode="
            << modeNameText.toStdString()
            << ", count="
            << paths.size()
            << eol;
    }

    // 接管所有权与 PendingFileRenameOperations 都要求管理员令牌，
    // 未提权时直接引导重启提权，避免用户在一堆 error=5 里猜原因。
    if (mode == FileDeleteMode::ForceR3 || mode == FileDeleteMode::PendingReboot)
    {
        if (!ks::ui::isCurrentProcessElevated())
        {
            (void)ks::ui::requestAdministratorRestartForFeature(this, modeNameText);
            return;
        }
    }

    const QMessageBox::StandardButton userChoice = QMessageBox::question(
        this,
        confirmTitleText,
        confirmBodyText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    const int progressPid = kPro.add(this, "文件", modeNameText.toStdString());
    kPro.set(progressPid, "删除开始", 0, 5.0f);
    setProperty(kFileDeleteInProgressProperty, true);

    // 删除整体放在后台线程：moveToTrash 走 Shell IFileOperation（每项固定几十毫秒），
    // 递归展开还要走完整棵树，多选或删大目录时同步执行会把事件循环占死数秒到数分钟，
    // 连 kPro 进度条都刷不出来。写法与同文件的 transferSelectedItemsToOppositePanel 保持一致。
    const bool sourceWasLeftPanel = &panel == &m_leftPanel;
    const QString panelNameText = panel.panelNameText;
    const QPointer<FileDock> guardedSelf(this);
    const auto dispatcher = m_uiDispatcher;

    QThreadPool::globalInstance()->start(
        [guardedSelf, dispatcher, paths, panelNameText, modeNameText, mode, sourceWasLeftPanel, progressPid]()
        {
            // 进度按整数百分比节流：大目录会产生上万次回调，逐次 post 会把主线程事件队列打爆。
            int lastProgressBucket = 5;
            const auto progressReporter =
                [&lastProgressBucket, dispatcher, progressPid](const float progress)
                {
                    const int bucket = static_cast<int>(progress);
                    if (bucket <= lastProgressBucket)
                    {
                        return;
                    }
                    lastProgressBucket = bucket;
                    dispatcher->post(
                        [progressPid, progress]()
                        {
                            kPro.set(progressPid, "删除处理中", 0, progress);
                        });
                };

            FileDeleteBatchStats stats = runFileDeleteBatch(paths, mode, progressReporter);
            dispatcher->post(
                [guardedSelf,
                    stats = std::move(stats),
                    panelNameText,
                    modeNameText,
                    mode,
                    sourceWasLeftPanel,
                    progressPid,
                    originalCount = paths.size()]()
                {
                    kPro.set(progressPid, "删除完成", 0, 100.0f);
                    if (guardedSelf.isNull())
                    {
                        return;
                    }

                    FileDock* const dock = guardedSelf.data();
                    dock->setProperty(kFileDeleteInProgressProperty, false);
                    FilePanelWidgets& completedPanel = sourceWasLeftPanel
                        ? dock->m_leftPanel
                        : dock->m_rightPanel;
                    if (stats.failedCount == 0U)
                    {
                        dock->refreshPanel(completedPanel);
                    }

                    QStringList summaryLines;
                    if (stats.recycledCount > 0U)
                    {
                        summaryLines << QStringLiteral("已移入回收站：%1 项").arg(stats.recycledCount);
                    }
                    if ((stats.deletedFileCount + stats.deletedDirectoryCount) > 0U)
                    {
                        summaryLines << QStringLiteral("已永久删除：文件 %1 个、目录 %2 个")
                            .arg(stats.deletedFileCount)
                            .arg(stats.deletedDirectoryCount);
                    }
                    if (stats.pendingRebootCount > 0U)
                    {
                        summaryLines << QStringLiteral("已登记重启后删除：%1 项").arg(stats.pendingRebootCount);
                    }
                    if (stats.skippedReparseCount > 0U)
                    {
                        summaryLines << QStringLiteral("重解析点只删除了链接本身：%1 项")
                            .arg(stats.skippedReparseCount);
                    }
                    if (stats.permissionRepairCount > 0U)
                    {
                        summaryLines << QStringLiteral("触发接管所有权/授权的项：%1 项（所有权与 DACL 已被修改，不会自动还原）")
                            .arg(stats.permissionRepairCount);
                    }
                    if (stats.driverRecursionUnsupported)
                    {
                        summaryLines << QStringLiteral("当前 R0 驱动不支持内核递归删除，已回退为 R3 展开逐项删除。");
                    }
                    if (stats.failedCount > 0U)
                    {
                        summaryLines << QStringLiteral("失败：%1 项").arg(stats.failedCount);
                    }

                    {
                        kLogEvent completionEvent;
                        (stats.failedCount > 0U ? warn : info) << completionEvent
                            << "[FileDock] 删除完成, panel="
                            << panelNameText.toStdString()
                            << ", mode="
                            << modeNameText.toStdString()
                            << ", requested="
                            << originalCount
                            << ", recycled="
                            << stats.recycledCount
                            << ", files="
                            << stats.deletedFileCount
                            << ", dirs="
                            << stats.deletedDirectoryCount
                            << ", pendingReboot="
                            << stats.pendingRebootCount
                            << ", failed="
                            << stats.failedCount
                            << ", errorPreview=\n"
                            << buildLogPreviewText(stats.errors).toStdString()
                            << eol;
                    }

                    if (stats.driverUnavailable)
                    {
                        QMessageBox::warning(
                            dock,
                            QStringLiteral("驱动删除"),
                            QStringLiteral("无法连接 KswordARK 驱动设备，请先启用 R0 驱动。\n\n%1")
                                .arg(buildLogPreviewText(stats.errors)));
                        return;
                    }

                    // 有项目未能进回收站时必须显式告知：这些项已不可还原，
                    // 用户需要据此判断还能不能靠回收站补救。
                    if (!stats.permanentlyDeleted.isEmpty())
                    {
                        QMessageBox::warning(
                            dock,
                            QStringLiteral("部分项目已永久删除"),
                            QStringLiteral("有 %1 项无法移入回收站，已被永久删除，无法从回收站还原：\n\n%2")
                                .arg(stats.permanentlyDeleted.size())
                                .arg(buildLogPreviewText(stats.permanentlyDeleted)));
                    }

                    if (stats.failedCount > 0U)
                    {
                        QMessageBox::warning(
                            dock,
                            modeNameText,
                            QStringLiteral("%1 未全部完成。\n\n%2\n\n失败明细（最多显示前若干条）：\n%3")
                                .arg(modeNameText)
                                .arg(summaryLines.join(QStringLiteral("\n")))
                                .arg(buildLogPreviewText(stats.errors)));
                        // 模态弹窗运行嵌套事件循环；关闭时 Dock 可能已销毁，须重新校验 QPointer。
                        if (!guardedSelf.isNull())
                        {
                            FileDock* const completedDock = guardedSelf.data();
                            FilePanelWidgets& failedPanel = sourceWasLeftPanel
                                ? completedDock->m_leftPanel
                                : completedDock->m_rightPanel;
                            completedDock->refreshPanel(failedPanel);
                        }
                        return;
                    }

                    if (mode == FileDeleteMode::PendingReboot && stats.pendingRebootCount > 0U)
                    {
                        QMessageBox::information(
                            dock,
                            modeNameText,
                            QStringLiteral("%1\n\n目标仍然存在，系统会在下次重启的早期阶段执行删除。")
                                .arg(summaryLines.join(QStringLiteral("\n"))));
                    }
                },
                [progressPid]()
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                });
        });
}

void FileDock::unlockSelectedItemsByDriver(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }
    if (paths.size() != 1)
    {
        // 当前文件解锁器会先扫描占用来源，再让用户选择关闭句柄或结束进程。
        // 多路径下候选句柄/进程关系容易混在一起，暂不提供批量入口，避免误结束无关进程。
        kLogEvent event;
        info << event
            << "[FileDock] 文件解锁器取消：暂不支持多选, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << paths.size()
            << eol;
        return;
    }

    unlockPathsByDriver(paths, QStringLiteral("panel_context_menu"), &panel);
}

void FileDock::addOplockToSelectedFile(FilePanelWidgets& panel, const FileOplockLevel level)
{
    const QString levelText = fileOplockLevelText(level);
    const unsigned long controlCode = fileOplockControlCode(level);
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("请只选择一个文件。"));
        return;
    }

    const QFileInfo fileInfo(paths.front());
    if (!fileInfo.isFile())
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("Oplock 入口当前只支持普通文件。"));
        return;
    }

    const QString normalizedPath = normalizeFileDockPath(fileInfo.absoluteFilePath());
    if (hasActiveOplockForPath(normalizedPath)
        || m_releasingOplockPaths.contains(normalizedPath, Qt::CaseInsensitive))
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("该文件已经由 FileDock 持有 Oplock：\n%1").arg(normalizedPath));
        return;
    }

    auto oplockEntry = std::make_shared<FileOplockEntry>();
    oplockEntry->path = normalizedPath;
    oplockEntry->level = level;
    const QPointer<FileDock> safeThis(this);
    const auto dispatcher = m_uiDispatcher;
    const std::weak_ptr<FileOplockEntry> weakEntry(oplockEntry);
    oplockEntry->cleanupLease = ks::ui::AsyncCleanupRegistry::global().acquire(
        [weakEntry, safeThis, dispatcher]()
        {
            if (const auto entry = weakEntry.lock())
            {
                entry->releaseRequested.store(true);
                FileDock::cancelFileOplockRequest(*entry);
            }
            // Remove only this stopped identity. A canceled application shutdown
            // may admit a new Oplock before this queued GUI cleanup is delivered.
            dispatcher->post([weakEntry, safeThis, dispatcher]()
            {
                const auto entry = weakEntry.lock();
                if (!safeThis || !entry) return;
                {
                    std::lock_guard<std::mutex> lock(safeThis->m_activeOplockMutex);
                    const auto found = std::find(safeThis->m_activeOplocks.begin(),
                        safeThis->m_activeOplocks.end(), entry);
                    if (found == safeThis->m_activeOplocks.end()) return;
                    safeThis->m_activeOplocks.erase(found);
                }
                const QString path = entry->path;
                safeThis->m_releasingOplockPaths.push_back(path);
                retireFileOplockEntries(std::vector<std::shared_ptr<FileOplockEntry>>{ entry },
                    [safeThis, dispatcher, path](const auto&)
                    {
                        dispatcher->post([safeThis, path]()
                        {
                            if (safeThis) safeThis->m_releasingOplockPaths.removeAll(path);
                        });
                    });
            });
        });
    if (!oplockEntry->cleanupLease) return; // Shutdown rejected admission; no native request entered.

    std::wstring nativePath = normalizedPath.toStdWString();
    HANDLE fileHandle = ::CreateFileW(
        nativePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        const DWORD errorCode = ::GetLastError();
        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("打开文件失败，无法请求 %1 Oplock，Win32=%2：\n%3")
                .arg(levelText)
                .arg(errorCode)
                .arg(normalizedPath));
        kLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：CreateFileW, path="
            << normalizedPath.toStdString()
            << ", level="
            << levelText.toStdString()
            << ", error="
            << errorCode
            << eol;
        return;
    }

    oplockEntry->fileHandle = fileHandle;
    oplockEntry->eventHandle = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (oplockEntry->eventHandle == nullptr)
    {
        const DWORD errorCode = ::GetLastError();
        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("创建 %1 Oplock 等待事件失败，Win32=%2。").arg(levelText).arg(errorCode));
        kLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：CreateEventW, path="
            << normalizedPath.toStdString()
            << ", level="
            << levelText.toStdString()
            << ", error="
            << errorCode
            << eol;
        return;
    }
    unsigned long requestError = ERROR_SUCCESS;
    if (!requestFileOplock(*oplockEntry, requestError))
    {
        if (requestError == ERROR_SUCCESS)
        {
            QMessageBox::information(
                this,
                QStringLiteral("添加 Oplock"),
                QStringLiteral("%1 Oplock 请求已立即完成，没有保持中的 Oplock：\n%2")
                    .arg(levelText, normalizedPath));
            kLogEvent event;
            info << event
                << "[FileDock] 添加 Oplock：请求同步完成, path="
                << normalizedPath.toStdString()
                << ", level="
                << levelText.toStdString()
                << eol;
            return;
        }

        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("请求 %1 Oplock 失败，Win32=%2：\n%3")
                .arg(levelText)
                .arg(requestError)
                .arg(normalizedPath));
        kLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：DeviceIoControl, path="
            << normalizedPath.toStdString()
            << ", level="
            << levelText.toStdString()
            << ", controlCode=0x"
            << QString::number(controlCode, 16).toStdString()
            << ", error="
            << requestError
            << eol;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        m_activeOplocks.push_back(oplockEntry);
    }

    oplockEntry->waitThread = std::thread([safeThis, dispatcher, oplockEntry]() {
        for (;;)
        {
            bool completionOk = false;
            DWORD completionError = ERROR_SUCCESS;
            DWORD bytesTransferred = 0;
            HANDLE fileHandle = INVALID_HANDLE_VALUE;
            {
                std::lock_guard<std::mutex> lock(oplockEntry->ioMutex);
                fileHandle = oplockEntry->fileHandle;
            }
            completionOk = (::GetOverlappedResult(
                fileHandle,
                &oplockEntry->overlapped,
                &bytesTransferred,
                TRUE) != FALSE);
            if (!completionOk)
            {
                completionError = ::GetLastError();
            }
            {
                std::lock_guard<std::mutex> lock(oplockEntry->ioMutex);
                oplockEntry->ioPending = false;
            }

            if (oplockEntry->releaseRequested.load())
            {
                break;
            }

            const std::uint64_t breakSequence = oplockEntry->breakCount.fetch_add(1U) + 1U;
            unsigned long acknowledgeError = ERROR_SUCCESS;
            const bool acknowledgeOk = completionOk
                ? FileDock::acknowledgeFileOplockBreak(*oplockEntry, acknowledgeError)
                : false;
            const std::size_t capturedProcessCount =
                (completionOk && acknowledgeOk && !oplockEntry->releaseRequested.load())
                ? FileDock::recordFileOplockAccessPrograms(*oplockEntry, breakSequence)
                : 0U;

            {
                dispatcher->post(
                    [
                        safeThis,
                        oplockEntry,
                        completionOk,
                        completionError,
                        acknowledgeOk,
                        acknowledgeError,
                        capturedProcessCount
                    ]() {
                        if (safeThis != nullptr)
                        {
                            safeThis->handleOplockCompleted(
                                oplockEntry,
                                completionOk,
                                completionError,
                                acknowledgeOk,
                                acknowledgeError,
                                capturedProcessCount);
                        }
                    });
            }

            if (!completionOk || !acknowledgeOk)
            {
                break;
            }

            for (;;)
            {
                if (oplockEntry->releaseRequested.load())
                {
                    break;
                }

                unsigned long rearmError = ERROR_SUCCESS;
                if (FileDock::requestFileOplock(*oplockEntry, rearmError))
                {
                    break;
                }
                if (oplockEntry->releaseRequested.load())
                {
                    break;
                }

                if (!oplockEntry->rearmWarningReported.exchange(true))
                {
                    dispatcher->post(
                        [safeThis, oplockEntry, rearmError]() {
                            if (safeThis != nullptr)
                            {
                                safeThis->handleOplockRearmPending(oplockEntry, rearmError);
                            }
                        });
                }

                if (oplockEntry->eventHandle != nullptr)
                {
                    (void)::ResetEvent(oplockEntry->eventHandle);
                    (void)::WaitForSingleObject(oplockEntry->eventHandle, 250);
                }
                else
                {
                    ::Sleep(250);
                }
            }

            if (oplockEntry->releaseRequested.load())
            {
                break;
            }
        }
    });

    QMessageBox::information(
        this,
        QStringLiteral("添加 Oplock"),
        QStringLiteral("已为文件添加 %1 Oplock。保持期间如果其它进程触发访问，将累计次数并自动重新挂起，直到手动释放：\n%2")
            .arg(levelText, normalizedPath));
    kLogEvent event;
    info << event
        << "[FileDock] 添加 Oplock 成功, path="
        << normalizedPath.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", controlCode=0x"
        << QString::number(controlCode, 16).toStdString()
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::releaseSelectedFileOplock(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放 Oplock"),
            QStringLiteral("请只选择一个已添加 Oplock 的文件。"));
        return;
    }

    const QString normalizedPath = normalizeFileDockPath(paths.front());
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        auto iterator = std::find_if(
            m_activeOplocks.begin(),
            m_activeOplocks.end(),
            [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr && pathEqualsCaseInsensitive(entry->path, normalizedPath);
            });
        if (iterator != m_activeOplocks.end())
        {
            targetEntry = *iterator;
            m_activeOplocks.erase(iterator);
        }
    }

    if (targetEntry == nullptr)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放 Oplock"),
            QStringLiteral("当前文件没有由 FileDock 持有的 Oplock：\n%1").arg(normalizedPath));
        return;
    }

    targetEntry->releaseRequested.store(true);
    cancelFileOplockRequest(*targetEntry);
    m_releasingOplockPaths.push_back(normalizedPath);
    const int progressPid = kPro.add(this, "文件", "释放 Oplock");
    const auto dispatcher = m_uiDispatcher;
    const QPointer<FileDock> safeThis(this);
    retireFileOplockEntries(std::vector<std::shared_ptr<FileOplockEntry>>{ targetEntry },
        [safeThis, dispatcher, normalizedPath, progressPid](const auto& entries)
        {
            const auto& entry = entries.front();
            const std::uint64_t breakCount = entry->breakCount.load();
            const auto accessProcessCount = entry->accessRecords.size();
            const auto uncapturedBreakCount = entry->uncapturedBreakCount;
            const QString levelText = FileDock::fileOplockLevelText(entry->level);
            closeWin32Handle(entry->fileHandle);
            closeWin32Handle(entry->eventHandle);
            dispatcher->post([safeThis, normalizedPath, progressPid, breakCount,
                accessProcessCount, uncapturedBreakCount, levelText]()
            {
                if (!safeThis) return;
                safeThis->m_releasingOplockPaths.removeAll(normalizedPath);
                kPro.set(progressPid, "释放 Oplock", 0, 100.0f);
                QMessageBox::information(safeThis, QStringLiteral("释放 Oplock"),
                    QStringLiteral("已释放 %1 Oplock。\n触发次数：%2\n记录进程：%3\n未捕获触发：%4\n文件：%5")
                        .arg(levelText).arg(breakCount).arg(accessProcessCount)
                        .arg(uncapturedBreakCount).arg(normalizedPath));
                kLogEvent event;
                info << event << "[FileDock] 释放当前 Oplock, path=" << normalizedPath.toStdString()
                    << ", level=" << levelText.toStdString() << ", breakCount=" << breakCount
                    << ", accessProcessCount=" << accessProcessCount << ", uncapturedBreakCount="
                    << uncapturedBreakCount << eol;
            });
        });
}

void FileDock::showSelectedFileOplockAccessRecords(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("Oplock 访问记录"),
            QStringLiteral("请只选择一个已添加 Oplock 的文件。"));
        return;
    }

    const QString normalizedPath = normalizeFileDockPath(paths.front());
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        auto iterator = std::find_if(
            m_activeOplocks.begin(),
            m_activeOplocks.end(),
            [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr &&
                    !entry->releaseRequested.load() &&
                    pathEqualsCaseInsensitive(entry->path, normalizedPath);
            });
        if (iterator != m_activeOplocks.end())
        {
            targetEntry = *iterator;
        }
    }

    if (targetEntry == nullptr)
    {
        QMessageBox::information(
            this,
            QStringLiteral("Oplock 访问记录"),
            QStringLiteral("当前文件没有由 FileDock 持有的 Oplock：\n%1").arg(normalizedPath));
        return;
    }

    std::vector<FileOplockAccessRecord> accessRecords;
    QString diagnosticText;
    std::uint64_t uncapturedBreakCount = 0U;
    {
        std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
        accessRecords = targetEntry->accessRecords;
        diagnosticText = targetEntry->lastAccessScanDiagnostic;
        uncapturedBreakCount = targetEntry->uncapturedBreakCount;
    }
    std::sort(
        accessRecords.begin(),
        accessRecords.end(),
        [](const FileOplockAccessRecord& left, const FileOplockAccessRecord& right) {
            if (left.lastBreakSequence != right.lastBreakSequence)
            {
                return left.lastBreakSequence > right.lastBreakSequence;
            }
            return left.processId < right.processId;
        });

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Oplock 访问记录"));
    dialog.resize(1180, 620);

    auto* layout = new QVBoxLayout(&dialog);
    auto* summaryLabel = new QLabel(
        QStringLiteral("文件：%1\n级别：%2 | 触发次数：%3 | 记录进程：%4 | 未捕获触发：%5\n最近扫描：%6")
            .arg(normalizedPath)
            .arg(fileOplockLevelText(targetEntry->level))
            .arg(targetEntry->breakCount.load())
            .arg(accessRecords.size())
            .arg(uncapturedBreakCount)
            .arg(diagnosticText.trimmed().isEmpty() ? QStringLiteral("-") : diagnosticText),
        &dialog);
    summaryLabel->setWordWrap(true);
    layout->addWidget(summaryLabel);

    auto* table = new ks::ui::VisibleTableWidget(static_cast<int>(accessRecords.size()), 13, &dialog);
    // 已捕获 Oplock 记录固定于本对话框，保留导出、不叠加现场快照条。
    ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
    table->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("触发命中"),
        QStringLiteral("句柄命中"),
        QStringLiteral("访问掩码"),
        QStringLiteral("最近句柄"),
        QStringLiteral("首次触发"),
        QStringLiteral("最近触发"),
        QStringLiteral("首次时间"),
        QStringLiteral("最近时间"),
        QStringLiteral("命中路径"),
        QStringLiteral("规则/来源"),
        QStringLiteral("映像路径")
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    installFileTableCopyMenu(table, 0);

    auto makeItem = [](const QString& text) {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    };

    for (int row = 0; row < static_cast<int>(accessRecords.size()); ++row)
    {
        const FileOplockAccessRecord& record = accessRecords[static_cast<std::size_t>(row)];
        const QStringList ruleAndSourceList = QStringList{
            record.matchRuleList.join(QStringLiteral("\n")),
            record.enumerationSourceList.join(QStringLiteral("\n")),
            record.objectNameList.join(QStringLiteral("\n"))
        };
        table->setItem(row, 0, makeItem(QString::number(record.processId)));
        table->setItem(row, 1, makeItem(record.processName.isEmpty() ? QStringLiteral("Unknown") : record.processName));
        table->setItem(row, 2, makeItem(QString::number(record.hitCount)));
        table->setItem(row, 3, makeItem(QString::number(record.handleHitCount)));
        table->setItem(row, 4, makeItem(formatHandleValueText(record.lastGrantedAccess)));
        table->setItem(row, 5, makeItem(formatHandleValueText(record.lastHandleValue)));
        table->setItem(row, 6, makeItem(QString::number(record.firstBreakSequence)));
        table->setItem(row, 7, makeItem(QString::number(record.lastBreakSequence)));
        table->setItem(row, 8, makeItem(record.firstSeenText));
        table->setItem(row, 9, makeItem(record.lastSeenText));
        table->setItem(row, 10, makeItem(record.matchedTargetList.join(QStringLiteral("\n"))));
        table->setItem(row, 11, makeItem(ruleAndSourceList.join(QStringLiteral("\n"))));
        table->setItem(row, 12, makeItem(record.processImagePath));
    }
    table->resizeColumnsToContents();
    layout->addWidget(table, 1);

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    dialog.exec();
}

void FileDock::releaseAllActiveOplocks(const bool showMessage)
{
    std::vector<std::shared_ptr<FileOplockEntry>> entries;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        entries.swap(m_activeOplocks);
    }

    if (entries.empty()) return;
    QStringList releasedPaths;
    for (const auto& entry : entries)
    {
        if (!entry) continue;
        entry->releaseRequested.store(true);
        cancelFileOplockRequest(*entry);
        releasedPaths.push_back(entry->path);
        m_releasingOplockPaths.push_back(entry->path);
    }
    const auto dispatcher = m_uiDispatcher;
    const QPointer<FileDock> safeThis(this);
    const int progressPid = showMessage ? kPro.add(this, "文件", "释放全部 Oplock") : 0;
    retireFileOplockEntries(std::move(entries),
        [safeThis, dispatcher, releasedPaths, showMessage, progressPid](const auto& retired)
        {
            std::uint64_t totalBreakCount = 0;
            std::uint64_t totalUncapturedBreakCount = 0;
            std::size_t totalAccessProcessCount = 0;
            for (const auto& entry : retired)
            {
                if (!entry) continue;
                totalBreakCount += entry->breakCount.load();
                totalAccessProcessCount += entry->accessRecords.size();
                totalUncapturedBreakCount += entry->uncapturedBreakCount;
                closeWin32Handle(entry->fileHandle);
                closeWin32Handle(entry->eventHandle);
            }
            dispatcher->post([safeThis, releasedPaths, showMessage, progressPid, count = retired.size(),
                totalBreakCount, totalUncapturedBreakCount, totalAccessProcessCount]()
            {
                if (!safeThis) return;
                for (const auto& path : releasedPaths) safeThis->m_releasingOplockPaths.removeAll(path);
                if (showMessage)
                {
                    kPro.set(progressPid, "释放全部 Oplock", 0, 100.0f);
                    QMessageBox::information(safeThis, QStringLiteral("释放全部 Oplock"),
                        QStringLiteral("已释放 %1 个 Oplock，累计触发 %2 次，记录进程 %3 个，未捕获触发 %4 次。")
                            .arg(count).arg(totalBreakCount).arg(totalAccessProcessCount).arg(totalUncapturedBreakCount));
                }
                kLogEvent event;
                info << event << "[FileDock] 释放全部 Oplock, count=" << count
                    << ", totalBreakCount=" << totalBreakCount << ", totalAccessProcessCount="
                    << totalAccessProcessCount << ", totalUncapturedBreakCount=" << totalUncapturedBreakCount << eol;
            });
        });
}

bool FileDock::hasActiveOplockForPath(const QString& filePath) const
{
    const QString normalizedPath = normalizeFileDockPath(filePath);
    std::lock_guard<std::mutex> lock(m_activeOplockMutex);
    return std::any_of(
        m_activeOplocks.begin(),
        m_activeOplocks.end(),
        [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr &&
                !entry->releaseRequested.load() &&
                pathEqualsCaseInsensitive(entry->path, normalizedPath);
        });
}

std::size_t FileDock::activeOplockCount() const
{
    std::lock_guard<std::mutex> lock(m_activeOplockMutex);
    return static_cast<std::size_t>(std::count_if(
        m_activeOplocks.begin(),
        m_activeOplocks.end(),
        [](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr && !entry->releaseRequested.load();
        }));
}

std::uint64_t FileDock::activeOplockBreakCountForPath(const QString& filePath) const
{
    const QString normalizedPath = normalizeFileDockPath(filePath);
    std::lock_guard<std::mutex> lock(m_activeOplockMutex);
    auto iterator = std::find_if(
        m_activeOplocks.begin(),
        m_activeOplocks.end(),
        [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr &&
                !entry->releaseRequested.load() &&
                pathEqualsCaseInsensitive(entry->path, normalizedPath);
        });
    if (iterator == m_activeOplocks.end() || *iterator == nullptr)
    {
        return 0U;
    }
    return (*iterator)->breakCount.load();
}

std::size_t FileDock::activeOplockAccessProcessCountForPath(const QString& filePath) const
{
    const QString normalizedPath = normalizeFileDockPath(filePath);
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        auto iterator = std::find_if(
            m_activeOplocks.begin(),
            m_activeOplocks.end(),
            [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr &&
                    !entry->releaseRequested.load() &&
                    pathEqualsCaseInsensitive(entry->path, normalizedPath);
            });
        if (iterator != m_activeOplocks.end())
        {
            targetEntry = *iterator;
        }
    }
    if (targetEntry == nullptr)
    {
        return 0U;
    }

    std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
    return targetEntry->accessRecords.size();
}

void FileDock::handleOplockCompleted(
    std::shared_ptr<FileOplockEntry> entry,
    const bool completionOk,
    const unsigned long completionError,
    const bool acknowledgeOk,
    const unsigned long acknowledgeError,
    const std::size_t capturedProcessCount)
{
    if (entry == nullptr)
    {
        return;
    }

    const bool wasManualRelease = entry->releaseRequested.load();
    if (wasManualRelease)
    {
        return;
    }

    const QString stateText = oplockCompletionText(completionOk, completionError);
    const QString levelText = fileOplockLevelText(entry->level);
    const std::uint64_t breakCount = entry->breakCount.load();
    kLogEvent event;
    info << event
        << "[FileDock] Oplock 访问触发, path="
        << entry->path.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", breakCount="
        << breakCount
        << ", completionOk="
        << (completionOk ? "true" : "false")
        << ", completionError="
        << completionError
        << ", state="
        << stateText.toStdString()
        << ", acknowledgeOk="
        << (acknowledgeOk ? "true" : "false")
        << ", acknowledgeError="
        << acknowledgeError
        << ", capturedProcessCount="
        << capturedProcessCount
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::handleOplockRearmPending(
    std::shared_ptr<FileOplockEntry> entry,
    const unsigned long requestError)
{
    if (entry == nullptr || entry->releaseRequested.load())
    {
        return;
    }

    const QString levelText = fileOplockLevelText(entry->level);
    kLogEvent event;
    warn << event
        << "[FileDock] Oplock 触发后重新挂起暂时失败，将后台重试, path="
        << entry->path.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", breakCount="
        << entry->breakCount.load()
        << ", requestError="
        << requestError
        << eol;
}

void FileDock::unlockPathsByDriver(
    const std::vector<QString>& targetPaths,
    const QString& triggerTag,
    FilePanelWidgets* panelForRefresh)
{
    std::vector<QString> paths;
    paths.reserve(targetPaths.size());
    for (const QString& path : targetPaths)
    {
        const QString normalizedPath = QDir::toNativeSeparators(path.trimmed());
        if (!normalizedPath.isEmpty())
        {
            paths.push_back(normalizedPath);
        }
    }
    if (paths.empty())
    {
        return;
    }

    // 旧解锁器入口直达文件属性的统一占用/解锁页。
    // 属性窗口关闭时通过共享取消标记使扫描回调安全失效。
    Q_UNUSED(triggerTag);
    Q_UNUSED(panelForRefresh);
    openHandleUsageScanWindow(paths);
    return;

    enum class RefreshTarget
    {
        Both = 0,
        Left,
        Right
    };
    const RefreshTarget refreshTarget =
        (panelForRefresh == &m_leftPanel) ? RefreshTarget::Left :
        (panelForRefresh == &m_rightPanel) ? RefreshTarget::Right :
        RefreshTarget::Both;

    struct UnlockJobResult
    {
        bool scanCompleted = false;
        QStringList scanDetailList;
        std::vector<UnlockProcessCandidate> processCandidateList;
        std::vector<UnlockHandleCandidate> handleCandidateList;
        UnlockOperationMode operationMode = UnlockOperationMode::CloseHandleR3;
        std::vector<std::uint32_t> selectedProcessIdList;
        std::vector<UnlockHandleCandidate> selectedHandleList;
        std::size_t closeHandleSuccessCount = 0U;
        std::size_t terminateSuccessCount = 0U;
        QStringList operationFailList;
        QStringList skippedTargetList;
        QString driverErrorText;
    };

    {
        std::lock_guard<std::mutex> lock(m_unlockerWorkerMutex);
        if (m_unlockerWorkerRunning.load())
        {
            return;
        }
        if (m_unlockerWorkerThread.joinable())
        {
            m_unlockerWorkerThread.join();
        }
        m_unlockerWorkerStopRequested.store(false);
        m_unlockerWorkerRunning.store(true);
    }

    const int progressPid = kPro.add(this, "文件", "文件解锁器");
    kPro.set(progressPid, "准备扫描占用来源", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    {
        std::lock_guard<std::mutex> lock(m_unlockerWorkerMutex);
        m_unlockerWorkerThread = std::thread([safeThis, paths, triggerTag, refreshTarget, progressPid, this]() {
        UnlockJobResult jobResult;
        const auto markWorkerStopped = [this]() {
            this->m_unlockerWorkerRunning.store(false);
            };
        const auto stopRequested = [this]()
        {
            return this->m_unlockerWorkerStopRequested.load();
        };

        kPro.set(progressPid, "扫描占用来源", 0, 35.0f);
        const filedock::handleusage::HandleUsageScanResult scanResult =
            filedock::handleusage::scanHandleUsageByPaths(
                paths,
                progressPid,
                true,
                stopRequested);
        if (stopRequested())
        {
            kPro.set(progressPid, "用户取消", 0, 100.0f);
            markWorkerStopped();
            return;
        }
        jobResult.scanCompleted = true;
        jobResult.scanDetailList.push_back(
            QStringLiteral("matched=%1, elapsedMs=%2, diagnostic=%3")
            .arg(scanResult.matchedHandleCount)
            .arg(scanResult.elapsedMs)
            .arg(scanResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : scanResult.diagnosticText.simplified()));

        std::map<std::uint32_t, UnlockProcessCandidate> candidateByPid;
        const std::uint32_t currentProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
        for (const filedock::handleusage::HandleUsageEntry& entry : scanResult.entries)
        {
            if (stopRequested())
            {
                kPro.set(progressPid, "用户取消", 0, 100.0f);
                markWorkerStopped();
                return;
            }
            if (entry.processId == 0U)
            {
                continue;
            }

            UnlockProcessCandidate& processCandidate = candidateByPid[entry.processId];
            processCandidate.processId = entry.processId;
            if (processCandidate.matchCount == 0U)
            {
                processCandidate.processCreationTime = entry.processCreationTime;
            }
            else if (processCandidate.processCreationTime != entry.processCreationTime)
            {
                // 同一轮扫描中 PID 身份不一致说明进程已退出/复用；清零使后续动作失败关闭。
                processCandidate.processCreationTime = 0U;
            }
            if (processCandidate.processName.isEmpty() && !entry.processName.trimmed().isEmpty())
            {
                processCandidate.processName = entry.processName.trimmed();
            }
            if (processCandidate.processImagePath.isEmpty() && !entry.processImagePath.trimmed().isEmpty())
            {
                processCandidate.processImagePath = entry.processImagePath.trimmed();
            }
            appendUniqueText(processCandidate.matchedTargetList, entry.matchedTargetPath);
            appendUniqueText(processCandidate.matchRuleList, entry.matchRuleText);
            processCandidate.matchCount += 1U;
            processCandidate.isCurrentProcess = entry.processId == currentProcessId;
            processCandidate.isCriticalProcess = entry.processId <= 4U || isCriticalProcessName(processCandidate.processName);

            UnlockHandleCandidate handleCandidate{};
            handleCandidate.processId = entry.processId;
            handleCandidate.processCreationTime = entry.processCreationTime;
            handleCandidate.processName = entry.processName.trimmed();
            handleCandidate.processImagePath = entry.processImagePath.trimmed();
            handleCandidate.handleValue = entry.handleValue;
            handleCandidate.grantedAccess = entry.grantedAccess;
            handleCandidate.matchedTargetPath = entry.matchedTargetPath;
            handleCandidate.matchedByDirectoryRule = entry.matchedByDirectoryRule;
            handleCandidate.matchRuleText = entry.matchRuleText;
            handleCandidate.objectName = entry.objectName;
            handleCandidate.enumerationSource = entry.enumerationSource;
            handleCandidate.isCurrentProcess = processCandidate.isCurrentProcess;
            handleCandidate.isCriticalProcess = processCandidate.isCriticalProcess;
            jobResult.handleCandidateList.push_back(handleCandidate);
        }

        jobResult.processCandidateList.reserve(candidateByPid.size());
        for (const auto& entry : candidateByPid)
        {
            if (stopRequested())
            {
                kPro.set(progressPid, "用户取消", 0, 100.0f);
                markWorkerStopped();
                return;
            }
            jobResult.processCandidateList.push_back(entry.second);
        }

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        UnlockSelectionResult selectionResult;
        const std::shared_ptr<UnlockSelectionSharedState> selectionState =
            std::make_shared<UnlockSelectionSharedState>();
        const bool selectionInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [selectionState, safeThis, progressPid, jobResult]() {
                QWidget* const unlockerDialogParent = resolveVisibleDialogParent(safeThis.data());
                UnlockSelectionResult uiSelectionResult;
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                }
                else if (jobResult.processCandidateList.empty() && jobResult.handleCandidateList.empty())
                {
                    kPro.set(progressPid, "未发现占用来源", 0, 100.0f);
                }
                else
                {
                    uiSelectionResult = showUnlockSelectionDialog(
                        unlockerDialogParent,
                        jobResult.processCandidateList,
                        jobResult.handleCandidateList);
                }

                {
                    std::lock_guard<std::mutex> lock(selectionState->mutex);
                    selectionState->result = uiSelectionResult;
                    selectionState->completed = true;
                }

                selectionState->condition.notify_all();
            },
            Qt::QueuedConnection);
        if (!selectionInvokeOk)
        {
            kPro.set(progressPid, "回调失败", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        {
            std::unique_lock<std::mutex> lock(selectionState->mutex);
            while (!selectionState->completed)
            {
                if (safeThis.isNull() || this->m_unlockerWorkerStopRequested.load())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    markWorkerStopped();
                    return;
                }

                selectionState->condition.wait_for(lock, std::chrono::milliseconds(100));
            }

            selectionResult = selectionState->result;
        }

        const bool noSelectedHandle = selectionResult.selectedHandleList.empty();
        const bool noSelectedProcess = selectionResult.selectedProcessIdList.empty();
        if (!selectionResult.accepted
            || (selectionResult.operationMode == UnlockOperationMode::CloseHandleR3 && noSelectedHandle)
            || (selectionResult.operationMode != UnlockOperationMode::CloseHandleR3 && noSelectedProcess))
        {
            kPro.set(progressPid, "用户取消", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        jobResult.operationMode = selectionResult.operationMode;
        jobResult.selectedHandleList = selectionResult.selectedHandleList;
        jobResult.selectedProcessIdList = selectionResult.selectedProcessIdList;
        kPro.set(progressPid, unlockOperationModeToText(jobResult.operationMode).toStdString(), 0, 55.0f);

        if (jobResult.operationMode == UnlockOperationMode::CloseHandleR3)
        {
            const std::size_t totalHandleCount = jobResult.selectedHandleList.size();
            for (std::size_t index = 0; index < totalHandleCount; ++index)
            {
                if (safeThis.isNull() || this->m_unlockerWorkerStopRequested.load())
                {
                    break;
                }

                const UnlockHandleCandidate& handleCandidate = jobResult.selectedHandleList[index];
                if (handleCandidate.processId <= 4U
                    || handleCandidate.handleValue == 0U
                    || handleCandidate.isCurrentProcess
                    || handleCandidate.isCriticalProcess)
                {
                    jobResult.skippedTargetList.push_back(
                        QStringLiteral("pid=%1 | handle=%2 | %3 | 已保护或无效，未关闭")
                        .arg(handleCandidate.processId)
                        .arg(formatHandleValueText(handleCandidate.handleValue))
                        .arg(handleCandidate.processName.isEmpty() ? QStringLiteral("Unknown") : handleCandidate.processName));
                    continue;
                }

                std::string detailText;
                const bool closeOk = ks::file::CloseRemoteHandle(
                    handleCandidate.processId,
                    handleCandidate.handleValue,
                    handleCandidate.processCreationTime,
                    handleCandidate.matchedTargetPath.toStdWString(),
                    handleCandidate.matchedByDirectoryRule,
                    detailText);
                if (closeOk)
                {
                    jobResult.closeHandleSuccessCount += 1U;
                }
                else
                {
                    jobResult.operationFailList.push_back(
                        QStringLiteral("pid=%1 | handle=%2 | %3 | %4")
                        .arg(handleCandidate.processId)
                        .arg(formatHandleValueText(handleCandidate.handleValue))
                        .arg(handleCandidate.processName.isEmpty() ? QStringLiteral("Unknown") : handleCandidate.processName)
                        .arg(QString::fromStdString(detailText)));
                }

                const float progress =
                    55.0f + (static_cast<float>(index + 1) / static_cast<float>(totalHandleCount)) * 40.0f;
                kPro.set(progressPid, "关闭选中句柄", 0, progress);
            }
        }
        else
        {
            ksword::ark::DriverHandle driverHandle;
            if (jobResult.operationMode == UnlockOperationMode::TerminateProcessR0)
            {
                std::string openDriverDetailText;
                driverHandle = openKswordArkDriverHandle(&openDriverDetailText);
                if (!driverHandle.isValid())
                {
                    jobResult.driverErrorText = QString::fromStdString(openDriverDetailText);
                }
            }

            std::map<std::uint32_t, UnlockProcessCandidate> candidateBySelectedPid;
            for (const UnlockProcessCandidate& candidate : jobResult.processCandidateList)
            {
                candidateBySelectedPid[candidate.processId] = candidate;
            }

            if (jobResult.operationMode == UnlockOperationMode::TerminateProcessR0
                && !driverHandle.isValid())
            {
                jobResult.operationFailList.push_back(
                    QStringLiteral("R0 驱动连接失败：%1")
                    .arg(jobResult.driverErrorText));
            }
            else
            {
                const std::size_t totalProcessCount = jobResult.selectedProcessIdList.size();
                for (std::size_t index = 0; index < totalProcessCount; ++index)
                {
                    if (safeThis.isNull() || this->m_unlockerWorkerStopRequested.load())
                    {
                        break;
                    }

                    const std::uint32_t processId = jobResult.selectedProcessIdList[index];
                    const auto candidateIter = candidateBySelectedPid.find(processId);
                    const QString processName = (candidateIter != candidateBySelectedPid.end())
                        ? candidateIter->second.processName
                        : QString();
                    const std::uint64_t processCreationTime = (candidateIter != candidateBySelectedPid.end())
                        ? candidateIter->second.processCreationTime
                        : 0U;
                    const bool protectedProcess = candidateIter != candidateBySelectedPid.end()
                        && (candidateIter->second.isCurrentProcess
                            || candidateIter->second.isCriticalProcess
                            || candidateIter->second.processCreationTime == 0U);
                    if (processId <= 4U
                        || processId == static_cast<std::uint32_t>(::GetCurrentProcessId())
                        || protectedProcess
                        || processCreationTime == 0U)
                    {
                        jobResult.skippedTargetList.push_back(
                            QStringLiteral("pid=%1 | %2 | 已保护，未结束")
                            .arg(processId)
                            .arg(processName.isEmpty() ? QStringLiteral("Unknown") : processName));
                        continue;
                    }

                    std::string detailText;
                    bool terminateOk = false;
                    if (jobResult.operationMode == UnlockOperationMode::TerminateProcessR0)
                    {
                        // 即使由驱动执行结束，也先持有已核对创建时间的 R3 进程句柄；
                        // 这样驱动按 PID 查询期间不会命中复用后的另一个进程对象。
                        HANDLE verifiedProcessHandle = nullptr;
                        if (ks::file::OpenProcessForVerifiedAction(
                                processId,
                                processCreationTime,
                                SYNCHRONIZE,
                                verifiedProcessHandle,
                                detailText))
                        {
                            terminateOk = terminateProcessByR0Driver(driverHandle, processId, &detailText);
                            ::CloseHandle(verifiedProcessHandle);
                        }
                    }
                    else
                    {
                        terminateOk = terminateProcessByR3(
                            processId,
                            processCreationTime,
                            &detailText);
                    }
                    if (terminateOk)
                    {
                        jobResult.terminateSuccessCount += 1U;
                    }
                    else
                    {
                        jobResult.operationFailList.push_back(
                            QStringLiteral("pid=%1 | %2 | %3")
                            .arg(processId)
                            .arg(processName.isEmpty() ? QStringLiteral("Unknown") : processName)
                            .arg(QString::fromStdString(detailText)));
                    }

                    const float progress =
                        55.0f + (static_cast<float>(index + 1) / static_cast<float>(totalProcessCount)) * 40.0f;
                    kPro.set(progressPid, "结束选中进程", 0, progress);
                }
            }

            driverHandle.reset();
        }

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        const bool finishInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, triggerTag, refreshTarget, progressPid, jobResult, paths, markWorkerStopped]() {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                QList<QAbstractItemView*> affectedViews;
                if (refreshTarget == RefreshTarget::Left)
                {
                    affectedViews.push_back(safeThis->m_leftPanel.fileView);
                }
                else if (refreshTarget == RefreshTarget::Right)
                {
                    affectedViews.push_back(safeThis->m_rightPanel.fileView);
                }
                else
                {
                    affectedViews.push_back(safeThis->m_leftPanel.fileView);
                    affectedViews.push_back(safeThis->m_rightPanel.fileView);
                }
                const auto refreshPanels = [safeThis, refreshTarget]()
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (refreshTarget == RefreshTarget::Left)
                    {
                        safeThis->refreshPanel(safeThis->m_leftPanel);
                    }
                    else if (refreshTarget == RefreshTarget::Right)
                    {
                        safeThis->refreshPanel(safeThis->m_rightPanel);
                    }
                    else
                    {
                        safeThis->refreshPanel(safeThis->m_leftPanel);
                        safeThis->refreshPanel(safeThis->m_rightPanel);
                    }
                };
                const QString refreshKey =
                    refreshTarget == RefreshTarget::Left
                    ? QStringLiteral("file-unlocker-panel-refresh-left")
                    : (refreshTarget == RefreshTarget::Right
                        ? QStringLiteral("file-unlocker-panel-refresh-right")
                        : QStringLiteral("file-unlocker-panel-refresh-both"));
                if (!ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    refreshKey,
                    affectedViews,
                    refreshPanels))
                {
                    refreshPanels();
                }

                const QString modeText = unlockOperationModeToText(jobResult.operationMode);
                const std::size_t selectedCount = (jobResult.operationMode == UnlockOperationMode::CloseHandleR3)
                    ? jobResult.selectedHandleList.size()
                    : jobResult.selectedProcessIdList.size();
                const std::size_t successCount = (jobResult.operationMode == UnlockOperationMode::CloseHandleR3)
                    ? jobResult.closeHandleSuccessCount
                    : jobResult.terminateSuccessCount;
                kLogEvent event;
                if (!jobResult.operationFailList.isEmpty() || !jobResult.skippedTargetList.isEmpty())
                {
                    warn << event
                        << "[FileDock] 文件解锁器部分失败, panel="
                        << triggerTag.toStdString()
                        << ", mode="
                        << modeText.toStdString()
                        << ", targetCount="
                        << paths.size()
                        << ", occupyProcessCount="
                        << jobResult.processCandidateList.size()
                        << ", handleRecordCount="
                        << jobResult.handleCandidateList.size()
                        << ", selectedCount="
                        << selectedCount
                        << ", successCount="
                        << successCount
                        << ", failCount="
                        << (jobResult.operationFailList.size() + jobResult.skippedTargetList.size())
                        << ", scanPreview=\n"
                        << buildLogPreviewText(jobResult.scanDetailList).toStdString()
                        << ", failPreview=\n"
                        << buildLogPreviewText(jobResult.operationFailList + jobResult.skippedTargetList).toStdString()
                        << eol;
                }
                else
                {
                    info << event
                        << "[FileDock] 文件解锁器完成, panel="
                        << triggerTag.toStdString()
                        << ", mode="
                        << modeText.toStdString()
                        << ", targetCount="
                        << paths.size()
                        << ", occupyProcessCount="
                        << jobResult.processCandidateList.size()
                        << ", handleRecordCount="
                        << jobResult.handleCandidateList.size()
                        << ", selectedCount="
                        << selectedCount
                        << ", successCount="
                        << successCount
                        << eol;
                }

                kPro.set(progressPid, "文件解锁器完成", 0, 100.0f);
                markWorkerStopped();
            },
            Qt::QueuedConnection);
        if (!finishInvokeOk)
        {
            kPro.set(progressPid, "回调失败", 0, 100.0f);
            markWorkerStopped();
        }
        });
    }
}

void FileDock::unlockFileByPath(const QString& targetPath)
{
    const QString normalizedPath = QDir::toNativeSeparators(targetPath.trimmed());
    if (normalizedPath.isEmpty())
    {
        return;
    }

    unlockPathsByDriver(std::vector<QString>{ normalizedPath }, QStringLiteral("system_context_menu"), nullptr);
}

void FileDock::takeOwnershipSelectedItems(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("取得文件所有权并授予完全控制"));
        return;
    }

    kLogEvent startEvent;
    info << startEvent
        << "[FileDock] 取得所有权请求, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << eol;

    const QMessageBox::StandardButton userChoice = QMessageBox::question(
        this,
        QStringLiteral("取得所有权"),
        QStringLiteral("将对选中的 %1 项执行“取得所有权 + 完全控制授权”。\n此操作可能需要管理员权限，是否继续？")
        .arg(paths.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    const int progressPid = kPro.add(this, "文件", "取得所有权");
    kPro.set(progressPid, "准备执行", 0, 5.0f);

    const bool leftPanelRequest = (&panel == &m_leftPanel);
    const QString panelNameText = panel.panelNameText;
    QPointer<FileDock> safeThis(this);
    const auto dispatcher = m_uiDispatcher;
    std::thread([safeThis, dispatcher, paths, progressPid, leftPanelRequest, panelNameText]()
    {
        QStringList errorDetails;
        for (std::size_t index = 0; index < paths.size(); ++index)
        {
            const QString& targetPath = paths[index];
            QString detailText;
            const bool itemOk = takeOwnershipBySystemCommand(targetPath, detailText);
            if (!itemOk)
            {
                errorDetails.push_back(detailText);
            }

            const float progress = 5.0f + (static_cast<float>(index + 1) / static_cast<float>(paths.size())) * 90.0f;
            kPro.set(progressPid, "处理中", 0, progress);
        }
        kPro.set(progressPid, "完成", 0, 100.0f);

        dispatcher->post(
            [safeThis, progressPid, leftPanelRequest, panelNameText, paths, errorDetails]()
            {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                FilePanelWidgets& targetPanel = leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                const auto refreshTargetPanel = [safeThis, leftPanelRequest]()
                {
                    if (!safeThis.isNull())
                    {
                        FilePanelWidgets& commitPanel =
                            leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                        safeThis->refreshPanel(commitPanel);
                    }
                };
                const QString refreshKey = leftPanelRequest
                    ? QStringLiteral("file-ownership-refresh-left")
                    : QStringLiteral("file-ownership-refresh-right");
                if (!ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    refreshKey,
                    { targetPanel.fileView },
                    refreshTargetPanel))
                {
                    refreshTargetPanel();
                }
                if (!errorDetails.isEmpty())
                {
                    kLogEvent failEvent;
                    warn << failEvent
                        << "[FileDock] 取得所有权部分失败, panel="
                        << panelNameText.toStdString()
                        << ", failCount="
                        << errorDetails.size()
                        << ", detailPreview=\n"
                        << buildLogPreviewText(errorDetails).toStdString()
                        << eol;
                    return;
                }

                kLogEvent finishEvent;
                info << finishEvent
                    << "[FileDock] 取得所有权完成, panel="
                    << panelNameText.toStdString()
                    << ", successCount="
                    << paths.size()
                    << eol;
            },
            [progressPid]()
            {
                kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            });
    }).detach();
}

void FileDock::setSelectedFileIntegrityLevel(FilePanelWidgets& panel,
    const unsigned long integrityRid, const QString& levelDisplayText, const std::vector<QString>& menuPaths)
{
    if (m_fileMutationOperation && m_fileMutationOperation->isInFlight()) return;
    const std::vector<QString> paths = menuPaths;
    if (paths.empty()) return;
    const QString directory = panel.currentPath;
    const auto directoryGeneration = panel.navigationGeneration;
    const QMessageBox::StandardButton userChoice = QMessageBox::question(this,
        QStringLiteral("设置文件完整性"),
        QStringLiteral("将对选中的 %1 项写入文件 Mandatory Label：%2。\n"
            "该操作会影响低/中/高完整性进程对对象的写入权限，可能需要管理员权限。是否继续？")
            .arg(paths.size()).arg(levelDisplayText), QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (userChoice != QMessageBox::Yes) return;
    submitFileMutation(panel, paths, {}, integrityRid, levelDisplayText, 3, directory, directoryGeneration);
}

void FileDock::showColumnManagerDialog(FilePanelWidgets& panel)
{
    {
        kLogEvent event;
        info << event
            << "[FileDock] 打开列管理器, panel="
            << panel.panelNameText.toStdString()
            << eol;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("列管理器"));
    ks::ui::StyleSecondaryWindow(&dialog);
    dialog.resize(400, 400);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
    ks::ui::StyleSecondaryContentLayout(rootLayout);
    QLabel* tipLabel = new QLabel(QStringLiteral("勾选表示显示该列，可拖拽表头调整顺序。"), &dialog);
    tipLabel->setWordWrap(true);
    rootLayout->addWidget(tipLabel, 0);

    const bool manualMode = currentModeIsManual(panel);
    const int columnCount = manualMode
        ? (panel.manualModel == nullptr ? 0 : panel.manualModel->columnCount())
        : (panel.fsModel == nullptr ? 0 : panel.fsModel->columnCount());
    std::vector<QCheckBox*> columnChecks;
    columnChecks.reserve(static_cast<std::size_t>(columnCount));
    for (int column = 0; column < columnCount; ++column)
    {
        const QString columnName = manualMode
            ? panel.manualModel->headerData(column, Qt::Horizontal).toString()
            : panel.fsModel->headerData(column, Qt::Horizontal).toString();
        QCheckBox* checkBox = new QCheckBox(columnName, &dialog);
        checkBox->setChecked(!panel.fileView->isColumnHidden(column));
        checkBox->setToolTip(QStringLiteral("切换列“%1”显示状态").arg(columnName));
        rootLayout->addWidget(checkBox, 0);
        columnChecks.push_back(checkBox);
    }
    rootLayout->addStretch(1);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    ks::ui::StyleSecondaryButtonBox(buttonBox);
    ks::ui::StyleSecondaryFooter(buttonBox);
    rootLayout->addWidget(buttonBox, 0);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    for (int column = 0; column < static_cast<int>(columnChecks.size()); ++column)
    {
        const bool visible = columnChecks[static_cast<std::size_t>(column)]->isChecked();
        panel.fileView->setColumnHidden(column, !visible);
    }

    kLogEvent event;
    info << event
        << "[FileDock] 列管理器应用完成, panel="
        << panel.panelNameText.toStdString()
        << eol;
}

void FileDock::showFileDetailDialog(const QString& filePath, const QString& initialTabKey)
{
    showFileDetailDialog(QStringList{ filePath }, initialTabKey);
}

void FileDock::showFileDetailDialog(const QStringList& filePaths, const QString& initialTabKey)
{
    QStringList detailPaths;
    QSet<QString> seenPaths;
    for (const QString& candidatePath : filePaths)
    {
        // This entry point owns only lexical target identity. Existence/access
        // are reported by the detail dialog's asynchronous snapshot, never here.
        const QString trimmedPath = candidatePath.trimmed();
        if (trimmedPath.isEmpty()) continue;
        const QString normalizedPath = QDir::cleanPath(
            QDir::toNativeSeparators(trimmedPath));
        const QString identityKey = normalizedPath.toLower();
        if (!normalizedPath.isEmpty() && !seenPaths.contains(identityKey))
        {
            seenPaths.insert(identityKey);
            detailPaths.push_back(normalizedPath);
        }
    }
    if (detailPaths.isEmpty())
    {
        kLogEvent event;
        warn << event << "[FileDock] 打开文件详情失败：没有可访问目标" << eol;
        return;
    }

    FileDetailDialog* dialog = new FileDetailDialog(detailPaths, this, initialTabKey);
    dialog->setWindowFlag(Qt::WindowStaysOnTopHint, false);
    dialog->show();
    dialog->raise();
    dialog->activateWindow();

    kLogEvent event;
    info << event
        << "[FileDock] 打开文件详情窗口, targetCount="
        << detailPaths.size()
        << eol;
}

void FileDock::openFileDetailByPath(const QString& filePath)
{
    showFileDetailDialog(filePath);
}

QString FileDock::currentIndexPath(const FilePanelWidgets& panel) const
{
    if (!fileResultActionsReady(panel)) return {};
    if (panel.fileView == nullptr)
    {
        return QString();
    }

    const QModelIndex proxyIndex = panel.fileView->currentIndex();
    if (!proxyIndex.isValid())
    {
        return QString();
    }

    if (currentModeIsManual(panel))
    {
        if (panel.manualProxyModel == nullptr || panel.manualModel == nullptr)
        {
            return QString();
        }

        const QModelIndex sourceIndex = panel.manualProxyModel->mapToSource(proxyIndex);
        if (!sourceIndex.isValid())
        {
            return QString();
        }

        return sourceIndex.siblingAtColumn(
            static_cast<int>(ManualModelColumn::FullPath)).data().toString();
    }

    if (panel.proxyModel == nullptr || panel.fsModel == nullptr)
    {
        return QString();
    }
    const QModelIndex sourceIndex = panel.proxyModel->mapToSource(proxyIndex);
    return sourceIndex.isValid() ? panel.fsModel->filePath(sourceIndex) : QString();
}

std::vector<QString> FileDock::selectedPaths(const FilePanelWidgets& panel) const
{
    std::vector<QString> result;
    if (!fileResultActionsReady(panel)) return result;
    if (panel.fileView == nullptr || panel.fileView->selectionModel() == nullptr)
    {
        return result;
    }

    const QModelIndexList selectedRows = panel.fileView->selectionModel()->selectedRows(0);
    result.reserve(static_cast<std::size_t>(selectedRows.size()));
    QSet<QString> seenPaths;
    seenPaths.reserve(selectedRows.size());

    if (currentModeIsManual(panel))
    {
        if (panel.manualProxyModel == nullptr || panel.manualModel == nullptr)
        {
            return result;
        }
        for (const QModelIndex& proxyIndex : selectedRows)
        {
            const QModelIndex sourceIndex = panel.manualProxyModel->mapToSource(proxyIndex);
            if (!sourceIndex.isValid())
            {
                continue;
            }
            const QString pathText = sourceIndex.siblingAtColumn(
                static_cast<int>(ManualModelColumn::FullPath)).data().toString();
            if (pathText.isEmpty())
            {
                continue;
            }
            if (!seenPaths.contains(pathText))
            {
                seenPaths.insert(pathText);
                result.push_back(pathText);
            }
        }
    }
    else
    {
        if (panel.proxyModel == nullptr || panel.fsModel == nullptr)
        {
            return result;
        }
        for (const QModelIndex& proxyIndex : selectedRows)
        {
            const QModelIndex sourceIndex = panel.proxyModel->mapToSource(proxyIndex);
            if (!sourceIndex.isValid())
            {
                continue;
            }
            const QString path = panel.fsModel->filePath(sourceIndex);
            if (path.isEmpty())
            {
                continue;
            }
            if (!seenPaths.contains(path))
            {
                seenPaths.insert(path);
                result.push_back(path);
            }
        }
    }

    // 如果多选为空但存在当前行，回退为当前行路径，便于右键单项操作。
    if (result.empty())
    {
        const QString currentPath = currentIndexPath(panel);
        if (!currentPath.isEmpty())
        {
            result.push_back(currentPath);
        }
    }
    return result;
}

QString FileDock::formatSizeText(std::uint64_t sizeBytes)
{
    static const std::array<const char*, 5> units{ "B", "KB", "MB", "GB", "TB" };
    double value = static_cast<double>(sizeBytes);
    std::size_t unitIndex = 0;
    while (value >= 1024.0 && (unitIndex + 1) < units.size())
    {
        value /= 1024.0;
        ++unitIndex;
    }

    if (unitIndex == 0)
    {
        return QStringLiteral("%1 %2").arg(static_cast<qulonglong>(sizeBytes)).arg(units[unitIndex]);
    }
    return QStringLiteral("%1 %2").arg(QString::number(value, 'f', 2)).arg(units[unitIndex]);
}

namespace
{
    [[maybe_unused]] const bool kFileNavigationRegistered =
        ks::ui::RegisterTypedPageNavigationCatalog<FileDock>(QStringLiteral("file"));
}
