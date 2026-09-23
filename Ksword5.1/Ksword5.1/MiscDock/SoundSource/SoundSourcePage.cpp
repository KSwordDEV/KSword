#include "SoundSourcePage.h"

#include "../../theme.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QDateTime>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHideEvent>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QRunnable>
#include <QSet>
#include <QShowEvent>
#include <QTableWidget>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>

// ============================================================
// SoundSourcePage.cpp
// 作用：
// - 展示“谁正在发声”的 R3 实时结论；
// - 展示 R0 对会话 PID 的多源身份核验；
// - 通过 A/B/C 互补列组控制高密度证据表。
// ============================================================

namespace
{
    constexpr int kAutoRefreshIntervalMs = 1500;
    constexpr std::int64_t kRecentAudibleRetentionMs = 5000;

    enum SoundSourceColumn
    {
        ColumnVerdict = 0,
        ColumnProcess,
        ColumnPid,
        ColumnPeakMaximum,
        ColumnPeakAverage,
        ColumnSessionState,
        ColumnEndpoint,
        ColumnEndpointPeak,
        ColumnEndpointRole,
        ColumnSessionVolume,
        ColumnMuted,
        ColumnSessionName,
        ColumnSessionInstance,
        ColumnImagePath,
        ColumnCreationTime,
        ColumnKernelVerdict,
        ColumnKernelSources,
        ColumnKernelConfidence,
        ColumnKernelAnomaly,
        ColumnKernelObjects,
        ColumnEvidenceDetail,
        ColumnCount
    };

    // tableHeaders：集中维护列标题，避免列索引与显示文本错位。
    QStringList tableHeaders()
    {
        return {
            QStringLiteral("结论"),
            QStringLiteral("进程"),
            QStringLiteral("PID"),
            QStringLiteral("会话峰值"),
            QStringLiteral("平均峰值"),
            QStringLiteral("会话状态"),
            QStringLiteral("输出端点"),
            QStringLiteral("端点峰值"),
            QStringLiteral("默认角色"),
            QStringLiteral("会话音量"),
            QStringLiteral("静音"),
            QStringLiteral("会话名称"),
            QStringLiteral("会话实例"),
            QStringLiteral("映像路径"),
            QStringLiteral("R3 创建时间"),
            QStringLiteral("R0 结论"),
            QStringLiteral("R0 来源"),
            QStringLiteral("R0 置信度"),
            QStringLiteral("R0 异常"),
            QStringLiteral("R0 对象"),
            QStringLiteral("证据说明")
        };
    }

    // kernelSourceText：把共享协议来源位展开成人可读矩阵。
    QString kernelSourceText(const std::uint32_t sourceMask)
    {
        QStringList sourceNames;
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U)
        {
            sourceNames.push_back(QStringLiteral("Public API"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U)
        {
            sourceNames.push_back(QStringLiteral("ActiveProcessLinks"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U)
        {
            sourceNames.push_back(QStringLiteral("PspCidTable"));
        }
        return sourceNames.isEmpty()
            ? QStringLiteral("不可用")
            : sourceNames.join(QStringLiteral(" + "));
    }

    // percentText：把 0.0~1.0 音频量转换成紧凑百分比。
    QString percentText(const float value, const int decimals)
    {
        return QStringLiteral("%1%")
            .arg(static_cast<double>(value) * 100.0, 0, 'f', decimals);
    }

    // addressText：0 表示字段不可用，非 0 使用稳定十六进制展示。
    QString addressText(const std::uint64_t address)
    {
        if (address == 0U)
        {
            return QStringLiteral("不可用");
        }
        return QStringLiteral("0x%1").arg(address, 0, 16).toUpper();
    }
}

namespace ks::misc
{
    SoundSourcePage::SoundSourcePage(
        const std::uint32_t processIdFilter,
        const std::uint64_t expectedCreationTime100ns,
        QWidget* const parent)
        : QWidget(parent)
        , m_processIdFilter(processIdFilter)
        , m_expectedCreationTime100ns(expectedCreationTime100ns)
    {
        initializeUi();
        initializeConnections();
        applyColumnPreset(ColumnPreset::Overview);
        applyThemeStyle();
    }

    void SoundSourcePage::showEvent(QShowEvent* const event)
    {
        QWidget::showEvent(event);
        if (m_autoRefreshCheck != nullptr &&
            m_autoRefreshCheck->isChecked() &&
            m_refreshTimer != nullptr)
        {
            m_refreshTimer->start();
        }
        if (m_records.empty() && !m_refreshing)
        {
            requestRefresh(false);
        }
    }

    void SoundSourcePage::hideEvent(QHideEvent* const event)
    {
        if (m_refreshTimer != nullptr)
        {
            m_refreshTimer->stop();
        }
        QWidget::hideEvent(event);
    }

    void SoundSourcePage::changeEvent(QEvent* const event)
    {
        QWidget::changeEvent(event);
        if (event != nullptr &&
            (event->type() == QEvent::PaletteChange ||
             event->type() == QEvent::StyleChange ||
             event->type() == QEvent::ApplicationPaletteChange))
        {
            applyThemeStyle();
        }
    }

    void SoundSourcePage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(8);

        m_titleLabel = new QLabel(
            m_processIdFilter == 0U
                ? QStringLiteral("声音来源")
                : QStringLiteral("当前进程的声音来源"),
            this);
        m_titleLabel->setToolTip(
            QStringLiteral("R3 采样 Core Audio 会话峰值、状态、音量与端点；R0 多源交叉核验会话 PID，只佐证进程身份，不读取或修改音频流。"));
        rootLayout->addWidget(m_titleLabel);

        auto* toolbarLayout = new QHBoxLayout();
        toolbarLayout->setSpacing(6);
        m_refreshButton = new QToolButton(this);
        m_refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        m_refreshButton->setToolTip(QStringLiteral("立即重新采样声音来源，并重试 R0 证据"));
        toolbarLayout->addWidget(m_refreshButton);

        m_autoRefreshCheck = new QCheckBox(QStringLiteral("自动刷新"), this);
        m_autoRefreshCheck->setChecked(true);
        m_autoRefreshCheck->setToolTip(
            QStringLiteral("页面可见时每 1.5 秒执行一次短时峰值采样"));
        toolbarLayout->addWidget(m_autoRefreshCheck);

        m_showSilentCheck = new QCheckBox(QStringLiteral("显示静默会话"), this);
        m_showSilentCheck->setChecked(false);
        m_showSilentCheck->setToolTip(
            QStringLiteral("显示当前未检测到波形的全部输出音频会话"));
        toolbarLayout->addWidget(m_showSilentCheck);
        toolbarLayout->addSpacing(10);

        m_columnPresetGroup = new QButtonGroup(this);
        m_columnPresetGroup->setExclusive(true);
        m_overviewPresetButton = new QToolButton(this);
        m_audioPresetButton = new QToolButton(this);
        m_kernelPresetButton = new QToolButton(this);
        const QList<QToolButton*> presetButtons = {
            m_overviewPresetButton,
            m_audioPresetButton,
            m_kernelPresetButton
        };
        const QStringList presetNames = {
            QStringLiteral("A"),
            QStringLiteral("B"),
            QStringLiteral("C")
        };
        const QStringList presetTooltips = {
            QStringLiteral("A：发声进程概览"),
            QStringLiteral("B：Core Audio 会话与端点链路"),
            QStringLiteral("C：R0 多源进程身份核验证据")
        };
        for (int buttonIndex = 0; buttonIndex < presetButtons.size(); ++buttonIndex)
        {
            QToolButton* const presetButton = presetButtons.at(buttonIndex);
            presetButton->setText(presetNames.at(buttonIndex));
            presetButton->setCheckable(true);
            presetButton->setToolTip(presetTooltips.at(buttonIndex));
            presetButton->setFixedSize(30, 26);
            m_columnPresetGroup->addButton(presetButton, buttonIndex);
            toolbarLayout->addWidget(presetButton);
        }
        toolbarLayout->addStretch(1);
        rootLayout->addLayout(toolbarLayout);

        m_summaryLabel = new QLabel(
            QStringLiteral("尚未采样声音来源。"),
            this);
        m_summaryLabel->setWordWrap(true);
        rootLayout->addWidget(m_summaryLabel);

        m_statusLabel = new QLabel(QStringLiteral("等待刷新"), this);
        m_statusLabel->setWordWrap(true);
        rootLayout->addWidget(m_statusLabel);

        m_table = new QTableWidget(this);
        m_table->setColumnCount(ColumnCount);
        m_table->setHorizontalHeaderLabels(tableHeaders());
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        m_table->setAlternatingRowColors(true);
        m_table->setSortingEnabled(false);
        m_table->verticalHeader()->setVisible(false);
        m_table->horizontalHeader()->setSectionsMovable(true);
        m_table->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
        m_table->horizontalHeader()->setToolTip(
            QStringLiteral("右键表头可逐列显示或隐藏；手动调整后进入自定义列布局"));
        rootLayout->addWidget(m_table, 1);

        m_refreshTimer = new QTimer(this);
        m_refreshTimer->setInterval(kAutoRefreshIntervalMs);
        m_refreshTimer->setTimerType(Qt::CoarseTimer);
    }

    void SoundSourcePage::initializeConnections()
    {
        connect(m_refreshButton, &QToolButton::clicked, this, [this]()
        {
            requestRefresh(true);
        });
        connect(m_refreshTimer, &QTimer::timeout, this, [this]()
        {
            requestRefresh(false);
        });
        connect(m_autoRefreshCheck, &QCheckBox::toggled, this, [this](const bool enabled)
        {
            if (enabled && isVisible())
            {
                m_refreshTimer->start();
            }
            else
            {
                m_refreshTimer->stop();
            }
        });
        connect(m_showSilentCheck, &QCheckBox::toggled, this, [this]()
        {
            rebuildTable();
        });
        connect(m_columnPresetGroup, &QButtonGroup::idClicked, this, [this](const int presetId)
        {
            if (presetId == 0)
            {
                applyColumnPreset(ColumnPreset::Overview);
            }
            else if (presetId == 1)
            {
                applyColumnPreset(ColumnPreset::AudioPath);
            }
            else if (presetId == 2)
            {
                applyColumnPreset(ColumnPreset::KernelEvidence);
            }
        });
        connect(
            m_table->horizontalHeader(),
            &QHeaderView::customContextMenuRequested,
            this,
            [this](const QPoint& position)
            {
                showHeaderContextMenu(position);
            });
    }

    void SoundSourcePage::requestRefresh(const bool manualRequest)
    {
        if (m_refreshing)
        {
            return;
        }
        if (manualRequest)
        {
            // 手动刷新是用户明确重试动作，允许重新探测此前不可用的 R0。
            m_autoKernelProbeEnabled = true;
        }

        m_refreshing = true;
        m_refreshButton->setEnabled(false);
        m_statusLabel->setText(QStringLiteral("正在连续采样 Core Audio 会话峰值…"));
        const std::uint64_t ticket = ++m_refreshTicket;

        SoundSourceScanOptions options;
        options.processIdFilter = m_processIdFilter;
        options.expectedCreationTime100ns = m_expectedCreationTime100ns;
        options.includeKernelEvidence = m_autoKernelProbeEnabled;
        options.sampleCount = 6;
        options.sampleIntervalMs = 40;

        const QPointer<SoundSourcePage> guardedPage(this);
        QRunnable* const task = QRunnable::create(
            [guardedPage, options, ticket]()
            {
                SoundSourceScanResult result = detectSoundSources(options);
                SoundSourcePage* const contextObject = guardedPage.data();
                if (contextObject == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    contextObject,
                    [guardedPage, ticket, result = std::move(result)]() mutable
                    {
                        if (!guardedPage.isNull())
                        {
                            guardedPage->applyScanResult(ticket, result);
                        }
                    },
                    Qt::QueuedConnection);
            });
        QThreadPool::globalInstance()->start(task);
    }

    void SoundSourcePage::applyScanResult(
        const std::uint64_t ticket,
        const SoundSourceScanResult& result)
    {
        if (ticket != m_refreshTicket)
        {
            return;
        }

        m_refreshing = false;
        m_refreshButton->setEnabled(true);
        if (result.kernelAttempted && !result.kernelAvailable)
        {
            // 自动刷新不重复触发 R0 不可用提示；用户点击刷新时仍可显式重试。
            m_autoKernelProbeEnabled = false;
        }

        std::vector<SoundSourceRecord> mergedRecords = result.records;
        mergeRecentHistory(mergedRecords);
        m_records = std::move(mergedRecords);
        rebuildTable();
        updateSummary(result);
    }

    void SoundSourcePage::mergeRecentHistory(
        std::vector<SoundSourceRecord>& records)
    {
        const std::int64_t nowUnixMs = QDateTime::currentMSecsSinceEpoch();
        QSet<QString> currentKeys;
        for (SoundSourceRecord& record : records)
        {
            const QString key = recordKey(record);
            currentKeys.insert(key);
            if (record.currentlyAudible)
            {
                record.lastAudibleUnixMs = nowUnixMs;
                m_recentRecords.insert(key, record);
                continue;
            }

            const auto recentIterator = m_recentRecords.constFind(key);
            if (recentIterator != m_recentRecords.constEnd() &&
                nowUnixMs - recentIterator->lastAudibleUnixMs <=
                    kRecentAudibleRetentionMs)
            {
                record.recentlyAudible = true;
                record.lastAudibleUnixMs = recentIterator->lastAudibleUnixMs;
                const double elapsedSeconds =
                    static_cast<double>(nowUnixMs - record.lastAudibleUnixMs) /
                    1000.0;
                record.verdictText =
                    QStringLiteral("最近发声（%1 秒前）").arg(elapsedSeconds, 0, 'f', 1);
            }
        }

        for (auto iterator = m_recentRecords.begin();
             iterator != m_recentRecords.end();)
        {
            const std::int64_t elapsedMs =
                nowUnixMs - iterator->lastAudibleUnixMs;
            if (elapsedMs > kRecentAudibleRetentionMs)
            {
                iterator = m_recentRecords.erase(iterator);
                continue;
            }
            if (!currentKeys.contains(iterator.key()))
            {
                SoundSourceRecord recentRecord = iterator.value();
                recentRecord.currentlyAudible = false;
                recentRecord.recentlyAudible = true;
                const double elapsedSeconds =
                    static_cast<double>(elapsedMs) / 1000.0;
                recentRecord.verdictText =
                    QStringLiteral("最近发声（%1 秒前）").arg(elapsedSeconds, 0, 'f', 1);
                records.push_back(std::move(recentRecord));
            }
            ++iterator;
        }

        std::stable_sort(
            records.begin(),
            records.end(),
            [](const SoundSourceRecord& left, const SoundSourceRecord& right)
            {
                if (left.currentlyAudible != right.currentlyAudible)
                {
                    return left.currentlyAudible;
                }
                if (left.recentlyAudible != right.recentlyAudible)
                {
                    return left.recentlyAudible;
                }
                return left.peakMaximum > right.peakMaximum;
            });
    }

    void SoundSourcePage::rebuildTable()
    {
        const bool showSilentSessions =
            m_showSilentCheck != nullptr && m_showSilentCheck->isChecked();
        std::vector<const SoundSourceRecord*> visibleRecords;
        for (const SoundSourceRecord& record : m_records)
        {
            if (showSilentSessions ||
                record.currentlyAudible ||
                record.recentlyAudible)
            {
                visibleRecords.push_back(&record);
            }
        }

        m_table->setRowCount(static_cast<int>(visibleRecords.size()));
        for (int rowIndex = 0; rowIndex < static_cast<int>(visibleRecords.size()); ++rowIndex)
        {
            const SoundSourceRecord& record = *visibleRecords[static_cast<std::size_t>(rowIndex)];
            const QString kernelObjectText =
                QStringLiteral("EPROCESS=%1；ObjectTable=%2")
                .arg(addressText(record.kernel.processObjectAddress))
                .arg(addressText(record.kernel.objectTableAddress));
            const QString creationTimeText = record.creationTime100ns == 0U
                ? QStringLiteral("不可用")
                : QStringLiteral("0x%1").arg(record.creationTime100ns, 0, 16).toUpper();
            const QString anomalyText = record.kernel.attempted
                ? QStringLiteral("0x%1").arg(record.kernel.anomalyFlags, 0, 16).toUpper()
                : QStringLiteral("未采样");
            const QString confidenceText = record.kernel.attempted
                ? QStringLiteral("%1").arg(record.kernel.confidence)
                : QStringLiteral("未采样");
            const QStringList values = {
                record.verdictText,
                record.processName,
                QString::number(record.processId),
                percentText(record.peakMaximum, 3),
                percentText(record.peakAverage, 3),
                record.stateText,
                record.endpointName,
                percentText(record.endpointPeakMaximum, 3),
                record.endpointRoleText,
                record.volumeAvailable
                    ? percentText(record.sessionVolume, 1)
                    : QStringLiteral("不可用"),
                record.muted ? QStringLiteral("是") : QStringLiteral("否"),
                record.sessionName,
                record.sessionInstanceId,
                record.imagePath,
                creationTimeText,
                record.kernel.attempted
                    ? record.kernel.statusText
                    : QStringLiteral("未采样"),
                record.kernel.attempted
                    ? kernelSourceText(record.kernel.sourceMask)
                    : QStringLiteral("未采样"),
                confidenceText,
                anomalyText,
                record.kernel.attempted
                    ? kernelObjectText
                    : QStringLiteral("未采样"),
                record.kernel.detailText
            };

            for (int columnIndex = 0; columnIndex < ColumnCount; ++columnIndex)
            {
                auto* item = new QTableWidgetItem(values.at(columnIndex));
                item->setToolTip(values.at(columnIndex));
                if (record.currentlyAudible)
                {
                    item->setBackground(KswordTheme::SuccessBackgroundColor());
                }
                else if (record.recentlyAudible)
                {
                    item->setBackground(KswordTheme::WarningBackgroundColor());
                }
                if (columnIndex == ColumnPid)
                {
                    item->setTextAlignment(Qt::AlignCenter);
                }
                m_table->setItem(rowIndex, columnIndex, item);
            }
        }
        m_table->resizeColumnsToContents();
    }

    void SoundSourcePage::updateSummary(const SoundSourceScanResult& result)
    {
        if (!result.audioQueryOk)
        {
            m_summaryLabel->setText(
                m_processIdFilter == 0U
                    ? QStringLiteral("未能读取系统输出音频会话。")
                    : QStringLiteral("未能读取当前进程的输出音频会话。"));
            m_statusLabel->setText(result.diagnosticText);
            return;
        }

        QSet<QString> currentSourceKeys;
        QSet<QString> recentSourceKeys;
        int activeSessionCount = 0;
        int corroboratedCount = 0;
        for (const SoundSourceRecord& record : m_records)
        {
            const QString sourceKey = record.processId == 0U
                ? record.processName
                : QString::number(record.processId);
            if (record.currentlyAudible)
            {
                currentSourceKeys.insert(sourceKey);
            }
            else if (record.recentlyAudible)
            {
                recentSourceKeys.insert(sourceKey);
            }
            if (record.sessionActive)
            {
                ++activeSessionCount;
            }
            if (record.currentlyAudible && record.kernel.corroborated)
            {
                ++corroboratedCount;
            }
        }

        if (m_processIdFilter != 0U &&
            currentSourceKeys.isEmpty() &&
            recentSourceKeys.isEmpty())
        {
            m_summaryLabel->setText(
                QStringLiteral("当前进程在本次采样窗口内没有发声。"));
        }
        else
        {
            m_summaryLabel->setText(
                QStringLiteral(
                    "确认正在发声：%1 个进程；最近发声：%2 个进程；活动会话：%3；其中 R0 多源一致：%4。")
                .arg(currentSourceKeys.size())
                .arg(recentSourceKeys.size())
                .arg(activeSessionCount)
                .arg(corroboratedCount));
        }

        QString statusText = QStringLiteral("Core Audio 采样窗口：%1 ms。")
            .arg(result.sampleWindowMs);
        if (result.kernelAttempted && !result.kernelAvailable)
        {
            statusText += QStringLiteral(
                " R0 当前不可用，自动刷新将继续保留 R3 检测；点击刷新按钮可重新尝试 R0。");
            if (!result.kernelDiagnosticText.isEmpty())
            {
                statusText += QStringLiteral(" ") + result.kernelDiagnosticText;
            }
        }
        else if (result.kernelAvailable)
        {
            statusText += QStringLiteral(" R0 进程身份核验已完成。");
            if (!result.kernelDiagnosticText.isEmpty())
            {
                statusText += QStringLiteral(" ") + result.kernelDiagnosticText;
            }
        }
        else
        {
            statusText += QStringLiteral(" 本轮没有需要 R0 核验的活动 PID。");
        }
        m_statusLabel->setText(statusText);
    }

    void SoundSourcePage::applyColumnPreset(const ColumnPreset preset)
    {
        QSet<int> visibleColumns;
        if (preset == ColumnPreset::Overview)
        {
            visibleColumns = {
                ColumnVerdict,
                ColumnProcess,
                ColumnPid,
                ColumnPeakMaximum,
                ColumnEndpoint,
                ColumnKernelVerdict
            };
        }
        else if (preset == ColumnPreset::AudioPath)
        {
            visibleColumns = {
                ColumnVerdict,
                ColumnProcess,
                ColumnPid,
                ColumnPeakMaximum,
                ColumnSessionState,
                ColumnEndpoint,
                ColumnEndpointRole,
                ColumnSessionVolume,
                ColumnMuted,
                ColumnSessionName
            };
        }
        else if (preset == ColumnPreset::KernelEvidence)
        {
            visibleColumns = {
                ColumnVerdict,
                ColumnProcess,
                ColumnPid,
                ColumnKernelVerdict,
                ColumnKernelSources,
                ColumnKernelConfidence,
                ColumnKernelAnomaly,
                ColumnKernelObjects,
                ColumnEvidenceDetail
            };
        }
        else
        {
            return;
        }

        for (int columnIndex = 0; columnIndex < ColumnCount; ++columnIndex)
        {
            m_table->setColumnHidden(
                columnIndex,
                !visibleColumns.contains(columnIndex));
        }
        m_columnPreset = preset;
        m_overviewPresetButton->setChecked(preset == ColumnPreset::Overview);
        m_audioPresetButton->setChecked(preset == ColumnPreset::AudioPath);
        m_kernelPresetButton->setChecked(preset == ColumnPreset::KernelEvidence);
        m_table->resizeColumnsToContents();
    }

    void SoundSourcePage::showHeaderContextMenu(const QPoint& position)
    {
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        const QStringList headers = tableHeaders();
        for (int columnIndex = 0; columnIndex < ColumnCount; ++columnIndex)
        {
            QAction* const columnAction = menu.addAction(headers.at(columnIndex));
            columnAction->setCheckable(true);
            columnAction->setChecked(!m_table->isColumnHidden(columnIndex));
            columnAction->setData(columnIndex);
        }

        QAction* const selectedAction = menu.exec(
            m_table->horizontalHeader()->mapToGlobal(position));
        if (selectedAction == nullptr)
        {
            return;
        }
        const int columnIndex = selectedAction->data().toInt();
        if (columnIndex < 0 || columnIndex >= ColumnCount)
        {
            return;
        }
        m_table->setColumnHidden(columnIndex, !selectedAction->isChecked());
        setCustomColumnLayout();
    }

    void SoundSourcePage::setCustomColumnLayout()
    {
        m_columnPreset = ColumnPreset::Custom;
        m_columnPresetGroup->setExclusive(false);
        m_overviewPresetButton->setChecked(false);
        m_audioPresetButton->setChecked(false);
        m_kernelPresetButton->setChecked(false);
        m_columnPresetGroup->setExclusive(true);
    }

    void SoundSourcePage::applyThemeStyle()
    {
        m_titleLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryColorHex()));
        m_summaryLabel->setStyleSheet(
            QStringLiteral("font-weight:600;color:%1;")
            .arg(KswordTheme::TextPrimaryColorHex()));
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;")
            .arg(KswordTheme::TextSecondaryColorHex()));

        // 常态不描边不铺底，选中态已有实心强调色足够区分，hover 才补边框。
        // 占位符编号与 arg() 严格一一对应：arg 替换的是编号最小的 %n，不是固定 %1。
        const QString presetButtonStyle = QStringLiteral(
            "QToolButton{background:transparent;color:%1;border:1px solid transparent;border-radius:4px;}"
            "QToolButton:hover{border-color:%2;background:%3;}"
            "QToolButton:checked{background:%2;color:%4;border-color:%2;}"
            "QToolButton:disabled{color:%5;background:transparent;border-color:transparent;}")
            .arg(KswordTheme::TextPrimaryColorHex())                     // %1
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))  // %2
            .arg(KswordTheme::SurfaceAltColorHex())                      // %3
            .arg(KswordTheme::OnAccentHex())                             // %4
            .arg(KswordTheme::TextDisabledColorHex());                   // %5
        m_refreshButton->setStyleSheet(presetButtonStyle);
        m_overviewPresetButton->setStyleSheet(presetButtonStyle);
        m_audioPresetButton->setStyleSheet(presetButtonStyle);
        m_kernelPresetButton->setStyleSheet(presetButtonStyle);
    }

    QString SoundSourcePage::recordKey(
        const SoundSourceRecord& record) const
    {
        QString sessionKey = record.sessionInstanceId;
        if (sessionKey.trimmed().isEmpty())
        {
            sessionKey = record.sessionIdentifier;
        }
        if (sessionKey.trimmed().isEmpty())
        {
            sessionKey = QStringLiteral("pid:%1").arg(record.processId);
        }
        return record.endpointId + QStringLiteral("|") + sessionKey;
    }
}
