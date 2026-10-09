#include "HudPerformancePanel.h"
#include "../shared/ui/KsPainterChart.h"
#include "../shared/ui/MetricChartBinding.h"

#include "PerformanceNavCard.h"
#include "HudColors.h"

#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMutexLocker>
#include <QMetaObject>
#include <QPainterPath>
#include <QPainter>
#include <QPointer>
#include <QProcess>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShowEvent>
#include <QStackedWidget>
#include <QTimer>
#include <QThreadPool>
#include <QVariantAnimation>
#include <QVector>
#include <QVBoxLayout>

#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <cmath>

#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <intrin.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <Psapi.h>
#include <PowrProf.h>
#include <dxgi1_6.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Dxgi.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    class CpuCoreSparklineWidget final : public QWidget
    {
    public:
        explicit CpuCoreSparklineWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setAttribute(Qt::WA_StyledBackground, true);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            m_sampleAnimation = new QVariantAnimation(this);
            m_sampleAnimation->setDuration(260);
            m_sampleAnimation->setEasingCurve(QEasingCurve::OutCubic);
            m_sampleAnimation->setStartValue(0.0);
            m_sampleAnimation->setEndValue(1.0);
            connect(m_sampleAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
                m_animationProgress = value.toDouble();
                update();
            });
        }

        void appendSample(const double usagePercent, const int historyLength)
        {
            const double boundedValue = qBound(0.0, usagePercent, 100.0);
            m_previousSample = m_samples.isEmpty()
                ? boundedValue
                : m_samples.back();
            m_previousSampleCount = static_cast<int>(m_samples.size());
            m_historyWindowShifted = m_previousSampleCount >= historyLength;
            m_samples.push_back(boundedValue);
            while (m_samples.size() > historyLength)
            {
                m_samples.pop_front();
            }
            m_animationProgress = 0.0;
            m_sampleAnimation->stop();
            m_sampleAnimation->start();
        }

    protected:
        void paintEvent(QPaintEvent* eventPointer) override
        {
            Q_UNUSED(eventPointer);

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);
            painter.fillRect(rect(), Qt::transparent);

            const QRectF contentRect = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
            if (contentRect.width() <= 4.0 || contentRect.height() <= 4.0)
            {
                return;
            }

            const QColor accent = palette().color(QPalette::Highlight);
            QColor border = accent;
            border.setAlpha(48);
            painter.setPen(QPen(border, 1.0));
            QColor track = palette().color(QPalette::WindowText);
            track.setAlpha(8);
            painter.setBrush(track);
            painter.drawRoundedRect(contentRect, 6.0, 6.0);

            border.setAlpha(28);
            painter.setPen(QPen(border, 1.0));
            const double midY = contentRect.top() + contentRect.height() * 0.5;
            painter.drawLine(
                QPointF(contentRect.left() + 4.0, midY),
                QPointF(contentRect.right() - 4.0, midY));

            if (m_samples.size() < 2)
            {
                return;
            }

            QPainterPath linePath;
            const double usableWidth = std::max(1.0, contentRect.width() - 8.0);
            const double usableHeight = std::max(1.0, contentRect.height() - 8.0);
            for (int indexValue = 0; indexValue < m_samples.size(); ++indexValue)
            {
                const int sampleCount = m_samples.size();
                const double targetRatio =
                    static_cast<double>(indexValue) / static_cast<double>(sampleCount - 1);
                double startRatio = targetRatio;
                if (m_animationProgress < 1.0)
                {
                    if (m_historyWindowShifted && m_previousSampleCount == sampleCount)
                    {
                        startRatio = indexValue + 1 < sampleCount
                            ? static_cast<double>(indexValue + 1) / static_cast<double>(sampleCount - 1)
                            : 1.0;
                    }
                    else if (m_previousSampleCount + 1 == sampleCount && m_previousSampleCount > 1)
                    {
                        startRatio = indexValue < m_previousSampleCount
                            ? static_cast<double>(indexValue) / static_cast<double>(m_previousSampleCount - 1)
                            : 1.0;
                    }
                }
                const double xRatio =
                    startRatio + (targetRatio - startRatio) * m_animationProgress;
                const double xValue = contentRect.left() + 4.0 + usableWidth * xRatio;
                double sampleValue = m_samples.at(indexValue);
                if (indexValue == m_samples.size() - 1 && m_animationProgress < 1.0)
                {
                    sampleValue = m_previousSample
                        + (sampleValue - m_previousSample) * m_animationProgress;
                }
                const double yValue =
                    contentRect.bottom() - 4.0 - usableHeight * (sampleValue / 100.0);
                if (indexValue == 0)
                {
                    linePath.moveTo(xValue, yValue);
                }
                else
                {
                    linePath.lineTo(xValue, yValue);
                }
            }

            painter.setPen(QPen(accent, 1.5));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(linePath);
        }

    private:
        QVector<double> m_samples;
        int m_previousSampleCount = 0;
        bool m_historyWindowShifted = false;
        QVariantAnimation* m_sampleAnimation = nullptr;
        double m_previousSample = 0.0;
        double m_animationProgress = 1.0;
    };

    constexpr double kOneGiBInBytes = 1024.0 * 1024.0 * 1024.0;

    QColor textPrimaryColor()
    {
        return QColor(242, 246, 252);
    }

    QString queryPowerShellTextSync(const QString& scriptText, const int timeoutMs)
    {
        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments({
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
            });
        process.start();
        if (!process.waitForStarted(1200))
        {
            return QStringLiteral("PowerShell start failed.");
        }
        if (!process.waitForFinished(timeoutMs))
        {
            process.kill();
            process.waitForFinished(800);
            return QStringLiteral("PowerShell timeout.");
        }
        const QString standardOutputText =
            QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
        const QString standardErrorText =
            QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            return standardErrorText.isEmpty()
                ? QStringLiteral("PowerShell failed.")
                : standardErrorText;
        }
        return standardOutputText.isEmpty() ? QStringLiteral("<empty>") : standardOutputText;
    }

    QString extractSensorValueFromOutput(const QString& rawOutputText)
    {
        const QString firstLineText = rawOutputText
            .split('\n', Qt::SkipEmptyParts)
            .value(0)
            .trimmed();
        if (firstLineText.isEmpty()
            || firstLineText == QStringLiteral("<empty>")
            || firstLineText.contains(QStringLiteral("PowerShell"), Qt::CaseInsensitive)
            || firstLineText.contains(QStringLiteral("failed"), Qt::CaseInsensitive)
            || firstLineText.contains(QStringLiteral("timeout"), Qt::CaseInsensitive))
        {
            return QStringLiteral("N/A");
        }
        return firstLineText;
    }

    QString queryCpuTemperatureText()
    {
        const QString temperatureScript = QStringLiteral(
            "$v=Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | "
            "Select-Object -First 1 -ExpandProperty CurrentTemperature; "
            "if($null -eq $v){'N/A'}else{([math]::Round(($v/10)-273.15,1)).ToString() + '°C'}");
        return extractSensorValueFromOutput(queryPowerShellTextSync(temperatureScript, 2200));
    }

    QString queryCpuVoltageText()
    {
        const QString voltageScript = QStringLiteral(
            "$v=Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty CurrentVoltage; "
            "if($null -eq $v -or $v -eq 0){'N/A'}else{([math]::Round($v*0.1,2)).ToString() + 'V'}");
        return extractSensorValueFromOutput(queryPowerShellTextSync(voltageScript, 2200));
    }

    QString queryCpuBrandTextByCpuid()
    {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0x80000000);
        const unsigned int maxExtendedLeaf = static_cast<unsigned int>(cpuInfo[0]);
        if (maxExtendedLeaf < 0x80000004)
        {
            return QStringLiteral("N/A");
        }

        char brandBuffer[49] = {};
        int* brandIntBuffer = reinterpret_cast<int*>(brandBuffer);
        __cpuid(brandIntBuffer, 0x80000002);
        __cpuid(brandIntBuffer + 4, 0x80000003);
        __cpuid(brandIntBuffer + 8, 0x80000004);

        const QString brandText = QString::fromLatin1(brandBuffer).trimmed();
        return brandText.isEmpty() ? QStringLiteral("N/A") : brandText;
    }

    int countBits(KAFFINITY affinityMask)
    {
        int count = 0;
        while (affinityMask != 0)
        {
            count += static_cast<int>(affinityMask & 1);
            affinityMask >>= 1;
        }
        return count;
    }

    void appendTransparentBackgroundStyle(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setAttribute(Qt::WA_StyledBackground, true);
        widgetPointer->setAutoFillBackground(false);

        const QString transparentStyleText =
            QStringLiteral("background:transparent;background-color:transparent;border:none;");
        if (!widgetPointer->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            widgetPointer->setStyleSheet(widgetPointer->styleSheet() + transparentStyleText);
        }

        QAbstractScrollArea* abstractScrollAreaPointer =
            qobject_cast<QAbstractScrollArea*>(widgetPointer);
        if (abstractScrollAreaPointer == nullptr || abstractScrollAreaPointer->viewport() == nullptr)
        {
            return;
        }

        abstractScrollAreaPointer->viewport()->setAttribute(Qt::WA_StyledBackground, true);
        abstractScrollAreaPointer->viewport()->setAutoFillBackground(false);
        if (!abstractScrollAreaPointer->viewport()->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            abstractScrollAreaPointer->viewport()->setStyleSheet(
                abstractScrollAreaPointer->viewport()->styleSheet() + transparentStyleText);
        }
    }

    void configureTransparentChart(QChart* chartPointer)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->setBackgroundVisible(false);
        chartPointer->setPlotAreaBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
        chartPointer->setTitleBrush(QBrush(textPrimaryColor()));
        if (chartPointer->legend() != nullptr)
        {
            chartPointer->legend()->setLabelColor(textPrimaryColor());
        }
    }

    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double safeValue = std::max(0.0, bytesPerSecondValue);
        if (safeValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(safeValue, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(safeValue / 1024.0, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(safeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(safeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    QString bytesToReadableText(const double bytesValue)
    {
        const double safeValue = std::max(0.0, bytesValue);
        if (safeValue < 1024.0)
        {
            return QStringLiteral("%1 B").arg(safeValue, 0, 'f', 0);
        }
        if (safeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB").arg(safeValue / 1024.0, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB").arg(safeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB").arg(safeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    QString resolveGpuEngineKeyFromCounter(const QString& counterNameText)
    {
        const QString lowerText = counterNameText.toLower();
        if (lowerText.contains(QStringLiteral("engtype_3d")))
        {
            return QStringLiteral("3d");
        }
        if (lowerText.contains(QStringLiteral("engtype_copy")))
        {
            return QStringLiteral("copy");
        }
        if (lowerText.contains(QStringLiteral("engtype_videoencode"))
            || lowerText.contains(QStringLiteral("engtype_videncode")))
        {
            return QStringLiteral("video_encode");
        }
        if (lowerText.contains(QStringLiteral("engtype_videodecode"))
            || lowerText.contains(QStringLiteral("engtype_viddecode")))
        {
            return QStringLiteral("video_decode");
        }
        return QString();
    }

    QString formatDurationText(const std::uint64_t totalSeconds)
    {
        const std::uint64_t dayCount = totalSeconds / 86400ULL;
        const std::uint64_t hourCount = (totalSeconds % 86400ULL) / 3600ULL;
        const std::uint64_t minuteCount = (totalSeconds % 3600ULL) / 60ULL;
        const std::uint64_t secondCount = totalSeconds % 60ULL;
        return QStringLiteral("%1:%2:%3:%4")
            .arg(dayCount)
            .arg(hourCount, 2, 10, QLatin1Char('0'))
            .arg(minuteCount, 2, 10, QLatin1Char('0'))
            .arg(secondCount, 2, 10, QLatin1Char('0'));
    }

    struct MemoryHardwareSummarySnapshot
    {
        int speedMhz = 0;
        int usedSlots = 0;
        int totalSlots = 0;
        QString formFactorText = QStringLiteral("N/A");
    };

    struct GpuHardwareSummarySnapshot
    {
        QString adapterNameText = QStringLiteral("N/A");
        QString driverVersionText = QStringLiteral("N/A");
        QString driverDateText = QStringLiteral("N/A");
        QString pnpDeviceIdText = QStringLiteral("N/A");
        double dedicatedMemoryGiB = 0.0;
    };

    MemoryHardwareSummarySnapshot queryMemoryHardwareSummarySnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$mods=Get-CimInstance Win32_PhysicalMemory; "
            "$arr=Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1 -ExpandProperty MemoryDevices; "
            "$speed=($mods | Select-Object -First 1 -ExpandProperty ConfiguredClockSpeed); "
            "$formCode=($mods | Select-Object -First 1 -ExpandProperty FormFactor); "
            "$formText=if([int]$formCode -eq 8){'DIMM'}elseif([int]$formCode -eq 12){'SODIMM'}elseif([int]$formCode -gt 0){'Code'+[string]$formCode}else{'N/A'}; "
            "\"$speed|$($mods.Count)|$arr|$formText\"");
        const QString outputText = queryPowerShellTextSync(scriptText, 3200);
        const QStringList fieldList = outputText.split('|');

        MemoryHardwareSummarySnapshot snapshot;
        if (fieldList.size() >= 4)
        {
            snapshot.speedMhz = fieldList.at(0).trimmed().toInt();
            snapshot.usedSlots = fieldList.at(1).trimmed().toInt();
            snapshot.totalSlots = fieldList.at(2).trimmed().toInt();
            snapshot.formFactorText = fieldList.at(3).trimmed();
            if (snapshot.formFactorText.isEmpty())
            {
                snapshot.formFactorText = QStringLiteral("N/A");
            }
        }
        return snapshot;
    }

    GpuHardwareSummarySnapshot queryGpuHardwareSummarySnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1 Name,DriverVersion,DriverDate,AdapterRAM,PNPDeviceID; "
            "if($null -eq $gpu){'N/A|N/A|N/A|N/A|0'}else{\"$($gpu.Name)|$($gpu.DriverVersion)|$($gpu.DriverDate)|$($gpu.PNPDeviceID)|$($gpu.AdapterRAM)\"}");
        const QString outputText = queryPowerShellTextSync(scriptText, 2800);
        const QStringList fieldList = outputText.split('|');

        GpuHardwareSummarySnapshot snapshot;
        if (fieldList.size() >= 5)
        {
            snapshot.adapterNameText = fieldList.at(0).trimmed();
            snapshot.driverVersionText = fieldList.at(1).trimmed();
            snapshot.driverDateText = fieldList.at(2).trimmed();
            snapshot.pnpDeviceIdText = fieldList.at(3).trimmed();
            const double memoryBytes = fieldList.at(4).trimmed().toDouble();
            snapshot.dedicatedMemoryGiB = memoryBytes / kOneGiBInBytes;
        }
        return snapshot;
    }

    QChartView* createNoFrameChartView(QChart* chartPointer, QWidget* parentWidget)
    {
        chartPointer->setAnimationOptions(QChart::AllAnimations);
        chartPointer->setAnimationDuration(260);
        chartPointer->setAnimationEasingCurve(QEasingCurve::OutCubic);
        configureTransparentChart(chartPointer);
        QChartView* chartView = new QChartView(chartPointer, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        chartView->setMinimumHeight(56);
        appendTransparentBackgroundStyle(chartView);
        return chartView;
    }
}

HudPerformancePanel::HudPerformancePanel(QWidget* parent)
    : QWidget(parent)
{
    appendTransparentBackgroundStyle(this);
    initializeUi();
    refreshCpuTopologyStaticInfo();
    refreshSystemVolumeInfo();

    m_cachedSensorText = QStringLiteral("N/A|N/A");
    if (m_cpuModelLabel != nullptr)
    {
        m_cpuModelLabel->setText(m_cpuModelText);
    }

    requestAsyncStaticInfoRefresh();
    requestAsyncSensorRefresh();

    m_liveSampleWatcher = new QFutureWatcher<LiveSampleResult>(this);
    connect(m_liveSampleWatcher, &QFutureWatcher<LiveSampleResult>::finished, this, [this]()
    {
        m_liveSampleInProgress = false;
        applyLiveSampleResult(m_liveSampleWatcher->result());
    });

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(1000);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]()
    {
        requestLiveRefresh();
    });
    m_refreshTimer->start();

    requestLiveRefresh();
}

HudPerformancePanel::~HudPerformancePanel()
{
    if (m_refreshTimer != nullptr)
    {
        m_refreshTimer->stop();
    }
    if (m_liveSampleWatcher != nullptr)
    {
        m_liveSampleWatcher->waitForFinished();
    }

    if (m_cpuPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle));
        m_cpuPerfQueryHandle = nullptr;
        m_coreCounterHandles.clear();
    }

    if (m_diskPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle));
        m_diskPerfQueryHandle = nullptr;
        m_diskReadCounterHandle = nullptr;
        m_diskWriteCounterHandle = nullptr;
    }

    if (m_gpuPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_gpuPerfQueryHandle));
        m_gpuPerfQueryHandle = nullptr;
        m_gpuCounterHandle = nullptr;
    }
}

void HudPerformancePanel::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    adjustChartHeights();
}

void HudPerformancePanel::setEffectiveBackgroundColor(const QColor& colorValue)
{
    // 文字和自绘 CPU 线都使用独立 HUD 底色；动态 palette QSS 随本次更新生效。
    QPalette colors = palette();
    const QColor primary = KswordHudColors::Readable(QColor(242, 246, 252), colorValue);
    const QColor secondary = KswordHudColors::Readable(QColor(185, 205, 225), colorValue);
    colors.setColor(QPalette::Window, colorValue);
    colors.setColor(QPalette::Base, colorValue);
    colors.setColor(QPalette::WindowText, primary);
    colors.setColor(QPalette::Text, primary);
    colors.setColor(QPalette::Mid, secondary);
    colors.setColor(QPalette::Highlight, KswordHudColors::Readable(QColor(72, 170, 255), colorValue, 3.0));
    setPalette(colors);

    // 项目自有 QChart 持有实色，不能仅更新 QWidget palette；每条曲线保留原数据色种子。
    const auto widgets = findChildren<QWidget*>();
    for (QWidget* widget : widgets)
    {
        auto* view = dynamic_cast<QChartView*>(widget);
        if (view == nullptr || view->chart() == nullptr)
        {
            continue;
        }
        applyChartColors(view->chart(), colorValue);
        view->update();
    }
    update();
}

void HudPerformancePanel::applyChartColors(QChart* chart, const QColor& colorValue)
{
    if (chart != nullptr)
    {
        const QColor primary = KswordHudColors::Readable(QColor(242, 246, 252), colorValue);
        const QColor secondary = KswordHudColors::Readable(QColor(185, 205, 225), colorValue);
        chart->setTitleBrush(primary);
        if (chart->legend() != nullptr)
        {
            chart->legend()->setLabelColor(primary);
        }
        for (QAbstractAxis* axis : chart->axes())
        {
            axis->setLabelsBrush(secondary);
            axis->setTitleBrush(primary);
            axis->setLinePenColor(secondary);
            const QVariant savedGrid = axis->property("ksword_hud_grid_seed");
            const QColor gridSeed = savedGrid.isValid() ? savedGrid.value<QColor>() : axis->gridLinePen().color();
            if (!savedGrid.isValid())
            {
                axis->setProperty("ksword_hud_grid_seed", gridSeed);
            }
            QColor grid = KswordHudColors::Readable(gridSeed, colorValue, 3.0);
            grid.setAlpha(gridSeed.alpha());
            axis->setGridLineColor(grid);
        }
        for (QAbstractSeries* series : chart->series())
        {
            if (auto* line = dynamic_cast<QLineSeries*>(series))
            {
                const QVariant savedSeed = line->property("ksword_hud_series_seed");
                const QColor seed = savedSeed.isValid() ? savedSeed.value<QColor>() : line->color();
                if (!savedSeed.isValid())
                {
                    line->setProperty("ksword_hud_series_seed", seed);
                }
                line->setColor(KswordHudColors::Readable(seed, colorValue, 3.0));
            }
        }
    }
}

void HudPerformancePanel::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);
    QTimer::singleShot(0, this, [this]()
    {
        adjustChartHeights();
    });
    QTimer::singleShot(80, this, [this]()
    {
        adjustChartHeights();
    });
}

void HudPerformancePanel::initializeUi()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    m_bodyLayout = new QHBoxLayout();
    m_bodyLayout->setContentsMargins(0, 0, 0, 0);
    m_bodyLayout->setSpacing(8);
    rootLayout->addLayout(m_bodyLayout, 1);

    m_sidebarList = new QListWidget(this);
    m_sidebarList->setFrameShape(QFrame::NoFrame);
    m_sidebarList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_sidebarList->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_sidebarList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_sidebarList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_sidebarList->setSpacing(3);
    m_sidebarList->setFixedWidth(286);
    m_sidebarList->setStyleSheet(QStringLiteral(
        "QListWidget{border:none;background:transparent;}"
        "QListWidget::item{border:none;padding:0px;margin:0px;}"
        "QListWidget::item:selected{background:transparent;}"));
    appendTransparentBackgroundStyle(m_sidebarList);
    m_bodyLayout->addWidget(m_sidebarList, 0);

    m_detailStack = new QStackedWidget(this);
    appendTransparentBackgroundStyle(m_detailStack);
    m_bodyLayout->addWidget(m_detailStack, 1);

    initializeCpuPage();
    initializeMemoryPage();
    initializeDiskPage();
    initializeNetworkPage();
    initializeGpuPage();
    initializeSidebarCards();

    connect(m_sidebarList, &QListWidget::currentRowChanged, this, [this](const int rowIndex)
    {
        syncSidebarSelection(rowIndex);
    });

    m_sidebarList->setCurrentRow(0);
    syncSidebarSelection(0);
}

void HudPerformancePanel::initializeSidebarCards()
{
    auto addCardItem =
        [this](PerformanceNavCard*& cardOut, const QString& titleText, const QColor& accentColor)
        {
            QListWidgetItem* itemPointer = new QListWidgetItem();
            cardOut = new PerformanceNavCard(m_sidebarList);
            cardOut->setTitleText(titleText);
            cardOut->setSubtitleText(QStringLiteral("Sampling..."));
            cardOut->setAccentColor(accentColor);
            itemPointer->setSizeHint(cardOut->sizeHint());
            m_sidebarList->addItem(itemPointer);
            m_sidebarList->setItemWidget(itemPointer, cardOut);
        };

    addCardItem(m_cpuNavCard, QStringLiteral("CPU"), QColor(90, 178, 255));
    addCardItem(m_memoryNavCard, QStringLiteral("Memory"), QColor(184, 99, 255));
    addCardItem(m_diskNavCard, QStringLiteral("Disk"), QColor(104, 204, 116));
    addCardItem(m_networkNavCard, QStringLiteral("Ethernet"), QColor(230, 149, 76));
    addCardItem(m_gpuNavCard, QStringLiteral("GPU"), QColor(105, 173, 255));
}

void HudPerformancePanel::initializeCpuPage()
{
    m_cpuPage = new QWidget(m_detailStack);
    appendTransparentBackgroundStyle(m_cpuPage);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_cpuPage);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(QStringLiteral("CPU"), m_cpuPage);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:palette(window-text);"));
    m_cpuModelLabel = new QLabel(QStringLiteral("Detecting..."), m_cpuPage);
    m_cpuModelLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_cpuModelLabel->setStyleSheet(QStringLiteral("font-size:15px;font-weight:500;color:palette(window-text);"));
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(m_cpuModelLabel, 0);
    pageLayout->addLayout(headerLayout, 0);

    m_cpuSummaryLabel = new QLabel(QStringLiteral("30-second utilization history"), m_cpuPage);
    m_cpuSummaryLabel->setStyleSheet(QStringLiteral("color:palette(mid);font-size:14px;font-weight:600;"));
    pageLayout->addWidget(m_cpuSummaryLabel, 0);

    m_coreChartScrollArea = new QScrollArea(m_cpuPage);
    m_coreChartScrollArea->setWidgetResizable(true);
    m_coreChartScrollArea->setFrameShape(QFrame::NoFrame);
    m_coreChartScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_coreChartScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_coreChartScrollArea->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
    appendTransparentBackgroundStyle(m_coreChartScrollArea);

    m_coreChartHostWidget = new QWidget(m_coreChartScrollArea);
    appendTransparentBackgroundStyle(m_coreChartHostWidget);
    m_coreChartGridLayout = new QGridLayout(m_coreChartHostWidget);
    m_coreChartGridLayout->setContentsMargins(0, 0, 0, 0);
    m_coreChartGridLayout->setHorizontalSpacing(6);
    m_coreChartGridLayout->setVerticalSpacing(6);
    m_coreChartScrollArea->setWidget(m_coreChartHostWidget);
    pageLayout->addWidget(m_coreChartScrollArea, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    m_cpuPrimaryDetailLabel = new QLabel(QStringLiteral("Sampling..."), m_cpuPage);
    m_cpuSecondaryDetailLabel = new QLabel(QStringLiteral("Loading hardware details..."), m_cpuPage);
    m_cpuPrimaryDetailLabel->setWordWrap(false);
    m_cpuSecondaryDetailLabel->setWordWrap(false);
    m_cpuPrimaryDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    m_cpuSecondaryDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    detailLayout->addWidget(m_cpuPrimaryDetailLabel, 1);
    detailLayout->addWidget(m_cpuSecondaryDetailLabel, 1);
    pageLayout->addLayout(detailLayout, 0);

    initializeCoreCharts();
    m_detailStack->addWidget(m_cpuPage);
}

void HudPerformancePanel::initializeMemoryPage()
{
    m_memoryPage = new QWidget(m_detailStack);
    appendTransparentBackgroundStyle(m_memoryPage);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_memoryPage);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(QStringLiteral("Memory"), m_memoryPage);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:palette(window-text);"));
    m_memoryCapacityLabel = new QLabel(QStringLiteral("Loading..."), m_memoryPage);
    m_memoryCapacityLabel->setStyleSheet(QStringLiteral("font-size:31px;font-weight:500;color:palette(window-text);"));
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(m_memoryCapacityLabel, 0);
    pageLayout->addLayout(headerLayout, 0);

    m_memorySummaryLabel = new QLabel(QStringLiteral("Memory utilization"), m_memoryPage);
    m_memorySummaryLabel->setStyleSheet(QStringLiteral("color:palette(mid);font-size:14px;font-weight:600;"));
    pageLayout->addWidget(m_memorySummaryLabel, 0);

    m_memoryLineSeries = new QLineSeries(m_memoryPage);
    m_memoryLineSeries->setColor(QColor(184, 99, 255));
    for (int indexValue = 0; indexValue < m_historyLength; ++indexValue)
    {
        m_memoryLineSeries->append(indexValue, 0.0);
    }

    QChart* chartPointer = new QChart();
    chartPointer->addSeries(m_memoryLineSeries);
    chartPointer->legend()->hide();
    chartPointer->setTitle(QStringLiteral("Memory usage trend"));

    m_memoryAxisX = new QValueAxis(chartPointer);
    m_memoryAxisX->setRange(0, m_historyLength);
    m_memoryAxisX->setLabelsVisible(false);
    m_memoryAxisX->setGridLineVisible(true);
    m_memoryAxisX->setGridLineColor(QColor(184, 99, 255, 35));

    m_memoryAxisY = new QValueAxis(chartPointer);
    m_memoryAxisY->setRange(0.0, 100.0);
    m_memoryAxisY->setLabelsVisible(false);
    m_memoryAxisY->setGridLineVisible(true);
    m_memoryAxisY->setGridLineColor(QColor(184, 99, 255, 35));

    chartPointer->addAxis(m_memoryAxisX, Qt::AlignBottom);
    chartPointer->addAxis(m_memoryAxisY, Qt::AlignLeft);
    m_memoryLineSeries->attachAxis(m_memoryAxisX);
    m_memoryLineSeries->attachAxis(m_memoryAxisY);

    m_memoryChartView = createNoFrameChartView(chartPointer, m_memoryPage);
    pageLayout->addWidget(m_memoryChartView, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    m_memoryPrimaryDetailLabel = new QLabel(QStringLiteral("Sampling..."), m_memoryPage);
    m_memorySecondaryDetailLabel = new QLabel(QStringLiteral("Loading hardware details..."), m_memoryPage);
    m_memoryPrimaryDetailLabel->setWordWrap(false);
    m_memorySecondaryDetailLabel->setWordWrap(false);
    m_memoryPrimaryDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    m_memorySecondaryDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    detailLayout->addWidget(m_memoryPrimaryDetailLabel, 1);
    detailLayout->addWidget(m_memorySecondaryDetailLabel, 1);
    pageLayout->addLayout(detailLayout, 0);

    m_detailStack->addWidget(m_memoryPage);
}

void HudPerformancePanel::initializeDiskPage()
{
    m_diskPage = new QWidget(m_detailStack);
    appendTransparentBackgroundStyle(m_diskPage);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_diskPage);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("Disk"), m_diskPage);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:palette(window-text);"));
    pageLayout->addWidget(titleLabel, 0);

    m_diskSummaryLabel = new QLabel(QStringLiteral("Initializing..."), m_diskPage);
    m_diskSummaryLabel->setStyleSheet(QStringLiteral("color:palette(mid);font-size:14px;font-weight:600;"));
    pageLayout->addWidget(m_diskSummaryLabel, 0);

    m_diskReadLineSeries = new QLineSeries(m_diskPage);
    m_diskReadLineSeries->setName(QStringLiteral("Read"));
    m_diskReadLineSeries->setColor(QColor(80, 170, 255));
    m_diskWriteLineSeries = new QLineSeries(m_diskPage);
    m_diskWriteLineSeries->setName(QStringLiteral("Write"));
    m_diskWriteLineSeries->setColor(QColor(255, 190, 105));
    for (int indexValue = 0; indexValue < m_historyLength; ++indexValue)
    {
        m_diskReadLineSeries->append(indexValue, 0.0);
        m_diskWriteLineSeries->append(indexValue, 0.0);
    }

    QChart* chartPointer = new QChart();
    chartPointer->addSeries(m_diskReadLineSeries);
    chartPointer->addSeries(m_diskWriteLineSeries);
    chartPointer->legend()->setVisible(true);
    chartPointer->legend()->setAlignment(Qt::AlignBottom);
    chartPointer->setTitle(QStringLiteral("Disk throughput trend"));

    m_diskAxisX = new QValueAxis(chartPointer);
    m_diskAxisX->setRange(0, m_historyLength);
    m_diskAxisX->setLabelsVisible(false);
    m_diskAxisX->setGridLineVisible(false);

    m_diskAxisY = new QValueAxis(chartPointer);
    m_diskAxisY->setRange(0.0, 1.0);
    m_diskAxisY->setLabelsVisible(false);
    m_diskAxisY->setGridLineVisible(false);

    chartPointer->addAxis(m_diskAxisX, Qt::AlignBottom);
    chartPointer->addAxis(m_diskAxisY, Qt::AlignLeft);
    m_diskReadLineSeries->attachAxis(m_diskAxisX);
    m_diskReadLineSeries->attachAxis(m_diskAxisY);
    m_diskWriteLineSeries->attachAxis(m_diskAxisX);
    m_diskWriteLineSeries->attachAxis(m_diskAxisY);

    m_diskChartView = createNoFrameChartView(chartPointer, m_diskPage);
    pageLayout->addWidget(m_diskChartView, 1);

    m_diskDetailLabel = new QLabel(QStringLiteral("Sampling..."), m_diskPage);
    m_diskDetailLabel->setWordWrap(false);
    m_diskDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    pageLayout->addWidget(m_diskDetailLabel, 0);

    m_detailStack->addWidget(m_diskPage);
}

void HudPerformancePanel::initializeNetworkPage()
{
    m_networkPage = new QWidget(m_detailStack);
    appendTransparentBackgroundStyle(m_networkPage);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_networkPage);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("Ethernet"), m_networkPage);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:palette(window-text);"));
    pageLayout->addWidget(titleLabel, 0);

    m_networkSummaryLabel = new QLabel(QStringLiteral("Initializing..."), m_networkPage);
    m_networkSummaryLabel->setStyleSheet(QStringLiteral("color:palette(mid);font-size:14px;font-weight:600;"));
    pageLayout->addWidget(m_networkSummaryLabel, 0);

    m_networkRxLineSeries = new QLineSeries(m_networkPage);
    m_networkRxLineSeries->setName(QStringLiteral("Receive"));
    m_networkRxLineSeries->setColor(QColor(92, 190, 255));
    m_networkTxLineSeries = new QLineSeries(m_networkPage);
    m_networkTxLineSeries->setName(QStringLiteral("Send"));
    m_networkTxLineSeries->setColor(QColor(153, 129, 255));
    for (int indexValue = 0; indexValue < m_historyLength; ++indexValue)
    {
        m_networkRxLineSeries->append(indexValue, 0.0);
        m_networkTxLineSeries->append(indexValue, 0.0);
    }

    QChart* chartPointer = new QChart();
    chartPointer->addSeries(m_networkRxLineSeries);
    chartPointer->addSeries(m_networkTxLineSeries);
    chartPointer->legend()->setVisible(true);
    chartPointer->legend()->setAlignment(Qt::AlignBottom);
    chartPointer->setTitle(QStringLiteral("Network throughput trend"));

    m_networkAxisX = new QValueAxis(chartPointer);
    m_networkAxisX->setRange(0, m_historyLength);
    m_networkAxisX->setLabelsVisible(false);
    m_networkAxisX->setGridLineVisible(false);

    m_networkAxisY = new QValueAxis(chartPointer);
    m_networkAxisY->setRange(0.0, 1.0);
    m_networkAxisY->setLabelsVisible(false);
    m_networkAxisY->setGridLineVisible(false);

    chartPointer->addAxis(m_networkAxisX, Qt::AlignBottom);
    chartPointer->addAxis(m_networkAxisY, Qt::AlignLeft);
    m_networkRxLineSeries->attachAxis(m_networkAxisX);
    m_networkRxLineSeries->attachAxis(m_networkAxisY);
    m_networkTxLineSeries->attachAxis(m_networkAxisX);
    m_networkTxLineSeries->attachAxis(m_networkAxisY);

    m_networkChartView = createNoFrameChartView(chartPointer, m_networkPage);
    pageLayout->addWidget(m_networkChartView, 1);

    m_networkDetailLabel = new QLabel(QStringLiteral("Sampling..."), m_networkPage);
    m_networkDetailLabel->setWordWrap(false);
    m_networkDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    pageLayout->addWidget(m_networkDetailLabel, 0);

    m_detailStack->addWidget(m_networkPage);
}

void HudPerformancePanel::initializeGpuPage()
{
    m_gpuPage = new QWidget(m_detailStack);
    appendTransparentBackgroundStyle(m_gpuPage);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_gpuPage);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(QStringLiteral("GPU"), m_gpuPage);
    titleLabel->setStyleSheet(QStringLiteral("font-size:46px;font-weight:700;color:palette(window-text);"));
    m_gpuAdapterTitleLabel = new QLabel(QStringLiteral("Loading adapter..."), m_gpuPage);
    m_gpuAdapterTitleLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_gpuAdapterTitleLabel->setStyleSheet(QStringLiteral("font-size:18px;font-weight:500;color:palette(window-text);"));
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(m_gpuAdapterTitleLabel, 0);
    pageLayout->addLayout(headerLayout, 0);

    m_gpuSummaryLabel = new QLabel(QStringLiteral("Initializing..."), m_gpuPage);
    m_gpuSummaryLabel->setStyleSheet(QStringLiteral("color:palette(mid);font-size:14px;font-weight:600;"));
    pageLayout->addWidget(m_gpuSummaryLabel, 0);

    m_gpuEngineHostWidget = new QWidget(m_gpuPage);
    appendTransparentBackgroundStyle(m_gpuEngineHostWidget);
    m_gpuEngineGridLayout = new QGridLayout(m_gpuEngineHostWidget);
    m_gpuEngineGridLayout->setContentsMargins(0, 0, 0, 0);
    m_gpuEngineGridLayout->setHorizontalSpacing(6);
    m_gpuEngineGridLayout->setVerticalSpacing(6);
    m_gpuEngineCharts.clear();

    auto addGpuEngineChart =
        [this](const QString& engineKeyText, const QString& displayNameText, const QColor& lineColor, const int rowIndex, const int columnIndex)
        {
            QWidget* cellWidget = new QWidget(m_gpuEngineHostWidget);
            appendTransparentBackgroundStyle(cellWidget);
            QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
            cellLayout->setContentsMargins(0, 0, 0, 0);
            cellLayout->setSpacing(2);

            QLabel* cellTitle = new QLabel(displayNameText, cellWidget);
            cellTitle->setStyleSheet(QStringLiteral("font-size:14px;font-weight:600;color:palette(window-text);"));
            cellLayout->addWidget(cellTitle, 0);

            QLineSeries* lineSeries = new QLineSeries(cellWidget);
            lineSeries->setColor(lineColor);
            for (int historyIndex = 0; historyIndex < m_historyLength; ++historyIndex)
            {
                lineSeries->append(historyIndex, 0.0);
            }

            QChart* chartPointer = new QChart();
            chartPointer->addSeries(lineSeries);
            chartPointer->legend()->hide();

            QValueAxis* axisX = new QValueAxis(chartPointer);
            axisX->setRange(0, m_historyLength);
            axisX->setLabelsVisible(false);
            axisX->setGridLineVisible(true);
            axisX->setGridLineColor(QColor(lineColor.red(), lineColor.green(), lineColor.blue(), 40));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            axisY->setRange(0.0, 100.0);
            axisY->setLabelsVisible(false);
            axisY->setGridLineVisible(true);
            axisY->setGridLineColor(QColor(lineColor.red(), lineColor.green(), lineColor.blue(), 40));

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            lineSeries->attachAxis(axisX);
            lineSeries->attachAxis(axisY);

            QChartView* chartView = createNoFrameChartView(chartPointer, cellWidget);
            cellLayout->addWidget(chartView, 1);
            m_gpuEngineGridLayout->addWidget(cellWidget, rowIndex, columnIndex);

            GpuEngineChartEntry chartEntry;
            chartEntry.engineKeyText = engineKeyText;
            chartEntry.displayNameText = displayNameText;
            chartEntry.titleLabel = cellTitle;
            chartEntry.chartView = chartView;
            chartEntry.lineSeries = lineSeries;
            chartEntry.axisX = axisX;
            chartEntry.axisY = axisY;
            m_gpuEngineCharts.push_back(chartEntry);
        };

    addGpuEngineChart(QStringLiteral("3d"), QStringLiteral("3D"), QColor(105, 173, 255), 0, 0);
    addGpuEngineChart(QStringLiteral("copy"), QStringLiteral("Copy"), QColor(110, 196, 247), 0, 1);
    addGpuEngineChart(QStringLiteral("video_encode"), QStringLiteral("Video Encode"), QColor(125, 184, 255), 1, 0);
    addGpuEngineChart(QStringLiteral("video_decode"), QStringLiteral("Video Decode"), QColor(137, 178, 255), 1, 1);
    pageLayout->addWidget(m_gpuEngineHostWidget, 1);

    m_gpuDedicatedMemoryLineSeries = new QLineSeries(m_gpuPage);
    m_gpuDedicatedMemoryLineSeries->setColor(QColor(92, 167, 255));
    m_gpuSharedMemoryLineSeries = new QLineSeries(m_gpuPage);
    m_gpuSharedMemoryLineSeries->setColor(QColor(113, 185, 255));
    for (int indexValue = 0; indexValue < m_historyLength; ++indexValue)
    {
        m_gpuDedicatedMemoryLineSeries->append(indexValue, 0.0);
        m_gpuSharedMemoryLineSeries->append(indexValue, 0.0);
    }

    auto createGpuMemoryChart =
        [this](
            const QString& titleText,
            QLineSeries* lineSeries,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut)
        {
            QChart* chartPointer = new QChart();
            chartPointer->addSeries(lineSeries);
            chartPointer->legend()->hide();
            chartPointer->setTitle(titleText);

            QValueAxis* axisX = new QValueAxis(chartPointer);
            axisX->setRange(0, m_historyLength);
            axisX->setLabelsVisible(false);
            axisX->setGridLineVisible(true);
            axisX->setGridLineColor(QColor(92, 167, 255, 35));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            axisY->setRange(0.0, 1.0);
            axisY->setLabelsVisible(false);
            axisY->setGridLineVisible(true);
            axisY->setGridLineColor(QColor(92, 167, 255, 35));

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            lineSeries->attachAxis(axisX);
            lineSeries->attachAxis(axisY);

            if (axisXOut != nullptr)
            {
                *axisXOut = axisX;
            }
            if (axisYOut != nullptr)
            {
                *axisYOut = axisY;
            }
            if (chartViewOut != nullptr)
            {
                *chartViewOut = createNoFrameChartView(chartPointer, m_gpuPage);
            }
        };

    createGpuMemoryChart(
        QStringLiteral("Dedicated GPU memory"),
        m_gpuDedicatedMemoryLineSeries,
        &m_gpuDedicatedMemoryAxisX,
        &m_gpuDedicatedMemoryAxisY,
        &m_gpuDedicatedMemoryChartView);
    createGpuMemoryChart(
        QStringLiteral("Shared GPU memory"),
        m_gpuSharedMemoryLineSeries,
        &m_gpuSharedMemoryAxisX,
        &m_gpuSharedMemoryAxisY,
        &m_gpuSharedMemoryChartView);

    pageLayout->addWidget(m_gpuDedicatedMemoryChartView, 0);
    pageLayout->addWidget(m_gpuSharedMemoryChartView, 0);

    m_gpuDetailLabel = new QLabel(QStringLiteral("Sampling..."), m_gpuPage);
    m_gpuDetailLabel->setWordWrap(false);
    m_gpuDetailLabel->setStyleSheet(QStringLiteral("font-size:14px;color:palette(window-text);"));
    pageLayout->addWidget(m_gpuDetailLabel, 0);

    m_detailStack->addWidget(m_gpuPage);
}

void HudPerformancePanel::initializeCoreCharts()
{
    const DWORD logicalProcessorCount = std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const int coreCount = static_cast<int>(logicalProcessorCount);
    const int columnCount = std::max(1, static_cast<int>(std::ceil(std::sqrt(static_cast<double>(coreCount)))));
    const int rowCount = std::max(
        1,
        static_cast<int>(std::ceil(static_cast<double>(coreCount) / static_cast<double>(columnCount))));
    m_cpuCoreGridColumnCount = columnCount;
    m_cpuCoreGridRowCount = rowCount;

    m_coreChartEntries.clear();
    m_coreChartEntries.reserve(coreCount);

    for (int coreIndex = 0; coreIndex < coreCount; ++coreIndex)
    {
        CoreChartEntry chartEntry;
        chartEntry.containerWidget = new QWidget(m_coreChartHostWidget);
        appendTransparentBackgroundStyle(chartEntry.containerWidget);
        QVBoxLayout* containerLayout = new QVBoxLayout(chartEntry.containerWidget);
        containerLayout->setContentsMargins(4, 4, 4, 4);
        containerLayout->setSpacing(2);

        chartEntry.titleLabel = new QLabel(
            QStringLiteral("CPU %1").arg(coreIndex),
            chartEntry.containerWidget);
        chartEntry.titleLabel->setStyleSheet(QStringLiteral("color:palette(mid);font-weight:600;"));
        chartEntry.titleLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        chartEntry.titleLabel->setMinimumWidth(128);
        containerLayout->addWidget(chartEntry.titleLabel, 0);

        auto* sparklineWidget = new CpuCoreSparklineWidget(chartEntry.containerWidget);
        chartEntry.chartWidget = sparklineWidget;
        containerLayout->addWidget(chartEntry.chartWidget, 1);

        const int rowIndex = coreIndex / columnCount;
        const int columnIndex = coreIndex % columnCount;
        m_coreChartGridLayout->addWidget(chartEntry.containerWidget, rowIndex, columnIndex);
        m_coreChartEntries.push_back(chartEntry);
    }

    adjustChartHeights();
}

void HudPerformancePanel::syncSidebarSelection(const int selectedRowIndex)
{
    if (m_detailStack == nullptr)
    {
        return;
    }

    const int pageCount = m_detailStack->count();
    if (pageCount <= 0)
    {
        return;
    }

    const int boundedIndex = qBound(0, selectedRowIndex, pageCount - 1);
    m_detailStack->setCurrentIndex(boundedIndex);

    if (m_cpuNavCard != nullptr) m_cpuNavCard->setSelectedState(boundedIndex == 0);
    if (m_memoryNavCard != nullptr) m_memoryNavCard->setSelectedState(boundedIndex == 1);
    if (m_diskNavCard != nullptr) m_diskNavCard->setSelectedState(boundedIndex == 2);
    if (m_networkNavCard != nullptr) m_networkNavCard->setSelectedState(boundedIndex == 3);
    if (m_gpuNavCard != nullptr) m_gpuNavCard->setSelectedState(boundedIndex == 4);

    adjustChartHeights();
    QTimer::singleShot(0, this, [this]() { adjustChartHeights(); });
    QTimer::singleShot(80, this, [this]() { adjustChartHeights(); });
}

void HudPerformancePanel::adjustChartHeights()
{
    if (m_cpuPage != nullptr
        && m_coreChartHostWidget != nullptr
        && m_coreChartGridLayout != nullptr
        && !m_coreChartEntries.empty())
    {
        auto applyFixedHeightIfChanged =
            [](QWidget* widgetPointer, const int heightValue)
            {
                if (widgetPointer == nullptr || heightValue <= 0)
                {
                    return;
                }
                if (widgetPointer->minimumHeight() == heightValue
                    && widgetPointer->maximumHeight() == heightValue)
                {
                    return;
                }
                widgetPointer->setMinimumHeight(heightValue);
                widgetPointer->setMaximumHeight(heightValue);
            };

        int chartViewportHeight = 0;
        if (m_coreChartScrollArea != nullptr && m_coreChartScrollArea->viewport() != nullptr)
        {
            chartViewportHeight = m_coreChartScrollArea->viewport()->height();
        }
        if (chartViewportHeight <= 0 && m_coreChartScrollArea != nullptr)
        {
            chartViewportHeight = m_coreChartScrollArea->height();
        }
        if (chartViewportHeight < 120)
        {
            int cpuReferenceHeight = 0;
            if (m_detailStack != nullptr)
            {
                cpuReferenceHeight = m_detailStack->contentsRect().height();
            }
            if (cpuReferenceHeight <= 0)
            {
                cpuReferenceHeight = m_cpuPage->contentsRect().height();
            }
            chartViewportHeight = std::max(120, cpuReferenceHeight / 2);
        }

        const int availableChartAreaHeight = std::max(1, chartViewportHeight);
        const int gridRows = std::max(1, m_cpuCoreGridRowCount);
        const int gridSpacing = std::max(0, m_coreChartGridLayout->verticalSpacing());
        const int cellHeight = std::max(
            18,
            (availableChartAreaHeight - gridSpacing * (gridRows - 1)) / gridRows);

        for (CoreChartEntry& chartEntry : m_coreChartEntries)
        {
            if (chartEntry.containerWidget != nullptr)
            {
                applyFixedHeightIfChanged(chartEntry.containerWidget, cellHeight);
            }
            if (chartEntry.chartWidget != nullptr)
            {
                applyFixedHeightIfChanged(chartEntry.chartWidget, std::max(10, cellHeight - 12));
            }
        }

        const int hostHeight = gridRows * cellHeight + gridSpacing * (gridRows - 1);
        applyFixedHeightIfChanged(m_coreChartHostWidget, hostHeight);
        if (m_coreChartScrollArea != nullptr)
        {
            m_coreChartScrollArea->setMinimumHeight(0);
            m_coreChartScrollArea->setMaximumHeight(QWIDGETSIZE_MAX);
        }
    }

    auto adjustMainChartHeight =
        [](
            QWidget* pageWidget,
            QChartView* chartView,
            const double ratioValue,
            const int minHeightValue,
            const int reserveHeightValue)
        {
            if (pageWidget == nullptr || chartView == nullptr)
            {
                return;
            }
            const int pageHeight = pageWidget->contentsRect().height();
            const int maxAllowedHeight = std::max(minHeightValue, pageHeight - reserveHeightValue);
            const int expectedHeight = static_cast<int>(std::round(static_cast<double>(pageHeight) * ratioValue));
            const int finalHeight = qBound(minHeightValue, expectedHeight, maxAllowedHeight);
            chartView->setMinimumHeight(finalHeight);
            chartView->setMaximumHeight(finalHeight);
        };

    adjustMainChartHeight(m_memoryPage, m_memoryChartView, 0.36, 56, 116);
    adjustMainChartHeight(m_diskPage, m_diskChartView, 0.40, 58, 120);
    adjustMainChartHeight(m_networkPage, m_networkChartView, 0.40, 58, 120);

    if (m_gpuPage != nullptr)
    {
        auto applyMaxHeightIfChanged =
            [](QWidget* widgetPointer, const int maxHeightValue)
            {
                if (widgetPointer == nullptr || maxHeightValue <= 0)
                {
                    return;
                }
                if (widgetPointer->minimumHeight() == 0
                    && widgetPointer->maximumHeight() == maxHeightValue)
                {
                    return;
                }
                widgetPointer->setMinimumHeight(0);
                widgetPointer->setMaximumHeight(maxHeightValue);
            };

        int gpuReferenceHeight = 0;
        if (m_detailStack != nullptr)
        {
            gpuReferenceHeight = m_detailStack->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = m_gpuPage->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = 320;
        }

        const int titleHeight = std::max(
            m_gpuAdapterTitleLabel != nullptr ? m_gpuAdapterTitleLabel->sizeHint().height() : 0,
            44);
        const int summaryHeight = m_gpuSummaryLabel != nullptr
            ? m_gpuSummaryLabel->sizeHint().height()
            : 20;
        const int detailHeight = m_gpuDetailLabel != nullptr
            ? m_gpuDetailLabel->sizeHint().height()
            : 22;
        const int reservedHeight = titleHeight + summaryHeight + detailHeight + 38;
        const int availableHeight = std::max(120, gpuReferenceHeight - reservedHeight);
        const int engineAreaHeight = static_cast<int>(std::round(static_cast<double>(availableHeight) * 0.52));
        const int memoryAreaEachHeight = std::max(34, (availableHeight - engineAreaHeight - 8) / 2);

        if (m_gpuEngineHostWidget != nullptr && m_gpuEngineGridLayout != nullptr)
        {
            const int rowSpacing = std::max(0, m_gpuEngineGridLayout->verticalSpacing());
            const int cellHeight = std::max(30, (engineAreaHeight - rowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : m_gpuEngineCharts)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(18, cellHeight - 10));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(14);
                    chartEntry.titleLabel->setMaximumHeight(18);
                }
            }
            applyMaxHeightIfChanged(m_gpuEngineHostWidget, engineAreaHeight);
        }

        if (m_gpuDedicatedMemoryChartView != nullptr)
        {
            applyMaxHeightIfChanged(m_gpuDedicatedMemoryChartView, memoryAreaEachHeight);
        }
        if (m_gpuSharedMemoryChartView != nullptr)
        {
            applyMaxHeightIfChanged(m_gpuSharedMemoryChartView, memoryAreaEachHeight);
        }
    }
}

void HudPerformancePanel::initializePerformanceCounters()
{
    if (m_cpuPerfQueryHandle != nullptr)
    {
        return;
    }

    PDH_HQUERY queryHandle = nullptr;
    const PDH_STATUS queryStatus = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
    if (queryStatus != ERROR_SUCCESS || queryHandle == nullptr)
    {
        return;
    }

    m_cpuPerfQueryHandle = queryHandle;
    m_coreCounterHandles.clear();
    m_coreCounterHandles.reserve(m_coreChartEntries.size());

    for (int coreIndex = 0; coreIndex < static_cast<int>(m_coreChartEntries.size()); ++coreIndex)
    {
        const QString counterPath = QStringLiteral("\\Processor(%1)\\% Processor Time").arg(coreIndex);
        PDH_HCOUNTER counterHandle = nullptr;
        const PDH_STATUS addStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            reinterpret_cast<LPCWSTR>(counterPath.utf16()),
            0,
            &counterHandle);
        if (addStatus != ERROR_SUCCESS || counterHandle == nullptr)
        {
            m_coreCounterHandles.push_back(nullptr);
            continue;
        }
        m_coreCounterHandles.push_back(counterHandle);
    }

    ::PdhCollectQueryData(queryHandle);
}

void HudPerformancePanel::refreshAllViews()
{
    requestLiveRefresh();
}

void HudPerformancePanel::requestLiveRefresh()
{
    if (m_liveSampleInProgress || m_liveSampleWatcher == nullptr)
    {
        return;
    }

    m_liveSampleInProgress = true;
    m_liveSampleWatcher->setFuture(QtConcurrent::run([this]()
    {
        return collectLiveSampleResult();
    }));
}

HudPerformancePanel::LiveSampleResult HudPerformancePanel::collectLiveSampleResult()
{
    QMutexLocker locker(&m_liveSampleMutex);

    LiveSampleResult result;
    result.perCoreOk = samplePerCoreUsage(&result.coreUsageList, &result.totalCpuUsage);
    if (!result.perCoreOk)
    {
        result.coreUsageList.assign(m_coreChartEntries.size(), 0.0);
        result.totalCpuUsage = 0.0;
    }

    result.memoryOk = sampleMemoryUsage(&result.memoryUsagePercent);
    if (!result.memoryOk)
    {
        result.memoryUsagePercent = 0.0;
    }
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
    {
        result.totalPhysBytes = static_cast<std::uint64_t>(memoryStatus.ullTotalPhys);
        result.availPhysBytes = static_cast<std::uint64_t>(memoryStatus.ullAvailPhys);
    }

    result.diskOk = sampleDiskRate(&result.diskReadBytesPerSec, &result.diskWriteBytesPerSec);
    if (!result.diskOk)
    {
        result.diskReadBytesPerSec = 0.0;
        result.diskWriteBytesPerSec = 0.0;
    }

    result.networkOk = sampleNetworkRate(&result.networkRxBytesPerSec, &result.networkTxBytesPerSec);
    if (!result.networkOk)
    {
        result.networkRxBytesPerSec = 0.0;
        result.networkTxBytesPerSec = 0.0;
    }

    m_gpuMetricMemoryValid = false; // 未进行本帧DXGI查询时不能沿用上帧成功状态。
    result.gpuOk = sampleGpuUsage(&result.gpuUsagePercent);
    result.gpuMemoryOk = m_gpuMetricMemoryValid;
    if (!result.gpuOk)
    {
        result.gpuUsagePercent = 0.0;
    }

    result.powerInfoOk = sampleCpuPowerInfo(&result.powerInfoList);
    result.systemPerfOk = sampleSystemPerformanceSnapshot(&result.systemPerfSnapshot);

    result.primaryNetworkAdapterName = m_primaryNetworkAdapterName;
    result.primaryNetworkLinkBitsPerSecond = m_primaryNetworkLinkBitsPerSecond;
    result.gpuUsage3DPercent = m_gpuUsage3DPercent;
    result.gpuUsageCopyPercent = m_gpuUsageCopyPercent;
    result.gpuUsageVideoEncodePercent = m_gpuUsageVideoEncodePercent;
    result.gpuUsageVideoDecodePercent = m_gpuUsageVideoDecodePercent;
    result.gpuDedicatedUsedGiB = m_gpuDedicatedUsedGiB;
    result.gpuDedicatedBudgetGiB = m_gpuDedicatedBudgetGiB;
    result.gpuSharedUsedGiB = m_gpuSharedUsedGiB;
    result.gpuSharedBudgetGiB = m_gpuSharedBudgetGiB;
    result.systemVolumeText = m_systemVolumeText;
    result.systemVolumeTotalBytes = m_systemVolumeTotalBytes;
    result.systemVolumeFreeBytes = m_systemVolumeFreeBytes;
    result.sampleTimeMs = QDateTime::currentMSecsSinceEpoch(); // 在后台读取结束时记录真实采样帧。
    return result;
}

void HudPerformancePanel::applyLiveSampleResult(const LiveSampleResult& liveSampleResult)
{
    {
        QMutexLocker locker(&m_liveSampleMutex);
        m_primaryNetworkAdapterName = liveSampleResult.primaryNetworkAdapterName;
        m_primaryNetworkLinkBitsPerSecond = liveSampleResult.primaryNetworkLinkBitsPerSecond;
        m_gpuUsage3DPercent = liveSampleResult.gpuUsage3DPercent;
        m_gpuUsageCopyPercent = liveSampleResult.gpuUsageCopyPercent;
        m_gpuUsageVideoEncodePercent = liveSampleResult.gpuUsageVideoEncodePercent;
        m_gpuUsageVideoDecodePercent = liveSampleResult.gpuUsageVideoDecodePercent;
        m_gpuDedicatedUsedGiB = liveSampleResult.gpuDedicatedUsedGiB;
        m_gpuDedicatedBudgetGiB = liveSampleResult.gpuDedicatedBudgetGiB;
        m_gpuSharedUsedGiB = liveSampleResult.gpuSharedUsedGiB;
        m_gpuSharedBudgetGiB = liveSampleResult.gpuSharedBudgetGiB;
        m_systemVolumeText = liveSampleResult.systemVolumeText;
        m_systemVolumeTotalBytes = liveSampleResult.systemVolumeTotalBytes;
        m_systemVolumeFreeBytes = liveSampleResult.systemVolumeFreeBytes;
        m_lastTotalPhysBytes = liveSampleResult.totalPhysBytes;
        m_lastAvailPhysBytes = liveSampleResult.availPhysBytes;
    }

    m_metricSampleTimeMs = liveSampleResult.sampleTimeMs; // 保留后台采样时刻，绝不换成UI送达时刻。
    m_metricMemoryValid = liveSampleResult.memoryOk;
    m_metricDiskValid = liveSampleResult.diskOk;
    m_metricNetworkValid = liveSampleResult.networkOk;
    m_metricGpuValid = liveSampleResult.gpuOk;
    m_metricGpuMemoryValid = liveSampleResult.gpuMemoryOk;
    ++m_sampleCounter;
    updateView(
        liveSampleResult.coreUsageList,
        liveSampleResult.memoryUsagePercent,
        liveSampleResult.diskReadBytesPerSec,
        liveSampleResult.diskWriteBytesPerSec,
        liveSampleResult.networkRxBytesPerSec,
        liveSampleResult.networkTxBytesPerSec,
        liveSampleResult.gpuUsagePercent);
    updateTaskManagerDetailLabels(
        liveSampleResult.coreUsageList,
        liveSampleResult.powerInfoList,
        liveSampleResult.memoryUsagePercent,
        liveSampleResult.diskReadBytesPerSec,
        liveSampleResult.diskWriteBytesPerSec,
        liveSampleResult.networkRxBytesPerSec,
        liveSampleResult.networkTxBytesPerSec,
        liveSampleResult.gpuUsagePercent,
        &liveSampleResult.systemPerfSnapshot,
        liveSampleResult.systemPerfOk);

    if ((m_sampleCounter % 5) == 1)
    {
        requestAsyncSensorRefresh();
    }
    if ((m_sampleCounter % 60) == 1)
    {
        requestAsyncStaticInfoRefresh();
    }
}

bool HudPerformancePanel::samplePerCoreUsage(
    std::vector<double>* coreUsageOut,
    double* totalUsageOut)
{
    if (coreUsageOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }
    coreUsageOut->clear();
    *totalUsageOut = 0.0; // 采集早退也不能保留上次聚合值。
    if (m_cpuPerfQueryHandle == nullptr)
    {
        initializePerformanceCounters();
    }
    if (m_cpuPerfQueryHandle == nullptr)
    {
        return false;
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle);
    if (::PdhCollectQueryData(queryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    coreUsageOut->clear();
    coreUsageOut->reserve(m_coreCounterHandles.size());
    double usageSum = 0.0;
    int validCount = 0;

    for (void* counterHandleVoid : m_coreCounterHandles)
    {
        if (counterHandleVoid == nullptr)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        PDH_FMT_COUNTERVALUE formattedValue{};
        const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &formattedValue);
        if (readStatus != ERROR_SUCCESS
            || (formattedValue.CStatus != PDH_CSTATUS_VALID_DATA
                && formattedValue.CStatus != PDH_CSTATUS_NEW_DATA)
            || !std::isfinite(formattedValue.doubleValue))
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        const double usageValue = qBound(0.0, formattedValue.doubleValue, 100.0);
        coreUsageOut->push_back(usageValue);
        usageSum += usageValue;
        ++validCount;
    }

    *totalUsageOut = validCount > 0 ? (usageSum / static_cast<double>(validCount)) : 0.0;
    return validCount > 0;
}

bool HudPerformancePanel::sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut)
{
    if (powerInfoOut == nullptr)
    {
        return false;
    }

    const ULONG logicalProcessorCount = std::max<ULONG>(
        1,
        static_cast<ULONG>(m_coreChartEntries.size()));
    struct KsProcessorPowerInformation
    {
        ULONG Number;
        ULONG MaxMhz;
        ULONG CurrentMhz;
        ULONG MhzLimit;
        ULONG MaxIdleState;
        ULONG CurrentIdleState;
    };
    std::vector<KsProcessorPowerInformation> nativeInfoList(logicalProcessorCount);

    const NTSTATUS ntStatus = ::CallNtPowerInformation(
        ProcessorInformation,
        nullptr,
        0,
        nativeInfoList.data(),
        static_cast<ULONG>(nativeInfoList.size() * sizeof(KsProcessorPowerInformation)));
    if (ntStatus != 0)
    {
        return false;
    }

    powerInfoOut->clear();
    powerInfoOut->reserve(nativeInfoList.size());
    for (const KsProcessorPowerInformation& nativeInfo : nativeInfoList)
    {
        CpuPowerSnapshot snapshot;
        snapshot.coreIndex = nativeInfo.Number;
        snapshot.currentMhz = nativeInfo.CurrentMhz;
        snapshot.maxMhz = nativeInfo.MaxMhz;
        snapshot.limitMhz = nativeInfo.MhzLimit;
        powerInfoOut->push_back(snapshot);
    }
    return true;
}

bool HudPerformancePanel::sampleMemoryUsage(double* memoryUsagePercentOut)
{
    if (memoryUsagePercentOut == nullptr)
    {
        return false;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE)
    {
        *memoryUsagePercentOut = 0.0;
        return false;
    }

    *memoryUsagePercentOut = static_cast<double>(memoryStatus.dwMemoryLoad);
    return true;
}

bool HudPerformancePanel::sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    if (m_diskPerfQueryHandle == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER readCounterHandle = nullptr;
        PDH_HCOUNTER writeCounterHandle = nullptr;
        const PDH_STATUS addReadStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
            0,
            &readCounterHandle);
        const PDH_STATUS addWriteStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
            0,
            &writeCounterHandle);
        if (addReadStatus != ERROR_SUCCESS || addWriteStatus != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        m_diskPerfQueryHandle = queryHandle;
        m_diskReadCounterHandle = readCounterHandle;
        m_diskWriteCounterHandle = writeCounterHandle;
        ::PdhCollectQueryData(queryHandle);
        return false;
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle);
    if (::PdhCollectQueryData(queryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    PDH_FMT_COUNTERVALUE readValue{};
    PDH_FMT_COUNTERVALUE writeValue{};
    const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(m_diskReadCounterHandle),
        PDH_FMT_DOUBLE,
        nullptr,
        &readValue);
    const PDH_STATUS writeStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(m_diskWriteCounterHandle),
        PDH_FMT_DOUBLE,
        nullptr,
        &writeValue);
    if (readStatus != ERROR_SUCCESS || writeStatus != ERROR_SUCCESS)
    {
        return false;
    }

    *readBytesPerSecOut = std::max(0.0, readValue.doubleValue);
    *writeBytesPerSecOut = std::max(0.0, writeValue.doubleValue);
    return true;
}

bool HudPerformancePanel::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    ULONG tableSize = 0;
    if (::GetIfTable(nullptr, &tableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER || tableSize == 0)
    {
        return false;
    }

    std::vector<unsigned char> tableBuffer(tableSize);
    auto* tablePointer = reinterpret_cast<MIB_IFTABLE*>(tableBuffer.data());
    if (::GetIfTable(tablePointer, &tableSize, FALSE) != NO_ERROR)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    std::uint64_t primaryTrafficBytes = 0;
    QString primaryAdapterName;
    std::uint64_t primaryLinkBitsPerSecond = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->dwNumEntries; ++rowIndex)
    {
        const MIB_IFROW& rowValue = tablePointer->table[rowIndex];
        if (rowValue.dwOperStatus != IF_OPER_STATUS_OPERATIONAL
            || rowValue.dwType == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        totalRxBytes += static_cast<std::uint64_t>(rowValue.dwInOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.dwOutOctets);

        const std::uint64_t rowTrafficBytes =
            static_cast<std::uint64_t>(rowValue.dwInOctets)
            + static_cast<std::uint64_t>(rowValue.dwOutOctets);
        if (rowTrafficBytes >= primaryTrafficBytes)
        {
            primaryTrafficBytes = rowTrafficBytes;
            primaryAdapterName = QString::fromLocal8Bit(
                reinterpret_cast<const char*>(rowValue.bDescr),
                static_cast<int>(rowValue.dwDescrLen)).trimmed();
            primaryLinkBitsPerSecond = static_cast<std::uint64_t>(rowValue.dwSpeed);
        }
    }

    m_primaryNetworkAdapterName = primaryAdapterName;
    m_primaryNetworkLinkBitsPerSecond = primaryLinkBitsPerSecond;

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (m_lastNetworkSampleMs <= 0)
    {
        m_lastNetworkSampleMs = nowMs;
        m_lastNetworkRxBytes = totalRxBytes;
        m_lastNetworkTxBytes = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 elapsedMs = nowMs - m_lastNetworkSampleMs;
    if (elapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t deltaRx =
        totalRxBytes >= m_lastNetworkRxBytes ? (totalRxBytes - m_lastNetworkRxBytes) : 0;
    const std::uint64_t deltaTx =
        totalTxBytes >= m_lastNetworkTxBytes ? (totalTxBytes - m_lastNetworkTxBytes) : 0;

    m_lastNetworkSampleMs = nowMs;
    m_lastNetworkRxBytes = totalRxBytes;
    m_lastNetworkTxBytes = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(deltaRx) * 1000.0 / static_cast<double>(elapsedMs);
    *txBytesPerSecOut = static_cast<double>(deltaTx) * 1000.0 / static_cast<double>(elapsedMs);
    return true;
}

bool HudPerformancePanel::sampleGpuUsage(double* gpuUsagePercentOut)
{
    if (gpuUsagePercentOut == nullptr)
    {
        return false;
    }

    if (m_gpuPerfQueryHandle == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER counterHandle = nullptr;
        const PDH_STATUS addStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\GPU Engine(*)\\Utilization Percentage",
            0,
            &counterHandle);
        if (addStatus != ERROR_SUCCESS || counterHandle == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        m_gpuPerfQueryHandle = queryHandle;
        m_gpuCounterHandle = counterHandle;
        ::PdhCollectQueryData(queryHandle);
        *gpuUsagePercentOut = 0.0;
        return true;
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_gpuPerfQueryHandle);
    if (::PdhCollectQueryData(queryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_gpuCounterHandle),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        nullptr);
    if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
    {
        m_gpuUsage3DPercent = 0.0;
        m_gpuUsageCopyPercent = 0.0;
        m_gpuUsageVideoEncodePercent = 0.0;
        m_gpuUsageVideoDecodePercent = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    std::vector<unsigned char> rawBuffer(bufferSize);
    auto* itemPtr = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
    queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_gpuCounterHandle),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        itemPtr);
    if (queryStatus != ERROR_SUCCESS)
    {
        m_gpuUsage3DPercent = 0.0;
        m_gpuUsageCopyPercent = 0.0;
        m_gpuUsageVideoEncodePercent = 0.0;
        m_gpuUsageVideoDecodePercent = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    double usage3DPercent = 0.0;
    double usageCopyPercent = 0.0;
    double usageVideoEncodePercent = 0.0;
    double usageVideoDecodePercent = 0.0;
    double peakUsage = 0.0;
    for (DWORD indexValue = 0; indexValue < itemCount; ++indexValue)
    {
        const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPtr[indexValue];
        if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
        {
            continue;
        }

        const double engineUsagePercent = qBound(0.0, itemValue.FmtValue.doubleValue, 100.0);
        const QString engineNameText = QString::fromWCharArray(
            itemValue.szName != nullptr ? itemValue.szName : L"");
        const QString engineKeyText = resolveGpuEngineKeyFromCounter(engineNameText);
        if (engineKeyText == QStringLiteral("3d"))
        {
            usage3DPercent = std::max(usage3DPercent, engineUsagePercent);
        }
        else if (engineKeyText == QStringLiteral("copy"))
        {
            usageCopyPercent = std::max(usageCopyPercent, engineUsagePercent);
        }
        else if (engineKeyText == QStringLiteral("video_encode"))
        {
            usageVideoEncodePercent = std::max(usageVideoEncodePercent, engineUsagePercent);
        }
        else if (engineKeyText == QStringLiteral("video_decode"))
        {
            usageVideoDecodePercent = std::max(usageVideoDecodePercent, engineUsagePercent);
        }

        peakUsage = std::max(peakUsage, engineUsagePercent);
    }

    m_gpuUsage3DPercent = usage3DPercent;
    m_gpuUsageCopyPercent = usageCopyPercent;
    m_gpuUsageVideoEncodePercent = usageVideoEncodePercent;
    m_gpuUsageVideoDecodePercent = usageVideoDecodePercent;
    *gpuUsagePercentOut = qBound(0.0, peakUsage, 100.0);
    sampleGpuMemoryInfoByDxgi();
    return true;
}

bool HudPerformancePanel::sampleGpuMemoryInfoByDxgi()
{
    m_gpuMetricMemoryValid = false; // 所有早退路径都明确失效，避免旧显存数据进入新历史帧。
    IDXGIFactory6* factoryPointer = nullptr;
    const HRESULT createFactoryStatus = ::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer));
    if (FAILED(createFactoryStatus) || factoryPointer == nullptr)
    {
        return false;
    }

    bool querySuccess = false;
    for (UINT adapterIndex = 0;; ++adapterIndex)
    {
        IDXGIAdapter1* adapterPointer = nullptr;
        const HRESULT enumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
        if (enumStatus == DXGI_ERROR_NOT_FOUND)
        {
            break;
        }
        if (FAILED(enumStatus) || adapterPointer == nullptr)
        {
            continue;
        }

        DXGI_ADAPTER_DESC1 adapterDesc{};
        adapterPointer->GetDesc1(&adapterDesc);
        if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0)
        {
            adapterPointer->Release();
            continue;
        }

        IDXGIAdapter3* adapter3Pointer = nullptr;
        const HRESULT queryInterfaceStatus = adapterPointer->QueryInterface(IID_PPV_ARGS(&adapter3Pointer));
        if (SUCCEEDED(queryInterfaceStatus) && adapter3Pointer != nullptr)
        {
            DXGI_QUERY_VIDEO_MEMORY_INFO localMemoryInfo{};
            DXGI_QUERY_VIDEO_MEMORY_INFO nonLocalMemoryInfo{};
            const HRESULT localStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                &localMemoryInfo);
            const HRESULT nonLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                &nonLocalMemoryInfo);
            if (SUCCEEDED(localStatus) && SUCCEEDED(nonLocalStatus))
            {
                m_gpuDedicatedUsedGiB = static_cast<double>(localMemoryInfo.CurrentUsage) / kOneGiBInBytes;
                m_gpuDedicatedBudgetGiB = static_cast<double>(localMemoryInfo.Budget) / kOneGiBInBytes;
                m_gpuSharedUsedGiB = static_cast<double>(nonLocalMemoryInfo.CurrentUsage) / kOneGiBInBytes;
                m_gpuSharedBudgetGiB = static_cast<double>(nonLocalMemoryInfo.Budget) / kOneGiBInBytes;

                if (m_gpuSharedBudgetGiB <= 0.0)
                {
                    MEMORYSTATUSEX memoryStatus{};
                    memoryStatus.dwLength = sizeof(memoryStatus);
                    if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
                    {
                        const double totalMemoryGiB =
                            static_cast<double>(memoryStatus.ullTotalPhys) / kOneGiBInBytes;
                        m_gpuSharedBudgetGiB = std::max(0.5, totalMemoryGiB * 0.5);
                    }
                }

                const QString adapterNameText = QString::fromWCharArray(adapterDesc.Description).trimmed();
                if (!adapterNameText.isEmpty())
                {
                    m_gpuAdapterNameText = adapterNameText;
                }
                querySuccess = true;
            }
            adapter3Pointer->Release();
        }

        adapterPointer->Release();
        if (querySuccess)
        {
            break;
        }
    }

    factoryPointer->Release();
    m_gpuMetricMemoryValid = querySuccess;
    return querySuccess;
}

bool HudPerformancePanel::sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const
{
    if (snapshotOut == nullptr)
    {
        return false;
    }

    PERFORMANCE_INFORMATION perfInfo{};
    perfInfo.cb = sizeof(perfInfo);
    if (::GetPerformanceInfo(&perfInfo, sizeof(perfInfo)) == FALSE)
    {
        return false;
    }

    const std::uint64_t pageSizeBytes = static_cast<std::uint64_t>(perfInfo.PageSize);
    snapshotOut->processCount = static_cast<std::uint32_t>(perfInfo.ProcessCount);
    snapshotOut->threadCount = static_cast<std::uint32_t>(perfInfo.ThreadCount);
    snapshotOut->handleCount = static_cast<std::uint32_t>(perfInfo.HandleCount);
    snapshotOut->commitTotalBytes = static_cast<std::uint64_t>(perfInfo.CommitTotal) * pageSizeBytes;
    snapshotOut->commitLimitBytes = static_cast<std::uint64_t>(perfInfo.CommitLimit) * pageSizeBytes;
    snapshotOut->cachedBytes = static_cast<std::uint64_t>(perfInfo.SystemCache) * pageSizeBytes;
    snapshotOut->pagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelPaged) * pageSizeBytes;
    snapshotOut->nonPagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelNonpaged) * pageSizeBytes;
    return true;
}

void HudPerformancePanel::updateView(
    const std::vector<double>& coreUsageList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double usageValue : coreUsageList)
        {
            averageCpuUsage += usageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    if (m_cpuSummaryLabel != nullptr)
    {
        m_cpuSummaryLabel->setText(
            QStringLiteral("CPU total: %1%    Memory: %2%    Logical processors: %3")
            .arg(averageCpuUsage, 0, 'f', 1)
            .arg(memoryUsagePercent, 0, 'f', 1)
            .arg(coreUsageList.size()));
    }
    if (m_cpuModelLabel != nullptr && !m_cpuModelText.isEmpty())
    {
        m_cpuModelLabel->setText(m_cpuModelText);
    }

    const bool cpuPageVisible =
        (m_detailStack != nullptr && m_detailStack->currentWidget() == m_cpuPage);
    if (cpuPageVisible)
    {
        const int chartCount = std::min(
            static_cast<int>(m_coreChartEntries.size()),
            static_cast<int>(coreUsageList.size()));
        for (int indexValue = 0; indexValue < chartCount; ++indexValue)
        {
            CoreChartEntry& chartEntry = m_coreChartEntries[static_cast<std::size_t>(indexValue)];
            const double usageValue = coreUsageList[static_cast<std::size_t>(indexValue)];
            if (chartEntry.titleLabel != nullptr)
            {
                const QString titleText = QStringLiteral("CPU %1  %2%")
                    .arg(indexValue, 2, 10, QLatin1Char('0'))
                    .arg(usageValue, 5, 'f', 1, QLatin1Char(' '));
                if (chartEntry.titleLabel->text() != titleText)
                {
                    chartEntry.titleLabel->setText(titleText);
                }
            }
            appendCoreSeriesPoint(chartEntry, usageValue);
        }
    }

    if (m_memorySummaryLabel != nullptr)
    {
        m_memorySummaryLabel->setText(
            QStringLiteral("Current memory load: %1%").arg(memoryUsagePercent, 0, 'f', 1));
    }
    appendGeneralSeriesPoint(
        m_memoryLineSeries,
        m_memoryAxisX,
        m_memoryAxisY,
        memoryUsagePercent,
        0.0);

    if (m_diskSummaryLabel != nullptr)
    {
        m_diskSummaryLabel->setText(
            QStringLiteral("Read: %1    Write: %2")
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec)));
    }
    appendGeneralSeriesPoint(m_diskReadLineSeries, m_diskAxisX, m_diskAxisY, diskReadBytesPerSec, 0.0);
    appendGeneralSeriesPoint(m_diskWriteLineSeries, m_diskAxisX, m_diskAxisY, diskWriteBytesPerSec, 0.0);
    const auto diskRange = ks::ui::MetricChartBinding::SharedRange({ m_diskReadLineSeries, m_diskWriteLineSeries },
        ks::ui::MetricXMode::StableId, { 0.0, 1.0, 1.15, {} });
    if (m_diskAxisY != nullptr)
    {
        m_diskAxisY->setRange(diskRange.minimumY, diskRange.maximumY);
    }

    if (m_networkSummaryLabel != nullptr)
    {
        m_networkSummaryLabel->setText(
            QStringLiteral("Receive: %1    Send: %2")
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkTxBytesPerSec)));
    }
    appendGeneralSeriesPoint(m_networkRxLineSeries, m_networkAxisX, m_networkAxisY, networkRxBytesPerSec, 0.0);
    appendGeneralSeriesPoint(m_networkTxLineSeries, m_networkAxisX, m_networkAxisY, networkTxBytesPerSec, 0.0);
    const auto networkRange = ks::ui::MetricChartBinding::SharedRange({ m_networkRxLineSeries, m_networkTxLineSeries },
        ks::ui::MetricXMode::StableId, { 0.0, 1.0, 1.15, {} });
    if (m_networkAxisY != nullptr)
    {
        m_networkAxisY->setRange(networkRange.minimumY, networkRange.maximumY);
    }

    if (m_gpuSummaryLabel != nullptr)
    {
        m_gpuSummaryLabel->setText(
            QStringLiteral("GPU: %1%    3D: %2%    Copy: %3%")
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(m_gpuUsage3DPercent, 0, 'f', 1)
            .arg(m_gpuUsageCopyPercent, 0, 'f', 1));
    }

    for (GpuEngineChartEntry& chartEntry : m_gpuEngineCharts)
    {
        double usagePercent = 0.0;
        if (chartEntry.engineKeyText == QStringLiteral("3d"))
        {
            usagePercent = m_gpuUsage3DPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("copy"))
        {
            usagePercent = m_gpuUsageCopyPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_encode"))
        {
            usagePercent = m_gpuUsageVideoEncodePercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_decode"))
        {
            usagePercent = m_gpuUsageVideoDecodePercent;
        }

        appendGeneralSeriesPoint(
            chartEntry.lineSeries,
            chartEntry.axisX,
            chartEntry.axisY,
            usagePercent,
            0.0);
        if (chartEntry.titleLabel != nullptr)
        {
            chartEntry.titleLabel->setText(
                QStringLiteral("%1  %2%")
                .arg(chartEntry.displayNameText)
                .arg(usagePercent, 0, 'f', 1));
        }
    }

    appendGeneralSeriesPoint(
        m_gpuDedicatedMemoryLineSeries,
        m_gpuDedicatedMemoryAxisX,
        m_gpuDedicatedMemoryAxisY,
        m_gpuDedicatedUsedGiB,
        0.0);
    appendGeneralSeriesPoint(
        m_gpuSharedMemoryLineSeries,
        m_gpuSharedMemoryAxisX,
        m_gpuSharedMemoryAxisY,
        m_gpuSharedUsedGiB,
        0.0);
    if (m_gpuDedicatedMemoryAxisY != nullptr)
    {
        const double dedicatedUpperGiB = std::max(
            0.5,
            (m_gpuDedicatedBudgetGiB > 0.0 ? m_gpuDedicatedBudgetGiB : m_gpuDedicatedMemoryGiB));
        m_gpuDedicatedMemoryAxisY->setRange(0.0, dedicatedUpperGiB);
    }
    if (m_gpuSharedMemoryAxisY != nullptr)
    {
        const double sharedUpperGiB = std::max(0.5, m_gpuSharedBudgetGiB);
        m_gpuSharedMemoryAxisY->setRange(0.0, sharedUpperGiB);
    }

    updateSidebarCards(
        averageCpuUsage,
        memoryUsagePercent,
        m_lastTotalPhysBytes,
        m_lastAvailPhysBytes,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
}

void HudPerformancePanel::updateSidebarCards(
    const double cpuUsagePercent,
    const double memoryUsagePercent,
    const std::uint64_t totalPhysBytes,
    const std::uint64_t availPhysBytes,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    if (m_cpuNavCard != nullptr)
    {
        m_cpuNavCard->setSubtitleText(
            QStringLiteral("%1%  %2 GHz")
            .arg(cpuUsagePercent, 0, 'f', 0)
            .arg(m_lastCpuSpeedGhz, 0, 'f', 2));
        m_cpuNavCard->appendSample(cpuUsagePercent);
    }

    if (m_memoryNavCard != nullptr && totalPhysBytes > 0)
    {
        const double totalGiB = static_cast<double>(totalPhysBytes) / kOneGiBInBytes;
        const double usedGiB =
            static_cast<double>(totalPhysBytes - availPhysBytes) / kOneGiBInBytes;
        m_memoryNavCard->setSubtitleText(
            QStringLiteral("%1/%2 GB (%3%)")
            .arg(usedGiB, 0, 'f', 1)
            .arg(totalGiB, 0, 'f', 1)
            .arg(memoryUsagePercent, 0, 'f', 0));
        m_memoryNavCard->appendSample(memoryUsagePercent);
    }

    if (m_diskNavCard != nullptr)
    {
        const double totalDiskBytesPerSec = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
        m_diskNavAutoScaleBytesPerSec = std::max(
            totalDiskBytesPerSec + 1.0,
            m_diskNavAutoScaleBytesPerSec * 0.96);
        const double diskUsagePercent = qBound(
            0.0,
            totalDiskBytesPerSec / std::max(1.0, m_diskNavAutoScaleBytesPerSec) * 100.0,
            100.0);
        m_diskNavCard->setSubtitleText(
            QStringLiteral("R %1 / W %2")
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec)));
        m_diskNavCard->appendSample(diskUsagePercent);
    }

    if (m_networkNavCard != nullptr)
    {
        const double totalNetworkBytesPerSec = std::max(0.0, networkRxBytesPerSec) + std::max(0.0, networkTxBytesPerSec);
        m_networkNavAutoScaleBytesPerSec = std::max(
            totalNetworkBytesPerSec + 1.0,
            m_networkNavAutoScaleBytesPerSec * 0.96);
        const double networkUsagePercent = qBound(
            0.0,
            totalNetworkBytesPerSec / std::max(1.0, m_networkNavAutoScaleBytesPerSec) * 100.0,
            100.0);
        m_networkNavCard->setSubtitleText(
            QStringLiteral("S %1 / R %2")
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec)));
        m_networkNavCard->appendSample(networkUsagePercent);
    }

    if (m_gpuNavCard != nullptr)
    {
        m_gpuNavCard->setSubtitleText(
            QStringLiteral("%1%  %2/%3 GB")
            .arg(gpuUsagePercent, 0, 'f', 0)
            .arg(m_gpuDedicatedUsedGiB, 0, 'f', 1)
            .arg((m_gpuDedicatedBudgetGiB > 0.0 ? m_gpuDedicatedBudgetGiB : m_gpuDedicatedMemoryGiB), 0, 'f', 1));
        m_gpuNavCard->appendSample(gpuUsagePercent);
    }
}

void HudPerformancePanel::updateTaskManagerDetailLabels(
    const std::vector<double>& coreUsageList,
    const std::vector<CpuPowerSnapshot>& powerInfoList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent,
    const SystemPerformanceSnapshot* const systemPerfSnapshotPointer,
    const bool systemPerfOk)
{
    Q_UNUSED(memoryUsagePercent);

    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double usageValue : coreUsageList)
        {
            averageCpuUsage += usageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    double currentMhzSum = 0.0;
    double maxMhzSum = 0.0;
    int cpuPowerCount = 0;
    for (const CpuPowerSnapshot& snapshot : powerInfoList)
    {
        if (snapshot.currentMhz > 0)
        {
            currentMhzSum += static_cast<double>(snapshot.currentMhz);
        }
        if (snapshot.maxMhz > 0)
        {
            maxMhzSum += static_cast<double>(snapshot.maxMhz);
        }
        ++cpuPowerCount;
    }
    const double currentCpuGhz = cpuPowerCount > 0
        ? (currentMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    const double baseCpuGhz = cpuPowerCount > 0
        ? (maxMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    m_lastCpuSpeedGhz = currentCpuGhz;

    const std::uint64_t uptimeSeconds = static_cast<std::uint64_t>(::GetTickCount64() / 1000ULL);

    if (m_cpuPrimaryDetailLabel != nullptr)
    {
        m_cpuPrimaryDetailLabel->setText(
            QStringLiteral(
                "Utilization: %1%\n"
                "Speed: %2 GHz\n"
                "Processes: %3\n"
                "Threads: %4\n"
                "Handles: %5\n"
                "Up time: %6")
            .arg(averageCpuUsage, 0, 'f', 1)
            .arg(currentCpuGhz, 0, 'f', 2)
            .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? QString::number(systemPerfSnapshotPointer->processCount) : QStringLiteral("N/A"))
            .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? QString::number(systemPerfSnapshotPointer->threadCount) : QStringLiteral("N/A"))
            .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? QString::number(systemPerfSnapshotPointer->handleCount) : QStringLiteral("N/A"))
            .arg(formatDurationText(uptimeSeconds)));
    }

    if (m_cpuSecondaryDetailLabel != nullptr)
    {
        m_cpuSecondaryDetailLabel->setText(
            QStringLiteral(
                "Base speed: %1 GHz\n"
                "Sockets: %2\n"
                "Cores: %3\n"
                "Logical processors: %4\n"
                "L1 cache: %5\n"
                "L2 cache: %6\n"
                "L3 cache: %7")
            .arg(baseCpuGhz, 0, 'f', 2)
            .arg(m_cpuPackageCount > 0 ? QString::number(m_cpuPackageCount) : QStringLiteral("N/A"))
            .arg(m_cpuPhysicalCoreCount > 0 ? QString::number(m_cpuPhysicalCoreCount) : QStringLiteral("N/A"))
            .arg(m_cpuLogicalCoreCount > 0 ? QString::number(m_cpuLogicalCoreCount) : QStringLiteral("N/A"))
            .arg(m_cpuL1CacheBytes > 0 ? bytesToReadableText(static_cast<double>(m_cpuL1CacheBytes)) : QStringLiteral("N/A"))
            .arg(m_cpuL2CacheBytes > 0 ? bytesToReadableText(static_cast<double>(m_cpuL2CacheBytes)) : QStringLiteral("N/A"))
            .arg(m_cpuL3CacheBytes > 0 ? bytesToReadableText(static_cast<double>(m_cpuL3CacheBytes)) : QStringLiteral("N/A")));
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    const bool memoryStatusOk = (::GlobalMemoryStatusEx(&memoryStatus) == TRUE);
    if (memoryStatusOk)
    {
        const double totalGiB = static_cast<double>(memoryStatus.ullTotalPhys) / kOneGiBInBytes;
        const double availableGiB = static_cast<double>(memoryStatus.ullAvailPhys) / kOneGiBInBytes;
        const double usedGiB = totalGiB - availableGiB;
        if (m_memoryCapacityLabel != nullptr)
        {
            m_memoryCapacityLabel->setText(QStringLiteral("%1 GB").arg(totalGiB, 0, 'f', 1));
        }
        if (m_memoryPrimaryDetailLabel != nullptr)
        {
            m_memoryPrimaryDetailLabel->setText(
                QStringLiteral(
                    "In use: %1 GB\n"
                    "Available: %2 GB\n"
                    "Committed: %3 / %4\n"
                    "Cached: %5\n"
                    "Paged pool: %6\n"
                    "Non-paged pool: %7")
                .arg(usedGiB, 0, 'f', 1)
                .arg(availableGiB, 0, 'f', 1)
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->commitTotalBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->commitLimitBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->cachedBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->pagedPoolBytes)) : QStringLiteral("N/A"))
                .arg(systemPerfOk && systemPerfSnapshotPointer != nullptr ? bytesToReadableText(static_cast<double>(systemPerfSnapshotPointer->nonPagedPoolBytes)) : QStringLiteral("N/A")));
        }
    }

    if (m_memorySecondaryDetailLabel != nullptr)
    {
        ULONGLONG installedMemoryKb = 0;
        ::GetPhysicallyInstalledSystemMemory(&installedMemoryKb);
        const double installedBytes = static_cast<double>(installedMemoryKb) * 1024.0;
        const double reservedBytes = memoryStatusOk
            ? std::max(0.0, installedBytes - static_cast<double>(memoryStatus.ullTotalPhys))
            : 0.0;
        m_memorySecondaryDetailLabel->setText(
            QStringLiteral(
                "Speed: %1 MHz\n"
                "Slots used: %2/%3\n"
                "Form factor: %4\n"
                "Hardware reserved: %5")
            .arg(m_memorySpeedMhz > 0 ? QString::number(m_memorySpeedMhz) : QStringLiteral("N/A"))
            .arg(m_memorySlotUsed > 0 ? QString::number(m_memorySlotUsed) : QStringLiteral("N/A"))
            .arg(m_memorySlotTotal > 0 ? QString::number(m_memorySlotTotal) : QStringLiteral("N/A"))
            .arg(m_memoryFormFactorText.isEmpty() ? QStringLiteral("N/A") : m_memoryFormFactorText)
            .arg(bytesToReadableText(reservedBytes)));
    }

    if (m_diskDetailLabel != nullptr)
    {
        const double diskTotalRate = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
        const double diskApproxPercent = qBound(
            0.0,
            diskTotalRate / std::max(1.0, m_diskNavAutoScaleBytesPerSec) * 100.0,
            100.0);
        m_diskDetailLabel->setText(
            QStringLiteral(
                "Active time (approx): %1%\n"
                "Read speed: %2\n"
                "Write speed: %3\n"
                "System volume: %4\n"
                "Total: %5\n"
                "Free: %6")
            .arg(diskApproxPercent, 0, 'f', 1)
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec))
            .arg(m_systemVolumeText.isEmpty() ? QStringLiteral("N/A") : m_systemVolumeText)
            .arg(m_systemVolumeTotalBytes > 0
                ? bytesToReadableText(static_cast<double>(m_systemVolumeTotalBytes))
                : QStringLiteral("N/A"))
            .arg(m_systemVolumeFreeBytes > 0
                ? bytesToReadableText(static_cast<double>(m_systemVolumeFreeBytes))
                : QStringLiteral("N/A")));
    }

    if (m_networkDetailLabel != nullptr)
    {
        const QString adapterText = m_primaryNetworkAdapterName.isEmpty()
            ? QStringLiteral("N/A")
            : m_primaryNetworkAdapterName;
        const double linkMbps = static_cast<double>(m_primaryNetworkLinkBitsPerSecond) / (1000.0 * 1000.0);
        m_networkDetailLabel->setText(
            QStringLiteral(
                "Adapter: %1\n"
                "Send: %2\n"
                "Receive: %3\n"
                "Link speed: %4 Mbps")
            .arg(adapterText)
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(linkMbps > 0.0 ? QString::number(linkMbps, 'f', 1) : QStringLiteral("N/A")));
    }

    if (m_gpuAdapterTitleLabel != nullptr)
    {
        m_gpuAdapterTitleLabel->setText(
            m_gpuAdapterNameText.isEmpty() ? QStringLiteral("N/A") : m_gpuAdapterNameText);
    }
    if (m_gpuDedicatedMemoryChartView != nullptr && m_gpuDedicatedMemoryChartView->chart() != nullptr)
    {
        m_gpuDedicatedMemoryChartView->chart()->setTitle(
            QStringLiteral("Dedicated GPU memory  %1 / %2 GiB")
            .arg(m_gpuDedicatedUsedGiB, 0, 'f', 2)
            .arg(m_gpuDedicatedBudgetGiB > 0.0 ? m_gpuDedicatedBudgetGiB : m_gpuDedicatedMemoryGiB, 0, 'f', 2));
    }
    if (m_gpuSharedMemoryChartView != nullptr && m_gpuSharedMemoryChartView->chart() != nullptr)
    {
        m_gpuSharedMemoryChartView->chart()->setTitle(
            QStringLiteral("Shared GPU memory  %1 / %2 GiB")
            .arg(m_gpuSharedUsedGiB, 0, 'f', 2)
            .arg(m_gpuSharedBudgetGiB, 0, 'f', 2));
    }

    if (m_gpuDetailLabel != nullptr)
    {
        m_gpuDetailLabel->setText(
            QStringLiteral(
                "Utilization: %1%\n"
                "3D: %2%   Copy: %3%   Video Encode: %4%   Video Decode: %5%\n"
                "Dedicated memory: %6 / %7 GiB\n"
                "Shared memory: %8 / %9 GiB\n"
                "Driver version: %10\n"
                "Driver date: %11\n"
                "PNP: %12")
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(m_gpuUsage3DPercent, 0, 'f', 1)
            .arg(m_gpuUsageCopyPercent, 0, 'f', 1)
            .arg(m_gpuUsageVideoEncodePercent, 0, 'f', 1)
            .arg(m_gpuUsageVideoDecodePercent, 0, 'f', 1)
            .arg(m_gpuDedicatedUsedGiB, 0, 'f', 2)
            .arg((m_gpuDedicatedBudgetGiB > 0.0 ? m_gpuDedicatedBudgetGiB : m_gpuDedicatedMemoryGiB), 0, 'f', 2)
            .arg(m_gpuSharedUsedGiB, 0, 'f', 2)
            .arg(m_gpuSharedBudgetGiB, 0, 'f', 2)
            .arg(m_gpuDriverVersionText.isEmpty() ? QStringLiteral("N/A") : m_gpuDriverVersionText)
            .arg(m_gpuDriverDateText.isEmpty() ? QStringLiteral("N/A") : m_gpuDriverDateText)
            .arg(m_gpuPnpDeviceIdText.isEmpty() ? QStringLiteral("N/A") : m_gpuPnpDeviceIdText));
    }
}

void HudPerformancePanel::appendCoreSeriesPoint(CoreChartEntry& chartEntry, const double usagePercent)
{
    auto* sparklineWidget = static_cast<CpuCoreSparklineWidget*>(chartEntry.chartWidget);
    if (sparklineWidget == nullptr)
    {
        return;
    }
    sparklineWidget->appendSample(usagePercent, m_historyLength);
}

void HudPerformancePanel::appendGeneralSeriesPoint(QLineSeries* lineSeries, QValueAxis* axisX,
    QValueAxis* axisY, const double sampleValue, const double minAxisYValue)
{
    if (lineSeries == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }
    // HUD 拥有独立进程模型，复用相同采样身份、有效性和轴策略算法。
    bool valid = true;
    if (lineSeries == m_memoryLineSeries)
    {
        valid = m_metricMemoryValid;
    }
    else if (lineSeries == m_diskReadLineSeries || lineSeries == m_diskWriteLineSeries)
    {
        valid = m_metricDiskValid;
    }
    else if (lineSeries == m_networkRxLineSeries || lineSeries == m_networkTxLineSeries)
    {
        valid = m_metricNetworkValid;
    }
    else if (lineSeries == m_gpuDedicatedMemoryLineSeries || lineSeries == m_gpuSharedMemoryLineSeries)
    {
        valid = m_metricGpuMemoryValid;
    }
    for (const GpuEngineChartEntry& engine : m_gpuEngineCharts)
    {
        if (lineSeries == engine.lineSeries)
        {
            valid = m_metricGpuValid;
            break;
        }
    }
    auto* binding = ks::ui::MetricChartBinding::ForSeries(lineSeries, m_historyLength);
    binding->append({ static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, sampleValue, valid });
    ks::ui::MetricAxisPolicy policy{ minAxisYValue, 1.0, 1.15, {} };
    if (lineSeries == m_memoryLineSeries)
    {
        policy.fixedMaximumY = 100.0;
    }
    const auto range = binding->range(policy);
    axisX->setRange(range.minimumX, range.maximumX);
    axisY->setRange(range.minimumY, range.maximumY);
}

QString HudPerformancePanel::formatRateText(const double bytesPerSecondValue) const
{
    return bytesPerSecondToText(bytesPerSecondValue);
}

void HudPerformancePanel::requestAsyncStaticInfoRefresh()
{
    bool expectedFlag = false;
    if (!m_staticInfoRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_staticInfoRefreshing.store(false);
        return;
    }

    const QPointer<HudPerformancePanel> safeThis(this);
    QThreadPool::globalInstance()->start([applicationContext, safeThis]()
    {
        const MemoryHardwareSummarySnapshot memorySummary = queryMemoryHardwareSummarySnapshot();
        const GpuHardwareSummarySnapshot gpuSummary = queryGpuHardwareSummarySnapshot();

        // 应用析构等待全局线程池；页面可随时销毁，页面指针只在 UI 回调内访问。
        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis, memorySummary, gpuSummary]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->m_memorySpeedMhz = memorySummary.speedMhz;
                safeThis->m_memorySlotUsed = memorySummary.usedSlots;
                safeThis->m_memorySlotTotal = memorySummary.totalSlots;
                safeThis->m_memoryFormFactorText = memorySummary.formFactorText;
                safeThis->m_gpuAdapterNameText = gpuSummary.adapterNameText;
                safeThis->m_gpuDriverVersionText = gpuSummary.driverVersionText;
                safeThis->m_gpuDriverDateText = gpuSummary.driverDateText;
                safeThis->m_gpuPnpDeviceIdText = gpuSummary.pnpDeviceIdText;
                safeThis->m_gpuDedicatedMemoryGiB = gpuSummary.dedicatedMemoryGiB;
                safeThis->m_staticInfoRefreshing.store(false);
            },
            Qt::QueuedConnection);

    });
}

void HudPerformancePanel::requestAsyncSensorRefresh()
{
    bool expectedFlag = false;
    if (!m_sensorRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_sensorRefreshing.store(false);
        return;
    }

    const QPointer<HudPerformancePanel> safeThis(this);
    QThreadPool::globalInstance()->start([applicationContext, safeThis]()
    {
        const QString sensorText = QStringLiteral("%1|%2")
            .arg(queryCpuTemperatureText())
            .arg(queryCpuVoltageText());

        // 后台采集不使用页面接收器，排队结果在 UI 线程确认页面仍然有效。
        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis, sensorText]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->m_cachedSensorText = sensorText;
                safeThis->m_sensorRefreshing.store(false);
            },
            Qt::QueuedConnection);

    });
}

void HudPerformancePanel::refreshCpuTopologyStaticInfo()
{
    m_cpuModelText = queryCpuBrandTextByCpuid();

    DWORD requiredBytes = 0;
    ::GetLogicalProcessorInformationEx(RelationAll, nullptr, &requiredBytes);
    if (requiredBytes == 0)
    {
        m_cpuLogicalCoreCount = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    std::vector<unsigned char> buffer(requiredBytes);
    auto* infoPointer =
        reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationAll, infoPointer, &requiredBytes) == FALSE)
    {
        m_cpuLogicalCoreCount = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    int packageCount = 0;
    int physicalCoreCount = 0;
    int logicalCoreCount = 0;
    std::uint64_t l1Bytes = 0;
    std::uint64_t l2Bytes = 0;
    std::uint64_t l3Bytes = 0;

    DWORD offsetBytes = 0;
    while (offsetBytes < requiredBytes)
    {
        auto* entryPointer = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() + offsetBytes);
        if (entryPointer->Relationship == RelationProcessorPackage)
        {
            ++packageCount;
        }
        else if (entryPointer->Relationship == RelationProcessorCore)
        {
            ++physicalCoreCount;
            for (WORD groupIndex = 0; groupIndex < entryPointer->Processor.GroupCount; ++groupIndex)
            {
                logicalCoreCount += countBits(entryPointer->Processor.GroupMask[groupIndex].Mask);
            }
        }
        else if (entryPointer->Relationship == RelationCache)
        {
            if (entryPointer->Cache.Level == 1)
            {
                l1Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 2)
            {
                l2Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 3)
            {
                l3Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
        }

        if (entryPointer->Size == 0)
        {
            break;
        }
        offsetBytes += entryPointer->Size;
    }

    m_cpuPackageCount = std::max(1, packageCount);
    m_cpuPhysicalCoreCount = std::max(1, physicalCoreCount);
    m_cpuLogicalCoreCount = logicalCoreCount > 0
        ? logicalCoreCount
        : static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    m_cpuL1CacheBytes = l1Bytes;
    m_cpuL2CacheBytes = l2Bytes;
    m_cpuL3CacheBytes = l3Bytes;
}

void HudPerformancePanel::refreshSystemVolumeInfo()
{
    QString systemDrive = qEnvironmentVariable("SystemDrive");
    if (systemDrive.isEmpty())
    {
        systemDrive = QStringLiteral("C:");
    }

    QString rootPath = systemDrive;
    if (!rootPath.endsWith('\\'))
    {
        rootPath += QLatin1Char('\\');
    }

    ULARGE_INTEGER freeAvailableBytes{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFreeBytes{};
    if (::GetDiskFreeSpaceExW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        &freeAvailableBytes,
        &totalBytes,
        &totalFreeBytes) == TRUE)
    {
        m_systemVolumeTotalBytes = static_cast<std::uint64_t>(totalBytes.QuadPart);
        m_systemVolumeFreeBytes = static_cast<std::uint64_t>(totalFreeBytes.QuadPart);
    }

    wchar_t volumeNameBuffer[MAX_PATH] = {};
    if (::GetVolumeInformationW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        volumeNameBuffer,
        MAX_PATH,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0) == TRUE)
    {
        const QString volumeNameText = QString::fromWCharArray(volumeNameBuffer).trimmed();
        if (!volumeNameText.isEmpty())
        {
            m_systemVolumeText = QStringLiteral("%1 (%2)").arg(volumeNameText, systemDrive);
            return;
        }
    }

    m_systemVolumeText = rootPath;
}

QString HudPerformancePanel::buildCpuSensorText(const bool forceRefresh)
{
    if (forceRefresh)
    {
        requestAsyncSensorRefresh();
    }

    if (!m_cachedSensorText.isEmpty())
    {
        return m_cachedSensorText;
    }
    return QStringLiteral("N/A|N/A");
}
