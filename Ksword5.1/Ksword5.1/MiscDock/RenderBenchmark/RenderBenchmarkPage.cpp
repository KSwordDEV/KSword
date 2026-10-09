#include "RenderBenchmarkPage.h"

// ============================================================
// RenderBenchmarkPage.cpp
// 作用说明：
// 1) 实现“渲染基准”页的四项测试与统一报告输出；
// 2) 所有测量都在 UI 线程完成——被测对象正是 UI 线程本身；
// 3) 只报告本机实测值，不内置任何“应该是多少”的判定阈值。
// ============================================================

#include "../../Internationalization/LanguageManager.h"
#include "../../SettingsDock/AppearanceSettings.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QPaintEvent>
#include <QPixmap>
#include <QPlainTextEdit>
#include "../../UI/CodeTextEdit.h"
#include <QProgressBar>
#include <QPushButton>
#include <QRect>
#include <QScreen>
#include <QScrollArea>
#include <QSpinBox>
#include <QTextStream>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <tlhelp32.h>

namespace
{
    // kFrameBudgetMs 作用：
    // - 60fps 下单帧的时间预算；超过它的样本按“掉帧”计数。
    constexpr double kFrameBudgetMs = 1000.0 / 60.0;

    // 组合特性相关常量：与 MainWindow 保持同一套取值。
    // 这里刻意不复用 MainWindow 的内部常量，基准页应当能独立说明自己在下发什么。
    constexpr DWORD kWindowCompositionAttributeAccentPolicy = 19;
    constexpr DWORD kAccentEnableAcrylicBlurBehind = 4;

    struct AccentPolicyData
    {
        DWORD accentState = 0;
        DWORD accentFlags = 0;
        DWORD gradientColor = 0;
        DWORD animationId = 0;
    };

    struct WindowCompositionAttributeData
    {
        DWORD attribute = 0;
        void* dataPointer = nullptr;
        SIZE_T dataSizeBytes = 0;
    };

    using SetWindowCompositionAttributeFunction = BOOL(WINAPI*)(HWND, void*);

    // resolveSetWindowCompositionAttribute 作用：
    // - 取 user32 未导出的组合特性入口；旧系统上可能不存在，返回空指针由调用方降级。
    SetWindowCompositionAttributeFunction resolveSetWindowCompositionAttribute()
    {
        static SetWindowCompositionAttributeFunction cachedEntry =
            []() -> SetWindowCompositionAttributeFunction {
                HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
                if (user32ModuleHandle == nullptr)
                {
                    return nullptr;
                }
                return reinterpret_cast<SetWindowCompositionAttributeFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetWindowCompositionAttribute"));
            }();
        return cachedEntry;
    }

    // submitAcrylicAccent 作用：
    // - 给指定窗口下发一次亚克力组合特性。
    // 入参 windowHandle：目标窗口；入参 tintAlpha：着色层不透明度（0~255）。
    // 返回：true=下发成功。
    bool submitAcrylicAccent(HWND windowHandle, const int tintAlpha)
    {
        SetWindowCompositionAttributeFunction entry = resolveSetWindowCompositionAttribute();
        if (entry == nullptr || windowHandle == nullptr)
        {
            return false;
        }
        AccentPolicyData accentPolicy{};
        accentPolicy.accentState = kAccentEnableAcrylicBlurBehind;
        // gradientColor 排布为 0xAABBGGRR，这里用中性深灰，颜色本身不影响测量结论。
        accentPolicy.gradientColor =
            (static_cast<DWORD>(std::clamp(tintAlpha, 0, 255)) << 24) | 0x00202020;
        WindowCompositionAttributeData compositionData{};
        compositionData.attribute = kWindowCompositionAttributeAccentPolicy;
        compositionData.dataPointer = &accentPolicy;
        compositionData.dataSizeBytes = sizeof(accentPolicy);
        return entry(windowHandle, &compositionData) != FALSE;
    }

    // summarizeSamples 作用：
    // - 把一组耗时样本折算成统一统计口径。
    // 入参 samples：耗时样本（毫秒），可乱序。
    // 返回：统计结果；样本为空时返回全零。
    ks::misc::BenchmarkSampleSummary summarizeSamples(std::vector<double> samples)
    {
        ks::misc::BenchmarkSampleSummary summary;
        if (samples.empty())
        {
            return summary;
        }
        double total = 0.0;
        for (const double value : samples)
        {
            total += value;
            summary.worstMs = std::max(summary.worstMs, value);
            if (value > kFrameBudgetMs)
            {
                ++summary.overBudgetCount;
            }
        }
        std::sort(samples.begin(), samples.end());
        summary.sampleCount = static_cast<int>(samples.size());
        summary.averageMs = total / static_cast<double>(samples.size());
        summary.p95Ms = samples[samples.size() * 95 / 100];
        return summary;
    }

    // pumpUserInterface 作用：
    // - 在长测试中间放行一次事件处理，让按钮状态与进度条能刷新出来；
    // - 不用 QThread::msleep 空等，避免界面看起来像卡死。
    void pumpUserInterface(const int milliseconds)
    {
        QElapsedTimer waitTimer;
        waitTimer.start();
        do
        {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
            if (waitTimer.elapsed() < milliseconds)
            {
                ::Sleep(2);
            }
        } while (waitTimer.elapsed() < milliseconds);
    }

    // locateMainRootContainer 作用：
    // - 按 objectName 找到主窗口的背景根容器；
    // - 基准页可能被内嵌到别处，所以从所有顶层窗口里找而不是假定父链。
    // 返回：根容器指针；未找到返回空。
    QWidget* locateMainRootContainer()
    {
        const QWidgetList topLevelWidgets = QApplication::topLevelWidgets();
        for (QWidget* const topLevelWidget : topLevelWidgets)
        {
            if (topLevelWidget == nullptr)
            {
                continue;
            }
            if (topLevelWidget->objectName() == QStringLiteral("ksMainRootContainer"))
            {
                return topLevelWidget;
            }
            QWidget* const foundWidget =
                topLevelWidget->findChild<QWidget*>(QStringLiteral("ksMainRootContainer"));
            if (foundWidget != nullptr)
            {
                return foundWidget;
            }
        }
        return nullptr;
    }

    // buildGradientWallpaper 作用：
    // - 在没有可用背景图时合成一张渐变位图，保证拖动测试仍有真实的图片绘制负载。
    // 入参 imageSize：目标尺寸。
    // 返回：可直接绘制的位图。
    QPixmap buildGradientWallpaper(const QSize& imageSize)
    {
        QImage generatedImage(imageSize, QImage::Format_ARGB32_Premultiplied);
        for (int rowIndex = 0; rowIndex < imageSize.height(); ++rowIndex)
        {
            QRgb* const scanLine = reinterpret_cast<QRgb*>(generatedImage.scanLine(rowIndex));
            for (int columnIndex = 0; columnIndex < imageSize.width(); ++columnIndex)
            {
                scanLine[columnIndex] = qRgba(
                    (columnIndex * 255) / std::max(1, imageSize.width()),
                    (rowIndex * 255) / std::max(1, imageSize.height()),
                    128,
                    255);
            }
        }
        return QPixmap::fromImage(generatedImage);
    }

    // ProbeBackgroundWidget 作用：
    // - 复刻主窗口背景绘制器的关键路径：穿透底色 + 居中等比覆盖的背景图；
    // - 拖动基准要测的正是这条路径叠加透明子控件树后的成本。
    class ProbeBackgroundWidget final : public QWidget
    {
    public:
        ProbeBackgroundWidget(QPixmap backgroundImage, const int imageOpacityPercent, QWidget* parent)
            : QWidget(parent)
            , m_backgroundImage(std::move(backgroundImage))
            , m_imageOpacityPercent(std::clamp(imageOpacityPercent, 0, 100))
        {
            setAutoFillBackground(false);
            setAttribute(Qt::WA_StyledBackground, false);
            setAttribute(Qt::WA_OpaquePaintEvent, false);
        }

    protected:
        void paintEvent(QPaintEvent* event) override
        {
            QPainter painter(this);
            if (event != nullptr)
            {
                painter.setClipRegion(event->region());
            }
            // 与主窗口一致：穿透模式下底色 alpha 保留 1，维持鼠标命中。
            QColor hitTestFloorColor(18, 18, 18);
            hitTestFloorColor.setAlpha(1);
            painter.setCompositionMode(QPainter::CompositionMode_Source);
            painter.fillRect(rect(), hitTestFloorColor);
            painter.setCompositionMode(QPainter::CompositionMode_SourceOver);

            if (m_backgroundImage.isNull() || m_imageOpacityPercent <= 0 || rect().isEmpty())
            {
                return;
            }
            QSizeF scaledSize(m_backgroundImage.size());
            scaledSize.scale(QSizeF(rect().size()), Qt::KeepAspectRatioByExpanding);
            const QRectF targetRect(
                (static_cast<double>(rect().width()) - scaledSize.width()) / 2.0,
                (static_cast<double>(rect().height()) - scaledSize.height()) / 2.0,
                scaledSize.width(),
                scaledSize.height());
            painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter.setOpacity(static_cast<double>(m_imageOpacityPercent) / 100.0);
            painter.drawPixmap(
                targetRect,
                m_backgroundImage,
                QRectF(QPointF(0, 0), m_backgroundImage.size()));
        }

    private:
        QPixmap m_backgroundImage;
        int m_imageOpacityPercent = 0;
    };

    // SolidColorPanel 作用：
    // - 合成探测用的纯色背景面板，作为“窗口后方的已知内容”。
    class SolidColorPanel final : public QWidget
    {
    public:
        explicit SolidColorPanel(const QColor& fillColor)
            : m_fillColor(fillColor)
        {
            setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
            setAttribute(Qt::WA_ShowWithoutActivating, true);
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.fillRect(rect(), m_fillColor);
        }

    private:
        QColor m_fillColor;
    };

    // ScreenAreaSample 作用：抓屏采样得到的平均颜色。
    struct ScreenAreaSample
    {
        double redAverage = 0.0;
        double greenAverage = 0.0;
        double blueAverage = 0.0;
        bool valid = false;
    };

    // sampleScreenArea 作用：
    // - 读取窗口所在屏幕区域**经 DWM 合成后**的最终画面并求平均色；
    // - 必须用 GetDC(nullptr)+BitBlt：PrintWindow 只给窗口自身像素，
    //   抓不到亚克力对后方内容的模糊结果。
    // 入参 windowHandle：目标窗口；入参 insetRatio：四周内缩比例，避开边缘阴影。
    // 返回：平均色采样结果。
    ScreenAreaSample sampleScreenArea(HWND windowHandle, const double insetRatio)
    {
        ScreenAreaSample sample;
        RECT windowRect{};
        if (windowHandle == nullptr || ::GetWindowRect(windowHandle, &windowRect) == FALSE)
        {
            return sample;
        }
        const int fullWidth = windowRect.right - windowRect.left;
        const int fullHeight = windowRect.bottom - windowRect.top;
        const int insetX = static_cast<int>(fullWidth * insetRatio);
        const int insetY = static_cast<int>(fullHeight * insetRatio);
        const int sampleWidth = fullWidth - insetX * 2;
        const int sampleHeight = fullHeight - insetY * 2;
        if (sampleWidth <= 0 || sampleHeight <= 0)
        {
            return sample;
        }

        HDC screenDeviceContext = ::GetDC(nullptr);
        if (screenDeviceContext == nullptr)
        {
            return sample;
        }
        HDC memoryDeviceContext = ::CreateCompatibleDC(screenDeviceContext);
        HBITMAP memoryBitmap = ::CreateCompatibleBitmap(screenDeviceContext, sampleWidth, sampleHeight);
        HGDIOBJ previousObject = ::SelectObject(memoryDeviceContext, memoryBitmap);
        const BOOL blitOk = ::BitBlt(
            memoryDeviceContext,
            0,
            0,
            sampleWidth,
            sampleHeight,
            screenDeviceContext,
            windowRect.left + insetX,
            windowRect.top + insetY,
            SRCCOPY);

        if (blitOk != FALSE)
        {
            BITMAPINFO bitmapInfo{};
            bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bitmapInfo.bmiHeader.biWidth = sampleWidth;
            bitmapInfo.bmiHeader.biHeight = -sampleHeight; // 负高度表示自顶向下排布。
            bitmapInfo.bmiHeader.biPlanes = 1;
            bitmapInfo.bmiHeader.biBitCount = 32;
            bitmapInfo.bmiHeader.biCompression = BI_RGB;
            std::vector<BYTE> pixelBuffer(static_cast<size_t>(sampleWidth) * sampleHeight * 4);
            const int copiedLines = ::GetDIBits(
                memoryDeviceContext,
                memoryBitmap,
                0,
                static_cast<UINT>(sampleHeight),
                pixelBuffer.data(),
                &bitmapInfo,
                DIB_RGB_COLORS);
            if (copiedLines != 0)
            {
                double totalRed = 0.0;
                double totalGreen = 0.0;
                double totalBlue = 0.0;
                const size_t pixelCount = static_cast<size_t>(sampleWidth) * sampleHeight;
                for (size_t pixelIndex = 0; pixelIndex < pixelCount; ++pixelIndex)
                {
                    totalBlue += pixelBuffer[pixelIndex * 4 + 0];
                    totalGreen += pixelBuffer[pixelIndex * 4 + 1];
                    totalRed += pixelBuffer[pixelIndex * 4 + 2];
                }
                sample.redAverage = totalRed / static_cast<double>(pixelCount);
                sample.greenAverage = totalGreen / static_cast<double>(pixelCount);
                sample.blueAverage = totalBlue / static_cast<double>(pixelCount);
                sample.valid = true;
            }
        }

        ::SelectObject(memoryDeviceContext, previousObject);
        ::DeleteObject(memoryBitmap);
        ::DeleteDC(memoryDeviceContext);
        ::ReleaseDC(nullptr, screenDeviceContext);
        return sample;
    }

    // probeWindowResponseMs 作用：
    // - 往目标窗口的消息队列里塞一个空消息并等它被处理完；
    // - UI 线程忙于重绘时回不了 WM_NULL，往返耗时就是它被阻塞的时长；
    // - SMTO_BLOCK 保证我们不会被提前放行，SMTO_ABORTIFHUNG 让挂死窗口快速返回。
    // 入参 windowHandle：目标窗口；入参 timeoutMs：上限，超时按上限计。
    // 返回：往返耗时（毫秒）。
    double probeWindowResponseMs(HWND windowHandle, const UINT timeoutMs)
    {
        DWORD_PTR messageResult = 0;
        QElapsedTimer roundTripTimer;
        roundTripTimer.start();
        const LRESULT sendResult = ::SendMessageTimeoutW(
            windowHandle,
            WM_NULL,
            0,
            0,
            SMTO_BLOCK | SMTO_ABORTIFHUNG,
            timeoutMs,
            &messageResult);
        const double elapsedMs = static_cast<double>(roundTripTimer.nsecsElapsed()) / 1e6;
        return sendResult == 0 ? static_cast<double>(timeoutMs) : elapsedMs;
    }

    // WindowEnumerationContext 作用：EnumWindows 回调的收集上下文。
    struct WindowEnumerationContext
    {
        QVector<ks::misc::TargetWindowEntry>* entries = nullptr;
        DWORD selfProcessId = 0;
    };

    // queryProcessImageName 作用：
    // - 按 PID 取映像名；查询失败返回空串，由调用方降级展示。
    QString queryProcessImageName(const DWORD processId)
    {
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        QString imageName;
        if (::Process32FirstW(snapshotHandle, &processEntry) != FALSE)
        {
            do
            {
                if (processEntry.th32ProcessID == processId)
                {
                    imageName = QString::fromWCharArray(processEntry.szExeFile);
                    break;
                }
            } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);
        }
        ::CloseHandle(snapshotHandle);
        return imageName;
    }

    // enumerateVisibleTopLevelWindow 作用：EnumWindows 回调，收集可见、有标题的顶层窗口。
    BOOL CALLBACK enumerateVisibleTopLevelWindow(HWND windowHandle, LPARAM callbackParameter)
    {
        WindowEnumerationContext* const context =
            reinterpret_cast<WindowEnumerationContext*>(callbackParameter);
        if (context == nullptr || context->entries == nullptr)
        {
            return FALSE;
        }
        if (::IsWindowVisible(windowHandle) == FALSE || ::GetWindow(windowHandle, GW_OWNER) != nullptr)
        {
            return TRUE;
        }
        RECT windowRect{};
        if (::GetWindowRect(windowHandle, &windowRect) == FALSE)
        {
            return TRUE;
        }
        // 过滤掉工具窗口与极小窗口：它们移动起来没有参考价值。
        if ((windowRect.right - windowRect.left) < 200 || (windowRect.bottom - windowRect.top) < 200)
        {
            return TRUE;
        }
        wchar_t titleBuffer[512] = {};
        ::GetWindowTextW(windowHandle, titleBuffer, static_cast<int>(std::size(titleBuffer)) - 1);
        const QString titleText = QString::fromWCharArray(titleBuffer).trimmed();
        if (titleText.isEmpty())
        {
            return TRUE;
        }

        DWORD ownerProcessId = 0;
        ::GetWindowThreadProcessId(windowHandle, &ownerProcessId);
        const QString imageName = queryProcessImageName(ownerProcessId);

        ks::misc::TargetWindowEntry entry;
        entry.windowHandleValue = reinterpret_cast<quint64>(windowHandle);
        entry.belongsToSelf = (ownerProcessId == context->selfProcessId);
        entry.displayText = QStringLiteral("%1 - %2 (PID %3)")
            .arg(titleText.left(60))
            .arg(imageName.isEmpty() ? QStringLiteral("?") : imageName)
            .arg(ownerProcessId);
        context->entries->push_back(entry);
        return TRUE;
    }
}

namespace ks::misc
{
    RenderBenchmarkPage::RenderBenchmarkPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        refreshTargetWindowList();

        kLogEvent initEvent;
        info << initEvent << "[RenderBenchmark] 渲染基准页初始化完成。" << eol;
    }

    void RenderBenchmarkPage::initializeUi()
    {
        QVBoxLayout* const rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(10, 10, 10, 10);
        rootLayout->setSpacing(8);

        ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

        // ===== 顶部操作条 =====
        QHBoxLayout* const topActionLayout = new QHBoxLayout();
        topActionLayout->setSpacing(6);

        m_runAllButton = new QPushButton(QStringLiteral("运行全部测试"), this);
        // 被测对象就是 UI 线程本身，这条必须让用户在点之前看到，否则会把预期内的卡顿当成崩溃。
        m_runAllButton->setToolTip(
            QStringLiteral("所有测量都在 UI 线程执行，每项测试运行时界面会短暂无响应，属于预期行为。结论随 Windows 版本和当前外观设置变化，此页只报告实测值。"));
        languageManager.bindText(
            m_runAllButton,
            QStringLiteral("misc.render_benchmark.run_all"),
            QStringLiteral("运行全部测试"));
        topActionLayout->addWidget(m_runAllButton);

        m_statusLabel = new QLabel(QStringLiteral("就绪。"), this);
        languageManager.bindText(
            m_statusLabel,
            QStringLiteral("misc.render_benchmark.status.idle"),
            QStringLiteral("就绪。"));
        topActionLayout->addWidget(m_statusLabel, 1);

        m_progressBar = new QProgressBar(this);
        m_progressBar->setRange(0, 100);
        m_progressBar->setValue(0);
        m_progressBar->setFixedWidth(180);
        m_progressBar->setVisible(false);
        topActionLayout->addWidget(m_progressBar);

        rootLayout->addLayout(topActionLayout);

        // ===== 测试一：主窗口重绘基准 =====
        QGroupBox* const repaintGroupBox = new QGroupBox(QStringLiteral("主窗口整树重绘"), this);
        languageManager.bindText(
            repaintGroupBox,
            QStringLiteral("misc.render_benchmark.repaint.group"),
            QStringLiteral("主窗口整树重绘"));
        QVBoxLayout* const repaintLayout = new QVBoxLayout(repaintGroupBox);
        repaintLayout->setSpacing(6);

        QLabel* const repaintHintLabel = new QLabel(
            QStringLiteral("把主窗口根容器渲染到离屏位图，量一次完整重绘的耗时，并拆出“仅背景层”与“子控件树”各占多少。"
                "启用透明背景后所有 Dock 内容都是透明的，父容器重绘会连带重画整棵控件树，这一项就是用来看那个代价的。"
                "测量走离屏渲染，不会改动屏幕上的真实界面。"),
            repaintGroupBox);
        repaintHintLabel->setWordWrap(true);
        languageManager.bindText(
            repaintHintLabel,
            QStringLiteral("misc.render_benchmark.repaint.hint"),
            QStringLiteral("把主窗口根容器渲染到离屏位图，量一次完整重绘的耗时，并拆出“仅背景层”与“子控件树”各占多少。"
                "启用透明背景后所有 Dock 内容都是透明的，父容器重绘会连带重画整棵控件树，这一项就是用来看那个代价的。"
                "测量走离屏渲染，不会改动屏幕上的真实界面。"));
        repaintLayout->addWidget(repaintHintLabel);

        QHBoxLayout* const repaintActionLayout = new QHBoxLayout();
        repaintActionLayout->setSpacing(6);
        QLabel* const repaintIterationLabel = new QLabel(QStringLiteral("采样次数"), repaintGroupBox);
        languageManager.bindText(
            repaintIterationLabel,
            QStringLiteral("misc.render_benchmark.repaint.iterations"),
            QStringLiteral("采样次数"));
        repaintActionLayout->addWidget(repaintIterationLabel);
        m_repaintIterationSpin = new QSpinBox(repaintGroupBox);
        m_repaintIterationSpin->setRange(3, 200);
        m_repaintIterationSpin->setValue(20);
        repaintActionLayout->addWidget(m_repaintIterationSpin);
        m_runRepaintButton = new QPushButton(QStringLiteral("运行重绘基准"), repaintGroupBox);
        languageManager.bindText(
            m_runRepaintButton,
            QStringLiteral("misc.render_benchmark.repaint.run"),
            QStringLiteral("运行重绘基准"));
        repaintActionLayout->addWidget(m_runRepaintButton);
        repaintActionLayout->addStretch();
        repaintLayout->addLayout(repaintActionLayout);
        rootLayout->addWidget(repaintGroupBox);

        // ===== 测试二：拖动 A/B =====
        QGroupBox* const dragGroupBox = new QGroupBox(QStringLiteral("拖动流畅度 A/B"), this);
        languageManager.bindText(
            dragGroupBox,
            QStringLiteral("misc.render_benchmark.drag.group"),
            QStringLiteral("拖动流畅度 A/B"));
        QVBoxLayout* const dragLayout = new QVBoxLayout(dragGroupBox);
        dragLayout->setSpacing(6);

        QLabel* const dragHintLabel = new QLabel(
            QStringLiteral("建一个与主窗口同构的测试窗口（无边框、透明背景、磨砂材质、铺满透明表格），模拟 60fps 拖动，"
                "对比“每次材质刷新都重绘整树”与“只下发材质不重绘”两种策略的掉帧率。运行时屏幕上会出现一个测试窗口并自行移动，测完自动关闭。"),
            dragGroupBox);
        dragHintLabel->setWordWrap(true);
        languageManager.bindText(
            dragHintLabel,
            QStringLiteral("misc.render_benchmark.drag.hint"),
            QStringLiteral("建一个与主窗口同构的测试窗口（无边框、透明背景、磨砂材质、铺满透明表格），模拟 60fps 拖动，"
                "对比“每次材质刷新都重绘整树”与“只下发材质不重绘”两种策略的掉帧率。运行时屏幕上会出现一个测试窗口并自行移动，测完自动关闭。"));
        dragLayout->addWidget(dragHintLabel);

        QHBoxLayout* const dragActionLayout = new QHBoxLayout();
        dragActionLayout->setSpacing(6);
        QLabel* const dragFrameLabel = new QLabel(QStringLiteral("模拟帧数"), dragGroupBox);
        languageManager.bindText(
            dragFrameLabel,
            QStringLiteral("misc.render_benchmark.drag.frames"),
            QStringLiteral("模拟帧数"));
        dragActionLayout->addWidget(dragFrameLabel);
        m_dragFrameSpin = new QSpinBox(dragGroupBox);
        m_dragFrameSpin->setRange(30, 600);
        m_dragFrameSpin->setValue(120);
        dragActionLayout->addWidget(m_dragFrameSpin);

        QLabel* const dragRowLabel = new QLabel(QStringLiteral("表格行数"), dragGroupBox);
        languageManager.bindText(
            dragRowLabel,
            QStringLiteral("misc.render_benchmark.drag.rows"),
            QStringLiteral("表格行数"));
        dragActionLayout->addWidget(dragRowLabel);
        m_dragRowSpin = new QSpinBox(dragGroupBox);
        m_dragRowSpin->setRange(0, 3000);
        m_dragRowSpin->setValue(600);
        dragActionLayout->addWidget(m_dragRowSpin);

        m_runDragButton = new QPushButton(QStringLiteral("运行拖动对比"), dragGroupBox);
        languageManager.bindText(
            m_runDragButton,
            QStringLiteral("misc.render_benchmark.drag.run"),
            QStringLiteral("运行拖动对比"));
        dragActionLayout->addWidget(m_runDragButton);
        dragActionLayout->addStretch();
        dragLayout->addLayout(dragActionLayout);
        rootLayout->addWidget(dragGroupBox);

        // ===== 测试三：DWM 合成能力探测 =====
        QGroupBox* const compositionGroupBox = new QGroupBox(QStringLiteral("DWM 合成能力探测"), this);
        languageManager.bindText(
            compositionGroupBox,
            QStringLiteral("misc.render_benchmark.composition.group"),
            QStringLiteral("DWM 合成能力探测"));
        QVBoxLayout* const compositionLayout = new QVBoxLayout(compositionGroupBox);
        compositionLayout->setSpacing(6);

        QLabel* const compositionHintLabel = new QLabel(
            QStringLiteral("在屏幕上铺一块纯红面板和一块纯蓝面板，把磨砂窗口在两者之间移动，"
                "用 BitBlt 抓 DWM 合成后的画面求平均色。据此判断两件事：磨砂是否真的生效（采样值应偏离面板本色），"
                "以及移动后不做任何处理时磨砂是否仍会跟随重采样。运行时屏幕会短暂出现彩色面板。"),
            compositionGroupBox);
        compositionHintLabel->setWordWrap(true);
        languageManager.bindText(
            compositionHintLabel,
            QStringLiteral("misc.render_benchmark.composition.hint"),
            QStringLiteral("在屏幕上铺一块纯红面板和一块纯蓝面板，把磨砂窗口在两者之间移动，"
                "用 BitBlt 抓 DWM 合成后的画面求平均色。据此判断两件事：磨砂是否真的生效（采样值应偏离面板本色），"
                "以及移动后不做任何处理时磨砂是否仍会跟随重采样。运行时屏幕会短暂出现彩色面板。"));
        compositionLayout->addWidget(compositionHintLabel);

        QHBoxLayout* const compositionActionLayout = new QHBoxLayout();
        compositionActionLayout->setSpacing(6);
        m_runCompositionButton = new QPushButton(QStringLiteral("运行合成探测"), compositionGroupBox);
        languageManager.bindText(
            m_runCompositionButton,
            QStringLiteral("misc.render_benchmark.composition.run"),
            QStringLiteral("运行合成探测"));
        compositionActionLayout->addWidget(m_runCompositionButton);
        compositionActionLayout->addStretch();
        compositionLayout->addLayout(compositionActionLayout);
        rootLayout->addWidget(compositionGroupBox);

        // ===== 测试四：目标窗口响应探针 =====
        QGroupBox* const responseGroupBox = new QGroupBox(QStringLiteral("窗口响应探针"), this);
        languageManager.bindText(
            responseGroupBox,
            QStringLiteral("misc.render_benchmark.response.group"),
            QStringLiteral("窗口响应探针"));
        QVBoxLayout* const responseLayout = new QVBoxLayout(responseGroupBox);
        responseLayout->setSpacing(6);

        QLabel* const responseHintLabel = new QLabel(
            QStringLiteral("对选定窗口连续 SetWindowPos 模拟拖动，每帧用 WM_NULL 往返测它的 UI 线程被阻塞多久——"
                "线程忙着重绘就回不了空消息，往返耗时即卡顿时长。可以测别的进程的窗口。"
                "测试只移动窗口位置，结束后放回原处；最大化的窗口无法移动，请先还原。"),
            responseGroupBox);
        responseHintLabel->setWordWrap(true);
        languageManager.bindText(
            responseHintLabel,
            QStringLiteral("misc.render_benchmark.response.hint"),
            QStringLiteral("对选定窗口连续 SetWindowPos 模拟拖动，每帧用 WM_NULL 往返测它的 UI 线程被阻塞多久——"
                "线程忙着重绘就回不了空消息，往返耗时即卡顿时长。可以测别的进程的窗口。"
                "测试只移动窗口位置，结束后放回原处；最大化的窗口无法移动，请先还原。"));
        responseLayout->addWidget(responseHintLabel);

        QHBoxLayout* const responseTargetLayout = new QHBoxLayout();
        responseTargetLayout->setSpacing(6);
        QLabel* const responseTargetLabel = new QLabel(QStringLiteral("目标窗口"), responseGroupBox);
        languageManager.bindText(
            responseTargetLabel,
            QStringLiteral("misc.render_benchmark.response.target"),
            QStringLiteral("目标窗口"));
        responseTargetLayout->addWidget(responseTargetLabel);
        m_targetWindowCombo = new QComboBox(responseGroupBox);
        m_targetWindowCombo->setMinimumWidth(360);
        responseTargetLayout->addWidget(m_targetWindowCombo, 1);
        m_refreshTargetsButton = new QPushButton(QStringLiteral("刷新窗口列表"), responseGroupBox);
        languageManager.bindText(
            m_refreshTargetsButton,
            QStringLiteral("misc.render_benchmark.response.refresh"),
            QStringLiteral("刷新窗口列表"));
        responseTargetLayout->addWidget(m_refreshTargetsButton);
        responseLayout->addLayout(responseTargetLayout);

        QHBoxLayout* const responseActionLayout = new QHBoxLayout();
        responseActionLayout->setSpacing(6);
        QLabel* const responseFrameLabel = new QLabel(QStringLiteral("模拟帧数"), responseGroupBox);
        languageManager.bindText(
            responseFrameLabel,
            QStringLiteral("misc.render_benchmark.response.frames"),
            QStringLiteral("模拟帧数"));
        responseActionLayout->addWidget(responseFrameLabel);
        m_responseFrameSpin = new QSpinBox(responseGroupBox);
        m_responseFrameSpin->setRange(30, 600);
        m_responseFrameSpin->setValue(120);
        responseActionLayout->addWidget(m_responseFrameSpin);
        m_runResponseButton = new QPushButton(QStringLiteral("运行响应探针"), responseGroupBox);
        languageManager.bindText(
            m_runResponseButton,
            QStringLiteral("misc.render_benchmark.response.run"),
            QStringLiteral("运行响应探针"));
        responseActionLayout->addWidget(m_runResponseButton);
        responseActionLayout->addStretch();
        responseLayout->addLayout(responseActionLayout);
        rootLayout->addWidget(responseGroupBox);

        // ===== 报告区 =====
        QHBoxLayout* const reportActionLayout = new QHBoxLayout();
        reportActionLayout->setSpacing(6);
        QLabel* const reportLabel = new QLabel(QStringLiteral("测试报告"), this);
        languageManager.bindText(
            reportLabel,
            QStringLiteral("misc.render_benchmark.report"),
            QStringLiteral("测试报告"));
        reportActionLayout->addWidget(reportLabel);
        reportActionLayout->addStretch();
        m_copyReportButton = new QPushButton(QStringLiteral("复制报告"), this);
        languageManager.bindText(
            m_copyReportButton,
            QStringLiteral("misc.render_benchmark.report.copy"),
            QStringLiteral("复制报告"));
        reportActionLayout->addWidget(m_copyReportButton);
        m_saveReportButton = new QPushButton(QStringLiteral("导出报告"), this);
        languageManager.bindText(
            m_saveReportButton,
            QStringLiteral("misc.render_benchmark.report.save"),
            QStringLiteral("导出报告"));
        reportActionLayout->addWidget(m_saveReportButton);
        m_clearReportButton = new QPushButton(QStringLiteral("清空报告"), this);
        languageManager.bindText(
            m_clearReportButton,
            QStringLiteral("misc.render_benchmark.report.clear"),
            QStringLiteral("清空报告"));
        reportActionLayout->addWidget(m_clearReportButton);
        rootLayout->addLayout(reportActionLayout);

        m_reportEdit = new CodeTextEdit(this);
        static_cast<CodeTextEdit*>(m_reportEdit)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        m_reportEdit->setReadOnly(true);
        m_reportEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
        m_reportEdit->setMinimumHeight(180);
        rootLayout->addWidget(m_reportEdit, 1);
    }

    void RenderBenchmarkPage::initializeConnections()
    {
        connect(m_runAllButton, &QPushButton::clicked, this, [this]() { runAllBenchmarks(); });
        connect(m_runRepaintButton, &QPushButton::clicked, this, [this]() { runMainWindowRepaintBenchmark(); });
        connect(m_runDragButton, &QPushButton::clicked, this, [this]() { runDragSimulationBenchmark(); });
        connect(m_runCompositionButton, &QPushButton::clicked, this, [this]() { runCompositionProbe(); });
        connect(m_runResponseButton, &QPushButton::clicked, this, [this]() { runWindowResponseProbe(); });
        connect(m_refreshTargetsButton, &QPushButton::clicked, this, [this]() { refreshTargetWindowList(); });
        connect(m_copyReportButton, &QPushButton::clicked, this, [this]() { copyReportToClipboard(); });
        connect(m_saveReportButton, &QPushButton::clicked, this, [this]() { saveReportToFile(); });
        connect(m_clearReportButton, &QPushButton::clicked, this, [this]() { m_reportEdit->clear(); });
    }

    void RenderBenchmarkPage::appendReportLine(const QString& lineText)
    {
        if (m_reportEdit != nullptr)
        {
            m_reportEdit->appendPlainText(lineText);
        }
    }

    void RenderBenchmarkPage::appendReportSection(const QString& titleText)
    {
        appendReportLine(QString());
        appendReportLine(QStringLiteral("=== %1 @ %2 ===")
            .arg(titleText)
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
    }

    void RenderBenchmarkPage::appendSummaryLine(
        const QString& labelText,
        const BenchmarkSampleSummary& summary)
    {
        if (summary.sampleCount <= 0)
        {
            appendReportLine(QStringLiteral("  %1: 无有效样本").arg(labelText));
            return;
        }
        appendReportLine(QStringLiteral("  %1: 平均 %2 ms / p95 %3 ms / 最差 %4 ms / 超预算 %5 of %6 (%7%)")
            .arg(labelText)
            .arg(summary.averageMs, 0, 'f', 2)
            .arg(summary.p95Ms, 0, 'f', 2)
            .arg(summary.worstMs, 0, 'f', 2)
            .arg(summary.overBudgetCount)
            .arg(summary.sampleCount)
            .arg(100.0 * summary.overBudgetCount / summary.sampleCount, 0, 'f', 1));
    }

    void RenderBenchmarkPage::setBusy(const bool busy, const QString& statusText)
    {
        m_busy = busy;
        // 批次运行期间即使单项测试结束也不放开按钮：
        // 两项之间要放行事件循环刷新进度，那一小段时间足够用户点进第二个测试。
        const bool enabled = !busy && !m_batchRunning;
        m_runAllButton->setEnabled(enabled);
        m_runRepaintButton->setEnabled(enabled);
        m_runDragButton->setEnabled(enabled);
        m_runCompositionButton->setEnabled(enabled);
        m_runResponseButton->setEnabled(enabled);
        m_refreshTargetsButton->setEnabled(enabled);
        m_progressBar->setVisible(busy);
        if (!statusText.isEmpty())
        {
            m_statusLabel->setText(statusText);
        }
        else if (!busy)
        {
            m_statusLabel->setText(QStringLiteral("就绪。"));
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }

    void RenderBenchmarkPage::refreshTargetWindowList()
    {
        m_targetWindows.clear();
        WindowEnumerationContext context;
        context.entries = &m_targetWindows;
        context.selfProcessId = ::GetCurrentProcessId();
        ::EnumWindows(enumerateVisibleTopLevelWindow, reinterpret_cast<LPARAM>(&context));

        m_targetWindowCombo->clear();
        int preferredIndex = -1;
        for (int entryIndex = 0; entryIndex < m_targetWindows.size(); ++entryIndex)
        {
            const TargetWindowEntry& entry = m_targetWindows.at(entryIndex);
            m_targetWindowCombo->addItem(entry.displayText, QVariant(entry.windowHandleValue));
            if (entry.belongsToSelf && preferredIndex < 0)
            {
                preferredIndex = entryIndex;
            }
        }
        if (preferredIndex >= 0)
        {
            m_targetWindowCombo->setCurrentIndex(preferredIndex);
        }
    }

    void RenderBenchmarkPage::runMainWindowRepaintBenchmark()
    {
        if (m_busy)
        {
            return;
        }
        appendReportSection(QStringLiteral("主窗口整树重绘"));

        QWidget* const rootContainer = locateMainRootContainer();
        if (rootContainer == nullptr || rootContainer->size().isEmpty())
        {
            appendReportLine(QStringLiteral("  未找到主窗口根容器（ksMainRootContainer），跳过。"));
            return;
        }

        setBusy(true, QStringLiteral("正在测量主窗口重绘..."));
        const int iterationCount = m_repaintIterationSpin->value();

        // 渲染到离屏位图：与真实重绘走同一条绘制路径，但不触碰屏幕像素。
        QPixmap offscreenCanvas(rootContainer->size());
        std::vector<double> fullTreeSamples;
        std::vector<double> backgroundOnlySamples;
        fullTreeSamples.reserve(static_cast<size_t>(iterationCount));
        backgroundOnlySamples.reserve(static_cast<size_t>(iterationCount));

        QElapsedTimer renderTimer;
        for (int iterationIndex = 0; iterationIndex < iterationCount; ++iterationIndex)
        {
            offscreenCanvas.fill(Qt::transparent);
            renderTimer.restart();
            rootContainer->render(
                &offscreenCanvas,
                QPoint(),
                QRegion(),
                QWidget::DrawWindowBackground | QWidget::DrawChildren);
            fullTreeSamples.push_back(static_cast<double>(renderTimer.nsecsElapsed()) / 1e6);

            offscreenCanvas.fill(Qt::transparent);
            renderTimer.restart();
            rootContainer->render(
                &offscreenCanvas,
                QPoint(),
                QRegion(),
                QWidget::RenderFlags(QWidget::DrawWindowBackground));
            backgroundOnlySamples.push_back(static_cast<double>(renderTimer.nsecsElapsed()) / 1e6);

            m_progressBar->setValue((iterationIndex + 1) * 100 / std::max(1, iterationCount));
            QCoreApplication::processEvents(QEventLoop::AllEvents, 2);
        }

        const BenchmarkSampleSummary fullSummary = summarizeSamples(fullTreeSamples);
        const BenchmarkSampleSummary backgroundSummary = summarizeSamples(backgroundOnlySamples);

        appendReportLine(QStringLiteral("  根容器尺寸: %1 x %2，采样 %3 次")
            .arg(rootContainer->width())
            .arg(rootContainer->height())
            .arg(iterationCount));
        appendSummaryLine(QStringLiteral("整树重绘"), fullSummary);
        appendSummaryLine(QStringLiteral("仅背景层"), backgroundSummary);
        appendReportLine(QStringLiteral("  子控件树占用: %1 ms（整树平均 - 背景层平均）")
            .arg(std::max(0.0, fullSummary.averageMs - backgroundSummary.averageMs), 0, 'f', 2));
        appendReportLine(QStringLiteral("  含义: 每让根容器重绘一次，就要付出“整树重绘”这个耗时。"
            "若它超过帧预算 %1 ms，任何按帧触发根容器重绘的逻辑都会造成可见掉帧。")
            .arg(kFrameBudgetMs, 0, 'f', 1));

        setBusy(false);
    }

    void RenderBenchmarkPage::runDragSimulationBenchmark()
    {
        if (m_busy)
        {
            return;
        }
        appendReportSection(QStringLiteral("拖动流畅度 A/B"));
        setBusy(true, QStringLiteral("正在模拟拖动..."));

        const int frameCount = m_dragFrameSpin->value();
        const int rowCount = m_dragRowSpin->value();

        // 复用当前外观配置，保证测出来的是用户真实设置下的成本。
        const ks::settings::AppearanceSettings appearanceSettings = ks::settings::loadAppearanceSettings();
        const QString resolvedImagePath =
            ks::settings::resolveBackgroundImagePathForLoad(appearanceSettings.backgroundImagePath);
        QPixmap backgroundImage;
        if (!resolvedImagePath.isEmpty())
        {
            backgroundImage.load(resolvedImagePath);
        }
        if (backgroundImage.isNull())
        {
            backgroundImage = buildGradientWallpaper(QSize(1920, 1080));
        }

        QScreen* const primaryScreen = QApplication::primaryScreen();
        const QRect availableRect = primaryScreen != nullptr
            ? primaryScreen->availableGeometry()
            : QRect(0, 0, 1280, 720);
        const QSize probeSize(
            std::min(1200, std::max(600, availableRect.width() / 2)),
            std::min(800, std::max(400, availableRect.height() / 2)));

        struct DragScenarioResult
        {
            QString label;
            BenchmarkSampleSummary summary;
        };
        QVector<DragScenarioResult> scenarioResults;

        // 两轮：分别对应“刷新时重绘整树”与“只下发材质不重绘”。
        for (int scenarioIndex = 0; scenarioIndex < 2; ++scenarioIndex)
        {
            const bool repaintOnRefresh = (scenarioIndex == 0);

            QWidget probeWindow;
            probeWindow.setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
            probeWindow.setAttribute(Qt::WA_TranslucentBackground, true);
            probeWindow.setAttribute(Qt::WA_ShowWithoutActivating, true);
            probeWindow.resize(probeSize);

            QVBoxLayout* const probeLayout = new QVBoxLayout(&probeWindow);
            probeLayout->setContentsMargins(0, 0, 0, 0);
            probeLayout->setSpacing(0);

            ProbeBackgroundWidget* const probeBackground = new ProbeBackgroundWidget(
                backgroundImage,
                appearanceSettings.backgroundOpacityPercent,
                &probeWindow);
            probeLayout->addWidget(probeBackground, 1);

            QVBoxLayout* const backgroundLayout = new QVBoxLayout(probeBackground);
            backgroundLayout->setContentsMargins(0, 0, 0, 0);

            QTreeWidget* const probeTree = new QTreeWidget(probeBackground);
            probeTree->setColumnCount(6);
            probeTree->setUniformRowHeights(true);
            probeTree->setHeaderLabels(QStringList()
                << QStringLiteral("名称")
                << QStringLiteral("标识")
                << QStringLiteral("占用")
                << QStringLiteral("路径")
                << QStringLiteral("状态")
                << QStringLiteral("计数"));
            // 与透明模式下的 Dock 内容同构：全部表面透明，父重绘会连带整树重绘。
            probeTree->setStyleSheet(QStringLiteral(
                "QTreeWidget { background: transparent; border: none; }"
                "QTreeWidget::item { background: transparent; }"
                "QHeaderView::section { background: transparent; }"));
            for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex)
            {
                QTreeWidgetItem* const rowItem = new QTreeWidgetItem(probeTree);
                rowItem->setText(0, QStringLiteral("benchmark_row_%1").arg(rowIndex));
                rowItem->setText(1, QString::number(1000 + rowIndex));
                rowItem->setText(2, QStringLiteral("%1 KB").arg((rowIndex * 137) % 900000));
                rowItem->setText(3, QStringLiteral("C:\\Windows\\System32\\benchmark.dll"));
                rowItem->setText(4, QStringLiteral("running"));
                rowItem->setText(5, QString::number((rowIndex * 7) % 4096));
            }
            backgroundLayout->addWidget(probeTree, 1);

            const QPoint startPoint(
                availableRect.left() + 40,
                availableRect.top() + std::max(0, (availableRect.height() - probeSize.height()) / 2));
            probeWindow.move(startPoint);
            probeWindow.show();
            pumpUserInterface(220);

            const HWND probeHandle = reinterpret_cast<HWND>(probeWindow.winId());
            const int acrylicTintAlpha =
                ks::settings::tintAlphaFromOpacityPercent(appearanceSettings.acrylicTintOpacityPercent);
            submitAcrylicAccent(probeHandle, acrylicTintAlpha);
            pumpUserInterface(200);

            const int travelRange = std::max(
                60,
                availableRect.width() - probeSize.width() - 80);
            std::vector<double> frameSamples;
            frameSamples.reserve(static_cast<size_t>(frameCount));

            QElapsedTimer frameTimer;
            bool refreshQueued = false;
            QElapsedTimer throttleTimer;
            throttleTimer.start();

            for (int frameIndex = 0; frameIndex < frameCount; ++frameIndex)
            {
                const int offsetX = (frameIndex % 120) * travelRange / 120;
                frameTimer.restart();
                probeWindow.move(startPoint.x() + offsetX, startPoint.y());

                // 复刻 40ms 节流：拖动期间材质刷新按固定间隔触发。
                if (!refreshQueued && throttleTimer.elapsed() >= 40)
                {
                    refreshQueued = true;
                }
                if (refreshQueued)
                {
                    refreshQueued = false;
                    throttleTimer.restart();
                    submitAcrylicAccent(probeHandle, acrylicTintAlpha);
                    if (repaintOnRefresh)
                    {
                        probeBackground->repaint();
                    }
                }
                QCoreApplication::processEvents(QEventLoop::AllEvents, 4);
                const double busyMs = static_cast<double>(frameTimer.nsecsElapsed()) / 1e6;
                frameSamples.push_back(busyMs);

                if (busyMs < kFrameBudgetMs)
                {
                    ::Sleep(static_cast<DWORD>(kFrameBudgetMs - busyMs));
                }
                m_progressBar->setValue(
                    (scenarioIndex * 50) + (frameIndex + 1) * 50 / std::max(1, frameCount));
            }

            probeWindow.hide();
            pumpUserInterface(120);

            DragScenarioResult scenarioResult;
            scenarioResult.label = repaintOnRefresh
                ? QStringLiteral("刷新时重绘整树")
                : QStringLiteral("只下发材质不重绘");
            scenarioResult.summary = summarizeSamples(frameSamples);
            scenarioResults.push_back(scenarioResult);
        }

        appendReportLine(QStringLiteral("  测试窗口: %1 x %2，表格 %3 行，模拟 %4 帧 @ 60fps")
            .arg(probeSize.width())
            .arg(probeSize.height())
            .arg(rowCount)
            .arg(frameCount));
        for (const DragScenarioResult& scenarioResult : scenarioResults)
        {
            appendSummaryLine(scenarioResult.label, scenarioResult.summary);
        }
        if (scenarioResults.size() == 2
            && scenarioResults.at(0).summary.sampleCount > 0
            && scenarioResults.at(1).summary.sampleCount > 0)
        {
            const double repaintJankRate = 100.0
                * scenarioResults.at(0).summary.overBudgetCount
                / scenarioResults.at(0).summary.sampleCount;
            const double plainJankRate = 100.0
                * scenarioResults.at(1).summary.overBudgetCount
                / scenarioResults.at(1).summary.sampleCount;
            appendReportLine(QStringLiteral("  掉帧率差异: %1% -> %2%")
                .arg(repaintJankRate, 0, 'f', 1)
                .arg(plainJankRate, 0, 'f', 1));
        }

        setBusy(false);
    }

    void RenderBenchmarkPage::runCompositionProbe()
    {
        if (m_busy)
        {
            return;
        }
        appendReportSection(QStringLiteral("DWM 合成能力探测"));

        if (resolveSetWindowCompositionAttribute() == nullptr)
        {
            appendReportLine(QStringLiteral("  本机 user32 未导出 SetWindowCompositionAttribute，无法测试亚克力。"));
            return;
        }

        setBusy(true, QStringLiteral("正在探测 DWM 合成..."));

        QScreen* const primaryScreen = QApplication::primaryScreen();
        const QRect availableRect = primaryScreen != nullptr
            ? primaryScreen->availableGeometry()
            : QRect(0, 0, 1280, 720);
        const int panelWidth = availableRect.width() / 2;
        const int panelHeight = availableRect.height() / 2;
        const int panelTop = availableRect.top() + availableRect.height() / 4;

        // 两块已知纯色作为“窗口后方的内容”，颜色选正红与正蓝，红蓝分量之差足够区分。
        const QColor redPanelColor(220, 20, 20);
        const QColor bluePanelColor(20, 20, 220);
        SolidColorPanel redPanel(redPanelColor);
        redPanel.setGeometry(availableRect.left(), panelTop, panelWidth, panelHeight);
        redPanel.show();
        SolidColorPanel bluePanel(bluePanelColor);
        bluePanel.setGeometry(availableRect.left() + panelWidth, panelTop, panelWidth, panelHeight);
        bluePanel.show();
        pumpUserInterface(200);

        const QSize probeSize(360, 260);
        QWidget acrylicProbe;
        acrylicProbe.setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
        acrylicProbe.setAttribute(Qt::WA_TranslucentBackground, true);
        acrylicProbe.setAttribute(Qt::WA_ShowWithoutActivating, true);
        acrylicProbe.resize(probeSize);

        const QPoint overRedPoint(
            availableRect.left() + panelWidth / 2 - probeSize.width() / 2,
            panelTop + panelHeight / 2 - probeSize.height() / 2);
        const QPoint overBluePoint(
            availableRect.left() + panelWidth + panelWidth / 2 - probeSize.width() / 2,
            panelTop + panelHeight / 2 - probeSize.height() / 2);

        acrylicProbe.move(overRedPoint);
        acrylicProbe.show();
        pumpUserInterface(220);

        const HWND probeHandle = reinterpret_cast<HWND>(acrylicProbe.winId());
        // 着色 alpha 压低，让后方面板颜色在采样里占主导，否则测的就是着色层自己。
        const bool accentApplied = submitAcrylicAccent(probeHandle, 24);
        pumpUserInterface(500);
        m_progressBar->setValue(30);

        const ScreenAreaSample overRedSample = sampleScreenArea(probeHandle, 0.20);

        // 移动到蓝区后什么都不做：这一步就是在问“DWM 会不会自己重采样”。
        acrylicProbe.move(overBluePoint);
        pumpUserInterface(600);
        m_progressBar->setValue(70);
        const ScreenAreaSample overBlueSample = sampleScreenArea(probeHandle, 0.20);

        acrylicProbe.hide();
        redPanel.hide();
        bluePanel.hide();
        pumpUserInterface(120);
        m_progressBar->setValue(100);

        appendReportLine(QStringLiteral("  组合特性下发: %1")
            .arg(accentApplied ? QStringLiteral("成功") : QStringLiteral("失败")));
        if (!overRedSample.valid || !overBlueSample.valid)
        {
            appendReportLine(QStringLiteral("  屏幕采样失败，无法判定。"));
            setBusy(false);
            return;
        }

        const double redBias = overRedSample.redAverage - overRedSample.blueAverage;
        const double blueBias = overBlueSample.redAverage - overBlueSample.blueAverage;
        appendReportLine(QStringLiteral("  红面板上方采样: R %1 / G %2 / B %3，R-B %4")
            .arg(overRedSample.redAverage, 0, 'f', 1)
            .arg(overRedSample.greenAverage, 0, 'f', 1)
            .arg(overRedSample.blueAverage, 0, 'f', 1)
            .arg(redBias, 0, 'f', 1));
        appendReportLine(QStringLiteral("  蓝面板上方采样: R %1 / G %2 / B %3，R-B %4")
            .arg(overBlueSample.redAverage, 0, 'f', 1)
            .arg(overBlueSample.greenAverage, 0, 'f', 1)
            .arg(overBlueSample.blueAverage, 0, 'f', 1)
            .arg(blueBias, 0, 'f', 1));

        // 采样值明显偏离面板本色，说明经过了亚克力的着色与亮度处理而非直接透过。
        const double redDeviation = std::abs(overRedSample.redAverage - redPanelColor.red());
        const bool acrylicEffective = accentApplied && redDeviation > 5.0;
        appendReportLine(QStringLiteral("  磨砂是否生效: %1（红面板本色 R %2，采样 R %3，偏离 %4）")
            .arg(acrylicEffective ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(redPanelColor.red())
            .arg(overRedSample.redAverage, 0, 'f', 1)
            .arg(redDeviation, 0, 'f', 1));

        const bool resampled = (redBias > 10.0) && (blueBias < -10.0);
        appendReportLine(QStringLiteral("  移动后自动重采样: %1")
            .arg(resampled ? QStringLiteral("是") : QStringLiteral("否")));
        appendReportLine(resampled
            ? QStringLiteral("  含义: 窗口移动后无需重下发组合特性，也无需重绘，DWM 会自行跟随。"
                "按帧刷新材质只会白白付出重绘代价。")
            : QStringLiteral("  含义: 本机 DWM 不会自动跟随窗口位置重采样，"
                "移动结束后需要补下发一次组合特性才能拿到正确画面。"));

        setBusy(false);
    }

    void RenderBenchmarkPage::runWindowResponseProbe()
    {
        if (m_busy)
        {
            return;
        }
        appendReportSection(QStringLiteral("窗口响应探针"));

        if (m_targetWindowCombo->currentIndex() < 0)
        {
            appendReportLine(QStringLiteral("  没有可用的目标窗口，请先刷新窗口列表。"));
            return;
        }
        const quint64 handleValue = m_targetWindowCombo->currentData().toULongLong();
        HWND targetHandle = reinterpret_cast<HWND>(handleValue);
        if (targetHandle == nullptr || ::IsWindow(targetHandle) == FALSE)
        {
            appendReportLine(QStringLiteral("  目标窗口已失效，请刷新窗口列表后重试。"));
            return;
        }
        if (::IsZoomed(targetHandle) != FALSE)
        {
            appendReportLine(QStringLiteral("  目标窗口处于最大化状态，无法移动。请先还原窗口再测。"));
            return;
        }

        RECT originRect{};
        if (::GetWindowRect(targetHandle, &originRect) == FALSE)
        {
            appendReportLine(QStringLiteral("  读取目标窗口位置失败，跳过。"));
            return;
        }

        setBusy(true, QStringLiteral("正在探测窗口响应..."));
        const int frameCount = m_responseFrameSpin->value();
        const int originX = originRect.left;
        const int originY = originRect.top;

        // 先测静止基线：把“这个窗口本来就慢”和“移动导致的卡顿”区分开。
        std::vector<double> idleSamples;
        for (int idleIndex = 0; idleIndex < 30; ++idleIndex)
        {
            idleSamples.push_back(probeWindowResponseMs(targetHandle, 200));
            ::Sleep(10);
            QCoreApplication::processEvents(QEventLoop::AllEvents, 2);
        }

        std::vector<double> movingSamples;
        movingSamples.reserve(static_cast<size_t>(frameCount));
        QElapsedTimer frameTimer;
        for (int frameIndex = 0; frameIndex < frameCount; ++frameIndex)
        {
            frameTimer.restart();
            const int offsetX = (frameIndex % 60) * 4;
            ::SetWindowPos(
                targetHandle,
                nullptr,
                originX + offsetX,
                originY,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            movingSamples.push_back(probeWindowResponseMs(targetHandle, 500));
            const double spentMs = static_cast<double>(frameTimer.nsecsElapsed()) / 1e6;
            if (spentMs < kFrameBudgetMs)
            {
                ::Sleep(static_cast<DWORD>(kFrameBudgetMs - spentMs));
            }
            m_progressBar->setValue((frameIndex + 1) * 100 / std::max(1, frameCount));
            QCoreApplication::processEvents(QEventLoop::AllEvents, 2);
        }

        // 无论测量结果如何都要把窗口放回去：这是别人的窗口。
        ::SetWindowPos(
            targetHandle,
            nullptr,
            originX,
            originY,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

        appendReportLine(QStringLiteral("  目标: %1").arg(m_targetWindowCombo->currentText()));
        appendSummaryLine(QStringLiteral("静止基线"), summarizeSamples(idleSamples));
        appendSummaryLine(QStringLiteral("移动期间"), summarizeSamples(movingSamples));
        appendReportLine(QStringLiteral("  含义: 往返耗时即目标窗口 UI 线程被阻塞的时长；"
            "移动期间显著高于静止基线，说明它在按窗口位置做重绘。"));
        appendReportLine(QStringLiteral("  窗口已放回原位置 %1,%2").arg(originX).arg(originY));

        setBusy(false);
    }

    void RenderBenchmarkPage::runAllBenchmarks()
    {
        if (m_busy || m_batchRunning)
        {
            return;
        }
        m_batchRunning = true;
        appendReportSection(QStringLiteral("完整基准"));
        appendReportLine(QStringLiteral("  开始时间: %1")
            .arg(QDateTime::currentDateTime().toString(Qt::ISODate)));

        runMainWindowRepaintBenchmark();
        pumpUserInterface(150);
        runDragSimulationBenchmark();
        pumpUserInterface(150);
        runCompositionProbe();
        pumpUserInterface(150);
        runWindowResponseProbe();

        appendReportLine(QString());
        appendReportLine(QStringLiteral("完整基准结束。"));

        // 批次标志必须在最后一次 setBusy 之后清掉，否则按钮不会重新启用。
        m_batchRunning = false;
        setBusy(false);
    }

    void RenderBenchmarkPage::copyReportToClipboard()
    {
        QClipboard* const clipboard = QApplication::clipboard();
        if (clipboard != nullptr && m_reportEdit != nullptr)
        {
            clipboard->setText(m_reportEdit->toPlainText());
            m_statusLabel->setText(QStringLiteral("报告已复制到剪贴板。"));
        }
    }

    void RenderBenchmarkPage::saveReportToFile()
    {
        if (m_reportEdit == nullptr)
        {
            return;
        }
        const QString targetPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出渲染基准报告"),
            QStringLiteral("ksword_render_benchmark.txt"),
            QStringLiteral("Text (*.txt)"));
        if (targetPath.isEmpty())
        {
            return;
        }
        QFile reportFile(targetPath);
        if (!reportFile.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            m_statusLabel->setText(QStringLiteral("导出失败：无法写入所选路径。"));
            return;
        }
        QTextStream reportStream(&reportFile);
        reportStream << m_reportEdit->toPlainText();
        reportFile.close();
        m_statusLabel->setText(QStringLiteral("报告已导出。"));
    }
}
