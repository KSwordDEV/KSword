#include "DesktopDrawingPage.h"

#include "../../Internationalization/LanguageManager.h"
#include "../../UI/ThemeStatusRole.h"

#include <QApplication>
#include <QColorDialog>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

namespace
{
    constexpr int kStopHotkeyId = 0x4B44;

    QSpinBox* makeSpin(QWidget* parent, int minimum, int maximum, int value)
    {
        auto* spin = new QSpinBox(parent);
        spin->setRange(minimum, maximum);
        spin->setValue(value);
        spin->setKeyboardTracking(false);
        return spin;
    }
}

namespace ks::misc
{
    DesktopDrawingPage::DesktopDrawingPage(QWidget* parent) : QWidget(parent)
    {
        initializeUi();
        m_timer = new QTimer(this);
        m_timer->setTimerType(Qt::PreciseTimer);
        connect(m_timer, &QTimer::timeout, this, &DesktopDrawingPage::drawFrame);
        connect(qApp, &QCoreApplication::aboutToQuit, this, &DesktopDrawingPage::stopDrawing);
        qApp->installNativeEventFilter(this);
        refreshDisplays();
    }

    DesktopDrawingPage::~DesktopDrawingPage()
    {
        stopDrawing();
        if (qApp)
        {
            qApp->removeNativeEventFilter(this);
        }
    }

    void DesktopDrawingPage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(12, 12, 12, 12);
        root->setSpacing(10);

        auto* scroll = new QScrollArea(this);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        m_settings = new QWidget(scroll);
        auto* form = new QFormLayout(m_settings);
        form->setContentsMargins(0, 0, 0, 0);
        form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        auto addRow = [&](const QString& key, const QString& text, QWidget* control)
            {
                auto* label = new QLabel(m_settings);
                language.bindText(label, key, text);
                label->setBuddy(control);
                form->addRow(label, control);
            };

        m_displayCombo = new QComboBox(m_settings);
        m_displayCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        m_displayCombo->setMinimumContentsLength(20);
        addRow(QStringLiteral("misc.desktop_drawing.display"), QStringLiteral("绘制显示器"), m_displayCombo);
        auto* refresh = new QPushButton(m_settings);
        language.bindText(refresh, QStringLiteral("misc.desktop_drawing.refresh"), QStringLiteral("刷新显示器"));
        form->addRow(QString(), refresh);

        m_patternCombo = new QComboBox(m_settings);
        auto addPattern = [&](desktop_drawing::Pattern pattern, const QString& key, const QString& text)
            {
                const int index = m_patternCombo->count();
                m_patternCombo->addItem(text, static_cast<int>(pattern));
                language.bindComboBoxItem(m_patternCombo, index, key, text);
            };
        addPattern(desktop_drawing::Pattern::Cross, QStringLiteral("misc.desktop_drawing.cross"), QStringLiteral("十字准星"));
        addPattern(desktop_drawing::Pattern::Circle, QStringLiteral("misc.desktop_drawing.circle"), QStringLiteral("圆环"));
        addPattern(desktop_drawing::Pattern::Rectangle, QStringLiteral("misc.desktop_drawing.rectangle"), QStringLiteral("矩形边框"));
        addPattern(desktop_drawing::Pattern::Diamond, QStringLiteral("misc.desktop_drawing.diamond"), QStringLiteral("菱形"));
        addPattern(desktop_drawing::Pattern::Star, QStringLiteral("misc.desktop_drawing.star"), QStringLiteral("五角星"));
        m_patternCombo->setCurrentIndex(4);
        addRow(QStringLiteral("misc.desktop_drawing.pattern"), QStringLiteral("绘制图案"), m_patternCombo);

        m_xSpin = makeSpin(m_settings, 0, 0, 0);
        m_ySpin = makeSpin(m_settings, 0, 0, 0);
        m_sizeSpin = makeSpin(m_settings, 16, 1024, 160);
        m_lineWidthSpin = makeSpin(m_settings, 1, 32, 3);
        m_rateSpin = makeSpin(m_settings, 5, 120, 30);
        addRow(QStringLiteral("misc.desktop_drawing.x"), QStringLiteral("中心横坐标（物理像素）"), m_xSpin);
        addRow(QStringLiteral("misc.desktop_drawing.y"), QStringLiteral("中心纵坐标（物理像素）"), m_ySpin);
        auto* center = new QPushButton(m_settings);
        language.bindText(center, QStringLiteral("misc.desktop_drawing.center"), QStringLiteral("居中到所选显示器"));
        form->addRow(QString(), center);
        addRow(QStringLiteral("misc.desktop_drawing.size"), QStringLiteral("图案尺寸（物理像素）"), m_sizeSpin);
        addRow(QStringLiteral("misc.desktop_drawing.line_width"), QStringLiteral("线条宽度（物理像素）"), m_lineWidthSpin);
        addRow(QStringLiteral("misc.desktop_drawing.rate"), QStringLiteral("每秒重绘次数"), m_rateSpin);
        m_colorButton = new QPushButton(m_settings);
        updateColorButton();
        addRow(QStringLiteral("misc.desktop_drawing.color"), QStringLiteral("图案颜色"), m_colorButton);
        scroll->setWidget(m_settings);
        root->addWidget(scroll, 1);

        auto* actions = new QHBoxLayout;
        m_startButton = new QPushButton(this);
        m_stopButton = new QPushButton(this);
        language.bindText(m_startButton, QStringLiteral("misc.desktop_drawing.start"), QStringLiteral("开始绘制"));
        language.bindText(m_stopButton, QStringLiteral("misc.desktop_drawing.stop"), QStringLiteral("停止并刷新"));
        m_stopButton->setEnabled(false);
        actions->addWidget(m_startButton);
        actions->addWidget(m_stopButton);
        actions->addStretch();
        root->addLayout(actions);
        m_hotkeyLabel = new QLabel(this);
        m_hotkeyLabel->setWordWrap(true);
        language.bindText(m_hotkeyLabel, QStringLiteral("misc.desktop_drawing.hotkey"),
            QStringLiteral("按 Ctrl+Alt+F10 停止绘制。"));
        root->addWidget(m_hotkeyLabel);
        m_statusLabel = new QLabel(this);
        m_statusLabel->setWordWrap(true);
        language.bindText(m_statusLabel, QStringLiteral("misc.desktop_drawing.idle"), QStringLiteral("尚未开始绘制。"));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Idle);
        root->addWidget(m_statusLabel);

        connect(refresh, &QPushButton::clicked, this, &DesktopDrawingPage::refreshDisplays);
        connect(center, &QPushButton::clicked, this, &DesktopDrawingPage::updateCoordinates);
        connect(m_displayCombo, &QComboBox::currentIndexChanged, this, &DesktopDrawingPage::updateCoordinates);
        connect(m_colorButton, &QPushButton::clicked, this, &DesktopDrawingPage::chooseColor);
        connect(m_startButton, &QPushButton::clicked, this, &DesktopDrawingPage::startDrawing);
        connect(m_stopButton, &QPushButton::clicked, this, &DesktopDrawingPage::stopDrawing);
    }

    void DesktopDrawingPage::refreshDisplays()
    {
        stopDrawing();
        const QString previous = m_displayCombo->currentData().toString();
        const QSignalBlocker blocker(m_displayCombo);
        m_displays = desktop_drawing::enumerateDisplays();
        m_displayCombo->clear();
        for (const auto& display : m_displays)
        {
            const QString name = QString::fromStdWString(display.name);
            m_displayCombo->addItem(QStringLiteral("%1  (%2 x %3)").arg(name)
                .arg(display.bounds.right - display.bounds.left)
                .arg(display.bounds.bottom - display.bounds.top), name);
        }
        const int previousIndex = m_displayCombo->findData(previous);
        if (previousIndex >= 0)
        {
            m_displayCombo->setCurrentIndex(previousIndex);
        }
        updateCoordinates();
        m_startButton->setEnabled(!m_displays.empty());
        if (m_displays.empty())
        {
            showFailure(desktop_drawing::DrawResult::DisplayChanged);
        }
    }

    void DesktopDrawingPage::updateCoordinates()
    {
        const int index = m_displayCombo->currentIndex();
        if (index < 0 || index >= static_cast<int>(m_displays.size()))
        {
            return;
        }
        const RECT& bounds = m_displays[index].bounds;
        m_xSpin->setRange(0, bounds.right - bounds.left - 1);
        m_ySpin->setRange(0, bounds.bottom - bounds.top - 1);
        m_xSpin->setValue((bounds.right - bounds.left) / 2);
        m_ySpin->setValue((bounds.bottom - bounds.top) / 2);
    }

    void DesktopDrawingPage::chooseColor()
    {
        const QColor color = QColorDialog::getColor(m_color, this,
            ks::i18n::text(QStringLiteral("misc.desktop_drawing.color"), QStringLiteral("图案颜色")));
        if (color.isValid())
        {
            m_color = color;
            updateColorButton();
        }
    }

    void DesktopDrawingPage::updateColorButton()
    {
        QPixmap swatch(20, 20);
        swatch.fill(m_color);
        m_colorButton->setIcon(QIcon(swatch));
        m_colorButton->setText(m_color.name(QColor::HexRgb));
    }

    void DesktopDrawingPage::startDrawing()
    {
        if (m_timer->isActive())
        {
            return;
        }
        const int index = m_displayCombo->currentIndex();
        if (index < 0 || index >= static_cast<int>(m_displays.size()))
        {
            showFailure(desktop_drawing::DrawResult::DisplayChanged);
            return;
        }
        desktop_drawing::Options options;
        options.display = m_displays[index];
        options.pattern = static_cast<desktop_drawing::Pattern>(m_patternCombo->currentData().toInt());
        options.x = m_xSpin->value();
        options.y = m_ySpin->value();
        options.size = m_sizeSpin->value();
        options.lineWidth = m_lineWidthSpin->value();
        options.color = RGB(m_color.red(), m_color.green(), m_color.blue());
        const auto result = m_renderer.start(options);
        if (result != desktop_drawing::DrawResult::Success)
        {
            showFailure(result);
            return;
        }
        // nullptr 将热键关联到当前线程消息队列，不需要为绘制创建窗口。
        m_hotkeyRegistered = ::RegisterHotKey(nullptr, kStopHotkeyId,
            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, VK_F10) != FALSE;
        auto& language = ks::i18n::LanguageManager::instance();
        if (m_hotkeyRegistered)
        {
            language.bindText(m_hotkeyLabel, QStringLiteral("misc.desktop_drawing.hotkey"),
                QStringLiteral("按 Ctrl+Alt+F10 停止绘制。"));
        }
        else
        {
            language.bindText(m_hotkeyLabel, QStringLiteral("misc.desktop_drawing.hotkey_unavailable"),
                QStringLiteral("快捷键不可用，请使用“停止并刷新”。"));
        }
        ks::ui::ApplyStatusRole(m_hotkeyLabel, m_hotkeyRegistered ? ks::ui::StatusRole::None : ks::ui::StatusRole::Warning);
        m_timer->start((1000 + m_rateSpin->value() - 1) / m_rateSpin->value());
        setRunning(true);
        language.bindText(m_statusLabel, QStringLiteral("misc.desktop_drawing.running"),
            QStringLiteral("正在绘制。"));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Info);
    }

    void DesktopDrawingPage::stopDrawing()
    {
        const bool wasRunning = m_timer && m_timer->isActive();
        if (m_timer)
        {
            m_timer->stop();
        }
        if (m_hotkeyRegistered)
        {
            ::UnregisterHotKey(nullptr, kStopHotkeyId);
            m_hotkeyRegistered = false;
        }
        m_renderer.stop();
        setRunning(false);
        if (wasRunning)
        {
            ks::i18n::LanguageManager::instance().bindText(m_statusLabel,
                QStringLiteral("misc.desktop_drawing.stopped"), QStringLiteral("已停止绘制。"));
            ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Idle);
        }
    }

    void DesktopDrawingPage::setRunning(bool running)
    {
        m_settings->setEnabled(!running);
        m_startButton->setEnabled(!running && !m_displays.empty());
        m_stopButton->setEnabled(running);
    }

    void DesktopDrawingPage::drawFrame()
    {
        const auto result = m_renderer.drawFrame();
        if (result != desktop_drawing::DrawResult::Success)
        {
            stopDrawing();
            showFailure(result);
        }
    }

    void DesktopDrawingPage::showFailure(desktop_drawing::DrawResult result)
    {
        auto& language = ks::i18n::LanguageManager::instance();
        if (result == desktop_drawing::DrawResult::DesktopUnavailable)
        {
            language.bindText(m_statusLabel, QStringLiteral("misc.desktop_drawing.desktop_unavailable"),
                QStringLiteral("桌面已切换，绘制已停止。"));
        }
        else if (result == desktop_drawing::DrawResult::DisplayChanged)
        {
            language.bindText(m_statusLabel, QStringLiteral("misc.desktop_drawing.display_changed"),
                QStringLiteral("显示器不可用或布局已变化。请刷新显示器后重新开始。"));
        }
        else
        {
            language.bindText(m_statusLabel, QStringLiteral("misc.desktop_drawing.failed"),
                QStringLiteral("绘制失败，请重新开始。"));
        }
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Warning);
    }

    bool DesktopDrawingPage::nativeEventFilter(const QByteArray&, void* message, qintptr* result)
    {
        const auto* native = static_cast<const MSG*>(message);
        if (!native)
        {
            return false;
        }
        if (native->message == WM_HOTKEY && native->wParam == kStopHotkeyId && m_hotkeyRegistered)
        {
            stopDrawing();
            if (result)
            {
                *result = 0;
            }
            return true;
        }
        if (native->message == WM_DISPLAYCHANGE)
        {
            const bool wasRunning = m_timer->isActive();
            stopDrawing();
            if (wasRunning)
            {
                showFailure(desktop_drawing::DrawResult::DisplayChanged);
            }
        }
        return false;
    }
}
