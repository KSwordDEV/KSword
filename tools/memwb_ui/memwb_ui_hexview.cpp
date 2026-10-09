// memwb_ui_hexview.cpp
// 作用：HexView 离屏夹具的公共设施实现（设置重定向、事件泵、夹具构造、朴素查找）与总入口 RunHexViewTests。
// 见 memwb_ui_hexview.h。

#include "memwb_ui_hexview.h"

#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QMenu>
#include <QThread>

#include <iostream>

namespace memwb_test
{
    // 构造：重定向默认 QSettings。
    SettingsRedirect::SettingsRedirect()
    {
        // 记下原状以便恢复；组织名与应用名必须非空，否则默认 QSettings 没有存储位置。
        m_previousFormat = QSettings::defaultFormat();
        m_previousOrganization = QCoreApplication::organizationName();
        m_previousApplication = QCoreApplication::applicationName();
        QCoreApplication::setOrganizationName(QStringLiteral("KswordMemwbTest"));
        QCoreApplication::setApplicationName(QStringLiteral("hexview"));
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_dir.path());
        Reset();
    }

    // 析构：恢复。
    SettingsRedirect::~SettingsRedirect()
    {
        QSettings::setDefaultFormat(m_previousFormat);
        QCoreApplication::setOrganizationName(m_previousOrganization);
        QCoreApplication::setApplicationName(m_previousApplication);
    }

    // 清空全部键并写盘。
    void SettingsRedirect::Reset()
    {
        QSettings settings;
        settings.clear();
        settings.sync();
    }

    // INI 路径：默认 QSettings 的实际文件位置。
    QString SettingsRedirect::iniPath() const
    {
        const QSettings settings;
        return settings.fileName();
    }

    // 泵事件直到条件成立。
    bool PumpUntil(const std::function<bool()>& condition, int timeoutMs)
    {
        QElapsedTimer timer;
        timer.start();
        while (!condition())
        {
            if (timer.elapsed() > timeoutMs)
            {
                return condition();
            }
            QApplication::processEvents(QEventLoop::AllEvents, 10);
            QThread::msleep(2);
        }
        return true;
    }

    // 泵事件一段时间。
    void PumpFor(int milliseconds)
    {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < milliseconds)
        {
            QApplication::processEvents(QEventLoop::AllEvents, 10);
            QThread::msleep(2);
        }
    }

    // 激活窗口。
    bool ActivateWindow(QWidget* window)
    {
        window->show();
        window->activateWindow();
        window->raise();
        return QTest::qWaitForWindowActive(window, 2000);
    }

    // 构造并显示。
    std::unique_ptr<ks::ui::HexView> MakeHexView(
        std::uint64_t base,
        const QByteArray& data,
        bool editable,
        const QSize& size)
    {
        auto view = std::make_unique<ks::ui::HexView>();
        view->resize(size);
        view->show();
        view->setBuffer(base, data);
        view->setEditable(editable);
        QApplication::processEvents();
        return view;
    }

    // 菜单像素检查：弹出、抓图、取内边距处像素。
    bool MenuPaintsSurface(QMenu* menu)
    {
        menu->popup(QPoint(40, 40));
        Flush();
        const QImage image = menu->grab().toImage().convertToFormat(QImage::Format_ARGB32);
        menu->hide();
        Flush();
        if (image.width() < 8 || image.height() < 8)
        {
            return false;
        }

        // 菜单样式是 border:1px + padding:3px：(2,2) 与右下角内侧都落在内边距里，应是表面色且完全不透明。
        const QRgb topLeft = image.pixel(2, 2);
        const QRgb bottomRight = image.pixel(image.width() - 3, image.height() - 3);
        const QColor surface = KswordTheme::SurfaceColor();
        return qAlpha(topLeft) == 255 && qAlpha(bottomRight) == 255
            && ColorsClose(QColor(topLeft), surface, 4) && ColorsClose(QColor(bottomRight), surface, 4);
    }

    // 单元格状态。
    ks::ui::HexCanvas::CellState CellOf(ks::ui::HexView& view, std::uint64_t address)
    {
        return view.canvas()->cellStateAt(address);
    }

    // 朴素查找：O(N*L) 的双重循环，只为给被测引擎当对照。
    std::vector<std::uint64_t> NaiveMatches(
        const QByteArray& data,
        std::uint64_t base,
        const QByteArray& needle,
        const QByteArray& mask)
    {
        std::vector<std::uint64_t> hits;
        if (needle.isEmpty() || data.size() < needle.size())
        {
            return hits;
        }
        for (qsizetype start = 0; start + needle.size() <= data.size(); ++start)
        {
            bool match = true;
            for (qsizetype column = 0; column < needle.size(); ++column)
            {
                const std::uint8_t maskByte = mask.isEmpty() ? 0xFF : static_cast<std::uint8_t>(mask.at(column));
                const std::uint8_t dataByte = static_cast<std::uint8_t>(data.at(start + column));
                const std::uint8_t needleByte = static_cast<std::uint8_t>(needle.at(column));
                if ((dataByte & maskByte) != (needleByte & maskByte))
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                hits.push_back(base + static_cast<std::uint64_t>(start));
            }
        }
        return hits;
    }

    // 总入口：设置重定向在整个 HexView 验证期间有效。
    void RunHexViewTests(const QString& shotsDir)
    {
        const int checksBefore = g_checks;
        const int failuresBefore = g_failures;
        SettingsRedirect redirect;
        ApplyTheme(false);

        RunHexViewCoreTests();
        RunHexViewHostTests();
        RunHexViewCompatTests();
        RunHexViewReferenceTests();
        RunHexViewFindTests();
        RunHexViewFindLogicTests();
        RunHexViewGotoTests();
        RunHexViewExportTests();
        RunHexViewShots(shotsDir);

        std::cout << "hexview: " << (g_checks - checksBefore) << " checks, "
                  << (g_failures - failuresBefore) << " failures" << std::endl;
    }
}
