// Production dialog constructor, general-page UI and theme functions are
// extracted at build time. Only data providers/actions are replaced with
// inert typed samples. No target file, process, driver or clipboard is used.
#include "../Ksword5.1/Ksword5.1/FileDock/FilePropertyView.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../Ksword5.1/Ksword5.1/UI/UI_All.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QDesktopServices>
#include <QDialog>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QFileIconProvider>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSet>
#include <QStackedWidget>
#include <QStyle>
#include <QTabBar>
#include <QTabWidget>
#include <QTest>
#include <QToolButton>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <memory>

using file_dock_detail::FilePropertyView;
using file_dock_detail::PropertyDocument;

namespace
{
    unsigned checks = 0;
    void require(const bool condition, const char* message)
    {
        ++checks;
        if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
    }
    void flush()
    {
        QCoreApplication::processEvents();
        QTest::qWait(20);
        QCoreApplication::processEvents();
    }
    PropertyDocument sampleProperties()
    {
        PropertyDocument document;
        document.section(QStringLiteral("路径"))
            .field(QStringLiteral("Win32 路径"), QStringLiteral("C:\\Tools\\KSword\\KSword.exe"))
            .field(QStringLiteral("NT 路径"), QStringLiteral("\\Device\\HarddiskVolume3\\Tools\\KSword\\KSword.exe"))
            .field(QStringLiteral("查询来源"), QStringLiteral("R3 QFileInfo + R0 KswordARK"), true);
        document.section(QStringLiteral("基本信息"))
            .field(QStringLiteral("文件名"), QStringLiteral("KSword.exe"))
            .field(QStringLiteral("扩展名"), QStringLiteral("exe"))
            .field(QStringLiteral("大小"), QStringLiteral("12.40 MB (13,008,896 bytes)"))
            .field(QStringLiteral("创建时间"), QStringLiteral("2026-10-06 14:22:10"))
            .field(QStringLiteral("修改时间"), QStringLiteral("2026-10-07 18:11:03"))
            .field(QStringLiteral("访问时间"), QStringLiteral("2026-10-08 20:58:17"))
            .field(QStringLiteral("可执行"), QStringLiteral("是"), true)
            .field(QStringLiteral("隐藏"), QStringLiteral("否"), true)
            .field(QStringLiteral("可写"), QStringLiteral("是"), true)
            .field(QStringLiteral("重解析点"), QStringLiteral("否"), true);
        document.section(QStringLiteral("内核视图（R0）"))
            .field(QStringLiteral("大小（EndOfFile）"), QStringLiteral("12.40 MB"))
            .field(QStringLiteral("磁盘占用（分配大小）"), QStringLiteral("12.41 MB"))
            .field(QStringLiteral("FileObject"), QStringLiteral("0xFFFF9FBE10A80120"));
        document.section(QStringLiteral("文件属性位"))
            .field(QStringLiteral("属性"), QStringLiteral("0x00000020"))
            .field(QStringLiteral("FILE_ATTRIBUTE_ARCHIVE"), QStringLiteral("归档"), true);
        return document;
    }

#include "native-dialog-helpers.inc"

    class FileDetailDialogFixture final : public QDialog
    {
    public:
#include "native-dialog-members.inc"
        FilePropertyView* propertyView() const { return m_generalPropertyView; }
        void restyle() { applyThemeStyle(); }
        QTabWidget* tabs() const { return m_tabWidget; }
    private:
        void refreshGeneralTab() { m_generalPropertyView->setDocument(sampleProperties()); }
        QWidget* buildHashTab() { return buildDeferredTab(QStringLiteral("hash")); }
        QWidget* buildDeferredTab(const QString& key)
        {
            auto* page = new QWidget(this);
            page->setProperty("fixture_page_key", key);
            return page;
        }
        void activateDeferredTab(QTabWidget*, int) {}
        void discardPendingChanges() {}
        void saveAllPendingChanges() {}
        QStringList m_filePaths;
        QString m_filePath;
        bool m_batchMode = false;
        QString m_initialTabKey;
        std::shared_ptr<std::atomic_bool> m_hashCancelRequested;
        std::shared_ptr<std::atomic_bool> m_usageScanCancelRequested;
        QWidget* m_tabNavigation = nullptr;
        QTabWidget* m_tabWidget = nullptr;
        QButtonGroup* m_tabNavigationButtonGroup = nullptr;
        QList<QToolButton*> m_tabNavigationButtons;
        QCheckBox* m_backupBeforeSaveCheck = nullptr;
        QLabel* m_pendingChangesLabel = nullptr;
        QPushButton* m_discardPendingButton = nullptr;
        QPushButton* m_saveAllButton = nullptr;
        bool m_themeStyleApplying = false;
        FilePropertyView* m_generalPropertyView = nullptr;
    };
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    application.setFont(QFont(QStringLiteral("Microsoft YaHei"), 10));
    QString error;
    require(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"), &error), "real language initialization");
    const QString output = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    require(!output.isEmpty() && QDir().mkpath(output), "owned screenshot output");
    for (const bool dark : {false, true})
    {
        KswordTheme::SetDarkModeEnabled(dark);
        application.setPalette(buildFileDetailDialogPalette(nullptr));
        application.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
        FileDetailDialogFixture dialog(QStringList{QStringLiteral("C:\\Tools\\KSword\\KSword.exe")});
        dialog.setAttribute(Qt::WA_DeleteOnClose, false);
        dialog.propertyView()->setPresentation(FilePropertyView::Presentation::Sections);
        dialog.show();
        flush();
        require(dialog.tabs()->count() == 14, "actual constructor preserves all 14 tabs");
        require(!dialog.tabs()->tabBar()->isVisible(), "tabs use actual sidebar navigation");
        auto* navigation = dialog.findChild<QWidget*>(QStringLiteral("FileDetailTabNavigation"));
        require(navigation != nullptr && navigation->findChildren<QToolButton*>().size() == 14,
            "actual constructor has all 14 navigation buttons");
        for (const auto size : {QSize(1160, 800), QSize(800, 640), QSize(640, 480)})
        {
            dialog.resize(size);
            flush();
            require(dialog.size() == size, "actual shell can resize without content expanding it");
            require(dialog.propertyView()->width() > 0 && dialog.propertyView()->width() < size.width(), "native content fits beside navigation");
            auto* scroll = dialog.findChild<QScrollArea*>(QStringLiteral("FileDetailNavigationScroll"));
            require(scroll != nullptr, "actual sidebar scroll is present");
            if (size.height() == 480) require(scroll->verticalScrollBar()->maximum() > 0, "small dialog scroll exposes all tabs");
            const QString name = QStringLiteral("file-properties-%1-%2x%3.png")
                .arg(dark ? QStringLiteral("dark") : QStringLiteral("light"))
                .arg(size.width()).arg(size.height());
            require(dialog.grab().save(QDir(output).filePath(name)), "actual shell preview saved");
        }
        dialog.resize(800, 640);
        dialog.propertyView()->setPresentation(FilePropertyView::Presentation::Tree);
        flush();
        require(dialog.grab().save(QDir(output).filePath(dark ? QStringLiteral("file-properties-dark-tree.png") :
            QStringLiteral("file-properties-light-tree.png"))), "actual tree style shell saved");
        auto longDocument = sampleProperties();
        longDocument.nodes[0].children[0].value = QStringLiteral("C:\\") + QString(600, QLatin1Char('A')) + QStringLiteral("\\KSword.exe");
        dialog.propertyView()->setDocument(longDocument);
        dialog.resize(640, 480);
        flush();
        require(dialog.width() == 640, "unbroken long raw path does not expand native dialog");
        require(dialog.propertyView()->tree()->verticalScrollBar()->maximum() > 0, "long path remains accessible with native scrolling");
    }
    std::cout << "PASS: " << checks << " production dialog shell layout checks; backend data mocked\n";
}
