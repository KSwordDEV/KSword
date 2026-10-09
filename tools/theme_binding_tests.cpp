// 真实主题绑定、旧补偿器及标题栏/命令弹层离屏回归；不执行命令或操作其他程序窗口。
#include "../Ksword5.1/Ksword5.1/UI/ThemeBinding.h"
#include "../Ksword5.1/Ksword5.1/UI/ThemeColorRemap.h"
#include "../Ksword5.1/Ksword5.1/UI/CommandExecutionPopup.h"
#include "../Ksword5.1/Ksword5.1/Framework/CustomTitleBar.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QEvent>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QTest>
#include <QVariant>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <thread>

namespace
{
    unsigned checks = 0; // 仅主线程统计实际行为断言。

    // require 输入契约条件和诊断，失败立即非零退出，避免把异常退出当作通过。
    void require(const bool condition, const char* message)
    {
        ++checks;
        if (!condition)
        {
            std::cerr << "THEME_BINDING_FAIL: " << message << '\n';
            std::exit(1);
        }
    }

    // pump 排空本轮及重入后排队的主题更新，不启动生产主窗口或真实后台任务。
    void pump()
    {
        for (int pass = 0; pass < 4; ++pass)
        {
            QApplication::processEvents();
        }
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }

    // bindingContracts 验证合并、角色身份、局部 palette、替换和销毁的真实 QWidget 行为。
    void bindingContracts()
    {
        QWidget owner; // 未登记的父容器仍归旧兼容路径。
        QLabel bound(&owner);
        QLabel child(&bound);
        int firstCalls = 0; // 当前登记函数的实际执行次数。
        QColor roleColor(Qt::red); // 显式角色值，不从旧控件 RGB 推断角色。
        require(ks::ui::BindWidgetTheme(&bound, [&]() {
            ++firstCalls;
            bound.setStyleSheet(QStringLiteral("color:%1;").arg(roleColor.name()));
        }), "GUI widget accepts role binding");
        require(firstCalls == 0, "binding does not repolish synchronously during construction");
        require(ks::ui::HasWidgetThemeBinding(&bound), "registered widget is explicitly owned");
        require(!ks::ui::HasWidgetThemeBinding(&owner) && !ks::ui::HasWidgetThemeBinding(&child),
            "binding does not claim unregistered parents or children");
        pump();
        require(firstCalls == 1 && bound.styleSheet().contains(roleColor.name()),
            "first queued refresh uses the declared role");

        // 同一轮大量 palette/显式请求只提交一次角色刷新；局部 palette 不被全局覆盖。
        for (int eventIndex = 0; eventIndex < 40; ++eventIndex)
        {
            QEvent event(QEvent::PaletteChange);
            QApplication::sendEvent(&bound, &event);
            ks::ui::RefreshWidgetThemeBindings();
        }
        roleColor = Qt::blue;
        pump();
        require(firstCalls == 2 && bound.styleSheet().contains(roleColor.name()),
            "repeated events coalesce and use current role values");
        QPalette localPalette = bound.palette(); // 独立窗口的局部底色必须由它自己保留。
        require(ks::ui::BindWidgetTheme(&bound, [&]() {
            ++firstCalls;
            bound.setStyleSheet(QStringLiteral("color:%1;").arg(roleColor.name()));
        }, ks::ui::ThemePalettePolicy::PreserveLocal), "independent widget explicitly preserves local palette");
        localPalette.setColor(QPalette::Base, QColor(17, 29, 43));
        bound.setPalette(localPalette);
        pump();
        require(bound.palette().color(QPalette::Base) == QColor(17, 29, 43),
            "binding preserves the widget local palette");

        int replacementCalls = 0; // 同一控件的新角色策略只替换原有函数。
        require(ks::ui::BindWidgetTheme(&bound, [&]() { ++replacementCalls; }),
            "existing binding can be replaced");
        pump();
        const int previousCalls = firstCalls;
        ks::ui::RefreshWidgetThemeBindings();
        pump();
        require(replacementCalls == 2 && firstCalls == previousCalls,
            "replacement neither duplicates registration nor calls the old strategy");
        require(!ks::ui::BindWidgetTheme(nullptr, []() {}) &&
            !ks::ui::BindWidgetTheme(&bound, {}), "invalid binding inputs are rejected");

        std::atomic_bool workerAccepted{ true }; // 只在线程中检查 API 门禁，不访问 QWidget 成员。
        std::thread worker([&]() {
            workerAccepted.store(ks::ui::BindWidgetTheme(&bound, []() {}));
        });
        worker.join();
        require(!workerAccepted.load(), "worker thread cannot register or touch GUI state");

        // 销毁前排队的回调不能执行；回调自身删除 owner 也不能访问已析构绑定。
        int deletedCalls = 0;
        auto* deleted = new QWidget;
        ks::ui::BindWidgetTheme(deleted, [&]() { ++deletedCalls; });
        delete deleted;
        pump();
        require(deletedCalls == 0, "queued callback is discarded when widget dies");
        QPointer<QWidget> selfDeleting = new QWidget;
        ks::ui::BindWidgetTheme(selfDeleting, [&]() { delete selfDeleting.data(); });
        pump();
        require(selfDeleting.isNull(), "callback can destroy its own widget safely");

        // 缓存属性中的地址失效后只比较存活子树，不解引用已删除对象。
        auto* disposable = new QWidget;
        ks::ui::BindWidgetTheme(disposable, []() {});
        QObject* cached = disposable->property("KSWORD_EXPLICIT_THEME_BINDING").value<QObject*>();
        delete cached;
        require(!ks::ui::HasWidgetThemeBinding(disposable), "manual child deletion clears ownership logically");
        require(ks::ui::BindWidgetTheme(disposable, []() {}), "stale cache can be safely rebound");
        delete disposable;
        pump();

        // 真正嵌套事件循环会提前消费待刷队列；重新登记后的策略仍必须在外层退出后执行。
        QWidget nestedOwner;
        int originalNestedCalls = 0;
        int replacementNestedCalls = 0;
        require(ks::ui::BindWidgetTheme(&nestedOwner, [&]() {
            ++originalNestedCalls;
            ks::ui::BindWidgetTheme(&nestedOwner, [&]() { ++replacementNestedCalls; });
            QApplication::processEvents();
        }), "nested refresh can replace its own strategy");
        pump();
        require(originalNestedCalls == 1 && replacementNestedCalls == 1,
            "strategy replacement survives a nested event loop consuming pending work");
    }

    // legacyCompatibility 验证明确绑定和存量旧色值补偿可以共存，且不按旧 RGB 改写角色。
    void legacyCompatibility()
    {
        KswordTheme::SetPrimaryAccentColor(QStringLiteral("#3865a8"));
        const auto oldTheme = ks::ui::CaptureThemeColorSnapshot();
        const QString previousAccent = KswordTheme::PrimaryAccentColor().name();
        QLabel declared;
        QLabel legacy;
        declared.setStyleSheet(QStringLiteral("color:%1;").arg(previousAccent));
        legacy.setStyleSheet(QStringLiteral("color:%1;").arg(previousAccent));
        ks::ui::BindWidgetTheme(&declared, [&]() {
            declared.setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::ErrorColor().name()));
        });
        // 在角色刷新前执行补偿：它必须跳过绑定控件，不能先猜成另一个强调角色。
        KswordTheme::SetPrimaryAccentColor(QStringLiteral("#b34c6f"));
        const auto result = ks::ui::RemapStaleThemeColors(oldTheme);
        require(declared.styleSheet().contains(previousAccent), "legacy remapper skips declared widget");
        require(!legacy.styleSheet().contains(previousAccent) && result.rewrittenWidgetCount > 0,
            "unregistered legacy widget retains old compatibility behavior");
        ks::ui::RefreshWidgetThemeBindings();
        pump();
        require(declared.styleSheet().contains(KswordTheme::ErrorColor().name()),
            "registered appearance resolves its semantic role instead of the old RGB");
    }

    // productionWidgets 使用实际标题栏和命令弹层，不发送 execution 信号或执行系统命令。
    void productionWidgets()
    {
        QWidget host;
        QLineEdit input(&host);
        QWidget anchor(&host);
        ks::ui::CustomTitleBar title(&host);
        ks::ui::CommandExecutionPopup popup(&host, &anchor, &input);
        require(ks::ui::HasWidgetThemeBinding(&title) && ks::ui::HasWidgetThemeBinding(&popup),
            "both production widgets register explicit theme appearance");
        auto* pin = title.findChild<QPushButton*>(QStringLiteral("ksTitlePinButton"));
        require(pin != nullptr, "production title bar exposes its existing pin button");
        QPixmap iconPixels(12, 12);
        iconPixels.fill(Qt::green);
        pin->setIcon(QIcon(iconPixels));
        const auto iconKey = pin->icon().cacheKey(); // 主题刷新不能重置由图标管理器处理的图标。
        const QString oldTitleStyle = title.styleSheet();
        const QString oldPopupStyle = popup.styleSheet();
        KswordTheme::SetMainBackgroundColor(QStringLiteral("#26394c"));
        KswordTheme::SetPrimaryAccentColor(QStringLiteral("#168e7a"));
        ks::ui::RefreshWidgetThemeBindings();
        pump();
        require(title.styleSheet() != oldTitleStyle && popup.styleSheet() != oldPopupStyle,
            "existing production styles refresh when background and accent roles change");
        require(pin->icon().cacheKey() == iconKey, "style refresh preserves already themed icon identity");
        require(input.text().isEmpty(), "appearance update does not submit or change command text");
        QString languageError;
        require(ks::i18n::LanguageManager::instance().setLanguage(QStringLiteral("en-US"), &languageError),
            "production language manager switches to English");
        pump();
        require(title.titleInputLineEdit() != nullptr, "language refresh retains live title input controls");
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv); // 唯一离屏应用；产物和状态都在此私有夹具进程中。
    app.setQuitOnLastWindowClosed(false);
    QString languageError;
    require(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"), &languageError),
        "production language packs initialize");
    bindingContracts();
    legacyCompatibility();
    productionWidgets();
    pump();
    std::cout << "THEME_BINDING_RESULT=SUCCESS\nTHEME_BINDING_CHECKS=" << checks << '\n';
    return 0;
}
