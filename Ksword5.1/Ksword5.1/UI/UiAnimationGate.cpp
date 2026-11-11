#include "./UiAnimationGate.h"

#include <QApplication>
#include <QCoreApplication>
#include <QVariant>
#include <QPointer>
#include <algorithm>
#include <vector>

namespace
{
    // 属性名集中在此定义，避免调用方各自硬编码字符串。
    const char* const kUiAnimationsEnabledProperty = "ksword_ui_animations_enabled";
    std::vector<QPointer<QObject>> animationObservers;
}

void ks::ui::SetGlobalUiAnimationsEnabled(const bool enabled)
{
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        const bool changed = AreUiAnimationsEnabled() != enabled;
        appInstance->setProperty(kUiAnimationsEnabledProperty, enabled);
        if (changed) {
            animationObservers.erase(std::remove_if(animationObservers.begin(), animationObservers.end(),
                [](const auto& observer) { return observer.isNull(); }), animationObservers.end());
            const auto observers = animationObservers;
            for (const auto& observer : observers) if (observer) {
                QEvent event(UiAnimationsChangedEventType());
                QCoreApplication::sendEvent(observer, &event);
            }
        }
    }
}

QEvent::Type ks::ui::UiAnimationsChangedEventType()
{
    static const auto type = static_cast<QEvent::Type>(QEvent::registerEventType());
    return type;
}

void ks::ui::ObserveUiAnimations(QObject* observer)
{
    if (!observer) return;
    animationObservers.erase(std::remove_if(animationObservers.begin(), animationObservers.end(),
        [](const auto& entry) { return entry.isNull(); }), animationObservers.end());
    animationObservers.emplace_back(observer);
}

bool ks::ui::AreUiAnimationsEnabled()
{
    QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        return false; // 没有图形应用时不存在界面动画。
    }
    const QVariant value = appInstance->property(kUiAnimationsEnabledProperty);
    // 设置尚未下发前默认保留动画，避免启动阶段被误判为关闭。
    return value.isValid() ? value.toBool() : true;
}
