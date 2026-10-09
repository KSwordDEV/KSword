#pragma once

// NotificationCardManager：统一管理日志通知与任务进度卡片。
// - 从全局日志/进度管理器读取增量快照；
// - 把卡片布局到显示器工作区或主窗口 Dock 客户区；
// - 保证复制、展开按钮以外的区域跨进程点击穿透。

#include "../Framework.h"
#include "../SettingsDock/AppearanceSettings.h"

#include <QObject>

#include <cstddef>
#include <memory>
#include <vector>

class QWidget;
class QTimer;

namespace ks::ui
{
    class NotificationCard;
    struct NotificationCardRecord;

    class NotificationCardManager final : public QObject
    {
    public:
        NotificationCardManager(QWidget* mainWindow, QWidget* clientAnchor, QObject* parent = nullptr);
        ~NotificationCardManager() override;

        NotificationCardManager(const NotificationCardManager&) = delete;
        NotificationCardManager& operator=(const NotificationCardManager&) = delete;

        // applySettings：应用最新通知首选项。禁用时立即移除全部卡片；位置与方向变更立即重排。
        void applySettings(const ks::settings::AppearanceSettings& settings);

        // refreshVisuals：主题切换后刷新已有卡片的颜色与透明背景。
        void refreshVisuals();

        // onHostGeometryChanged：主窗口移动、缩放、最小化/还原后重算卡片位置。
        void onHostGeometryChanged();

        // clearCards：立即移除当前全部日志和进度卡片。
        void clearCards();

        bool isProgressTaskOverflowed(int pid) const;
        QWidget* hostWindow() const;

    private:
        void refreshFromManagers();
        void refreshLogCards();
        // 同一应用快照驱动两种视图；force 只重绘已有卡片，设置/语言切换不会换 QWidget。
        void refreshProgressCards(const std::shared_ptr<const kProgressSnapshot>& snapshot, bool force = false);
        void removeExpiredLogCards();
        void reflowCards(bool animate);
        void trimLogCardsToMaximum(bool animate);

        void appendLogCard(const kEvent& eventItem);
        void appendProgressCard(const kProgressTask& taskItem);
        void removeRecordAt(std::size_t index, bool animate);

        QWidget* m_mainWindow = nullptr;
        QWidget* m_clientAnchor = nullptr;
        QTimer* m_refreshTimer = nullptr;
        ks::settings::AppearanceSettings m_settings;
        std::size_t m_lastLogRevision = 0;
        std::size_t m_knownLogCount = 0;
        std::size_t m_lastProgressRevision = 0;
        std::vector<std::unique_ptr<NotificationCardRecord>> m_cards;
        std::vector<int> m_overflowProgressTaskIds;
    };

    // 供 kProgress::UI 查询：仅在对应进度卡片超出区域时使用非模态选项弹窗。
    bool isProgressTaskNotificationOverflowed(int pid);
    QWidget* notificationCardHostWindow();
}
