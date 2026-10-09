#pragma once

#include "../UI/StructuredFieldView.h"
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QVector>
#include <QDesktopServices>
#include <QUrl>

class QEvent;
class QGridLayout;
class QScrollArea;
class QShowEvent;
class QToolButton;
class HardwareDock;
class PerformanceNavCard;

class WelcomeDock : public QWidget
{
    Q_OBJECT
public:

    explicit WelcomeDock(QWidget* parent = nullptr);

    QLabel* m_leftImage;       // 左侧图片：展示欢迎页主 Logo。
    QPushButton* m_languageSettingsBtn; // 语言设置按钮：打开设置对话框中的语言页签。
    QLabel* m_copyright;       // 版权信息：展示版权、版本号和编译时间。
    QLabel* m_contributors;    // 贡献者信息：展示当前参与名单。
    QLabel* m_referenceTitle;  // 参考项目标题：说明下方按钮均为外部参考仓库入口。
    QLabel* m_donors;          // 捐赠者信息：展示当前公开感谢的捐赠者名单。
    QPushButton* m_githubBtn;  // Github按钮：打开项目仓库入口。
    QPushButton* m_qqBtn;      // QQ群按钮：保留项目交流群入口。
    QPushButton* m_pplControlBtn;      // PPLcontrol按钮：打开 PPLcontrol 参考仓库。
    QPushButton* m_systemInformerBtn;  // System Informer按钮：打开 System Informer 参考仓库。
    QPushButton* m_skt64Btn;           // SKT64按钮：打开 SKT64 参考仓库。

    // 布局管理器：欢迎页只保留主内容区，并在主入口下方展示贡献者和参考项目。
    QHBoxLayout* m_mainLayout;      // 主布局：承载欢迎页主体内容。
    QVBoxLayout* m_leftLayout;      // 左侧垂直布局：按 Logo、发布信息、按钮区和扩展信息排列。
    QHBoxLayout* m_btnLayout;       // 按钮水平布局：放置 Github 与 QQ 群按钮。
    QHBoxLayout* m_referenceLayout; // 参考项目布局：横向放置外部参考仓库按钮。

    // 欢迎页专用布局控件。所有尺寸都允许压缩，避免 ADS 在 Dock 层级创建滚动条。
    QHBoxLayout* m_performanceLayout = nullptr;
    QWidget* m_systemInfoPanel = nullptr;
    QGridLayout* m_systemInfoLayout = nullptr;
    QToolButton* m_contributorsCollapse = nullptr;
    QToolButton* m_donorsCollapse = nullptr;
    QScrollArea* m_contributorsScroll = nullptr;
    QScrollArea* m_donorsScroll = nullptr;
    QWidget* m_contributorsBody = nullptr;
    QWidget* m_donorsBody = nullptr;
    QVector<PerformanceNavCard*> m_performanceCards;

    // WelcomeDock 复用 HardwareDock 的实时采样结果；硬件 Dock 即使尚未打开也会被主窗口启动采样。
    HardwareDock* m_hardwareDock = nullptr;
    double m_diskDisplayScale = 1024.0 * 1024.0;
    double m_networkDisplayScale = 1024.0 * 1024.0;

signals:
    // languageSettingsRequested 作用：通知主窗口打开设置对话框并定位到语言页签。
    void languageSettingsRequested();

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    void retranslateUi();
    void initializeLanguageButtonStyle();
    // refreshThemeColors 只更新已有欢迎页控件的主题角色，不重建内容或请求硬件采样。
    void refreshThemeColors();
    // scheduleThemeRefresh 合并 palette 通知；退出 Qt 子树传播栈后再重设局部样式。
    void scheduleThemeRefresh();
    void initializePerformanceCards();
    void initializeContributorCollapse();
    void updateCollapseState(bool contributorsExpanded);
    void updatePerformanceSnapshot(
        double cpuUsagePercent,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateSystemInfoFromHardwareFields(const ks::ui::FieldDocument& overviewFields);

public:
    // setHardwareDock 作用：把 WelcomeDock 接到主窗口已创建的 HardwareDock 采样源。
    void setHardwareDock(HardwareDock* hardwareDock);

private:
    bool m_themeRefreshScheduled = false; // 当前事件轮只排队一次主题刷新。
};
