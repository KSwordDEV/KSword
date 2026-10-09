#pragma once

// ============================================================
// VirtualLocationPage.h
// 作用：
// 1) 在“杂项”里提供虚拟定位入口，把任意坐标写成 Windows 的系统默认位置；
// 2) 展示位置服务、隐私开关与组策略，说明虚拟坐标在什么条件下才会被采纳；
// 3) 支持 WGS-84 / GCJ-02 / BD-09 输入互换与预设点，避免手工换算；
// 4) 提供实况定位读数做应用前后对照，写入后立即回读校验。
// ============================================================

#include "VirtualLocationBackend.h"

#include "../../Framework.h"

#include <QWidget>

class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QPushButton;
class QShowEvent;
namespace ks::ui { class StructuredFieldView; }

namespace ks::misc
{
    // VirtualLocationPage：
    // - 作用：虚拟定位页；所有系统修改都落在注册表上，随时可以一键清除；
    // - 说明：页面不做任何注入或 API Hook，只影响走 Windows 位置服务的调用方。
    class VirtualLocationPage final : public QWidget
    {
    public:
        // 构造函数：只建界面，不访问注册表，避免打开“杂项”就触发一次系统查询。
        explicit VirtualLocationPage(QWidget* parent = nullptr);
        ~VirtualLocationPage() override = default;

    protected:
        // 页面第一次真正可见时才读一次系统状态。
        void showEvent(QShowEvent* event) override;
        // 语义色（Warning 及其背景）在 theme.h 里没有 palette 等价物，写进 QSS 就被
        // 定死在下发那一刻的主题上；而同一段样式里的文字色是动态的 palette(text)。
        // 主题切换时不重下发，横幅就会变成暗底黑字或浅底白字。
        void changeEvent(QEvent* event) override;

    private:
        // initializeUi：建出说明、状态区、坐标输入区与操作区。
        void initializeUi();
        // applyScopeBannerStyle：下发生效范围横幅样式，构造期与主题切换共用。
        void applyScopeBannerStyle();
        // initializeConnections：把按钮、下拉与数值框接到各自的处理函数。
        void initializeConnections();

        // refreshStatus：同步读取位置服务状态与当前默认位置，并刷新到界面。
        void refreshStatus();
        // applyVirtualLocation：把输入坐标换算到 WGS-84 后写入默认位置，并立即回读校验。
        void applyVirtualLocation();
        // clearVirtualLocation：删除默认位置的五个值，把系统恢复成未设置状态。
        void clearVirtualLocation();
        // toggleProviderPolicy：按复选框状态写入或删除 DisableWindowsLocationProvider。
        void toggleProviderPolicy(bool disabled);
        // restartLocationService：停掉 lfsvc 丢弃缓存，让下一次定位重新取默认位置。
        void restartLocationService();
        // requestLiveFix：在后台线程向 WinRT 要一次定位；fillInputs 为 true 时把结果回填输入框。
        void requestLiveFix(bool fillInputs);
        // applyLiveFixResult：在 UI 线程收拢实况定位结果。
        void applyLiveFixResult(
            const virtual_location::LiveFixResult& fixResult,
            bool fillInputs);

        // applyPreset：把预设点按当前坐标系换算后填进输入框。
        void applyPreset(int presetIndex);
        // updateConversionPreview：显示同一位置在三套坐标系下的读数。
        void updateConversionPreview();

        // currentCoordinateSystem：读出下拉框当前选中的坐标系。
        virtual_location::CoordinateSystem currentCoordinateSystem() const;
        // inputCoordinate：把四个数值框组装成当前坐标系下的坐标。
        virtual_location::GeoCoordinate inputCoordinate() const;
        // setInputCoordinate：按当前坐标系回填数值框，期间屏蔽信号避免反复换算。
        void setInputCoordinate(const virtual_location::GeoCoordinate& coordinate);

        // setResultText：把一次操作的结论写到底部，isError 决定配色。
        void setResultText(const QString& text, bool isError);
        // setBusy：一次同步操作没结束时禁用按钮，防止重复点击。
        void setBusy(bool busy);
        // updateButtons：按忙碌状态和当前系统状态刷新按钮可用性。
        void updateButtons();

    private:
        QLabel* m_scopeLabel = nullptr;            // m_scopeLabel：生效范围与局限说明。
        QLabel* m_serviceLabel = nullptr;          // m_serviceLabel：位置服务与隐私开关状态。
        QLabel* m_policyLabel = nullptr;           // m_policyLabel：位置相关组策略状态。
        QLabel* m_currentLocationLabel = nullptr;  // m_currentLocationLabel：当前系统默认位置读数。
        QLabel* m_conversionLabel = nullptr;       // m_conversionLabel：三套坐标系换算预览。
        QLabel* m_liveFixLabel = nullptr;          // m_liveFixLabel：最近一次实况定位结果。
        QLabel* m_resultLabel = nullptr;           // m_resultLabel：最近一次操作结论。
        ks::ui::StructuredFieldView* m_rawValueView = nullptr; // 默认位置键下的结构化注册表属性。
        QComboBox* m_coordinateSystemCombo = nullptr; // m_coordinateSystemCombo：输入坐标所属坐标系。
        QComboBox* m_presetCombo = nullptr;        // m_presetCombo：内置预设坐标点。
        QDoubleSpinBox* m_latitudeSpin = nullptr;  // m_latitudeSpin：纬度输入。
        QDoubleSpinBox* m_longitudeSpin = nullptr; // m_longitudeSpin：经度输入。
        QDoubleSpinBox* m_altitudeSpin = nullptr;  // m_altitudeSpin：海拔输入。
        QDoubleSpinBox* m_accuracySpin = nullptr;  // m_accuracySpin：误差半径输入。
        QCheckBox* m_forceProviderCheck = nullptr; // m_forceProviderCheck：是否禁用 Windows 位置提供程序。
        QPushButton* m_refreshButton = nullptr;    // m_refreshButton：重新读取系统状态。
        QPushButton* m_liveFixButton = nullptr;    // m_liveFixButton：读一次系统实况定位。
        QPushButton* m_useLiveFixButton = nullptr; // m_useLiveFixButton：读一次实况定位并回填输入。
        QPushButton* m_applyButton = nullptr;      // m_applyButton：写入虚拟定位。
        QPushButton* m_clearButton = nullptr;      // m_clearButton：清除虚拟定位。
        QPushButton* m_restartServiceButton = nullptr; // m_restartServiceButton：重启位置服务丢缓存。

        int m_lastCoordinateSystemIndex = 0;       // m_lastCoordinateSystemIndex：上一次选中的坐标系，用于切换时换算。
        bool m_busy = false;                       // m_busy：同步操作进行中。
        bool m_liveFixRunning = false;             // m_liveFixRunning：后台实况定位进行中。
        bool m_updatingInputs = false;             // m_updatingInputs：正在程序化回填数值框。
        bool m_defaultLocationPresent = false;     // m_defaultLocationPresent：系统当前是否已有默认位置。
        bool m_providerDisabled = false;           // m_providerDisabled：组策略当前是否已禁用位置提供程序。
    };
}
