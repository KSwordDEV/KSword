#include "VirtualLocationPage.h"
#include "../../UI/PrimaryPageStyle.h"
#include "../../UI/ToolbarMetrics.h"

#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QEvent>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include "../../UI/StructuredFieldView.h"
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QVBoxLayout>

#include <thread>
#include <utility>

namespace
{
    using ks::misc::virtual_location::CoordinateSystem;
    using ks::misc::virtual_location::GeoCoordinate;
    using ks::misc::virtual_location::RegistryBackend;

    // kLiveFixTimeoutMilliseconds：
    // - 系统首次定位可能要走网络查询，给到 12 秒再判超时。
    constexpr unsigned long kLiveFixTimeoutMilliseconds = 12000UL;

    // backendText：
    // - 输入 backend：一次注册表访问走通的通道；
    // - 作用：告诉用户到底是 R3 还是驱动完成的；
    // - 返回：通道说明文本。
    QString backendText(const RegistryBackend backend)
    {
        switch (backend) {
        case RegistryBackend::Win32:
            return QStringLiteral("R3 直接写入");
        case RegistryBackend::Driver:
            return QStringLiteral("R0 驱动写入");
        case RegistryBackend::None:
        default:
            break;
        }
        return QStringLiteral("无可用通道");
    }

    ks::ui::FieldDocument defaultLocationDocument(
        const ks::misc::virtual_location::DefaultLocationSnapshot& snapshot)
    {
        namespace location = ks::misc::virtual_location;
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("默认位置注册表"));
        document.field(QStringLiteral("注册表键"), location::defaultLocationKeyPath());
        document.field(QStringLiteral("读取成功"), snapshot.readable ? QStringLiteral("是") : QStringLiteral("否"), true);
        document.field(QStringLiteral("已设置默认位置"), snapshot.present ? QStringLiteral("是") : QStringLiteral("否"), true);
        if (!snapshot.failureText.isEmpty()) document.note(snapshot.failureText);
        if (snapshot.values.isEmpty()) document.note(QStringLiteral("（该键下没有默认位置相关的值）"));
        for (const auto& value : snapshot.values)
        {
            document.section(value.name);
            document.nodes.last().translateName = false;
            document.field(QStringLiteral("类型"), location::registryValueTypeText(value.type));
            document.field(QStringLiteral("值"), location::registryValuePreview(value));
            document.field(QStringLiteral("字节数"), QString::number(value.bytes.size()));
            document.field(QStringLiteral("原始字节"), QString::fromLatin1(value.bytes.toHex(' ').toUpper()));
            document.field(QStringLiteral("读取通道"), value.backend == RegistryBackend::Driver
                ? QStringLiteral("R0") : value.backend == RegistryBackend::Win32 ? QStringLiteral("R3") : QStringLiteral("无可用通道"), true);
        }
        return document;
    }

    // formatCoordinate：
    // - 输入 coordinate：一组坐标；
    // - 作用：拼出“纬度, 经度”，小数位固定 6 位，约合米级；
    // - 返回：单行文本。
    QString formatCoordinate(const GeoCoordinate& coordinate)
    {
        return QStringLiteral("%1, %2")
            .arg(coordinate.latitude, 0, 'f', 6)
            .arg(coordinate.longitude, 0, 'f', 6);
    }

    // showOpaqueMessage：
    // - 作用：弹一个不透明的主题化提示框，避免继承父链的半透明背景；
    // - 返回：无。
    void showOpaqueMessage(
        QWidget* const parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksVirtualLocationMessageBox"));
        dialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
    }

    // askConfirmation：
    // - 作用：对影响全系统的开关做一次显式确认；
    // - 返回：true 表示用户选择继续。
    bool askConfirmation(
        QWidget* const parent,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksVirtualLocationConfirmBox"));
        dialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(QMessageBox::Warning);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        dialog.setDefaultButton(QMessageBox::No);
        return dialog.exec() == QMessageBox::Yes;
    }
}

namespace ks::misc
{
    VirtualLocationPage::VirtualLocationPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        updateConversionPreview();
        updateButtons();
    }

    void VirtualLocationPage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
    }

    void VirtualLocationPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() == QEvent::ApplicationPaletteChange
            || event->type() == QEvent::PaletteChange)
        {
            applyScopeBannerStyle();
        }
    }

    // applyScopeBannerStyle 作用：
    // - 输入：无，读取当前主题的语义色；
    // - 处理：下发生效范围横幅样式，构造期与主题切换后走同一条路径；
    // - 返回：无，横幅尚未创建时静默跳过。
    void VirtualLocationPage::applyScopeBannerStyle()
    {
        if (m_scopeLabel == nullptr)
        {
            return;
        }
        m_scopeLabel->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;}")
                .arg(KswordTheme::WarningHex())
                .arg(KswordTheme::ThemeColorName(KswordTheme::WarningBackgroundColor()))
                .arg(KswordTheme::TextPrimaryHex()));
    }

    void VirtualLocationPage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        // ===================== 生效范围说明 =====================
        m_scopeLabel = new QLabel(this);
        m_scopeLabel->setWordWrap(true);
        applyScopeBannerStyle();
        language.bindText(
            m_scopeLabel,
            QStringLiteral("misc.virtual_location.scope"),
            QStringLiteral(
                "本页把坐标写成 Windows 的“系统默认位置”，只对通过 Windows 位置服务取位置的程序生效，"
                "而且要在系统拿不到更精确的定位源时才会被采用。浏览器网页定位、自带 IP 库或自建定位 SDK 的应用不受影响。"
                "修改只落在注册表上，随时可以用“清除虚拟定位”还原。"));
        rootLayout->addWidget(m_scopeLabel);

        // ===================== 当前状态 =====================
        auto* statusGroup = new QGroupBox(this);
        // 已生效位置与待输入参数使用独立的轻分组，减少连续表单的混淆。
        ks::ui::StylePrimaryGroup(statusGroup);
        language.bindText(
            statusGroup,
            QStringLiteral("misc.virtual_location.status.title"),
            QStringLiteral("当前状态"));
        auto* statusLayout = new QVBoxLayout(statusGroup);
        statusLayout->setSpacing(6);

        m_serviceLabel = new QLabel(statusGroup);
        m_serviceLabel->setWordWrap(true);
        m_serviceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        statusLayout->addWidget(m_serviceLabel);

        m_policyLabel = new QLabel(statusGroup);
        m_policyLabel->setWordWrap(true);
        m_policyLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_policyLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        statusLayout->addWidget(m_policyLabel);

        m_currentLocationLabel = new QLabel(statusGroup);
        m_currentLocationLabel->setWordWrap(true);
        m_currentLocationLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_currentLocationLabel->setStyleSheet(
            QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
        statusLayout->addWidget(m_currentLocationLabel);

        m_rawValueView = new ks::ui::StructuredFieldView(statusGroup);
        m_rawValueView->setObjectName(QStringLiteral("ksVirtualLocationRawView"));
        m_rawValueView->setMinimumHeight(160);
        m_rawValueView->setMaximumHeight(240);
        m_rawValueView->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("默认位置注册表属性将在刷新后显示。")));
        language.bindToolTip(
            m_rawValueView,
            QStringLiteral("misc.virtual_location.raw.tooltip"),
            QStringLiteral("默认位置键下读到的值、类型、完整原始字节和 R3 / R0 读取通道。"));
        statusLayout->addWidget(m_rawValueView);

        m_liveFixLabel = new QLabel(statusGroup);
        m_liveFixLabel->setWordWrap(true);
        m_liveFixLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        language.bindText(
            m_liveFixLabel,
            QStringLiteral("misc.virtual_location.livefix.idle"),
            QStringLiteral("实况定位：尚未读取。"));
        statusLayout->addWidget(m_liveFixLabel);

        auto* statusButtonLayout = new QHBoxLayout();
        m_refreshButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QString(),
            statusGroup);
        m_liveFixButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/virtual_location.svg")),
            QString(),
            statusGroup);
        language.bindText(
            m_refreshButton,
            QStringLiteral("misc.virtual_location.refresh"),
            QStringLiteral("刷新状态"));
        language.bindText(
            m_liveFixButton,
            QStringLiteral("misc.virtual_location.livefix.query"),
            QStringLiteral("读取实况定位"));
        language.bindToolTip(
            m_liveFixButton,
            QStringLiteral("misc.virtual_location.livefix.tooltip"),
            QStringLiteral(
                "向 Windows 位置服务要一次坐标。返回来源显示“默认位置”，就说明虚拟定位已经被采纳。"));
        statusButtonLayout->addWidget(m_refreshButton);
        statusButtonLayout->addWidget(m_liveFixButton);
        statusButtonLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(statusButtonLayout);
        statusLayout->addLayout(statusButtonLayout);
        rootLayout->addWidget(statusGroup);

        // ===================== 虚拟坐标 =====================
        auto* inputGroup = new QGroupBox(this);
        ks::ui::StylePrimaryGroup(inputGroup);
        language.bindText(
            inputGroup,
            QStringLiteral("misc.virtual_location.input.title"),
            QStringLiteral("虚拟坐标"));
        auto* inputLayout = new QGridLayout(inputGroup);
        inputLayout->setHorizontalSpacing(10);
        inputLayout->setVerticalSpacing(8);

        auto* systemLabel = new QLabel(inputGroup);
        language.bindText(
            systemLabel,
            QStringLiteral("misc.virtual_location.input.system"),
            QStringLiteral("坐标系："));
        m_coordinateSystemCombo = new QComboBox(inputGroup);
        ks::ui::StylePrimaryCombo(m_coordinateSystemCombo);
        m_coordinateSystemCombo->setObjectName(
            QStringLiteral("ksVirtualLocationSystemCombo"));
        m_coordinateSystemCombo->addItem(QStringLiteral("WGS-84（GPS / Windows 原始坐标）"));
        m_coordinateSystemCombo->addItem(QStringLiteral("GCJ-02（高德 / 腾讯地图坐标）"));
        m_coordinateSystemCombo->addItem(QStringLiteral("BD-09（百度地图坐标）"));
        language.bindToolTip(
            m_coordinateSystemCombo,
            QStringLiteral("misc.virtual_location.input.system.tooltip"),
            QStringLiteral(
                "从国内地图复制来的坐标多半是 GCJ-02 或 BD-09；选对坐标系后会自动换算成 WGS-84 再写入系统。"));
        inputLayout->addWidget(systemLabel, 0, 0);
        inputLayout->addWidget(m_coordinateSystemCombo, 0, 1, 1, 3);

        auto* presetLabel = new QLabel(inputGroup);
        language.bindText(
            presetLabel,
            QStringLiteral("misc.virtual_location.input.preset"),
            QStringLiteral("预设点："));
        m_presetCombo = new QComboBox(inputGroup);
        ks::ui::StylePrimaryCombo(m_presetCombo);
        m_presetCombo->setObjectName(QStringLiteral("ksVirtualLocationPresetCombo"));
        m_presetCombo->addItem(QStringLiteral("（不使用预设点）"));
        int presetCount = 0;
        const virtual_location::PresetLocation* const presets =
            virtual_location::presetLocations(&presetCount);
        for (int presetIndex = 0; presetIndex < presetCount; ++presetIndex) {
            m_presetCombo->addItem(
                ks::i18n::text(
                    QString::fromLatin1(presets[presetIndex].nameKey),
                    QString::fromUtf8(presets[presetIndex].nameText)));
        }
        inputLayout->addWidget(presetLabel, 1, 0);
        inputLayout->addWidget(m_presetCombo, 1, 1, 1, 3);

        auto* latitudeLabel = new QLabel(inputGroup);
        language.bindText(
            latitudeLabel,
            QStringLiteral("misc.virtual_location.input.latitude"),
            QStringLiteral("纬度："));
        m_latitudeSpin = new QDoubleSpinBox(inputGroup);
        m_latitudeSpin->setObjectName(QStringLiteral("ksVirtualLocationLatitudeSpin"));
        m_latitudeSpin->setDecimals(8);
        m_latitudeSpin->setRange(-90.0, 90.0);
        m_latitudeSpin->setSingleStep(0.0001);
        m_latitudeSpin->setValue(39.909187);

        auto* longitudeLabel = new QLabel(inputGroup);
        language.bindText(
            longitudeLabel,
            QStringLiteral("misc.virtual_location.input.longitude"),
            QStringLiteral("经度："));
        m_longitudeSpin = new QDoubleSpinBox(inputGroup);
        m_longitudeSpin->setObjectName(QStringLiteral("ksVirtualLocationLongitudeSpin"));
        m_longitudeSpin->setDecimals(8);
        m_longitudeSpin->setRange(-180.0, 180.0);
        m_longitudeSpin->setSingleStep(0.0001);
        m_longitudeSpin->setValue(116.397451);

        inputLayout->addWidget(latitudeLabel, 2, 0);
        inputLayout->addWidget(m_latitudeSpin, 2, 1);
        inputLayout->addWidget(longitudeLabel, 2, 2);
        inputLayout->addWidget(m_longitudeSpin, 2, 3);

        auto* altitudeLabel = new QLabel(inputGroup);
        language.bindText(
            altitudeLabel,
            QStringLiteral("misc.virtual_location.input.altitude"),
            QStringLiteral("海拔："));
        m_altitudeSpin = new QDoubleSpinBox(inputGroup);
        m_altitudeSpin->setObjectName(QStringLiteral("ksVirtualLocationAltitudeSpin"));
        m_altitudeSpin->setDecimals(2);
        m_altitudeSpin->setRange(-1000.0, 100000.0);
        m_altitudeSpin->setValue(44.0);
        // LanguageManager::bindSuffix 只接 QSpinBox，这里两个都是 QDoubleSpinBox，
        // 直接取一次词条设进去；单位切换跟随下次页面重建。
        m_altitudeSpin->setSuffix(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.input.meter.suffix"),
                QStringLiteral(" 米")));

        auto* accuracyLabel = new QLabel(inputGroup);
        language.bindText(
            accuracyLabel,
            QStringLiteral("misc.virtual_location.input.accuracy"),
            QStringLiteral("误差半径："));
        m_accuracySpin = new QDoubleSpinBox(inputGroup);
        m_accuracySpin->setObjectName(QStringLiteral("ksVirtualLocationAccuracySpin"));
        m_accuracySpin->setDecimals(1);
        m_accuracySpin->setRange(0.0, 100000.0);
        m_accuracySpin->setValue(50.0);
        m_accuracySpin->setSuffix(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.input.meter.suffix"),
                QStringLiteral(" 米")));

        inputLayout->addWidget(altitudeLabel, 3, 0);
        inputLayout->addWidget(m_altitudeSpin, 3, 1);
        inputLayout->addWidget(accuracyLabel, 3, 2);
        inputLayout->addWidget(m_accuracySpin, 3, 3);

        m_conversionLabel = new QLabel(inputGroup);
        m_conversionLabel->setWordWrap(true);
        m_conversionLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_conversionLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        inputLayout->addWidget(m_conversionLabel, 4, 0, 1, 4);

        inputLayout->setColumnStretch(1, 1);
        inputLayout->setColumnStretch(3, 1);
        rootLayout->addWidget(inputGroup);

        // ===================== 操作 =====================
        auto* actionGroup = new QGroupBox(this);
        ks::ui::StylePrimaryGroup(actionGroup);
        language.bindText(
            actionGroup,
            QStringLiteral("misc.virtual_location.action.title"),
            QStringLiteral("操作"));
        auto* actionLayout = new QVBoxLayout(actionGroup);
        actionLayout->setSpacing(8);

        m_forceProviderCheck = new QCheckBox(actionGroup);
        language.bindText(
            m_forceProviderCheck,
            QStringLiteral("misc.virtual_location.action.force_provider"),
            QStringLiteral("同时禁用 Windows 位置提供程序，强制定位回落到默认位置（影响全系统）"));
        language.bindToolTip(
            m_forceProviderCheck,
            QStringLiteral("misc.virtual_location.action.force_provider.tooltip"),
            QStringLiteral(
                "写入组策略 DisableWindowsLocationProvider=1，关掉 Windows 自带的网络定位。"
                "关掉之后依赖真实定位的程序（地图、天气、查找我的设备）都会失去精确位置，取消勾选即可还原。"));
        actionLayout->addWidget(m_forceProviderCheck);

        auto* buttonLayout = new QHBoxLayout();
        m_applyButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/virtual_location.svg")),
            QString(),
            actionGroup);
        m_clearButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
            QString(),
            actionGroup);
        m_useLiveFixButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QString(),
            actionGroup);
        m_restartServiceButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QString(),
            actionGroup);
        language.bindText(
            m_applyButton,
            QStringLiteral("misc.virtual_location.action.apply"),
            QStringLiteral("应用虚拟定位"));
        language.bindText(
            m_clearButton,
            QStringLiteral("misc.virtual_location.action.clear"),
            QStringLiteral("清除虚拟定位"));
        language.bindText(
            m_useLiveFixButton,
            QStringLiteral("misc.virtual_location.action.use_livefix"),
            QStringLiteral("用实况定位填入"));
        language.bindText(
            m_restartServiceButton,
            QStringLiteral("misc.virtual_location.action.restart_service"),
            QStringLiteral("重启位置服务"));
        language.bindToolTip(
            m_restartServiceButton,
            QStringLiteral("misc.virtual_location.action.restart_service.tooltip"),
            QStringLiteral(
                "停止 lfsvc 让它丢掉进程内缓存。服务是按需触发启动的，下一次有程序请求定位会自动拉起。"));
        for (QPushButton* const button :
             { m_refreshButton, m_liveFixButton, m_applyButton, m_clearButton,
               m_useLiveFixButton, m_restartServiceButton }) {
            button->setStyleSheet(KswordTheme::ThemedButtonStyle());
        }
        buttonLayout->addWidget(m_applyButton);
        buttonLayout->addWidget(m_clearButton);
        buttonLayout->addWidget(m_useLiveFixButton);
        buttonLayout->addWidget(m_restartServiceButton);
        buttonLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(buttonLayout);
        actionLayout->addLayout(buttonLayout);

        m_resultLabel = new QLabel(actionGroup);
        m_resultLabel->setWordWrap(true);
        m_resultLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        language.bindText(
            m_resultLabel,
            QStringLiteral("misc.virtual_location.action.idle"),
            QStringLiteral("尚未执行任何操作。"));
        actionLayout->addWidget(m_resultLabel);
        rootLayout->addWidget(actionGroup);

        rootLayout->addStretch(1);
    }

    void VirtualLocationPage::initializeConnections()
    {
        connect(
            m_refreshButton,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            m_liveFixButton,
            &QPushButton::clicked,
            this,
            [this]() { requestLiveFix(false); });
        connect(
            m_useLiveFixButton,
            &QPushButton::clicked,
            this,
            [this]() { requestLiveFix(true); });
        connect(
            m_applyButton,
            &QPushButton::clicked,
            this,
            [this]() { applyVirtualLocation(); });
        connect(
            m_clearButton,
            &QPushButton::clicked,
            this,
            [this]() { clearVirtualLocation(); });
        connect(
            m_restartServiceButton,
            &QPushButton::clicked,
            this,
            [this]() { restartLocationService(); });
        connect(
            m_forceProviderCheck,
            &QCheckBox::toggled,
            this,
            [this](const bool checked) { toggleProviderPolicy(checked); });
        connect(
            m_presetCombo,
            &QComboBox::currentIndexChanged,
            this,
            [this](const int index) { applyPreset(index - 1); });

        // 切换坐标系时保持“同一个地点”，把当前输入换算到新坐标系再回填。
        connect(
            m_coordinateSystemCombo,
            &QComboBox::currentIndexChanged,
            this,
            [this](const int index) {
                if (m_updatingInputs) {
                    return;
                }
                static const CoordinateSystem systems[] = {
                    CoordinateSystem::Wgs84,
                    CoordinateSystem::Gcj02,
                    CoordinateSystem::Bd09,
                };
                const int previousIndex = m_lastCoordinateSystemIndex;
                m_lastCoordinateSystemIndex = index;
                if (previousIndex < 0 || previousIndex > 2 || index < 0 || index > 2) {
                    updateConversionPreview();
                    return;
                }
                GeoCoordinate previous;
                previous.latitude = m_latitudeSpin->value();
                previous.longitude = m_longitudeSpin->value();
                previous.altitude = m_altitudeSpin->value();
                previous.errorRadiusMeters = m_accuracySpin->value();
                setInputCoordinate(
                    virtual_location::convertCoordinate(
                        previous, systems[previousIndex], systems[index]));
                updateConversionPreview();
            });

        for (QDoubleSpinBox* const spinBox :
             { m_latitudeSpin, m_longitudeSpin, m_altitudeSpin, m_accuracySpin }) {
            connect(
                spinBox,
                &QDoubleSpinBox::valueChanged,
                this,
                [this](double) {
                    if (m_updatingInputs) {
                        return;
                    }
                    updateConversionPreview();
                });
        }
    }

    void VirtualLocationPage::refreshStatus()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);

        const virtual_location::ServiceSnapshot serviceSnapshot =
            virtual_location::readServiceSnapshot();
        const virtual_location::DefaultLocationSnapshot locationSnapshot =
            virtual_location::readDefaultLocation();

        m_serviceLabel->setText(
            QStringLiteral("位置服务：%1；系统位置开关：%2；桌面应用位置：%3")
                .arg(serviceSnapshot.serviceStateText)
                .arg(
                    serviceSnapshot.consentReadable
                        ? (serviceSnapshot.locationAllowed
                               ? QStringLiteral("已允许")
                               : QStringLiteral("已拒绝"))
                        : QStringLiteral("读取失败"))
                .arg(
                    serviceSnapshot.desktopAppAllowed
                        ? QStringLiteral("已允许")
                        : QStringLiteral("已拒绝")));

        m_providerDisabled = serviceSnapshot.providerDisabledByPolicy;
        m_policyLabel->setText(
            QStringLiteral("组策略：%1%2")
                .arg(serviceSnapshot.policyDetailText)
                .arg(
                    serviceSnapshot.locationDisabledByPolicy
                        ? QStringLiteral("（定位已被策略整体关闭，虚拟坐标同样读不到）")
                        : QString()));
        {
            const QSignalBlocker blocker(m_forceProviderCheck);
            m_forceProviderCheck->setChecked(m_providerDisabled);
        }

        m_defaultLocationPresent = locationSnapshot.present;
        if (!locationSnapshot.readable) {
            m_currentLocationLabel->setText(
                QStringLiteral("默认位置：读取失败。%1").arg(locationSnapshot.failureText));
            m_currentLocationLabel->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                    .arg(KswordTheme::ErrorHex()));
        }
        else if (!locationSnapshot.present) {
            m_currentLocationLabel->setText(QStringLiteral("默认位置：未设置。"));
            m_currentLocationLabel->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                    .arg(KswordTheme::TextSecondaryHex()));
        }
        else {
            const GeoCoordinate gcj = virtual_location::convertCoordinate(
                locationSnapshot.coordinate,
                CoordinateSystem::Wgs84,
                CoordinateSystem::Gcj02);
            m_currentLocationLabel->setText(
                QStringLiteral("默认位置：WGS-84 %1；GCJ-02 %2；海拔 %3 米；误差 %4 米")
                    .arg(formatCoordinate(locationSnapshot.coordinate))
                    .arg(formatCoordinate(gcj))
                    .arg(locationSnapshot.coordinate.altitude, 0, 'f', 1)
                    .arg(locationSnapshot.coordinate.errorRadiusMeters, 0, 'f', 1));
            m_currentLocationLabel->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                    .arg(KswordTheme::SuccessHex()));
        }

        m_rawValueView->setDocument(defaultLocationDocument(locationSnapshot));

        setBusy(false);
    }

    void VirtualLocationPage::applyVirtualLocation()
    {
        if (m_busy) {
            return;
        }

        // 写进注册表的必须是 WGS-84：Windows 位置服务不认国内的偏移坐标系。
        const GeoCoordinate wgsCoordinate = virtual_location::convertCoordinate(
            inputCoordinate(), currentCoordinateSystem(), CoordinateSystem::Wgs84);

        setBusy(true);
        const virtual_location::OperationResult writeResult =
            virtual_location::applyDefaultLocation(wgsCoordinate);
        setBusy(false);

        if (!writeResult.ok) {
            setResultText(
                QStringLiteral("应用失败：%1").arg(writeResult.detailText),
                true);
            kLogEvent applyEvent;
            err << applyEvent << "[VirtualLocationPage] 写入系统默认位置失败。" << eol;
            refreshStatus();
            return;
        }

        // 立刻回读一次：注册表值类型或路径万一跟预期不符，这里就能当场暴露。
        const virtual_location::DefaultLocationSnapshot verifySnapshot =
            virtual_location::readDefaultLocation();
        const bool verified = verifySnapshot.present &&
            qAbs(verifySnapshot.coordinate.latitude - wgsCoordinate.latitude) < 1e-5 &&
            qAbs(verifySnapshot.coordinate.longitude - wgsCoordinate.longitude) < 1e-5;

        setResultText(
            verified
                ? QStringLiteral("已写入并回读校验通过：WGS-84 %1（%2）。要让已经在跑的程序拿到新位置，"
                                 "通常还需要重启位置服务或重启该程序。")
                      .arg(formatCoordinate(wgsCoordinate))
                      .arg(backendText(writeResult.backend))
                : QStringLiteral("已写入（%1），但回读校验没通过，请检查下方原始值清单。")
                      .arg(backendText(writeResult.backend)),
            !verified);

        kLogEvent applyEvent;
        info << applyEvent << "[VirtualLocationPage] 系统默认位置已更新。" << eol;
        refreshStatus();
    }

    void VirtualLocationPage::clearVirtualLocation()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);
        const virtual_location::OperationResult clearResult =
            virtual_location::clearDefaultLocation();
        setBusy(false);

        setResultText(
            clearResult.ok
                ? QStringLiteral("已清除系统默认位置（%1）。").arg(backendText(clearResult.backend))
                : QStringLiteral("清除失败：%1").arg(clearResult.detailText),
            !clearResult.ok);
        refreshStatus();
    }

    void VirtualLocationPage::toggleProviderPolicy(const bool disabled)
    {
        if (m_updatingInputs) {
            return;
        }
        if (disabled == m_providerDisabled) {
            return;
        }

        if (disabled &&
            !askConfirmation(
                this,
                ks::i18n::text(
                    QStringLiteral("misc.virtual_location.title"),
                    QStringLiteral("虚拟定位")),
                ks::i18n::text(
                    QStringLiteral("misc.virtual_location.action.force_provider.confirm"),
                    QStringLiteral(
                        "将写入组策略 DisableWindowsLocationProvider=1，关闭 Windows 自带的网络定位。\n\n"
                        "关闭后所有依赖真实定位的程序都只能拿到默认位置，部分系统功能（天气、地图、查找我的设备）"
                        "会失去精确位置。取消勾选即可还原。\n\n确定继续吗？")))) {
            const QSignalBlocker blocker(m_forceProviderCheck);
            m_forceProviderCheck->setChecked(false);
            return;
        }

        setBusy(true);
        const virtual_location::OperationResult policyResult =
            virtual_location::setLocationProviderDisabled(disabled);
        setBusy(false);

        if (!policyResult.ok) {
            setResultText(
                QStringLiteral("组策略修改失败：%1").arg(policyResult.detailText),
                true);
            const QSignalBlocker blocker(m_forceProviderCheck);
            m_forceProviderCheck->setChecked(m_providerDisabled);
            return;
        }

        m_providerDisabled = disabled;
        setResultText(
            disabled
                ? QStringLiteral("已禁用 Windows 位置提供程序（%1）。策略要在位置服务下次启动后才完全生效。")
                      .arg(backendText(policyResult.backend))
                : QStringLiteral("已恢复 Windows 位置提供程序（%1）。")
                      .arg(backendText(policyResult.backend)),
            false);
        refreshStatus();
    }

    void VirtualLocationPage::restartLocationService()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);
        const virtual_location::OperationResult restartResult =
            virtual_location::restartLocationService();
        setBusy(false);

        setResultText(
            restartResult.ok
                ? QStringLiteral("位置服务已停止，下一次有程序请求定位时会自动重新启动并读取新的默认位置。")
                : QStringLiteral("重启位置服务失败：%1").arg(restartResult.detailText),
            !restartResult.ok);
        refreshStatus();
    }

    void VirtualLocationPage::requestLiveFix(const bool fillInputs)
    {
        if (m_liveFixRunning) {
            return;
        }
        m_liveFixRunning = true;
        updateButtons();
        m_liveFixLabel->setText(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.livefix.running"),
                QStringLiteral("实况定位：正在向 Windows 位置服务请求坐标…")));

        const QPointer<VirtualLocationPage> guardThis(this);
        std::thread([guardThis, fillInputs]() {
            const virtual_location::LiveFixResult fixResult =
                virtual_location::queryLiveFix(kLiveFixTimeoutMilliseconds);
            QMetaObject::invokeMethod(
                qApp,
                [guardThis, fillInputs, fixResult]() {
                    if (guardThis == nullptr) {
                        return;
                    }
                    guardThis->applyLiveFixResult(fixResult, fillInputs);
                }, Qt::QueuedConnection);
        }).detach();
    }

    void VirtualLocationPage::applyLiveFixResult(
        const virtual_location::LiveFixResult& fixResult,
        const bool fillInputs)
    {
        m_liveFixRunning = false;

        if (!fixResult.ok) {
            m_liveFixLabel->setText(
                QStringLiteral("实况定位：读取失败。%1").arg(fixResult.failureText));
            m_liveFixLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::ErrorHex()));
            updateButtons();
            return;
        }

        m_liveFixLabel->setText(
            QStringLiteral("实况定位：WGS-84 %1；海拔 %2 米；误差 %3 米；来源 %4")
                .arg(formatCoordinate(fixResult.coordinate))
                .arg(fixResult.coordinate.altitude, 0, 'f', 1)
                .arg(fixResult.coordinate.errorRadiusMeters, 0, 'f', 1)
                .arg(fixResult.sourceText));
        m_liveFixLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));

        if (fillInputs) {
            // 实况读数是 WGS-84，先换到当前输入坐标系再回填，避免用户看到偏移过的数字。
            setInputCoordinate(
                virtual_location::convertCoordinate(
                    fixResult.coordinate,
                    CoordinateSystem::Wgs84,
                    currentCoordinateSystem()));
            updateConversionPreview();
        }
        updateButtons();
    }

    void VirtualLocationPage::applyPreset(const int presetIndex)
    {
        if (presetIndex < 0) {
            return;
        }
        int presetCount = 0;
        const virtual_location::PresetLocation* const presets =
            virtual_location::presetLocations(&presetCount);
        if (presetIndex >= presetCount) {
            return;
        }

        GeoCoordinate wgsCoordinate;
        wgsCoordinate.latitude = presets[presetIndex].latitude;
        wgsCoordinate.longitude = presets[presetIndex].longitude;
        wgsCoordinate.altitude = presets[presetIndex].altitude;
        wgsCoordinate.errorRadiusMeters = m_accuracySpin->value();
        setInputCoordinate(
            virtual_location::convertCoordinate(
                wgsCoordinate, CoordinateSystem::Wgs84, currentCoordinateSystem()));
        updateConversionPreview();
    }

    void VirtualLocationPage::updateConversionPreview()
    {
        const GeoCoordinate current = inputCoordinate();
        const CoordinateSystem system = currentCoordinateSystem();
        const GeoCoordinate wgs =
            virtual_location::convertCoordinate(current, system, CoordinateSystem::Wgs84);
        const GeoCoordinate gcj =
            virtual_location::convertCoordinate(current, system, CoordinateSystem::Gcj02);
        const GeoCoordinate bd =
            virtual_location::convertCoordinate(current, system, CoordinateSystem::Bd09);
        m_conversionLabel->setText(
            QStringLiteral("换算预览：WGS-84 %1｜GCJ-02 %2｜BD-09 %3（写入系统的是 WGS-84）")
                .arg(formatCoordinate(wgs))
                .arg(formatCoordinate(gcj))
                .arg(formatCoordinate(bd)));
    }

    virtual_location::CoordinateSystem VirtualLocationPage::currentCoordinateSystem() const
    {
        switch (m_coordinateSystemCombo->currentIndex()) {
        case 1:
            return CoordinateSystem::Gcj02;
        case 2:
            return CoordinateSystem::Bd09;
        case 0:
        default:
            break;
        }
        return CoordinateSystem::Wgs84;
    }

    virtual_location::GeoCoordinate VirtualLocationPage::inputCoordinate() const
    {
        GeoCoordinate coordinate;
        coordinate.latitude = m_latitudeSpin->value();
        coordinate.longitude = m_longitudeSpin->value();
        coordinate.altitude = m_altitudeSpin->value();
        coordinate.errorRadiusMeters = m_accuracySpin->value();
        coordinate.altitudeAccuracyMeters = m_accuracySpin->value();
        return coordinate;
    }

    void VirtualLocationPage::setInputCoordinate(const GeoCoordinate& coordinate)
    {
        m_updatingInputs = true;
        m_latitudeSpin->setValue(coordinate.latitude);
        m_longitudeSpin->setValue(coordinate.longitude);
        m_altitudeSpin->setValue(coordinate.altitude);
        if (coordinate.errorRadiusMeters > 0.0) {
            m_accuracySpin->setValue(coordinate.errorRadiusMeters);
        }
        m_updatingInputs = false;
    }

    void VirtualLocationPage::setResultText(const QString& text, const bool isError)
    {
        m_resultLabel->setText(text);
        m_resultLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(isError ? KswordTheme::ErrorHex() : KswordTheme::SuccessHex()));
    }

    void VirtualLocationPage::setBusy(const bool busy)
    {
        m_busy = busy;
        updateButtons();
    }

    void VirtualLocationPage::updateButtons()
    {
        const bool idle = !m_busy && !m_liveFixRunning;
        m_refreshButton->setEnabled(idle);
        m_applyButton->setEnabled(idle);
        m_clearButton->setEnabled(idle && m_defaultLocationPresent);
        m_liveFixButton->setEnabled(idle);
        m_useLiveFixButton->setEnabled(idle);
        m_restartServiceButton->setEnabled(idle);
        m_forceProviderCheck->setEnabled(idle);
    }
}
