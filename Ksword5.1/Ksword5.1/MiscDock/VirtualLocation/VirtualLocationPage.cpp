#include "VirtualLocationPage.h"
#include "../../UI/AsyncOperation.h"
#include <tuple>
#include "../../UI/PrimaryPageStyle.h"
#include "../../UI/ParameterWorkspace.h"
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

    enum class VirtualLocationBodyText
    {
        Scope, Status, LiveFixIdle, Refresh, QueryLiveFix, Input, SystemLabel,
        PresetLabel, LatitudeLabel, LongitudeLabel, AltitudeLabel, AccuracyLabel,
        Action, ForceProvider, Apply, Clear, UseLiveFix, RestartService, Idle,
        Wgs84, Gcj02, Bd09, NoPreset, Conversion
    };
    struct VirtualLocationBodyEntry
    {
        const char* target;
        const char* key;
        const char* fallback;
        bool mnemonic;
    };
    constexpr VirtualLocationBodyEntry kVirtualLocationBody[] = {
        {"ks_virtual_location_scope", "misc.virtual_location.scope", "本页把坐标写成 Windows 的“系统默认位置”，只对通过 Windows 位置服务取位置的程序生效，"
                "而且要在系统拿不到更精确的定位源时才会被采用。浏览器网页定位、自带 IP 库或自建定位 SDK 的应用不受影响。"
                "修改只落在注册表上，随时可以用“清除虚拟定位”还原。", false},
        {"ks_virtual_location_status", "misc.virtual_location.status.title", "当前状态", false},
        {"ks_virtual_location_live_fix", "misc.virtual_location.livefix.idle", "实况定位：尚未读取。", false},
        {"ks_virtual_location_refresh", "misc.virtual_location.refresh", "刷新状态", true},
        {"ks_virtual_location_query_live_fix", "misc.virtual_location.livefix.query", "读取实况定位", true},
        {"ks_virtual_location_input", "misc.virtual_location.input.title", "虚拟坐标", false},
        {"ks_virtual_location_system_label", "misc.virtual_location.input.system", "坐标系：", false},
        {"ks_virtual_location_preset_label", "misc.virtual_location.input.preset", "预设点：", false},
        {"ks_virtual_location_latitude_label", "misc.virtual_location.input.latitude", "纬度：", false},
        {"ks_virtual_location_longitude_label", "misc.virtual_location.input.longitude", "经度：", false},
        {"ks_virtual_location_altitude_label", "misc.virtual_location.input.altitude", "海拔：", false},
        {"ks_virtual_location_accuracy_label", "misc.virtual_location.input.accuracy", "误差半径：", false},
        {"ks_virtual_location_action", "misc.virtual_location.action.title", "操作", false},
        {"ks_virtual_location_provider_state", "misc.virtual_location.action.provider_state", "Windows 位置提供程序：尚未查询", false},
        {"ks_virtual_location_apply", "misc.virtual_location.action.apply", "应用虚拟定位", true},
        {"ks_virtual_location_clear", "misc.virtual_location.action.clear", "清除虚拟定位", true},
        {"ks_virtual_location_use_live_fix", "misc.virtual_location.action.use_livefix", "用实况定位填入", true},
        {"ks_virtual_location_restart_service", "misc.virtual_location.action.restart_service", "重启位置服务", true},
        {"ks_virtual_location_result", "misc.virtual_location.action.idle", "尚未执行任何操作。", false},
        {"ksVirtualLocationSystemCombo", "", "WGS-84（GPS / Windows 原始坐标）", false},
        {"ksVirtualLocationSystemCombo", "", "GCJ-02（高德 / 腾讯地图坐标）", false},
        {"ksVirtualLocationSystemCombo", "", "BD-09（百度地图坐标）", false},
        {"ksVirtualLocationPresetCombo", "", "（不使用预设点）", false},
        {"ks_virtual_location_conversion", "", "", false}
    };
    const VirtualLocationBodyEntry& virtualLocationBodyEntry(VirtualLocationBodyText id)
    {
        return kVirtualLocationBody[static_cast<int>(id)];
    }
    QString virtualLocationBodySource(VirtualLocationBodyText id)
    {
        return QString::fromUtf8(virtualLocationBodyEntry(id).fallback);
    }
    QString virtualLocationBodyText(VirtualLocationBodyText id)
    {
        const auto& entry = virtualLocationBodyEntry(id);
        const QString fallback = virtualLocationBodySource(id);
        return *entry.key ? ks::i18n::text(QString::fromLatin1(entry.key), fallback)
            : ks::i18n::sourceText(fallback);
    }
    QString virtualLocationBodyTarget(VirtualLocationBodyText id)
    {
        return QString::fromLatin1(virtualLocationBodyEntry(id).target);
    }
    void bindVirtualLocationBody(QObject* target, VirtualLocationBodyText id)
    {
        const auto& entry = virtualLocationBodyEntry(id);
        target->setObjectName(virtualLocationBodyTarget(id));
        ks::i18n::LanguageManager::instance().bindText(target,
            QString::fromLatin1(entry.key), virtualLocationBodySource(id));
    }
    constexpr char kVirtualLocationRawSearchPrefix[] = "ks_virtual_location_diagnostics";
    constexpr double kInitialLatitude = 39.909187;
    constexpr double kInitialLongitude = 116.397451;
    constexpr double kInitialAltitude = 44.0;
    constexpr double kInitialAccuracy = 50.0;
    GeoCoordinate initialInputCoordinate()
    {
        GeoCoordinate coordinate;
        coordinate.latitude = kInitialLatitude;
        coordinate.longitude = kInitialLongitude;
        coordinate.altitude = kInitialAltitude;
        coordinate.errorRadiusMeters = kInitialAccuracy;
        coordinate.altitudeAccuracyMeters = kInitialAccuracy;
        return coordinate;
    }

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

    QString conversionPreviewText(const GeoCoordinate& current, CoordinateSystem system)
    {
        const GeoCoordinate wgs =
            ks::misc::virtual_location::convertCoordinate(current, system, CoordinateSystem::Wgs84);
        const GeoCoordinate gcj =
            ks::misc::virtual_location::convertCoordinate(current, system, CoordinateSystem::Gcj02);
        const GeoCoordinate bd =
            ks::misc::virtual_location::convertCoordinate(current, system, CoordinateSystem::Bd09);
        return QStringLiteral("换算预览：WGS-84 %1｜GCJ-02 %2｜BD-09 %3（写入系统的是 WGS-84）")
            .arg(formatCoordinate(wgs))
            .arg(formatCoordinate(gcj))
            .arg(formatCoordinate(bd));
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
    QVector<ks::ui::PageSearchBodyText> VirtualLocationPage::coldSearchBody()
    {
        QVector<ks::ui::PageSearchBodyText> body;
        body.reserve(42);
        const auto append = [&body](VirtualLocationBodyText id, const QStringList& groups = {})
        {
            body.append({virtualLocationBodyText(id), virtualLocationBodyTarget(id), groups,
                virtualLocationBodyEntry(id).mnemonic});
        };
        append(VirtualLocationBodyText::Scope);
        append(VirtualLocationBodyText::Input);
        const QStringList input{virtualLocationBodyText(VirtualLocationBodyText::Input)};
        append(VirtualLocationBodyText::SystemLabel, input);
        for (const auto id : {VirtualLocationBodyText::Wgs84, VirtualLocationBodyText::Gcj02,
            VirtualLocationBodyText::Bd09}) append(id, input);
        append(VirtualLocationBodyText::PresetLabel, input);
        append(VirtualLocationBodyText::NoPreset, input);
        int presetCount = 0;
        const auto* presets = virtual_location::presetLocations(&presetCount);
        for (int index = 0; index < presetCount; ++index)
            body.append({ks::i18n::text(QString::fromLatin1(presets[index].nameKey),
                QString::fromUtf8(presets[index].nameText)),
                virtualLocationBodyTarget(VirtualLocationBodyText::NoPreset), input, false});
        for (const auto id : {VirtualLocationBodyText::LatitudeLabel, VirtualLocationBodyText::LongitudeLabel,
            VirtualLocationBodyText::AltitudeLabel, VirtualLocationBodyText::AccuracyLabel}) append(id, input);
        body.append({ks::i18n::sourceText(conversionPreviewText(initialInputCoordinate(), CoordinateSystem::Wgs84)),
            virtualLocationBodyTarget(VirtualLocationBodyText::Conversion), input, false});
        append(VirtualLocationBodyText::Action);
        const QStringList action{virtualLocationBodyText(VirtualLocationBodyText::Action)};
        append(VirtualLocationBodyText::ForceProvider, action);
        append(VirtualLocationBodyText::UseLiveFix, action);
        append(VirtualLocationBodyText::RestartService, action);
        // Adding the original buttons/receipt to workspace layouts reparents
        // them out of their source groups before the real QObject traversal.
        append(VirtualLocationBodyText::Apply);
        append(VirtualLocationBodyText::Clear);
        append(VirtualLocationBodyText::Status);
        const QStringList status{virtualLocationBodyText(VirtualLocationBodyText::Status)};
        auto fields = ks::ui::StructuredFieldView::coldSearchBody(QString::fromLatin1(kVirtualLocationRawSearchPrefix));
        for (auto& field : fields)
        {
            field.groupTitles = status + field.groupTitles;
            body.append(std::move(field));
        }
        append(VirtualLocationBodyText::LiveFixIdle, status);
        append(VirtualLocationBodyText::Refresh, status);
        append(VirtualLocationBodyText::QueryLiveFix, status);
        append(VirtualLocationBodyText::Idle);
        return body;
    }

    VirtualLocationPage::VirtualLocationPage(QWidget* parent)
        : QWidget(parent)
    {
        m_statusOperation = new ks::ui::AsyncOperation(this);
        m_mutationOperation = new ks::ui::AsyncOperation(this);
        initializeUi();
        initializeConnections();
        m_statusOperation->setStateChangedCallback([this]() {
            if (m_statusPending && !m_statusOperation->isInFlight())
            {
                m_statusPending = false;
                setBusy(false);
                showAsyncFailure();
            }
        });
        m_mutationOperation->setStateChangedCallback([this]() {
            if (m_mutationPending && !m_mutationOperation->isInFlight())
            {
                m_mutationPending = false;
                setBusy(false);
                showAsyncFailure();
            }
        });
        updateConversionPreview();
        updateButtons();
    }

    VirtualLocationPage::~VirtualLocationPage()
    {
        m_statusOperation->close();
        m_mutationOperation->close();
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
        if (event->type() == QEvent::LanguageChange && m_providerButton) updateButtons();
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
        ks::ui::StyleWorkspacePage(this, 0);
        rootLayout->setSpacing(10);

        // 生效范围说明和内部工作区分别管理留白，避免参数框外再套一圈。
        auto* introduction = new QWidget(this); // 范围说明仍固定在页顶。
        auto* introductionLayout = new QVBoxLayout(introduction);
        introductionLayout->setContentsMargins(16, 16, 16, 0);
        rootLayout->addWidget(introduction);

        // ===================== 生效范围说明 =====================
        m_scopeLabel = new QLabel(this);
        m_scopeLabel->setWordWrap(true);
        applyScopeBannerStyle();
        bindVirtualLocationBody(m_scopeLabel, VirtualLocationBodyText::Scope);
        introductionLayout->addWidget(m_scopeLabel);

        // 单列坐标编辑与只读定位证据并排，避免经纬度横排挤出参数边界。
        auto* workspace = new ks::ui::ParameterWorkspace(this, 480);
        workspace->useWideParameterLayout(55);
        rootLayout->addWidget(workspace, 1);

        // ===================== 当前状态 =====================
        auto* statusGroup = new QGroupBox(this);
        // 已生效位置与待输入参数使用独立的轻分组，减少连续表单的混淆。
        ks::ui::StylePrimaryGroup(statusGroup);
        bindVirtualLocationBody(statusGroup, VirtualLocationBodyText::Status);
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
        m_rawValueView->setSearchTargetPrefix(QString::fromLatin1(kVirtualLocationRawSearchPrefix));
        m_rawValueView->setObjectName(QStringLiteral("ksVirtualLocationRawView"));
        m_rawValueView->setMinimumHeight(160);
        m_rawValueView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        m_rawValueView->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("默认位置注册表属性将在刷新后显示。")));
        language.bindToolTip(
            m_rawValueView,
            QStringLiteral("misc.virtual_location.raw.tooltip"),
            QStringLiteral("默认位置键下读到的值、类型、完整原始字节和 R3 / R0 读取通道。"));
        statusLayout->addWidget(m_rawValueView);

        m_liveFixLabel = new QLabel(statusGroup);
        m_liveFixLabel->setWordWrap(true);
        m_liveFixLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        bindVirtualLocationBody(m_liveFixLabel, VirtualLocationBodyText::LiveFixIdle);
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
        bindVirtualLocationBody(m_refreshButton, VirtualLocationBodyText::Refresh);
        bindVirtualLocationBody(m_liveFixButton, VirtualLocationBodyText::QueryLiveFix);
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
        ks::ui::StyleParameterSection(statusGroup);
        workspace->results()->addWidget(statusGroup, 1);

        // ===================== 虚拟坐标 =====================
        auto* inputGroup = new QGroupBox(this);
        ks::ui::StylePrimaryGroup(inputGroup);
        bindVirtualLocationBody(inputGroup, VirtualLocationBodyText::Input);
        auto* inputLayout = new QGridLayout(inputGroup);
        inputLayout->setHorizontalSpacing(10);
        inputLayout->setVerticalSpacing(8);

        auto* systemLabel = new QLabel(inputGroup);
        bindVirtualLocationBody(systemLabel, VirtualLocationBodyText::SystemLabel);
        m_coordinateSystemCombo = new QComboBox(inputGroup);
        ks::ui::StylePrimaryCombo(m_coordinateSystemCombo);
        m_coordinateSystemCombo->setObjectName(
            QStringLiteral("ksVirtualLocationSystemCombo"));
        m_coordinateSystemCombo->addItem(virtualLocationBodySource(VirtualLocationBodyText::Wgs84));
        m_coordinateSystemCombo->addItem(virtualLocationBodySource(VirtualLocationBodyText::Gcj02));
        m_coordinateSystemCombo->addItem(virtualLocationBodySource(VirtualLocationBodyText::Bd09));
        language.bindToolTip(
            m_coordinateSystemCombo,
            QStringLiteral("misc.virtual_location.input.system.tooltip"),
            QStringLiteral(
                "从国内地图复制来的坐标多半是 GCJ-02 或 BD-09；选对坐标系后会自动换算成 WGS-84 再写入系统。"));
        inputLayout->addWidget(systemLabel, 0, 0);
        inputLayout->addWidget(m_coordinateSystemCombo, 0, 1);

        auto* presetLabel = new QLabel(inputGroup);
        bindVirtualLocationBody(presetLabel, VirtualLocationBodyText::PresetLabel);
        m_presetCombo = new QComboBox(inputGroup);
        ks::ui::StylePrimaryCombo(m_presetCombo);
        m_presetCombo->setObjectName(QStringLiteral("ksVirtualLocationPresetCombo"));
        m_presetCombo->addItem(virtualLocationBodySource(VirtualLocationBodyText::NoPreset));
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
        inputLayout->addWidget(m_presetCombo, 1, 1);

        auto* latitudeLabel = new QLabel(inputGroup);
        bindVirtualLocationBody(latitudeLabel, VirtualLocationBodyText::LatitudeLabel);
        m_latitudeSpin = new QDoubleSpinBox(inputGroup);
        m_latitudeSpin->setObjectName(QStringLiteral("ksVirtualLocationLatitudeSpin"));
        m_latitudeSpin->setDecimals(8);
        m_latitudeSpin->setRange(-90.0, 90.0);
        m_latitudeSpin->setSingleStep(0.0001);
        m_latitudeSpin->setValue(kInitialLatitude);

        auto* longitudeLabel = new QLabel(inputGroup);
        bindVirtualLocationBody(longitudeLabel, VirtualLocationBodyText::LongitudeLabel);
        m_longitudeSpin = new QDoubleSpinBox(inputGroup);
        m_longitudeSpin->setObjectName(QStringLiteral("ksVirtualLocationLongitudeSpin"));
        m_longitudeSpin->setDecimals(8);
        m_longitudeSpin->setRange(-180.0, 180.0);
        m_longitudeSpin->setSingleStep(0.0001);
        m_longitudeSpin->setValue(kInitialLongitude);

        inputLayout->addWidget(latitudeLabel, 2, 0);
        inputLayout->addWidget(m_latitudeSpin, 2, 1);
        inputLayout->addWidget(longitudeLabel, 3, 0);
        inputLayout->addWidget(m_longitudeSpin, 3, 1);

        auto* altitudeLabel = new QLabel(inputGroup);
        bindVirtualLocationBody(altitudeLabel, VirtualLocationBodyText::AltitudeLabel);
        m_altitudeSpin = new QDoubleSpinBox(inputGroup);
        m_altitudeSpin->setObjectName(QStringLiteral("ksVirtualLocationAltitudeSpin"));
        m_altitudeSpin->setDecimals(2);
        m_altitudeSpin->setRange(-1000.0, 100000.0);
        m_altitudeSpin->setValue(kInitialAltitude);
        // LanguageManager::bindSuffix 只接 QSpinBox，这里两个都是 QDoubleSpinBox，
        // 直接取一次词条设进去；单位切换跟随下次页面重建。
        m_altitudeSpin->setSuffix(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.input.meter.suffix"),
                QStringLiteral(" 米")));

        auto* accuracyLabel = new QLabel(inputGroup);
        bindVirtualLocationBody(accuracyLabel, VirtualLocationBodyText::AccuracyLabel);
        m_accuracySpin = new QDoubleSpinBox(inputGroup);
        m_accuracySpin->setObjectName(QStringLiteral("ksVirtualLocationAccuracySpin"));
        m_accuracySpin->setDecimals(1);
        m_accuracySpin->setRange(0.0, 100000.0);
        m_accuracySpin->setValue(kInitialAccuracy);
        m_accuracySpin->setSuffix(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.input.meter.suffix"),
                QStringLiteral(" 米")));

        inputLayout->addWidget(altitudeLabel, 4, 0);
        inputLayout->addWidget(m_altitudeSpin, 4, 1);
        inputLayout->addWidget(accuracyLabel, 5, 0);
        inputLayout->addWidget(m_accuracySpin, 5, 1);

        m_conversionLabel = new QLabel(inputGroup);
        m_conversionLabel->setObjectName(virtualLocationBodyTarget(VirtualLocationBodyText::Conversion));
        m_conversionLabel->setWordWrap(true);
        m_conversionLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_conversionLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        inputLayout->addWidget(m_conversionLabel, 6, 0, 1, 2);

        inputLayout->setColumnStretch(1, 1);
        ks::ui::StyleParameterSection(inputGroup);
        workspace->parameters()->addWidget(inputGroup);

        // ===================== 操作 =====================
        auto* actionGroup = new QGroupBox(this);
        ks::ui::StylePrimaryGroup(actionGroup);
        bindVirtualLocationBody(actionGroup, VirtualLocationBodyText::Action);
        auto* actionLayout = new QVBoxLayout(actionGroup);
        actionLayout->setSpacing(8);

        m_providerStateLabel = new QLabel(actionGroup);
        m_providerStateLabel->setObjectName(virtualLocationBodyTarget(VirtualLocationBodyText::ForceProvider));
        m_providerStateLabel->setTextFormat(Qt::PlainText);
        m_providerStateLabel->setWordWrap(true);
        actionLayout->addWidget(m_providerStateLabel);
        m_providerButton = new QPushButton(actionGroup);
        m_providerButton->setObjectName(QStringLiteral("ks_virtual_location_provider_action"));
        m_providerButton->setToolTip(ks::i18n::sourceText(QStringLiteral(
            "这是独立的系统策略操作，不随坐标应用。禁用会影响所有使用 Windows 位置服务的程序；恢复可撤销此策略。")));
        actionLayout->addWidget(m_providerButton);

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
        bindVirtualLocationBody(m_applyButton, VirtualLocationBodyText::Apply);
        bindVirtualLocationBody(m_clearButton, VirtualLocationBodyText::Clear);
        bindVirtualLocationBody(m_useLiveFixButton, VirtualLocationBodyText::UseLiveFix);
        bindVirtualLocationBody(m_restartServiceButton, VirtualLocationBodyText::RestartService);
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
        workspace->actions()->addWidget(m_applyButton);
        workspace->actions()->addWidget(m_clearButton);
        workspace->actions()->addStretch(1);
        buttonLayout->addWidget(m_useLiveFixButton);
        buttonLayout->addWidget(m_restartServiceButton);
        buttonLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(buttonLayout);
        actionLayout->addLayout(buttonLayout);

        m_resultLabel = new QLabel(actionGroup);
        m_resultLabel->setWordWrap(true);
        m_resultLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        bindVirtualLocationBody(m_resultLabel, VirtualLocationBodyText::Idle);
        workspace->results()->addWidget(m_resultLabel);
        ks::ui::StyleParameterSection(actionGroup);
        workspace->parameters()->addWidget(actionGroup);
        // 定位字段数量适中，宽屏仅将坐标与全系统选项并排，不扩成整页表单。
        ks::ui::ArrangeParameterColumns(workspace->parameters(),
            { inputGroup }, { actionGroup }, 300);
        workspace->finish();
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
            m_providerButton,
            &QPushButton::clicked,
            this,
            [this]() { toggleProviderPolicy(!m_providerDisabled); });
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

    void VirtualLocationPage::showAsyncFailure()
    {
        setResultText(ks::i18n::text(QStringLiteral("misc.async.receipt_missing"),
            QStringLiteral("后台任务未返回有效回执，请刷新状态。")), true);
    }

    void VirtualLocationPage::refreshStatus()
    {
        if (m_busy) return;
        m_statusPending = true;
        setBusy(true);
        using Snapshot = std::pair<virtual_location::ServiceSnapshot, virtual_location::DefaultLocationSnapshot>;
        m_statusOperation->submit<int, Snapshot>(0,
            [](const int&, const ks::ui::AsyncOperationToken& token) {
                Snapshot snapshot;
                if (token.isCanceled()) return snapshot;
                snapshot.first = virtual_location::readServiceSnapshot();
                if (!token.isCanceled()) snapshot.second = virtual_location::readDefaultLocation();
                return snapshot;
            },
            [this](const Snapshot& snapshot, std::uint64_t) {
                m_statusPending = false;
                setBusy(false);
                applyStatusSnapshot(snapshot.first, snapshot.second);
                return true;
            },
            [this](std::exception_ptr) {
                m_statusPending = false;
                setBusy(false);
                showAsyncFailure();
            });
    }

    void VirtualLocationPage::applyStatusSnapshot(
        const virtual_location::ServiceSnapshot& serviceSnapshot,
        const virtual_location::DefaultLocationSnapshot& locationSnapshot)
    {
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
        m_providerStateQueried = true;
        m_providerStateLoaded = serviceSnapshot.providerPolicyReadable;

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

        updateButtons();
    }

    void VirtualLocationPage::applyVirtualLocation()
    {
        if (m_busy) {
            return;
        }

        // 写进注册表的必须是 WGS-84：Windows 位置服务不认国内的偏移坐标系。
        const GeoCoordinate wgsCoordinate = virtual_location::convertCoordinate(
            inputCoordinate(), currentCoordinateSystem(), CoordinateSystem::Wgs84);

        runMutation([wgsCoordinate]() {
            const auto result = virtual_location::applyDefaultLocation(wgsCoordinate);
            kLogEvent applyEvent;
            if (!result.ok) err << applyEvent << "[VirtualLocationPage] 写入系统默认位置失败。" << eol;
            else info << applyEvent << "[VirtualLocationPage] 系统默认位置已更新。" << eol;
            return result;
        },
            [this, wgsCoordinate](const virtual_location::OperationResult& writeResult,
                const virtual_location::DefaultLocationSnapshot& verifySnapshot) {
                if (!writeResult.ok) {
                    setResultText(
                        QStringLiteral("应用失败：%1").arg(writeResult.detailText),
                        true);
                    return;
                }

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

            });
    }

    void VirtualLocationPage::clearVirtualLocation()
    {
        if (m_busy) {
            return;
        }
        runMutation([]() { return virtual_location::clearDefaultLocation(); },
            [this](const virtual_location::OperationResult& clearResult,
                const virtual_location::DefaultLocationSnapshot&) {
                setResultText(
                    clearResult.ok
                        ? QStringLiteral("已清除系统默认位置（%1）。").arg(backendText(clearResult.backend))
                        : QStringLiteral("清除失败：%1").arg(clearResult.detailText),
                    !clearResult.ok);
            });
    }

    void VirtualLocationPage::toggleProviderPolicy(const bool disabled)
    {
        if (m_busy || m_liveFixRunning || !m_providerStateLoaded) return;
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
                        "会失去精确位置。点击“恢复位置提供程序”可撤销此策略。\n\n确定继续吗？")))) {
            return;
        }

        runMutation([disabled]() { return virtual_location::setLocationProviderDisabled(disabled); },
            [this, disabled](const virtual_location::OperationResult& policyResult,
                const virtual_location::DefaultLocationSnapshot&) {
                if (!policyResult.ok) {
                    setResultText(
                        QStringLiteral("组策略修改失败：%1").arg(policyResult.detailText),
                        true);
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
            });
    }

    void VirtualLocationPage::restartLocationService()
    {
        if (m_busy) {
            return;
        }
        runMutation([]() { return virtual_location::restartLocationService(); },
            [this](const virtual_location::OperationResult& restartResult,
                const virtual_location::DefaultLocationSnapshot&) {
                setResultText(
                    restartResult.ok
                        ? QStringLiteral("位置服务已停止，下一次有程序请求定位时会自动重新启动并读取新的默认位置。")
                        : QStringLiteral("重启位置服务失败：%1").arg(restartResult.detailText),
                    !restartResult.ok);
            });
    }

    void VirtualLocationPage::runMutation(
        std::function<virtual_location::OperationResult()> operation,
        std::function<void(const virtual_location::OperationResult&,
            const virtual_location::DefaultLocationSnapshot&)> applyReceipt)
    {
        if (m_busy) return;
        m_statusOperation->cancel();
        m_mutationPending = true;
        setBusy(true);
        using Operation = std::function<virtual_location::OperationResult()>;
        using Receipt = std::tuple<virtual_location::OperationResult,
            virtual_location::ServiceSnapshot, virtual_location::DefaultLocationSnapshot>;
        const auto accepted = m_mutationOperation->submitTransaction<Operation, Receipt>(std::move(operation),
            [](const Operation& execute) {
                const auto result = execute();
                const auto service = virtual_location::readServiceSnapshot();
                const auto location = virtual_location::readDefaultLocation();
                return Receipt{result, service, location};
            },
            [this, applyReceipt = std::move(applyReceipt)](const Receipt& receipt, std::uint64_t) {
                m_mutationPending = false;
                const QPointer<VirtualLocationPage> alive(this);
                applyReceipt(std::get<0>(receipt), std::get<2>(receipt));
                if (alive)
                {
                    alive->applyStatusSnapshot(std::get<1>(receipt), std::get<2>(receipt));
                    alive->setBusy(false);
                }
                return true;
            },
            [this](std::exception_ptr) {
                m_mutationPending = false;
                setBusy(false);
                showAsyncFailure();
            });
        if (accepted == 0)
        {
            m_mutationPending = false;
            setBusy(false);
            showAsyncFailure();
        }
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
        m_conversionLabel->setText(
            conversionPreviewText(current, system));
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
        m_providerButton->setEnabled(idle && m_providerStateLoaded);
        m_providerButton->setText(ks::i18n::sourceText(m_providerDisabled
            ? QStringLiteral("恢复位置提供程序") : QStringLiteral("禁用位置提供程序")));
        m_providerStateLabel->setText(ks::i18n::sourceText(!m_providerStateQueried
            ? QStringLiteral("Windows 位置提供程序：尚未查询")
            : !m_providerStateLoaded ? QStringLiteral("Windows 位置提供程序：策略读取失败，请刷新状态。")
            : m_providerDisabled ? QStringLiteral("Windows 位置提供程序：已被此策略禁用")
                                 : QStringLiteral("Windows 位置提供程序：未被此策略禁用")));
    }
}
