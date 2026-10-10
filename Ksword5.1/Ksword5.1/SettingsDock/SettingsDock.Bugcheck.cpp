#include "SettingsDock.h"
#include "../UI/ToolbarMetrics.h"

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Internationalization/LanguageManager.h"

#include <QCoreApplication>
#include <QComboBox>
#include <QGroupBox>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QThreadPool>
#include <QVBoxLayout>

namespace
{
    // bugcheckDiagnosticsStatusText：按当前语言返回自动安装状态说明，忙碌状态优先展示。
    QString bugcheckDiagnosticsStatusText(const bool autoInstallEnabled, const bool busy)
    {
        if (busy)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.installing"),
                QStringLiteral("正在由 R0 工作项准备蓝屏诊断。卸载驱动会安全取消本次准备。"));
        }
        if (autoInstallEnabled)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.auto_enabled"),
                QStringLiteral("已启用自动安装：后续 R0 驱动成功启动后，程序会发送安装 IOCTL。"));
        }
        return ks::i18n::text(
            QStringLiteral("settings.features.bugcheck.status.auto_disabled"),
            QStringLiteral("未配置自动安装。普通 R0 驱动启动不会扫描 BGP 私有函数或注册蓝屏诊断回调。"));
    }

    // bugcheckDiagnosticsInstallResultText：把协议状态转换为不夸大成功范围的用户提示。
    QString bugcheckDiagnosticsInstallResultText(
        const ksword::ark::BugcheckDiagnosticsResult& result)
    {
        // 旧协议响应已送达驱动；优先解释兼容要求，不把版本拒绝归类为传输失败。
        if (result.unsupported ||
            (result.io.ok &&
             result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED))
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.unsupported"),
                QStringLiteral("当前加载的 R0 驱动不支持蓝屏模式协议。请更新并重新加载驱动后重试。"));
        }
        if (!result.io.ok && result.io.message == "bugcheck_render_mode_not_applied")
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.mode_failed"),
                QStringLiteral("渲染模式已保存，但当前驱动未应用此模式。Win32：%1，状态：%2。"))
                .arg(result.io.win32Error)
                .arg(result.response.status);
        }
        if (!result.io.ok)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.transport_failed"),
                QStringLiteral("安装请求未送达 R0 驱动。Win32 错误：%1。"))
                .arg(result.io.win32Error);
        }
        if (result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.session_installed"),
                QStringLiteral("本次蓝屏诊断已安装。驱动卸载或系统重启后失效。"));
        }
        if (result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.busy"),
                QStringLiteral("蓝屏诊断正在安装或清理，请等待当前操作完成。"));
        }
        if (result.response.status ==
                KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_PREPARATION_FAILED &&
            static_cast<unsigned long>(result.response.lastStatus) == 0xC00000B5UL)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.timeout"),
                QStringLiteral("蓝屏诊断未能在 30 秒安全预算内完成，R0 已停止继续准备并清理临时资源。"));
        }
        return ks::i18n::text(
            QStringLiteral("settings.features.bugcheck.status.preparation_failed"),
            QStringLiteral("蓝屏诊断准备失败，Windows 原生蓝屏和转储不会被修改。NTSTATUS：0x%1。"))
            .arg(static_cast<unsigned long>(result.response.lastStatus), 8, 16, QLatin1Char('0'))
            .toUpper();
    }
}

void SettingsDock::initializeBugcheckDiagnosticsControls(
    QVBoxLayout* const featuresRootLayout)
{
    if (featuresRootLayout == nullptr)
    {
        return;
    }

    // 此分组早于整页配置载入；先取模式字段，确保初始选项不会回落到构造默认值。
    m_currentAppearanceSettings.bugcheckDiagnosticsRenderMode =
        ks::settings::loadAppearanceSettings().bugcheckDiagnosticsRenderMode;
    // 功能独立分组只承载配置与明确安装动作，不与危险 Guard 的一次性 Hook 混在一起。
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    QGroupBox* const bugcheckGroupBox = new QGroupBox(
        QStringLiteral("蓝屏诊断"),
        m_featuresTab);
    languageManager.bindText(
        bugcheckGroupBox,
        QStringLiteral("settings.features.bugcheck.group"),
        QStringLiteral("蓝屏诊断"));
    QVBoxLayout* const bugcheckLayout = new QVBoxLayout(bugcheckGroupBox);
    bugcheckLayout->setSpacing(8);

    QLabel* const hintLabel = new QLabel(
        QStringLiteral("仅在自动安装已配置或明确点击“本次安装”后，R0 才会扫描 BGP 私有函数、准备蓝屏绘制资源并注册转储回调。此操作曾在不兼容系统上造成异常，安装失败时会保留 Windows 原生蓝屏和转储路径。"),
        bugcheckGroupBox);
    hintLabel->setWordWrap(true);
    languageManager.bindText(
        hintLabel,
        QStringLiteral("settings.features.bugcheck.hint"),
        QStringLiteral("仅在自动安装已配置或明确点击“本次安装”后，R0 才会扫描 BGP 私有函数、准备蓝屏绘制资源并注册转储回调。此操作曾在不兼容系统上造成异常，安装失败时会保留 Windows 原生蓝屏和转储路径。"));
    bugcheckLayout->addWidget(hintLabel);

    // 模式项的业务值直接使用共享协议；翻译只改变可见文字，不改变模式值。
    QLabel* const renderModeLabel = new QLabel(bugcheckGroupBox); // 模式控件的可访问标签。
    languageManager.bindText(
        renderModeLabel,
        QStringLiteral("settings.features.bugcheck.render_mode"),
        QStringLiteral("蓝屏渲染模式"));
    bugcheckLayout->addWidget(renderModeLabel);
    m_bugcheckDiagnosticsRenderModeCombo = new QComboBox(bugcheckGroupBox);
    renderModeLabel->setBuddy(m_bugcheckDiagnosticsRenderModeCombo);
    m_bugcheckDiagnosticsRenderModeCombo->addItem(
        QStringLiteral("诊断面板（默认）"),
        static_cast<int>(KSWORD_ARK_BUGCHECK_RENDER_MODE_DIAGNOSTIC));
    m_bugcheckDiagnosticsRenderModeCombo->addItem(
        QStringLiteral("Linux 风格（诊断二维码）"),
        static_cast<int>(KSWORD_ARK_BUGCHECK_RENDER_MODE_LINUX_QR));
    languageManager.bindComboBoxItem(
        m_bugcheckDiagnosticsRenderModeCombo,
        0,
        QStringLiteral("settings.features.bugcheck.render_mode.diagnostic"),
        QStringLiteral("诊断面板（默认）"));
    languageManager.bindComboBoxItem(
        m_bugcheckDiagnosticsRenderModeCombo,
        1,
        QStringLiteral("settings.features.bugcheck.render_mode.linux_qr"),
        QStringLiteral("Linux 风格（诊断二维码）"));
    languageManager.bindToolTip(
        m_bugcheckDiagnosticsRenderModeCombo,
        QStringLiteral("settings.features.bugcheck.render_mode.tooltip"),
        QStringLiteral("选择后立即保存。已安装的诊断会切换模式；尚未安装时在下次安装生效。Linux 风格将已采集诊断信息写入中央二维码。"));
    bugcheckLayout->addWidget(m_bugcheckDiagnosticsRenderModeCombo);
    // activated 只响应用户操作，载入配置或切换语言不会误写磁盘/访问驱动。
    connect(
        m_bugcheckDiagnosticsRenderModeCombo,
        QOverload<int>::of(&QComboBox::activated),
        this,
        [this](const int selectedIndex)
        {
            setBugcheckDiagnosticsRenderMode(
                m_bugcheckDiagnosticsRenderModeCombo->itemData(selectedIndex).toInt());
        });

    m_bugcheckDiagnosticsStatusLabel = new QLabel(bugcheckGroupBox);
    m_bugcheckDiagnosticsStatusLabel->setWordWrap(true);
    bugcheckLayout->addWidget(m_bugcheckDiagnosticsStatusLabel);

    // 三个文字按钮表达的是不同持久化与生命周期语义，图标不足以避免误解。
    m_enableBugcheckDiagnosticsAutoInstallButton = new QPushButton(
        QStringLiteral("驱动安装时自动安装蓝屏诊断"),
        bugcheckGroupBox);
    languageManager.bindText(
        m_enableBugcheckDiagnosticsAutoInstallButton,
        QStringLiteral("settings.features.bugcheck.auto_install"),
        QStringLiteral("驱动安装时自动安装蓝屏诊断"));
    m_enableBugcheckDiagnosticsAutoInstallButton->setToolTip(
        QStringLiteral("写入配置文件。之后每次 R0 驱动成功启动，程序都会发送蓝屏诊断安装 IOCTL。"));
    languageManager.bindToolTip(
        m_enableBugcheckDiagnosticsAutoInstallButton,
        QStringLiteral("settings.features.bugcheck.auto_install.tooltip"),
        QStringLiteral("写入配置文件。之后每次 R0 驱动成功启动，程序都会发送蓝屏诊断安装 IOCTL。"));
    bugcheckLayout->addWidget(m_enableBugcheckDiagnosticsAutoInstallButton);
    ks::ui::NormalizeToolbarControl(m_enableBugcheckDiagnosticsAutoInstallButton);

    m_disableBugcheckDiagnosticsAutoInstallButton = new QPushButton(
        QStringLiteral("取消自动安装"),
        bugcheckGroupBox);
    languageManager.bindText(
        m_disableBugcheckDiagnosticsAutoInstallButton,
        QStringLiteral("settings.features.bugcheck.cancel_auto_install"),
        QStringLiteral("取消自动安装"));
    m_disableBugcheckDiagnosticsAutoInstallButton->setToolTip(
        QStringLiteral("移除配置文件中的自动安装项。不影响当前已经安装的诊断，当前诊断会在驱动卸载或重启后失效。"));
    languageManager.bindToolTip(
        m_disableBugcheckDiagnosticsAutoInstallButton,
        QStringLiteral("settings.features.bugcheck.cancel_auto_install.tooltip"),
        QStringLiteral("移除配置文件中的自动安装项。不影响当前已经安装的诊断，当前诊断会在驱动卸载或重启后失效。"));
    bugcheckLayout->addWidget(m_disableBugcheckDiagnosticsAutoInstallButton);
    ks::ui::NormalizeToolbarControl(m_disableBugcheckDiagnosticsAutoInstallButton);

    m_installBugcheckDiagnosticsForSessionButton = new QPushButton(
        QStringLiteral("本次安装"),
        bugcheckGroupBox);
    languageManager.bindText(
        m_installBugcheckDiagnosticsForSessionButton,
        QStringLiteral("settings.features.bugcheck.install_session"),
        QStringLiteral("本次安装"));
    m_installBugcheckDiagnosticsForSessionButton->setToolTip(
        QStringLiteral("立即向当前 R0 驱动发送安装 IOCTL。驱动卸载或系统重启后失效，不改写自动安装配置。"));
    languageManager.bindToolTip(
        m_installBugcheckDiagnosticsForSessionButton,
        QStringLiteral("settings.features.bugcheck.install_session.tooltip"),
        QStringLiteral("立即向当前 R0 驱动发送安装 IOCTL。驱动卸载或系统重启后失效，不改写自动安装配置。"));
    bugcheckLayout->addWidget(m_installBugcheckDiagnosticsForSessionButton);
    ks::ui::NormalizeToolbarControl(m_installBugcheckDiagnosticsForSessionButton);

    featuresRootLayout->addWidget(bugcheckGroupBox);
    connect(
        m_enableBugcheckDiagnosticsAutoInstallButton,
        &QPushButton::clicked,
        this,
        [this]()
        {
            setBugcheckDiagnosticsAutoInstall(true);
        });
    connect(
        m_disableBugcheckDiagnosticsAutoInstallButton,
        &QPushButton::clicked,
        this,
        [this]()
        {
            setBugcheckDiagnosticsAutoInstall(false);
        });
    connect(
        m_installBugcheckDiagnosticsForSessionButton,
        &QPushButton::clicked,
        this,
        [this]()
        {
            installBugcheckDiagnosticsForCurrentSession();
        });
    refreshBugcheckDiagnosticsStatusText();
}

void SettingsDock::refreshBugcheckDiagnosticsStatusText()
{
    if (m_bugcheckDiagnosticsRenderModeCombo != nullptr)
    {
        const int modeIndex = m_bugcheckDiagnosticsRenderModeCombo->findData(
            m_currentAppearanceSettings.bugcheckDiagnosticsRenderMode); // 恢复持久化选择。
        m_bugcheckDiagnosticsRenderModeCombo->setCurrentIndex(modeIndex >= 0 ? modeIndex : 0);
    }
    if (m_bugcheckDiagnosticsStatusLabel == nullptr || m_bugcheckDiagnosticsInstallBusy)
    {
        return;
    }

    // 标签默认只反映持久化选项，手动安装完成的会话态由异步回调写入更具体的结果。
    m_bugcheckDiagnosticsStatusLabel->setText(
        bugcheckDiagnosticsStatusText(
            m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled,
            false));
}

void SettingsDock::setBugcheckDiagnosticsAutoInstall(const bool enabled)
{
    if (m_bugcheckDiagnosticsInstallBusy)
    {
        return;
    }

    // 读取最新磁盘配置后只改一个字段，避免操作按钮误提交外观页中尚未点击“应用”的内容。
    ks::settings::AppearanceSettings savedSettings = ks::settings::loadAppearanceSettings();
    savedSettings.bugcheckDiagnosticsAutoInstallEnabled = enabled;
    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(savedSettings, &saveErrorText))
    {
        if (m_bugcheckDiagnosticsStatusLabel != nullptr)
        {
            m_bugcheckDiagnosticsStatusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("settings.features.bugcheck.status.save_failed"),
                    QStringLiteral("蓝屏诊断自动安装配置保存失败：%1。"))
                .arg(saveErrorText));
        }
        kLogEvent settingsEvent;
        err << settingsEvent
            << "[SettingsDock] 保存蓝屏诊断自动安装配置失败: "
            << saveErrorText.toStdString()
            << eol;
        return;
    }

    // 内存快照同步后再发信号，使 MainWindow 在当前会话立即更新诊断页入口可见性。
    m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled = enabled;
    refreshBugcheckDiagnosticsStatusText();
    emit bugcheckDiagnosticsAutoInstallChanged(enabled);

    kLogEvent settingsEvent;
    info << settingsEvent
        << "[SettingsDock] 蓝屏诊断自动安装配置已更新: "
        << (enabled ? "enabled" : "disabled")
        << eol;
}

void SettingsDock::setBugcheckDiagnosticsRenderMode(const int renderMode)
{
    if (m_bugcheckDiagnosticsInstallBusy ||
        (renderMode != static_cast<int>(KSWORD_ARK_BUGCHECK_RENDER_MODE_DIAGNOSTIC) &&
         renderMode != static_cast<int>(KSWORD_ARK_BUGCHECK_RENDER_MODE_LINUX_QR)))
    {
        return;
    }

    // 只改最新磁盘快照中的模式字段，不提交外观页尚未应用的选项。
    ks::settings::AppearanceSettings savedSettings = ks::settings::loadAppearanceSettings();
    savedSettings.bugcheckDiagnosticsRenderMode = renderMode;
    QString saveErrorText; // 保存失败说明回投状态标签，保留原模式选择。
    if (!ks::settings::saveAppearanceSettings(savedSettings, &saveErrorText))
    {
        refreshBugcheckDiagnosticsStatusText();
        m_bugcheckDiagnosticsStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.mode_save_failed"),
                QStringLiteral("蓝屏渲染模式保存失败：%1。"))
                .arg(saveErrorText));
        return;
    }

    // 保存成功同步当前页及主窗口快照，下次驱动启动始终使用同一模式。
    m_currentAppearanceSettings.bugcheckDiagnosticsRenderMode = renderMode;
    emit bugcheckDiagnosticsRenderModeChanged(renderMode);
    if (!ks::ui::isCurrentProcessElevated())
    {
        m_bugcheckDiagnosticsStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.mode_saved"),
                QStringLiteral("渲染模式已保存，将在下次安装蓝屏诊断时使用。")));
        return;
    }
    configureBugcheckDiagnosticsForCurrentSession(
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_SET_RENDER_MODE);
}

void SettingsDock::installBugcheckDiagnosticsForCurrentSession()
{
    configureBugcheckDiagnosticsForCurrentSession(
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL);
}

void SettingsDock::configureBugcheckDiagnosticsForCurrentSession(const unsigned long action)
{
    if (m_bugcheckDiagnosticsInstallBusy)
    {
        return;
    }
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("蓝屏诊断本次安装"));
        return;
    }

    // 仅安装动作请求显示诊断入口；模式切换不会隐式安装回调或扫描 BGP。
    if (action == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL)
    {
        emit bugcheckDiagnosticsInstallationStarted();
    }
    setBugcheckDiagnosticsControlsBusy(true);
    if (action == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_SET_RENDER_MODE)
    {
        m_bugcheckDiagnosticsStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.mode_updating"),
                QStringLiteral("正在更新蓝屏渲染模式。")));
    }
    const unsigned long renderMode = static_cast<unsigned long>(
        m_currentAppearanceSettings.bugcheckDiagnosticsRenderMode); // 捕获本次操作的模式值。
    const QPointer<SettingsDock> guardedSettingsDock(this); // 异步回投避免访问已关闭的设置页。
    QThreadPool::globalInstance()->start(
        [guardedSettingsDock, action, renderMode]()
        {
            const ksword::ark::BugcheckDiagnosticsResult result =
                ksword::ark::DriverClient().configureBugcheckDiagnostics(action, renderMode);
            QCoreApplication* const application = QCoreApplication::instance();
            if (application == nullptr)
            {
                return;
            }

            if (!guardedSettingsDock.isNull())
            {
                QMetaObject::invokeMethod(
                    guardedSettingsDock,
                    [guardedSettingsDock, result, action, renderMode]()
                {
                    if (guardedSettingsDock == nullptr)
                    {
                        return;
                    }

                    guardedSettingsDock->setBugcheckDiagnosticsControlsBusy(false);
                    // 切换结果区分“已保存”与“当前驱动已应用”，不把离线配置称为成功切换。
                    if (action == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_SET_RENDER_MODE)
                    {
                        QString modeStatusText; // 当前模式请求的可见结果。
                        if (result.unsupported ||
                            (result.io.ok &&
                             result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED))
                        {
                            modeStatusText = bugcheckDiagnosticsInstallResultText(result);
                        }
                        else if (result.io.ok &&
                            result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK &&
                            result.response.renderMode == renderMode)
                        {
                            modeStatusText = ks::i18n::text(
                                QStringLiteral("settings.features.bugcheck.status.mode_applied"),
                                QStringLiteral("当前蓝屏渲染模式已更新。"));
                        }
                        else if ((result.io.ok &&
                            result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INACTIVE) ||
                            (!result.io.ok &&
                             (result.io.win32Error == ERROR_FILE_NOT_FOUND ||
                              result.io.win32Error == ERROR_PATH_NOT_FOUND ||
                              result.io.win32Error == ERROR_SERVICE_NOT_ACTIVE)))
                        {
                            modeStatusText = ks::i18n::text(
                                QStringLiteral("settings.features.bugcheck.status.mode_saved"),
                                QStringLiteral("渲染模式已保存，将在下次安装蓝屏诊断时使用。"));
                        }
                        else
                        {
                            modeStatusText = ks::i18n::text(
                                QStringLiteral("settings.features.bugcheck.status.mode_failed"),
                                QStringLiteral("渲染模式已保存，但当前驱动未应用此模式。Win32：%1，状态：%2。"))
                                .arg(result.io.win32Error)
                                .arg(result.response.status);
                        }
                        guardedSettingsDock->m_bugcheckDiagnosticsStatusLabel->setText(modeStatusText);
                        return;
                    }
                    if (guardedSettingsDock->m_bugcheckDiagnosticsStatusLabel != nullptr)
                    {
                        guardedSettingsDock->m_bugcheckDiagnosticsStatusLabel->setText(
                            bugcheckDiagnosticsInstallResultText(result));
                    }
                    if (result.io.ok &&
                        result.response.status ==
                            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
                    {
                        emit guardedSettingsDock->bugcheckDiagnosticsInstalledForSession();
                    }

                    kLogEvent settingsEvent;
                    if (result.io.ok &&
                        result.response.status ==
                            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
                    {
                        info << settingsEvent
                            << "[SettingsDock] 本次蓝屏诊断安装完成, callbackMask=0x"
                            << std::hex
                            << result.response.callbackMask
                            << std::dec
                            << eol;
                    }
                    else
                    {
                        warn << settingsEvent
                            << "[SettingsDock] 本次蓝屏诊断安装未完成, win32="
                            << result.io.win32Error
                            << ", protocol="
                            << result.response.status
                            << ", ntstatus=0x"
                            << std::hex
                            << static_cast<unsigned long>(result.response.lastStatus)
                            << std::dec
                            << eol;
                    }
                },
                Qt::QueuedConnection);
            }
        });
}

void SettingsDock::setBugcheckDiagnosticsControlsBusy(const bool busy)
{
    m_bugcheckDiagnosticsInstallBusy = busy;
    if (m_bugcheckDiagnosticsRenderModeCombo != nullptr)
    {
        m_bugcheckDiagnosticsRenderModeCombo->setEnabled(!busy);
    }
    if (m_enableBugcheckDiagnosticsAutoInstallButton != nullptr)
    {
        m_enableBugcheckDiagnosticsAutoInstallButton->setEnabled(!busy);
    }
    if (m_disableBugcheckDiagnosticsAutoInstallButton != nullptr)
    {
        m_disableBugcheckDiagnosticsAutoInstallButton->setEnabled(!busy);
    }
    if (m_installBugcheckDiagnosticsForSessionButton != nullptr)
    {
        m_installBugcheckDiagnosticsForSessionButton->setEnabled(!busy);
    }
    if (m_bugcheckDiagnosticsStatusLabel != nullptr && busy)
    {
        m_bugcheckDiagnosticsStatusLabel->setText(
            bugcheckDiagnosticsStatusText(
                m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled,
                true));
    }
}
