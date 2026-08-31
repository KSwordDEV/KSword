#include "SettingsDock.h"

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Internationalization/LanguageManager.h"

#include <QCoreApplication>
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
        if (result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.unsupported"),
                QStringLiteral("当前 R0 驱动未包含蓝屏诊断安装能力。"));
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

void SettingsDock::installBugcheckDiagnosticsForCurrentSession()
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

    // 先通知主窗口显示入口，再开始后台调用，避免 R0 请求未完成时用户看不到诊断页面。
    emit bugcheckDiagnosticsInstallationStarted();
    setBugcheckDiagnosticsControlsBusy(true);
    const QPointer<SettingsDock> guardedSettingsDock(this);
    QThreadPool::globalInstance()->start(
        [guardedSettingsDock]()
        {
            const ksword::ark::BugcheckDiagnosticsResult result =
                ksword::ark::DriverClient().configureBugcheckDiagnostics(
                    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL);
            QCoreApplication* const application = QCoreApplication::instance();
            if (application == nullptr)
            {
                return;
            }

            if (!guardedSettingsDock.isNull())
            {
                QMetaObject::invokeMethod(
                    guardedSettingsDock,
                    [guardedSettingsDock, result]()
                {
                    if (guardedSettingsDock == nullptr)
                    {
                        return;
                    }

                    guardedSettingsDock->setBugcheckDiagnosticsControlsBusy(false);
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
