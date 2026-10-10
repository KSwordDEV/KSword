#include "SettingsDock.h"
#include "../UI/ToolbarMetrics.h"

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

void SettingsDock::initializeOnlineScanTab()
{
    // m_onlineScanTab 作用：承载在线扫描服务的 API Key 配置控件。
    m_onlineScanTab = new QWidget(m_tabWidget);
    QVBoxLayout* rootLayout = new QVBoxLayout(m_onlineScanTab);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(12);

    QLabel* hintLabel = new QLabel(
        QStringLiteral("在线扫描模块会在运行时从本设置读取 API Key。当前右键“上传到沙箱”仅接入 VirusTotal；ThreatBook 暂不显示入口。"),
        m_onlineScanTab);
    hintLabel->setWordWrap(true);
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    languageManager.bindText(hintLabel, QStringLiteral("settings.online.hint"), QStringLiteral("在线扫描模块会在运行时从本设置读取 API Key。当前右键“上传到沙箱”仅接入 VirusTotal；ThreatBook 暂不显示入口。"));
    rootLayout->addWidget(hintLabel, 0);

    // keyGroupBox 作用：集中放置两个在线扫描服务的密钥输入框。
    QGroupBox* keyGroupBox = new QGroupBox(QStringLiteral("在线扫描 API Key"), m_onlineScanTab);
    languageManager.bindText(keyGroupBox, QStringLiteral("settings.online.group"), QStringLiteral("在线扫描 API Key"));
    QFormLayout* formLayout = new QFormLayout(keyGroupBox);
    formLayout->setContentsMargins(10, 10, 10, 10);
    formLayout->setSpacing(8);
    formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_virusTotalApiKeyEdit = new QLineEdit(keyGroupBox);
    m_virusTotalApiKeyEdit->setPlaceholderText(QStringLiteral("VirusTotal API Key"));
    m_virusTotalApiKeyEdit->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    m_virusTotalApiKeyEdit->setClearButtonEnabled(true);
    m_virusTotalApiKeyEdit->setToolTip(QStringLiteral("用于 VirusTotal v3 API 的 x-apikey 请求头；留空时上传会提示先配置 Key"));
    languageManager.bindToolTip(m_virusTotalApiKeyEdit, QStringLiteral("settings.online.virustotal.tooltip"), QStringLiteral("用于 VirusTotal v3 API 的 x-apikey 请求头；留空时上传会提示先配置 Key"));
    QLabel* virusTotalLabel = new QLabel(QStringLiteral("VirusTotal"), keyGroupBox);
    formLayout->addRow(virusTotalLabel, m_virusTotalApiKeyEdit);

    // m_threatBookApiKeyEdit 作用：保存 ThreatBook file/upload 与 file/report 使用的 apikey 参数。
    m_threatBookApiKeyEdit = new QLineEdit(keyGroupBox);
    m_threatBookApiKeyEdit->setPlaceholderText(QStringLiteral("ThreatBook / 微步在线 API Key"));
    languageManager.bindPlaceholder(m_threatBookApiKeyEdit, QStringLiteral("settings.online.threatbook.placeholder"), QStringLiteral("ThreatBook / 微步在线 API Key"));
    m_threatBookApiKeyEdit->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    m_threatBookApiKeyEdit->setClearButtonEnabled(true);
    m_threatBookApiKeyEdit->setToolTip(QStringLiteral("用于 ThreatBook v3 API 的 apikey 参数；留空时上传会提示先配置 Key"));
    languageManager.bindToolTip(m_threatBookApiKeyEdit, QStringLiteral("settings.online.threatbook.tooltip"), QStringLiteral("用于 ThreatBook v3 API 的 apikey 参数；留空时上传会提示先配置 Key"));
    QLabel* threatBookLabel = new QLabel(QStringLiteral("ThreatBook"), keyGroupBox);
    formLayout->addRow(threatBookLabel, m_threatBookApiKeyEdit);

    rootLayout->addWidget(keyGroupBox, 0);

    QLabel* storageHintLabel = new QLabel(
        QStringLiteral("提示：API Key 会保存到当前设置 JSON 中，路径与外观设置一致；若不希望保留密钥，可清空后保存。"),
        m_onlineScanTab);
    storageHintLabel->setWordWrap(true);
    languageManager.bindText(storageHintLabel, QStringLiteral("settings.online.storage_hint"), QStringLiteral("提示：API Key 会保存到当前设置 JSON 中，路径与外观设置一致；若不希望保留密钥，可清空后保存。"));
    rootLayout->addWidget(storageHintLabel, 0);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->addStretch(1);
    m_saveOnlineScanKeysButton = new QPushButton(QStringLiteral("保存 API Key"), m_onlineScanTab);
    languageManager.bindText(m_saveOnlineScanKeysButton, QStringLiteral("settings.online.save"), QStringLiteral("保存 API Key"));
    m_saveOnlineScanKeysButton->setMinimumWidth(112);
    m_saveOnlineScanKeysButton->setFixedHeight(30);
    m_saveOnlineScanKeysButton->setToolTip(QStringLiteral("保存 VirusTotal 与 ThreatBook API Key 到设置 JSON"));
    languageManager.bindToolTip(m_saveOnlineScanKeysButton, QStringLiteral("settings.online.save.tooltip"), QStringLiteral("保存 VirusTotal 与 ThreatBook API Key 到设置 JSON"));
    m_saveOnlineScanKeysButton->setEnabled(false);
    actionLayout->addWidget(m_saveOnlineScanKeysButton, 0);
    ks::ui::NormalizeToolbarRow(actionLayout);
    rootLayout->addLayout(actionLayout);

    rootLayout->addStretch(1);
    m_tabWidget->addTab(m_onlineScanTab, QStringLiteral("在线扫描"));
    languageManager.bindTab(m_tabWidget, m_onlineScanTab, QStringLiteral("settings.tab.online_scan"), QStringLiteral("在线扫描"));

    bindOnlineScanSignals();
}

void SettingsDock::bindOnlineScanSignals()
{
    if (m_virusTotalApiKeyEdit != nullptr)
    {
        connect(m_virusTotalApiKeyEdit, &QLineEdit::textEdited, this, [this](const QString& /*text*/) {
            markPendingChanges(QStringLiteral("VirusTotal API Key 变化"));
            });
    }

    // ThreatBook 输入框变化后只标记待保存，不立即写盘，保持和外观页一致的应用模型。
    if (m_threatBookApiKeyEdit != nullptr)
    {
        connect(m_threatBookApiKeyEdit, &QLineEdit::textEdited, this, [this](const QString& /*text*/) {
            markPendingChanges(QStringLiteral("ThreatBook API Key 变化"));
            });
    }

    if (m_saveOnlineScanKeysButton != nullptr)
    {
        connect(m_saveOnlineScanKeysButton, &QPushButton::clicked, this, [this]() {
            saveAndEmitFromUi(QStringLiteral("点击在线扫描 API Key 保存按钮"));
            });
    }
}
