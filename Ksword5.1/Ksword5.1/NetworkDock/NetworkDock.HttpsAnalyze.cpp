#include "NetworkDock.InternalCommon.h"
#include "../UI/CodeTextEdit.h"
#include "../UI/UI_All.h"
#include "../UI/VisibleTableWidget.h"
#include "HttpsProxyService.h"
#include "../theme.h"

#include <QApplication>
#include <QFileDialog>
#include <QSaveFile>
#include <QTextStream>
#include <WinInet.h>

#pragma comment(lib, "Wininet.lib")

using namespace network_dock_detail;

namespace
{
    // HttpsParsedColumn：HTTPS解析表列索引定义。
    enum HttpsParsedColumn
    {
        HttpsParsedColumnTime = 0,
        HttpsParsedColumnSession,
        HttpsParsedColumnClient,
        HttpsParsedColumnProcess,
        HttpsParsedColumnHost,
        HttpsParsedColumnEvent,
        HttpsParsedColumnMethod,
        HttpsParsedColumnPath,
        HttpsParsedColumnStatus,
        HttpsParsedColumnContentType,
        HttpsParsedColumnTls,
        HttpsParsedColumnAlpn,
        HttpsParsedColumnElapsed,
        HttpsParsedColumnUpload,
        HttpsParsedColumnDownload,
        HttpsParsedColumnDetail,
        HttpsParsedColumnCount
    };

    // kMaxHttpsParsedEntries 用途：限制 UI 和详情缓存的记录数，避免长期监控导致内存持续增长。
    constexpr int kMaxHttpsParsedEntries = 10000;

    // g_httpsProxyBusyOperationActive 用途：
    // - 标记 HTTPS 解析页是否有“根证书准备”或“代理停止”后台任务在执行；
    // - 任务期间控制栏按钮统一置灰，既做重入保护，也给用户明确反馈；
    // - 进程内只会存在一个 HTTPS 解析页，且读写全部发生在 UI 线程，
    //   因此用文件级静态状态承载，避免为此改动被多个文件共用的 NetworkDock.h。
    bool g_httpsProxyBusyOperationActive = false;

    // buildHttpsProxyStatusText 作用：
    // - 按代理运行状态拼出状态标签文本，供异步回调恢复标签时复用同一批文案。
    // 参数 proxyRunning：代理是否处于运行状态。
    // 参数 listenAddressText：当前监听地址文本。
    // 参数 listenPort：当前监听端口。
    // 返回：可直接交给 updateHttpsProxyStatusLabel 的状态文本。
    QString buildHttpsProxyStatusText(
        const bool proxyRunning,
        const QString& listenAddressText,
        const std::uint16_t listenPort)
    {
        if (!proxyRunning)
        {
            return QStringLiteral("状态：HTTPS代理未启动");
        }
        return QStringLiteral("状态：HTTPS代理已启动，监听 %1:%2")
            .arg(listenAddressText)
            .arg(listenPort);
    }

    // buildHttpsDetailWindowStyle 作用：
    // - 为 HTTPS 详情窗生成独立主题样式；
    // - 重点覆盖 QPlainTextEdit/QTabWidget/QLabel，修复深色模式下残留白底。
    QString buildHttpsDetailWindowStyle()
    {
        const QString windowBackground = KswordTheme::SurfaceHex();
        const QString panelBackground = KswordTheme::SurfaceAltHex();
        // 静音底色在 palette 里没有对应角色，退一档取 alternate-base；
        // 输入区仍有 1px 边框区分，视觉差异可以忽略。
        const QString inputBackground = KswordTheme::SurfaceAltHex();
        const QString borderColor = KswordTheme::BorderHex();
        const QString textColor = KswordTheme::TextPrimaryHex();
        const QString secondaryTextColor = KswordTheme::TextSecondaryHex();
        const QString accentColor = KswordTheme::PrimaryBlueHex;

        return QStringLiteral(
            "QWidget{"
            "  background:%1;"
            "  color:%2;"
            "}"
            "QLabel{"
            "  background:transparent;"
            "  color:%2;"
            "}"
            "QTabWidget::pane{"
            "  background:%3;"
            "  border:1px solid %4;"
            "  border-radius:4px;"
            "}"
            "QTabBar::tab{"
            "  background:%1;"
            "  color:%5;"
            "  border:1px solid %4;"
            "  padding:6px 12px;"
            "  margin-right:2px;"
            "  border-top-left-radius:4px;"
            "  border-top-right-radius:4px;"
            "}"
            "QTabBar::tab:selected{"
            "  background:%3;"
            "  color:%2;"
            "  border-bottom-color:%3;"
            "}"
            "QPlainTextEdit{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %4;"
            "  selection-background-color:%7;"
            "  selection-color:%8;"
            "}"
            "QMenu{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %4;"
            "}"
            "QMenu::item:selected{"
            "  background:%7;"
            "  color:%8;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%4;"
            "  margin:2px 6px;"
            "}"
            "QScrollBar:vertical,QScrollBar:horizontal{"
            "  background:%3;"
            "}"
            "QScrollBar::handle:vertical,QScrollBar::handle:horizontal{"
            "  background:%7;"
            "}")
            .arg(windowBackground)
            .arg(textColor)
            .arg(panelBackground)
            .arg(borderColor)
            .arg(secondaryTextColor)
            .arg(inputBackground)
            .arg(accentColor)
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    class HttpsParsedDetailWindow final : public QWidget
    {
    public:
        explicit HttpsParsedDetailWindow(const ks::network::HttpsProxyParsedEntry& parsedEntry, QWidget* parent = nullptr)
            : QWidget(parent)
        {
            // wrapFieldHtml 作用：
            // - 把长字段包装成可自动换行的富文本块；
            // - 避免长路径/长主机名把详情窗横向撑出屏幕。
            const auto wrapFieldHtml =
                [](const QString& fieldText) -> QString
                {
                    return QStringLiteral(
                        "<div style='white-space:pre-wrap;word-break:break-all;'>%1</div>")
                        .arg(fieldText.toHtmlEscaped());
                };

            setAttribute(Qt::WA_DeleteOnClose, true);
            setWindowFlag(Qt::Window, true);
            setAttribute(Qt::WA_StyledBackground, true);
            setAutoFillBackground(true);
            setWindowTitle(QStringLiteral("HTTPS详情 - #%1 %2")
                .arg(parsedEntry.sessionId)
                .arg(parsedEntry.eventTypeText));
            ks::ui::applyResponsiveWindowGeometry(
                this,
                parent,
                QSize(1376, 720),
                QSize(720, 480));
            setStyleSheet(buildHttpsDetailWindowStyle());

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(8, 8, 8, 8);
            rootLayout->setSpacing(6);

            QLabel* metaLabel = new QLabel(this);
            metaLabel->setWordWrap(true);
            metaLabel->setTextFormat(Qt::RichText);
            metaLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            metaLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
            metaLabel->setStyleSheet(QStringLiteral("padding:6px 8px;border:1px solid %1;border-radius:4px;")
                .arg(KswordTheme::BorderHex()));
            metaLabel->setText(QStringLiteral(
                "时间: %1<br/>客户端: %2<br/>进程: %3<br/>目标: %4:%5<br/>事件: %6<br/>方法: %7<br/>路径: %8<br/>状态码: %9<br/>内容类型: %10<br/>内容长度: %11<br/>耗时: %12 ms<br/>上行/下行: %13 / %14 字节<br/>TLS: %15<br/>ALPN: %16<br/>密码套件: %17<br/>SNI: %18<br/>证书主体: %19<br/>证书签发者: %20<br/>证书到期: %21<br/>证书 SHA-256: %22<br/>详情: %23")
                .arg(QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(parsedEntry.timestampMs)).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")))
                .arg(wrapFieldHtml(parsedEntry.clientEndpointText))
                .arg(wrapFieldHtml(parsedEntry.clientProcessText))
                .arg(wrapFieldHtml(parsedEntry.targetHostText))
                .arg(parsedEntry.targetPort)
                .arg(wrapFieldHtml(parsedEntry.eventTypeText))
                .arg(wrapFieldHtml(parsedEntry.methodText))
                .arg(wrapFieldHtml(parsedEntry.pathText))
                .arg(parsedEntry.statusCode)
                .arg(wrapFieldHtml(parsedEntry.contentTypeText))
                .arg(parsedEntry.contentLength >= 0 ? QString::number(parsedEntry.contentLength) : QStringLiteral("未知"))
                .arg(parsedEntry.elapsedMs)
                .arg(parsedEntry.uploadBytes)
                .arg(parsedEntry.downloadBytes)
                .arg(wrapFieldHtml(parsedEntry.tlsVersionText))
                .arg(wrapFieldHtml(parsedEntry.alpnText))
                .arg(wrapFieldHtml(parsedEntry.cipherSuiteText))
                .arg(wrapFieldHtml(parsedEntry.sniText))
                .arg(wrapFieldHtml(parsedEntry.certificateSubjectText))
                .arg(wrapFieldHtml(parsedEntry.certificateIssuerText))
                .arg(wrapFieldHtml(parsedEntry.certificateExpiryText))
                .arg(wrapFieldHtml(parsedEntry.certificateSha256Text))
                .arg(wrapFieldHtml(parsedEntry.detailText)));
            rootLayout->addWidget(metaLabel);

            QTabWidget* tabWidget = new QTabWidget(this);
            rootLayout->addWidget(tabWidget, 1);

            QWidget* hexPage = new QWidget(tabWidget);
            QVBoxLayout* hexLayout = new QVBoxLayout(hexPage);
            hexLayout->setContentsMargins(0, 0, 0, 0);
            hexLayout->setSpacing(4);

            QLabel* hintLabel = new QLabel(QStringLiteral("下方使用项目内现有 HexEditorWidget 展示 HTTPS 事件原始字节。"), hexPage);
            hintLabel->setWordWrap(true);
            hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
            hexLayout->addWidget(hintLabel);

            HexEditorWidget* hexEditorWidget = new HexEditorWidget(hexPage);
            hexEditorWidget->setEditable(false);
            hexEditorWidget->setBytesPerRow(16);
            if (!parsedEntry.rawBytes.isEmpty())
            {
                hexEditorWidget->setByteArray(parsedEntry.rawBytes, 0);
            }
            else
            {
                hexEditorWidget->clearData();
            }
            hexLayout->addWidget(hexEditorWidget, 1);
            tabWidget->addTab(hexPage, QStringLiteral("十六进制"));

            QWidget* textPage = new QWidget(tabWidget);
            QVBoxLayout* textLayout = new QVBoxLayout(textPage);
            textLayout->setContentsMargins(0, 0, 0, 0);
            textLayout->setSpacing(4);

            QPlainTextEdit* textEditor = new CodeTextEdit(textPage);
            static_cast<CodeTextEdit*>(textEditor)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            textEditor->setReadOnly(true);
            textEditor->setLineWrapMode(QPlainTextEdit::NoWrap);
            textEditor->setPlainText(QString::fromUtf8(parsedEntry.rawBytes));
            textLayout->addWidget(textEditor, 1);
            tabWidget->addTab(textPage, QStringLiteral("文本"));
        }
    };

    // refreshInternetSettings 作用：
    // - 通知 WinINet 刷新代理配置；
    // - 两个通知都成功才返回 true，恢复事务据此决定能否安全清除。
    bool refreshInternetSettings(QString* errorTextOut)
    {
        const BOOL changedOk = ::InternetSetOptionW(
            nullptr,
            INTERNET_OPTION_SETTINGS_CHANGED,
            nullptr,
            0);
        const DWORD changedError = changedOk ? ERROR_SUCCESS : ::GetLastError();
        const BOOL refreshOk = ::InternetSetOptionW(
            nullptr,
            INTERNET_OPTION_REFRESH,
            nullptr,
            0);
        const DWORD refreshError = refreshOk ? ERROR_SUCCESS : ::GetLastError();
        if (changedOk && refreshOk)
        {
            return true;
        }
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "刷新 WinINet 代理配置失败：SETTINGS_CHANGED=%1，REFRESH=%2")
                .arg(changedError)
                .arg(refreshError);
        }
        return false;
    }

    // writeInternetSettingString 作用：
    // - 把字符串类型代理项写入当前用户 Internet Settings。
    bool writeInternetSettingString(const wchar_t* valueName, const QString& valueText, QString* errorTextOut)
    {
        const std::wstring valueNameText = std::wstring(valueName);
        const std::wstring valueDataText = valueText.toStdWString();
        const LONG resultCode = ::RegSetKeyValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueNameText.c_str(),
            REG_SZ,
            valueDataText.c_str(),
            static_cast<DWORD>((valueDataText.size() + 1) * sizeof(wchar_t)));
        if (resultCode != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("写入注册表失败：%1").arg(resultCode);
            }
            return false;
        }
        return true;
    }

    // writeInternetSettingDword 作用：
    // - 把 DWORD 类型代理项写入当前用户 Internet Settings。
    bool writeInternetSettingDword(const wchar_t* valueName, const DWORD valueData, QString* errorTextOut)
    {
        const LONG resultCode = ::RegSetKeyValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            REG_DWORD,
            &valueData,
            sizeof(valueData));
        if (resultCode != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("写入注册表失败：%1").arg(resultCode);
            }
            return false;
        }
        return true;
    }

    // readInternetSettingString 作用：读取当前用户 Internet Settings 下可选的字符串配置项。
    bool readInternetSettingString(const wchar_t* valueName, std::optional<QString>* valueOut, QString* errorTextOut)
    {
        if (valueOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("代理配置输出对象为空。");
            }
            return false;
        }

        DWORD dataSize = 0;
        const LONG sizeResult = ::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            RRF_RT_REG_SZ,
            nullptr,
            nullptr,
            &dataSize);
        if (sizeResult == ERROR_FILE_NOT_FOUND)
        {
            valueOut->reset();
            return true;
        }
        if (sizeResult != ERROR_SUCCESS || dataSize > 64 * 1024 || dataSize % sizeof(wchar_t) != 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取代理配置失败：%1").arg(sizeResult);
            }
            return false;
        }

        std::vector<wchar_t> valueBuffer(static_cast<std::size_t>(dataSize / sizeof(wchar_t)) + 1, L'\0');
        DWORD readSize = dataSize;
        const LONG readResult = ::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            RRF_RT_REG_SZ,
            nullptr,
            valueBuffer.data(),
            &readSize);
        if (readResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取代理配置失败：%1").arg(readResult);
            }
            return false;
        }

        *valueOut = QString::fromWCharArray(valueBuffer.data());
        return true;
    }

    // readInternetSettingDword 作用：读取当前用户 Internet Settings 下可选的 DWORD 配置项。
    bool readInternetSettingDword(const wchar_t* valueName, std::optional<std::uint32_t>* valueOut, QString* errorTextOut)
    {
        if (valueOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("代理配置输出对象为空。");
            }
            return false;
        }

        DWORD valueData = 0;
        DWORD dataSize = sizeof(valueData);
        const LONG readResult = ::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            RRF_RT_REG_DWORD,
            nullptr,
            &valueData,
            &dataSize);
        if (readResult == ERROR_FILE_NOT_FOUND)
        {
            valueOut->reset();
            return true;
        }
        if (readResult != ERROR_SUCCESS || dataSize != sizeof(valueData))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取代理配置失败：%1").arg(readResult);
            }
            return false;
        }

        *valueOut = static_cast<std::uint32_t>(valueData);
        return true;
    }

    // deleteInternetSetting 作用：删除当前用户 Internet Settings 下指定值，使其恢复为不存在状态。
    bool deleteInternetSetting(const wchar_t* valueName, QString* errorTextOut)
    {
        const LONG deleteResult = ::RegDeleteKeyValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName);
        if (deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除代理配置失败：%1").arg(deleteResult);
            }
            return false;
        }
        return true;
    }

    // buildHttpsProxyServerText 作用：在保留已有协议专属代理项的前提下，仅替换 HTTPS 代理端点。
    QString buildHttpsProxyServerText(const QString& originalProxyServerText, const QString& httpsEndpointText)
    {
        const QString trimmedOriginalText = originalProxyServerText.trimmed();
        if (trimmedOriginalText.isEmpty())
        {
            return QStringLiteral("https=%1").arg(httpsEndpointText);
        }

        const QStringList entryList = trimmedOriginalText.split(';', Qt::SkipEmptyParts);
        QStringList outputEntryList;
        outputEntryList.reserve(entryList.size() + 1);
        bool hasProtocolSpecificEntry = false;
        bool httpsEntryReplaced = false;
        for (const QString& rawEntryText : entryList)
        {
            const QString entryText = rawEntryText.trimmed();
            const int equalIndex = entryText.indexOf('=');
            if (equalIndex <= 0)
            {
                outputEntryList.append(entryText);
                continue;
            }

            hasProtocolSpecificEntry = true;
            const QString protocolText = entryText.left(equalIndex).trimmed();
            if (protocolText.compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0)
            {
                outputEntryList.append(QStringLiteral("https=%1").arg(httpsEndpointText));
                httpsEntryReplaced = true;
            }
            else
            {
                outputEntryList.append(entryText);
            }
        }

        if (hasProtocolSpecificEntry)
        {
            if (!httpsEntryReplaced)
            {
                outputEntryList.append(QStringLiteral("https=%1").arg(httpsEndpointText));
            }
            return outputEntryList.join(';');
        }

        // 原配置是作用于全部协议的单端点。HTTPS 监控期间把该端点显式保留给 HTTP，避免直接丢失原 HTTP 代理。
        return QStringLiteral("http=%1;https=%2").arg(trimmedOriginalText, httpsEndpointText);
    }
}

void NetworkDock::initializeHttpsAnalyzeTab()
{
    m_httpsAnalyzePage = new QWidget(this);
    m_httpsAnalyzeLayout = new QVBoxLayout(m_httpsAnalyzePage);
    m_httpsAnalyzeLayout->setContentsMargins(6, 6, 6, 6);
    m_httpsAnalyzeLayout->setSpacing(6);

    m_httpsAnalyzeControlLayout = new QHBoxLayout();
    m_httpsAnalyzeControlLayout->setSpacing(6);

    m_httpsListenAddressEdit = new QLineEdit(QStringLiteral("127.0.0.1"), m_httpsAnalyzePage);
    m_httpsListenAddressEdit->setToolTip(QStringLiteral("HTTPS代理监听地址。"));
    m_httpsListenAddressEdit->setMaximumWidth(140);

    m_httpsListenPortSpin = new QSpinBox(m_httpsAnalyzePage);
    m_httpsListenPortSpin->setRange(1, 65535);
    m_httpsListenPortSpin->setValue(8889);
    m_httpsListenPortSpin->setToolTip(QStringLiteral("HTTPS代理监听端口。"));

    m_httpsStartProxyButton = new QPushButton(QStringLiteral("启动代理"), m_httpsAnalyzePage);
    m_httpsStartProxyButton->setIcon(QIcon(":/Icon/process_start.svg"));
    // 抓取范围并入启动按钮：用户在这里决定要不要开，也正是在这里需要知道抓不到什么。
    m_httpsStartProxyButton->setToolTip(QStringLiteral("启动本地 HTTPS 解析代理。只记录经过本地系统代理的 HTTP/1.1 流量；QUIC/HTTP/3、直连流量和启用证书锁定的应用不会进入本表。"));

    m_httpsStopProxyButton = new QPushButton(QStringLiteral("停止代理"), m_httpsAnalyzePage);
    m_httpsStopProxyButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_httpsStopProxyButton->setToolTip(QStringLiteral("停止本地 HTTPS 解析代理。"));

    m_httpsTrustCertButton = new QPushButton(QStringLiteral("信任证书"), m_httpsAnalyzePage);
    m_httpsTrustCertButton->setIcon(QIcon(":/Icon/process_details.svg"));
    m_httpsTrustCertButton->setToolTip(QStringLiteral("一键生成并信任 HTTPS 代理根证书。"));

    m_httpsApplyProxyButton = new QPushButton(QStringLiteral("应用系统代理"), m_httpsAnalyzePage);
    m_httpsApplyProxyButton->setIcon(QIcon(":/Icon/process_main.svg"));
    m_httpsApplyProxyButton->setToolTip(QStringLiteral("把系统代理切换到本地 HTTPS 代理。"));

    m_httpsClearProxyButton = new QPushButton(QStringLiteral("还原系统代理"), m_httpsAnalyzePage);
    m_httpsClearProxyButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_httpsClearProxyButton->setToolTip(QStringLiteral("恢复本页应用 HTTPS 代理前保存的系统代理配置。"));

    m_httpsProxyStatusLabel = new QLabel(QStringLiteral("状态：HTTPS代理未启动"), m_httpsAnalyzePage);
    m_httpsProxyStatusLabel->setWordWrap(true);
    m_httpsProxyStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_httpsAnalyzeControlLayout->addWidget(new QLabel(QStringLiteral("监听地址:"), m_httpsAnalyzePage));
    m_httpsAnalyzeControlLayout->addWidget(m_httpsListenAddressEdit);
    m_httpsAnalyzeControlLayout->addWidget(new QLabel(QStringLiteral("端口:"), m_httpsAnalyzePage));
    m_httpsAnalyzeControlLayout->addWidget(m_httpsListenPortSpin);
    m_httpsAnalyzeControlLayout->addWidget(m_httpsStartProxyButton);
    m_httpsAnalyzeControlLayout->addWidget(m_httpsStopProxyButton);
    m_httpsAnalyzeControlLayout->addWidget(m_httpsTrustCertButton);
    m_httpsAnalyzeControlLayout->addWidget(m_httpsApplyProxyButton);
    m_httpsAnalyzeControlLayout->addWidget(m_httpsClearProxyButton);
    m_httpsAnalyzeControlLayout->addWidget(m_httpsProxyStatusLabel, 1);
    m_httpsAnalyzeLayout->addLayout(m_httpsAnalyzeControlLayout);

    QHBoxLayout* parsedFilterLayout = new QHBoxLayout();
    parsedFilterLayout->setSpacing(6);
    m_httpsParsedFilterEdit = new QLineEdit(m_httpsAnalyzePage);
    m_httpsParsedFilterEdit->setClearButtonEnabled(true);
    m_httpsParsedFilterEdit->setPlaceholderText(QStringLiteral("筛选主机、路径、方法、状态码、内容类型、TLS 或详情..."));
    m_httpsParsedFilterEdit->setToolTip(QStringLiteral("实时筛选当前 HTTPS 解析记录，不影响代理转发或完整缓存。"));
    m_httpsParsedEventFilterCombo = new QComboBox(m_httpsAnalyzePage);
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("全部事件"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("CONNECT"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("TLS"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("REQUEST"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("RESPONSE"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("SUMMARY"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("ERROR"));
    m_httpsParsedEventFilterCombo->setToolTip(QStringLiteral("按 HTTPS 代理事件类型筛选。"));
    m_httpsClearParsedButton = new QPushButton(QStringLiteral("清空解析结果"), m_httpsAnalyzePage);
    m_httpsClearParsedButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_httpsClearParsedButton->setToolTip(QStringLiteral("清空解析表和详情缓存，不停止 HTTPS 代理。"));
    m_httpsExportParsedButton = new QPushButton(QStringLiteral("导出可见 CSV"), m_httpsAnalyzePage);
    m_httpsExportParsedButton->setIcon(QIcon(":/Icon/log_copy.svg"));
    m_httpsExportParsedButton->setToolTip(QStringLiteral("将当前筛选后可见的 HTTPS 解析记录导出为 UTF-8 CSV。"));
    m_httpsAutoScrollCheck = new QCheckBox(QStringLiteral("自动滚动"), m_httpsAnalyzePage);
    m_httpsAutoScrollCheck->setChecked(true);
    m_httpsAutoScrollCheck->setToolTip(QStringLiteral("新记录到达时自动定位到最后一条可见记录。"));
    m_httpsParsedSummaryLabel = new QLabel(QStringLiteral("显示 0 / 0，请求 0，响应 0，错误 0"), m_httpsAnalyzePage);
    m_httpsParsedSummaryLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    parsedFilterLayout->addWidget(new QLabel(QStringLiteral("筛选:"), m_httpsAnalyzePage));
    parsedFilterLayout->addWidget(m_httpsParsedFilterEdit, 1);
    parsedFilterLayout->addWidget(m_httpsParsedEventFilterCombo);
    parsedFilterLayout->addWidget(m_httpsAutoScrollCheck);
    parsedFilterLayout->addWidget(m_httpsExportParsedButton);
    parsedFilterLayout->addWidget(m_httpsClearParsedButton);
    parsedFilterLayout->addWidget(m_httpsParsedSummaryLabel);
    m_httpsAnalyzeLayout->addLayout(parsedFilterLayout);

    m_httpsParsedTable = new ks::ui::VisibleTableWidget(m_httpsAnalyzePage);
    m_httpsParsedTable->setColumnCount(HttpsParsedColumnCount);
    m_httpsParsedTable->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("会话"),
        QStringLiteral("客户端"),
        QStringLiteral("进程"),
        QStringLiteral("主机"),
        QStringLiteral("事件"),
        QStringLiteral("方法"),
        QStringLiteral("路径"),
        QStringLiteral("状态码"),
        QStringLiteral("内容类型"),
        QStringLiteral("TLS"),
        QStringLiteral("ALPN"),
        QStringLiteral("耗时"),
        QStringLiteral("上行"),
        QStringLiteral("下行"),
        QStringLiteral("详情")
        });
    m_httpsParsedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_httpsParsedTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_httpsParsedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_httpsParsedTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_httpsParsedTable->verticalHeader()->setVisible(false);
    m_httpsParsedTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_httpsParsedTable->horizontalHeader()->setSectionResizeMode(HttpsParsedColumnDetail, QHeaderView::Stretch);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnTime, 120);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnSession, 70);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnClient, 140);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnProcess, 180);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnHost, 160);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnEvent, 90);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnMethod, 70);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnPath, 220);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnStatus, 70);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnContentType, 160);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnTls, 80);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnAlpn, 80);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnElapsed, 80);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnUpload, 100);
    m_httpsParsedTable->setColumnWidth(HttpsParsedColumnDownload, 100);
    m_httpsAnalyzeLayout->addWidget(m_httpsParsedTable, 1);

    m_httpsProxyLogOutput = new CodeTextEdit(m_httpsAnalyzePage);
    static_cast<CodeTextEdit*>(m_httpsProxyLogOutput)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    m_httpsProxyLogOutput->setReadOnly(true);
    m_httpsProxyLogOutput->setMaximumBlockCount(600);
    m_httpsProxyLogOutput->setPlaceholderText(QStringLiteral("HTTPS 代理启动、证书安装和解析异常会显示在这里。"));
    m_httpsProxyLogOutput->setFixedHeight(150);
    m_httpsAnalyzeLayout->addWidget(m_httpsProxyLogOutput, 0);

    m_sideTabWidget->addTab(m_httpsAnalyzePage, QIcon(":/Icon/process_details.svg"), QStringLiteral("HTTPS解析"));
    updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理未启动"));
    updateHttpsParsedSummary();

    connect(m_httpsParsedFilterEdit, &QLineEdit::textChanged, this, [this](const QString&) { applyHttpsParsedTableFilter(); });
    connect(m_httpsParsedEventFilterCombo, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](const int) { applyHttpsParsedTableFilter(); });
    connect(m_httpsClearParsedButton, &QPushButton::clicked, this, [this]() { clearHttpsParsedEntries(); });
    connect(m_httpsExportParsedButton, &QPushButton::clicked, this, [this]() { exportVisibleHttpsParsedEntries(); });

    connect(m_httpsParsedTable, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int /*column*/)
        {
            openHttpsParsedDetailByRow(row);
        });
    connect(m_httpsParsedTable, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            if (m_httpsParsedTable == nullptr)
            {
                return;
            }

            const QTableWidgetItem* clickedItem = m_httpsParsedTable->itemAt(localPosition);
            if (clickedItem == nullptr)
            {
                return;
            }

            const int rowIndex = clickedItem->row();
            m_httpsParsedTable->setCurrentCell(rowIndex, clickedItem->column());

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* detailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看详情"));
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制当前行"));
            QAction* copyDetailAction = contextMenu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制详情文本"));
            QAction* selectedAction = contextMenu.exec(m_httpsParsedTable->viewport()->mapToGlobal(localPosition));
            if (selectedAction == detailAction)
            {
                openHttpsParsedDetailByRow(rowIndex);
            }
            else if (selectedAction == copyRowAction)
            {
                // 复制当前行：
                // - 输入：用户右键选中的 HTTPS 解析行；
                // - 处理：逐列读取单元格文本并用 TSV 格式拼接；
                // - 输出：写入系统剪贴板，方便粘贴到表格或工单。
                QStringList rowTextParts;
                rowTextParts.reserve(HttpsParsedColumnCount);
                for (int columnIndex = 0; columnIndex < HttpsParsedColumnCount; ++columnIndex)
                {
                    const QTableWidgetItem* cellItem = m_httpsParsedTable->item(rowIndex, columnIndex);
                    rowTextParts.append(cellItem != nullptr ? cellItem->text() : QString());
                }
                QApplication::clipboard()->setText(rowTextParts.join(QChar('\t')));
            }
            else if (selectedAction == copyDetailAction)
            {
                if (rowIndex >= 0 && rowIndex < static_cast<int>(m_httpsParsedEntryCache.size()))
                {
                    const ks::network::HttpsProxyParsedEntry& parsedEntry = m_httpsParsedEntryCache[static_cast<std::size_t>(rowIndex)];
                    QApplication::clipboard()->setText(QString::fromUtf8(parsedEntry.rawBytes));
                }
            }
        });
}

void NetworkDock::startHttpsProxyService()
{
    if (m_httpsProxyService == nullptr)
    {
        appendHttpsProxyLogLine(QStringLiteral("HTTPS代理服务尚未初始化。"));
        return;
    }
    if (g_httpsProxyBusyOperationActive)
    {
        // 已有证书准备或停止任务在跑，忽略这次点击，等回调结束后按钮会自动恢复。
        return;
    }

    const QHostAddress listenAddress(m_httpsListenAddressEdit != nullptr ? m_httpsListenAddressEdit->text().trimmed() : QStringLiteral("127.0.0.1"));
    if (listenAddress.isNull())
    {
        appendHttpsProxyLogLine(QStringLiteral("监听地址无效。"));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("监听地址无效。"));
        return;
    }

    const std::uint16_t listenPort = static_cast<std::uint16_t>(m_httpsListenPortSpin != nullptr ? m_httpsListenPortSpin->value() : 8889);

    // 根证书生成/导出要拉起 powershell.exe，首次启动典型 1~5 秒；
    // 这一段整体交给服务的后台线程，UI 线程只置灰按钮并显示准备中状态。
    g_httpsProxyBusyOperationActive = true;
    updateHttpsProxyStatusLabel(QStringLiteral("状态：正在准备根证书..."));

    const QPointer<NetworkDock> guardedSelf(this);
    m_httpsProxyService->ensureRootCertificateAsync(
        false,
        [guardedSelf, listenAddress, listenPort](const bool certificatePrepared, const QString& certificateErrorText)
        {
            g_httpsProxyBusyOperationActive = false;
            if (guardedSelf == nullptr)
            {
                return;
            }

            NetworkDock* const networkDock = guardedSelf.data();
            if (networkDock->m_httpsProxyService == nullptr)
            {
                networkDock->updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理未启动"));
                return;
            }

            QString failureText = certificateErrorText;
            bool startSucceeded = false;
            if (certificatePrepared)
            {
                QString startErrorText;
                startSucceeded = networkDock->m_httpsProxyService->start(listenAddress, listenPort, &startErrorText);
                if (!startSucceeded)
                {
                    failureText = startErrorText;
                }
            }

            if (!startSucceeded)
            {
                networkDock->appendHttpsProxyLogLine(QStringLiteral("启动失败：%1").arg(failureText));
                networkDock->updateHttpsProxyStatusLabel(
                    buildHttpsProxyStatusText(networkDock->m_httpsProxyRunning, listenAddress.toString(), listenPort));
                QMessageBox::warning(
                    networkDock,
                    QStringLiteral("HTTPS解析"),
                    QStringLiteral("启动 HTTPS 代理失败：\n%1").arg(failureText));
                return;
            }

            networkDock->m_httpsProxyRunning = true;
            networkDock->updateHttpsProxyStatusLabel(
                buildHttpsProxyStatusText(true, listenAddress.toString(), listenPort));
        });
}

void NetworkDock::stopHttpsProxyService()
{
    if (m_httpsProxyService == nullptr)
    {
        return;
    }
    if (g_httpsProxyBusyOperationActive)
    {
        return;
    }

    // 等待会话线程退出可能耗时（会话线程可能正卡在证书生成的 powershell.exe 上），
    // 这一段放到服务的后台线程，UI 线程只置灰按钮并显示停止中状态。
    g_httpsProxyBusyOperationActive = true;
    m_httpsProxyRunning = false;
    updateHttpsProxyStatusLabel(QStringLiteral("状态：正在停止HTTPS代理..."));

    // 系统代理指向的是即将下线的端口，先同步还原（纯注册表写入，开销可忽略），
    // 避免在会话收尾期间还有新流量被导向已停止的代理。
    if (m_httpsSystemProxySnapshotCaptured)
    {
        clearHttpsSystemProxy();
    }

    const QPointer<NetworkDock> guardedSelf(this);
    m_httpsProxyService->stopAsync(
        [guardedSelf]()
        {
            g_httpsProxyBusyOperationActive = false;
            if (guardedSelf == nullptr)
            {
                return;
            }
            guardedSelf->updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理已停止"));
        });
}

void NetworkDock::ensureHttpsRootCertificateTrusted()
{
    if (m_httpsProxyService == nullptr)
    {
        appendHttpsProxyLogLine(QStringLiteral("HTTPS代理服务尚未初始化。"));
        return;
    }
    if (g_httpsProxyBusyOperationActive)
    {
        return;
    }

    const QMessageBox::StandardButton confirmation = QMessageBox::question(
        this,
        QStringLiteral("信任 HTTPS 根证书"),
        QStringLiteral("此操作会将 Ksword 根证书加入“当前用户”的受信任根证书颁发机构。\n\n"
            "仅在你拥有或获授权分析的流量环境中继续。是否信任该证书？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    // 生成根证书并导入信任根同样要跑 powershell.exe，整段交给后台线程。
    g_httpsProxyBusyOperationActive = true;
    updateHttpsProxyStatusLabel(QStringLiteral("状态：正在准备根证书..."));

    const QPointer<NetworkDock> guardedSelf(this);
    m_httpsProxyService->ensureRootCertificateAsync(
        true,
        [guardedSelf](const bool certificatePrepared, const QString& certificateErrorText)
        {
            g_httpsProxyBusyOperationActive = false;
            if (guardedSelf == nullptr)
            {
                return;
            }

            NetworkDock* const networkDock = guardedSelf.data();
            if (!certificatePrepared)
            {
                const QString listenAddressText = (networkDock->m_httpsProxyService != nullptr)
                    ? networkDock->m_httpsProxyService->currentListenAddress().toString()
                    : QString();
                const std::uint16_t listenPort = (networkDock->m_httpsProxyService != nullptr)
                    ? networkDock->m_httpsProxyService->currentListenPort()
                    : static_cast<std::uint16_t>(0);
                networkDock->appendHttpsProxyLogLine(QStringLiteral("信任证书失败：%1").arg(certificateErrorText));
                networkDock->updateHttpsProxyStatusLabel(
                    buildHttpsProxyStatusText(networkDock->m_httpsProxyRunning, listenAddressText, listenPort));
                QMessageBox::warning(
                    networkDock,
                    QStringLiteral("HTTPS解析"),
                    QStringLiteral("信任根证书失败：\n%1").arg(certificateErrorText));
                return;
            }

            networkDock->appendHttpsProxyLogLine(QStringLiteral("HTTPS 根证书已生成并导入当前用户信任根。"));
            networkDock->updateHttpsProxyStatusLabel(QStringLiteral("状态：根证书已信任，可启动代理"));
        });
}

void NetworkDock::applyHttpsSystemProxy()
{
    if (m_httpsProxyRecoveryRequired)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("HTTPS解析"),
            QStringLiteral(
                "存在尚未成功恢复的 HTTPS 系统代理事务。请先重新启动 KSword 完成自动恢复，"
                "当前不会覆盖原始代理快照。"));
        return;
    }
    if (m_httpsProxyService == nullptr || !m_httpsProxyService->isRunning())
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("请先启动 HTTPS 代理，再应用系统代理。"));
        return;
    }
    if (!m_httpsProxyService->isRootTrusted())
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("请先信任 HTTPS 根证书，否则客户端会拒绝代理证书。"));
        return;
    }

    const QString listenAddressText = (m_httpsListenAddressEdit != nullptr)
        ? m_httpsListenAddressEdit->text().trimmed()
        : QStringLiteral("127.0.0.1");

    const QMessageBox::StandardButton confirmation = QMessageBox::question(
        this,
        QStringLiteral("应用 HTTPS 系统代理"),
        QStringLiteral("将把当前用户的 HTTPS 系统代理切换到 %1:%2。\n\n"
            "该代理会解密并显示通过此代理的 HTTPS 请求头和响应头，正文只转发不保存。停止代理或点击“还原系统代理”会恢复当前配置。是否继续？")
            .arg(listenAddressText)
            .arg(m_httpsListenPortSpin != nullptr ? m_httpsListenPortSpin->value() : 8889),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (!captureHttpsSystemProxySnapshot(&errorText))
    {
        appendHttpsProxyLogLine(QStringLiteral("保存系统代理配置失败：%1").arg(errorText));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("保存原系统代理配置失败：\n%1").arg(errorText));
        return;
    }

    const QString originalProxyServerText = m_httpsPreviousProxyServer.value_or(QString());
    const QString proxyServerText = buildHttpsProxyServerText(
        originalProxyServerText,
        QStringLiteral("%1:%2").arg(listenAddressText).arg(m_httpsListenPortSpin != nullptr ? m_httpsListenPortSpin->value() : 8889));
    if (!writeInternetSettingString(L"ProxyServer", proxyServerText, &errorText)
        || !writeInternetSettingString(L"ProxyOverride", QStringLiteral("localhost;127.*;<local>"), &errorText)
        || !writeInternetSettingDword(L"ProxyEnable", 1, &errorText)
        || !writeInternetSettingDword(L"AutoDetect", 0, &errorText)
        || !writeInternetSettingString(L"AutoConfigURL", QString(), &errorText))
    {
        const QString applyErrorText = errorText;
        QString restoreErrorText;
        const bool restoreOk = restoreHttpsSystemProxySnapshot(&restoreErrorText);
        errorText = restoreOk
            ? applyErrorText
            : QStringLiteral("%1\n回滚原系统代理也失败：%2")
                .arg(applyErrorText, restoreErrorText);
        appendHttpsProxyLogLine(QStringLiteral("应用系统代理失败：%1").arg(errorText));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("应用系统代理失败：\n%1").arg(errorText));
        return;
    }

    if (!refreshInternetSettings(&errorText))
    {
        const QString applyErrorText = errorText;
        QString restoreErrorText;
        const bool restoreOk = restoreHttpsSystemProxySnapshot(&restoreErrorText);
        errorText = restoreOk
            ? applyErrorText
            : QStringLiteral("%1\n回滚原系统代理也失败：%2")
                .arg(applyErrorText, restoreErrorText);
        appendHttpsProxyLogLine(QStringLiteral("应用系统代理失败：%1").arg(errorText));
        QMessageBox::warning(
            this,
            QStringLiteral("HTTPS解析"),
            QStringLiteral("应用系统代理失败：\n%1").arg(errorText));
        return;
    }
    appendHttpsProxyLogLine(QStringLiteral("系统代理已切换到 %1。").arg(proxyServerText));
}

void NetworkDock::clearHttpsSystemProxy()
{
    if (!m_httpsSystemProxySnapshotCaptured)
    {
        appendHttpsProxyLogLine(QStringLiteral("未发现由 HTTPS 解析页保存的系统代理快照，不修改当前系统代理。"));
        return;
    }

    QString errorText;
    if (!restoreHttpsSystemProxySnapshot(&errorText))
    {
        appendHttpsProxyLogLine(QStringLiteral("还原系统代理失败：%1").arg(errorText));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("还原系统代理失败：\n%1").arg(errorText));
        return;
    }

    appendHttpsProxyLogLine(QStringLiteral("系统代理已恢复为 HTTPS 解析页应用前的配置。"));
}

bool NetworkDock::captureHttpsSystemProxySnapshot(QString* errorTextOut)
{
    if (m_httpsProxyRecoveryRequired)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "存在尚未完成的 HTTPS 代理恢复事务，不能覆盖原始代理快照。");
        }
        return false;
    }
    if (m_httpsSystemProxySnapshotCaptured)
    {
        return true;
    }

    std::optional<std::uint32_t> previousProxyEnable;
    std::optional<std::uint32_t> previousAutoDetect;
    std::optional<QString> previousProxyServer;
    std::optional<QString> previousProxyOverride;
    std::optional<QString> previousAutoConfigUrl;
    QString errorText;
    if (!readInternetSettingDword(L"ProxyEnable", &previousProxyEnable, &errorText)
        || !readInternetSettingDword(L"AutoDetect", &previousAutoDetect, &errorText)
        || !readInternetSettingString(L"ProxyServer", &previousProxyServer, &errorText)
        || !readInternetSettingString(L"ProxyOverride", &previousProxyOverride, &errorText)
        || !readInternetSettingString(L"AutoConfigURL", &previousAutoConfigUrl, &errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    if (!persistHttpsSystemProxyRecoveryTransaction(
            previousProxyEnable,
            previousAutoDetect,
            previousProxyServer,
            previousProxyOverride,
            previousAutoConfigUrl,
            &errorText))
    {
        m_httpsProxyRecoveryRequired = true;
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    m_httpsPreviousProxyEnable = previousProxyEnable;
    m_httpsPreviousAutoDetect = previousAutoDetect;
    m_httpsPreviousProxyServer = previousProxyServer;
    m_httpsPreviousProxyOverride = previousProxyOverride;
    m_httpsPreviousAutoConfigUrl = previousAutoConfigUrl;
    m_httpsSystemProxySnapshotCaptured = true;
    return true;
}

bool NetworkDock::restoreHttpsSystemProxySnapshot(QString* errorTextOut)
{
    if (!m_httpsSystemProxySnapshotCaptured)
    {
        return true;
    }

    QString errorText;
    const auto restoreDword = [&errorText](const wchar_t* valueName, const std::optional<std::uint32_t>& value) -> bool
        {
            return value.has_value()
                ? writeInternetSettingDword(valueName, static_cast<DWORD>(*value), &errorText)
                : deleteInternetSetting(valueName, &errorText);
        };
    const auto restoreString = [&errorText](const wchar_t* valueName, const std::optional<QString>& value) -> bool
        {
            return value.has_value()
                ? writeInternetSettingString(valueName, *value, &errorText)
                : deleteInternetSetting(valueName, &errorText);
        };

    if (!restoreDword(L"ProxyEnable", m_httpsPreviousProxyEnable)
        || !restoreDword(L"AutoDetect", m_httpsPreviousAutoDetect)
        || !restoreString(L"ProxyServer", m_httpsPreviousProxyServer)
        || !restoreString(L"ProxyOverride", m_httpsPreviousProxyOverride)
        || !restoreString(L"AutoConfigURL", m_httpsPreviousAutoConfigUrl))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    if (!refreshInternetSettings(&errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }
    if (!clearHttpsSystemProxyRecoveryTransaction(&errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    m_httpsPreviousProxyEnable.reset();
    m_httpsPreviousAutoDetect.reset();
    m_httpsPreviousProxyServer.reset();
    m_httpsPreviousProxyOverride.reset();
    m_httpsPreviousAutoConfigUrl.reset();
    m_httpsSystemProxySnapshotCaptured = false;
    m_httpsProxyRecoveryRequired = false;
    return true;
}

void NetworkDock::onHttpsProxyParsedEntryArrived(const ks::network::HttpsProxyParsedEntry& parsedEntry)
{
    if (m_httpsParsedTable == nullptr)
    {
        return;
    }

    if (m_httpsParsedTable->rowCount() >= kMaxHttpsParsedEntries)
    {
        m_httpsParsedTable->removeRow(0);
        if (!m_httpsParsedEntryCache.empty())
        {
            m_httpsParsedEntryCache.erase(m_httpsParsedEntryCache.begin());
        }
    }

    m_httpsParsedEntryCache.push_back(parsedEntry);
    const int rowIndex = m_httpsParsedTable->rowCount();
    m_httpsParsedTable->insertRow(rowIndex);

    const QString timeText = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(parsedEntry.timestampMs)).toString(QStringLiteral("HH:mm:ss.zzz"));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnTime, createPacketCell(timeText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnSession, createPacketCell(QString::number(parsedEntry.sessionId)));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnClient, createPacketCell(parsedEntry.clientEndpointText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnProcess, createPacketCell(parsedEntry.clientProcessText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnHost, createPacketCell(QStringLiteral("%1:%2").arg(parsedEntry.targetHostText).arg(parsedEntry.targetPort)));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnEvent, createPacketCell(parsedEntry.eventTypeText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnMethod, createPacketCell(parsedEntry.methodText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnPath, createPacketCell(parsedEntry.pathText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnStatus, createPacketCell(parsedEntry.statusCode > 0 ? QString::number(parsedEntry.statusCode) : QString()));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnContentType, createPacketCell(parsedEntry.contentTypeText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnTls, createPacketCell(parsedEntry.tlsVersionText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnAlpn, createPacketCell(parsedEntry.alpnText));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnElapsed, createPacketCell(parsedEntry.elapsedMs > 0 ? QStringLiteral("%1 ms").arg(parsedEntry.elapsedMs) : QString()));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnUpload, createPacketCell(parsedEntry.uploadBytes > 0 ? QString::number(parsedEntry.uploadBytes) : QString()));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnDownload, createPacketCell(parsedEntry.downloadBytes > 0 ? QString::number(parsedEntry.downloadBytes) : QString()));
    m_httpsParsedTable->setItem(rowIndex, HttpsParsedColumnDetail, createPacketCell(parsedEntry.detailText));
    applyHttpsParsedTableFilter();
    if (m_httpsAutoScrollCheck != nullptr && m_httpsAutoScrollCheck->isChecked() && !m_httpsParsedTable->isRowHidden(rowIndex))
    {
        m_httpsParsedTable->scrollToBottom();
    }
}

void NetworkDock::applyHttpsParsedTableFilter()
{
    if (m_httpsParsedTable == nullptr)
    {
        return;
    }

    const QString keywordText = m_httpsParsedFilterEdit != nullptr
        ? m_httpsParsedFilterEdit->text().trimmed()
        : QString();
    const QString eventTypeText = m_httpsParsedEventFilterCombo != nullptr
        ? m_httpsParsedEventFilterCombo->currentText()
        : QStringLiteral("全部事件");
    const bool filterByEventType = !eventTypeText.isEmpty() && eventTypeText != QStringLiteral("全部事件");

    for (int rowIndex = 0; rowIndex < m_httpsParsedTable->rowCount(); ++rowIndex)
    {
        bool keywordMatched = keywordText.isEmpty();
        if (!keywordMatched)
        {
            for (int columnIndex = 0; columnIndex < HttpsParsedColumnCount; ++columnIndex)
            {
                const QTableWidgetItem* cellItem = m_httpsParsedTable->item(rowIndex, columnIndex);
                if (cellItem != nullptr && cellItem->text().contains(keywordText, Qt::CaseInsensitive))
                {
                    keywordMatched = true;
                    break;
                }
            }
        }

        const QTableWidgetItem* eventItem = m_httpsParsedTable->item(rowIndex, HttpsParsedColumnEvent);
        const bool eventMatched = !filterByEventType
            || (eventItem != nullptr && eventItem->text().compare(eventTypeText, Qt::CaseInsensitive) == 0);
        m_httpsParsedTable->setRowHidden(rowIndex, !keywordMatched || !eventMatched);
    }

    updateHttpsParsedSummary();
}

void NetworkDock::clearHttpsParsedEntries()
{
    if (m_httpsParsedTable == nullptr)
    {
        return;
    }

    m_httpsParsedEntryCache.clear();
    m_httpsParsedTable->setRowCount(0);
    updateHttpsParsedSummary();
    appendHttpsProxyLogLine(QStringLiteral("HTTPS 解析结果和详情缓存已清空。"));
}

void NetworkDock::exportVisibleHttpsParsedEntries()
{
    if (m_httpsParsedTable == nullptr)
    {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 HTTPS 解析记录"),
        QStringLiteral("https-analysis.csv"),
        QStringLiteral("CSV 文件 (*.csv)"));
    if (filePath.isEmpty())
    {
        return;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("无法创建导出文件：%1").arg(outputFile.errorString()));
        return;
    }

    const auto escapeCsvField = [](QString fieldText) -> QString
        {
            fieldText.replace('"', QStringLiteral("\"\""));
            return QStringLiteral("\"%1\"").arg(fieldText);
        };

    outputFile.write("\xEF\xBB\xBF");
    QTextStream outputStream(&outputFile);
    QStringList headerTextList;
    for (int columnIndex = 0; columnIndex < HttpsParsedColumnCount; ++columnIndex)
    {
        const QTableWidgetItem* headerItem = m_httpsParsedTable->horizontalHeaderItem(columnIndex);
        headerTextList.append(escapeCsvField(headerItem != nullptr ? headerItem->text() : QString()));
    }
    outputStream << headerTextList.join(',') << Qt::endl;

    int exportedRowCount = 0;
    for (int rowIndex = 0; rowIndex < m_httpsParsedTable->rowCount(); ++rowIndex)
    {
        if (m_httpsParsedTable->isRowHidden(rowIndex))
        {
            continue;
        }

        QStringList rowTextList;
        rowTextList.reserve(HttpsParsedColumnCount);
        for (int columnIndex = 0; columnIndex < HttpsParsedColumnCount; ++columnIndex)
        {
            const QTableWidgetItem* cellItem = m_httpsParsedTable->item(rowIndex, columnIndex);
            rowTextList.append(escapeCsvField(cellItem != nullptr ? cellItem->text() : QString()));
        }
        outputStream << rowTextList.join(',') << Qt::endl;
        ++exportedRowCount;
    }

    if (!outputFile.commit())
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("写入导出文件失败：%1").arg(outputFile.errorString()));
        return;
    }
    appendHttpsProxyLogLine(QStringLiteral("已导出 %1 条可见 HTTPS 解析记录：%2").arg(exportedRowCount).arg(filePath));
}

void NetworkDock::updateHttpsParsedSummary()
{
    if (m_httpsParsedSummaryLabel == nullptr || m_httpsParsedTable == nullptr)
    {
        return;
    }

    int visibleCount = 0;
    int requestCount = 0;
    int responseCount = 0;
    int errorCount = 0;
    for (int rowIndex = 0; rowIndex < m_httpsParsedTable->rowCount(); ++rowIndex)
    {
        if (!m_httpsParsedTable->isRowHidden(rowIndex))
        {
            ++visibleCount;
        }

        const QTableWidgetItem* eventItem = m_httpsParsedTable->item(rowIndex, HttpsParsedColumnEvent);
        if (eventItem == nullptr)
        {
            continue;
        }
        const QString eventText = eventItem->text();
        if (eventText == QStringLiteral("REQUEST"))
        {
            ++requestCount;
        }
        else if (eventText == QStringLiteral("RESPONSE"))
        {
            ++responseCount;
        }
        else if (eventText == QStringLiteral("ERROR"))
        {
            ++errorCount;
        }
    }

    m_httpsParsedSummaryLabel->setText(QStringLiteral("显示 %1 / %2，请求 %3，响应 %4，错误 %5")
        .arg(visibleCount)
        .arg(m_httpsParsedTable->rowCount())
        .arg(requestCount)
        .arg(responseCount)
        .arg(errorCount));
}

void NetworkDock::openHttpsParsedDetailByRow(const int row)
{
    if (row < 0 || row >= static_cast<int>(m_httpsParsedEntryCache.size()))
    {
        return;
    }

    HttpsParsedDetailWindow* detailWindow =
        new HttpsParsedDetailWindow(m_httpsParsedEntryCache[static_cast<std::size_t>(row)], nullptr);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
}

void NetworkDock::appendHttpsProxyLogLine(const QString& logLine)
{
    if (m_httpsProxyLogOutput == nullptr)
    {
        return;
    }

    const QString prefixedLine = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
        .arg(logLine);
    m_httpsProxyLogOutput->appendPlainText(prefixedLine);
}

void NetworkDock::updateHttpsProxyStatusLabel(const QString& statusText)
{
    if (m_httpsProxyStatusLabel != nullptr)
    {
        m_httpsProxyStatusLabel->setText(statusText);
    }

    // 后台证书准备/代理停止期间统一置灰控制栏：既防重入，也让用户看得出正在处理。
    const bool busyOperationActive = g_httpsProxyBusyOperationActive;
    if (m_httpsStartProxyButton != nullptr)
    {
        m_httpsStartProxyButton->setEnabled(!m_httpsProxyRunning && !busyOperationActive);
    }
    if (m_httpsStopProxyButton != nullptr)
    {
        m_httpsStopProxyButton->setEnabled(m_httpsProxyRunning && !busyOperationActive);
    }
    if (m_httpsTrustCertButton != nullptr)
    {
        m_httpsTrustCertButton->setEnabled(!busyOperationActive);
    }
    if (m_httpsApplyProxyButton != nullptr)
    {
        m_httpsApplyProxyButton->setEnabled(!busyOperationActive);
    }
    if (m_httpsClearProxyButton != nullptr)
    {
        m_httpsClearProxyButton->setEnabled(!busyOperationActive);
    }
}
