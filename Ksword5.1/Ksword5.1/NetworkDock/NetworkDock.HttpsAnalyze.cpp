#include "../UI/KeyboardItemActivation.h"
#include "NetworkDock.NavigationData.h"
#include "NetworkDock.InternalCommon.h"
#include "../UI/TableContextMenu.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/PageControlStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/DetailPresentation.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/CodeTextEdit.h"
#include "../UI/UI_All.h"
#include "../UI/VisibleTableWidget.h"
#include "HttpsProxyService.h"
#include "../UI/RetainedCleanupJob.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../theme.h"

#include <QApplication>
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QPointer>
#include "../UI/TableInteractionSupport.h"
#include "../Internationalization/LanguageManager.h"
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

    // HTTPS详情使用共享摘要/文档卡片/内容导航，原始字节视图保持。
    class HttpsParsedDetailWindow final : public QWidget
    {
    public:
        explicit HttpsParsedDetailWindow(const ks::network::HttpsProxyParsedEntry& parsedEntry, QWidget* parent = nullptr)
            : QWidget(parent)
        {
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
            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            ks::ui::ConfigureDetailDialogRoot(this);
            rootLayout->addWidget(ks::ui::CreateDetailSummaryHeader(this, windowTitle(),
                parsedEntry.clientProcessText, QIcon(QStringLiteral(":/Icon/process_details.svg"))));

            // 元数据保留真实字段，不再用23行富文本摘要占据全部窗口高度。
            ks::ui::FieldDocument metadata;
            metadata.section(QStringLiteral("常规信息"));
            metadata.field(QStringLiteral("时间"), QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(parsedEntry.timestampMs)).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
            metadata.field(QStringLiteral("客户端"), parsedEntry.clientEndpointText);
            metadata.field(QStringLiteral("进程"), parsedEntry.clientProcessText);
            metadata.field(QStringLiteral("目标"), QStringLiteral("%1:%2").arg(parsedEntry.targetHostText).arg(parsedEntry.targetPort));
            metadata.field(QStringLiteral("事件"), parsedEntry.eventTypeText);
            metadata.field(QStringLiteral("方法"), parsedEntry.methodText);
            metadata.field(QStringLiteral("路径"), parsedEntry.pathText);
            metadata.field(QStringLiteral("状态码"), QString::number(parsedEntry.statusCode));
            metadata.field(QStringLiteral("内容类型"), parsedEntry.contentTypeText);
            metadata.field(QStringLiteral("内容长度"), parsedEntry.contentLength >= 0 ? QString::number(parsedEntry.contentLength) : QStringLiteral("未知"));
            metadata.field(QStringLiteral("耗时"), QStringLiteral("%1 ms").arg(parsedEntry.elapsedMs));
            metadata.field(QStringLiteral("上行/下行"), QStringLiteral("%1 / %2 字节").arg(parsedEntry.uploadBytes).arg(parsedEntry.downloadBytes));
            metadata.section(QStringLiteral("TLS"));
            metadata.field(QStringLiteral("TLS"), parsedEntry.tlsVersionText);
            metadata.field(QStringLiteral("ALPN"), parsedEntry.alpnText);
            metadata.field(QStringLiteral("密码套件"), parsedEntry.cipherSuiteText);
            metadata.field(QStringLiteral("SNI"), parsedEntry.sniText);
            metadata.field(QStringLiteral("证书主体"), parsedEntry.certificateSubjectText);
            metadata.field(QStringLiteral("证书签发者"), parsedEntry.certificateIssuerText);
            metadata.field(QStringLiteral("证书到期"), parsedEntry.certificateExpiryText);
            metadata.field(QStringLiteral("证书 SHA-256"), parsedEntry.certificateSha256Text);
            metadata.field(QStringLiteral("详情"), parsedEntry.detailText);
            QTabWidget* tabWidget = new QTabWidget(this);
            auto* metadataSource = new ks::ui::StructuredFieldView(tabWidget);
            metadataSource->setDocument(metadata);
            tabWidget->addTab(ks::ui::CreateDetailFieldProjection(metadataSource, tabWidget), QStringLiteral("常规信息"));

            QWidget* hexPage = new QWidget(tabWidget);
            QVBoxLayout* hexLayout = new QVBoxLayout(hexPage);
            hexLayout->setContentsMargins(16, 16, 16, 16);
            hexLayout->setSpacing(4);

            QLabel* hintLabel = new QLabel(QStringLiteral("下方展示 HTTPS 事件原始字节。"), hexPage);
            hintLabel->setWordWrap(true);
            hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
            hexLayout->addWidget(hintLabel);

            ks::ui::HexView* hexEditorWidget = new ks::ui::HexView(hexPage);
            hexEditorWidget->setEditable(false);
            hexEditorWidget->setBytesPerRow(16);
            if (!parsedEntry.rawBytes.isEmpty())
            {
                hexEditorWidget->setBuffer(0, parsedEntry.rawBytes);
            }
            else
            {
                hexEditorWidget->clearBuffer();
            }
            hexLayout->addWidget(hexEditorWidget, 1);
            tabWidget->addTab(hexPage, QStringLiteral("十六进制"));

            QWidget* textPage = new QWidget(tabWidget);
            QVBoxLayout* textLayout = new QVBoxLayout(textPage);
            textLayout->setContentsMargins(16, 16, 16, 16);
            textLayout->setSpacing(4);

            QPlainTextEdit* textEditor = new CodeTextEdit(textPage);
            static_cast<CodeTextEdit*>(textEditor)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            textEditor->setReadOnly(true);
            textEditor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
            textEditor->setPlainText(QString::fromUtf8(parsedEntry.rawBytes));
            textLayout->addWidget(textEditor, 1);
            tabWidget->addTab(textPage, QStringLiteral("文本"));
            ks::ui::SetDetailTabGroups(tabWidget, {{ks::ui::DetailNavigationKind::General, {0}},
                {ks::ui::DetailNavigationKind::Content, {1, 2}}});
            rootLayout->addWidget(ks::ui::CreateDetailTabShell(tabWidget, this), 1);
            ks::ui::InstallDetailWindowFramework(this);
            ks::ui::ApplyDetailDialogChrome(this);
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

class NetworkDock::HttpsParsedModel final : public QAbstractTableModel
{
public:
    using Entry = std::shared_ptr<const ks::network::HttpsProxyParsedEntry>;
    HttpsParsedModel(QObject* owner, QStringList headers) : QAbstractTableModel(owner), m_headers(std::move(headers)) {}
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : static_cast<int>(m_rows.size()); }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : HttpsParsedColumnCount; }
    Entry entryAt(int row) const { return row >= 0 && row < rowCount() ? m_rows[static_cast<std::size_t>(row)] : Entry(); }
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < m_headers.size())
            return ks::i18n::displayText(m_headers[section]);
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
    {
        const auto value = entryAt(index.row());
        if (!index.isValid() || !value || (role != Qt::DisplayRole && role != Qt::ToolTipRole)) return {};
        const auto& e = *value;
        switch (index.column())
        {
        case HttpsParsedColumnTime: return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(e.timestampMs)).toString(QStringLiteral("HH:mm:ss.zzz"));
        case HttpsParsedColumnSession: return QString::number(e.sessionId);
        case HttpsParsedColumnClient: return e.clientEndpointText;
        case HttpsParsedColumnProcess: return e.clientProcessText;
        case HttpsParsedColumnHost: return QStringLiteral("%1:%2").arg(e.targetHostText).arg(e.targetPort);
        case HttpsParsedColumnEvent: return e.eventTypeText;
        case HttpsParsedColumnMethod: return e.methodText;
        case HttpsParsedColumnPath: return e.pathText;
        case HttpsParsedColumnStatus: return e.statusCode > 0 ? QString::number(e.statusCode) : QString();
        case HttpsParsedColumnContentType: return e.contentTypeText;
        case HttpsParsedColumnTls: return e.tlsVersionText;
        case HttpsParsedColumnAlpn: return e.alpnText;
        case HttpsParsedColumnElapsed: return e.elapsedMs > 0 ? QStringLiteral("%1 ms").arg(e.elapsedMs) : QString();
        case HttpsParsedColumnUpload: return e.uploadBytes > 0 ? QString::number(e.uploadBytes) : QString();
        case HttpsParsedColumnDownload: return e.downloadBytes > 0 ? QString::number(e.downloadBytes) : QString();
        case HttpsParsedColumnDetail: return e.detailText;
        default: return {};
        }
    }
    Qt::ItemFlags flags(const QModelIndex& index) const override
    { return index.isValid() ? Qt::ItemIsEnabled | Qt::ItemIsSelectable : Qt::NoItemFlags; }
    bool synchronize(const std::deque<Entry>& canonical)
    {
        // Capture only the new tail before Qt signals can reenter the producer.
        // Normal refresh examines removed/new rows, never all old display cells.
        std::size_t removed = 0;
        if (canonical.empty()) removed = m_rows.size();
        else while (removed < m_rows.size() && m_rows[removed] != canonical.front()) ++removed;
        const auto kept = m_rows.size() - removed;
        std::vector<Entry> tail;
        if (canonical.size() > kept) tail.assign(canonical.begin() + static_cast<std::ptrdiff_t>(kept), canonical.end());
        const QPointer<HttpsParsedModel> guard(this);
        if (removed != 0)
        {
            beginRemoveRows({}, 0, static_cast<int>(removed) - 1);
            if (!guard) return false;
            for (std::size_t i = 0; i < removed; ++i) m_rows.pop_front();
            endRemoveRows();
            if (!guard) return false;
        }
        if (!tail.empty())
        {
            beginInsertRows({}, static_cast<int>(kept), static_cast<int>(kept + tail.size()) - 1);
            if (!guard) return false;
            for (auto& entry : tail) m_rows.push_back(std::move(entry));
            endInsertRows();
            if (!guard) return false;
        }
        return true;
    }
private:
    QStringList m_headers;
    std::deque<Entry> m_rows;
};

class NetworkDock::HttpsParsedProxy final : public QSortFilterProxyModel
{
public:
    explicit HttpsParsedProxy(QObject* owner) : QSortFilterProxyModel(owner) { setDynamicSortFilter(false); }
    void setFilters(QString keyword, QString event)
    {
        if (keyword == m_keyword && event == m_event) return;
        m_keyword = std::move(keyword); m_event = std::move(event);
        invalidateFilter();
    }
protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override
    {
        if (!m_event.isEmpty() && sourceModel()->index(row, HttpsParsedColumnEvent, parent)
            .data().toString().compare(m_event, Qt::CaseInsensitive) != 0) return false;
        if (m_keyword.isEmpty()) return true;
        for (int column = 0; column < HttpsParsedColumnCount; ++column)
            if (sourceModel()->index(row, column, parent).data().toString().contains(m_keyword, Qt::CaseInsensitive)) return true;
        return false;
    }
private:
    QString m_keyword, m_event;
};


void NetworkDock::initializeHttpsAnalyzeTab()
{
    if (m_httpsAnalyzePage == nullptr) m_httpsAnalyzePage = new QWidget(this);
    m_httpsAnalyzeLayout = new QVBoxLayout(m_httpsAnalyzePage);
    m_httpsAnalyzeLayout->setContentsMargins(6, 6, 6, 6);
    m_httpsAnalyzeLayout->setSpacing(6);

    // 代理配置与结果筛选留在同一工具区，两行原有信息均保持可见。
    auto* httpsToolbar = new QWidget(m_httpsAnalyzePage);
    ks::ui::StylePrimaryToolbar(httpsToolbar);
    auto* httpsToolsLayout = new QVBoxLayout(httpsToolbar);
    httpsToolsLayout->setContentsMargins(8, 4, 8, 6);
    httpsToolsLayout->setSpacing(8);
    m_httpsAnalyzeControlLayout = new QHBoxLayout();
    m_httpsAnalyzeControlLayout->setSpacing(6);

    m_httpsListenAddressEdit = new QLineEdit(QStringLiteral("127.0.0.1"), m_httpsAnalyzePage);
    m_httpsListenAddressEdit->setToolTip(QStringLiteral("HTTPS代理监听地址。"));
    m_httpsListenAddressEdit->setMaximumWidth(140);
    // 监听地址是独立参数输入，不能借用搜索字段或透明祖先的底色。
    ks::ui::StyleStandaloneInput(m_httpsListenAddressEdit);

    m_httpsListenPortSpin = new QSpinBox(m_httpsAnalyzePage);
    m_httpsListenPortSpin->setRange(1, 65535);
    m_httpsListenPortSpin->setValue(8889);
    ks::ui::StyleStandaloneInput(m_httpsListenPortSpin);
    m_httpsListenPortSpin->setToolTip(QStringLiteral("HTTPS代理监听端口。"));

    m_httpsStartProxyButton = new QPushButton(QStringLiteral("启动代理"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsStartProxyButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);
    m_httpsStartProxyButton->setIcon(QIcon(":/Icon/process_start.svg"));
    // 抓取范围并入启动按钮：用户在这里决定要不要开，也正是在这里需要知道抓不到什么。
    m_httpsStartProxyButton->setToolTip(QStringLiteral("启动本地 HTTPS 解析代理。只记录经过本地系统代理的 HTTP/1.1 流量；QUIC/HTTP/3、直连流量和启用证书锁定的应用不会进入本表。"));

    m_httpsStopProxyButton = new QPushButton(QStringLiteral("停止代理"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsStopProxyButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    m_httpsStopProxyButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_httpsStopProxyButton->setToolTip(QStringLiteral("停止本地 HTTPS 解析代理。"));

    m_httpsTrustCertButton = new QPushButton(QStringLiteral("信任证书"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsTrustCertButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);
    m_httpsTrustCertButton->setIcon(QIcon(":/Icon/process_details.svg"));
    m_httpsTrustCertButton->setToolTip(QStringLiteral("一键生成并信任 HTTPS 代理根证书。"));

    m_httpsApplyProxyButton = new QPushButton(QStringLiteral("应用系统代理"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsApplyProxyButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);
    m_httpsApplyProxyButton->setIcon(QIcon(":/Icon/process_main.svg"));
    m_httpsApplyProxyButton->setToolTip(QStringLiteral("把系统代理切换到本地 HTTPS 代理。"));

    m_httpsClearProxyButton = new QPushButton(QStringLiteral("还原系统代理"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsClearProxyButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
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
    httpsToolsLayout->addLayout(m_httpsAnalyzeControlLayout);
    ks::ui::NormalizeToolbarRow(m_httpsAnalyzeControlLayout);

    QHBoxLayout* parsedFilterLayout = new QHBoxLayout();
    parsedFilterLayout->setSpacing(6);
    m_httpsParsedFilterEdit = new QLineEdit(m_httpsAnalyzePage);
    ks::ui::StyleSearchField(m_httpsParsedFilterEdit);
    m_httpsParsedFilterEdit->setClearButtonEnabled(true);
    m_httpsParsedFilterEdit->setPlaceholderText(QStringLiteral("筛选主机、路径、方法、状态码、内容类型、TLS 或详情..."));
    m_httpsParsedFilterEdit->setToolTip(QStringLiteral("实时筛选当前 HTTPS 解析记录，不影响代理转发或完整缓存。"));
    m_httpsParsedEventFilterCombo = new QComboBox(m_httpsAnalyzePage);
    ks::ui::StylePrimaryCombo(m_httpsParsedEventFilterCombo);
    ks::ui::StyleStandaloneInput(m_httpsParsedEventFilterCombo);
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("全部事件"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("CONNECT"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("TLS"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("REQUEST"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("RESPONSE"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("SUMMARY"));
    m_httpsParsedEventFilterCombo->addItem(QStringLiteral("ERROR"));
    m_httpsParsedEventFilterCombo->setToolTip(QStringLiteral("按 HTTPS 代理事件类型筛选。"));
    m_httpsClearParsedButton = new QPushButton(QStringLiteral("清空解析结果"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsClearParsedButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    m_httpsClearParsedButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_httpsClearParsedButton->setToolTip(QStringLiteral("清空解析表和详情缓存，不停止 HTTPS 代理。"));
    m_httpsExportParsedButton = new QPushButton(QStringLiteral("导出可见 CSV"), m_httpsAnalyzePage);
    // 页面明确选择动作语义；颜色变化不改变确认或执行路径。
    ks::ui::ApplyFlatButtonTheme(m_httpsExportParsedButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
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
    httpsToolsLayout->addLayout(parsedFilterLayout);
    ks::ui::NormalizeToolbarRow(parsedFilterLayout);
    m_httpsAnalyzeLayout->addWidget(httpsToolbar);

    m_httpsParsedTable = new ks::ui::TableActionTableView(m_httpsAnalyzePage);
    ks::ui::SetTableActionBarMode(m_httpsParsedTable, ks::ui::TableActionBarMode::None);
    m_httpsParsedModel = new HttpsParsedModel(this, {
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
    m_httpsParsedProxy = new HttpsParsedProxy(this);
    m_httpsParsedProxy->setSourceModel(m_httpsParsedModel);
    m_httpsParsedTable->setModel(m_httpsParsedProxy);
    m_httpsParsedTable->setProperty("ks_i18n_preserve_model_data", true);
    m_httpsParsedTable->setSortingEnabled(true);
    m_httpsParsedProxy->sort(-1);
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

    network_navigation_detail::AddTab(m_sideTabWidget, m_httpsAnalyzePage, QStringLiteral("https"), QIcon(":/Icon/process_details.svg"));
    updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理未启动"));
    updateHttpsParsedSummary();

    connect(m_httpsParsedFilterEdit, &QLineEdit::textChanged, this, [this](const QString&) { applyHttpsParsedTableFilter(); });
    connect(m_httpsParsedEventFilterCombo, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](const int) { applyHttpsParsedTableFilter(); });
    connect(m_httpsClearParsedButton, &QPushButton::clicked, this, [this]() { clearHttpsParsedEntries(); });
    connect(m_httpsExportParsedButton, &QPushButton::clicked, this, [this]() { exportVisibleHttpsParsedEntries(); });

    ks::ui::InstallKeyboardItemActivation(m_httpsParsedTable);
    connect(m_httpsParsedTable, &QTableView::doubleClicked, this, [this](const QModelIndex& index)
        {
            openHttpsParsedDetailByRow(index.row());
        });
    connect(m_httpsParsedTable, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            if (m_httpsParsedTable == nullptr)
            {
                return;
            }

            const QModelIndex clickedIndex = m_httpsParsedTable->indexAt(localPosition);
            if (!clickedIndex.isValid())
            {
                return;
            }

            const int rowIndex = clickedIndex.row();
            m_httpsParsedTable->setCurrentIndex(clickedIndex);
            const auto evidence = m_httpsParsedModel->entryAt(m_httpsParsedProxy->mapToSource(clickedIndex).row());
            if (!evidence) return;
            QStringList frozenRow;
            for (int column = 0; column < HttpsParsedColumnCount; ++column)
                frozenRow.push_back(m_httpsParsedProxy->index(rowIndex, column).data().toString());

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* detailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看详情"));
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制当前行"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            QAction* copyDetailAction = contextMenu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制详情文本"));
            QAction* selectedAction = contextMenu.exec(m_httpsParsedTable->viewport()->mapToGlobal(localPosition));
            if (selectedAction == detailAction)
            {
                auto* detail = new HttpsParsedDetailWindow(*evidence, nullptr);
                detail->setAttribute(Qt::WA_DeleteOnClose, true);
                detail->show();
                detail->raise();
                detail->activateWindow();
            }
            else if (selectedAction == copyRowAction)
            {
                // 复制当前行：
                // - 输入：用户右键选中的 HTTPS 解析行；
                // - 处理：逐列读取单元格文本并用 TSV 格式拼接；
                // - 输出：写入系统剪贴板，方便粘贴到表格或工单。
                QApplication::clipboard()->setText(frozenRow.join(QChar('	')));
            }
            else if (selectedAction == copyDetailAction)
            {
                QApplication::clipboard()->setText(QString::fromUtf8(evidence->rawBytes));
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
    if (m_httpsRecoveryCleanup && m_httpsRecoveryCleanup->isCleanupRequested()
        && !m_httpsRecoveryCleanup->isComplete())
    {
        m_httpsRecoveryCleanup->requestCleanup(); // Explicit user restore retries the same witness.
        return;
    }
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

    if (!ensureHttpsProxyRecoveryCleanup())
    {
        if (errorTextOut) *errorTextOut = QStringLiteral("存在尚未完成的 HTTPS 代理恢复事务，不能覆盖原始代理快照。");
        return false;
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

bool NetworkDock::restoreHttpsSystemProxySnapshotValues(
    const HttpsSystemProxySnapshot& snapshot, QString* errorTextOut)
{
    if (!snapshot.captured) return true;
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

    if (!restoreDword(L"ProxyEnable", snapshot.proxyEnable)
        || !restoreDword(L"AutoDetect", snapshot.autoDetect)
        || !restoreString(L"ProxyServer", snapshot.proxyServer)
        || !restoreString(L"ProxyOverride", snapshot.proxyOverride)
        || !restoreString(L"AutoConfigURL", snapshot.autoConfigUrl))
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

    return true;
}

bool NetworkDock::ensureHttpsProxyRecoveryCleanup()
{
    if (m_httpsRecoveryCleanup && !m_httpsRecoveryCleanup->isComplete())
        return !m_httpsRecoveryCleanup->isCleanupRequested();
    const auto state = std::make_shared<HttpsProxyRecoveryState>();
    const auto dispatcher = m_trafficDispatcher;
    const auto freeze = [this, state]()
    {
        if (m_httpsRecoveryState == state) retireHttpsProxyRecovery();
    };
    const auto restored = [this, state]()
    {
        if (m_httpsRecoveryState != state) return;
        m_httpsPreviousProxyEnable.reset();
        m_httpsPreviousAutoDetect.reset();
        m_httpsPreviousProxyServer.reset();
        m_httpsPreviousProxyOverride.reset();
        m_httpsPreviousAutoConfigUrl.reset();
        m_httpsSystemProxySnapshotCaptured = false;
        m_httpsProxyRecoveryRequired = false;
    };
    const auto cleanup = ks::ui::RetainedCleanupJob::create(
        [state, dispatcher, restored]()
        {
            QString error;
            if (!restoreHttpsSystemProxySnapshotValues(state->snapshot, &error))
            {
                kLogEvent restoreEvent;
                warn << restoreEvent << "[NetworkDock] HTTPS 系统代理恢复失败：" << error << eol;
                return false;
            }
            dispatcher->post(restored);
            return true;
        }, 0, [state, dispatcher, freeze]()
        {
            state->stopRequested.store(true);
            dispatcher->post(freeze);
        },
        [state]() { return state->ready.load(); });
    if (!cleanup) return false;
    state->ready.store(false);
    m_httpsRecoveryState = state;
    m_httpsRecoveryCleanup = cleanup;
    if (state->stopRequested.load())
    {
        retireHttpsProxyRecovery();
        return false;
    }
    return true;
}

void NetworkDock::retireHttpsProxyRecovery()
{
    const auto state = m_httpsRecoveryState;
    const auto cleanup = m_httpsRecoveryCleanup;
    if (!state || !cleanup || state->frozen) return;
    state->frozen = true;
    state->snapshot = {m_httpsSystemProxySnapshotCaptured,
        m_httpsPreviousProxyEnable, m_httpsPreviousAutoDetect,
        m_httpsPreviousProxyServer, m_httpsPreviousProxyOverride,
        m_httpsPreviousAutoConfigUrl};
    if (state->snapshot.captured) m_httpsProxyRecoveryRequired = true;
    const auto nativeStopped = [state, cleanup]()
    {
        state->ready.store(true);
        cleanup->notifyReadyToAttempt();
    };
    // Preserve teardown order: actual session STOP, then original proxy writes,
    // WinINet refresh, and finally durable recovery-record removal.
    if (m_httpsProxyService) m_httpsProxyService->stopAsync({}, nativeStopped);
    else nativeStopped();
    if (!cleanup->isCleanupRequested()) cleanup->requestCleanup();
}

bool NetworkDock::restoreHttpsSystemProxySnapshot(QString* errorTextOut)
{
    const HttpsSystemProxySnapshot snapshot{m_httpsSystemProxySnapshotCaptured,
        m_httpsPreviousProxyEnable, m_httpsPreviousAutoDetect,
        m_httpsPreviousProxyServer, m_httpsPreviousProxyOverride,
        m_httpsPreviousAutoConfigUrl};
    if (!restoreHttpsSystemProxySnapshotValues(snapshot, errorTextOut)) return false;

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
    // Every accepted full event updates the one canonical bounded window, even
    // when the page/menu is hidden. The existing 50ms UI clock coalesces projection.
    if (m_httpsParsedEntryCache.size() >= static_cast<std::size_t>(kMaxHttpsParsedEntries))
    {
        adjustHttpsParsedEventCount(m_httpsParsedEntryCache.front()->eventTypeText, -1);
        m_httpsParsedEntryCache.pop_front();
    }
    m_httpsParsedEntryCache.push_back(std::make_shared<const ks::network::HttpsProxyParsedEntry>(parsedEntry));
    adjustHttpsParsedEventCount(parsedEntry.eventTypeText, 1);
    m_httpsProjectionDirty = true;
}

void NetworkDock::synchronizeVisibleHttpsProjection()
{
    if (!m_httpsProjectionDirty || m_httpsProjectionInProgress || m_httpsAnalyzePage == nullptr
        || !m_httpsAnalyzePage->isVisible() || m_httpsParsedModel == nullptr || m_httpsParsedProxy == nullptr) return;
    const QPointer<NetworkDock> guard(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this, QStringLiteral("network-https-projection"),
        {m_httpsParsedTable}, [guard]() { if (guard) guard->synchronizeVisibleHttpsProjection(); })) return;
    m_httpsProjectionDirty = false;
    m_httpsProjectionInProgress = true;
    if (!m_httpsParsedModel->synchronize(m_httpsParsedEntryCache) || !guard) return;
    const auto keyword = m_httpsParsedFilterEdit ? m_httpsParsedFilterEdit->text().trimmed() : QString();
    const auto event = m_httpsParsedEventFilterCombo && m_httpsParsedEventFilterCombo->currentIndex() > 0
        ? m_httpsParsedEventFilterCombo->currentText() : QString();
    m_httpsParsedProxy->setFilters(keyword, event);
    if (!guard) return;
    m_httpsParsedVisibleCount = m_httpsParsedProxy->rowCount();
    m_httpsProjectionInProgress = false;
    updateHttpsParsedSummary();
    if (!guard) return;
    if (!m_httpsProjectionDirty && m_httpsAutoScrollCheck && m_httpsAutoScrollCheck->isChecked()
        && m_httpsParsedVisibleCount > 0) m_httpsParsedTable->scrollToBottom();
}

void NetworkDock::adjustHttpsParsedEventCount(const QString& eventType, const int delta)
{
    if (eventType == QStringLiteral("REQUEST")) m_httpsParsedRequestCount += delta;
    else if (eventType == QStringLiteral("RESPONSE")) m_httpsParsedResponseCount += delta;
    else if (eventType == QStringLiteral("ERROR")) m_httpsParsedErrorCount += delta;
}

void NetworkDock::applyHttpsParsedTableFilter()
{
    m_httpsProjectionDirty = true;
    synchronizeVisibleHttpsProjection();
}

void NetworkDock::clearHttpsParsedEntries()
{
    if (m_httpsParsedTable == nullptr)
    {
        return;
    }

    m_httpsParsedEntryCache.clear();
    m_httpsParsedVisibleCount = 0;
    m_httpsParsedRequestCount = 0;
    m_httpsParsedResponseCount = 0;
    m_httpsParsedErrorCount = 0;
    m_httpsProjectionDirty = true;
    synchronizeVisibleHttpsProjection();
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
        headerTextList.append(escapeCsvField(m_httpsParsedTable->model()->headerData(columnIndex, Qt::Horizontal).toString()));
    }
    outputStream << headerTextList.join(',') << Qt::endl;

    int exportedRowCount = 0;
    for (int rowIndex = 0; rowIndex < m_httpsParsedTable->model()->rowCount(); ++rowIndex)
    {

        QStringList rowTextList;
        rowTextList.reserve(HttpsParsedColumnCount);
        for (int columnIndex = 0; columnIndex < HttpsParsedColumnCount; ++columnIndex)
        {
            rowTextList.append(escapeCsvField(m_httpsParsedTable->model()->index(rowIndex, columnIndex).data().toString()));
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
    if (m_httpsParsedSummaryLabel == nullptr || m_httpsParsedTable == nullptr
        || m_httpsAnalyzePage == nullptr || !m_httpsAnalyzePage->isVisible())
    {
        return;
    }
    m_httpsParsedSummaryLabel->setText(QStringLiteral("显示 %1 / %2，请求 %3，响应 %4，错误 %5")
        .arg(m_httpsParsedVisibleCount)
        .arg(static_cast<qulonglong>(m_httpsParsedEntryCache.size()))
        .arg(m_httpsParsedRequestCount)
        .arg(m_httpsParsedResponseCount)
        .arg(m_httpsParsedErrorCount));
}

void NetworkDock::openHttpsParsedDetailByRow(const int row)
{
    const auto evidence = m_httpsParsedModel && m_httpsParsedProxy
        ? m_httpsParsedModel->entryAt(m_httpsParsedProxy->mapToSource(m_httpsParsedProxy->index(row, 0)).row()) : HttpsParsedModel::Entry();
    if (!evidence)
    {
        return;
    }

    HttpsParsedDetailWindow* detailWindow =
        new HttpsParsedDetailWindow(*evidence, nullptr);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
}

void NetworkDock::appendHttpsProxyLogLine(const QString& logLine)
{
    // Recovery/status messages must remain visible even before this tab is opened.
    // Only such an actual message prepares the cold page; ordinary Dock open does not.
    const QPointer<NetworkDock> owner(this);
    if (m_httpsProxyLogOutput == nullptr && !ensureNetworkToolPage(m_httpsAnalyzePage)) return;
    if (!owner) return;
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
