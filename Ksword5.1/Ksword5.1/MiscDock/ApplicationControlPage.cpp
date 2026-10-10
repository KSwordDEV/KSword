#include "../UI/StructuredFieldView.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "ApplicationControlPage.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

#include "../UI/CodeEditorWidget.h"

#include "../ksword/startup/startup.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPlainTextEdit>
#include "../UI/CodeTextEdit.h"
#include <QMetaObject>
#include <QMetaType>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTabWidget>
#include <QTableWidget>
#include <QUuid>
#include <QVariant>
#include <QVBoxLayout>
#include <QXmlStreamReader>

#include <algorithm>
#include <atomic>
#include <exception>
#include <thread>
#include <utility>

namespace
{
    // makeReadOnlyItem：
    // - 创建只读表格项；
    // - text 为单元格文本；
    // - 返回一个可直接塞进 QTableWidget 的 item。
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    // sizeTextFromBytes：
    // - 把字节数格式化为人类可读文本；
    // - bytes 小于 0 时返回破折号。
    QString sizeTextFromBytes(const qint64 bytes)
    {
        if (bytes < 0)
        {
            return QStringLiteral("—");
        }

        const double value = static_cast<double>(bytes);
        if (value < 1024.0)
        {
            return QStringLiteral("%1 B").arg(bytes);
        }
        if (value < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB").arg(value / 1024.0, 0, 'f', 2);
        }
        if (value < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB").arg(value / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB").arg(value / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // dateTimeText：
    // - 把本地时间转成展示字符串；
    // - 无效时间返回破折号。
    QString dateTimeText(const QDateTime& dateTime)
    {
        return dateTime.isValid()
            ? dateTime.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
            : QStringLiteral("—");
    }

    // sidToFriendlyText：
    // - 把常见 SID 映射为更容易读的文本；
    // - 未知 SID 原样回退。
    QString sidToFriendlyText(const QString& sidText)
    {
        const QString trimmedSid = sidText.trimmed();
        if (trimmedSid == QStringLiteral("S-1-1-0")) return QStringLiteral("Everyone");
        if (trimmedSid == QStringLiteral("S-1-5-32-545")) return QStringLiteral("Users");
        if (trimmedSid == QStringLiteral("S-1-5-32-544")) return QStringLiteral("Administrators");
        if (trimmedSid == QStringLiteral("S-1-5-18")) return QStringLiteral("SYSTEM");
        if (trimmedSid == QStringLiteral("S-1-5-19")) return QStringLiteral("LOCAL SERVICE");
        if (trimmedSid == QStringLiteral("S-1-5-20")) return QStringLiteral("NETWORK SERVICE");
        return trimmedSid;
    }

    // pathLikeTextToRegex：
    // - 把带 * 和 ? 的路径通配转换为正则表达式；
    // - 用于 AppLocker 路径规则的可能命中判断。
    QRegularExpression pathLikeTextToRegex(QString text)
    {
        text = text.trimmed();
        text.replace(QStringLiteral("/"), QStringLiteral("\\"));
        text.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
        text.replace(QStringLiteral("."), QStringLiteral("\\."));
        text.replace(QStringLiteral("+"), QStringLiteral("\\+"));
        text.replace(QStringLiteral("("), QStringLiteral("\\("));
        text.replace(QStringLiteral(")"), QStringLiteral("\\)"));
        text.replace(QStringLiteral("$"), QStringLiteral("\\$"));
        text.replace(QStringLiteral("^"), QStringLiteral("\\^"));
        text.replace(QStringLiteral("{"), QStringLiteral("\\{"));
        text.replace(QStringLiteral("}"), QStringLiteral("\\}"));
        text.replace(QStringLiteral("|"), QStringLiteral("\\|"));
        text.replace(QStringLiteral("*"), QStringLiteral(".*"));
        text.replace(QStringLiteral("?"), QStringLiteral("."));
        return QRegularExpression(QStringLiteral("^%1$").arg(text), QRegularExpression::CaseInsensitiveOption);
    }

    // expandCommonEnvironmentTokens：
    // - 展开 AppLocker 路径规则里常见的环境变量；
    // - 先做一轮常见变量替换，再留给正则通配匹配。
    QString expandCommonEnvironmentTokens(QString text)
    {
        const QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        const auto replaceToken = [&text, &env](const QString& token, const QString& envName) {
            const QString value = env.value(envName);
            if (!value.isEmpty())
            {
                text.replace(token, QDir::toNativeSeparators(value), Qt::CaseInsensitive);
            }
        };

        replaceToken(QStringLiteral("%WINDIR%"), QStringLiteral("WINDIR"));
        replaceToken(QStringLiteral("%SYSTEMROOT%"), QStringLiteral("SystemRoot"));
        replaceToken(QStringLiteral("%OSDRIVE%"), QStringLiteral("SystemDrive"));
        replaceToken(QStringLiteral("%PROGRAMFILES%"), QStringLiteral("ProgramFiles"));
        replaceToken(QStringLiteral("%PROGRAMFILES(X86)%"), QStringLiteral("ProgramFiles(x86)"));
        replaceToken(QStringLiteral("%USERPROFILE%"), QStringLiteral("USERPROFILE"));
        replaceToken(QStringLiteral("%LOCALAPPDATA%"), QStringLiteral("LOCALAPPDATA"));
        replaceToken(QStringLiteral("%APPDATA%"), QStringLiteral("APPDATA"));
        replaceToken(QStringLiteral("%TEMP%"), QStringLiteral("TEMP"));
        replaceToken(QStringLiteral("%TMP%"), QStringLiteral("TMP"));
        return text;
    }

    // isBroadPathRuleText：
    // - 判断路径规则是否过宽；
    // - 用于在 AppLocker 表格中标记风险。
    bool isBroadPathRuleText(const QString& conditionText)
    {
        const QString lower = conditionText.toLower();
        return conditionText.trimmed() == QStringLiteral("*")
            || lower.contains(QStringLiteral("\\users\\"))
            || lower.contains(QStringLiteral("\\downloads\\"))
            || lower.contains(QStringLiteral("\\desktop\\"))
            || lower.contains(QStringLiteral("\\temp\\"))
            || lower.contains(QStringLiteral("\\appdata\\local\\temp"))
            || lower.contains(QStringLiteral("\\programdata\\"))
            || lower.contains(QStringLiteral("%temp%"))
            || lower.contains(QStringLiteral("%userprofile%"))
            || lower.contains(QStringLiteral("%localappdata%"))
            || lower.contains(QStringLiteral("%appdata%"));
    }


    // auditStateText：
    // - 输入：R0 安全审计协议里的状态枚举值；
    // - 处理：把 UNKNOWN/PRESENT/ENABLED 等数字转换为 UI 可读文本；
    // - 返回：中文状态文本，未知枚举保留原始数字。
    QString auditStateText(const unsigned long stateValue)
    {
        switch (stateValue)
        {
        case KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN:
            return QStringLiteral("Unknown");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT:
            return QStringLiteral("Present");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT:
            return QStringLiteral("Absent");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_ENABLED:
            return QStringLiteral("Enabled");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_DISABLED:
            return QStringLiteral("Disabled");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE:
            return QStringLiteral("Unavailable");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_DEGRADED:
            return QStringLiteral("Degraded");
        default:
            return QStringLiteral("Unknown(%1)").arg(stateValue);
        }
    }

    // boolFlagText：
    // - 输入：R0 返回的 0/1 布尔型标志；
    // - 处理：把 0/1 转成 No/Yes，异常值保留原始数字；
    // - 返回：适合摘要行展示的短文本。
    QString boolFlagText(const unsigned long flagValue)
    {
        if (flagValue == 0UL)
        {
            return QStringLiteral("No");
        }
        if (flagValue == 1UL)
        {
            return QStringLiteral("Yes");
        }
        return QStringLiteral("Value(%1)").arg(flagValue);
    }

    // ntStatusText：
    // - 输入：R0 或 wrapper 传播出的 NTSTATUS/状态码；
    // - 处理：按 8 位十六进制保留原始诊断值；
    // - 返回：0xXXXXXXXX 文本。
    QString ntStatusText(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(statusValue), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // hexMaskText：
    // - 输入：fieldFlags/sourceMask 等无符号位图；
    // - 处理：统一格式化为十六进制，避免十进制位图难以审计；
    // - 返回：0xXXXXXXXX 文本。
    QString hexMaskText(const unsigned long maskValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(maskValue), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // fixedWideText：
    // - 输入：R0 固定长度 wchar_t 缓冲区和最大字符数；
    // - 处理：只读取第一个 NUL 之前的内容，避免把尾部填充带入 UI；
    // - 返回：trim 后的 QString，空值返回破折号。
    QString fixedWideText(const wchar_t* bufferText, const int maxCharacters)
    {
        if (bufferText == nullptr || maxCharacters <= 0)
        {
            return QStringLiteral("—");
        }

        int textLength = 0;
        while (textLength < maxCharacters && bufferText[textLength] != L'\0')
        {
            ++textLength;
        }

        const QString convertedText = QString::fromWCharArray(bufferText, textLength).trimmed();
        return convertedText.isEmpty() ? QStringLiteral("—") : convertedText;
    }

    // r0IoMessageText：
    // - 输入：ArkDriverClient 返回的原始 io.message；
    // - 处理：把 DeviceIoControl/version/空消息等底层字符串归一成人可读说明；
    // - 返回：适合放入平台安全表格“说明”列的中文文本。
    QString r0IoMessageText(const std::string& messageText)
    {
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString rawText = QString::fromStdString(messageText).trimmed();
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该安全审计入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该安全审计入口");
        }
        if (rawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回结构化安全审计数据");
        }
        return rawText.isEmpty() ? QStringLiteral("无额外驱动消息") : rawText;
    }

    // ioSummaryText：
    // - 输入：ArkDriverClient 标准 IoResult；
    // - 处理：合并传输状态、Win32 错误、NTSTATUS、返回字节数和友好说明；
    // - 返回：单行诊断文本，便于平台安全表格展示。
    QString ioSummaryText(const ksword::ark::IoResult& ioResult)
    {
        QStringList parts;
        parts << QStringLiteral("ok=%1").arg(ioResult.ok ? QStringLiteral("true") : QStringLiteral("false"));
        parts << QStringLiteral("win32=%1").arg(ioResult.win32Error);
        parts << QStringLiteral("nt=%1").arg(ntStatusText(ioResult.ntStatus));
        parts << QStringLiteral("bytes=%1").arg(ioResult.bytesReturned);
        parts << QStringLiteral("说明=%1").arg(r0IoMessageText(ioResult.message));
        return parts.join(QStringLiteral(" | "));
    }

    // collapseSpaces：
    // - 压缩文本中的多余空白；
    // - 便于表格展示。
    QString collapseSpaces(QString text)
    {
        text = text.simplified();
        return text;
    }

    // appLockerPowerShellPrelude：显式定位和加载模块，避免自动加载和 PSModulePath 差异。
    QString appLockerPowerShellPrelude()
    {
        return QStringLiteral(
            "$module=Get-Module -ListAvailable -Name AppLocker | Select-Object -First 1;"
            "if($null -eq $module){throw 'AppLocker PowerShell 模块不可用'};"
            "Import-Module -Name $module.Path -ErrorAction Stop;"
            "foreach($commandName in @('Get-AppLockerPolicy','Set-AppLockerPolicy','Test-AppLockerPolicy')){"
            "if($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)){throw ('AppLocker 模块未提供必需命令: '+$commandName)}};");
    }

    // jsonValueToText：
    // - 将 JSON 值转换为展示文本；
    // - 对数组和对象做紧凑化回退，避免丢信息。
    QString jsonValueToText(const QJsonValue& value)
    {
        switch (value.type())
        {
        case QJsonValue::String:
            return value.toString();
        case QJsonValue::Double:
            return QString::number(value.toDouble());
        case QJsonValue::Bool:
            return value.toBool() ? QStringLiteral("True") : QStringLiteral("False");
        case QJsonValue::Array:
            return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
        case QJsonValue::Object:
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        case QJsonValue::Null:
        case QJsonValue::Undefined:
        default:
            return QString();
        }
    }

    // classifyCodeIntegrityVerdict：
    // - 根据事件消息和级别做允许/阻止/审计粗分类；
    // - 仅做展示用途，不作为系统判定。
    QString classifyCodeIntegrityVerdict(const QString& messageText, const QString& levelText)
    {
        const QString lower = messageText.toLower();
        if (lower.contains(QStringLiteral("audit")) || lower.contains(QStringLiteral("审计")) || lower.contains(QStringLiteral("would have been blocked")))
        {
            return QStringLiteral("审计");
        }
        if (lower.contains(QStringLiteral("block")) || lower.contains(QStringLiteral("deny")) || lower.contains(QStringLiteral("阻止")) || lower.contains(QStringLiteral("not allowed")))
        {
            return QStringLiteral("阻止");
        }
        if (lower.contains(QStringLiteral("allow")) || lower.contains(QStringLiteral("loaded")) || lower.contains(QStringLiteral("允许")))
        {
            return QStringLiteral("允许");
        }
        if (levelText.contains(QStringLiteral("warning"), Qt::CaseInsensitive))
        {
            return QStringLiteral("审计");
        }
        return QStringLiteral("事件");
    }

    // collectElementSummary：
    // - 递归收集 XML 元素名称与属性摘要；
    // - reader 必须位于 StartElement 上；
    // - 返回格式类似 "FilePathCondition Path=C:\\*"。
    QString collectElementSummary(QXmlStreamReader& reader)
    {
        const QString elementName = reader.name().toString();
        QStringList fragments;
        const auto attributes = reader.attributes();
        for (const QXmlStreamAttribute& attribute : attributes)
        {
            fragments.push_back(QStringLiteral("%1=%2")
                .arg(attribute.name().toString(), attribute.value().toString()));
        }

        while (reader.readNextStartElement())
        {
            fragments.push_back(collectElementSummary(reader));
        }

        if (fragments.isEmpty())
        {
            return elementName;
        }
        return QStringLiteral("%1 %2").arg(elementName, fragments.join(QStringLiteral(" | ")));
    }

    // fillTable：
    // - 以纯文本二维数组重建 QTableWidget；
    // - headers 为列标题。
    void fillTable(
        QTableWidget* table,
        const QStringList& headers,
        const QVector<QStringList>& rows,
        const QVector<QVariant>& firstColumnUserData = {})
    {
        if (table == nullptr)
        {
            return;
        }

        const bool sortingEnabled = table->isSortingEnabled();
        table->setSortingEnabled(false);
        table->clear();
        table->setColumnCount(headers.size());
        table->setRowCount(rows.size());
        table->setHorizontalHeaderLabels(headers);

        for (int row = 0; row < rows.size(); ++row)
        {
            const QStringList& values = rows.at(row);
            for (int column = 0; column < headers.size(); ++column)
            {
                const QString cellText = column < values.size() ? values.at(column) : QString();
                QTableWidgetItem* item = makeReadOnlyItem(cellText);
                if (column == 0 && row < firstColumnUserData.size())
                {
                    item->setData(Qt::UserRole, firstColumnUserData.at(row));
                }
                table->setItem(row, column, item);
            }
        }

        table->setSortingEnabled(sortingEnabled);
        if (table->horizontalHeader() != nullptr)
        {
            table->horizontalHeader()->setStretchLastSection(true);
        }
    }

    // selectTableContextRow：同步右键命中的行，空白区域返回 -1。
    int selectTableContextRow(QTableWidget* table, const QPoint& localPosition)
    {
        if (table == nullptr)
        {
            return -1;
        }

        const QModelIndex index = table->indexAt(localPosition);
        if (!index.isValid())
        {
            return -1;
        }

        table->setCurrentIndex(index);
        if (table->selectionModel() != nullptr && !table->selectionModel()->isRowSelected(index.row(), QModelIndex()))
        {
            table->selectRow(index.row());
        }
        return index.row();
    }

    // tableCellText：安全读取表格单元格的显示文本。
    QString tableCellText(const QTableWidget* table, const int row, const int column)
    {
        if (table == nullptr || row < 0 || column < 0)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(row, column);
        return item != nullptr ? item->text().trimmed() : QString();
    }
}

namespace ks::misc
{
    ApplicationControlPage::ApplicationControlPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        refreshAsync();
    }

    void ApplicationControlPage::initializeUi()
    {
        m_rootLayout = new QVBoxLayout(this);
        m_rootLayout->setContentsMargins(0, 0, 0, 0);
        m_rootLayout->setSpacing(6);

        m_toolbarWidget = new QWidget(this);
        auto* toolbarLayout = new QHBoxLayout(m_toolbarWidget);
        toolbarLayout->setContentsMargins(0, 0, 0, 0);
        toolbarLayout->setSpacing(8);

        m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), m_toolbarWidget);
        m_refreshButton->setToolTip(QStringLiteral("重新采集 AppLocker / WDAC / Defender / 事件日志"));
        m_exportButton = new QPushButton(QIcon(QStringLiteral(":/Icon/log_export.svg")), QStringLiteral("导出 TSV"), m_toolbarWidget);
        m_exportButton->setToolTip(QStringLiteral("导出当前页主表格为 TSV"));
        m_statusLabel = new QLabel(QStringLiteral("状态: 正在加载…"), m_toolbarWidget);
        m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

        toolbarLayout->addWidget(m_refreshButton);
        toolbarLayout->addWidget(m_exportButton);
        toolbarLayout->addStretch(1);
        toolbarLayout->addWidget(m_statusLabel);
        ks::ui::NormalizeToolbarRow(toolbarLayout);
        m_rootLayout->addWidget(m_toolbarWidget, 0);

        m_tabWidget = new QTabWidget(this);
        ks::ui::StylePageTabs(m_tabWidget);
        m_rootLayout->addWidget(m_tabWidget, 1);

        m_appLockerPage = buildAppLockerPage();
        m_wdacPage = buildWdacPage();
        m_defenderPage = buildDefenderPage();
        m_platformPage = buildPlatformPage();
        m_eventPage = buildEventLogPage();
        m_fileDiagnosisPage = buildFileDiagnosisPage();

        m_tabWidget->addTab(m_appLockerPage, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("AppLocker"));
        m_tabWidget->addTab(m_wdacPage, QIcon(QStringLiteral(":/Icon/disk_storage.svg")), QStringLiteral("WDAC / Code Integrity"));
        m_tabWidget->addTab(m_defenderPage, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("Defender / ASR"));
        m_tabWidget->addTab(m_platformPage, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("平台安全"));
        m_tabWidget->addTab(m_eventPage, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("事件日志"));
        m_tabWidget->addTab(m_fileDiagnosisPage, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("文件诊断"));

        connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
        connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportCurrentTableTsv(); });
    }

    QWidget* ApplicationControlPage::buildAppLockerPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        m_appLockerSummary = new ks::ui::StructuredFieldView(page);

        m_appLockerSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("AppLocker 摘要会在后台刷新后显示。")));
        m_appLockerSummary->setMaximumHeight(160);

        auto* actionRow = new QWidget(page);
        auto* actionLayout = new QHBoxLayout(actionRow);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        m_appLockerEditButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑策略…"), actionRow);
        m_appLockerEditButton->setToolTip(QStringLiteral("读取本地 AppLocker XML 策略并在确认后写回。需要管理员权限。"));
        m_appLockerEditButton->setEnabled(false);
        actionLayout->addWidget(m_appLockerEditButton);
        actionLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(actionLayout);

        m_appLockerTable = new ks::ui::VisibleTableWidget(page);
        // 执行规则增删值得保存前后策略，保留快照对比。
        ks::ui::SetTableActionBarMode(m_appLockerTable, ks::ui::TableActionBarMode::Full);
        initializeTable(m_appLockerTable, true);
        m_appLockerTable->setContextMenuPolicy(Qt::CustomContextMenu);

        layout->addWidget(m_appLockerSummary, 0);
        layout->addWidget(actionRow, 0);
        layout->addWidget(m_appLockerTable, 1);
        connect(m_appLockerEditButton, &QPushButton::clicked, this, [this]() { editAppLockerPolicy(); });
        connect(m_appLockerTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showAppLockerContextMenu(localPosition);
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildWdacPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        m_wdacSummary = new ks::ui::StructuredFieldView(page);

        m_wdacSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("WDAC / Code Integrity 摘要会在后台刷新后显示。")));
        m_wdacSummary->setMaximumHeight(160);

        auto* actionRow = new QWidget(page);
        auto* actionLayout = new QHBoxLayout(actionRow);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        m_wdacEditButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑策略 XML…"), actionRow);
        m_wdacEditButton->setToolTip(QStringLiteral("编辑 WDAC 源 XML；可选择编译并通过 CiTool 部署。部署前请确认策略经过验证。"));
        actionLayout->addWidget(m_wdacEditButton);
        actionLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(actionLayout);

        m_policyFileTable = new ks::ui::VisibleTableWidget(page);
        // 活动 WDAC 策略列表需要对比部署前后状态。
        ks::ui::SetTableActionBarMode(m_policyFileTable, ks::ui::TableActionBarMode::Full);
        initializeTable(m_policyFileTable, true);
        m_policyFileTable->setContextMenuPolicy(Qt::CustomContextMenu);

        m_codeIntegrityEventTable = new ks::ui::VisibleTableWidget(page);
        // WDAC 页的附属事件流水保留复制导出，避免两条完整操作栏。
        ks::ui::SetTableActionBarMode(m_codeIntegrityEventTable, ks::ui::TableActionBarMode::Compact);
        initializeTable(m_codeIntegrityEventTable, true);

        layout->addWidget(m_wdacSummary, 0);
        layout->addWidget(actionRow, 0);
        layout->addWidget(m_policyFileTable, 1);
        layout->addWidget(m_codeIntegrityEventTable, 1);
        connect(m_wdacEditButton, &QPushButton::clicked, this, [this]() { editWdacPolicy(); });
        connect(m_policyFileTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showWdacContextMenu(localPosition);
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildDefenderPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        m_defenderSummary = new ks::ui::StructuredFieldView(page);

        m_defenderSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("Defender 状态会在后台刷新后显示。")));
        m_defenderSummary->setMaximumHeight(160);

        auto* actionRow = new QWidget(page);
        auto* actionLayout = new QHBoxLayout(actionRow);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        m_defenderEditButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑选中项…"), actionRow);
        m_defenderEditButton->setToolTip(QStringLiteral("编辑表格当前选中的 Defender / ASR 配置。需要管理员权限，受篡改防护限制时系统会拒绝写入。"));
        actionLayout->addWidget(m_defenderEditButton);
        actionLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(actionLayout);

        m_defenderTable = new ks::ui::VisibleTableWidget(page);
        // Defender 配置摘要已有编辑入口，收拢快照动作。
        ks::ui::SetTableActionBarMode(m_defenderTable, ks::ui::TableActionBarMode::Compact);
        initializeTable(m_defenderTable, true);
        m_defenderTable->setContextMenuPolicy(Qt::CustomContextMenu);

        layout->addWidget(m_defenderSummary, 0);
        layout->addWidget(actionRow, 0);
        layout->addWidget(m_defenderTable, 1);
        connect(m_defenderEditButton, &QPushButton::clicked, this, [this]() { editDefenderSetting(); });
        connect(m_defenderTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showDefenderContextMenu(localPosition);
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildPlatformPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        m_platformSummary = new ks::ui::StructuredFieldView(page);

        m_platformSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("CI / VBS / Hyper-V / Driver Trust / BAM 摘要会在后台刷新后显示。")));
        m_platformSummary->setMaximumHeight(160);

        m_platformTable = new ks::ui::VisibleTableWidget(page);
        // 平台安全键值摘要已有统一导出，不需要独立快照栏。
        ks::ui::SetTableActionBarMode(m_platformTable, ks::ui::TableActionBarMode::None);
        initializeTable(m_platformTable, true);

        layout->addWidget(m_platformSummary, 0);
        layout->addWidget(m_platformTable, 1);
        return page;
    }

    QWidget* ApplicationControlPage::buildEventLogPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        auto* filterRow = new QWidget(page);
        auto* filterLayout = new QHBoxLayout(filterRow);
        filterLayout->setContentsMargins(0, 0, 0, 0);
        filterLayout->setSpacing(8);

        m_eventVerdictFilterCombo = new QComboBox(filterRow);
        m_eventVerdictFilterCombo->addItems({
            QStringLiteral("全部分类"),
            QStringLiteral("阻止"),
            QStringLiteral("审计"),
            QStringLiteral("允许"),
            QStringLiteral("事件"),
            QStringLiteral("读取失败")
            });
        m_eventVerdictFilterCombo->setToolTip(QStringLiteral("按 Code Integrity 判定分类筛选事件。"));

        m_eventLimitCombo = new QComboBox(filterRow);
        m_eventLimitCombo->addItems({
            QStringLiteral("最近 100 条"),
            QStringLiteral("最近 200 条"),
            QStringLiteral("最近 500 条"),
            QStringLiteral("最近 1000 条")
            });
        m_eventLimitCombo->setCurrentIndex(1);
        m_eventLimitCombo->setToolTip(QStringLiteral("控制本页从 Code Integrity 事件日志读取的最大事件数。"));

        filterLayout->addWidget(new QLabel(QStringLiteral("分类"), filterRow), 0);
        filterLayout->addWidget(m_eventVerdictFilterCombo, 0);
        filterLayout->addWidget(new QLabel(QStringLiteral("数量"), filterRow), 0);
        filterLayout->addWidget(m_eventLimitCombo, 0);
        filterLayout->addStretch(1);

        m_eventSummary = new ks::ui::StructuredFieldView(page);

        m_eventSummaryDocument = ks::ui::FieldDocument{}.note(QStringLiteral("等待 Code Integrity 事件采集。"));
        m_eventSummary->setDocument(m_eventSummaryDocument);
        m_eventSummary->setMaximumHeight(150);

        m_eventTable = new ks::ui::VisibleTableWidget(page);
        // 事件本身是时间序列，保留复制导出并收拢重复快照。
        ks::ui::SetTableActionBarMode(m_eventTable, ks::ui::TableActionBarMode::Compact);
        initializeTable(m_eventTable, true);
        m_eventTable->setMinimumHeight(220);

        ks::ui::NormalizeToolbarRow(filterLayout);
        layout->addWidget(filterRow, 0);
        layout->addWidget(m_eventSummary, 0);
        layout->addWidget(m_eventTable, 1);

        connect(m_eventVerdictFilterCombo, &QComboBox::currentTextChanged, this, [this]() {
            rebuildEventTable();
        });
        connect(m_eventLimitCombo, &QComboBox::currentTextChanged, this, [this]() {
            refreshAsync();
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildFileDiagnosisPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        auto* inputRow = new QWidget(page);
        auto* inputLayout = new QHBoxLayout(inputRow);
        inputLayout->setContentsMargins(0, 0, 0, 0);
        inputLayout->setSpacing(8);

        m_filePathEdit = new QLineEdit(inputRow);
        m_filePathEdit->setPlaceholderText(QStringLiteral("输入 exe / dll / script 文件路径"));
        m_fileBrowseButton = new QPushButton(QStringLiteral("浏览…"), inputRow);
        m_fileDiagnoseButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("诊断"), inputRow);
        m_fileDiagnoseButton->setToolTip(QStringLiteral("诊断所选文件是否会被 AppLocker / WDAC / Defender 拦截"));

        inputLayout->addWidget(m_filePathEdit, 1);
        inputLayout->addWidget(m_fileBrowseButton);
        inputLayout->addWidget(m_fileDiagnoseButton);

        m_fileDiagnosisSummary = new ks::ui::StructuredFieldView(page);

        m_fileDiagnosisSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("文件诊断结果会在运行后显示。")));
        m_fileDiagnosisSummary->setMaximumHeight(180);

        m_fileDiagnosisTable = new ks::ui::VisibleTableWidget(page);
        // 单文件诊断的少量检查项不需要冻结或跨表快照。
        ks::ui::SetTableActionBarMode(m_fileDiagnosisTable, ks::ui::TableActionBarMode::None);
        initializeTable(m_fileDiagnosisTable, true);

        ks::ui::NormalizeToolbarRow(inputLayout);
        layout->addWidget(inputRow, 0);
        layout->addWidget(m_fileDiagnosisSummary, 0);
        layout->addWidget(m_fileDiagnosisTable, 1);

        connect(m_fileBrowseButton, &QPushButton::clicked, this, [this]() {
            const QString filePath = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择待诊断文件"),
                QString(),
                QStringLiteral("可执行文件 (*.exe *.dll *.sys *.scr *.cpl *.ocx *.msi *.ps1 *.vbs *.js *.cmd *.bat);;所有文件 (*.*)"));
            if (!filePath.isEmpty())
            {
                m_filePathEdit->setText(filePath);
            }
        });

        connect(m_fileDiagnoseButton, &QPushButton::clicked, this, [this]() { runFileDiagnosisAsync(); });
        return page;
    }

    void ApplicationControlPage::initializeTable(QTableWidget* table, const bool stretchLastColumn)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        // 全局表格支持会为 DefaultContextMenu 注册复制选中行和导出 TSV。
        // 此处不得再手动追加同类动作，避免菜单出现两组复制入口。
        table->setContextMenuPolicy(Qt::DefaultContextMenu);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->horizontalHeader()->setStretchLastSection(stretchLastColumn);
        table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    }

    QTableWidget* ApplicationControlPage::currentExportTable() const
    {
        if (m_tabWidget == nullptr)
        {
            return nullptr;
        }

        switch (m_tabWidget->currentIndex())
        {
        case 0: return m_appLockerTable;
        case 1:
            if (m_codeIntegrityEventTable != nullptr
                && (m_codeIntegrityEventTable->hasFocus()
                    || (m_codeIntegrityEventTable->selectionModel() != nullptr
                        && !m_codeIntegrityEventTable->selectionModel()->selectedRows().isEmpty())))
            {
                return m_codeIntegrityEventTable;
            }
            return m_policyFileTable;
        case 2: return m_defenderTable;
        case 3: return m_platformTable;
        case 4: return m_eventTable;
        case 5: return m_fileDiagnosisTable;
        default: return nullptr;
        }
    }

    void ApplicationControlPage::showAppLockerContextMenu(const QPoint& localPosition)
    {
        const int selectedRow = selectTableContextRow(m_appLockerTable, localPosition);
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* addAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("新增路径规则…"));
        QAction* editAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑选中规则…"));
        QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("删除选中规则"));
        const bool canModify = m_appLockerModuleAvailable && m_pendingMutationCount == 0;
        addAction->setEnabled(canModify);
        editAction->setEnabled(canModify && selectedRow >= 0);
        deleteAction->setEnabled(canModify && selectedRow >= 0);

        QAction* selectedAction = menu.exec(m_appLockerTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == addAction)
        {
            addAppLockerRule();
        }
        else if (selectedAction == editAction)
        {
            editAppLockerRule(selectedRow);
        }
        else if (selectedAction == deleteAction)
        {
            deleteAppLockerRule();
        }
    }

    void ApplicationControlPage::showWdacContextMenu(const QPoint& localPosition)
    {
        const int selectedRow = selectTableContextRow(m_policyFileTable, localPosition);
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* addAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("新增源策略 XML…"));
        QAction* editAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑源策略 XML…"));
        QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("删除源策略 XML…"));

        QAction* selectedAction = menu.exec(m_policyFileTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == addAction)
        {
            addWdacPolicy();
        }
        else if (selectedAction == editAction)
        {
            const QString selectedPath = tableCellText(m_policyFileTable, selectedRow, 0);
            editWdacPolicy(selectedPath.endsWith(QStringLiteral(".xml"), Qt::CaseInsensitive) ? selectedPath : QString());
        }
        else if (selectedAction == deleteAction)
        {
            deleteWdacPolicy();
        }
    }

    void ApplicationControlPage::showDefenderContextMenu(const QPoint& localPosition)
    {
        const int selectedRow = selectTableContextRow(m_defenderTable, localPosition);
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* addAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("新增 ASR 规则…"));
        QAction* editAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑选中配置…"));
        QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("删除/重置选中配置"));
        editAction->setEnabled(selectedRow >= 0);
        deleteAction->setEnabled(selectedRow >= 0);

        QAction* selectedAction = menu.exec(m_defenderTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == addAction)
        {
            addDefenderAsrRule();
        }
        else if (selectedAction == editAction)
        {
            editDefenderSetting();
        }
        else if (selectedAction == deleteAction)
        {
            deleteDefenderSetting();
        }
    }

    void ApplicationControlPage::runPowerShellMutationAsync(
        const QString& operationName,
        const QString& scriptText)
    {
        ++m_pendingMutationCount;
        if (m_refreshButton != nullptr) m_refreshButton->setEnabled(false);
        if (m_exportButton != nullptr) m_exportButton->setEnabled(false);
        if (m_appLockerEditButton != nullptr) m_appLockerEditButton->setEnabled(false);
        if (m_wdacEditButton != nullptr) m_wdacEditButton->setEnabled(false);
        if (m_defenderEditButton != nullptr) m_defenderEditButton->setEnabled(false);
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("状态: 正在%1…").arg(operationName));
        }

        const QPointer<ApplicationControlPage> guardThis(this);
        std::thread([guardThis, operationName, scriptText]() {
            QString errorText;
            const QString outputText = runPowerShellCaptureText(scriptText, 30000, &errorText);
            const bool succeeded = outputText.contains(QStringLiteral("__OK__")) && errorText.trimmed().isEmpty();
            QString diagnosticText = outputText;
            diagnosticText.remove(QStringLiteral("__OK__"));
            diagnosticText.remove(QStringLiteral("__ERROR__"));
            diagnosticText = diagnosticText.trimmed();
            if (!errorText.trimmed().isEmpty())
            {
                diagnosticText = diagnosticText.isEmpty()
                    ? errorText.trimmed()
                    : QStringLiteral("%1\n%2").arg(diagnosticText, errorText.trimmed());
            }

            QMetaObject::invokeMethod(qApp, [guardThis, operationName, succeeded, diagnosticText]() {
                if (guardThis.isNull())
                {
                    return;
                }

                guardThis->m_pendingMutationCount = std::max(0, guardThis->m_pendingMutationCount - 1);
                const bool hasPendingMutation = guardThis->m_pendingMutationCount > 0;
                if (guardThis->m_refreshButton != nullptr) guardThis->m_refreshButton->setEnabled(!hasPendingMutation);
                if (guardThis->m_exportButton != nullptr) guardThis->m_exportButton->setEnabled(!hasPendingMutation);
                if (guardThis->m_appLockerEditButton != nullptr) guardThis->m_appLockerEditButton->setEnabled(!hasPendingMutation && guardThis->m_appLockerModuleAvailable);
                if (guardThis->m_wdacEditButton != nullptr) guardThis->m_wdacEditButton->setEnabled(!hasPendingMutation);
                if (guardThis->m_defenderEditButton != nullptr) guardThis->m_defenderEditButton->setEnabled(!hasPendingMutation);

                if (!succeeded)
                {
                    if (guardThis->m_statusLabel != nullptr)
                    {
                        guardThis->m_statusLabel->setText(QStringLiteral("状态: %1失败").arg(operationName));
                    }
                    QMessageBox::warning(
                        guardThis.data(),
                        operationName,
                        QStringLiteral("操作失败。\n%1")
                            .arg(diagnosticText.isEmpty() ? QStringLiteral("未返回额外错误信息。") : diagnosticText));
                    return;
                }

                if (guardThis->m_statusLabel != nullptr)
                {
                    guardThis->m_statusLabel->setText(QStringLiteral("状态: %1完成，正在刷新…").arg(operationName));
                }
                QMessageBox::information(guardThis.data(), operationName, QStringLiteral("操作已完成，正在重新读取配置。"));
                guardThis->refreshAsync();
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::editAppLockerPolicy()
    {
        if (!m_appLockerModuleAvailable || m_pendingMutationCount > 0 || m_appLockerEditButton == nullptr)
        {
            return;
        }

        m_appLockerEditButton->setEnabled(false);
        const QPointer<ApplicationControlPage> guardThis(this);
        std::thread([guardThis]() {
            const QString queryScript = appLockerPowerShellPrelude() + QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "try {"
                "  $xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);"
                "  if([string]::IsNullOrWhiteSpace($xml)){Write-Output '__NO_POLICY__'} else {Write-Output '__OK__'; Write-Output $xml}"
                "} catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }");
            QString errorText;
            const QString outputText = runPowerShellCaptureText(queryScript, 15000, &errorText);

            QMetaObject::invokeMethod(qApp, [guardThis, outputText, errorText]() {
                if (guardThis.isNull())
                {
                    return;
                }
                if (guardThis->m_appLockerEditButton != nullptr)
                {
                    guardThis->m_appLockerEditButton->setEnabled(
                        guardThis->m_appLockerModuleAvailable && guardThis->m_pendingMutationCount == 0);
                }

                QString policyXml;
                if (outputText.contains(QStringLiteral("__OK__")))
                {
                    policyXml = outputText.section(QChar::LineFeed, 1);
                }
                else if (outputText.contains(QStringLiteral("__NO_POLICY__")))
                {
                    policyXml = QStringLiteral("<AppLockerPolicy Version=\"1\">\n</AppLockerPolicy>\n");
                }
                else
                {
                    QString diagnosticText = outputText;
                    diagnosticText.remove(QStringLiteral("__ERROR__"));
                    diagnosticText = diagnosticText.trimmed();
                    if (!errorText.trimmed().isEmpty())
                    {
                        diagnosticText = diagnosticText.isEmpty()
                            ? errorText.trimmed()
                            : QStringLiteral("%1\n%2").arg(diagnosticText, errorText.trimmed());
                    }
                    QMessageBox::warning(
                        guardThis.data(),
                        QStringLiteral("编辑 AppLocker 策略"),
                        QStringLiteral("无法读取本地 AppLocker 策略。\n%1")
                            .arg(diagnosticText.isEmpty() ? QStringLiteral("未返回额外错误信息。") : diagnosticText));
                    return;
                }

                QDialog dialog(guardThis.data());
                dialog.setWindowTitle(QStringLiteral("编辑 AppLocker 策略 XML"));
                dialog.resize(900, 620);
                auto* layout = new QVBoxLayout(&dialog);
                auto* hintLabel = new QLabel(
                    QStringLiteral("仅编辑本地策略。保存将以 Replace 模式写回并覆盖当前本地 AppLocker 策略，组策略下发的规则仍由组策略管理。"),
                    &dialog);
                hintLabel->setWordWrap(true);
                hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                auto* editor = new CodeTextEdit(&dialog);
                editor->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Xml);
                editor->setPlainText(policyXml);
                editor->setLineWrapMode(QPlainTextEdit::NoWrap);
                auto* buttonBox = new QDialogButtonBox(&dialog);
                QPushButton* applyButton = buttonBox->addButton(QStringLiteral("保存并应用"), QDialogButtonBox::AcceptRole);
                buttonBox->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
                layout->addWidget(hintLabel);
                layout->addWidget(editor, 1);
                layout->addWidget(buttonBox);
                QObject::connect(applyButton, &QPushButton::clicked, &dialog, &QDialog::accept);
                QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
                if (dialog.exec() != QDialog::Accepted)
                {
                    return;
                }

                const QString editedXml = editor->toPlainText().trimmed();
                QXmlStreamReader xmlReader(editedXml);
                QString rootElementName;
                while (!xmlReader.atEnd())
                {
                    xmlReader.readNext();
                    if (rootElementName.isEmpty() && xmlReader.isStartElement())
                    {
                        rootElementName = xmlReader.name().toString();
                    }
                }
                if (xmlReader.hasError() || rootElementName.compare(QStringLiteral("AppLockerPolicy"), Qt::CaseInsensitive) != 0)
                {
                    QMessageBox::warning(
                        guardThis.data(),
                        QStringLiteral("编辑 AppLocker 策略"),
                        QStringLiteral("策略 XML 无效。根元素必须为 AppLockerPolicy。%1")
                            .arg(xmlReader.hasError() ? QStringLiteral("\n%1").arg(xmlReader.errorString()) : QString()));
                    return;
                }

                if (QMessageBox::warning(
                    guardThis.data(),
                    QStringLiteral("确认应用 AppLocker 策略"),
                    QStringLiteral("将覆盖当前本地 AppLocker 策略。错误策略可能导致应用或脚本无法启动。是否继续？"),
                    QMessageBox::Yes | QMessageBox::Cancel,
                    QMessageBox::Cancel) != QMessageBox::Yes)
                {
                    return;
                }

                const QString encodedXml = QString::fromLatin1(editedXml.toUtf8().toBase64());
                const QString applyScript = appLockerPowerShellPrelude() + QStringLiteral(
                    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                    "try {"
                    "  $xml=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%1'));"
                    "  Set-AppLockerPolicy -XmlPolicy $xml -ErrorAction Stop;"
                    "  Write-Output '__OK__'"
                    "} catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }")
                    .arg(encodedXml);
                guardThis->runPowerShellMutationAsync(QStringLiteral("应用 AppLocker 策略"), applyScript);
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::addAppLockerRule()
    {
        editAppLockerRule(-1);
    }

    void ApplicationControlPage::editAppLockerRule(const int row)
    {
        const bool isNewRule = row < 0;
        if (!m_appLockerModuleAvailable || m_pendingMutationCount > 0 || m_appLockerTable == nullptr)
        {
            return;
        }

        QString ruleId;
        QString initialCollectionText = QStringLiteral("EXE");
        QString initialActionText = QStringLiteral("Allow");
        QString initialSidText = QStringLiteral("S-1-1-0");
        QString initialNameText = QStringLiteral("Ksword Path Rule");
        QString initialDescriptionText;
        QString initialPathText;
        if (!isNewRule)
        {
            if (row >= m_appLockerTable->rowCount())
            {
                return;
            }
            const QTableWidgetItem* idItem = m_appLockerTable->item(row, 0);
            ruleId = idItem != nullptr ? idItem->data(Qt::UserRole).toString().trimmed() : QString();
            if (ruleId.isEmpty())
            {
                QMessageBox::information(this, QStringLiteral("编辑 AppLocker 规则"), QStringLiteral("当前规则没有可写入的本地规则 ID，可能由组策略下发。"));
                return;
            }
            if (!tableCellText(m_appLockerTable, row, 4).contains(QStringLiteral("Path"), Qt::CaseInsensitive))
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("编辑 AppLocker 规则"),
                    QStringLiteral("右键表单只编辑路径规则。发布者和哈希规则请使用“编辑策略…”中的 XML 编辑器。"));
                editAppLockerPolicy();
                return;
            }

            initialCollectionText = tableCellText(m_appLockerTable, row, 0);
            initialActionText = tableCellText(m_appLockerTable, row, 1);
            initialSidText = tableCellText(m_appLockerTable, row, 3);
            initialNameText = tableCellText(m_appLockerTable, row, 6);
            initialDescriptionText = initialNameText;
            const QRegularExpression pathPattern(QStringLiteral("Path=([^;|]+)"), QRegularExpression::CaseInsensitiveOption);
            const QRegularExpressionMatch pathMatch = pathPattern.match(tableCellText(m_appLockerTable, row, 5));
            initialPathText = pathMatch.hasMatch() ? pathMatch.captured(1).trimmed() : QString();
        }

        QDialog dialog(this);
        dialog.setWindowTitle(isNewRule ? QStringLiteral("新增 AppLocker 路径规则") : QStringLiteral("编辑 AppLocker 路径规则"));
        auto* formLayout = new QFormLayout(&dialog);
        auto* collectionCombo = new QComboBox(&dialog);
        collectionCombo->addItem(QStringLiteral("EXE"), QStringLiteral("Exe"));
        collectionCombo->addItem(QStringLiteral("DLL"), QStringLiteral("Dll"));
        collectionCombo->addItem(QStringLiteral("MSI"), QStringLiteral("Msi"));
        collectionCombo->addItem(QStringLiteral("Script"), QStringLiteral("Script"));
        auto* actionCombo = new QComboBox(&dialog);
        actionCombo->addItem(QStringLiteral("Allow"));
        actionCombo->addItem(QStringLiteral("Deny"));
        auto* sidEdit = new QLineEdit(initialSidText, &dialog);
        auto* nameEdit = new QLineEdit(initialNameText, &dialog);
        auto* pathEdit = new QLineEdit(initialPathText, &dialog);
        auto* descriptionEdit = new QLineEdit(initialDescriptionText, &dialog);
        pathEdit->setPlaceholderText(QStringLiteral("例如 %WINDIR%\\* 或 C:\\Program Files\\App\\*"));
        for (int index = 0; index < collectionCombo->count(); ++index)
        {
            if (collectionCombo->itemText(index).compare(initialCollectionText, Qt::CaseInsensitive) == 0)
            {
                collectionCombo->setCurrentIndex(index);
                break;
            }
        }
        collectionCombo->setEnabled(isNewRule);
        actionCombo->setCurrentIndex(initialActionText.compare(QStringLiteral("Deny"), Qt::CaseInsensitive) == 0 ? 1 : 0);
        formLayout->addRow(QStringLiteral("规则集合"), collectionCombo);
        formLayout->addRow(QStringLiteral("操作"), actionCombo);
        formLayout->addRow(QStringLiteral("用户或组 SID"), sidEdit);
        formLayout->addRow(QStringLiteral("规则名称"), nameEdit);
        formLayout->addRow(QStringLiteral("路径"), pathEdit);
        formLayout->addRow(QStringLiteral("说明"), descriptionEdit);
        auto* hintLabel = new QLabel(
            QStringLiteral("新增和编辑仅写入本地 AppLocker 路径规则。规则 ID、XML 转义和策略写回由程序处理，需要管理员权限。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        formLayout->addRow(hintLabel);
        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        buttonBox->button(QDialogButtonBox::Ok)->setText(isNewRule ? QStringLiteral("新增") : QStringLiteral("应用"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        formLayout->addRow(buttonBox);
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        const QString pathText = pathEdit->text().trimmed();
        const QString sidText = sidEdit->text().trimmed();
        const QString nameText = nameEdit->text().trimmed();
        if (pathText.isEmpty() || sidText.isEmpty() || nameText.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("AppLocker 路径规则"), QStringLiteral("路径、用户或组 SID 和规则名称不能为空。"));
            return;
        }
        if (QMessageBox::warning(
            this,
            isNewRule ? QStringLiteral("确认新增 AppLocker 规则") : QStringLiteral("确认修改 AppLocker 规则"),
            QStringLiteral("将写入本地 AppLocker 策略。错误规则可能阻止应用或脚本启动。是否继续？"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const auto encoded = [](const QString& text) {
            return QString::fromLatin1(text.toUtf8().toBase64());
        };
        const QString effectiveRuleId = isNewRule ? QUuid::createUuid().toString() : ruleId;
        QString mutationScript;
        if (isNewRule)
        {
            mutationScript = QStringLiteral(
                "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
                "$collectionType=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%2'));"
                "$action=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%3'));"
                "$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%4'));"
                "$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%5'));"
                "$description=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%6'));"
                "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%7'));"
                "$xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);"
                "$doc=New-Object System.Xml.XmlDocument;"
                "if([string]::IsNullOrWhiteSpace($xml)){$doc.LoadXml('<AppLockerPolicy Version=\"1\"></AppLockerPolicy>')}else{$doc.LoadXml($xml)};"
                "$collection=$null;foreach($candidate in $doc.DocumentElement.SelectNodes('RuleCollection')){if($candidate.GetAttribute('Type') -eq $collectionType){$collection=$candidate;break}};"
                "if($null -eq $collection){$collection=$doc.CreateElement('RuleCollection');$collection.SetAttribute('Type',$collectionType);$collection.SetAttribute('EnforcementMode','Enabled');[void]$doc.DocumentElement.AppendChild($collection)};"
                "$rule=$doc.CreateElement('FilePathRule');$rule.SetAttribute('Id',$ruleId);$rule.SetAttribute('Name',$name);$rule.SetAttribute('Description',$description);$rule.SetAttribute('UserOrGroupSid',$sid);$rule.SetAttribute('Action',$action);"
                "$conditions=$doc.CreateElement('Conditions');$condition=$doc.CreateElement('FilePathCondition');$condition.SetAttribute('Path',$path);[void]$conditions.AppendChild($condition);[void]$rule.AppendChild($conditions);[void]$collection.AppendChild($rule);"
                "Set-AppLockerPolicy -XmlPolicy $doc.OuterXml -ErrorAction Stop")
                .arg(encoded(effectiveRuleId))
                .arg(encoded(collectionCombo->currentData().toString()))
                .arg(encoded(actionCombo->currentText()))
                .arg(encoded(sidText))
                .arg(encoded(nameText))
                .arg(encoded(descriptionEdit->text()))
                .arg(encoded(pathText));
        }
        else
        {
            mutationScript = QStringLiteral(
                "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
                "$action=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%2'));"
                "$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%3'));"
                "$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%4'));"
                "$description=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%5'));"
                "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%6'));"
                "$xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);if([string]::IsNullOrWhiteSpace($xml)){throw '未配置本地 AppLocker 策略'};"
                "$doc=New-Object System.Xml.XmlDocument;$doc.LoadXml($xml);$rule=$null;foreach($candidate in $doc.SelectNodes('//*')){if($candidate.HasAttribute('Id') -and $candidate.GetAttribute('Id') -ieq $ruleId){$rule=$candidate;break}};"
                "if($null -eq $rule){throw '所选规则不在本地策略中，可能由组策略下发'};if($rule.LocalName -ne 'FilePathRule'){throw '所选规则不是路径规则'};"
                "$rule.SetAttribute('Name',$name);$rule.SetAttribute('Description',$description);$rule.SetAttribute('UserOrGroupSid',$sid);$rule.SetAttribute('Action',$action);$condition=$rule.SelectSingleNode('Conditions/FilePathCondition');if($null -eq $condition){throw '未找到路径条件'};$condition.SetAttribute('Path',$path);"
                "Set-AppLockerPolicy -XmlPolicy $doc.OuterXml -ErrorAction Stop")
                .arg(encoded(effectiveRuleId))
                .arg(encoded(actionCombo->currentText()))
                .arg(encoded(sidText))
                .arg(encoded(nameText))
                .arg(encoded(descriptionEdit->text()))
                .arg(encoded(pathText));
        }
        mutationScript = appLockerPowerShellPrelude() + QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{%1;Write-Output '__OK__'}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(mutationScript);
        runPowerShellMutationAsync(isNewRule ? QStringLiteral("新增 AppLocker 路径规则") : QStringLiteral("修改 AppLocker 路径规则"), mutationScript);
    }

    void ApplicationControlPage::deleteAppLockerRule()
    {
        if (!m_appLockerModuleAvailable || m_pendingMutationCount > 0 || m_appLockerTable == nullptr || m_appLockerTable->currentRow() < 0)
        {
            return;
        }
        const int row = m_appLockerTable->currentRow();
        const QTableWidgetItem* idItem = m_appLockerTable->item(row, 0);
        const QString ruleId = idItem != nullptr ? idItem->data(Qt::UserRole).toString().trimmed() : QString();
        if (ruleId.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("删除 AppLocker 规则"), QStringLiteral("当前规则没有可写入的本地规则 ID，可能由组策略下发。"));
            return;
        }
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认删除 AppLocker 规则"),
            QStringLiteral("将从本地 AppLocker 策略删除“%1”。是否继续？").arg(tableCellText(m_appLockerTable, row, 6)),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString encodedRuleId = QString::fromLatin1(ruleId.toUtf8().toBase64());
        const QString mutationScript = appLockerPowerShellPrelude() + QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{"
            "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));$xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);if([string]::IsNullOrWhiteSpace($xml)){throw '未配置本地 AppLocker 策略'};"
            "$doc=New-Object System.Xml.XmlDocument;$doc.LoadXml($xml);$rule=$null;foreach($candidate in $doc.SelectNodes('//*')){if($candidate.HasAttribute('Id') -and $candidate.GetAttribute('Id') -ieq $ruleId){$rule=$candidate;break}};"
            "if($null -eq $rule){throw '所选规则不在本地策略中，可能由组策略下发'};$collection=$rule.ParentNode;[void]$collection.RemoveChild($rule);if($collection.SelectNodes('*[contains(local-name(),\"Rule\")]').Count -eq 0){[void]$collection.ParentNode.RemoveChild($collection)};"
            "Set-AppLockerPolicy -XmlPolicy $doc.OuterXml -ErrorAction Stop;Write-Output '__OK__'"
            "}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(encodedRuleId);
        runPowerShellMutationAsync(QStringLiteral("删除 AppLocker 规则"), mutationScript);
    }

    void ApplicationControlPage::editWdacPolicy(const QString& requestedSourcePath)
    {
        if (m_pendingMutationCount > 0)
        {
            return;
        }

        QString sourcePath = requestedSourcePath;
        if (sourcePath.isEmpty())
        {
            sourcePath = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择 WDAC 源策略 XML"),
                QString(),
                QStringLiteral("WDAC 策略 XML (*.xml);;所有文件 (*.*)"));
        }
        if (sourcePath.isEmpty())
        {
            return;
        }

        QFile sourceFile(sourcePath);
        if (!sourceFile.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            QMessageBox::warning(this, QStringLiteral("编辑 WDAC 策略"), QStringLiteral("无法读取：%1").arg(sourcePath));
            return;
        }
        const QString originalXml = QString::fromUtf8(sourceFile.readAll());
        sourceFile.close();

        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("编辑 WDAC 源策略 XML"));
        dialog.resize(900, 620);
        auto* layout = new QVBoxLayout(&dialog);
        auto* hintLabel = new QLabel(
            QStringLiteral("保存仅更新所选 XML 源文件。选择“保存并部署”会调用 ConfigCI 编译为 CIP，再由 CiTool 更新系统策略。部署前请在测试环境验证策略。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto* editor = new CodeTextEdit(&dialog);
        editor->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Xml);
        editor->setPlainText(originalXml);
        editor->setLineWrapMode(QPlainTextEdit::NoWrap);
        auto* buttonBox = new QDialogButtonBox(&dialog);
        QPushButton* saveButton = buttonBox->addButton(QStringLiteral("保存源 XML"), QDialogButtonBox::AcceptRole);
        QPushButton* deployButton = buttonBox->addButton(QStringLiteral("保存并部署"), QDialogButtonBox::ActionRole);
        buttonBox->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
        bool deployRequested = false;
        layout->addWidget(hintLabel);
        layout->addWidget(editor, 1);
        layout->addWidget(buttonBox);
        QObject::connect(saveButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        QObject::connect(deployButton, &QPushButton::clicked, &dialog, [&dialog, &deployRequested]() {
            deployRequested = true;
            dialog.accept();
        });
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        const QString editedXml = editor->toPlainText().trimmed();
        QXmlStreamReader xmlReader(editedXml);
        QString rootElementName;
        while (!xmlReader.atEnd())
        {
            xmlReader.readNext();
            if (rootElementName.isEmpty() && xmlReader.isStartElement())
            {
                rootElementName = xmlReader.name().toString();
            }
        }
        if (xmlReader.hasError() || rootElementName.compare(QStringLiteral("SiPolicy"), Qt::CaseInsensitive) != 0)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("编辑 WDAC 策略"),
                QStringLiteral("策略 XML 无效。根元素必须为 SiPolicy。%1")
                    .arg(xmlReader.hasError() ? QStringLiteral("\n%1").arg(xmlReader.errorString()) : QString()));
            return;
        }

        QSaveFile outputFile(sourcePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text) ||
            outputFile.write(editedXml.toUtf8()) != editedXml.toUtf8().size() ||
            !outputFile.commit())
        {
            QMessageBox::warning(this, QStringLiteral("编辑 WDAC 策略"), QStringLiteral("无法保存：%1").arg(sourcePath));
            return;
        }

        if (!deployRequested)
        {
            QMessageBox::information(this, QStringLiteral("编辑 WDAC 策略"), QStringLiteral("已保存源 XML：%1").arg(sourcePath));
            return;
        }

        const QFileInfo sourceInfo(sourcePath);
        const QString binaryPath = sourceInfo.dir().absoluteFilePath(sourceInfo.completeBaseName() + QStringLiteral(".cip"));
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认部署 WDAC 策略"),
            QStringLiteral("将编译并部署：\n%1\n\n错误的 WDAC 策略可能阻止应用、驱动或系统组件加载。是否继续？").arg(sourcePath),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString encodedSourcePath = QString::fromLatin1(sourcePath.toUtf8().toBase64());
        const QString encodedBinaryPath = QString::fromLatin1(binaryPath.toUtf8().toBase64());
        const QString deployScript = QStringLiteral(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "try {"
            "  $xmlPath=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%1'));"
            "  $binaryPath=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%2'));"
            "  Import-Module ConfigCI -ErrorAction Stop;"
            "  ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binaryPath -ErrorAction Stop;"
            "  $ciTool=Join-Path $env:WINDIR 'System32\\CiTool.exe';"
            "  if(-not (Test-Path -LiteralPath $ciTool)){throw '未找到 CiTool.exe；CIP 已生成但未部署。'};"
            "  & $ciTool --update-policy $binaryPath;"
            "  if($LASTEXITCODE -ne 0){throw ('CiTool 退出码 '+$LASTEXITCODE)};"
            "  Write-Output '__OK__'"
            "} catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }")
            .arg(encodedSourcePath, encodedBinaryPath);
        runPowerShellMutationAsync(QStringLiteral("部署 WDAC 策略"), deployScript);
    }

    void ApplicationControlPage::addWdacPolicy()
    {
        if (m_pendingMutationCount > 0)
        {
            return;
        }

        const QString sourcePath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("新增 WDAC 源策略 XML"),
            QStringLiteral("wdac-policy.xml"),
            QStringLiteral("WDAC 策略 XML (*.xml)"));
        if (sourcePath.isEmpty())
        {
            return;
        }
        if (QFileInfo::exists(sourcePath) && QMessageBox::warning(
            this,
            QStringLiteral("新增 WDAC 源策略"),
            QStringLiteral("文件已存在，继续将覆盖该源 XML。是否继续？"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString policyTemplate = QStringLiteral(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<SiPolicy xmlns=\"urn:schemas-microsoft-com:sipolicy\">\n"
            "</SiPolicy>\n");
        QSaveFile outputFile(sourcePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text) ||
            outputFile.write(policyTemplate.toUtf8()) != policyTemplate.toUtf8().size() ||
            !outputFile.commit())
        {
            QMessageBox::warning(this, QStringLiteral("新增 WDAC 源策略"), QStringLiteral("无法创建：%1").arg(sourcePath));
            return;
        }
        QMessageBox::information(
            this,
            QStringLiteral("新增 WDAC 源策略"),
            QStringLiteral("已创建 XML 草稿。请在编辑器中补充有效策略内容后再编译部署。"));
        editWdacPolicy(sourcePath);
    }

    void ApplicationControlPage::deleteWdacPolicy()
    {
        if (m_pendingMutationCount > 0)
        {
            return;
        }

        const QString sourcePath = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("选择要删除的 WDAC 源策略 XML"),
            QString(),
            QStringLiteral("WDAC 策略 XML (*.xml);;所有文件 (*.*)"));
        if (sourcePath.isEmpty())
        {
            return;
        }
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认删除 WDAC 源策略"),
            QStringLiteral("将删除源 XML：\n%1\n\n已部署的 CIP 策略不会随文件删除自动卸载。是否继续？").arg(sourcePath),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }
        if (!QFile::remove(sourcePath))
        {
            QMessageBox::warning(this, QStringLiteral("删除 WDAC 源策略"), QStringLiteral("无法删除：%1").arg(sourcePath));
            return;
        }
        QMessageBox::information(this, QStringLiteral("删除 WDAC 源策略"), QStringLiteral("已删除源 XML：%1").arg(sourcePath));
    }

    void ApplicationControlPage::editDefenderSetting()
    {
        if (m_pendingMutationCount > 0 || m_defenderTable == nullptr || m_defenderTable->currentRow() < 0)
        {
            QMessageBox::information(this, QStringLiteral("编辑 Defender 配置"), QStringLiteral("请先在表格中选中要编辑的配置项。"));
            return;
        }

        const int selectedRow = m_defenderTable->currentRow();
        const QTableWidgetItem* nameItem = m_defenderTable->item(selectedRow, 0);
        const QTableWidgetItem* valueItem = m_defenderTable->item(selectedRow, 1);
        const QString settingName = nameItem != nullptr ? nameItem->text().trimmed() : QString();
        const QString currentValue = valueItem != nullptr ? valueItem->text().trimmed() : QString();

        enum class DefenderSettingKind { ControlledFolderAccess, PuaProtection, NetworkProtection, AsrRule, RealTimeProtection };
        DefenderSettingKind settingKind{};
        QString asrRuleId;
        if (settingName.compare(QStringLiteral("Controlled Folder Access"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::ControlledFolderAccess;
        }
        else if (settingName.compare(QStringLiteral("PUA Protection"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::PuaProtection;
        }
        else if (settingName.compare(QStringLiteral("Network Protection"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::NetworkProtection;
        }
        else if (settingName.compare(QStringLiteral("Real Time Protection"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::RealTimeProtection;
        }
        else
        {
            const QRegularExpression asrPattern(QStringLiteral("^ASR\\s+([0-9A-Fa-f-]{36})$"));
            const QRegularExpressionMatch asrMatch = asrPattern.match(settingName);
            if (!asrMatch.hasMatch())
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("编辑 Defender 配置"),
                    QStringLiteral("当前项不支持在此编辑。支持受控文件夹访问、PUA、防网络保护、ASR 规则和实时保护。"));
                return;
            }
            settingKind = DefenderSettingKind::AsrRule;
            asrRuleId = asrMatch.captured(1);
        }

        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("编辑 Defender 配置"));
        auto* formLayout = new QFormLayout(&dialog);
        auto* valueCombo = new QComboBox(&dialog);
        formLayout->addRow(QStringLiteral("配置项"), new QLabel(settingName, &dialog));
        formLayout->addRow(QStringLiteral("当前值"), new QLabel(currentValue, &dialog));
        if (settingKind == DefenderSettingKind::RealTimeProtection)
        {
            valueCombo->addItem(QStringLiteral("启用"), true);
            valueCombo->addItem(QStringLiteral("关闭"), false);
        }
        else if (settingKind == DefenderSettingKind::AsrRule)
        {
            valueCombo->addItem(QStringLiteral("禁用 (0)"), 0);
            valueCombo->addItem(QStringLiteral("阻止 (1)"), 1);
            valueCombo->addItem(QStringLiteral("审核 (2)"), 2);
            valueCombo->addItem(QStringLiteral("警告 (6)"), 6);
        }
        else
        {
            valueCombo->addItem(QStringLiteral("关闭 (0)"), 0);
            valueCombo->addItem(QStringLiteral("阻止/启用 (1)"), 1);
            valueCombo->addItem(QStringLiteral("审核 (2)"), 2);
        }
        for (int index = 0; index < valueCombo->count(); ++index)
        {
            const QString valueText = valueCombo->itemData(index).typeId() == QMetaType::Bool
                ? (valueCombo->itemData(index).toBool() ? QStringLiteral("True") : QStringLiteral("False"))
                : valueCombo->itemData(index).toString();
            if (valueText.compare(currentValue, Qt::CaseInsensitive) == 0)
            {
                valueCombo->setCurrentIndex(index);
                break;
            }
        }
        formLayout->addRow(QStringLiteral("新值"), valueCombo);
        auto* hintLabel = new QLabel(
            QStringLiteral("写入使用 Set-MpPreference。篡改防护、组织策略或 Defender 服务不可用时，Windows 会拒绝该操作并显示详细错误。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        formLayout->addRow(hintLabel);
        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("应用"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        formLayout->addRow(buttonBox);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        if (QMessageBox::warning(
            this,
            QStringLiteral("确认修改 Defender 配置"),
            QStringLiteral("将修改“%1”。是否继续？").arg(settingName),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        QString mutationScript;
        if (settingKind == DefenderSettingKind::ControlledFolderAccess)
        {
            mutationScript = QStringLiteral("Set-MpPreference -EnableControlledFolderAccess %1 -ErrorAction Stop").arg(valueCombo->currentData().toInt());
        }
        else if (settingKind == DefenderSettingKind::PuaProtection)
        {
            mutationScript = QStringLiteral("Set-MpPreference -PUAProtection %1 -ErrorAction Stop").arg(valueCombo->currentData().toInt());
        }
        else if (settingKind == DefenderSettingKind::NetworkProtection)
        {
            mutationScript = QStringLiteral("Set-MpPreference -EnableNetworkProtection %1 -ErrorAction Stop").arg(valueCombo->currentData().toInt());
        }
        else if (settingKind == DefenderSettingKind::RealTimeProtection)
        {
            mutationScript = QStringLiteral("Set-MpPreference -DisableRealtimeMonitoring $%1 -ErrorAction Stop")
                .arg(valueCombo->currentData().toBool() ? QStringLiteral("false") : QStringLiteral("true"));
        }
        else
        {
            const QString encodedRuleId = QString::fromLatin1(asrRuleId.toUtf8().toBase64());
            mutationScript = QStringLiteral(
                "$ruleId=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%1'));"
                "$pref=Get-MpPreference -ErrorAction Stop;"
                "$ids=@($pref.AttackSurfaceReductionRules_Ids);"
                "$actions=@($pref.AttackSurfaceReductionRules_Actions);"
                "$found=$false;"
                "for($i=0;$i -lt $ids.Count;$i++){if([string]$ids[$i] -ieq $ruleId){$actions[$i]=%2;$found=$true;break}};"
                "if(-not $found){$ids+=@($ruleId);$actions+=@(%2)};"
                "Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop")
                .arg(encodedRuleId)
                .arg(valueCombo->currentData().toInt());
        }
        mutationScript = QStringLiteral(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "try { %1; Write-Output '__OK__' }"
            "catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }")
            .arg(mutationScript);
        runPowerShellMutationAsync(QStringLiteral("修改 Defender 配置"), mutationScript);
    }


    void ApplicationControlPage::addDefenderAsrRule()
    {
        if (m_pendingMutationCount > 0)
        {
            return;
        }

        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("新增 ASR 规则"));
        auto* formLayout = new QFormLayout(&dialog);
        auto* ruleIdEdit = new QLineEdit(&dialog);
        ruleIdEdit->setPlaceholderText(QStringLiteral("输入 ASR 规则 GUID，例如 D4F..."));
        auto* actionCombo = new QComboBox(&dialog);
        actionCombo->addItem(QStringLiteral("禁用 (0)"), 0);
        actionCombo->addItem(QStringLiteral("阻止 (1)"), 1);
        actionCombo->addItem(QStringLiteral("审核 (2)"), 2);
        actionCombo->addItem(QStringLiteral("警告 (6)"), 6);
        formLayout->addRow(QStringLiteral("ASR 规则 GUID"), ruleIdEdit);
        formLayout->addRow(QStringLiteral("操作"), actionCombo);
        auto* hintLabel = new QLabel(
            QStringLiteral("请输入 Microsoft 支持的 ASR 规则 GUID。程序会保留现有 ASR 规则并添加新项，需要管理员权限。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        formLayout->addRow(hintLabel);
        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("新增"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        formLayout->addRow(buttonBox);
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        const QUuid ruleUuid(ruleIdEdit->text().trimmed());
        if (ruleUuid.isNull())
        {
            QMessageBox::warning(this, QStringLiteral("新增 ASR 规则"), QStringLiteral("ASR 规则 GUID 格式无效。"));
            return;
        }
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认新增 ASR 规则"),
            QStringLiteral("将新增 ASR 规则 %1。是否继续？").arg(ruleUuid.toString(QUuid::WithoutBraces)),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString encodedRuleId = QString::fromLatin1(ruleUuid.toString(QUuid::WithoutBraces).toUtf8().toBase64());
        QString mutationScript = QStringLiteral(
            "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
            "$pref=Get-MpPreference -ErrorAction Stop;$ids=@($pref.AttackSurfaceReductionRules_Ids);$actions=@($pref.AttackSurfaceReductionRules_Actions);"
            "foreach($id in $ids){if([string]$id -ieq $ruleId){throw '该 ASR 规则已存在，请使用编辑操作'}};"
            "$ids+=@($ruleId);$actions+=@(%2);"
            "Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop")
            .arg(encodedRuleId)
            .arg(actionCombo->currentData().toInt());
        mutationScript = QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{%1;Write-Output '__OK__'}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(mutationScript);
        runPowerShellMutationAsync(QStringLiteral("新增 ASR 规则"), mutationScript);
    }

    void ApplicationControlPage::deleteDefenderSetting()
    {
        if (m_pendingMutationCount > 0 || m_defenderTable == nullptr || m_defenderTable->currentRow() < 0)
        {
            return;
        }

        const int row = m_defenderTable->currentRow();
        const QString settingName = tableCellText(m_defenderTable, row, 0);
        QString mutationScript;
        QString operationName;
        const QRegularExpression asrPattern(QStringLiteral("^ASR\\s+([0-9A-Fa-f-]{36})$"));
        const QRegularExpressionMatch asrMatch = asrPattern.match(settingName);
        if (asrMatch.hasMatch())
        {
            const QString encodedRuleId = QString::fromLatin1(asrMatch.captured(1).toUtf8().toBase64());
            operationName = QStringLiteral("删除 ASR 规则");
            mutationScript = QStringLiteral(
                "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
                "$pref=Get-MpPreference -ErrorAction Stop;$ids=@($pref.AttackSurfaceReductionRules_Ids);$actions=@($pref.AttackSurfaceReductionRules_Actions);$newIds=@();$newActions=@();$found=$false;"
                "for($i=0;$i -lt $ids.Count;$i++){if([string]$ids[$i] -ieq $ruleId){$found=$true;continue};$newIds+=@($ids[$i]);if($i -lt $actions.Count){$newActions+=@($actions[$i])}};"
                "if(-not $found){throw '未找到 ASR 规则'};Set-MpPreference -AttackSurfaceReductionRules_Ids $newIds -AttackSurfaceReductionRules_Actions $newActions -ErrorAction Stop")
                .arg(encodedRuleId);
        }
        else if (settingName.compare(QStringLiteral("Controlled Folder Access"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置受控文件夹访问");
            mutationScript = QStringLiteral("Set-MpPreference -EnableControlledFolderAccess 0 -ErrorAction Stop");
        }
        else if (settingName.compare(QStringLiteral("PUA Protection"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置 PUA 保护");
            mutationScript = QStringLiteral("Set-MpPreference -PUAProtection 0 -ErrorAction Stop");
        }
        else if (settingName.compare(QStringLiteral("Network Protection"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置网络保护");
            mutationScript = QStringLiteral("Set-MpPreference -EnableNetworkProtection 0 -ErrorAction Stop");
        }
        else if (settingName.compare(QStringLiteral("Real Time Protection"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置实时保护");
            mutationScript = QStringLiteral("Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop");
        }
        else
        {
            QMessageBox::information(
                this,
                QStringLiteral("删除/重置 Defender 配置"),
                QStringLiteral("当前项没有可由 Defender 命令行删除或重置的接口。"));
            return;
        }

        if (QMessageBox::warning(
            this,
            QStringLiteral("确认%1").arg(operationName),
            asrMatch.hasMatch()
                ? QStringLiteral("将删除 ASR 规则“%1”。是否继续？").arg(settingName)
                : QStringLiteral("将把“%1”重置为默认关闭状态。是否继续？").arg(settingName),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }
        mutationScript = QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{%1;Write-Output '__OK__'}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(mutationScript);
        runPowerShellMutationAsync(operationName, mutationScript);
    }

    QString ApplicationControlPage::tableToTsv(QTableWidget* table, const bool selectedOnly) const
    {
        if (table == nullptr)
        {
            return QString();
        }

        QStringList lines;
        QStringList headerValues;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            QTableWidgetItem* headerItem = table->horizontalHeaderItem(column);
            headerValues.push_back(headerItem != nullptr ? headerItem->text() : QStringLiteral("Column %1").arg(column + 1));
        }
        lines.push_back(headerValues.join(QStringLiteral("\t")));

        QVector<int> rowIndexes;
        if (selectedOnly && table->selectionModel() != nullptr)
        {
            const QModelIndexList selectedRows = table->selectionModel()->selectedRows();
            rowIndexes.reserve(selectedRows.size());
            for (const QModelIndex& index : selectedRows)
            {
                rowIndexes.push_back(index.row());
            }
        }
        else
        {
            rowIndexes.reserve(table->rowCount());
            for (int row = 0; row < table->rowCount(); ++row)
            {
                rowIndexes.push_back(row);
            }
        }

        for (const int row : rowIndexes)
        {
            QStringList values;
            values.reserve(table->columnCount());
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QTableWidgetItem* item = table->item(row, column);
                values.push_back(item != nullptr ? item->text() : QString());
            }
            lines.push_back(values.join(QStringLiteral("\t")));
        }

        return lines.join(QStringLiteral("\n"));
    }

    void ApplicationControlPage::exportCurrentTableTsv()
    {
        QTableWidget* const table = currentExportTable();
        if (table == nullptr)
        {
            QMessageBox::information(this, QStringLiteral("导出 TSV"), QStringLiteral("当前页没有可导出的表格。"));
            return;
        }

        const QString outputPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出 TSV"),
            QStringLiteral("application_control.tsv"),
            QStringLiteral("TSV 文件 (*.tsv)"));
        if (outputPath.isEmpty())
        {
            return;
        }

        QFile outputFile(outputPath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        {
            QMessageBox::warning(this, QStringLiteral("导出 TSV"), QStringLiteral("无法写入：%1").arg(outputPath));
            return;
        }

        outputFile.write(tableToTsv(table, false).toUtf8());
        outputFile.close();
        QMessageBox::information(this, QStringLiteral("导出 TSV"), QStringLiteral("已导出：%1").arg(outputPath));
    }

    QString ApplicationControlPage::buildAppLockerRiskText(
        const QString& actionText,
        const QString& sidText,
        const QString& conditionTypeText,
        const QString& conditionText)
    {
        QStringList riskList;
        const QString loweredSid = sidText.trimmed();
        if (actionText.compare(QStringLiteral("Allow"), Qt::CaseInsensitive) == 0
            && (loweredSid == QStringLiteral("S-1-1-0") || sidToFriendlyText(loweredSid) == QStringLiteral("Everyone")))
        {
            riskList.push_back(QStringLiteral("Everyone Allow"));
        }

        if (conditionTypeText.compare(QStringLiteral("Path"), Qt::CaseInsensitive) == 0)
        {
            if (isBroadPathRuleText(conditionText))
            {
                riskList.push_back(QStringLiteral("Users writable path"));
            }
            const QString lower = conditionText.toLower();
            if (conditionText.trimmed() == QStringLiteral("*")
                || lower == QStringLiteral("*")
                || lower.contains(QStringLiteral("\\*"))
                || lower.contains(QStringLiteral("*\\"))
                || lower.contains(QStringLiteral("*.*")))
            {
                riskList.push_back(QStringLiteral("宽泛 * 规则"));
            }
        }
        else if (conditionText.trimmed().contains(QStringLiteral("*")))
        {
            riskList.push_back(QStringLiteral("宽泛 * 规则"));
        }

        return riskList.isEmpty() ? QString() : riskList.join(QStringLiteral("; "));
    }

    QString ApplicationControlPage::runPowerShellCaptureText(
        const QString& scriptText,
        const int timeoutMs,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments(QStringList{
            QStringLiteral("-NoLogo"),
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
        });
        process.start();
        if (!process.waitForStarted(5000))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法启动 powershell.exe。");
            }
            return QString();
        }

        if (!process.waitForFinished(timeoutMs))
        {
            process.kill();
            process.waitForFinished(2000);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("PowerShell 查询超时。");
            }
            return QString();
        }

        const QString stdOutText = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        const QString stdErrText = QString::fromUtf8(process.readAllStandardError()).trimmed();
        if (errorTextOut != nullptr)
        {
            *errorTextOut = stdErrText;
            if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
            {
                const QString exitHint = QStringLiteral("PowerShell 退出码 %1。").arg(process.exitCode());
                if (errorTextOut->isEmpty())
                {
                    *errorTextOut = exitHint;
                }
                else
                {
                    *errorTextOut += QStringLiteral("\n");
                    *errorTextOut += exitHint;
                }
            }
        }

        return stdOutText;
    }

    std::pair<QVector<ApplicationControlPage::AppLockerRuleRecord>, ks::ui::FieldDocument> ApplicationControlPage::parseAppLockerPolicyXml(
        const QString& xmlText)
    {
        QVector<AppLockerRuleRecord> records;
        if (xmlText.trimmed().isEmpty())
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("AppLocker: 未配置")) };
        }

        QXmlStreamReader reader(xmlText);
        QStringList summaryParts;
        int collectionCount = 0;

        const auto collectionToText = [](const QString& typeText) {
            if (typeText.compare(QStringLiteral("Exe"), Qt::CaseInsensitive) == 0) return QStringLiteral("EXE");
            if (typeText.compare(QStringLiteral("Dll"), Qt::CaseInsensitive) == 0) return QStringLiteral("DLL");
            if (typeText.compare(QStringLiteral("Msi"), Qt::CaseInsensitive) == 0) return QStringLiteral("MSI");
            if (typeText.compare(QStringLiteral("Script"), Qt::CaseInsensitive) == 0) return QStringLiteral("Script");
            if (typeText.compare(QStringLiteral("Appx"), Qt::CaseInsensitive) == 0 || typeText.contains(QStringLiteral("Packaged"), Qt::CaseInsensitive))
            {
                return QStringLiteral("Packaged app");
            }
            return typeText.isEmpty() ? QStringLiteral("Unknown") : typeText;
        };

        const auto conditionTypeFromSummary = [](const QString& summaryText) {
            const QString lower = summaryText.toLower();
            if (lower.contains(QStringLiteral("publisher"))) return QStringLiteral("Publisher");
            if (lower.contains(QStringLiteral("path"))) return QStringLiteral("Path");
            if (lower.contains(QStringLiteral("hash"))) return QStringLiteral("Hash");
            return QStringLiteral("Unknown");
        };

        while (!reader.atEnd())
        {
            reader.readNext();
            if (!reader.isStartElement())
            {
                continue;
            }

            if (reader.name().toString().compare(QStringLiteral("RuleCollection"), Qt::CaseInsensitive) != 0)
            {
                reader.skipCurrentElement();
                continue;
            }

            ++collectionCount;
            const QString collectionTypeText = collectionToText(reader.attributes().value(QStringLiteral("Type")).toString());
            int collectionRuleCount = 0;

            auto parseRuleElement = [&](const QString& ruleElementName) {
                AppLockerRuleRecord record;
                record.collectionText = collectionTypeText;
                const QXmlStreamAttributes attributes = reader.attributes();
                record.idText = attributes.value(QStringLiteral("Id")).toString();
                record.actionText = attributes.value(QStringLiteral("Action")).toString();
                record.sidText = attributes.value(QStringLiteral("UserOrGroupSid")).toString();
                record.userText = sidToFriendlyText(record.sidText);
                record.descriptionText = attributes.value(QStringLiteral("Description")).toString();
                if (record.descriptionText.trimmed().isEmpty())
                {
                    record.descriptionText = attributes.value(QStringLiteral("Name")).toString();
                }
                if (record.actionText.trimmed().isEmpty())
                {
                    record.actionText = QStringLiteral("—");
                }
                if (record.sidText.trimmed().isEmpty())
                {
                    record.sidText = QStringLiteral("—");
                }
                if (record.userText.trimmed().isEmpty())
                {
                    record.userText = QStringLiteral("—");
                }
                if (record.descriptionText.trimmed().isEmpty())
                {
                    record.descriptionText = QStringLiteral("—");
                }

                QStringList conditionSummaries;
                while (reader.readNextStartElement())
                {
                    const QString childName = reader.name().toString();
                    if (childName.compare(QStringLiteral("Conditions"), Qt::CaseInsensitive) == 0)
                    {
                        while (reader.readNextStartElement())
                        {
                            conditionSummaries.push_back(collectElementSummary(reader));
                        }
                    }
                    else
                    {
                        conditionSummaries.push_back(collectElementSummary(reader));
                    }
                }

                if (!conditionSummaries.isEmpty())
                {
                    record.conditionText = collapseSpaces(conditionSummaries.join(QStringLiteral(" ; ")));
                    record.conditionTypeText = conditionTypeFromSummary(conditionSummaries.front());
                }
                else
                {
                    record.conditionTypeText = QStringLiteral("Unknown");
                    record.conditionText = QStringLiteral("—");
                }

                record.riskText = buildAppLockerRiskText(
                    record.actionText,
                    record.sidText,
                    record.conditionTypeText,
                    record.conditionText);
                records.push_back(record);
                ++collectionRuleCount;
                Q_UNUSED(ruleElementName);
            };

            while (reader.readNextStartElement())
            {
                const QString childName = reader.name().toString();
                if (childName.endsWith(QStringLiteral("Rule"), Qt::CaseInsensitive))
                {
                    parseRuleElement(childName);
                }
                else
                {
                    reader.skipCurrentElement();
                }
            }

            summaryParts.push_back(QStringLiteral("%1: %2 条规则").arg(collectionTypeText).arg(collectionRuleCount));
        }

        if (reader.hasError())
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("AppLocker XML 解析失败：%1").arg(reader.errorString())) };
        }

        if (records.isEmpty())
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("AppLocker: 未配置")) };
        }

        ks::ui::FieldDocument summaryText;
        summaryText.field(QStringLiteral("AppLocker 规则集共"), QStringLiteral("AppLocker 规则集共 %1 个，规则共 %2 条。").arg(QStringLiteral("%1").arg(collectionCount)).arg(QStringLiteral("%1").arg(records.size())));
        if (!summaryParts.isEmpty())
        {

            for (const auto& part : summaryParts) summaryText.note(part);
        }
        return { records, summaryText };
    }

    std::pair<QVector<ApplicationControlPage::EventRecord>, ks::ui::FieldDocument> ApplicationControlPage::parseEventsJson(
        const QString& jsonText)
    {
        QVector<EventRecord> records;
        const QString trimmedText = jsonText.trimmed();
        if (trimmedText.isEmpty())
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("未获取到 Code Integrity 事件。")) };
        }

        QJsonParseError parseError{};
        const QJsonDocument document = QJsonDocument::fromJson(trimmedText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError)
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("事件 JSON 解析失败：%1").arg(parseError.errorString())) };
        }

        QJsonArray array;
        if (document.isArray())
        {
            array = document.array();
        }
        else if (document.isObject())
        {
            array.push_back(document.object());
        }

        int allowCount = 0;
        int blockCount = 0;
        int auditCount = 0;

        for (const QJsonValue& value : array)
        {
            const QJsonObject object = value.toObject();
            EventRecord record;
            QString timeText = jsonValueToText(object.value(QStringLiteral("TimeText")));
            if (timeText.isEmpty())
            {
                timeText = jsonValueToText(object.value(QStringLiteral("TimeCreated")));
            }
            record.timeText = collapseSpaces(timeText);

            record.idText = jsonValueToText(object.value(QStringLiteral("IdText")));
            if (record.idText.isEmpty())
            {
                record.idText = jsonValueToText(object.value(QStringLiteral("Id")));
            }

            record.levelText = jsonValueToText(object.value(QStringLiteral("LevelText")));
            if (record.levelText.isEmpty())
            {
                record.levelText = jsonValueToText(object.value(QStringLiteral("LevelDisplayName")));
            }

            record.messageText = jsonValueToText(object.value(QStringLiteral("MessageText")));
            if (record.messageText.isEmpty())
            {
                record.messageText = jsonValueToText(object.value(QStringLiteral("Message")));
            }
            record.messageText = collapseSpaces(record.messageText);
            {
                QStringList errorParts;
                const QString errorText = jsonValueToText(object.value(QStringLiteral("ErrorText"))).trimmed();
                const QString errorCategory = jsonValueToText(object.value(QStringLiteral("ErrorCategory"))).trimmed();
                const QString errorType = jsonValueToText(object.value(QStringLiteral("ErrorType"))).trimmed();
                const QString hresultText = jsonValueToText(object.value(QStringLiteral("HResult"))).trimmed();
                if (!errorText.isEmpty()) errorParts << QStringLiteral("ErrorId=%1").arg(errorText);
                if (!errorCategory.isEmpty()) errorParts << QStringLiteral("Category=%1").arg(errorCategory);
                if (!errorType.isEmpty()) errorParts << QStringLiteral("Type=%1").arg(errorType);
                if (!hresultText.isEmpty()) errorParts << QStringLiteral("HResult=%1").arg(hresultText);
                if (!errorParts.isEmpty())
                {
                    record.messageText = QStringLiteral("%1 | %2")
                        .arg(record.messageText)
                        .arg(errorParts.join(QStringLiteral(" | "))).trimmed();
                }
            }

            record.verdictText = jsonValueToText(object.value(QStringLiteral("VerdictText")));
            if (record.verdictText.isEmpty())
            {
                record.verdictText = jsonValueToText(object.value(QStringLiteral("Verdict")));
            }
            if (record.verdictText.trimmed().isEmpty())
            {
                record.verdictText = classifyCodeIntegrityVerdict(record.messageText, record.levelText);
            }

            if (record.verdictText == QStringLiteral("允许")) ++allowCount;
            else if (record.verdictText == QStringLiteral("阻止")) ++blockCount;
            else if (record.verdictText == QStringLiteral("审计")) ++auditCount;

            if (record.messageText.isEmpty())
            {
                record.messageText = QStringLiteral("—");
            }
            if (record.idText.isEmpty())
            {
                record.idText = QStringLiteral("—");
            }
            if (record.levelText.isEmpty())
            {
                record.levelText = QStringLiteral("—");
            }
            if (record.timeText.isEmpty())
            {
                record.timeText = QStringLiteral("—");
            }
            records.push_back(record);
        }

        if (records.size() == 1)
        {
            const EventRecord& onlyRecord = records.front();
            if (onlyRecord.timeText == QStringLiteral("—")
                && onlyRecord.idText == QStringLiteral("—")
                && onlyRecord.messageText.contains(QStringLiteral("error"), Qt::CaseInsensitive))
            {
                return { records, ks::ui::FieldDocument{}.note(QStringLiteral("Code Integrity 事件读取失败：%1").arg(onlyRecord.messageText)) };
            }
        }

        ks::ui::FieldDocument summaryText;
        summaryText.field(QStringLiteral("最近"), QStringLiteral("最近 %1 条事件：允许 %2，阻止 %3，审计 %4。").arg(QStringLiteral("%1").arg(records.size())).arg(QStringLiteral("%1").arg(allowCount)).arg(QStringLiteral("%1").arg(blockCount)).arg(QStringLiteral("%1").arg(auditCount)));
        return { records, summaryText };
    }

    std::pair<QVector<ApplicationControlPage::KeyValueRecord>, ks::ui::FieldDocument> ApplicationControlPage::parseDefenderJson(
        const QString& jsonText)
    {
        QVector<KeyValueRecord> records;
        const QString trimmedText = jsonText.trimmed();
        if (trimmedText.isEmpty())
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("未获取到 Defender 数据。")) };
        }

        QJsonParseError parseError{};
        const QJsonDocument document = QJsonDocument::fromJson(trimmedText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError)
        {
            return { records, ks::ui::FieldDocument{}.note(QStringLiteral("Defender JSON 解析失败：%1").arg(parseError.errorString())) };
        }

        QJsonArray array;
        if (document.isArray())
        {
            array = document.array();
        }
        else if (document.isObject())
        {
            const QJsonObject rootObject = document.object();
            if (rootObject.value(QStringLiteral("Rows")).isArray())
            {
                array = rootObject.value(QStringLiteral("Rows")).toArray();
            }
            else
            {
                array.push_back(rootObject);
            }
        }

        for (const QJsonValue& value : array)
        {
            const QJsonObject object = value.toObject();
            KeyValueRecord record;
            record.nameText = jsonValueToText(object.value(QStringLiteral("Name")));
            record.valueText = jsonValueToText(object.value(QStringLiteral("Value")));
            record.detailText = jsonValueToText(object.value(QStringLiteral("Detail")));
            if (record.nameText.isEmpty())
            {
                record.nameText = jsonValueToText(object.value(QStringLiteral("Key")));
            }
            if (record.valueText.isEmpty())
            {
                record.valueText = QStringLiteral("—");
            }
            if (record.detailText.isEmpty())
            {
                record.detailText = QStringLiteral("—");
            }
            records.push_back(record);
        }

        QStringList queryFailureSummaries;
        for (const KeyValueRecord& record : records)
        {
            const bool isDefenderFailure = record.nameText.contains(QStringLiteral("Defender"), Qt::CaseInsensitive)
                && (record.valueText.contains(QStringLiteral("Failed"), Qt::CaseInsensitive)
                    || record.valueText.contains(QStringLiteral("Unavailable"), Qt::CaseInsensitive));
            if (!isDefenderFailure)
            {
                continue;
            }

            const QString detailText = record.detailText.trimmed();
            if (detailText.contains(QStringLiteral("0x800106BA"), Qt::CaseInsensitive))
            {
                queryFailureSummaries.push_back(
                    QStringLiteral("%1：HRESULT 0x800106BA，Microsoft Defender Antivirus Service (WinDefend) 未启动、已禁用或已由其他安全产品接管。")
                        .arg(record.nameText));
            }
            else
            {
                queryFailureSummaries.push_back(
                    QStringLiteral("%1：%2")
                        .arg(record.nameText, detailText.isEmpty() ? QStringLiteral("未返回错误代码。") : detailText));
            }
        }
        if (!queryFailureSummaries.isEmpty())
        {
            ks::ui::FieldDocument diagnostics;
            for (const auto& failure : queryFailureSummaries) diagnostics.note(failure);
            return { records, diagnostics };
        }

        ks::ui::FieldDocument summaryText;
        summaryText.field(QStringLiteral("Defender 状态共"), QStringLiteral("Defender 状态共 %1 条。").arg(QStringLiteral("%1").arg(records.size())));
        return { records, summaryText };
    }

    void ApplicationControlPage::refreshAsync()
    {
        if (m_refreshButton != nullptr)
        {
            m_refreshButton->setEnabled(false);
        }
        if (m_exportButton != nullptr)
        {
            m_exportButton->setEnabled(false);
        }
        if (m_appLockerEditButton != nullptr)
        {
            m_appLockerEditButton->setEnabled(false);
        }
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("状态: 正在刷新…"));
        }
        if (m_appLockerSummary != nullptr) m_appLockerSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("正在采集 AppLocker…")));
        if (m_wdacSummary != nullptr) m_wdacSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("正在采集 WDAC / Code Integrity…")));
        if (m_defenderSummary != nullptr) m_defenderSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("正在采集 Defender…")));
        if (m_platformSummary != nullptr) m_platformSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("正在采集平台安全…")));
        m_eventSummaryDocument = ks::ui::FieldDocument{}.note(QStringLiteral("正在采集 Code Integrity 事件…"));
        if (m_eventSummary != nullptr) m_eventSummary->setDocument(m_eventSummaryDocument);

        const std::uint64_t refreshGeneration = ++m_refreshGeneration;
        const int requestedEventLimit = selectedEventLimit();
        const QPointer<ApplicationControlPage> guardThis(this);
        std::thread([guardThis, requestedEventLimit, refreshGeneration]() {
            QVector<AppLockerRuleRecord> appLockerRules;
            QVector<PolicyFileRecord> policyFiles;
            QVector<EventRecord> events;
            QVector<KeyValueRecord> defenderRows;
            QVector<KeyValueRecord> platformRows;
            bool appLockerModuleAvailable = true;
            ks::ui::FieldDocument appLockerSummary;
            appLockerSummary.field(QStringLiteral("AppLocker"), QStringLiteral("未配置"), true);
            ks::ui::FieldDocument wdacSummary;
            wdacSummary.field(QStringLiteral("WDAC / Code Integrity"), QStringLiteral("未发现常见策略文件。"), true);
            ks::ui::FieldDocument defenderSummary;
            defenderSummary.field(QStringLiteral("Defender"), QStringLiteral("未获取到状态。"), true);
            ks::ui::FieldDocument platformSummary;
            platformSummary.field(QStringLiteral("平台安全"), QStringLiteral("未获取到状态。"), true);
            ks::ui::FieldDocument eventSummary;
            eventSummary.note(QStringLiteral("未获取到 Code Integrity 事件。"));
            QString statusText = QStringLiteral("刷新完成");

            // appendPlatformRow：
            // - 输入：平台安全表格的一行名称、值和说明；
            // - 处理：追加到后台线程本地 platformRows 缓存；
            // - 返回：无返回值，最终由 UI 线程统一刷新表格。
            const auto appendPlatformRow = [&platformRows, &platformSummary](
                const QString& nameText,
                const QString& valueText,
                const QString& detailText) {
                KeyValueRecord record;
                record.nameText = nameText;
                record.valueText = valueText;
                record.detailText = detailText;
                platformRows.push_back(record);
                platformSummary.field(nameText, valueText);
                if (!detailText.isEmpty()) platformSummary.note(detailText);
            };

            // 1) WDAC / Code Integrity 文件扫描由 C++ 直接完成，避免额外脚本依赖。
            const QFileInfo sipolicyFile(QStringLiteral("C:/Windows/System32/CodeIntegrity/SIPolicy.p7b"));
            const QFileInfo activeDir(QStringLiteral("C:/Windows/System32/CodeIntegrity/CiPolicies/Active"));
            const auto appendPolicyFile = [&policyFiles](const QString& pathText, const QFileInfo& fileInfo, const QString& detailText, const QString& countText) {
                PolicyFileRecord record;
                record.pathText = pathText;
                record.existsText = fileInfo.exists() ? QStringLiteral("Yes") : QStringLiteral("No");
                record.sizeText = fileInfo.exists() ? sizeTextFromBytes(fileInfo.size()) : QStringLiteral("—");
                record.modifiedText = fileInfo.exists() ? dateTimeText(fileInfo.lastModified()) : QStringLiteral("—");
                record.countText = countText;
                record.detailText = detailText;
                policyFiles.push_back(record);
            };

            appendPolicyFile(
                QStringLiteral("C:\\Windows\\System32\\CodeIntegrity\\SIPolicy.p7b"),
                sipolicyFile,
                QStringLiteral("主 SIPolicy 文件"),
                sipolicyFile.exists() ? QStringLiteral("1") : QStringLiteral("0"));

            int activeCount = 0;
            if (activeDir.exists())
            {
                const QFileInfoList activeFiles = QDir(activeDir.absoluteFilePath()).entryInfoList(
                    QStringList{ QStringLiteral("*.cip") },
                    QDir::Files | QDir::Readable,
                    QDir::Name);
                activeCount = activeFiles.size();
                for (const QFileInfo& fileInfo : activeFiles)
                {
                    appendPolicyFile(
                        fileInfo.absoluteFilePath(),
                        fileInfo,
                        QStringLiteral("Active 目录下的 CIP 策略"),
                        QStringLiteral("1"));
                }
            }
            else
            {
                appendPolicyFile(
                    QStringLiteral("C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip"),
                    QFileInfo(),
                    QStringLiteral("Active 目录不存在"),
                    QStringLiteral("0"));
            }

            const int policyFileCount = (sipolicyFile.exists() ? 1 : 0) + activeCount;
            wdacSummary = {};
            wdacSummary.field(QStringLiteral("WDAC / Code Integrity 常见策略文件数"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(policyFileCount)));
            wdacSummary.field(QStringLiteral("- SIPolicy.p7b"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(sipolicyFile.exists() ? QStringLiteral("存在") : QStringLiteral("未找到"))));
            wdacSummary.field(QStringLiteral("- Active/*.cip"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(activeCount)));

            // 2) AppLocker：先探测模块。Windows 家庭版等不提供该模块时，不把能力缺失误报为权限或服务故障。
            const QString appLockerScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "$module=Get-Module -ListAvailable -Name AppLocker | Select-Object -First 1;"
                "if($null -eq $module){Write-Output '__APPLOCKER_MODULE_UNAVAILABLE__';exit 0};"
                "try {"
                "  Import-Module -Name $module.Path -ErrorAction Stop;"
                "  $xml=[string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop);"
                "  if([string]::IsNullOrWhiteSpace($xml)){Write-Output '__NO_POLICY__'; exit 0};"
                "  Write-Output '__OK__';"
                "  Write-Output $xml;"
                "} catch {"
                "  $msg=$_.Exception.Message;"
                "  if($msg -match 'No AppLocker policy|not configured|未配置'){Write-Output '__NO_POLICY__'}"
                "  else { Write-Output '__ERROR__'; Write-Output $msg }"
                "}");
            QString appLockerErrorText;
            const QString appLockerOutput = runPowerShellCaptureText(appLockerScript, 15000, &appLockerErrorText);
            QString appLockerXmlText;
            if (appLockerOutput.startsWith(QStringLiteral("__OK__")))
            {
                appLockerXmlText = appLockerOutput.section(QChar::LineFeed, 1);
            }
            else if (appLockerOutput.contains(QStringLiteral("__APPLOCKER_MODULE_UNAVAILABLE__")))
            {
                appLockerModuleAvailable = false;
                appLockerSummary = {};
                appLockerSummary.note(QStringLiteral("AppLocker 模块不可用。"));
                appLockerSummary.note(QStringLiteral("当前 Windows 未提供 AppLocker PowerShell 管理组件，无法读取、创建或修改 AppLocker 策略。"));
                appLockerSummary.note(QStringLiteral("Windows 家庭版通常不支持 AppLocker。"));
                appLockerSummary.note(QStringLiteral("WDAC、Defender、平台安全、事件日志和文件诊断仍可使用。"));
            }
            else if (appLockerOutput.contains(QStringLiteral("__NO_POLICY__")))
            {
                appLockerSummary = {};
                appLockerSummary.field(QStringLiteral("AppLocker"), QStringLiteral("未配置"), true);
            }
            else
            {
                const QString parseHint = appLockerErrorText.isEmpty() ? appLockerOutput : appLockerErrorText;
                appLockerSummary = {};
                appLockerSummary.note(QStringLiteral("AppLocker 读取失败。"));
                appLockerSummary.field(QStringLiteral("建议"), QStringLiteral("以管理员身份运行，并确认 Application Identity (AppIDSvc) 服务可用。"), true);
                appLockerSummary.note(QStringLiteral("%1").arg(QStringLiteral("%1").arg(parseHint.isEmpty() ? QStringLiteral("未返回额外错误信息。") : parseHint)));
            }

            if (!appLockerXmlText.trimmed().isEmpty())
            {
                const auto parsedAppLocker = parseAppLockerPolicyXml(appLockerXmlText);
                appLockerRules = parsedAppLocker.first;
                if (!parsedAppLocker.second.isEmpty())
                {
                    appLockerSummary = parsedAppLocker.second;
                }
                if (appLockerRules.isEmpty())
                {
                    appLockerSummary = {};
                    appLockerSummary.field(QStringLiteral("AppLocker"), QStringLiteral("未配置"), true);
                }
            }

            // 3) Defender / ASR 通过 PowerShell 输出为 JSON 数组，便于 UI 直读。
            const QString defenderScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "function Get-DefenderErrorDetail($errorRecord){"
                "  $parts=@();$exception=$errorRecord.Exception;"
                "  while($null -ne $exception){"
                "    $parts+=('ErrorType='+$exception.GetType().FullName);"
                "    if($exception.HResult -ne 0){$parts+=('HRESULT=0x{0:X8}' -f ($exception.HResult -band 0xFFFFFFFF))};"
                "    foreach($propertyName in @('NativeErrorCode','ErrorCode','StatusCode')){"
                "      $property=$exception.PSObject.Properties[$propertyName];"
                "      if($null -ne $property -and $null -ne $property.Value){$parts+=($propertyName+'='+$property.Value)}"
                "    };"
                "    $exception=$exception.InnerException"
                "  };"
                "  foreach($match in [regex]::Matches([string]$errorRecord.Exception.Message,'(?i)0x[0-9a-f]{8}')){$parts+=('UnderlyingHRESULT='+$match.Value.ToUpper())};"
                "  if(-not [string]::IsNullOrWhiteSpace($errorRecord.FullyQualifiedErrorId)){$parts+=('FullyQualifiedErrorId='+$errorRecord.FullyQualifiedErrorId)};"
                "  if($null -ne $errorRecord.CategoryInfo){$parts+=('Category='+$errorRecord.CategoryInfo.Category)};"
                "  ($parts | Select-Object -Unique) -join ' | '"
                "};"
                "$rows=@();$pref=$null;"
                "try {"
                "  $pref=Get-MpPreference -ErrorAction Stop;"
                "  $rows += [pscustomobject]@{Name='Controlled Folder Access'; Value=($pref.EnableControlledFolderAccess); Detail='0=Off,1=Block,2=Audit'};"
                "  $rows += [pscustomobject]@{Name='PUA Protection'; Value=($pref.PUAProtection); Detail='0=Disabled,1=Enabled,2=Audit'};"
                "  $rows += [pscustomobject]@{Name='Network Protection'; Value=($pref.EnableNetworkProtection); Detail='0=Disabled,1=Block,2=Audit'};"
                "  $asrIds=$pref.AttackSurfaceReductionRules_Ids;$asrActions=$pref.AttackSurfaceReductionRules_Actions;"
                "  $count=[Math]::Min(@($asrIds).Count,@($asrActions).Count);"
                "  for($i=0; $i -lt $count; $i++){ $rows += [pscustomobject]@{Name=('ASR '+$asrIds[$i]); Value=($asrActions[$i]); Detail='AttackSurfaceReduction rule'} }"
                "} catch { $rows += [pscustomobject]@{Name='Defender preferences'; Value='Unavailable'; Detail=(Get-DefenderErrorDetail $_)} };"
                "try {"
                "  $status=Get-MpComputerStatus -ErrorAction Stop;"
                "  if($status.PSObject.Properties['SmartScreenEnabled']) { $rows += [pscustomobject]@{Name='SmartScreen'; Value=($status.SmartScreenEnabled); Detail='Available from Get-MpComputerStatus'} };"
                "  $rows += [pscustomobject]@{Name='Real Time Protection'; Value=($status.RealTimeProtectionEnabled); Detail='Get-MpComputerStatus'};"
                "  $rows += [pscustomobject]@{Name='Tamper Protection'; Value=($status.IsTamperProtected); Detail='Get-MpComputerStatus'}"
                "} catch {"
                "  $detail=Get-DefenderErrorDetail $_;"
                "  if($detail -match '(?i)0x800106ba'){$detail='HRESULT=0x800106BA | WinDefend service is not active | '+$detail};"
                "  $rows += [pscustomobject]@{Name='Defender service status'; Value='Unavailable'; Detail=$detail}"
                "};"
                "$rows | ConvertTo-Json -Depth 4");
            QString defenderErrorText;
            const QString defenderJsonText = runPowerShellCaptureText(defenderScript, 15000, &defenderErrorText);
            if (!defenderJsonText.trimmed().isEmpty())
            {
                const auto parsedDefender = parseDefenderJson(defenderJsonText);
                defenderRows = parsedDefender.first;
                defenderSummary = parsedDefender.second;
                if (!defenderErrorText.trimmed().isEmpty())
                {
                    defenderSummary.note(QStringLiteral("%1").arg(QStringLiteral("%1").arg(defenderErrorText)));
                }
            }
            else if (!defenderErrorText.trimmed().isEmpty())
            {
                defenderSummary = {};
                defenderSummary.field(QStringLiteral("Defender 模块不可用或读取失败"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(defenderErrorText)));
            }

            // 4) 平台安全 / CI / VBS / Hyper-V / Driver Trust / BAM 全部只读采集。
            const QString platformScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "try {"
                "  $rows=@();"
                "  $dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop;"
                "  $rows += [pscustomobject]@{Name='CI SecurityServicesConfigured'; Value=([string]::Join(',', @($dg.SecurityServicesConfigured))); Detail='DeviceGuard'};"
                "  $rows += [pscustomobject]@{Name='CI SecurityServicesRunning'; Value=([string]::Join(',', @($dg.SecurityServicesRunning))); Detail='DeviceGuard'};"
                "  $rows += [pscustomobject]@{Name='VirtualizationBasedSecurityStatus'; Value=$dg.VirtualizationBasedSecurityStatus; Detail='0=Off,1=Enabled,2=Running'};"
                "  $rows += [pscustomobject]@{Name='RequiresPlatformSecurityFeatures'; Value=$dg.RequiredSecurityProperties; Detail='DeviceGuard'};"
                "  $rows += [pscustomobject]@{Name='Hyper-V Service'; Value=((Get-Service vmms -ErrorAction SilentlyContinue).Status); Detail='Virtual Machine Management Service'};"
                "  $rows += [pscustomobject]@{Name='VMBus Service'; Value=((Get-Service vmbus -ErrorAction SilentlyContinue).Status); Detail='Virtual Machine Bus'};"
                "  $rows += [pscustomobject]@{Name='vSwitch Service'; Value=((Get-Service vswitch -ErrorAction SilentlyContinue).Status); Detail='Hyper-V Virtual Switch'};"
                "  $rows += [pscustomobject]@{Name='vPCI Service'; Value=((Get-Service vpci -ErrorAction SilentlyContinue).Status); Detail='Virtual PCI'};"
                "  $rows += [pscustomobject]@{Name='HvSocket Service'; Value=((Get-Service hvsocket -ErrorAction SilentlyContinue).Status); Detail='Hyper-V Socket'};"
                "  $bam=@(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\*' -ErrorAction SilentlyContinue | Measure-Object).Count;"
                "  $rows += [pscustomobject]@{Name='BAM Keys'; Value=$bam; Detail='HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'};"
                "  $ah=@(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\amcache' -ErrorAction SilentlyContinue | Measure-Object).Count;"
                "  $rows += [pscustomobject]@{Name='ahcache Keys'; Value=$ah; Detail='HKLM\\SYSTEM\\CurrentControlSet\\Services\\amcache'};"
                "  $rows | ConvertTo-Json -Depth 4"
                "} catch {"
                "  [pscustomobject]@{Name='Platform query'; Value='Failed'; Detail=$_.Exception.Message} | ConvertTo-Json -Depth 3"
                "}");
            QString platformErrorText;
            const QString platformJsonText = runPowerShellCaptureText(platformScript, 15000, &platformErrorText);
            if (!platformJsonText.trimmed().isEmpty())
            {
                const auto parsedPlatform = parseDefenderJson(platformJsonText);
                platformRows = parsedPlatform.first;
                platformSummary = parsedPlatform.second;
                if (!platformErrorText.trimmed().isEmpty())
                {
                    platformSummary.note(QStringLiteral("%1").arg(QStringLiteral("%1").arg(platformErrorText)));
                }
            }
            else if (!platformErrorText.trimmed().isEmpty())
            {
                platformSummary = {};
                platformSummary.field(QStringLiteral("平台安全读取失败"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(platformErrorText)));
            }


            // 5) R0 安全态势审计通过 ArkDriverClient wrapper 查询，只追加摘要行，不替换 WMI/PowerShell baseline。
            try
            {
                const ksword::ark::DriverClient arkClient;
                const ksword::ark::SecurityStatusAuditResult securityStatus = arkClient.querySecurityStatus();
                const ksword::ark::DriverTrustViewAuditResult driverTrust = arkClient.queryDriverTrustView();
                const ksword::ark::HyperVSummaryAuditResult hyperVSummary = arkClient.queryHyperVSummary();
                const ksword::ark::AppControlStatusAuditResult appControlStatus = arkClient.queryAppControlStatus();

                const auto& securityResponse = securityStatus.response;
                appendPlatformRow(
                    QStringLiteral("R0 Security / CI"),
                    QStringLiteral("CI=%1, UMCI=%2, Options=%3")
                        .arg(boolFlagText(securityResponse.ciEnabled))
                        .arg(boolFlagText(securityResponse.umciEnabled))
                        .arg(hexMaskText(securityResponse.codeIntegrityOptions)),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, query=%3, ciStatus=%4, io=%5")
                        .arg(hexMaskText(securityResponse.fieldFlags))
                        .arg(hexMaskText(securityResponse.sourceMask))
                        .arg(ntStatusText(securityResponse.queryStatus))
                        .arg(ntStatusText(securityResponse.codeIntegrityStatus))
                        .arg(ioSummaryText(securityStatus.io)));

                appendPlatformRow(
                    QStringLiteral("R0 Security / VBS-HVCI-SKCI"),
                    QStringLiteral("VBS=%1, HVCI=%2, SKCI=%3")
                        .arg(boolFlagText(securityResponse.vbsPresent))
                        .arg(boolFlagText(securityResponse.hvciKmciEnabled))
                        .arg(boolFlagText(securityResponse.skciModuleLoaded)),
                    QStringLiteral("secureKernel=%1, hvciAudit=%2, hvciStrict=%3, hvciIum=%4, moduleStatus=%5")
                        .arg(boolFlagText(securityResponse.secureKernelModuleLoaded))
                        .arg(boolFlagText(securityResponse.hvciAuditMode))
                        .arg(boolFlagText(securityResponse.hvciStrictMode))
                        .arg(boolFlagText(securityResponse.hvciIumEnabled))
                        .arg(ntStatusText(securityResponse.moduleQueryStatus)));

                appendPlatformRow(
                    QStringLiteral("R0 Security / Test signing"),
                    QStringLiteral("testSigning=%1, testBuild=%2")
                        .arg(boolFlagText(securityResponse.testSigningEnabled))
                        .arg(boolFlagText(securityResponse.testBuild)),
                    QStringLiteral("flightBuild=%1, flighting=%2, secureBoot=%3, secureBootCapable=%4, secureBootStatus=%5")
                        .arg(boolFlagText(securityResponse.flightBuild))
                        .arg(boolFlagText(securityResponse.flightingEnabled))
                        .arg(boolFlagText(securityResponse.secureBootEnabled))
                        .arg(boolFlagText(securityResponse.secureBootCapable))
                        .arg(ntStatusText(securityResponse.secureBootStatus)));

                appendPlatformRow(
                    QStringLiteral("R0 Security / Debug posture"),
                    QStringLiteral("kdEnabled=%1, kdNotPresent=%2, ciDebug=%3")
                        .arg(boolFlagText(securityResponse.kernelDebuggerEnabled))
                        .arg(boolFlagText(securityResponse.kernelDebuggerNotPresent))
                        .arg(boolFlagText(securityResponse.ciDebugModeEnabled)),
                    QStringLiteral("debuggerStatus=%1, ciModuleLoaded=%2, io=%3")
                        .arg(ntStatusText(securityResponse.debuggerStatus))
                        .arg(boolFlagText(securityResponse.ciModuleLoaded))
                        .arg(r0IoMessageText(securityStatus.io.message)));

                const auto& hyperVResponse = hyperVSummary.response;
                appendPlatformRow(
                    QStringLiteral("R0 Hyper-V / Present"),
                    QStringLiteral("present=%1, vendor=%2")
                        .arg(boolFlagText(hyperVResponse.hypervisorPresent))
                        .arg(fixedWideText(hyperVResponse.hypervisorVendor, KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS)),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, query=%3, root=%4, io=%5")
                        .arg(hexMaskText(hyperVResponse.fieldFlags))
                        .arg(hexMaskText(hyperVResponse.sourceMask))
                        .arg(ntStatusText(hyperVResponse.queryStatus))
                        .arg(auditStateText(hyperVResponse.rootPartitionStatus))
                        .arg(ioSummaryText(hyperVSummary.io)));

                appendPlatformRow(
                    QStringLiteral("R0 Hyper-V / Modules"),
                    QStringLiteral("vmbus=%1, vswitch=%2, vpci=%3, hvsocket=%4")
                        .arg(auditStateText(hyperVResponse.vmbusStatus))
                        .arg(auditStateText(hyperVResponse.vSwitchStatus))
                        .arg(auditStateText(hyperVResponse.vPciStatus))
                        .arg(auditStateText(hyperVResponse.hvSocketStatus)),
                    QStringLiteral("winhv=%1, winhvruntime=%2, hvloader=%3, moduleStatus=%4")
                        .arg(auditStateText(hyperVResponse.winHvStatus))
                        .arg(auditStateText(hyperVResponse.winHvRuntimeStatus))
                        .arg(auditStateText(hyperVResponse.hvLoaderStatus))
                        .arg(ntStatusText(hyperVResponse.moduleQueryStatus)));

                const auto& appControlResponse = appControlStatus.response;
                appendPlatformRow(
                    QStringLiteral("R0 AppControl / Summary"),
                    QStringLiteral("AppID=%1, policy=%2, AppLocker=%3")
                        .arg(auditStateText(appControlResponse.appidStatus))
                        .arg(auditStateText(appControlResponse.appidPolicyStatus))
                        .arg(auditStateText(appControlResponse.appLockerFilterStatus)),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, query=%3, moduleStatus=%4, io=%5")
                        .arg(hexMaskText(appControlResponse.fieldFlags))
                        .arg(hexMaskText(appControlResponse.sourceMask))
                        .arg(ntStatusText(appControlResponse.queryStatus))
                        .arg(ntStatusText(appControlResponse.moduleQueryStatus))
                        .arg(ioSummaryText(appControlStatus.io)));

                appendPlatformRow(
                    QStringLiteral("R0 AppControl / Filters"),
                    QStringLiteral("mssecflt=%1, BAM=%2, ahcache=%3")
                        .arg(auditStateText(appControlResponse.mssecfltStatus))
                        .arg(auditStateText(appControlResponse.bamStatus))
                        .arg(auditStateText(appControlResponse.ahcacheStatus)),
                    QStringLiteral("AppLockerOwner=%1, AppLockerOwnerStatus=%2, mssecfltOwner=%3, mssecfltOwnerStatus=%4")
                        .arg(fixedWideText(appControlResponse.appLockerOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS))
                        .arg(auditStateText(appControlResponse.appLockerCallbackOwnerStatus))
                        .arg(fixedWideText(appControlResponse.mssecfltOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS))
                        .arg(auditStateText(appControlResponse.mssecfltCallbackOwnerStatus)));

                appendPlatformRow(
                    QStringLiteral("R0 DriverTrust / Counts"),
                    QStringLiteral("returned=%1, total=%2, truncated=%3")
                        .arg(driverTrust.returnedCount)
                        .arg(driverTrust.totalCount)
                        .arg(driverTrust.truncated),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, maxAccepted=%3, moduleStatus=%4, signingStatus=%5")
                        .arg(hexMaskText(driverTrust.fieldFlags))
                        .arg(hexMaskText(driverTrust.sourceMask))
                        .arg(driverTrust.maxEntriesAccepted)
                        .arg(ntStatusText(driverTrust.moduleQueryStatus))
                        .arg(ntStatusText(driverTrust.signingResolverStatus)));

                appendPlatformRow(
                    QStringLiteral("R0 DriverTrust / IO"),
                    r0IoMessageText(driverTrust.io.message),
                    ioSummaryText(driverTrust.io));

                platformSummary.section(QStringLiteral("R0 安全态势"));
                platformSummary.field(QStringLiteral("SecurityStatus"), securityStatus.io.ok ? QStringLiteral("OK") : QStringLiteral("Fail"));
                platformSummary.field(QStringLiteral("SecurityStatus NTSTATUS"), ntStatusText(securityStatus.io.ntStatus));
                platformSummary.field(QStringLiteral("DriverTrust returned"), QString::number(driverTrust.returnedCount));
                platformSummary.field(QStringLiteral("DriverTrust total"), QString::number(driverTrust.totalCount));
                platformSummary.field(QStringLiteral("DriverTrust truncated"), QString::number(driverTrust.truncated));
                platformSummary.field(QStringLiteral("HyperV present"), boolFlagText(hyperVResponse.hypervisorPresent));
                platformSummary.field(QStringLiteral("HyperV vendor"), fixedWideText(hyperVResponse.hypervisorVendor, KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS));
                platformSummary.field(QStringLiteral("HyperV flags"), hexMaskText(hyperVResponse.fieldFlags));
                platformSummary.field(QStringLiteral("AppControl AppID"), auditStateText(appControlResponse.appidStatus));
                platformSummary.field(QStringLiteral("AppControl AppLocker"), auditStateText(appControlResponse.appLockerFilterStatus));
                platformSummary.field(QStringLiteral("AppControl mssecflt"), auditStateText(appControlResponse.mssecfltStatus));
                platformSummary.field(QStringLiteral("AppControl BAM"), auditStateText(appControlResponse.bamStatus));
            }
            catch (const std::exception& exception)
            {
                appendPlatformRow(
                    QStringLiteral("内核安全审计"),
                    QStringLiteral("Exception"),
                    QString::fromLocal8Bit(exception.what()));
                platformSummary.field(QStringLiteral("R0 安全态势读取异常"), QString::fromLocal8Bit(exception.what()));
            }
            catch (...)
            {
                appendPlatformRow(
                    QStringLiteral("内核安全审计"),
                    QStringLiteral("Exception"),
                    QStringLiteral("未知异常"));
                platformSummary.field(QStringLiteral("R0 安全态势读取异常"), QStringLiteral("未知异常"), true);
            }

            // 5) Code Integrity 事件同样通过 PowerShell 输出为 JSON 数组。
            const QString eventScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "try {"
                "  $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'} -MaxEvents %1 -ErrorAction Stop;"
                "  $events | ForEach-Object {"
                "    $message = $_.Message;"
                "    $level = $_.LevelDisplayName;"
                "    $lower = if($message){ $message.ToLower() } else { '' };"
                "    $verdict = if($lower -match 'audit|审计|would have been blocked'){ '审计' } elseif($lower -match 'block|deny|阻止|not allowed'){ '阻止' } elseif($lower -match 'allow|loaded|允许'){ '允许' } else { '事件' };"
                "    [pscustomobject]@{TimeText=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); IdText=$_.Id; LevelText=$level; VerdictText=$verdict; MessageText=$message}"
                "  } | ConvertTo-Json -Depth 4"
                "} catch {"
                "  [pscustomobject]@{TimeText=''; IdText=''; LevelText=''; VerdictText='读取失败'; MessageText=$_.Exception.Message; ErrorText=$_.FullyQualifiedErrorId; ErrorCategory=$_.CategoryInfo.Category; ErrorType=$_.Exception.GetType().FullName; HResult=('0x{0:X8}' -f ($_.Exception.HResult -band 0xFFFFFFFF))} | ConvertTo-Json -Depth 3"
                "}").arg(requestedEventLimit);
            QString eventErrorText;
            const QString eventJsonText = runPowerShellCaptureText(eventScript, 15000, &eventErrorText);
            if (!eventJsonText.trimmed().isEmpty())
            {
                const auto parsedEvents = parseEventsJson(eventJsonText);
                events = parsedEvents.first;
                eventSummary = parsedEvents.second;
                if (!eventErrorText.trimmed().isEmpty())
                {
                    eventSummary.note(QStringLiteral("%1").arg(QStringLiteral("%1").arg(eventErrorText)));
                }
            }
            else if (!eventErrorText.trimmed().isEmpty())
            {
                eventSummary = {};
                eventSummary.field(QStringLiteral("Code Integrity 事件读取失败"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(eventErrorText)));
            }

            if (appLockerSummary.isEmpty())
            {
                appLockerSummary = {};
                appLockerSummary.field(QStringLiteral("AppLocker"), QStringLiteral("未配置"), true);
            }

            if (guardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(qApp, [guardThis,
                                             refreshGeneration,
                                             statusText,
                                             appLockerSummary,
                                              wdacSummary,
                                              defenderSummary,
                                              platformSummary,
                                              eventSummary,
                                              appLockerModuleAvailable,
                                              appLockerRules = std::move(appLockerRules),
                                              policyFiles = std::move(policyFiles),
                                              events = std::move(events),
                                              defenderRows = std::move(defenderRows),
                                              platformRows = std::move(platformRows)]() mutable {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->applyRefreshResult(
                    refreshGeneration,
                    statusText,
                    appLockerSummary,
                    wdacSummary,
                    defenderSummary,
                    platformSummary,
                    eventSummary,
                    appLockerModuleAvailable,
                    std::move(appLockerRules),
                    std::move(policyFiles),
                    std::move(events),
                    std::move(defenderRows),
                    std::move(platformRows));
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::applyRefreshResult(
        const std::uint64_t refreshGeneration,
        QString statusText,
        ks::ui::FieldDocument appLockerSummary,
        ks::ui::FieldDocument wdacSummary,
        ks::ui::FieldDocument defenderSummary,
        ks::ui::FieldDocument platformSummary,
        ks::ui::FieldDocument eventSummary,
        bool appLockerModuleAvailable,
        QVector<AppLockerRuleRecord> appLockerRules,
        QVector<PolicyFileRecord> policyFiles,
        QVector<EventRecord> events,
        QVector<KeyValueRecord> defenderRows,
        QVector<KeyValueRecord> platformRows)
    {
        // 只允许最后发起的任务写回；该检查也覆盖右键菜单延迟后再次进入的提交。
        if (refreshGeneration != m_refreshGeneration)
        {
            return;
        }

        const QList<QTableView*> applicationControlTables = {
            m_appLockerTable,
            m_policyFileTable,
            m_codeIntegrityEventTable,
            m_defenderTable,
            m_platformTable,
            m_eventTable
        };
        if (ks::ui::IsTableUiCommitBlockedByContextMenu(applicationControlTables))
        {
            const QPointer<ApplicationControlPage> safeThis(this);
            ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("application-control-refresh-apply"),
                applicationControlTables,
                [safeThis,
                    refreshGeneration,
                    statusText = std::move(statusText),
                    appLockerSummary = std::move(appLockerSummary),
                    wdacSummary = std::move(wdacSummary),
                    defenderSummary = std::move(defenderSummary),
                    platformSummary = std::move(platformSummary),
                    eventSummary = std::move(eventSummary),
                    appLockerModuleAvailable,
                    appLockerRules = std::move(appLockerRules),
                    policyFiles = std::move(policyFiles),
                    events = std::move(events),
                    defenderRows = std::move(defenderRows),
                    platformRows = std::move(platformRows)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRefreshResult(
                            refreshGeneration,
                            std::move(statusText),
                            std::move(appLockerSummary),
                            std::move(wdacSummary),
                            std::move(defenderSummary),
                            std::move(platformSummary),
                            std::move(eventSummary),
                            appLockerModuleAvailable,
                            std::move(appLockerRules),
                            std::move(policyFiles),
                            std::move(events),
                            std::move(defenderRows),
                            std::move(platformRows));
                    }
                });
            return;
        }

        m_appLockerRules = std::move(appLockerRules);
        m_appLockerModuleAvailable = appLockerModuleAvailable;

        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("状态: %1").arg(statusText));
        }

        if (m_appLockerSummary != nullptr)
        {
            m_appLockerSummary->setDocument(appLockerSummary);
        }
        if (m_appLockerEditButton != nullptr)
        {
            m_appLockerEditButton->setEnabled(m_appLockerModuleAvailable && m_pendingMutationCount == 0);
        }
        if (m_wdacSummary != nullptr)
        {
            m_wdacSummary->setDocument(wdacSummary);
        }
        if (m_defenderSummary != nullptr)
        {
            m_defenderSummary->setDocument(defenderSummary);
        }
        if (m_platformSummary != nullptr)
        {
            m_platformSummary->setDocument(platformSummary);
        }
        if (m_eventSummary != nullptr)
        {
            m_eventSummaryDocument = eventSummary;
            m_eventSummary->setDocument(eventSummary);
        }

        QVector<QStringList> appLockerRows;
        QVector<QVariant> appLockerRuleIds;
        appLockerRows.reserve(m_appLockerRules.size());
        appLockerRuleIds.reserve(m_appLockerRules.size());
        for (const AppLockerRuleRecord& record : m_appLockerRules)
        {
            appLockerRows.push_back(QStringList{
                record.collectionText,
                record.actionText,
                record.userText,
                record.sidText,
                record.conditionTypeText,
                record.conditionText,
                record.descriptionText,
                record.riskText
            });
            appLockerRuleIds.push_back(record.idText);
        }
        fillTable(
            m_appLockerTable,
            QStringList{
                QStringLiteral("规则集合"),
                QStringLiteral("Action"),
                QStringLiteral("User"),
                QStringLiteral("SID"),
                QStringLiteral("条件类型"),
                QStringLiteral("路径 / 发布者 / Hash"),
                QStringLiteral("描述"),
                QStringLiteral("风险")
            },
            appLockerRows,
            appLockerRuleIds);

        QVector<QStringList> policyRows;
        policyRows.reserve(policyFiles.size());
        for (const PolicyFileRecord& record : policyFiles)
        {
            policyRows.push_back(QStringList{
                record.pathText,
                record.existsText,
                record.sizeText,
                record.modifiedText,
                record.countText,
                record.detailText
            });
        }
        fillTable(
            m_policyFileTable,
            QStringList{
                QStringLiteral("文件路径"),
                QStringLiteral("存在"),
                QStringLiteral("大小"),
                QStringLiteral("修改时间"),
                QStringLiteral("策略数量"),
                QStringLiteral("说明")
            },
            policyRows);

        m_eventRows = std::move(events);

        QVector<QStringList> eventRows;
        eventRows.reserve(m_eventRows.size());
        for (const EventRecord& record : m_eventRows)
        {
            eventRows.push_back(QStringList{
                record.timeText,
                record.idText,
                record.levelText,
                record.verdictText,
                record.messageText
            });
        }
        fillTable(
            m_codeIntegrityEventTable,
            QStringList{
                QStringLiteral("时间"),
                QStringLiteral("事件 ID"),
                QStringLiteral("级别"),
                QStringLiteral("判定"),
                QStringLiteral("消息")
            },
            eventRows);
        rebuildEventTable();

        QVector<QStringList> defenderRowsTable;
        defenderRowsTable.reserve(defenderRows.size());
        for (const KeyValueRecord& record : defenderRows)
        {
            defenderRowsTable.push_back(QStringList{
                record.nameText,
                record.valueText,
                record.detailText
            });
        }
        fillTable(
            m_defenderTable,
            QStringList{
                QStringLiteral("字段"),
                QStringLiteral("值"),
                QStringLiteral("说明")
            },
            defenderRowsTable);

        QVector<QStringList> platformRowsTable;
        platformRowsTable.reserve(platformRows.size());
        for (const KeyValueRecord& record : platformRows)
        {
            platformRowsTable.push_back(QStringList{
                record.nameText,
                record.valueText,
                record.detailText
            });
        }
        fillTable(
            m_platformTable,
            QStringList{
                QStringLiteral("字段"),
                QStringLiteral("值"),
                QStringLiteral("说明")
            },
            platformRowsTable);

        if (m_refreshButton != nullptr)
        {
            m_refreshButton->setEnabled(true);
        }
        if (m_exportButton != nullptr)
        {
            m_exportButton->setEnabled(true);
        }
    }

    int ApplicationControlPage::selectedEventLimit() const
    {
        const QString text = m_eventLimitCombo != nullptr
            ? m_eventLimitCombo->currentText()
            : QStringLiteral("最近 200 条");
        const QRegularExpression numberPattern(QStringLiteral("(\\d+)"));
        const QRegularExpressionMatch match = numberPattern.match(text);
        if (!match.hasMatch())
        {
            return 200;
        }
        return std::clamp(match.captured(1).toInt(), 50, 2000);
    }

    void ApplicationControlPage::rebuildEventTable()
    {
        const QPointer<ApplicationControlPage> safeThis(this);
        if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("application-control-event-filter-rebuild"),
            {m_eventTable},
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->rebuildEventTable();
                }
            }))
        {
            return;
        }

        const QString selectedVerdictText = m_eventVerdictFilterCombo != nullptr
            ? m_eventVerdictFilterCombo->currentText()
            : QStringLiteral("全部分类");

        QVector<QStringList> visibleRows;
        visibleRows.reserve(m_eventRows.size());
        for (const EventRecord& record : m_eventRows)
        {
            const bool matched =
                selectedVerdictText == QStringLiteral("全部分类") ||
                record.verdictText.compare(selectedVerdictText, Qt::CaseInsensitive) == 0;
            if (!matched)
            {
                continue;
            }

            visibleRows.push_back(QStringList{
                record.timeText,
                record.idText,
                record.levelText,
                record.verdictText,
                record.messageText
            });
        }

        fillTable(
            m_eventTable,
            QStringList{
                QStringLiteral("时间"),
                QStringLiteral("事件 ID"),
                QStringLiteral("级别"),
                QStringLiteral("判定"),
                QStringLiteral("消息")
            },
            visibleRows);

        if (m_eventSummary != nullptr)
        {
            auto baseSummary = m_eventSummaryDocument;
            if (selectedVerdictText == QStringLiteral("全部分类"))
            {
                m_eventSummary->setDocument(baseSummary);
            }
            else
            {
                baseSummary.field(QStringLiteral("筛选"), selectedVerdictText);
                baseSummary.field(QStringLiteral("显示 / 总数"), QStringLiteral("%1 / %2").arg(visibleRows.size()).arg(m_eventRows.size()));
                m_eventSummary->setDocument(baseSummary);
            }
        }
    }

    QString ApplicationControlPage::buildPathMatchHint(
        const QString& filePathText,
        const QVector<AppLockerRuleRecord>& appLockerRules)
    {
        if (appLockerRules.isEmpty())
        {
            return QStringLiteral("当前没有 AppLocker 规则缓存，无法判断路径命中。");
        }

        QString sanitizedPathText = filePathText.trimmed();
        sanitizedPathText.remove(QChar('"'));
        const QFileInfo fileInfo(sanitizedPathText);
        const QString normalizedPath = QDir::toNativeSeparators(fileInfo.exists() ? fileInfo.absoluteFilePath() : sanitizedPathText);
        QStringList matches;

        for (const AppLockerRuleRecord& record : appLockerRules)
        {
            if (!record.conditionTypeText.contains(QStringLiteral("Path"), Qt::CaseInsensitive))
            {
                continue;
            }

            QString conditionText = record.conditionText;
            const QRegularExpression pathExtractor(QStringLiteral("Path=([^;|]+)"), QRegularExpression::CaseInsensitiveOption);
            const QRegularExpressionMatch match = pathExtractor.match(conditionText);
            if (match.hasMatch())
            {
                conditionText = match.captured(1).trimmed();
            }

            conditionText = expandCommonEnvironmentTokens(conditionText);
            const QRegularExpression regex = pathLikeTextToRegex(conditionText);
            const bool matched = regex.isValid()
                ? regex.match(normalizedPath).hasMatch()
                : normalizedPath.compare(conditionText, Qt::CaseInsensitive) == 0;
            if (!matched)
            {
                continue;
            }

            matches.push_back(QStringLiteral("%1 | %2 | %3 | %4")
                .arg(record.collectionText, record.actionText, record.userText, conditionText));
        }

        if (matches.isEmpty())
        {
            return QStringLiteral("未发现明显的 AppLocker 路径规则命中。");
        }

        return QStringLiteral("可能命中 %1 条 AppLocker 路径规则：\n%2")
            .arg(matches.size())
            .arg(matches.join(QStringLiteral("\n")));
    }

    void ApplicationControlPage::runFileDiagnosisAsync()
    {
        QString filePath = m_filePathEdit != nullptr ? m_filePathEdit->text().trimmed() : QString();
        filePath.remove(QChar('"'));
        if (filePath.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("文件诊断"), QStringLiteral("请输入文件路径。"));
            return;
        }

        if (m_fileDiagnoseButton != nullptr)
        {
            m_fileDiagnoseButton->setEnabled(false);
        }
        if (m_fileDiagnosisSummary != nullptr)
        {
            m_fileDiagnosisSummary->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("正在诊断：%1").arg(filePath)));
        }

        // 在 UI 线程取得隐式共享快照，后台线程不再读取 QWidget 所属缓存。
        QVector<AppLockerRuleRecord> appLockerRulesSnapshot = m_appLockerRules;
        const QPointer<ApplicationControlPage> guardThis(this);
        std::thread([guardThis,
                     filePath,
                     appLockerRulesSnapshot = std::move(appLockerRulesSnapshot)]() {
            QVector<KeyValueRecord> rows;
            ks::ui::FieldDocument summaryText;

            const QFileInfo fileInfo(filePath);
            const bool exists = fileInfo.exists() && fileInfo.isFile();
            const QString normalizedPath = QDir::toNativeSeparators(fileInfo.exists() ? fileInfo.absoluteFilePath() : filePath);
            const QString suffixText = fileInfo.suffix().toLower();
            const QString publisherText = exists
                ? QString::fromStdString(ks::startup::QueryPublisherTextByPath(filePath.toStdString()))
                : QString();
            const QString pathMatchHint = ApplicationControlPage::buildPathMatchHint(
                filePath,
                appLockerRulesSnapshot);

            const auto pushRow = [&rows](const QString& nameText, const QString& valueText, const QString& detailText) {
                KeyValueRecord record;
                record.nameText = nameText;
                record.valueText = valueText;
                record.detailText = detailText;
                rows.push_back(record);
            };

            pushRow(QStringLiteral("文件存在"), exists ? QStringLiteral("Yes") : QStringLiteral("No"), normalizedPath);
            pushRow(QStringLiteral("文件类型"), suffixText.isEmpty() ? QStringLiteral("—") : suffixText.toUpper(), QStringLiteral("输入文件扩展名"));

            if (exists)
            {
                QFile file(fileInfo.absoluteFilePath());
                if (file.open(QIODevice::ReadOnly))
                {
                    QCryptographicHash sha256(QCryptographicHash::Sha256);
                    while (!file.atEnd())
                    {
                        const QByteArray chunk = file.read(1024 * 1024);
                        if (!chunk.isEmpty())
                        {
                            sha256.addData(chunk);
                        }
                    }
                    pushRow(QStringLiteral("SHA256"), QString::fromLatin1(sha256.result().toHex()), QStringLiteral("QCryptographicHash"));
                }
                else
                {
                    pushRow(QStringLiteral("SHA256"), QStringLiteral("读取失败"), file.errorString());
                }
            }
            else
            {
                pushRow(QStringLiteral("SHA256"), QStringLiteral("—"), QStringLiteral("文件不存在"));
            }

            pushRow(
                QStringLiteral("签名/发布者"),
                publisherText.isEmpty() ? QStringLiteral("未获取到") : publisherText,
                QStringLiteral("复用 ks::startup::QueryPublisherTextByPath / WinVerifyTrust"));

            pushRow(
                QStringLiteral("AppLocker 路径命中"),
                pathMatchHint,
                QStringLiteral("只读推测，不修改策略"));

            pushRow(
                QStringLiteral("WDAC 提示"),
                QStringLiteral("若系统存在 WDAC / Code Integrity 策略，请结合事件日志判断最终结果。"),
                QStringLiteral("第一版仅做存在性和事件诊断"));

            QString testAppLockerText;
            if (exists)
            {
                QString escapedFilePath = filePath;
                escapedFilePath.replace(QStringLiteral("'"), QStringLiteral("''"));
                const QString testScript = appLockerPowerShellPrelude() + QStringLiteral(
                    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                    "try {"
                    "  $path='%1';"
                    "  $result = Test-AppLockerPolicy -Path $path -ErrorAction Stop;"
                    "  if($null -eq $result){ Write-Output '__NO_RESULT__' } else { $result | Out-String -Width 65535 }"
                    "} catch {"
                    "  Write-Output '__ERROR__';"
                    "  Write-Output $_.Exception.Message"
                    "}")
                    .arg(escapedFilePath);
                QString testErrorText;
                testAppLockerText = runPowerShellCaptureText(testScript, 12000, &testErrorText);
                if (!testAppLockerText.trimmed().isEmpty())
                {
                    pushRow(QStringLiteral("Test-AppLockerPolicy"), collapseSpaces(testAppLockerText), QStringLiteral("PowerShell 结构化测试"));
                }
                else if (!testErrorText.trimmed().isEmpty())
                {
                    pushRow(QStringLiteral("Test-AppLockerPolicy"), QStringLiteral("不可用"), testErrorText);
                }
            }

            summaryText = {};
            summaryText.field(QStringLiteral("文件"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(normalizedPath)));
            summaryText.field(QStringLiteral("存在"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(exists ? QStringLiteral("Yes") : QStringLiteral("No"))));
            summaryText.field(QStringLiteral("发布者"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(publisherText.isEmpty() ? QStringLiteral("未获取到") : publisherText)));
            summaryText.field(QStringLiteral("路径命中"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(pathMatchHint)));

            if (guardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(qApp, [guardThis, summaryText, rows = std::move(rows)]() mutable {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->applyFileDiagnosisResult(summaryText, std::move(rows));
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::applyFileDiagnosisResult(ks::ui::FieldDocument summaryText, QVector<KeyValueRecord> rows)
    {
        if (ks::ui::IsTableUiCommitBlockedByContextMenu({m_fileDiagnosisTable}))
        {
            const QPointer<ApplicationControlPage> safeThis(this);
            ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("application-control-file-diagnosis-apply"),
                {m_fileDiagnosisTable},
                [safeThis,
                    summaryText = std::move(summaryText),
                    rows = std::move(rows)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyFileDiagnosisResult(
                            std::move(summaryText),
                            std::move(rows));
                    }
                });
            return;
        }

        if (m_fileDiagnosisSummary != nullptr)
        {
            m_fileDiagnosisSummary->setDocument(summaryText);
        }

        QVector<QStringList> tableRows;
        tableRows.reserve(rows.size());
        for (const KeyValueRecord& record : rows)
        {
            tableRows.push_back(QStringList{ record.nameText, record.valueText, record.detailText });
        }
        fillTable(
            m_fileDiagnosisTable,
            QStringList{ QStringLiteral("检查项"), QStringLiteral("结果"), QStringLiteral("说明") },
            tableRows);

        if (m_fileDiagnoseButton != nullptr)
        {
            m_fileDiagnoseButton->setEnabled(true);
        }
    }
}
