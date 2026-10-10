#include "VirusTotalOnlineScan.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ThemeBinding.h"

#include "OnlineScanSupport.h"
#include "../Framework.h"
#include "../SettingsDock/AppearanceSettings.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHttpMultiPart>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QMenu>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScrollArea>
#include <QSizePolicy>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextBrowser>
#include <QThreadPool>
#include <QTabWidget>
#include <QTimer>
#include <QTimeZone>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <vector>

namespace
{
    // VirusTotal API 常量：集中维护官方 v3 端点，避免散落在业务逻辑中。
    constexpr const char* kVirusTotalFilesEndpoint = "https://www.virustotal.com/api/v3/files";
    constexpr const char* kVirusTotalFilesEndpointPrefix = "https://www.virustotal.com/api/v3/files/";
    constexpr const char* kVirusTotalLargeUploadUrlEndpoint = "https://www.virustotal.com/api/v3/files/upload_url";
    constexpr const char* kVirusTotalAnalysisEndpointPrefix = "https://www.virustotal.com/api/v3/analyses/";
    constexpr const char* kVirusTotalFileBehaviourEndpointPrefix = "https://www.virustotal.com/api/v3/file_behaviours/";
    constexpr int kInitialPollDelayMs = 15000;
    constexpr int kPollIntervalMs = 15000;
    constexpr int kMaxPollAttempts = 40;
    constexpr int kMaxRateLimitRetryAttempts = 2;
    constexpr int kDefaultRateLimitRetryDelayMs = 60000;
    constexpr int kMaxRateLimitRetryDelayMs = 300000;

    // setVirusTotalHeaders 作用：
    // - 给 VirusTotal 请求统一添加 API Key 和 User-Agent；
    // - Content-Type 由 QHttpMultiPart 或 Qt 自动处理，不在此处设置。
    // 入参 request：待修改的请求对象。
    // 入参 apiKey：用户配置的 API Key。
    // 返回：无。
    void setVirusTotalHeaders(QNetworkRequest* request, const QString& apiKey)
    {
        if (request == nullptr)
        {
            return;
        }
        request->setRawHeader("x-apikey", apiKey.toUtf8());
        request->setRawHeader("User-Agent", "Ksword5.1-OnlineScan/1.0");
    }

    // replyHttpStatusCode 作用：
    // - 从 Qt 网络响应中读取 HTTP 状态码；
    // - 统一处理属性缺失场景，避免每个 VT API handler 重复样板代码。
    // 入参 reply：已完成的 QNetworkReply，可为空。
    // 返回：HTTP 状态码；未知时返回 0。
    int replyHttpStatusCode(QNetworkReply* reply)
    {
        if (reply == nullptr)
        {
            return 0;
        }
        const QVariant statusCodeVariant = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        return statusCodeVariant.isValid() ? statusCodeVariant.toInt() : 0;
    }

    // replyRetryAfterText 作用：
    // - 读取 VirusTotal/API 网关可能返回的 Retry-After 响应头；
    // - 用于 429 限流时给 UI 和导出 JSON 写入可执行等待信息。
    // 入参 reply：已完成的 QNetworkReply，可为空。
    // 返回：Retry-After 原始文本；没有该头时为空字符串。
    QString replyRetryAfterText(QNetworkReply* reply)
    {
        if (reply == nullptr || !reply->hasRawHeader("Retry-After"))
        {
            return QString();
        }
        return QString::fromLatin1(reply->rawHeader("Retry-After")).trimmed();
    }

    // rateLimitRetryDelayMs 作用：
    // - 将 VirusTotal Retry-After 头转换成毫秒；
    // - Public API 常见返回秒数，无法解析时使用保守默认等待时间；
    // - 设置最大等待上限，避免 UI 长时间看似卡死。
    // 入参 reply：已完成的 429 响应，可为空。
    // 返回：用于 QTimer 的等待毫秒数。
    int rateLimitRetryDelayMs(QNetworkReply* reply)
    {
        const QString retryAfterText = replyRetryAfterText(reply);
        bool numberOk = false;
        const int retryAfterSeconds = retryAfterText.toInt(&numberOk);
        if (numberOk && retryAfterSeconds > 0)
        {
            return std::clamp(
                retryAfterSeconds * 1000,
                1000,
                kMaxRateLimitRetryDelayMs);
        }
        return kDefaultRateLimitRetryDelayMs;
    }

    // formatWaitSecondsText 作用：
    // - 把毫秒等待时间压缩成 UI 状态文本；
    // - 返回至少 1 秒，避免显示“0 秒后重试”。
    // 入参 delayMs：等待毫秒数。
    // 返回：中文秒数文本。
    QString formatWaitSecondsText(const int delayMs)
    {
        return QStringLiteral("%1 秒").arg(std::max(1, (delayMs + 999) / 1000));
    }

    // replyHttpMetadataObject 作用：
    // - 把 HTTP 层状态、Reason-Phrase 和 Retry-After 归档为结构化 JSON；
    // - 每次 VT API 响应都会随原始数据一起导出，便于排查限流/认证/404 等问题。
    // 入参 reply：已完成的 QNetworkReply，可为空。
    // 返回：包含 http_status/http_reason/retry_after 的对象；无法读取时字段尽量省略。
    QJsonObject replyHttpMetadataObject(QNetworkReply* reply)
    {
        QJsonObject metadataObject;
        const int statusCode = replyHttpStatusCode(reply);
        if (statusCode > 0)
        {
            metadataObject.insert(QStringLiteral("http_status"), statusCode);
        }

        if (reply != nullptr)
        {
            const QVariant reasonVariant = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
            const QString reasonText = reasonVariant.isValid()
                ? reasonVariant.toString().trimmed()
                : QString();
            if (!reasonText.isEmpty())
            {
                metadataObject.insert(QStringLiteral("http_reason"), reasonText);
            }

            const QString retryAfterText = replyRetryAfterText(reply);
            if (!retryAfterText.isEmpty())
            {
                metadataObject.insert(QStringLiteral("retry_after"), retryAfterText);
            }
        }
        return metadataObject;
    }

    // virusTotalErrorObjectFromBody 作用：
    // - 从 VirusTotal v3 错误响应体中提取 error 对象；
    // - 只读取 JSON 对象，不修改原始响应体，便于后续导出仍保持 VT 原始结构。
    // 入参 bodyBytes：QNetworkReply::readAll 读取到的完整响应体。
    // 返回：error 对象；响应体不是 JSON 或没有 error 字段时返回空对象。
    QJsonObject virusTotalErrorObjectFromBody(const QByteArray& bodyBytes)
    {
        if (bodyBytes.isEmpty())
        {
            return QJsonObject();
        }

        QJsonParseError parseError;
        const QJsonDocument jsonDocument = QJsonDocument::fromJson(bodyBytes, &parseError);
        if (parseError.error != QJsonParseError::NoError || !jsonDocument.isObject())
        {
            return QJsonObject();
        }
        return jsonDocument.object().value(QStringLiteral("error")).toObject();
    }

    // virusTotalResponseMetadataObject 作用：
    // - 在 HTTP 元数据基础上补充 VirusTotal error.code/message；
    // - 报告页、响应详情和导出 JSON 都能直接看到认证/权限/配额类别。
    // 入参 reply/bodyBytes：已完成的网络响应和完整响应体。
    // 返回：包含 HTTP 字段和可选 vt_error 字段的对象。
    QJsonObject virusTotalResponseMetadataObject(QNetworkReply* reply, const QByteArray& bodyBytes)
    {
        QJsonObject metadataObject = replyHttpMetadataObject(reply);
        const QJsonObject errorObject = virusTotalErrorObjectFromBody(bodyBytes);
        if (!errorObject.isEmpty())
        {
            metadataObject.insert(QStringLiteral("vt_error"), errorObject);
            const QString errorCode = errorObject.value(QStringLiteral("code")).toString().trimmed();
            if (!errorCode.isEmpty())
            {
                metadataObject.insert(QStringLiteral("vt_error_code"), errorCode);
            }
        }
        return metadataObject;
    }

    // maskedApiKeyText 作用：
    // - 生成 API Key 的安全诊断文本，只暴露长度和首尾少量字符；
    // - 绝不返回完整 Key，避免日志、截图或导出文件泄露密钥。
    // 入参 apiKey：当前运行时读取到的 VirusTotal API Key。
    // 返回：例如“长度=64，掩码=abcd...1234”；空值返回“空”。
    QString maskedApiKeyText(const QString& apiKey)
    {
        const QString trimmedKey = apiKey.trimmed();
        if (trimmedKey.isEmpty())
        {
            return QStringLiteral("空");
        }
        if (trimmedKey.size() <= 8)
        {
            return QStringLiteral("长度=%1，掩码=<过短，已隐藏>").arg(trimmedKey.size());
        }
        return QStringLiteral("长度=%1，掩码=%2...%3")
            .arg(trimmedKey.size())
            .arg(trimmedKey.left(4), trimmedKey.right(4));
    }

    // virusTotalErrorDiagnosisText 作用：
    // - 把 VirusTotal 常见错误码翻译成可执行排查建议；
    // - 重点区分“Key 错误”“权限/套餐不足”和“Public API 配额限制”。
    // 入参 statusCode：HTTP 状态码。
    // 入参 vtErrorCode：VT error.code，如 WrongCredentialsError。
    // 返回：面向 UI 的中文诊断；无法判断时返回空字符串。
    QString virusTotalErrorDiagnosisText(const int statusCode, const QString& vtErrorCode)
    {
        const QString normalizedCode = vtErrorCode.trimmed();
        if (normalizedCode == QStringLiteral("WrongCredentialsError"))
        {
            return QStringLiteral("诊断：VirusTotal 判定当前 x-apikey 无效。这通常不是免费版权限不足，而是 Key 输错、复制了旧 Key、账号/Key 被撤销，或程序读取到了错误配置文件。");
        }
        if (normalizedCode == QStringLiteral("AuthenticationRequiredError") || statusCode == 401)
        {
            return QStringLiteral("诊断：请求未通过 VirusTotal 认证。请确认设置中已保存 VT v3 API Key，并确认程序实际读取的是同一个配置文件。");
        }
        if (normalizedCode == QStringLiteral("ForbiddenError") || statusCode == 403)
        {
            return QStringLiteral("诊断：认证已到达服务端，但当前 Key 没有访问该端点的权限。Public/免费 Key 对部分 IOC、沙箱或高级行为接口可能不可用。");
        }
        if (normalizedCode == QStringLiteral("QuotaExceededError") ||
            normalizedCode == QStringLiteral("TooManyRequestsError") ||
            statusCode == 429)
        {
            return QStringLiteral("诊断：VirusTotal 配额或频率限制。Public API 常见限制较低，连续触发多个 API 时需要等待后重试。");
        }
        if (normalizedCode == QStringLiteral("NotFoundError") || statusCode == 404)
        {
            return QStringLiteral("诊断：VT 暂无该 hash/对象的数据，或该关系端点没有可返回结果。");
        }
        return QString();
    }

    // shouldAppendAuthDiagnostics 作用：
    // - 判断当前 VT 错误是否需要展示 Key 掩码和设置路径；
    // - NotFoundError/404 只是“暂无数据”，不应混入认证诊断，避免误导为 Key 错。
    // 入参 statusCode/vtErrorCode：HTTP 状态码与 VT error.code。
    // 返回：true=追加认证/配额诊断；false=不追加。
    bool shouldAppendAuthDiagnostics(const int statusCode, const QString& vtErrorCode)
    {
        const QString normalizedCode = vtErrorCode.trimmed();
        return statusCode == 401 ||
            statusCode == 403 ||
            statusCode == 429 ||
            normalizedCode == QStringLiteral("WrongCredentialsError") ||
            normalizedCode == QStringLiteral("AuthenticationRequiredError") ||
            normalizedCode == QStringLiteral("ForbiddenError") ||
            normalizedCode == QStringLiteral("QuotaExceededError") ||
            normalizedCode == QStringLiteral("TooManyRequestsError");
    }

    // virusTotalAuthDiagnosticsText 作用：
    // - 生成不泄露完整 Key 的认证上下文；
    // - 用于 401/403/429 以及 VT 错误响应，帮助定位到底读了哪个 settings JSON。
    // 入参 apiKey/settingsJsonPath：运行时读取到的密钥和设置文件路径。
    // 返回：多行诊断文本。
    QString virusTotalAuthDiagnosticsText(const QString& apiKey, const QString& settingsJsonPath)
    {
        QStringList lines;
        lines << QStringLiteral("认证诊断：");
        lines << QStringLiteral("- 请求头：x-apikey");
        lines << QStringLiteral("- 当前 Key：%1").arg(maskedApiKeyText(apiKey));
        lines << QStringLiteral("- 设置读取路径：%1").arg(QDir::toNativeSeparators(settingsJsonPath));
        return lines.join(QChar('\n'));
    }

    // virusTotalNetworkErrorText 作用：
    // - 包装通用网络错误文本；
    // - 区分 Key 错误、权限不足和 Public API 频率限制，避免用户把 401/403/429 混为一类。
    // 入参 reply/bodyBytes：失败响应和完整响应体。
    // 入参 apiKey/settingsJsonPath：用于安全诊断，不输出完整 Key。
    // 返回：适合 UI 展示、原始数据页归档的错误详情。
    QString virusTotalNetworkErrorText(
        QNetworkReply* reply,
        const QByteArray& bodyBytes,
        const QString& apiKey,
        const QString& settingsJsonPath)
    {
        QString errorText = ks::online_scan::networkReplyErrorText(reply, bodyBytes);
        const int statusCode = replyHttpStatusCode(reply);
        const QJsonObject vtErrorObject = virusTotalErrorObjectFromBody(bodyBytes);
        const QString vtErrorCode = vtErrorObject.value(QStringLiteral("code")).toString().trimmed();
        const QString vtErrorMessage = vtErrorObject.value(QStringLiteral("message")).toString().trimmed();
        if (!vtErrorCode.isEmpty())
        {
            errorText += QStringLiteral("\nVirusTotal 错误码：%1").arg(vtErrorCode);
        }
        if (!vtErrorMessage.isEmpty())
        {
            errorText += QStringLiteral("\nVirusTotal 错误消息：%1").arg(vtErrorMessage);
        }

        const QString diagnosisText = virusTotalErrorDiagnosisText(statusCode, vtErrorCode);
        if (!diagnosisText.isEmpty())
        {
            errorText += QLatin1Char('\n') + diagnosisText;
        }

        if (shouldAppendAuthDiagnostics(statusCode, vtErrorCode))
        {
            errorText += QLatin1Char('\n') + virusTotalAuthDiagnosticsText(apiKey, settingsJsonPath);
        }

        if (statusCode == 429)
        {
            const QString retryAfterText = replyRetryAfterText(reply);
            errorText += QStringLiteral("\nVirusTotal 返回 429：请求被限流。");
            if (!retryAfterText.isEmpty())
            {
                errorText += QStringLiteral("\nRetry-After：%1").arg(retryAfterText);
            }
            else
            {
                errorText += QStringLiteral("\nRetry-After：响应头未提供。");
            }
        }
        return errorText;
    }

    // endpointTextFromTitle 作用：
    // - 从响应章节标题中提取稳定 endpoint 字段；
    // - 导出 JSON 需要独立 endpoint，不应要求后续脚本从中文标题里再解析。
    // 入参 titleText：如“GET /api/v3/files/{sha256} 文件画像”。
    // 返回：如“GET /api/v3/files/{sha256}”；无法识别时返回原标题。
    QString endpointTextFromTitle(const QString& titleText)
    {
        const QString trimmedTitle = titleText.trimmed();
        static const QRegularExpression endpointExpression(QStringLiteral("^(GET|POST|PUT|PATCH|DELETE|HEAD)\\s+([^\\s]+)"));
        const QRegularExpressionMatch endpointMatch = endpointExpression.match(trimmedTitle);
        if (endpointMatch.hasMatch())
        {
            return endpointMatch.captured(1) + QLatin1Char(' ') + endpointMatch.captured(2);
        }
        return trimmedTitle;
    }

    // apiIndex 作用：
    // - 将 VtApiKind 映射到数组下标；
    // - AllApis 不是实际 Pane，归并到普通分析下标，避免越界。
    // 入参 apiKind：API 类型。
    // 返回：0..3 的 Pane 下标。
    int apiIndex(const VirusTotalOnlineScan::VtApiKind apiKind)
    {
        switch (apiKind)
        {
        case VirusTotalOnlineScan::VtApiKind::FileProfile:
            return 1;
        case VirusTotalOnlineScan::VtApiKind::Ioc:
            return 2;
        case VirusTotalOnlineScan::VtApiKind::Sandbox:
            return 3;
        case VirusTotalOnlineScan::VtApiKind::ShallowAnalysis:
        case VirusTotalOnlineScan::VtApiKind::AllApis:
        default:
            return 0;
        }
    }

    // paneApiKinds 作用：
    // - 统一返回真实一级 Tab 顺序；
    // - UI 创建、导出和清理状态均使用该顺序。
    // 返回：固定 4 个 Pane API。
    std::array<VirusTotalOnlineScan::VtApiKind, 4> paneApiKinds()
    {
        return {
            VirusTotalOnlineScan::VtApiKind::ShallowAnalysis,
            VirusTotalOnlineScan::VtApiKind::FileProfile,
            VirusTotalOnlineScan::VtApiKind::Ioc,
            VirusTotalOnlineScan::VtApiKind::Sandbox,
        };
    }

    // apiTitleText 作用：
    // - 返回一级 Tab 和按钮使用的人类可读名称。
    // 入参 apiKind：API 类型。
    // 返回：中文名称。
    QString apiTitleText(const VirusTotalOnlineScan::VtApiKind apiKind)
    {
        switch (apiKind)
        {
        case VirusTotalOnlineScan::VtApiKind::FileProfile:
            return QStringLiteral("文件画像");
        case VirusTotalOnlineScan::VtApiKind::Ioc:
            return QStringLiteral("IOC");
        case VirusTotalOnlineScan::VtApiKind::Sandbox:
            return QStringLiteral("沙箱");
        case VirusTotalOnlineScan::VtApiKind::AllApis:
            return QStringLiteral("全部API");
        case VirusTotalOnlineScan::VtApiKind::ShallowAnalysis:
        default:
            return QStringLiteral("普通分析");
        }
    }

    // apiExportKey 作用：
    // - 返回导出 JSON 中稳定的 API key；
    // - 便于后续脚本按固定 key 读取。
    // 入参 apiKind：API 类型。
    // 返回：ASCII key。
    QString apiExportKey(const VirusTotalOnlineScan::VtApiKind apiKind)
    {
        switch (apiKind)
        {
        case VirusTotalOnlineScan::VtApiKind::FileProfile:
            return QStringLiteral("file_profile");
        case VirusTotalOnlineScan::VtApiKind::Ioc:
            return QStringLiteral("ioc");
        case VirusTotalOnlineScan::VtApiKind::Sandbox:
            return QStringLiteral("sandbox");
        case VirusTotalOnlineScan::VtApiKind::AllApis:
            return QStringLiteral("all_apis");
        case VirusTotalOnlineScan::VtApiKind::ShallowAnalysis:
        default:
            return QStringLiteral("shallow_analysis");
        }
    }

    // apiStateText 作用：
    // - 将内部状态转换为报告视图提示文案。
    // 入参 apiState：当前状态。
    // 返回：中文状态文本。
    QString apiStateText(const VirusTotalOnlineScan::VtApiState apiState)
    {
        switch (apiState)
        {
        case VirusTotalOnlineScan::VtApiState::Hashing:
            return QStringLiteral("正在计算本地 Hash");
        case VirusTotalOnlineScan::VtApiState::Running:
            return QStringLiteral("正在请求 VirusTotal");
        case VirusTotalOnlineScan::VtApiState::Completed:
            return QStringLiteral("已完成");
        case VirusTotalOnlineScan::VtApiState::Empty:
            return QStringLiteral("VT 暂无该类数据");
        case VirusTotalOnlineScan::VtApiState::Failed:
            return QStringLiteral("失败");
        case VirusTotalOnlineScan::VtApiState::NotStarted:
        default:
            return QStringLiteral("未开始");
        }
    }

    // iocRelationships 作用：
    // - 返回默认接入的常用 IOC relationship；
    // - 顺序即报告视图展示顺序和串行请求顺序。
    // 返回：relationship 列表。
    QStringList iocRelationships()
    {
        return QStringList()
            << QStringLiteral("contacted_ips")
            << QStringLiteral("contacted_domains")
            << QStringLiteral("contacted_urls")
            << QStringLiteral("dropped_files")
            << QStringLiteral("bundled_files")
            << QStringLiteral("execution_parents");
    }

    // relationshipDisplayText 作用：
    // - 将 VT relationship key 转换为 UI 分区名称。
    // 入参 relationshipText：VT relationship key。
    // 返回：中文分区名。
    QString relationshipDisplayText(const QString& relationshipText)
    {
        if (relationshipText == QStringLiteral("contacted_ips"))
        {
            return QStringLiteral("连接 IP");
        }
        if (relationshipText == QStringLiteral("contacted_domains"))
        {
            return QStringLiteral("连接域名");
        }
        if (relationshipText == QStringLiteral("contacted_urls"))
        {
            return QStringLiteral("连接 URL");
        }
        if (relationshipText == QStringLiteral("dropped_files"))
        {
            return QStringLiteral("释放文件");
        }
        if (relationshipText == QStringLiteral("bundled_files"))
        {
            return QStringLiteral("打包文件");
        }
        if (relationshipText == QStringLiteral("execution_parents"))
        {
            return QStringLiteral("执行父样本");
        }
        return relationshipText;
    }

    // jsonValueCompactText 作用：
    // - 从任意 JSON 值提取适合表格/树节点的一行摘要；
    // - IOC 和沙箱列表需要避免把完整对象塞进一个单元格。
    // 入参 jsonValue：源 JSON 值。
    // 返回：一行摘要文本。
    QString jsonValueCompactText(const QJsonValue& jsonValue)
    {
        if (jsonValue.isString())
        {
            return jsonValue.toString();
        }
        if (jsonValue.isDouble() || jsonValue.isBool() || jsonValue.isNull())
        {
            if (jsonValue.isBool())
            {
                return jsonValue.toBool() ? QStringLiteral("true") : QStringLiteral("false");
            }
            if (jsonValue.isDouble())
            {
                return QString::number(jsonValue.toDouble());
            }
            return QStringLiteral("null");
        }
        if (jsonValue.isObject())
        {
            const QJsonObject objectValue = jsonValue.toObject();
            const QString idText = objectValue.value(QStringLiteral("id")).toString();
            if (!idText.isEmpty())
            {
                return idText;
            }
            const QJsonObject attributesObject = objectValue.value(QStringLiteral("attributes")).toObject();
            const QString nameText = attributesObject.value(QStringLiteral("meaningful_name")).toString();
            if (!nameText.isEmpty())
            {
                return nameText;
            }
            return QStringLiteral("{ %1 fields }").arg(objectValue.size());
        }
        if (jsonValue.isArray())
        {
            return QStringLiteral("[ %1 items ]").arg(jsonValue.toArray().size());
        }
        return QStringLiteral("-");
    }

    // jsonValueToInt 作用：
    // - 安全读取 VirusTotal stats 中的整数值；
    // - 兼容 JSON 字段缺失或类型异常。
    // 入参 objectValue：JSON 对象。
    // 入参 keyText：字段名。
    // 返回：字段整数值，缺失时为 0。
    int jsonValueToInt(const QJsonObject& objectValue, const QString& keyText)
    {
        return objectValue.value(keyText).toInt(0);
    }

    // utcTimestampText 作用：
    // - 生成原始响应章节时间戳；
    // - 输出使用 ISO 格式，便于导出 JSON/TXT 后做时间线分析。
    // 返回：当前 UTC 时间文本。
    QString utcTimestampText()
    {
        return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    }

    // fileDisplayText 作用：
    // - 生成实时结果窗口顶部文件说明；
    // - 兼容路径为空或 QFileInfo 无法解析文件名的情况。
    // 入参 filePath：本地样本路径。
    // 返回：文件名 + 路径的用户可读文本。
    QString fileDisplayText(const QString& filePath)
    {
        const QFileInfo fileInfo(filePath);
        const QString fileName = fileInfo.fileName().isEmpty()
            ? QStringLiteral("<未知文件>")
            : fileInfo.fileName();
        return QStringLiteral("%1\n%2").arg(fileName, QDir::toNativeSeparators(filePath));
    }

    // formatByteCount 作用：
    // - Convert VT/local file byte counts into compact human-readable text.
    // - The UI uses this for the headline and basic information table.
    // Input byteCount: raw byte count; negative means unknown.
    // Return: formatted size text, or "-" when unavailable.
    QString formatByteCount(const qint64 byteCount)
    {
        if (byteCount < 0)
        {
            return QStringLiteral("-");
        }
        if (byteCount < 1024)
        {
            return QStringLiteral("%1 B").arg(byteCount);
        }

        const double kibValue = static_cast<double>(byteCount) / 1024.0;
        if (kibValue < 1024.0)
        {
            return QStringLiteral("%1 KB").arg(kibValue, 0, 'f', 2);
        }

        const double mibValue = kibValue / 1024.0;
        if (mibValue < 1024.0)
        {
            return QStringLiteral("%1 MB").arg(mibValue, 0, 'f', 2);
        }

        const double gibValue = mibValue / 1024.0;
        return QStringLiteral("%1 GB").arg(gibValue, 0, 'f', 2);
    }

    // unixDateText 作用：
    // - Format VT epoch seconds into local time text.
    // - Unknown or zero timestamps are rendered as "-".
    // Input secondsValue: seconds since Unix epoch.
    // Return: local date/time string.
    QString unixDateText(const qint64 secondsValue)
    {
        if (secondsValue <= 0)
        {
            return QStringLiteral("-");
        }
        return QDateTime::fromSecsSinceEpoch(secondsValue, QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    }

    // jsonPrimitiveText 作用：
    // - Convert a primitive JSON value into a short display string for tables/trees.
    // - Objects and arrays are represented by shape markers because children carry details.
    // Input jsonValue: VT JSON value.
    // Return: user-readable scalar value.
    QString jsonPrimitiveText(const QJsonValue& jsonValue)
    {
        if (jsonValue.isString())
        {
            return jsonValue.toString();
        }
        if (jsonValue.isBool())
        {
            return jsonValue.toBool() ? QStringLiteral("true") : QStringLiteral("false");
        }
        if (jsonValue.isDouble())
        {
            const double numberValue = jsonValue.toDouble();
            const qint64 integerValue = static_cast<qint64>(numberValue);
            if (qFuzzyCompare(numberValue + 1.0, static_cast<double>(integerValue) + 1.0))
            {
                return QString::number(integerValue);
            }
            return QString::number(numberValue, 'f', 4);
        }
        if (jsonValue.isNull())
        {
            return QStringLiteral("null");
        }
        if (jsonValue.isUndefined())
        {
            return QStringLiteral("<undefined>");
        }
        if (jsonValue.isArray())
        {
            return QStringLiteral("[Array]");
        }
        if (jsonValue.isObject())
        {
            return QStringLiteral("{Object}");
        }
        return QString();
    }

    // categoryText 作用：
    // - Localize VirusTotal engine result category into concise Chinese text.
    // - Unknown categories are preserved so new VT values remain visible.
    // Input categoryTextValue: VT category string.
    // Return: localized category label.
    QString categoryText(const QString& categoryTextValue)
    {
        const QString normalizedText = categoryTextValue.trimmed().toLower();
        if (normalizedText == QStringLiteral("malicious"))
        {
            return QStringLiteral("恶意");
        }
        if (normalizedText == QStringLiteral("suspicious"))
        {
            return QStringLiteral("可疑");
        }
        if (normalizedText == QStringLiteral("harmless"))
        {
            return QStringLiteral("无害");
        }
        if (normalizedText == QStringLiteral("undetected"))
        {
            return QStringLiteral("无检出");
        }
        if (normalizedText == QStringLiteral("timeout"))
        {
            return QStringLiteral("超时");
        }
        if (normalizedText == QStringLiteral("confirmed-timeout"))
        {
            return QStringLiteral("确认超时");
        }
        if (normalizedText == QStringLiteral("failure"))
        {
            return QStringLiteral("失败");
        }
        if (normalizedText == QStringLiteral("type-unsupported"))
        {
            return QStringLiteral("类型不支持");
        }
        return categoryTextValue.trimmed().isEmpty() ? QStringLiteral("-") : categoryTextValue.trimmed();
    }

    // categoryPriority 作用：
    // - Sort engine rows by analyst importance.
    // - Detections appear first, then weak/unknown states, then clean results.
    // Input categoryTextValue: VT category string.
    // Return: lower value sorts earlier.
    int categoryPriority(const QString& categoryTextValue)
    {
        const QString normalizedText = categoryTextValue.trimmed().toLower();
        if (normalizedText == QStringLiteral("malicious"))
        {
            return 0;
        }
        if (normalizedText == QStringLiteral("suspicious"))
        {
            return 1;
        }
        if (normalizedText == QStringLiteral("failure") ||
            normalizedText == QStringLiteral("timeout") ||
            normalizedText == QStringLiteral("confirmed-timeout"))
        {
            return 2;
        }
        if (normalizedText == QStringLiteral("undetected"))
        {
            return 3;
        }
        if (normalizedText == QStringLiteral("harmless"))
        {
            return 4;
        }
        return 5;
    }

    // categoryColor 作用：
    // - Map VT categories to visible semantic colors.
    // - Colors are used only as foreground hints and keep table text readable.
    // Input categoryTextValue: VT category string.
    // Return: QColor; invalid color means default palette foreground.
    QColor categoryColor(const QString& categoryTextValue)
    {
        const QString normalizedText = categoryTextValue.trimmed().toLower();
        if (normalizedText == QStringLiteral("malicious"))
        {
            return KswordTheme::ErrorColor();
        }
        if (normalizedText == QStringLiteral("suspicious"))
        {
            return KswordTheme::WarningColor();
        }
        if (normalizedText == QStringLiteral("failure") ||
            normalizedText == QStringLiteral("timeout") ||
            normalizedText == QStringLiteral("confirmed-timeout"))
        {
            return KswordTheme::WarningColor();
        }
        if (normalizedText == QStringLiteral("undetected") ||
            normalizedText == QStringLiteral("harmless"))
        {
            return KswordTheme::SuccessColor();
        }
        return QColor();
    }

    // engineDetectionText 作用：
    // - 把 VirusTotal 单引擎 category/result 压缩成报告页一行双引擎布局需要的短文本；
    // - 恶意/可疑统一显示“检出：XXX”，未检出/无害显示短状态，异常状态保留诊断语义。
    // 入参 categoryTextValue：VT 返回的 category 字段。
    // 入参 resultTextValue：VT 返回的 result 字段。
    // 返回：用于“多引擎检测”结果列的短文本。
    QString engineDetectionText(const QString& categoryTextValue, const QString& resultTextValue)
    {
        const QString normalizedText = categoryTextValue.trimmed().toLower();
        const QString trimmedResultText = resultTextValue.trimmed();
        if (normalizedText == QStringLiteral("malicious") ||
            normalizedText == QStringLiteral("suspicious"))
        {
            return QStringLiteral("检出：%1").arg(trimmedResultText.isEmpty()
                ? categoryText(categoryTextValue)
                : trimmedResultText);
        }
        if (normalizedText == QStringLiteral("undetected"))
        {
            return QStringLiteral("未检出");
        }
        if (normalizedText == QStringLiteral("harmless"))
        {
            return QStringLiteral("安全");
        }
        if (normalizedText == QStringLiteral("timeout") ||
            normalizedText == QStringLiteral("confirmed-timeout"))
        {
            return QStringLiteral("超时");
        }
        if (normalizedText == QStringLiteral("failure"))
        {
            return QStringLiteral("失败");
        }
        if (normalizedText == QStringLiteral("type-unsupported"))
        {
            return QStringLiteral("不支持");
        }
        return trimmedResultText.isEmpty() ? categoryText(categoryTextValue) : trimmedResultText;
    }

    struct ReportVerdict
    {
        QString labelText;     // 报告顶部显示的四类结论之一。
        QString iconPath;      // qrc 中的 SVG 图标路径。
        QColor accentColor;    // 文本强调色。
    };

    // reportVerdictFromStats 作用：
    // - 把 VirusTotal stats 压缩为用户要求的四类结论：威胁、可疑、安全、未检出；
    // - 恶意优先级最高，其次可疑；无恶意/可疑且有 harmless 时视为安全；其余为未检出。
    // 入参 maliciousCount/suspiciousCount/harmlessCount：VT stats 中对应计数。
    // 返回：报告顶部使用的文案、图标和强调色。
    ReportVerdict reportVerdictFromStats(
        const int maliciousCount,
        const int suspiciousCount,
        const int harmlessCount)
    {
        if (maliciousCount > 0)
        {
            return {
                QStringLiteral("威胁"),
                QStringLiteral(":/Icon/vt_status_threat.svg"),
                KswordTheme::ErrorColor(),
            };
        }
        if (suspiciousCount > 0)
        {
            return {
                QStringLiteral("可疑"),
                QStringLiteral(":/Icon/vt_status_suspicious.svg"),
                KswordTheme::WarningColor(),
            };
        }
        if (harmlessCount > 0)
        {
            return {
                QStringLiteral("安全"),
                QStringLiteral(":/Icon/vt_status_safe.svg"),
                KswordTheme::SuccessColor(),
            };
        }
        return {
            QStringLiteral("未检出"),
            QStringLiteral(":/Icon/vt_status_undetected.svg"),
            KswordTheme::InfoColor(),
        };
    }

    // createReadOnlyTableItem 作用：
    // - Create a non-editable table item with optional semantic color.
    // - All result tables are display-only, so this helper centralizes flags/tooltips.
    // Input textValue: cell text.
    // Input foregroundColor: optional foreground color.
    // Return: newly allocated QTableWidgetItem owned by the table after setItem().
    QTableWidgetItem* createReadOnlyTableItem(const QString& textValue, const QColor& foregroundColor = QColor())
    {
        QTableWidgetItem* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(textValue);
        if (foregroundColor.isValid())
        {
            item->setForeground(QBrush(foregroundColor));
        }
        return item;
    }

    // configureReadOnlyTable 作用：
    // - Apply common read-only behavior to VT result tables.
    // - Keeps interaction predictable across overview, engine and detail tables.
    // Input table: table widget to configure.
    // Return: no value.
    void configureReadOnlyTable(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setHighlightSections(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->setWordWrap(false);
    }

    // configureBorderlessInfoTable 作用：
    // - 把 QTableWidget 调整为报告页的“文本信息块”效果；
    // - 隐藏表头、网格和外框，只保留两列字段和值。
    // 入参 table：目标表格。
    // 返回：无。
    void configureBorderlessInfoTable(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::None);
        configureReadOnlyTable(table);
        table->setFrameShape(QFrame::NoFrame);
        table->setShowGrid(false);
        table->setFocusPolicy(Qt::NoFocus);
        table->horizontalHeader()->setVisible(false);
        table->verticalHeader()->setVisible(false);
        table->verticalHeader()->setDefaultSectionSize(18);
        table->verticalHeader()->setMinimumSectionSize(16);
        table->setSelectionMode(QAbstractItemView::NoSelection);
        table->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
    }

    // fitTableHeightToRows 作用：
    // - 按当前行高计算 QTableWidget 的最小/最大高度；
    // - 用于基础信息这种紧凑文本块，避免空白区域让行距显得松散。
    // 入参 table：需要压缩高度的表格。
    // 返回：无。
    void fitTableHeightToRows(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        int totalHeight = table->frameWidth() * 2 + 2;
        if (table->horizontalHeader() != nullptr && table->horizontalHeader()->isVisible())
        {
            totalHeight += table->horizontalHeader()->height();
        }
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            totalHeight += table->rowHeight(rowIndex);
        }
        table->setMinimumHeight(totalHeight);
        table->setMaximumHeight(totalHeight);
    }

    // setTableRow 作用：
    // - Write a two-column key/value row into a QTableWidget.
    // - It grows the table when needed and keeps cells read-only.
    // Input table: target table.
    // Input rowIndex: target row.
    // Input keyText: left column label.
    // Input valueText: right column value.
    // Return: no value.
    void setTableRow(QTableWidget* table, const int rowIndex, const QString& keyText, const QString& valueText)
    {
        if (table == nullptr)
        {
            return;
        }
        if (table->rowCount() <= rowIndex)
        {
            table->setRowCount(rowIndex + 1);
        }
        table->setItem(rowIndex, 0, createReadOnlyTableItem(keyText));
        table->setItem(rowIndex, 1, createReadOnlyTableItem(valueText));
        table->setRowHeight(rowIndex, 18);
    }

    // visibleTableRowText 作用：
    // - 把表格当前行的所有可见列拼成 TSV；
    // - 右键复制时保留列顺序，方便粘贴到工单、Excel 或文本记录。
    // 入参 table：来源表格。
    // 入参 rowIndex：要复制的行号。
    // 返回：TSV 文本；输入无效时返回空字符串。
    QString visibleTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList cellTexts;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (table->isColumnHidden(columnIndex))
            {
                continue;
            }
            QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            cellTexts << (item == nullptr ? QString() : item->text());
        }
        return cellTexts.join(QChar('\t'));
    }

    // visibleTreeItemText 作用：
    // - 把树节点当前行的所有可见列拼成 TSV；
    // - 报告详情和响应详情都使用树控件，该函数保证复制行为一致。
    // 入参 tree：来源树控件。
    // 入参 item：要复制的节点。
    // 返回：TSV 文本；输入无效时返回空字符串。
    QString visibleTreeItemText(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        if (tree == nullptr || item == nullptr)
        {
            return QString();
        }

        QStringList cellTexts;
        for (int columnIndex = 0; columnIndex < tree->columnCount(); ++columnIndex)
        {
            if (tree->isColumnHidden(columnIndex))
            {
                continue;
            }
            cellTexts << item->text(columnIndex);
        }
        return cellTexts.join(QChar('\t'));
    }

    // treeItemContainsFilterText 作用：
    // - 检查树节点所有列是否包含筛选文本；
    // - 文件画像页的筛选框同时匹配“字段”和“值”，避免用户只知道 PE 字段值时搜不到。
    // 入参 item：待检查的树节点。
    // 入参 filterText：已经 trim 过的筛选文本。
    // 返回：true=当前节点任一列命中；false=当前节点不命中。
    bool treeItemContainsFilterText(QTreeWidgetItem* item, const QString& filterText)
    {
        if (item == nullptr || filterText.isEmpty())
        {
            return filterText.isEmpty();
        }

        const QTreeWidget* tree = item->treeWidget();
        const int columnCount = tree != nullptr ? tree->columnCount() : item->columnCount();
        for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
        {
            if (item->text(columnIndex).contains(filterText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    // applyTreeItemFilter 作用：
    // - 递归过滤树节点，保留命中节点及其父链；
    // - 子节点命中时自动展开父节点，保证筛选结果一眼可见。
    // 入参 item：当前树节点。
    // 入参 filterText：已经 trim 过的筛选文本；为空时恢复显示。
    // 返回：true=当前节点或任一子节点可见；false=整棵子树不命中。
    bool applyTreeItemFilter(QTreeWidgetItem* item, const QString& filterText)
    {
        if (item == nullptr)
        {
            return false;
        }

        bool childVisible = false;
        for (int childIndex = 0; childIndex < item->childCount(); ++childIndex)
        {
            childVisible = applyTreeItemFilter(item->child(childIndex), filterText) || childVisible;
        }

        const bool selfVisible = treeItemContainsFilterText(item, filterText);
        const bool visible = filterText.isEmpty() || selfVisible || childVisible;
        item->setHidden(!visible);
        if (!filterText.isEmpty() && visible && childVisible)
        {
            item->setExpanded(true);
        }
        return visible;
    }

    // applyTreeFilter 作用：
    // - 对 QTreeWidget 顶层节点应用筛选；
    // - 仅控制节点可见性，不删除原始报告节点，清空筛选后可完整恢复。
    // 入参 tree：目标报告树。
    // 入参 filterText：用户输入的筛选文本。
    // 返回：无。
    void applyTreeFilter(QTreeWidget* tree, const QString& filterText)
    {
        if (tree == nullptr)
        {
            return;
        }

        const QString normalizedFilterText = filterText.trimmed();
        for (int topIndex = 0; topIndex < tree->topLevelItemCount(); ++topIndex)
        {
            applyTreeItemFilter(tree->topLevelItem(topIndex), normalizedFilterText);
        }
    }

    // copyTextToClipboard 作用：
    // - 将 VT 报告页里用户右键选择的单元格/行复制到系统剪贴板；
    // - 空文本直接忽略，避免误清空已有剪贴板内容。
    // 入参 text：待复制文本。
    // 返回：无。
    void copyTextToClipboard(const QString& text)
    {
        if (text.isEmpty())
        {
            return;
        }
        QClipboard* clipboardObject = QApplication::clipboard();
        if (clipboardObject != nullptr)
        {
            clipboardObject->setText(text);
        }
    }

    // installTableCopyMenu 作用：
    // - 给 VT 报告页表格安装“复制单元格/复制当前行”右键菜单；
    // - 只复制数据，不改变分析状态，也不触发网络请求。
    // 入参 table：目标表格。
    // 返回：无。
    void installTableCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
            {
                QTableWidgetItem* clickedItem = table->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    table->setCurrentCell(clickedItem->row(), clickedItem->column());
                }

                QMenu contextMenu(table);
                contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
                QAction* copyCellAction = contextMenu.addAction(QStringLiteral("复制单元格"));
                QAction* copyRowAction = contextMenu.addAction(QStringLiteral("复制当前行"));
                const bool hasItem = clickedItem != nullptr || table->currentItem() != nullptr;
                copyCellAction->setEnabled(hasItem);
                copyRowAction->setEnabled(hasItem);

                QAction* selectedAction = contextMenu.exec(table->viewport()->mapToGlobal(localPosition));
                QTableWidgetItem* currentItem = table->currentItem();
                if (selectedAction == copyCellAction && currentItem != nullptr)
                {
                    copyTextToClipboard(currentItem->text());
                }
                else if (selectedAction == copyRowAction && currentItem != nullptr)
                {
                    copyTextToClipboard(visibleTableRowText(table, currentItem->row()));
                }
            });
    }

    // installTreeCopyMenu 作用：
    // - 给 VT 报告树和响应树安装“复制字段/复制值/复制当前行”右键菜单；
    // - 树节点中保存的是报告证据和原始响应摘要，右键复制便于复核和外部留档。
    // 入参 tree：目标树控件。
    // 返回：无。
    void installTreeCopyMenu(QTreeWidget* tree)
    {
        if (tree == nullptr)
        {
            return;
        }

        tree->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tree, &QTreeWidget::customContextMenuRequested, tree, [tree](const QPoint& localPosition)
            {
                QTreeWidgetItem* clickedItem = tree->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    tree->setCurrentItem(clickedItem);
                }

                QMenu contextMenu(tree);
                contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
                QAction* copyFieldAction = contextMenu.addAction(QStringLiteral("复制字段"));
                QAction* copyValueAction = contextMenu.addAction(QStringLiteral("复制值"));
                QAction* copyRowAction = contextMenu.addAction(QStringLiteral("复制当前行"));
                const bool hasItem = clickedItem != nullptr || tree->currentItem() != nullptr;
                copyFieldAction->setEnabled(hasItem);
                copyValueAction->setEnabled(hasItem);
                copyRowAction->setEnabled(hasItem);

                QAction* selectedAction = contextMenu.exec(tree->viewport()->mapToGlobal(localPosition));
                QTreeWidgetItem* currentItem = tree->currentItem();
                if (selectedAction == copyFieldAction && currentItem != nullptr)
                {
                    copyTextToClipboard(currentItem->text(0));
                }
                else if (selectedAction == copyValueAction && currentItem != nullptr)
                {
                    copyTextToClipboard(currentItem->text(1));
                }
                else if (selectedAction == copyRowAction && currentItem != nullptr)
                {
                    copyTextToClipboard(visibleTreeItemText(tree, currentItem));
                }
            });
    }

    // addTreeLeaf 作用：
    // - Add a simple key/value child item to a QTreeWidgetItem.
    // - Used by both readable static analysis tree and raw response tree.
    // Input parentItem: parent tree item.
    // Input keyText: field name.
    // Input valueText: field value.
    // Return: created child item, or nullptr if parent is missing.
    QTreeWidgetItem* addTreeLeaf(QTreeWidgetItem* parentItem, const QString& keyText, const QString& valueText)
    {
        if (parentItem == nullptr)
        {
            return nullptr;
        }
        QTreeWidgetItem* childItem = new QTreeWidgetItem(parentItem);
        childItem->setText(0, keyText);
        childItem->setText(1, valueText);
        childItem->setToolTip(0, keyText);
        childItem->setToolTip(1, valueText);
        return childItem;
    }

    // appendJsonValueToTree 作用：
    // - Recursively project JSON objects/arrays into an expandable tree.
    // - Object and array nodes keep the structural marker in column 1; scalar leaves show values.
    // Input parentItem: parent tree item.
    // Input keyText: current field/index label.
    // Input jsonValue: current JSON value.
    // Return: no value.
    void appendJsonValueToTree(QTreeWidgetItem* parentItem, const QString& keyText, const QJsonValue& jsonValue)
    {
        if (parentItem == nullptr)
        {
            return;
        }

        QTreeWidgetItem* currentItem = new QTreeWidgetItem(parentItem);
        currentItem->setText(0, keyText);
        if (jsonValue.isObject())
        {
            const QJsonObject objectValue = jsonValue.toObject();
            currentItem->setText(1, QStringLiteral("{ %1 fields }").arg(objectValue.size()));
            for (auto iterator = objectValue.constBegin(); iterator != objectValue.constEnd(); ++iterator)
            {
                appendJsonValueToTree(currentItem, iterator.key(), iterator.value());
            }
            return;
        }
        if (jsonValue.isArray())
        {
            const QJsonArray arrayValue = jsonValue.toArray();
            currentItem->setText(1, QStringLiteral("[ %1 items ]").arg(arrayValue.size()));
            for (int index = 0; index < arrayValue.size(); ++index)
            {
                appendJsonValueToTree(currentItem, QStringLiteral("[%1]").arg(index), arrayValue.at(index));
            }
            return;
        }

        const QString valueText = jsonPrimitiveText(jsonValue);
        currentItem->setText(1, valueText);
        currentItem->setToolTip(0, keyText);
        currentItem->setToolTip(1, valueText);
    }
}

VirusTotalOnlineScan::VirusTotalOnlineScan(QObject* parent)
    : QObject(parent)
    , m_networkManager(new QNetworkAccessManager(this))
{
}

VirusTotalOnlineScan::~VirusTotalOnlineScan() = default;

void VirusTotalOnlineScan::scanFile(
    const QString& filePath,
    const QString& sourceText,
    QWidget* dialogParent)
{
    scanFile(filePath, sourceText, VtApiKind::ShallowAnalysis, dialogParent);
}

void VirusTotalOnlineScan::scanFile(
    const QString& filePath,
    const QString& sourceText,
    const VtApiKind initialApi,
    QWidget* dialogParent)
{
    if (m_scanInProgress)
    {
        ks::online_scan::showErrorDialog(
            dialogParent,
            QStringLiteral("VirusTotal 在线扫描"),
            QStringLiteral("当前 VirusTotal 扫描仍在进行，请等待完成后再上传新文件。"));
        return;
    }

    resetRuntimeState();
    m_dialogParent = dialogParent;
    m_filePath = filePath.trimmed();
    m_sourceText = sourceText.trimmed().isEmpty()
        ? QStringLiteral("手动上传")
        : sourceText.trimmed();

    // settings 作用：从统一设置 JSON 读取 API Key，未配置时直接提示用户补充。
    // m_settingsJsonPath 作用：记录本次读取落点，后续 401/403/429 只展示路径和 Key 掩码。
    m_settingsJsonPath = ks::settings::resolveSettingsJsonPathForRead();
    const ks::settings::AppearanceSettings settings = ks::settings::loadAppearanceSettings();
    m_apiKey = settings.virusTotalApiKey.trimmed();
    if (m_apiKey.isEmpty())
    {
        ks::online_scan::showErrorDialog(
            dialogParent,
            QStringLiteral("在线扫描 API Key 未配置"),
            QStringLiteral("VirusTotal API Key 为空。\n\n请在“设置 -> 在线扫描”中填写 API Key，保存后重新上传文件。\n\n当前设置读取路径：%1")
                .arg(QDir::toNativeSeparators(m_settingsJsonPath)));
        return;
    }

    QString fileErrorText;
    if (!ks::online_scan::validateReadableFile(
        m_filePath,
        ks::online_scan::kVirusTotalLargeUploadMaxBytes,
        &fileErrorText))
    {
        ks::online_scan::showErrorDialog(dialogParent, QStringLiteral("VirusTotal 在线扫描"), fileErrorText);
        return;
    }

    ensureResultDialog();
    selectApiTab(initialApi);
    if (initialApi == VtApiKind::AllApis)
    {
        startAllApis();
        return;
    }
    startApiAnalysis(initialApi);
}

void VirusTotalOnlineScan::scanFile(const QString& filePath, QWidget* dialogParent)
{
    scanFile(filePath, QStringLiteral("手动上传"), dialogParent);
}

void VirusTotalOnlineScan::scanFileAndAutoDelete(
    const QString& filePath,
    const QString& sourceText,
    QWidget* dialogParent)
{
    scanFileAndAutoDelete(filePath, sourceText, VtApiKind::ShallowAnalysis, dialogParent);
}

void VirusTotalOnlineScan::scanFileAndAutoDelete(
    const QString& filePath,
    const QString& sourceText,
    const VtApiKind initialApi,
    QWidget* dialogParent)
{
    VirusTotalOnlineScan* scanner = new VirusTotalOnlineScan(dialogParent);
    scanner->m_autoDeleteWhenFinished = true;
    scanner->scanFile(filePath, sourceText, initialApi, dialogParent);
    if (!scanner->m_scanInProgress)
    {
        // 非浅分析类 API 也会异步请求，但 m_scanInProgress 只表示上传轮询。
        // 结果窗口已创建时不能立即释放对象，否则按钮/网络回调会访问悬空对象。
        if (scanner->m_resultDialog.isNull())
        {
            scanner->deleteLater();
        }
        else
        {
            scanner->m_deleteAfterResultDialogClosed = true;
        }
    }
}

void VirusTotalOnlineScan::scanFileAndAutoDelete(const QString& filePath, QWidget* dialogParent)
{
    scanFileAndAutoDelete(filePath, QStringLiteral("手动上传"), dialogParent);
}

void VirusTotalOnlineScan::setApiState(
    const VtApiKind apiKind,
    const VtApiState apiState,
    const QString& statusText)
{
    // 输入：一个一级 API Tab 的新状态。
    // 处理：写入状态数组，并刷新该 Pane 的占位文案和“开始分析”按钮。
    // 返回：无。
    const int index = apiIndex(apiKind);
    m_apiStates[static_cast<std::size_t>(index)] = apiState;

    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(index)];
    if (!pane.startButton.isNull())
    {
        pane.startButton->setVisible(apiState == VtApiState::NotStarted ||
            apiState == VtApiState::Empty ||
            apiState == VtApiState::Failed);
        pane.startButton->setEnabled(apiState != VtApiState::Running &&
            apiState != VtApiState::Hashing);
    }
    refreshApiPlaceholder(apiKind, statusText);
}

void VirusTotalOnlineScan::refreshApiPlaceholder(const VtApiKind apiKind, const QString& statusText)
{
    // 输入：目标 API 和可选状态文本。
    // 处理：为未完成的 Tab 提供清晰占位状态；已完成 Tab 不覆盖已有报告。
    // 返回：无。
    const int index = apiIndex(apiKind);
    const VtApiState apiState = m_apiStates[static_cast<std::size_t>(index)];
    if (apiState == VtApiState::Completed)
    {
        return;
    }

    const QString displayText = statusText.trimmed().isEmpty()
        ? apiStateText(apiState)
        : statusText.trimmed();
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(index)];
    const QList<QAbstractItemView*> itemViews{
        pane.fileInfoTable.data(),
        pane.engineTable.data(),
        pane.reportTree.data()
    };
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-api-placeholder-%1").arg(index),
            itemViews,
            [safeThis, apiKind, statusText]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshApiPlaceholder(apiKind, statusText);
                }
            }))
    {
        return;
    }
    if (!pane.overviewLabel.isNull())
    {
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:18px;font-weight:700;'>%1</div>"
            "<div style='margin-top:6px;'>%2</div>")
            .arg(apiTitleText(apiKind).toHtmlEscaped(), displayText.toHtmlEscaped()));
    }
    if (!pane.reportTree.isNull())
    {
        pane.reportTree->clear();
        QTreeWidgetItem* item = new QTreeWidgetItem(pane.reportTree);
        item->setText(0, apiTitleText(apiKind));
        item->setText(1, displayText);
        item->setExpanded(true);
    }
}

void VirusTotalOnlineScan::selectApiTab(const VtApiKind apiKind)
{
    if (m_resultTabWidget.isNull())
    {
        return;
    }
    m_resultTabWidget->setCurrentIndex(apiIndex(apiKind));
}

void VirusTotalOnlineScan::startApiAnalysis(const VtApiKind apiKind)
{
    ensureResultDialog();
    selectApiTab(apiKind);

    const int index = apiIndex(apiKind);
    const VtApiState currentState = m_apiStates[static_cast<std::size_t>(index)];
    if (currentState == VtApiState::Running || currentState == VtApiState::Hashing)
    {
        return;
    }
    if (!m_dispatchingQueuedApi && hasActiveApiOperation())
    {
        if (!m_deferredApiQueue.contains(apiKind))
        {
            m_deferredApiQueue.append(apiKind);
        }
        refreshApiPlaceholder(
            apiKind,
            QStringLiteral("已加入 VT 串行队列，等待当前 API 请求结束后自动开始。"));
        return;
    }

    if (apiKind == VtApiKind::ShallowAnalysis)
    {
        if (m_scanInProgress)
        {
            return;
        }
        setApiState(apiKind, VtApiState::Running, QStringLiteral("正在上传样本并等待普通分析结果。"));
        m_scanInProgress = true;
        m_progressPid = kPro.add(this, "在线扫描", "VirusTotal 上传准备");
        kPro.set(m_progressPid, "VirusTotal：准备上传样本", 0, 5.0f);

        const QFileInfo fileInfo(m_filePath);
        if (fileInfo.size() > ks::online_scan::kVirusTotalDirectUploadMaxBytes)
        {
            requestLargeUploadUrl();
            return;
        }
        uploadFileToUrl(QUrl(QString::fromLatin1(kVirusTotalFilesEndpoint)));
        return;
    }

    ensureLocalHashes(apiKind);
}

void VirusTotalOnlineScan::startAllApis()
{
    ensureResultDialog();
    m_allApisMode = true;
    m_allApiQueue.clear();
    m_allApiQueue << VtApiKind::ShallowAnalysis
        << VtApiKind::FileProfile
        << VtApiKind::Ioc
        << VtApiKind::Sandbox;
    if (hasActiveApiOperation())
    {
        updateResultSummary(QStringLiteral(
            "来源：%1\n文件：%2\n状态：全部 API 已排队，等待当前 VT 请求结束后串行执行。")
            .arg(m_sourceText, fileDisplayText(m_filePath)));
        return;
    }
    startNextQueuedAllApi();
}

bool VirusTotalOnlineScan::hasActiveApiOperation() const
{
    if (m_scanInProgress || m_localHashes.running)
    {
        return true;
    }
    for (const VtApiState apiState : m_apiStates)
    {
        if (apiState == VtApiState::Running || apiState == VtApiState::Hashing)
        {
            return true;
        }
    }
    return false;
}

void VirusTotalOnlineScan::startNextQueuedAllApi()
{
    while (!m_allApiQueue.isEmpty())
    {
        const VtApiKind nextApi = m_allApiQueue.takeFirst();
        const VtApiState queuedState = m_apiStates[static_cast<std::size_t>(apiIndex(nextApi))];
        if (queuedState == VtApiState::Completed || queuedState == VtApiState::Empty)
        {
            continue;
        }
        m_dispatchingQueuedApi = true;
        startApiAnalysis(nextApi);
        m_dispatchingQueuedApi = false;
        return;
    }

    m_allApisMode = false;
    if (m_sandboxHtmlFetchQueued && m_sandboxHtmlQueue.isEmpty())
    {
        m_sandboxHtmlFetchQueued = false;
    }
    if (m_sandboxHtmlFetchQueued && !m_sandboxHtmlQueue.isEmpty())
    {
        m_sandboxHtmlFetchQueued = false;
        requestNextSandboxHtmlReport();
        return;
    }
    if (!m_deferredSingleIocRelationships.isEmpty())
    {
        const QString relationshipText = m_deferredSingleIocRelationships.takeFirst();
        startSingleIocRelationship(relationshipText);
        return;
    }
    if (!m_deferredApiQueue.isEmpty())
    {
        const VtApiKind nextApi = m_deferredApiQueue.takeFirst();
        m_dispatchingQueuedApi = true;
        startApiAnalysis(nextApi);
        m_dispatchingQueuedApi = false;
        return;
    }

    finalizeAutoDeleteIfNeeded();
}

bool VirusTotalOnlineScan::scheduleRetryAfterRateLimit(
    const VtApiKind apiKind,
    const QString& retryKey,
    QNetworkReply* reply,
    const QString& statusText,
    std::function<void()> retryAction)
{
    // 输入：一个刚收到的 VT 响应和重试回调。
    // 处理：仅当 HTTP 429 时根据 Retry-After 串行延迟重试；超过上限时交还调用方走失败展示。
    // 返回：true 表示本函数已经安排重试，调用方不应继续把该 API 标记为失败。
    if (replyHttpStatusCode(reply) != 429 || !retryAction)
    {
        return false;
    }

    const QString normalizedRetryKey = retryKey.trimmed().isEmpty()
        ? apiTitleText(apiKind)
        : retryKey.trimmed();
    const int retryCount = m_vtRateLimitRetryCounts.value(normalizedRetryKey, 0);
    if (retryCount >= kMaxRateLimitRetryAttempts)
    {
        return false;
    }

    const int delayMs = rateLimitRetryDelayMs(reply);
    m_vtRateLimitRetryCounts.insert(normalizedRetryKey, retryCount + 1);
    const QString waitText = formatWaitSecondsText(delayMs);
    setApiState(
        apiKind,
        VtApiState::Running,
        QStringLiteral("%1\nVirusTotal 返回 429，%2 后自动重试（%3/%4）。")
            .arg(statusText.trimmed().isEmpty() ? apiTitleText(apiKind) : statusText.trimmed())
            .arg(waitText)
            .arg(retryCount + 1)
            .arg(kMaxRateLimitRetryAttempts));

    QPointer<VirusTotalOnlineScan> self(this);
    QTimer::singleShot(delayMs, this, [self, retryAction]()
        {
            if (self.isNull())
            {
                return;
            }
            retryAction();
        });
    return true;
}

void VirusTotalOnlineScan::ensureLocalHashes(const VtApiKind nextApi)
{
    if (m_localHashes.ready)
    {
        if (nextApi == VtApiKind::FileProfile)
        {
            requestFileProfile();
        }
        else if (nextApi == VtApiKind::Ioc)
        {
            if (m_iocRelationshipQueue.isEmpty())
            {
                m_iocRelationshipQueue = iocRelationships();
                m_iocRelationshipObjects = QJsonObject();
            }
            setApiState(nextApi, VtApiState::Running, QStringLiteral("正在请求常用 IOC 关系。"));
            requestNextIocRelationship();
        }
        else if (nextApi == VtApiKind::Sandbox)
        {
            requestSandboxSummary();
        }
        return;
    }

    if (!m_pendingHashApis.contains(nextApi))
    {
        m_pendingHashApis.append(nextApi);
    }
    setApiState(nextApi, VtApiState::Hashing, QStringLiteral("正在计算本地 MD5/SHA1/SHA256。"));
    if (m_localHashes.running)
    {
        return;
    }

    m_localHashes.running = true;
    const QString filePath = m_filePath;
    QPointer<VirusTotalOnlineScan> self(this);
    QRunnable* task = QRunnable::create([self, filePath]()
        {
            // 输入：样本路径。
            // 处理：后台流式计算 MD5/SHA1/SHA256，避免大文件阻塞 UI。
            // 返回：通过 QueuedConnection 回到 UI 线程。
            QString errorText;
            QString md5Text;
            QString sha1Text;
            QString sha256Text;
            QFile inputFile(filePath);
            if (!inputFile.open(QIODevice::ReadOnly))
            {
                errorText = QStringLiteral("打开文件失败：%1").arg(inputFile.errorString());
            }
            else
            {
                QCryptographicHash md5Hasher(QCryptographicHash::Md5);
                QCryptographicHash sha1Hasher(QCryptographicHash::Sha1);
                QCryptographicHash sha256Hasher(QCryptographicHash::Sha256);
                while (!inputFile.atEnd())
                {
                    const QByteArray chunkBytes = inputFile.read(1024 * 1024);
                    if (chunkBytes.isEmpty() && inputFile.error() != QFile::NoError)
                    {
                        errorText = QStringLiteral("读取文件失败：%1").arg(inputFile.errorString());
                        break;
                    }
                    md5Hasher.addData(chunkBytes);
                    sha1Hasher.addData(chunkBytes);
                    sha256Hasher.addData(chunkBytes);
                }
                if (errorText.isEmpty())
                {
                    md5Text = QString::fromLatin1(md5Hasher.result().toHex());
                    sha1Text = QString::fromLatin1(sha1Hasher.result().toHex());
                    sha256Text = QString::fromLatin1(sha256Hasher.result().toHex());
                }
            }

            if (!self.isNull())
            {
                QMetaObject::invokeMethod(
                    self.data(),
                    [self, md5Text, sha1Text, sha256Text, errorText]()
                    {
                        if (!self.isNull())
                        {
                            self->handleLocalHashesReady(md5Text, sha1Text, sha256Text, errorText);
                        }
                    },
                    Qt::QueuedConnection);
            }
        });
    QThreadPool::globalInstance()->start(task);
}

void VirusTotalOnlineScan::handleLocalHashesReady(
    const QString& md5Text,
    const QString& sha1Text,
    const QString& sha256Text,
    const QString& errorText)
{
    m_localHashes.running = false;
    if (!errorText.trimmed().isEmpty() || sha256Text.trimmed().isEmpty())
    {
        const QString finalErrorText = errorText.trimmed().isEmpty()
            ? QStringLiteral("本地 SHA256 计算结果为空。")
            : errorText.trimmed();
        const QList<VtApiKind> waitingApis = m_pendingHashApis;
        m_pendingHashApis.clear();
        for (const VtApiKind apiKind : waitingApis)
        {
            appendRawTextSection(apiKind, QStringLiteral("本地 Hash 计算失败"), finalErrorText);
            setApiState(apiKind, VtApiState::Failed, finalErrorText);
        }
        startNextQueuedAllApi();
        return;
    }

    m_localHashes.md5Text = md5Text;
    m_localHashes.sha1Text = sha1Text;
    m_localHashes.sha256Text = sha256Text;
    m_localHashes.ready = true;

    const QList<VtApiKind> waitingApis = m_pendingHashApis;
    m_pendingHashApis.clear();
    for (const VtApiKind apiKind : waitingApis)
    {
        ensureLocalHashes(apiKind);
    }
}

void VirusTotalOnlineScan::requestFileProfile()
{
    setApiState(VtApiKind::FileProfile, VtApiState::Running, QStringLiteral("正在请求文件完整画像。"));
    const QUrl requestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) + m_localHashes.sha256Text);
    QNetworkRequest request(requestUrl);
    setVirusTotalHeaders(&request, m_apiKey);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleFileProfileReply(reply);
        });
}

void VirusTotalOnlineScan::handleFileProfileReply(QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const QVariant statusCodeVariant = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    const int statusCode = statusCodeVariant.isValid() ? statusCodeVariant.toInt() : 0;
    const bool networkOk = reply->error() == QNetworkReply::NoError;
    const QString titleText = QStringLiteral("GET /api/v3/files/%1 文件画像").arg(m_localHashes.sha256Text);

    if (!networkOk)
    {
        if (statusCode == 404)
        {
            const QString emptyText = QStringLiteral("VT 暂无该文件画像。该 hash 目前没有 VirusTotal 文件对象记录；如需要画像，可先执行普通分析上传后稍后重试。");
            appendRawTextSection(VtApiKind::FileProfile, titleText + QStringLiteral(" 暂无数据"), emptyText, responseMetadata);
            appendRawReplyBodySection(VtApiKind::FileProfile, titleText + QStringLiteral(" 404 原始响应体"), bodyBytes, responseMetadata);
            reply->deleteLater();
            setApiState(VtApiKind::FileProfile, VtApiState::Empty, emptyText);
            startNextQueuedAllApi();
            return;
        }
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(VtApiKind::FileProfile, titleText + QStringLiteral(" 请求失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::FileProfile, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::FileProfile,
            titleText,
            reply,
            QStringLiteral("文件画像请求被限流。"),
            [this]()
            {
                requestFileProfile();
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        setApiState(
            VtApiKind::FileProfile,
            VtApiState::Failed,
            errorText);
        startNextQueuedAllApi();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::FileProfile, titleText + QStringLiteral(" 解析失败"), parseErrorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::FileProfile, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        setApiState(VtApiKind::FileProfile, VtApiState::Failed, parseErrorText);
        startNextQueuedAllApi();
        return;
    }

    appendRawJsonSection(VtApiKind::FileProfile, titleText, rootObject, responseMetadata);
    m_fileProfileObject = rootObject;
    const QJsonObject attributesObject = rootObject.value(QStringLiteral("data")).toObject().value(QStringLiteral("attributes")).toObject();
    if (attributesObject.isEmpty())
    {
        setApiState(VtApiKind::FileProfile, VtApiState::Empty, QStringLiteral("VT 文件画像为空。"));
    }
    else
    {
        setApiState(VtApiKind::FileProfile, VtApiState::Completed);
        refreshFileProfileResult(rootObject);
    }
    startNextQueuedAllApi();
}

void VirusTotalOnlineScan::requestNextIocRelationship()
{
    if (m_iocRelationshipQueue.isEmpty())
    {
        bool hasAnyData = false;
        for (const QString& relationshipText : iocRelationships())
        {
            const QJsonArray dataArray = m_iocRelationshipObjects
                .value(relationshipText)
                .toObject()
                .value(QStringLiteral("data"))
                .toArray();
            if (!dataArray.isEmpty())
            {
                hasAnyData = true;
                break;
            }
        }
        setApiState(
            VtApiKind::Ioc,
            hasAnyData ? VtApiState::Completed : VtApiState::Empty,
            hasAnyData ? QString() : QStringLiteral("VT 暂无该文件的常用 IOC 关系数据。"));
        refreshIocResult();
        startNextQueuedAllApi();
        return;
    }

    const QString relationshipText = m_iocRelationshipQueue.takeFirst();
    setApiState(
        VtApiKind::Ioc,
        VtApiState::Running,
        QStringLiteral("正在请求 %1。").arg(relationshipDisplayText(relationshipText)));
    const QUrl requestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) +
        m_localHashes.sha256Text +
        QLatin1Char('/') +
        relationshipText);
    QNetworkRequest request(requestUrl);
    setVirusTotalHeaders(&request, m_apiKey);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, relationshipText, reply]()
        {
            handleIocRelationshipReply(relationshipText, reply);
        });
}

void VirusTotalOnlineScan::handleIocRelationshipReply(const QString& relationshipText, QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const int statusCode = replyHttpStatusCode(reply);
    const bool networkOk = reply->error() == QNetworkReply::NoError;
    const QString titleText = QStringLiteral("GET /api/v3/files/%1/%2")
        .arg(m_localHashes.sha256Text, relationshipText);
    if (!networkOk)
    {
        if (statusCode == 404)
        {
            const QString emptyText = QStringLiteral("VT 暂无该类 IOC 数据。");
            appendRawTextSection(VtApiKind::Ioc, titleText + QStringLiteral(" 暂无数据"), emptyText, responseMetadata);
            appendRawReplyBodySection(VtApiKind::Ioc, titleText + QStringLiteral(" 404 原始响应体"), bodyBytes, responseMetadata);
            QJsonObject emptyObject;
            emptyObject.insert(QStringLiteral("relationship"), relationshipText);
            emptyObject.insert(QStringLiteral("data"), QJsonArray());
            emptyObject.insert(QStringLiteral("empty_reason"), emptyText);
            emptyObject.insert(QStringLiteral("response_metadata"), responseMetadata);
            m_iocRelationshipObjects.insert(relationshipText, emptyObject);
            reply->deleteLater();
            requestNextIocRelationship();
            return;
        }
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(VtApiKind::Ioc, titleText + QStringLiteral(" 请求失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Ioc, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::Ioc,
            titleText,
            reply,
            QStringLiteral("IOC %1 请求被限流。").arg(relationshipDisplayText(relationshipText)),
            [this, relationshipText]()
            {
                m_iocRelationshipQueue.prepend(relationshipText);
                requestNextIocRelationship();
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        QJsonObject errorObject;
        errorObject.insert(QStringLiteral("error"), errorText);
        errorObject.insert(QStringLiteral("relationship"), relationshipText);
        errorObject.insert(QStringLiteral("response_metadata"), responseMetadata);
        m_iocRelationshipObjects.insert(relationshipText, errorObject);
        requestNextIocRelationship();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::Ioc, titleText + QStringLiteral(" 解析失败"), parseErrorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Ioc, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        QJsonObject errorObject;
        errorObject.insert(QStringLiteral("error"), parseErrorText);
        errorObject.insert(QStringLiteral("relationship"), relationshipText);
        errorObject.insert(QStringLiteral("response_metadata"), responseMetadata);
        m_iocRelationshipObjects.insert(relationshipText, errorObject);
        requestNextIocRelationship();
        return;
    }

    appendRawJsonSection(VtApiKind::Ioc, titleText, rootObject, responseMetadata);
    m_iocRelationshipObjects.insert(relationshipText, rootObject);
    requestNextIocRelationship();
}

void VirusTotalOnlineScan::startSingleIocRelationship(const QString& relationshipText)
{
    // 输入：一个 VT files relationship 名称。
    // 处理：只启动该 relationship；若当前有 VT 请求运行，则放入独立分项队列，避免覆盖全量 IOC 队列。
    // 返回：无。
    const QString trimmedRelationship = relationshipText.trimmed();
    if (trimmedRelationship.isEmpty())
    {
        return;
    }

    ensureResultDialog();
    selectApiTab(VtApiKind::Ioc);
    if (!m_dispatchingQueuedApi && hasActiveApiOperation())
    {
        if (!m_deferredSingleIocRelationships.contains(trimmedRelationship))
        {
            m_deferredSingleIocRelationships.append(trimmedRelationship);
        }
        refreshApiPlaceholder(
            VtApiKind::Ioc,
            QStringLiteral("%1 已加入 VT 串行队列。").arg(relationshipDisplayText(trimmedRelationship)));
        return;
    }

    m_iocRelationshipQueue.clear();
    m_iocRelationshipQueue << trimmedRelationship;
    ensureLocalHashes(VtApiKind::Ioc);
}

void VirusTotalOnlineScan::requestSandboxSummary()
{
    setApiState(VtApiKind::Sandbox, VtApiState::Running, QStringLiteral("正在请求沙箱行为汇总。"));
    const QUrl requestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) +
        m_localHashes.sha256Text +
        QStringLiteral("/behaviour_summary"));
    QNetworkRequest request(requestUrl);
    setVirusTotalHeaders(&request, m_apiKey);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleSandboxSummaryReply(reply);
        });
}

void VirusTotalOnlineScan::handleSandboxSummaryReply(QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const int statusCode = replyHttpStatusCode(reply);
    const bool networkOk = reply->error() == QNetworkReply::NoError;
    const QString titleText = QStringLiteral("GET /api/v3/files/%1/behaviour_summary").arg(m_localHashes.sha256Text);
    if (!networkOk)
    {
        if (statusCode == 404)
        {
            const QString emptyText = QStringLiteral("VT 暂无该文件沙箱行为汇总。");
            appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 暂无数据"), emptyText, responseMetadata);
            appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 404 原始响应体"), bodyBytes, responseMetadata);
            reply->deleteLater();
            m_sandboxSummaryObject = QJsonObject();
            requestSandboxBehaviours();
            return;
        }
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 请求失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::Sandbox,
            titleText,
            reply,
            QStringLiteral("沙箱行为汇总请求被限流。"),
            [this]()
            {
                requestSandboxSummary();
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        m_sandboxSummaryObject = QJsonObject();
        requestSandboxBehaviours();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 解析失败"), parseErrorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        m_sandboxSummaryObject = QJsonObject();
        requestSandboxBehaviours();
        return;
    }

    appendRawJsonSection(VtApiKind::Sandbox, titleText, rootObject, responseMetadata);
    m_sandboxSummaryObject = rootObject;
    requestSandboxBehaviours();
}

void VirusTotalOnlineScan::requestSandboxBehaviours()
{
    setApiState(VtApiKind::Sandbox, VtApiState::Running, QStringLiteral("正在请求单沙箱报告列表。"));
    const QUrl requestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) +
        m_localHashes.sha256Text +
        QStringLiteral("/behaviours"));
    QNetworkRequest request(requestUrl);
    setVirusTotalHeaders(&request, m_apiKey);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleSandboxBehavioursReply(reply);
        });
}

void VirusTotalOnlineScan::handleSandboxBehavioursReply(QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const int statusCode = replyHttpStatusCode(reply);
    const bool networkOk = reply->error() == QNetworkReply::NoError;
    const QString titleText = QStringLiteral("GET /api/v3/files/%1/behaviours").arg(m_localHashes.sha256Text);
    if (!networkOk)
    {
        if (statusCode == 404)
        {
            const QString emptyText = QStringLiteral("VT 暂无该文件沙箱报告列表。");
            appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 暂无数据"), emptyText, responseMetadata);
            appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 404 原始响应体"), bodyBytes, responseMetadata);
            reply->deleteLater();
            m_sandboxBehavioursObject = QJsonObject();
            setApiState(
                VtApiKind::Sandbox,
                m_sandboxSummaryObject.isEmpty() ? VtApiState::Empty : VtApiState::Completed,
                m_sandboxSummaryObject.isEmpty() ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
            refreshSandboxResult();
            startNextQueuedAllApi();
            return;
        }
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 请求失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::Sandbox,
            titleText,
            reply,
            QStringLiteral("沙箱报告列表请求被限流。"),
            [this]()
            {
                requestSandboxBehaviours();
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        m_sandboxBehavioursObject = QJsonObject();
        setApiState(
            VtApiKind::Sandbox,
            m_sandboxSummaryObject.isEmpty() ? VtApiState::Empty : VtApiState::Completed,
            m_sandboxSummaryObject.isEmpty() ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
        refreshSandboxResult();
        startNextQueuedAllApi();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 解析失败"), parseErrorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        m_sandboxBehavioursObject = QJsonObject();
        setApiState(
            VtApiKind::Sandbox,
            m_sandboxSummaryObject.isEmpty() ? VtApiState::Empty : VtApiState::Completed,
            m_sandboxSummaryObject.isEmpty() ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
        refreshSandboxResult();
        startNextQueuedAllApi();
        return;
    }

    appendRawJsonSection(VtApiKind::Sandbox, titleText, rootObject, responseMetadata);
    m_sandboxBehavioursObject = rootObject;

    m_sandboxHtmlQueue.clear();
    const QJsonArray behavioursArray = rootObject.value(QStringLiteral("data")).toArray();
    for (const QJsonValue& behaviourValue : behavioursArray)
    {
        const QJsonObject behaviourObject = behaviourValue.toObject();
        const QJsonObject attributesObject = behaviourObject.value(QStringLiteral("attributes")).toObject();
        if (attributesObject.value(QStringLiteral("has_html_report")).toBool(false))
        {
            const QString behaviourId = behaviourObject.value(QStringLiteral("id")).toString();
            if (!behaviourId.isEmpty())
            {
                m_sandboxHtmlQueue.append(behaviourId);
            }
        }
    }

    setApiState(
        VtApiKind::Sandbox,
        (m_sandboxSummaryObject.isEmpty() && behavioursArray.isEmpty()) ? VtApiState::Empty : VtApiState::Completed,
        (m_sandboxSummaryObject.isEmpty() && behavioursArray.isEmpty()) ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
    refreshSandboxResult();
    if (m_allApisMode && !m_sandboxHtmlQueue.isEmpty())
    {
        requestNextSandboxHtmlReport();
        return;
    }
    startNextQueuedAllApi();
}

void VirusTotalOnlineScan::requestSandboxHtmlReport(const QString& behaviourId)
{
    const QString trimmedId = behaviourId.trimmed();
    if (trimmedId.isEmpty())
    {
        return;
    }
    if (!m_dispatchingQueuedApi && hasActiveApiOperation())
    {
        if (!m_sandboxHtmlQueue.contains(trimmedId))
        {
            m_sandboxHtmlQueue.append(trimmedId);
        }
        m_sandboxHtmlFetchQueued = true;
        refreshApiPlaceholder(
            VtApiKind::Sandbox,
            QStringLiteral("HTML 沙箱报告已加入 VT 串行队列：%1").arg(trimmedId));
        return;
    }
    setApiState(VtApiKind::Sandbox, VtApiState::Running, QStringLiteral("正在请求 HTML 沙箱报告：%1").arg(trimmedId));
    const QUrl requestUrl(QString::fromLatin1(kVirusTotalFileBehaviourEndpointPrefix) +
        trimmedId +
        QStringLiteral("/html"));
    QNetworkRequest request(requestUrl);
    setVirusTotalHeaders(&request, m_apiKey);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, trimmedId, reply]()
        {
            handleSandboxHtmlReply(trimmedId, reply);
        });
}

void VirusTotalOnlineScan::requestNextSandboxHtmlReport()
{
    if (m_sandboxHtmlQueue.isEmpty())
    {
        setApiState(VtApiKind::Sandbox, VtApiState::Completed);
        refreshSandboxResult();
        if (m_allApisMode && m_allApiQueue.isEmpty())
        {
            m_allApisMode = false;
        }
        startNextQueuedAllApi();
        return;
    }
    requestSandboxHtmlReport(m_sandboxHtmlQueue.takeFirst());
}

void VirusTotalOnlineScan::handleSandboxHtmlReply(const QString& behaviourId, QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const int statusCode = replyHttpStatusCode(reply);
    const bool networkOk = reply->error() == QNetworkReply::NoError;
    const QString titleText = QStringLiteral("GET /api/v3/file_behaviours/%1/html").arg(behaviourId);
    QJsonObject htmlObject;
    htmlObject.insert(QStringLiteral("behaviour_id"), behaviourId);
    htmlObject.insert(QStringLiteral("timestamp_utc"), utcTimestampText());
    htmlObject.insert(QStringLiteral("response_metadata"), responseMetadata);
    if (!networkOk)
    {
        if (statusCode == 404)
        {
            const QString emptyText = QStringLiteral("VT 暂无该 HTML 沙箱报告，可能已过期或当前 Key 无法访问该报告。");
            htmlObject.insert(QStringLiteral("empty_reason"), emptyText);
            appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 暂无数据"), emptyText, responseMetadata);
            appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 404 原始响应体"), bodyBytes, responseMetadata);
            reply->deleteLater();
            m_sandboxHtmlReports.insert(behaviourId, htmlObject);
            setApiState(VtApiKind::Sandbox, VtApiState::Completed);
            refreshSandboxResult();
            showSandboxHtmlPreview(behaviourId);
            if (!m_sandboxHtmlQueue.isEmpty() || m_allApisMode)
            {
                requestNextSandboxHtmlReport();
                return;
            }
            startNextQueuedAllApi();
            return;
        }
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        htmlObject.insert(QStringLiteral("error"), errorText);
        appendRawTextSection(VtApiKind::Sandbox, titleText + QStringLiteral(" 请求失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::Sandbox, titleText + QStringLiteral(" 原始响应体"), bodyBytes, responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::Sandbox,
            titleText,
            reply,
            QStringLiteral("HTML 沙箱报告请求被限流：%1").arg(behaviourId),
            [this, behaviourId]()
            {
                const bool previousDispatchingState = m_dispatchingQueuedApi;
                m_dispatchingQueuedApi = true;
                requestSandboxHtmlReport(behaviourId);
                m_dispatchingQueuedApi = previousDispatchingState;
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
    }
    else
    {
        const QString htmlText = QString::fromUtf8(bodyBytes);
        htmlObject.insert(QStringLiteral("html"), htmlText);
        appendRawTextSection(VtApiKind::Sandbox, titleText, htmlText, responseMetadata);
        reply->deleteLater();
    }
    m_sandboxHtmlReports.insert(behaviourId, htmlObject);
    setApiState(VtApiKind::Sandbox, VtApiState::Completed);
    refreshSandboxResult();
    showSandboxHtmlPreview(behaviourId);
    if (!m_sandboxHtmlQueue.isEmpty() || m_allApisMode)
    {
        requestNextSandboxHtmlReport();
        return;
    }
    startNextQueuedAllApi();
}

void VirusTotalOnlineScan::requestLargeUploadUrl()
{
    QNetworkRequest request(QUrl(QString::fromLatin1(kVirusTotalLargeUploadUrlEndpoint)));
    setVirusTotalHeaders(&request, m_apiKey);

    kPro.set(m_progressPid, "VirusTotal：获取大文件上传地址", 0, 8.0f);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleUploadUrlReply(reply);
        });
}

void VirusTotalOnlineScan::uploadFileToUrl(const QUrl& uploadUrl)
{
    QFile* uploadFile = new QFile(m_filePath);
    if (!uploadFile->open(QIODevice::ReadOnly))
    {
        const QString errorText = QStringLiteral("打开上传文件失败：%1").arg(uploadFile->errorString());
        uploadFile->deleteLater();
        finishWithError(QStringLiteral("VirusTotal 上传失败"), errorText);
        return;
    }

    // multiPart 作用：构造 VirusTotal v3 files 上传所需的 multipart/form-data 请求体。
    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QHttpPart filePart;
    const QString safeFileName = ks::online_scan::sanitizeFileNameForContentDisposition(QFileInfo(m_filePath).fileName());
    filePart.setHeader(
        QNetworkRequest::ContentDispositionHeader,
        QVariant(QStringLiteral("form-data; name=\"file\"; filename=\"%1\"").arg(safeFileName)));
    filePart.setBodyDevice(uploadFile);
    uploadFile->setParent(multiPart);
    multiPart->append(filePart);

    QNetworkRequest request(uploadUrl);
    setVirusTotalHeaders(&request, m_apiKey);

    kPro.set(m_progressPid, "VirusTotal：上传样本", 0, 12.0f);
    QNetworkReply* reply = m_networkManager->post(request, multiPart);
    multiPart->setParent(reply);

    connect(reply, &QNetworkReply::uploadProgress, this,
        [this](const qint64 sentBytes, const qint64 totalBytes)
        {
            if (m_progressPid == 0 || totalBytes <= 0)
            {
                return;
            }
            const float uploadPercent = static_cast<float>(sentBytes) * 40.0f / static_cast<float>(totalBytes);
            kPro.set(m_progressPid, "VirusTotal：上传样本", 0, 12.0f + std::min(uploadPercent, 40.0f));
        });
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleUploadReply(reply);
        });
}

void VirusTotalOnlineScan::handleUploadUrlReply(QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const bool networkOk = reply->error() == QNetworkReply::NoError;

    if (!networkOk)
    {
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(VtApiKind::ShallowAnalysis, QStringLiteral("获取大文件上传 URL 失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::ShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url 错误响应体"), bodyBytes, responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/files/upload_url"),
            reply,
            QStringLiteral("获取大文件上传 URL 被限流。"),
            [this]()
            {
                requestLargeUploadUrl();
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        finishWithError(
            QStringLiteral("VirusTotal 获取上传地址失败"),
            errorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (parseErrorText.isEmpty())
    {
        appendRawJsonSection(VtApiKind::ShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url"), rootObject, responseMetadata);
    }
    else
    {
        appendRawTextSection(VtApiKind::ShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url 解析失败"), parseErrorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::ShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url 原始响应体"), bodyBytes, responseMetadata);
    }
    const QString uploadUrlText = rootObject.value(QStringLiteral("data")).toString().trimmed();
    if (!parseErrorText.isEmpty() || uploadUrlText.isEmpty())
    {
        finishWithError(
            QStringLiteral("VirusTotal 获取上传地址失败"),
            parseErrorText.isEmpty() ? QStringLiteral("响应中缺少 data 上传 URL。") : parseErrorText);
        return;
    }

    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\n状态：已取得大文件上传 URL，正在上传样本。")
        .arg(m_sourceText, fileDisplayText(m_filePath)));
    uploadFileToUrl(QUrl(uploadUrlText));
}

void VirusTotalOnlineScan::handleUploadReply(QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const bool networkOk = reply->error() == QNetworkReply::NoError;

    if (!networkOk)
    {
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(VtApiKind::ShallowAnalysis, QStringLiteral("上传样本失败"), errorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::ShallowAnalysis, QStringLiteral("POST /api/v3/files 错误响应体"), bodyBytes, responseMetadata);
        const QUrl uploadUrl = reply->url();
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("POST %1").arg(uploadUrl.toString()),
            reply,
            QStringLiteral("上传样本请求被限流。"),
            [this, uploadUrl]()
            {
                uploadFileToUrl(uploadUrl);
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        finishWithError(
            QStringLiteral("VirusTotal 上传失败"),
            errorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (parseErrorText.isEmpty())
    {
        appendRawJsonSection(VtApiKind::ShallowAnalysis, QStringLiteral("POST /api/v3/files 上传响应"), rootObject, responseMetadata);
    }
    else
    {
        appendRawTextSection(VtApiKind::ShallowAnalysis, QStringLiteral("POST /api/v3/files 上传响应解析失败"), parseErrorText, responseMetadata);
        appendRawReplyBodySection(VtApiKind::ShallowAnalysis, QStringLiteral("POST /api/v3/files 原始响应体"), bodyBytes, responseMetadata);
    }
    if (!parseErrorText.isEmpty())
    {
        finishWithError(QStringLiteral("VirusTotal 上传失败"), parseErrorText);
        return;
    }

    const QJsonObject dataObject = rootObject.value(QStringLiteral("data")).toObject();
    m_analysisId = dataObject.value(QStringLiteral("id")).toString().trimmed();
    if (m_analysisId.isEmpty())
    {
        finishWithError(
            QStringLiteral("VirusTotal 上传失败"),
            QStringLiteral("上传响应中缺少 analysis id。\n\n%1").arg(ks::online_scan::formatJsonObject(rootObject)));
        return;
    }

    kPro.set(m_progressPid, "VirusTotal：等待分析结果", 0, 55.0f);
    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\nAnalysisId：%3\n状态：上传响应已返回，正在等待 VirusTotal 分析结果。")
        .arg(m_sourceText, fileDisplayText(m_filePath), m_analysisId));
    scheduleAnalysisPoll(kInitialPollDelayMs);
}

void VirusTotalOnlineScan::scheduleAnalysisPoll(const int delayMs)
{
    QTimer::singleShot(delayMs, this, [this]()
        {
            requestAnalysisStatus();
        });
}

void VirusTotalOnlineScan::requestAnalysisStatus()
{
    if (!m_scanInProgress || m_analysisId.isEmpty())
    {
        return;
    }

    ++m_pollAttempt;
    const float progressValue = std::min(95.0f, 55.0f + static_cast<float>(m_pollAttempt) * 1.0f);
    kPro.set(
        m_progressPid,
        QStringLiteral("VirusTotal：轮询分析结果(%1/%2)").arg(m_pollAttempt).arg(kMaxPollAttempts).toStdString(),
        0,
        progressValue);

    QNetworkRequest request(QUrl(QString::fromLatin1(kVirusTotalAnalysisEndpointPrefix) + m_analysisId));
    setVirusTotalHeaders(&request, m_apiKey);
    QNetworkReply* reply = m_networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleAnalysisReply(reply);
        });
}

void VirusTotalOnlineScan::handleAnalysisReply(QNetworkReply* reply)
{
    const QByteArray bodyBytes = reply->readAll();
    const QJsonObject responseMetadata = virusTotalResponseMetadataObject(reply, bodyBytes);
    const bool networkOk = reply->error() == QNetworkReply::NoError;

    if (!networkOk)
    {
        const QString errorText = virusTotalNetworkErrorText(reply, bodyBytes, m_apiKey, m_settingsJsonPath);
        appendRawTextSection(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 查询失败").arg(m_analysisId),
            errorText,
            responseMetadata);
        appendRawReplyBodySection(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 错误响应体").arg(m_analysisId),
            bodyBytes,
            responseMetadata);
        const bool retryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1").arg(m_analysisId),
            reply,
            QStringLiteral("查询分析结果被限流。"),
            [this]()
            {
                requestAnalysisStatus();
            });
        reply->deleteLater();
        if (retryScheduled)
        {
            return;
        }
        finishWithError(
            QStringLiteral("VirusTotal 查询失败"),
            errorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject rootObject = ks::online_scan::parseJsonObjectFromBytes(bodyBytes, &parseErrorText);
    if (parseErrorText.isEmpty())
    {
        appendRawJsonSection(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 第 %2 次响应")
                .arg(m_analysisId)
                .arg(m_pollAttempt),
            rootObject,
            responseMetadata);
    }
    else
    {
        appendRawTextSection(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 解析失败").arg(m_analysisId),
            parseErrorText,
            responseMetadata);
        appendRawReplyBodySection(
            VtApiKind::ShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 原始响应体").arg(m_analysisId),
            bodyBytes,
            responseMetadata);
    }
    if (!parseErrorText.isEmpty())
    {
        finishWithError(QStringLiteral("VirusTotal 查询失败"), parseErrorText);
        return;
    }

    const QJsonObject dataObject = rootObject.value(QStringLiteral("data")).toObject();
    const QJsonObject attributesObject = dataObject.value(QStringLiteral("attributes")).toObject();
    const QString statusText = attributesObject.value(QStringLiteral("status")).toString().trimmed().toLower();
    if (statusText == QStringLiteral("completed"))
    {
        finishWithResult(rootObject);
        return;
    }

    if (m_pollAttempt >= kMaxPollAttempts)
    {
        finishWithError(
            QStringLiteral("VirusTotal 查询超时"),
            QStringLiteral("分析任务尚未完成，analysis id：%1\n最后状态：%2")
                .arg(m_analysisId, statusText.isEmpty() ? QStringLiteral("未知") : statusText));
        return;
    }
    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\nAnalysisId：%3\n状态：%4；已轮询 %5/%6 次。")
        .arg(m_sourceText)
        .arg(fileDisplayText(m_filePath))
        .arg(m_analysisId)
        .arg(statusText.isEmpty() ? QStringLiteral("未知") : statusText)
        .arg(m_pollAttempt)
        .arg(kMaxPollAttempts));
    scheduleAnalysisPoll(kPollIntervalMs);
}

void VirusTotalOnlineScan::finishWithError(const QString& titleText, const QString& detailText)
{
    completeProgress(QStringLiteral("VirusTotal：扫描失败"));
    m_scanInProgress = false;
    ensureResultDialog();
    setApiState(VtApiKind::ShallowAnalysis, VtApiState::Failed, detailText);
    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\n状态：%3\n错误：%4")
        .arg(m_sourceText, fileDisplayText(m_filePath), titleText, detailText));
    if (!m_readableOverviewLabel.isNull())
    {
        m_readableOverviewLabel->setText(QStringLiteral(
            "<table cellspacing='0' cellpadding='0'>"
            "<tr>"
            "<td width='124'><img src=':/Icon/vt_status_threat.svg' width='104' height='104'/></td>"
            "<td>"
            "<div style='font-size:22px;font-weight:700;'>%1</div>"
            "<div style='margin-top:6px;color:%4;font-size:18px;font-weight:700;'>威胁</div>"
            "<div style='margin-top:8px;'>状态：%2</div>"
            "<div style='margin-top:6px;'>错误详情：%3</div>"
            "</td>"
            "</tr>"
            "</table>")
            .arg(QFileInfo(m_filePath).fileName().toHtmlEscaped().isEmpty()
                ? QStringLiteral("<未知文件>")
                : QFileInfo(m_filePath).fileName().toHtmlEscaped())
            .arg(titleText.toHtmlEscaped())
            .arg(detailText.toHtmlEscaped())
            .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
    }
    if (!m_resultTabWidget.isNull())
    {
        m_resultTabWidget->setCurrentIndex(0);
    }
    appendRawTextSection(titleText, detailText);
    startNextQueuedAllApi();
    finalizeAutoDeleteIfNeeded();
}

void VirusTotalOnlineScan::finishWithResult(const QJsonObject& analysisObject)
{
    completeProgress(QStringLiteral("VirusTotal：扫描完成"));
    m_scanInProgress = false;

    const QString summaryText = buildResultSummary(analysisObject);
    ensureResultDialog();
    const QJsonObject fileInfoObject = analysisObject
        .value(QStringLiteral("meta")).toObject()
        .value(QStringLiteral("file_info")).toObject();
    const QString md5Text = fileInfoObject.value(QStringLiteral("md5")).toString().trimmed();
    const QString sha1Text = fileInfoObject.value(QStringLiteral("sha1")).toString().trimmed();
    const QString sha256Text = fileInfoObject.value(QStringLiteral("sha256")).toString().trimmed();
    if (!sha256Text.isEmpty())
    {
        m_localHashes.md5Text = md5Text;
        m_localHashes.sha1Text = sha1Text;
        m_localHashes.sha256Text = sha256Text;
        m_localHashes.ready = true;
    }
    setApiState(VtApiKind::ShallowAnalysis, VtApiState::Completed);
    refreshReadableResult(analysisObject);
    updateResultSummary(QStringLiteral("来源：%1\n%2").arg(m_sourceText, summaryText));

    startNextQueuedAllApi();
    finalizeAutoDeleteIfNeeded();
}

void VirusTotalOnlineScan::resetRuntimeState()
{
    m_dialogParent.clear();
    m_resultDialog.clear();
    m_resultSummaryLabel.clear();
    m_resultTabWidget.clear();
    m_readableOverviewLabel.clear();
    m_fileInfoTable.clear();
    m_engineTable.clear();
    m_staticAnalysisTree.clear();
    m_responseTree.clear();
    m_resultEditor.clear();
    for (ApiPaneUi& pane : m_apiPanes)
    {
        pane.detailTabWidget.clear();
        pane.overviewLabel.clear();
        pane.startButton.clear();
        pane.sandboxHtmlButton.clear();
        pane.fileProfileFilterEdit.clear();
        pane.fileInfoTable.clear();
        pane.engineTable.clear();
        pane.reportTree.clear();
        pane.sandboxHtmlPreviewGroup.clear();
        pane.sandboxHtmlPreview.clear();
        pane.responseTree.clear();
        pane.rawEditor.clear();
    }
    for (VtApiState& apiState : m_apiStates)
    {
        apiState = VtApiState::NotStarted;
    }
    for (QString& rawText : m_apiRawText)
    {
        rawText.clear();
    }
    for (QJsonArray& rawSections : m_apiRawSections)
    {
        rawSections = QJsonArray();
    }
    m_filePath.clear();
    m_sourceText.clear();
    m_resultRawText.clear();
    m_resultRawSections = QJsonArray();
    m_localHashes = LocalHashContext();
    m_pendingHashApis.clear();
    m_allApiQueue.clear();
    m_deferredApiQueue.clear();
    m_deferredSingleIocRelationships.clear();
    m_fileProfileObject = QJsonObject();
    m_iocRelationshipObjects = QJsonObject();
    m_iocRelationshipQueue.clear();
    m_sandboxSummaryObject = QJsonObject();
    m_sandboxBehavioursObject = QJsonObject();
    m_sandboxHtmlReports = QJsonObject();
    m_sandboxHtmlQueue.clear();
    m_sandboxHtmlFetchQueued = false;
    m_vtRateLimitRetryCounts.clear();
    m_apiKey.clear();
    m_settingsJsonPath.clear();
    m_analysisId.clear();
    m_pollAttempt = 0;
    m_scanInProgress = false;
    m_allApisMode = false;
    m_dispatchingQueuedApi = false;
    m_progressPid = 0;
    m_deleteAfterResultDialogClosed = false;
}

void VirusTotalOnlineScan::completeProgress(const QString& messageText)
{
    if (m_progressPid == 0)
    {
        return;
    }
    kPro.set(m_progressPid, messageText.toStdString(), 0, 100.0f);
    m_progressPid = 0;
}

void VirusTotalOnlineScan::ensureResultDialog()
{
    if (!m_resultDialog.isNull())
    {
        if (!m_resultDialog->isVisible())
        {
            m_resultDialog->show();
        }
        m_resultDialog->raise();
        m_resultDialog->activateWindow();
        return;
    }

    QDialog* resultDialog = new QDialog(m_dialogParent.data());
    resultDialog->setAttribute(Qt::WA_DeleteOnClose, true);
    resultDialog->setObjectName(QStringLiteral("virusTotalLiveResultDialog"));
    resultDialog->setWindowTitle(QStringLiteral("VirusTotal 云沙箱上传结果"));
    resultDialog->resize(1180, 780);
    resultDialog->setStyleSheet(
        KswordTheme::OpaqueDialogStyle(resultDialog->objectName()) +
        QStringLiteral(
            "QDialog#virusTotalLiveResultDialog QLabel#vtOverviewCard{"
            "  border:0;"
            "  padding:4px 0 12px 0;"
            "}"
            "QDialog#virusTotalLiveResultDialog QGroupBox{"
            "  border:0;"
            "  margin-top:12px;"
            "  padding-top:12px;"
            "}"
            "QDialog#virusTotalLiveResultDialog QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  left:0px;"
            "  padding:0 4px;"
            "  font-weight:600;"
            "}"
            "QDialog#virusTotalLiveResultDialog QTabWidget::pane{"
            "  border:1px solid palette(mid);"
            "}"
            "QDialog#virusTotalLiveResultDialog QTableWidget#vtFileInfoTable{"
            "  border:0;"
            "  background:transparent;"
            "}"
            "QDialog#virusTotalLiveResultDialog QTableWidget#vtFileInfoTable::item{"
            "  border:0;"
            "  padding:1px 8px 1px 0;"
            "}"));

    // dialogLayout 作用：
    // - 顶部放全局 API 操作按钮；
    // - 中部放一级 API Tab，每个一级 Tab 内固定包含“报告视图/响应详情/原始数据”二级 Tab；
    // - 底部只保留关闭按钮，导出统一走顶部“导出所有API原始响应数据”。
    QVBoxLayout* dialogLayout = new QVBoxLayout(resultDialog);
    dialogLayout->setContentsMargins(0, 0, 0, 10);
    dialogLayout->setSpacing(0);

    QHBoxLayout* topButtonLayout = new QHBoxLayout();
    topButtonLayout->setContentsMargins(10, 8, 10, 8);
    QPushButton* runAllButton = new QPushButton(QStringLiteral("调用所有 API"), resultDialog);
    QPushButton* exportAllButton = new QPushButton(QStringLiteral("导出所有API原始响应数据"), resultDialog);
    topButtonLayout->addWidget(runAllButton, 0);
    topButtonLayout->addWidget(exportAllButton, 0);
    topButtonLayout->addStretch(1);
    dialogLayout->addLayout(topButtonLayout, 0);

    QTabWidget* resultTabWidget = new QTabWidget(resultDialog);
    resultTabWidget->setDocumentMode(false);

    const auto createCommonPane = [this, resultDialog, resultTabWidget](const VtApiKind apiKind) -> ApiPaneUi
        {
            ApiPaneUi pane;
            QWidget* apiPage = new QWidget(resultTabWidget);
            QVBoxLayout* apiLayout = new QVBoxLayout(apiPage);
            apiLayout->setContentsMargins(0, 0, 0, 0);
            apiLayout->setSpacing(0);

            QTabWidget* detailTabWidget = new QTabWidget(apiPage);
            pane.detailTabWidget = detailTabWidget;
            apiLayout->addWidget(detailTabWidget, 1);

            QWidget* reportPage = new QWidget(detailTabWidget);
            QVBoxLayout* reportPageLayout = new QVBoxLayout(reportPage);
            reportPageLayout->setContentsMargins(0, 0, 0, 0);
            QScrollArea* reportScrollArea = new QScrollArea(reportPage);
            reportScrollArea->setWidgetResizable(true);
            reportScrollArea->setFrameShape(QFrame::NoFrame);
            reportPageLayout->addWidget(reportScrollArea, 1);

            QWidget* reportContent = new QWidget(reportScrollArea);
            QVBoxLayout* reportLayout = new QVBoxLayout(reportContent);
            reportLayout->setContentsMargins(12, 12, 12, 12);
            reportLayout->setSpacing(10);

            QLabel* overviewLabel = new QLabel(reportContent);
            overviewLabel->setObjectName(QStringLiteral("vtOverviewCard"));
            overviewLabel->setTextFormat(Qt::RichText);
            overviewLabel->setWordWrap(true);
            pane.overviewLabel = overviewLabel;
            reportLayout->addWidget(overviewLabel, 0);

            QPushButton* startButton = new QPushButton(QStringLiteral("开始分析"), reportContent);
            pane.startButton = startButton;
            QObject::connect(startButton, &QPushButton::clicked, this, [this, apiKind]()
                {
                    startApiAnalysis(apiKind);
                });
            reportLayout->addWidget(startButton, 0);

            if (apiKind == VtApiKind::ShallowAnalysis)
            {
                QGroupBox* fileInfoGroup = new QGroupBox(QStringLiteral("基础信息 / HASH"), reportContent);
                QVBoxLayout* fileInfoLayout = new QVBoxLayout(fileInfoGroup);
                fileInfoLayout->setContentsMargins(0, 2, 0, 2);
                fileInfoLayout->setSpacing(0);
                QTableWidget* fileInfoTable = new ks::ui::VisibleTableWidget(fileInfoGroup);
                fileInfoTable->setObjectName(QStringLiteral("vtFileInfoTable"));
                fileInfoTable->setColumnCount(2);
                configureBorderlessInfoTable(fileInfoTable);
                installTableCopyMenu(fileInfoTable);
                fileInfoTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
                fileInfoTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
                setTableRow(fileInfoTable, 0, QStringLiteral("文件名"), QFileInfo(m_filePath).fileName());
                setTableRow(fileInfoTable, 1, QStringLiteral("文件大小"), formatByteCount(QFileInfo(m_filePath).size()));
                fitTableHeightToRows(fileInfoTable);
                fileInfoLayout->addWidget(fileInfoTable, 1);
                reportLayout->addWidget(fileInfoGroup, 0);
                pane.fileInfoTable = fileInfoTable;

                QGroupBox* engineGroup = new QGroupBox(QStringLiteral("多引擎检测"), reportContent);
                QVBoxLayout* engineLayout = new QVBoxLayout(engineGroup);
                QTableWidget* engineTable = new ks::ui::VisibleTableWidget(engineGroup);
                engineTable->setColumnCount(4);
                engineTable->setHorizontalHeaderLabels(QStringList()
                    << QStringLiteral("引擎")
                    << QStringLiteral("结果")
                    << QStringLiteral("引擎")
                    << QStringLiteral("结果"));
                configureReadOnlyTable(engineTable);
                installTableCopyMenu(engineTable);
                engineTable->horizontalHeader()->setVisible(false);
                engineTable->setSortingEnabled(false);
                engineTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
                engineTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
                engineTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
                engineTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
                engineLayout->addWidget(engineTable, 1);
                reportLayout->addWidget(engineGroup, 3);
                pane.engineTable = engineTable;
            }
            else if (apiKind == VtApiKind::Ioc)
            {
                QGroupBox* iocButtonGroup = new QGroupBox(QStringLiteral("IOC 分项分析"), reportContent);
                QHBoxLayout* iocButtonLayout = new QHBoxLayout(iocButtonGroup);
                iocButtonLayout->setContentsMargins(0, 4, 0, 4);
                for (const QString& relationshipText : iocRelationships())
                {
                    QPushButton* relationshipButton = new QPushButton(
                        QStringLiteral("%1 开始分析").arg(relationshipDisplayText(relationshipText)),
                        iocButtonGroup);
                    QObject::connect(relationshipButton, &QPushButton::clicked, this, [this, relationshipText]()
                        {
                            // 输入：用户点击某个 IOC relationship 分项按钮。
                            // 处理：只请求该 relationship；若当前有其它 VT 请求运行则进入独立待执行队列。
                            // 返回：无。
                            startSingleIocRelationship(relationshipText);
                        });
                    iocButtonLayout->addWidget(relationshipButton, 0);
                }
                iocButtonLayout->addStretch(1);
                reportLayout->addWidget(iocButtonGroup, 0);
            }

            QGroupBox* reportTreeGroup = new QGroupBox(
                apiKind == VtApiKind::ShallowAnalysis
                    ? QStringLiteral("静态分析 / 可展开详情")
                    : QStringLiteral("报告详情"),
                reportContent);
            QVBoxLayout* reportTreeLayout = new QVBoxLayout(reportTreeGroup);
            if (apiKind == VtApiKind::FileProfile)
            {
                QLineEdit* fileProfileFilterEdit = new QLineEdit(reportTreeGroup);
                // 文件画像树的字段/值过滤保留原提示，不触及文件提交或在线查询输入。
                ks::ui::BindSearchFieldTheme(fileProfileFilterEdit);
                fileProfileFilterEdit->setClearButtonEnabled(true);
                fileProfileFilterEdit->setPlaceholderText(QStringLiteral("筛选文件画像字段/值，例如 pe_info、signature、section、tag、hash"));
                fileProfileFilterEdit->setToolTip(QStringLiteral("输入关键字后筛选文件画像树；匹配字段和值，保留命中节点的父级路径。"));
                reportTreeLayout->addWidget(fileProfileFilterEdit, 0);
                pane.fileProfileFilterEdit = fileProfileFilterEdit;
            }
            QTreeWidget* reportTree = new QTreeWidget(reportTreeGroup);
            reportTree->setColumnCount(2);
            reportTree->setHeaderLabels(QStringList() << QStringLiteral("字段") << QStringLiteral("值"));
            reportTree->setAlternatingRowColors(true);
            reportTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
            reportTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            reportTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
            installTreeCopyMenu(reportTree);
            reportTreeLayout->addWidget(reportTree, 1);
            reportLayout->addWidget(reportTreeGroup, 2);
            pane.reportTree = reportTree;
            if (apiKind == VtApiKind::FileProfile && !pane.fileProfileFilterEdit.isNull())
            {
                QObject::connect(
                    pane.fileProfileFilterEdit,
                    &QLineEdit::textChanged,
                    reportTree,
                    [reportTree](const QString& filterText)
                    {
                        // 输入：文件画像筛选框文本。
                        // 处理：即时过滤报告树节点，仅隐藏不匹配项，不修改原始数据。
                        // 返回：无。
                        applyTreeFilter(reportTree, filterText);
                    });
            }

            if (apiKind == VtApiKind::Sandbox)
            {
                QObject::connect(reportTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int /*columnIndex*/)
                    {
                        // 输入：沙箱报告树中带 behaviour_id 的节点。
                        // 处理：双击“查看HTML报告”节点或其父沙箱节点时拉取对应 HTML 报告；
                        // 返回：无；已有报告时只切换到原始数据页查看。
                        if (item == nullptr)
                        {
                            return;
                        }
                        const QString behaviourId = item->data(0, Qt::UserRole).toString().trimmed();
                        if (behaviourId.isEmpty())
                        {
                            return;
                        }
                        selectApiTab(VtApiKind::Sandbox);
                        if (m_sandboxHtmlReports.contains(behaviourId))
                        {
                            showSandboxHtmlPreview(behaviourId);
                            return;
                        }
                        requestSandboxHtmlReport(behaviourId);
                    });

                QGroupBox* htmlPreviewGroup = new QGroupBox(QStringLiteral("HTML 报告预览"), reportContent);
                QVBoxLayout* htmlPreviewLayout = new QVBoxLayout(htmlPreviewGroup);
                htmlPreviewLayout->setContentsMargins(0, 4, 0, 0);
                QTextBrowser* htmlPreviewBrowser = new QTextBrowser(htmlPreviewGroup);
                htmlPreviewBrowser->setReadOnly(true);
                htmlPreviewBrowser->setOpenExternalLinks(false);
                htmlPreviewBrowser->setOpenLinks(false);
                htmlPreviewBrowser->setMinimumHeight(260);
                htmlPreviewBrowser->setPlaceholderText(QStringLiteral("双击带 HTML 报告的沙箱行后在此处显示渲染结果。"));
                htmlPreviewLayout->addWidget(htmlPreviewBrowser, 1);
                htmlPreviewGroup->setVisible(false);
                reportLayout->addWidget(htmlPreviewGroup, 2);
                pane.sandboxHtmlPreviewGroup = htmlPreviewGroup;
                pane.sandboxHtmlPreview = htmlPreviewBrowser;

                QPushButton* htmlButton = new QPushButton(QStringLiteral("拉取可用HTML报告"), reportContent);
                htmlButton->setVisible(false);
                QObject::connect(htmlButton, &QPushButton::clicked, this, [this]()
                    {
                        if (m_sandboxHtmlQueue.isEmpty())
                        {
                            const QJsonArray behavioursArray = m_sandboxBehavioursObject.value(QStringLiteral("data")).toArray();
                            for (const QJsonValue& behaviourValue : behavioursArray)
                            {
                                const QJsonObject behaviourObject = behaviourValue.toObject();
                                const QJsonObject attributesObject = behaviourObject.value(QStringLiteral("attributes")).toObject();
                                const QString behaviourId = behaviourObject.value(QStringLiteral("id")).toString();
                                if (attributesObject.value(QStringLiteral("has_html_report")).toBool(false) &&
                                    !behaviourId.isEmpty() &&
                                    !m_sandboxHtmlReports.contains(behaviourId))
                                {
                                    m_sandboxHtmlQueue.append(behaviourId);
                                }
                            }
                        }
                        requestNextSandboxHtmlReport();
                    });
                reportLayout->addWidget(htmlButton, 0);
                pane.sandboxHtmlButton = htmlButton;
            }

            reportLayout->addStretch(0);
            reportScrollArea->setWidget(reportContent);

            QWidget* responsePage = new QWidget(detailTabWidget);
            QVBoxLayout* responseLayout = new QVBoxLayout(responsePage);
            responseLayout->setContentsMargins(8, 8, 8, 8);
            QTreeWidget* responseTree = new QTreeWidget(responsePage);
            responseTree->setColumnCount(3);
            responseTree->setHeaderLabels(QStringList()
                << QStringLiteral("字段 / 响应阶段")
                << QStringLiteral("值")
                << QStringLiteral("时间(UTC)"));
            responseTree->setAlternatingRowColors(true);
            responseTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
            responseTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            responseTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
            responseTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
            installTreeCopyMenu(responseTree);
            responseLayout->addWidget(responseTree, 1);
            pane.responseTree = responseTree;

            QWidget* rawPage = new QWidget(detailTabWidget);
            QVBoxLayout* rawLayout = new QVBoxLayout(rawPage);
            rawLayout->setContentsMargins(8, 8, 8, 8);
            CodeEditorWidget* rawEditor = new CodeEditorWidget(resultDialog);
            rawEditor->setReadOnly(true);
            rawLayout->addWidget(rawEditor, 1);
            pane.rawEditor = rawEditor;

            detailTabWidget->addTab(reportPage, QStringLiteral("报告视图"));
            detailTabWidget->addTab(responsePage, QStringLiteral("响应详情"));
            detailTabWidget->addTab(rawPage, QStringLiteral("原始数据"));
            resultTabWidget->addTab(apiPage, apiTitleText(apiKind));
            return pane;
        };

    for (const VtApiKind apiKind : paneApiKinds())
    {
        m_apiPanes[static_cast<std::size_t>(apiIndex(apiKind))] = createCommonPane(apiKind);
    }

    ks::ui::SetDetailTabGroups(resultTabWidget, {{ks::ui::DetailNavigationKind::Analysis, {0, 1}},
        {ks::ui::DetailNavigationKind::Security, {2}}, {ks::ui::DetailNavigationKind::Behaviour, {3}}});
    dialogLayout->addWidget(ks::ui::CreateDetailTabShell(resultTabWidget, resultDialog), 1);
    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, resultDialog);

    QObject::connect(runAllButton, &QPushButton::clicked, this, [this]()
        {
            startAllApis();
        });
    QObject::connect(exportAllButton, &QPushButton::clicked, this, [this, resultDialog]()
        {
            // 输入：当前累计原始响应文本、结构化响应数组和样本文件名。
            // 处理：弹出保存对话框并写入包含全部 API 的 UTF-8 JSON 文件。
            // 返回：无；失败时通过弹窗提示。
            const QString defaultName = QStringLiteral("virustotal_%1_%2.json")
                .arg(QFileInfo(m_filePath).completeBaseName().isEmpty()
                    ? QStringLiteral("sample")
                    : QFileInfo(m_filePath).completeBaseName())
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
            const QString savePath = QFileDialog::getSaveFileName(
                resultDialog,
                QStringLiteral("导出 VirusTotal 全部 API 原始数据"),
                QDir(QDir::homePath()).absoluteFilePath(defaultName),
                QStringLiteral("JSON Files (*.json);;Text Files (*.txt);;All Files (*)"));
            if (savePath.isEmpty())
            {
                return;
            }

            QFile outputFile(savePath);
            if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
            {
                QMessageBox::warning(
                    resultDialog,
                    QStringLiteral("导出 VirusTotal 全部 API 原始数据"),
                    QStringLiteral("无法写入文件：%1\n%2").arg(savePath, outputFile.errorString()));
                return;
            }
            outputFile.write(buildRawExportJson());
            outputFile.close();
        });
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, resultDialog, &QDialog::close);
    dialogLayout->addWidget(buttonBox, 0);

    ks::ui::ApplyDetailDialogChrome(resultDialog);
    m_resultDialog = resultDialog;
    m_resultSummaryLabel.clear();
    m_resultTabWidget = resultTabWidget;
    ApiPaneUi& shallowPane = m_apiPanes[static_cast<std::size_t>(apiIndex(VtApiKind::ShallowAnalysis))];
    m_readableOverviewLabel = shallowPane.overviewLabel;
    m_fileInfoTable = shallowPane.fileInfoTable;
    m_engineTable = shallowPane.engineTable;
    m_staticAnalysisTree = shallowPane.reportTree;
    m_responseTree = shallowPane.responseTree;
    m_resultEditor = shallowPane.rawEditor;
    for (const VtApiKind apiKind : paneApiKinds())
    {
        refreshApiPlaceholder(apiKind);
    }
    QObject::connect(resultDialog, &QObject::destroyed, this, [this]()
        {
            // 输入：实时结果窗口 destroyed 信号。
            // 处理：清空弱指针，并在 scanFileAndAutoDelete 场景中释放扫描对象。
            // 返回：无；deleteLater 交给 Qt 事件循环执行。
            m_resultDialog.clear();
            m_resultSummaryLabel.clear();
            m_resultTabWidget.clear();
            m_readableOverviewLabel.clear();
            m_fileInfoTable.clear();
            m_engineTable.clear();
            m_staticAnalysisTree.clear();
            m_responseTree.clear();
            m_resultEditor.clear();
            for (ApiPaneUi& pane : m_apiPanes)
            {
                pane.detailTabWidget.clear();
                pane.overviewLabel.clear();
                pane.startButton.clear();
                pane.sandboxHtmlButton.clear();
                pane.fileProfileFilterEdit.clear();
                pane.fileInfoTable.clear();
                pane.engineTable.clear();
                pane.reportTree.clear();
                pane.sandboxHtmlPreviewGroup.clear();
                pane.sandboxHtmlPreview.clear();
                pane.responseTree.clear();
                pane.rawEditor.clear();
            }
            if (m_deleteAfterResultDialogClosed)
            {
                m_deleteAfterResultDialogClosed = false;
                deleteLater();
            }
        });
    resultDialog->show();
    resultDialog->raise();
    resultDialog->activateWindow();
}

void VirusTotalOnlineScan::appendRawJsonSection(const QString& titleText, const QJsonObject& jsonObject)
{
    appendRawJsonSection(VtApiKind::ShallowAnalysis, titleText, jsonObject);
}

void VirusTotalOnlineScan::appendRawJsonSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QJsonObject& jsonObject)
{
    appendRawJsonSection(apiKind, titleText, jsonObject, QJsonObject());
}

void VirusTotalOnlineScan::appendRawJsonSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QJsonObject& jsonObject,
    const QJsonObject& responseMetadata)
{
    ensureResultDialog();
    const QString timestampText = utcTimestampText();
    QJsonObject sectionObject;
    sectionObject.insert(QStringLiteral("timestamp_utc"), timestampText);
    sectionObject.insert(QStringLiteral("title"), titleText);
    sectionObject.insert(QStringLiteral("endpoint"), endpointTextFromTitle(titleText));
    sectionObject.insert(QStringLiteral("kind"), QStringLiteral("json"));
    sectionObject.insert(QStringLiteral("body"), jsonObject);
    if (!responseMetadata.isEmpty())
    {
        sectionObject.insert(QStringLiteral("response_metadata"), responseMetadata);
        if (responseMetadata.contains(QStringLiteral("http_status")))
        {
            sectionObject.insert(QStringLiteral("http_status"), responseMetadata.value(QStringLiteral("http_status")));
        }
        if (responseMetadata.contains(QStringLiteral("retry_after")))
        {
            sectionObject.insert(QStringLiteral("retry_after"), responseMetadata.value(QStringLiteral("retry_after")));
        }
    }
    const int index = apiIndex(apiKind);
    m_apiRawSections[static_cast<std::size_t>(index)].append(sectionObject);

    QString& rawText = m_apiRawText[static_cast<std::size_t>(index)];
    rawText += QStringLiteral("\n===== %1 | %2 =====\n")
        .arg(timestampText, titleText);
    if (!responseMetadata.isEmpty())
    {
        rawText += QStringLiteral("[HTTP] %1\n").arg(QString::fromUtf8(QJsonDocument(responseMetadata).toJson(QJsonDocument::Compact)));
    }
    rawText += ks::online_scan::formatJsonObject(jsonObject);
    rawText += QLatin1Char('\n');
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(index)];
    if (!pane.rawEditor.isNull())
    {
        pane.rawEditor->setRawText(rawText);
    }
    QJsonObject treeObject = jsonObject;
    if (!responseMetadata.isEmpty())
    {
        treeObject.insert(QStringLiteral("_ksword_http"), responseMetadata);
    }
    appendResponseTreeJsonSection(apiKind, titleText, timestampText, treeObject);
}

void VirusTotalOnlineScan::appendRawTextSection(const QString& titleText, const QString& detailText)
{
    appendRawTextSection(VtApiKind::ShallowAnalysis, titleText, detailText);
}

void VirusTotalOnlineScan::appendRawTextSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& detailText)
{
    appendRawTextSection(apiKind, titleText, detailText, QJsonObject());
}

void VirusTotalOnlineScan::appendRawTextSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& detailText,
    const QJsonObject& responseMetadata)
{
    ensureResultDialog();
    const QString timestampText = utcTimestampText();
    QJsonObject sectionObject;
    sectionObject.insert(QStringLiteral("timestamp_utc"), timestampText);
    sectionObject.insert(QStringLiteral("title"), titleText);
    sectionObject.insert(QStringLiteral("endpoint"), endpointTextFromTitle(titleText));
    sectionObject.insert(QStringLiteral("kind"), QStringLiteral("text"));
    sectionObject.insert(QStringLiteral("body"), detailText);
    if (!responseMetadata.isEmpty())
    {
        sectionObject.insert(QStringLiteral("response_metadata"), responseMetadata);
        if (responseMetadata.contains(QStringLiteral("http_status")))
        {
            sectionObject.insert(QStringLiteral("http_status"), responseMetadata.value(QStringLiteral("http_status")));
        }
        if (responseMetadata.contains(QStringLiteral("retry_after")))
        {
            sectionObject.insert(QStringLiteral("retry_after"), responseMetadata.value(QStringLiteral("retry_after")));
        }
    }
    const int index = apiIndex(apiKind);
    m_apiRawSections[static_cast<std::size_t>(index)].append(sectionObject);

    QString& rawText = m_apiRawText[static_cast<std::size_t>(index)];
    rawText += QStringLiteral("\n===== %1 | %2 =====\n")
        .arg(timestampText, titleText);
    if (!responseMetadata.isEmpty())
    {
        rawText += QStringLiteral("[HTTP] %1\n").arg(QString::fromUtf8(QJsonDocument(responseMetadata).toJson(QJsonDocument::Compact)));
    }
    rawText += detailText;
    rawText += QLatin1Char('\n');
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(index)];
    if (!pane.rawEditor.isNull())
    {
        pane.rawEditor->setRawText(rawText);
    }
    appendResponseTreeTextSection(apiKind, titleText, timestampText, detailText);
}

void VirusTotalOnlineScan::appendRawReplyBodySection(const QString& titleText, const QByteArray& bodyBytes)
{
    appendRawReplyBodySection(VtApiKind::ShallowAnalysis, titleText, bodyBytes);
}

void VirusTotalOnlineScan::appendRawReplyBodySection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QByteArray& bodyBytes)
{
    appendRawReplyBodySection(apiKind, titleText, bodyBytes, QJsonObject());
}

void VirusTotalOnlineScan::appendRawReplyBodySection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QByteArray& bodyBytes,
    const QJsonObject& responseMetadata)
{
    // 输入：HTTP 完整响应体，可能是 VirusTotal JSON 错误，也可能是网关/代理返回的纯文本。
    // 处理：优先按 JSON 对象保存；无法解析时按 UTF-8 文本保存，空响应体也显式记录。
    // 返回：无；所有数据追加到实时窗口和 m_resultRawSections，供导出 JSON 使用。
    if (bodyBytes.isEmpty())
    {
        appendRawTextSection(apiKind, titleText, QStringLiteral("<空响应体>"), responseMetadata);
        return;
    }

    QJsonParseError parseError;
    const QJsonDocument jsonDocument = QJsonDocument::fromJson(bodyBytes, &parseError);
    if (parseError.error == QJsonParseError::NoError && jsonDocument.isObject())
    {
        appendRawJsonSection(apiKind, titleText, jsonDocument.object(), responseMetadata);
        return;
    }

    appendRawTextSection(apiKind, titleText, QString::fromUtf8(bodyBytes), responseMetadata);
}

QByteArray VirusTotalOnlineScan::buildRawExportJson() const
{
    // rootObject 结构：
    // - metadata：上传来源、样本文件、analysis id、导出时间等上下文；
    // - local_hashes：本地样本 hash；
    // - apis：每个 API Tab 的原始 JSON/文本响应；
    // - legacy raw_text/responses 不再作为顶层字段，避免多 API 数据混在一起。
    QJsonObject metadataObject;
    metadataObject.insert(QStringLiteral("service"), QStringLiteral("VirusTotal"));
    metadataObject.insert(QStringLiteral("source"), m_sourceText);
    metadataObject.insert(QStringLiteral("file_path"), QDir::toNativeSeparators(m_filePath));
    metadataObject.insert(QStringLiteral("file_name"), QFileInfo(m_filePath).fileName());
    metadataObject.insert(QStringLiteral("analysis_id"), m_analysisId);
    metadataObject.insert(QStringLiteral("poll_attempts"), m_pollAttempt);
    metadataObject.insert(QStringLiteral("scan_in_progress"), m_scanInProgress);
    metadataObject.insert(QStringLiteral("settings_json_path"), QDir::toNativeSeparators(m_settingsJsonPath));
    metadataObject.insert(QStringLiteral("api_key_configured"), !m_apiKey.trimmed().isEmpty());
    metadataObject.insert(QStringLiteral("exported_at_utc"), utcTimestampText());

    QJsonObject localHashesObject;
    localHashesObject.insert(QStringLiteral("md5"), m_localHashes.md5Text);
    localHashesObject.insert(QStringLiteral("sha1"), m_localHashes.sha1Text);
    localHashesObject.insert(QStringLiteral("sha256"), m_localHashes.sha256Text);
    localHashesObject.insert(QStringLiteral("ready"), m_localHashes.ready);

    QJsonObject apisObject;
    for (const VtApiKind apiKind : paneApiKinds())
    {
        const int index = apiIndex(apiKind);
        QJsonObject apiObject;
        apiObject.insert(QStringLiteral("title"), apiTitleText(apiKind));
        apiObject.insert(QStringLiteral("state"), apiStateText(m_apiStates[static_cast<std::size_t>(index)]));
        apiObject.insert(QStringLiteral("responses"), m_apiRawSections[static_cast<std::size_t>(index)]);
        apiObject.insert(QStringLiteral("raw_text"), m_apiRawText[static_cast<std::size_t>(index)]);
        apisObject.insert(apiExportKey(apiKind), apiObject);
    }

    QJsonObject rootObject;
    rootObject.insert(QStringLiteral("metadata"), metadataObject);
    rootObject.insert(QStringLiteral("local_hashes"), localHashesObject);
    rootObject.insert(QStringLiteral("apis"), apisObject);
    return QJsonDocument(rootObject).toJson(QJsonDocument::Indented);
}

void VirusTotalOnlineScan::updateResultSummary(const QString& summaryText)
{
    ensureResultDialog();
    if (!m_resultSummaryLabel.isNull())
    {
        m_resultSummaryLabel->setText(summaryText);
    }
}

void VirusTotalOnlineScan::finalizeAutoDeleteIfNeeded()
{
    if (!m_autoDeleteWhenFinished)
    {
        return;
    }
    if (hasActiveApiOperation() ||
        !m_allApiQueue.isEmpty() ||
        !m_deferredApiQueue.isEmpty() ||
        !m_deferredSingleIocRelationships.isEmpty() ||
        m_sandboxHtmlFetchQueued)
    {
        return;
    }

    // 自动删除场景中，结果窗口按钮仍然需要读取 m_resultRawText 和 m_filePath。
    // 因此只要窗口存在，就把对象生命周期延长到窗口关闭；如果窗口尚未创建或已关闭，则直接释放对象。
    if (!m_resultDialog.isNull())
    {
        m_deleteAfterResultDialogClosed = true;
        return;
    }

    deleteLater();
}

QString VirusTotalOnlineScan::buildResultSummary(const QJsonObject& analysisObject) const
{
    const QJsonObject dataObject = analysisObject.value(QStringLiteral("data")).toObject();
    const QJsonObject attributesObject = dataObject.value(QStringLiteral("attributes")).toObject();
    const QJsonObject statsObject = attributesObject.value(QStringLiteral("stats")).toObject();

    // statsObject 作用：承载 VirusTotal 多引擎统计，缺失时仍返回基础 analysis id。
    const int maliciousCount = jsonValueToInt(statsObject, QStringLiteral("malicious"));
    const int suspiciousCount = jsonValueToInt(statsObject, QStringLiteral("suspicious"));
    const int harmlessCount = jsonValueToInt(statsObject, QStringLiteral("harmless"));
    const int undetectedCount = jsonValueToInt(statsObject, QStringLiteral("undetected"));
    const int timeoutCount = jsonValueToInt(statsObject, QStringLiteral("timeout"));
    const int failureCount = jsonValueToInt(statsObject, QStringLiteral("failure"));
    const int unsupportedCount = jsonValueToInt(statsObject, QStringLiteral("type-unsupported"));

    QStringList summaryLines;
    summaryLines << QStringLiteral("文件：%1").arg(QFileInfo(m_filePath).fileName());
    summaryLines << QStringLiteral("AnalysisId：%1").arg(m_analysisId);
    summaryLines << QStringLiteral("状态：%1").arg(attributesObject.value(QStringLiteral("status")).toString(QStringLiteral("未知")));
    summaryLines << QStringLiteral("恶意：%1，可疑：%2，无害：%3，未检出：%4")
        .arg(maliciousCount)
        .arg(suspiciousCount)
        .arg(harmlessCount)
        .arg(undetectedCount);
    summaryLines << QStringLiteral("超时：%1，失败：%2，不支持类型：%3")
        .arg(timeoutCount)
        .arg(failureCount)
        .arg(unsupportedCount);
    return summaryLines.join(QChar('\n'));
}

void VirusTotalOnlineScan::refreshReadableResult(const QJsonObject& analysisObject)
{
    // 输入：VirusTotal /analyses/{id} 的最终 JSON。
    // 处理：从固定字段 data.attributes.stats/results 与 meta.file_info 提取报告视图数据；
    //      检出项按恶意/可疑优先排序，静态分析树保留可展开的关键原始字段。
    // 返回：无；只刷新已创建的报告页控件。
    ensureResultDialog();

    const QList<QAbstractItemView*> itemViews{
        m_fileInfoTable.data(),
        m_engineTable.data(),
        m_staticAnalysisTree.data()
    };
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-readable-result"),
            itemViews,
            [safeThis, analysisObject]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshReadableResult(analysisObject);
                }
            }))
    {
        return;
    }

    const QJsonObject dataObject = analysisObject.value(QStringLiteral("data")).toObject();
    const QJsonObject attributesObject = dataObject.value(QStringLiteral("attributes")).toObject();
    const QJsonObject statsObject = attributesObject.value(QStringLiteral("stats")).toObject();
    const QJsonObject resultsObject = attributesObject.value(QStringLiteral("results")).toObject();
    const QJsonObject metaObject = analysisObject.value(QStringLiteral("meta")).toObject();
    const QJsonObject fileInfoObject = metaObject.value(QStringLiteral("file_info")).toObject();
    const QJsonObject linksObject = dataObject.value(QStringLiteral("links")).toObject();

    const int maliciousCount = jsonValueToInt(statsObject, QStringLiteral("malicious"));
    const int suspiciousCount = jsonValueToInt(statsObject, QStringLiteral("suspicious"));
    const int harmlessCount = jsonValueToInt(statsObject, QStringLiteral("harmless"));
    const int undetectedCount = jsonValueToInt(statsObject, QStringLiteral("undetected"));
    const int timeoutCount = jsonValueToInt(statsObject, QStringLiteral("timeout"));
    const int confirmedTimeoutCount = jsonValueToInt(statsObject, QStringLiteral("confirmed-timeout"));
    const int failureCount = jsonValueToInt(statsObject, QStringLiteral("failure"));
    const int unsupportedCount = jsonValueToInt(statsObject, QStringLiteral("type-unsupported"));
    const int detectedCount = maliciousCount + suspiciousCount;
    const int engineTotal = maliciousCount + suspiciousCount + harmlessCount + undetectedCount +
        timeoutCount + confirmedTimeoutCount + failureCount + unsupportedCount;

    const QString statusText = attributesObject.value(QStringLiteral("status")).toString(QStringLiteral("未知"));
    const QString sha256Text = fileInfoObject.value(QStringLiteral("sha256")).toString();
    const QString sha1Text = fileInfoObject.value(QStringLiteral("sha1")).toString();
    const QString md5Text = fileInfoObject.value(QStringLiteral("md5")).toString();
    const qint64 vtSizeBytes = static_cast<qint64>(fileInfoObject.value(QStringLiteral("size")).toDouble(-1.0));
    const QFileInfo localFileInfo(m_filePath);
    const qint64 displaySizeBytes = vtSizeBytes >= 0 ? vtSizeBytes : localFileInfo.size();

    const ReportVerdict verdict = reportVerdictFromStats(maliciousCount, suspiciousCount, harmlessCount);

    if (!m_readableOverviewLabel.isNull())
    {
        const QString verdictColorText = verdict.accentColor.isValid()
            ? verdict.accentColor.name(QColor::HexRgb)
            : KswordTheme::TextPrimaryColorHex();
        m_readableOverviewLabel->setText(QStringLiteral(
            "<table cellspacing='0' cellpadding='0'>"
            "<tr>"
            "<td width='124'><img src='%1' width='104' height='104'/></td>"
            "<td>"
            "<div style='font-size:22px;font-weight:700;'>%2</div>"
            "<div style='margin-top:6px;'>"
            "<span style='color:%3;font-size:18px;font-weight:700;'>%4</span>"
            "&nbsp;&nbsp; 检出率：<span style='color:%3;font-weight:700;'>%5 / %6</span>"
            "&nbsp;&nbsp; 状态：%7"
            "</div>"
            "<div style='margin-top:6px;'>AnalysisId：%8</div>"
            "</td>"
            "</tr>"
            "</table>")
            .arg(verdict.iconPath)
            .arg(localFileInfo.fileName().toHtmlEscaped().isEmpty()
                ? QStringLiteral("<未知文件>")
                : localFileInfo.fileName().toHtmlEscaped())
            .arg(verdictColorText)
            .arg(verdict.labelText.toHtmlEscaped())
            .arg(detectedCount)
            .arg(engineTotal)
            .arg(statusText.toHtmlEscaped())
            .arg(m_analysisId.toHtmlEscaped()));
    }

    if (!m_fileInfoTable.isNull())
    {
        m_fileInfoTable->setRowCount(0);
        setTableRow(m_fileInfoTable, 0, QStringLiteral("文件名"), localFileInfo.fileName());
        setTableRow(m_fileInfoTable, 1, QStringLiteral("文件大小"), formatByteCount(displaySizeBytes));
        setTableRow(m_fileInfoTable, 2, QStringLiteral("SHA256"), sha256Text.isEmpty() ? QStringLiteral("-") : sha256Text);
        setTableRow(m_fileInfoTable, 3, QStringLiteral("SHA1"), sha1Text.isEmpty() ? QStringLiteral("-") : sha1Text);
        setTableRow(m_fileInfoTable, 4, QStringLiteral("MD5"), md5Text.isEmpty() ? QStringLiteral("-") : md5Text);
        setTableRow(m_fileInfoTable, 5, QStringLiteral("AnalysisId"), dataObject.value(QStringLiteral("id")).toString(m_analysisId));
        setTableRow(m_fileInfoTable, 6, QStringLiteral("分析时间"), unixDateText(static_cast<qint64>(attributesObject.value(QStringLiteral("date")).toDouble(0.0))));
        setTableRow(m_fileInfoTable, 7, QStringLiteral("VT 文件链接"), linksObject.value(QStringLiteral("item")).toString(QStringLiteral("-")));
        fitTableHeightToRows(m_fileInfoTable);
    }

    if (!m_engineTable.isNull())
    {
        struct EngineRow
        {
            QString engineText;
            QString categoryRawText;
            QString resultText;
            QString versionText;
            QString updateText;
        };
        std::vector<EngineRow> engineRows;
        engineRows.reserve(static_cast<std::size_t>(resultsObject.size()));
        for (auto iterator = resultsObject.constBegin(); iterator != resultsObject.constEnd(); ++iterator)
        {
            const QJsonObject engineObject = iterator.value().toObject();
            EngineRow row;
            row.engineText = engineObject.value(QStringLiteral("engine_name")).toString(iterator.key());
            row.categoryRawText = engineObject.value(QStringLiteral("category")).toString();
            row.resultText = engineObject.value(QStringLiteral("result")).toString();
            row.versionText = engineObject.value(QStringLiteral("engine_version")).toString();
            row.updateText = engineObject.value(QStringLiteral("engine_update")).toString();
            engineRows.push_back(row);
        }
        std::sort(engineRows.begin(), engineRows.end(), [](const EngineRow& left, const EngineRow& right)
            {
                const int leftPriority = categoryPriority(left.categoryRawText);
                const int rightPriority = categoryPriority(right.categoryRawText);
                if (leftPriority != rightPriority)
                {
                    return leftPriority < rightPriority;
                }
                return QString::localeAwareCompare(left.engineText, right.engineText) < 0;
            });

        const int tableRowCount = static_cast<int>((engineRows.size() + 1) / 2);
        m_engineTable->clearContents();
        m_engineTable->setRowCount(tableRowCount);
        for (int visibleIndex = 0; visibleIndex < static_cast<int>(engineRows.size()); ++visibleIndex)
        {
            const EngineRow& row = engineRows[static_cast<std::size_t>(visibleIndex)];
            const QColor rowColor = categoryColor(row.categoryRawText);
            const QString versionText = row.versionText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : row.versionText.trimmed();
            const QString updateText = row.updateText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : row.updateText.trimmed();
            const QString tooltipText = QStringLiteral("版本：%1\n更新时间：%2").arg(versionText, updateText);
            const int tableRow = visibleIndex / 2;
            const int tableColumn = (visibleIndex % 2) * 2;

            QTableWidgetItem* engineItem = createReadOnlyTableItem(row.engineText);
            QTableWidgetItem* resultItem = createReadOnlyTableItem(
                engineDetectionText(row.categoryRawText, row.resultText),
                rowColor);
            engineItem->setToolTip(tooltipText);
            resultItem->setToolTip(tooltipText);
            m_engineTable->setItem(tableRow, tableColumn, engineItem);
            m_engineTable->setItem(tableRow, tableColumn + 1, resultItem);
            m_engineTable->setRowHeight(tableRow, 22);
        }
    }

    if (!m_staticAnalysisTree.isNull())
    {
        m_staticAnalysisTree->clear();
        QTreeWidgetItem* basicItem = new QTreeWidgetItem(m_staticAnalysisTree);
        basicItem->setText(0, QStringLiteral("基础信息"));
        basicItem->setText(1, QStringLiteral("文件与 Analysis 上下文"));
        addTreeLeaf(basicItem, QStringLiteral("文件名"), localFileInfo.fileName());
        addTreeLeaf(basicItem, QStringLiteral("大小"), formatByteCount(displaySizeBytes));
        addTreeLeaf(basicItem, QStringLiteral("SHA256"), sha256Text.isEmpty() ? QStringLiteral("-") : sha256Text);
        addTreeLeaf(basicItem, QStringLiteral("SHA1"), sha1Text.isEmpty() ? QStringLiteral("-") : sha1Text);
        addTreeLeaf(basicItem, QStringLiteral("MD5"), md5Text.isEmpty() ? QStringLiteral("-") : md5Text);

        QTreeWidgetItem* analysisItem = new QTreeWidgetItem(m_staticAnalysisTree);
        analysisItem->setText(0, QStringLiteral("分析任务"));
        analysisItem->setText(1, QStringLiteral("VirusTotal analysis"));
        addTreeLeaf(analysisItem, QStringLiteral("AnalysisId"), dataObject.value(QStringLiteral("id")).toString(m_analysisId));
        addTreeLeaf(analysisItem, QStringLiteral("状态"), statusText);
        addTreeLeaf(analysisItem, QStringLiteral("提交/分析时间"), unixDateText(static_cast<qint64>(attributesObject.value(QStringLiteral("date")).toDouble(0.0))));
        addTreeLeaf(analysisItem, QStringLiteral("Self 链接"), linksObject.value(QStringLiteral("self")).toString(QStringLiteral("-")));
        addTreeLeaf(analysisItem, QStringLiteral("File 链接"), linksObject.value(QStringLiteral("item")).toString(QStringLiteral("-")));

        QTreeWidgetItem* statsItem = new QTreeWidgetItem(m_staticAnalysisTree);
        statsItem->setText(0, QStringLiteral("统计字段"));
        statsItem->setText(1, QStringLiteral("data.attributes.stats"));
        appendJsonValueToTree(statsItem, QStringLiteral("stats"), statsObject);

        QTreeWidgetItem* rawAttributesItem = new QTreeWidgetItem(m_staticAnalysisTree);
        rawAttributesItem->setText(0, QStringLiteral("原始 attributes"));
        rawAttributesItem->setText(1, QStringLiteral("可展开查看 VT 固定字段"));
        appendJsonValueToTree(rawAttributesItem, QStringLiteral("attributes"), attributesObject);

        basicItem->setExpanded(true);
        analysisItem->setExpanded(true);
        statsItem->setExpanded(true);
        m_staticAnalysisTree->resizeColumnToContents(0);
    }

    if (!m_resultTabWidget.isNull())
    {
        m_resultTabWidget->setCurrentIndex(0);
    }
}

void VirusTotalOnlineScan::refreshFileProfileResult(const QJsonObject& fileObject)
{
    ensureResultDialog();
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(apiIndex(VtApiKind::FileProfile))];
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-file-profile-result"),
            {pane.reportTree.data()},
            [safeThis, fileObject]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshFileProfileResult(fileObject);
                }
            }))
    {
        return;
    }
    if (pane.startButton)
    {
        pane.startButton->setVisible(false);
    }

    const QJsonObject dataObject = fileObject.value(QStringLiteral("data")).toObject();
    const QJsonObject attributesObject = dataObject.value(QStringLiteral("attributes")).toObject();
    const QString meaningfulName = attributesObject.value(QStringLiteral("meaningful_name")).toString(QFileInfo(m_filePath).fileName());
    const QString typeText = attributesObject.value(QStringLiteral("type_description")).toString(
        attributesObject.value(QStringLiteral("type_tag")).toString(QStringLiteral("-")));
    const int reputation = attributesObject.value(QStringLiteral("reputation")).toInt(0);

    if (pane.overviewLabel)
    {
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:22px;font-weight:700;'>%1</div>"
            "<div style='margin-top:6px;'>类型：%2&nbsp;&nbsp; Reputation：%3</div>"
            "<div style='margin-top:6px;'>SHA256：%4</div>")
            .arg(meaningfulName.toHtmlEscaped())
            .arg(typeText.toHtmlEscaped())
            .arg(reputation)
            .arg(m_localHashes.sha256Text.toHtmlEscaped()));
    }
    if (!pane.reportTree)
    {
        return;
    }

    pane.reportTree->clear();
    QTreeWidgetItem* basicItem = new QTreeWidgetItem(pane.reportTree);
    basicItem->setText(0, QStringLiteral("文件画像"));
    basicItem->setText(1, QStringLiteral("基础属性"));
    addTreeLeaf(basicItem, QStringLiteral("名称"), meaningfulName);
    addTreeLeaf(basicItem, QStringLiteral("类型描述"), typeText);
    addTreeLeaf(basicItem, QStringLiteral("类型标签"), attributesObject.value(QStringLiteral("type_tag")).toString(QStringLiteral("-")));
    addTreeLeaf(basicItem, QStringLiteral("提交次数"), QString::number(attributesObject.value(QStringLiteral("times_submitted")).toInt(0)));
    addTreeLeaf(basicItem, QStringLiteral("Reputation"), QString::number(reputation));
    addTreeLeaf(basicItem, QStringLiteral("首次提交"), unixDateText(static_cast<qint64>(attributesObject.value(QStringLiteral("first_submission_date")).toDouble(0.0))));
    addTreeLeaf(basicItem, QStringLiteral("最后提交"), unixDateText(static_cast<qint64>(attributesObject.value(QStringLiteral("last_submission_date")).toDouble(0.0))));
    addTreeLeaf(basicItem, QStringLiteral("最后分析"), unixDateText(static_cast<qint64>(attributesObject.value(QStringLiteral("last_analysis_date")).toDouble(0.0))));
    addTreeLeaf(basicItem, QStringLiteral("MD5"), attributesObject.value(QStringLiteral("md5")).toString(m_localHashes.md5Text));
    addTreeLeaf(basicItem, QStringLiteral("SHA1"), attributesObject.value(QStringLiteral("sha1")).toString(m_localHashes.sha1Text));
    addTreeLeaf(basicItem, QStringLiteral("SHA256"), attributesObject.value(QStringLiteral("sha256")).toString(m_localHashes.sha256Text));
    addTreeLeaf(basicItem, QStringLiteral("SSDEEP"), attributesObject.value(QStringLiteral("ssdeep")).toString(QStringLiteral("-")));
    addTreeLeaf(basicItem, QStringLiteral("TLSH"), attributesObject.value(QStringLiteral("tlsh")).toString(QStringLiteral("-")));
    addTreeLeaf(basicItem, QStringLiteral("Authentihash"), attributesObject.value(QStringLiteral("authentihash")).toString(QStringLiteral("-")));

    QTreeWidgetItem* namesItem = new QTreeWidgetItem(pane.reportTree);
    namesItem->setText(0, QStringLiteral("名称 / 标签 / 投票"));
    namesItem->setText(1, QStringLiteral("可展开"));
    appendJsonValueToTree(namesItem, QStringLiteral("names"), attributesObject.value(QStringLiteral("names")));
    appendJsonValueToTree(namesItem, QStringLiteral("tags"), attributesObject.value(QStringLiteral("tags")));
    appendJsonValueToTree(namesItem, QStringLiteral("total_votes"), attributesObject.value(QStringLiteral("total_votes")));
    appendJsonValueToTree(namesItem, QStringLiteral("sandbox_verdicts"), attributesObject.value(QStringLiteral("sandbox_verdicts")));

    QTreeWidgetItem* peItem = new QTreeWidgetItem(pane.reportTree);
    peItem->setText(0, QStringLiteral("PE 信息"));
    peItem->setText(1, attributesObject.contains(QStringLiteral("pe_info")) ? QStringLiteral("pe_info") : QStringLiteral("无 PE 信息"));
    appendJsonValueToTree(peItem, QStringLiteral("pe_info"), attributesObject.value(QStringLiteral("pe_info")));

    QTreeWidgetItem* signatureItem = new QTreeWidgetItem(pane.reportTree);
    signatureItem->setText(0, QStringLiteral("签名信息"));
    signatureItem->setText(1, attributesObject.contains(QStringLiteral("signature_info")) ? QStringLiteral("signature_info") : QStringLiteral("无签名信息"));
    appendJsonValueToTree(signatureItem, QStringLiteral("signature_info"), attributesObject.value(QStringLiteral("signature_info")));

    QTreeWidgetItem* rawItem = new QTreeWidgetItem(pane.reportTree);
    rawItem->setText(0, QStringLiteral("原始 attributes"));
    rawItem->setText(1, QStringLiteral("完整字段"));
    appendJsonValueToTree(rawItem, QStringLiteral("attributes"), attributesObject);

    basicItem->setExpanded(true);
    namesItem->setExpanded(true);
    peItem->setExpanded(true);
    signatureItem->setExpanded(true);
    if (!pane.fileProfileFilterEdit.isNull())
    {
        applyTreeFilter(pane.reportTree, pane.fileProfileFilterEdit->text());
    }
    pane.reportTree->resizeColumnToContents(0);
}

void VirusTotalOnlineScan::refreshIocResult()
{
    ensureResultDialog();
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(apiIndex(VtApiKind::Ioc))];
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-ioc-result"),
            {pane.reportTree.data()},
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshIocResult();
                }
            }))
    {
        return;
    }
    if (pane.startButton)
    {
        pane.startButton->setVisible(m_apiStates[static_cast<std::size_t>(apiIndex(VtApiKind::Ioc))] != VtApiState::Completed);
    }
    if (pane.overviewLabel)
    {
        int totalCount = 0;
        for (const QString& relationshipText : iocRelationships())
        {
            totalCount += m_iocRelationshipObjects.value(relationshipText).toObject().value(QStringLiteral("data")).toArray().size();
        }
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:22px;font-weight:700;'>IOC 关系</div>"
            "<div style='margin-top:6px;'>已请求 %1 类关系，命中对象 %2 个。</div>"
            "<div style='margin-top:6px;'>SHA256：%3</div>")
            .arg(iocRelationships().size())
            .arg(totalCount)
            .arg(m_localHashes.sha256Text.toHtmlEscaped()));
    }
    if (!pane.reportTree)
    {
        return;
    }

    pane.reportTree->clear();
    bool hasAnyData = false;
    for (const QString& relationshipText : iocRelationships())
    {
        const QJsonObject relationshipObject = m_iocRelationshipObjects.value(relationshipText).toObject();
        const QJsonArray dataArray = relationshipObject.value(QStringLiteral("data")).toArray();
        QTreeWidgetItem* relationshipItem = new QTreeWidgetItem(pane.reportTree);
        relationshipItem->setText(0, relationshipDisplayText(relationshipText));
        relationshipItem->setText(1, relationshipObject.contains(QStringLiteral("error"))
            ? relationshipObject.value(QStringLiteral("error")).toString()
            : relationshipObject.value(QStringLiteral("empty_reason")).toString(QStringLiteral("%1 项").arg(dataArray.size())));
        if (!dataArray.isEmpty())
        {
            hasAnyData = true;
        }
        for (int itemIndex = 0; itemIndex < dataArray.size(); ++itemIndex)
        {
            const QJsonObject itemObject = dataArray.at(itemIndex).toObject();
            QTreeWidgetItem* objectItem = new QTreeWidgetItem(relationshipItem);
            objectItem->setText(0, jsonValueCompactText(itemObject.value(QStringLiteral("id"))));
            objectItem->setText(1, itemObject.value(QStringLiteral("type")).toString(QStringLiteral("{Object}")));
            appendJsonValueToTree(objectItem, QStringLiteral("object"), itemObject);
        }
        relationshipItem->setExpanded(true);
    }

    if (!hasAnyData)
    {
        QTreeWidgetItem* emptyItem = new QTreeWidgetItem(pane.reportTree);
        emptyItem->setText(0, QStringLiteral("结果"));
        emptyItem->setText(1, QStringLiteral("VT 暂无该文件的常用 IOC 关系数据。"));
    }
    pane.reportTree->resizeColumnToContents(0);
}

void VirusTotalOnlineScan::refreshSandboxResult()
{
    ensureResultDialog();
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(apiIndex(VtApiKind::Sandbox))];
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-sandbox-result"),
            {pane.reportTree.data()},
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshSandboxResult();
                }
            }))
    {
        return;
    }
    const QJsonArray behavioursArray = m_sandboxBehavioursObject.value(QStringLiteral("data")).toArray();
    int htmlAvailableCount = 0;
    for (const QJsonValue& behaviourValue : behavioursArray)
    {
        const QJsonObject behaviourObject = behaviourValue.toObject();
        if (behaviourObject.value(QStringLiteral("attributes")).toObject().value(QStringLiteral("has_html_report")).toBool(false))
        {
            ++htmlAvailableCount;
        }
    }
    if (pane.startButton)
    {
        pane.startButton->setVisible(m_apiStates[static_cast<std::size_t>(apiIndex(VtApiKind::Sandbox))] != VtApiState::Completed);
    }
    if (pane.sandboxHtmlButton)
    {
        pane.sandboxHtmlButton->setVisible(htmlAvailableCount > m_sandboxHtmlReports.size());
    }
    if (pane.sandboxHtmlPreviewGroup && m_sandboxHtmlReports.isEmpty())
    {
        pane.sandboxHtmlPreviewGroup->setVisible(false);
    }
    if (pane.overviewLabel)
    {
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:22px;font-weight:700;'>沙箱行为分析</div>"
            "<div style='margin-top:6px;'>沙箱报告：%1 个，HTML 可用：%2 个，已拉取：%3 个。</div>"
            "<div style='margin-top:6px;'>SHA256：%4</div>")
            .arg(behavioursArray.size())
            .arg(htmlAvailableCount)
            .arg(m_sandboxHtmlReports.size())
            .arg(m_localHashes.sha256Text.toHtmlEscaped()));
    }
    if (!pane.reportTree)
    {
        return;
    }

    pane.reportTree->clear();
    const QJsonObject summaryDataObject = m_sandboxSummaryObject.value(QStringLiteral("data")).toObject();
    QTreeWidgetItem* summaryItem = new QTreeWidgetItem(pane.reportTree);
    summaryItem->setText(0, QStringLiteral("行为汇总"));
    summaryItem->setText(1, summaryDataObject.isEmpty() ? QStringLiteral("无汇总数据") : QStringLiteral("{ %1 fields }").arg(summaryDataObject.size()));
    const QStringList commonSummaryKeys = QStringList()
        << QStringLiteral("processes_tree")
        << QStringLiteral("processes_created")
        << QStringLiteral("processes_terminated")
        << QStringLiteral("command_executions")
        << QStringLiteral("files_opened")
        << QStringLiteral("files_written")
        << QStringLiteral("files_deleted")
        << QStringLiteral("files_dropped")
        << QStringLiteral("registry_keys_opened")
        << QStringLiteral("registry_keys_set")
        << QStringLiteral("registry_keys_deleted")
        << QStringLiteral("mutexes_created")
        << QStringLiteral("dns_lookups")
        << QStringLiteral("ip_traffic")
        << QStringLiteral("http_conversations")
        << QStringLiteral("tcp_connections")
        << QStringLiteral("udp_conversations")
        << QStringLiteral("contacted_ips")
        << QStringLiteral("contacted_domains")
        << QStringLiteral("contacted_urls")
        << QStringLiteral("ids_alerts")
        << QStringLiteral("mitre_attack_techniques")
        << QStringLiteral("sigma_analysis_results")
        << QStringLiteral("signature_matches");
    for (const QString& keyText : commonSummaryKeys)
    {
        if (summaryDataObject.contains(keyText))
        {
            appendJsonValueToTree(summaryItem, keyText, summaryDataObject.value(keyText));
        }
    }

    QTreeWidgetItem* behavioursItem = new QTreeWidgetItem(pane.reportTree);
    behavioursItem->setText(0, QStringLiteral("单沙箱报告"));
    behavioursItem->setText(1, QStringLiteral("%1 个").arg(behavioursArray.size()));
    for (const QJsonValue& behaviourValue : behavioursArray)
    {
        const QJsonObject behaviourObject = behaviourValue.toObject();
        const QJsonObject attributesObject = behaviourObject.value(QStringLiteral("attributes")).toObject();
        const QString behaviourId = behaviourObject.value(QStringLiteral("id")).toString();
        QTreeWidgetItem* behaviourItem = new QTreeWidgetItem(behavioursItem);
        behaviourItem->setText(0, attributesObject.value(QStringLiteral("sandbox_name")).toString(behaviourId));
        behaviourItem->setText(1, QStringLiteral("HTML:%1 PCAP:%2 EVTX:%3 MEM:%4")
            .arg(attributesObject.value(QStringLiteral("has_html_report")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无"))
            .arg(attributesObject.value(QStringLiteral("has_pcap")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无"))
            .arg(attributesObject.value(QStringLiteral("has_evtx")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无"))
            .arg(attributesObject.value(QStringLiteral("has_memdump")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无")));
        if (attributesObject.value(QStringLiteral("has_html_report")).toBool(false) && !behaviourId.isEmpty())
        {
            behaviourItem->setData(0, Qt::UserRole, behaviourId);
            behaviourItem->setToolTip(0, QStringLiteral("双击查看 HTML 沙箱报告：%1").arg(behaviourId));
            behaviourItem->setToolTip(1, QStringLiteral("双击查看 HTML 沙箱报告"));
        }
        addTreeLeaf(behaviourItem, QStringLiteral("ID"), behaviourId);
        addTreeLeaf(behaviourItem, QStringLiteral("分析时间"), unixDateText(static_cast<qint64>(attributesObject.value(QStringLiteral("analysis_date")).toDouble(0.0))));
        addTreeLeaf(behaviourItem, QStringLiteral("behash"), attributesObject.value(QStringLiteral("behash")).toString(QStringLiteral("-")));
        if (attributesObject.value(QStringLiteral("has_html_report")).toBool(false) && !behaviourId.isEmpty())
        {
            QTreeWidgetItem* htmlActionItem = addTreeLeaf(
                behaviourItem,
                QStringLiteral("查看HTML报告"),
                m_sandboxHtmlReports.contains(behaviourId) ? QStringLiteral("已拉取，双击在下方预览") : QStringLiteral("双击开始拉取"));
            if (htmlActionItem != nullptr)
            {
                htmlActionItem->setData(0, Qt::UserRole, behaviourId);
                htmlActionItem->setToolTip(0, QStringLiteral("双击查看 HTML 沙箱报告：%1").arg(behaviourId));
                htmlActionItem->setToolTip(1, QStringLiteral("双击触发 GET /api/v3/file_behaviours/%1/html").arg(behaviourId));
            }
        }
        appendJsonValueToTree(behaviourItem, QStringLiteral("attributes"), attributesObject);
    }

    QTreeWidgetItem* htmlItem = new QTreeWidgetItem(pane.reportTree);
    htmlItem->setText(0, QStringLiteral("HTML 报告"));
    htmlItem->setText(1, QStringLiteral("已拉取 %1 个").arg(m_sandboxHtmlReports.size()));
    for (auto iterator = m_sandboxHtmlReports.constBegin(); iterator != m_sandboxHtmlReports.constEnd(); ++iterator)
    {
        const QJsonObject htmlObject = iterator.value().toObject();
        QTreeWidgetItem* reportItem = new QTreeWidgetItem(htmlItem);
        reportItem->setText(0, iterator.key());
        if (htmlObject.contains(QStringLiteral("error")))
        {
            reportItem->setText(1, htmlObject.value(QStringLiteral("error")).toString());
        }
        else if (htmlObject.contains(QStringLiteral("empty_reason")))
        {
            reportItem->setText(1, htmlObject.value(QStringLiteral("empty_reason")).toString());
        }
        else
        {
            const QString htmlText = htmlObject.value(QStringLiteral("html")).toString();
            reportItem->setText(1, QStringLiteral("HTML 已保存，长度 %1 字符").arg(htmlText.size()));
            addTreeLeaf(
                reportItem,
                QStringLiteral("HTML 预览"),
                htmlText.left(1200).replace(QChar('\n'), QChar(' ')).replace(QChar('\r'), QChar(' ')));
        }
    }

    summaryItem->setExpanded(true);
    behavioursItem->setExpanded(true);
    htmlItem->setExpanded(true);
    pane.reportTree->resizeColumnToContents(0);
}

void VirusTotalOnlineScan::showSandboxHtmlPreview(const QString& behaviourId)
{
    // 输入：一个已拉取或已记录错误的 file_behaviour id。
    // 处理：在沙箱报告视图下方显示 HTML 渲染内容；错误/空状态以紧凑文本卡片显示。
    // 返回：无；控件不存在或 id 不存在时静默返回，避免影响原始数据保存。
    const QString trimmedId = behaviourId.trimmed();
    if (trimmedId.isEmpty())
    {
        return;
    }

    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(apiIndex(VtApiKind::Sandbox))];
    if (pane.sandboxHtmlPreviewGroup.isNull() || pane.sandboxHtmlPreview.isNull())
    {
        return;
    }

    const QJsonObject htmlObject = m_sandboxHtmlReports.value(trimmedId).toObject();
    if (htmlObject.isEmpty())
    {
        return;
    }

    QString previewHtml;
    if (htmlObject.contains(QStringLiteral("html")))
    {
        previewHtml = htmlObject.value(QStringLiteral("html")).toString();
        if (previewHtml.trimmed().isEmpty())
        {
            previewHtml = QStringLiteral(
                "<div style='font-family:Segoe UI,Microsoft YaHei,sans-serif;padding:12px;'>"
                "<b>HTML 报告为空</b><br/>该沙箱对象返回了空 HTML。"
                "</div>");
        }
    }
    else
    {
        const QString messageText = htmlObject.contains(QStringLiteral("empty_reason"))
            ? htmlObject.value(QStringLiteral("empty_reason")).toString()
            : htmlObject.value(QStringLiteral("error")).toString(QStringLiteral("HTML 报告暂不可用。"));
        previewHtml = QStringLiteral(
            "<div style='font-family:Segoe UI,Microsoft YaHei,sans-serif;padding:12px;'>"
            "<div style='font-size:16px;font-weight:700;margin-bottom:8px;'>HTML 报告暂不可用</div>"
            "<pre style='white-space:pre-wrap;margin:0;'>%1</pre>"
            "</div>")
            .arg(messageText.toHtmlEscaped());
    }

    pane.sandboxHtmlPreviewGroup->setTitle(QStringLiteral("HTML 报告预览 - %1").arg(trimmedId));
    pane.sandboxHtmlPreview->setHtml(previewHtml);
    pane.sandboxHtmlPreviewGroup->setVisible(true);
    if (!pane.detailTabWidget.isNull())
    {
        pane.detailTabWidget->setCurrentIndex(0);
    }
}

void VirusTotalOnlineScan::appendResponseTreeJsonSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& timestampText,
    const QJsonObject& jsonObject)
{
    // 输入：一个已解析的 VT JSON 响应。
    // 处理：追加为响应详情页顶层节点，下级递归展开 JSON 字段。
    // 返回：无。
    const int index = apiIndex(apiKind);
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(index)];
    if (pane.responseTree.isNull())
    {
        return;
    }

    QTreeWidgetItem* sectionItem = new QTreeWidgetItem(pane.responseTree);
    sectionItem->setText(0, titleText);
    sectionItem->setText(1, QStringLiteral("{ %1 fields }").arg(jsonObject.size()));
    sectionItem->setText(2, timestampText);
    sectionItem->setExpanded(false);
    for (auto iterator = jsonObject.constBegin(); iterator != jsonObject.constEnd(); ++iterator)
    {
        appendJsonValueToTree(sectionItem, iterator.key(), iterator.value());
    }
    pane.responseTree->scrollToItem(sectionItem);
}

void VirusTotalOnlineScan::appendResponseTreeTextSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& timestampText,
    const QString& detailText)
{
    // 输入：一个非 JSON 响应或本地错误详情。
    // 处理：追加为响应详情页顶层节点，正文放在子节点中，避免撑开表头。
    // 返回：无。
    const int index = apiIndex(apiKind);
    ApiPaneUi& pane = m_apiPanes[static_cast<std::size_t>(index)];
    if (pane.responseTree.isNull())
    {
        return;
    }

    QTreeWidgetItem* sectionItem = new QTreeWidgetItem(pane.responseTree);
    sectionItem->setText(0, titleText);
    sectionItem->setText(1, QStringLiteral("text"));
    sectionItem->setText(2, timestampText);
    addTreeLeaf(sectionItem, QStringLiteral("详情"), detailText);
    sectionItem->setExpanded(true);
    pane.responseTree->scrollToItem(sectionItem);
}
