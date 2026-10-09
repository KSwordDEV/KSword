#include "OnlineScanSupport.h"
#include "../UI/DetailDialogChrome.h"

#include "../UI/CodeEditorWidget.h"
#include "../theme.h"

#include <QCryptographicHash>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QMessageBox>
#include <QNetworkReply>
#include <QPushButton>
#include <QVBoxLayout>

namespace
{
    // formatByteCount 作用：
    // - 把字节数格式化为人类可读文本；
    // - 文件大小错误提示会调用该函数。
    // 入参 byteCount：原始字节数。
    // 返回：带单位的大小字符串。
    QString formatByteCount(const qint64 byteCount)
    {
        const double mibValue = static_cast<double>(byteCount) / 1024.0 / 1024.0;
        return QStringLiteral("%1 MB").arg(mibValue, 0, 'f', 2);
    }

    // compactBodyPreview 作用：
    // - 将 HTTP 响应体压缩为有限长度预览；
    // - 避免错误弹窗因服务端返回大 JSON 而撑爆窗口。
    // 入参 bodyBytes：原始响应体。
    // 返回：最多约 4096 字符的预览文本。
    QString compactBodyPreview(const QByteArray& bodyBytes)
    {
        QString previewText = QString::fromUtf8(bodyBytes).trimmed();
        previewText.replace(QChar('\r'), QChar(' '));
        previewText.replace(QChar('\n'), QChar(' '));
        if (previewText.size() > 4096)
        {
            previewText = previewText.left(4096) + QStringLiteral(" ...");
        }
        return previewText;
    }
}

bool ks::online_scan::validateReadableFile(
    const QString& filePath,
    const qint64 maxBytes,
    QString* errorTextOut)
{
    const QString normalizedPath = filePath.trimmed();
    if (normalizedPath.isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件路径为空。");
        }
        return false;
    }

    // fileInfo 作用：承载输入路径的文件属性，后续用于存在性、类型和大小检查。
    const QFileInfo fileInfo(normalizedPath);
    if (!fileInfo.exists())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件不存在：%1").arg(normalizedPath);
        }
        return false;
    }
    if (!fileInfo.isFile())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("目标不是普通文件：%1").arg(normalizedPath);
        }
        return false;
    }
    if (!fileInfo.isReadable())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件不可读：%1").arg(normalizedPath);
        }
        return false;
    }

    // fileSizeBytes 作用：检查在线扫描服务对上传样本大小的硬性限制。
    const qint64 fileSizeBytes = fileInfo.size();
    if (maxBytes > 0 && fileSizeBytes > maxBytes)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件大小 %1 超过当前服务允许的 %2。")
                .arg(formatByteCount(fileSizeBytes), formatByteCount(maxBytes));
        }
        return false;
    }
    return true;
}

QString ks::online_scan::sanitizeFileNameForContentDisposition(const QString& fileName)
{
    QString safeFileName = fileName.trimmed();
    if (safeFileName.isEmpty())
    {
        safeFileName = QStringLiteral("sample.bin");
    }

    // Content-Disposition 的 filename 不能直接接受引号或路径分隔符。
    safeFileName.replace(QChar('"'), QChar('_'));
    safeFileName.replace(QChar('/'), QChar('_'));
    safeFileName.replace(QChar('\\'), QChar('_'));
    return safeFileName;
}

QJsonObject ks::online_scan::parseJsonObjectFromBytes(const QByteArray& bodyBytes, QString* errorTextOut)
{
    QJsonParseError parseError;
    const QJsonDocument jsonDocument = QJsonDocument::fromJson(bodyBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("JSON 解析失败：%1").arg(parseError.errorString());
        }
        return QJsonObject();
    }
    if (!jsonDocument.isObject())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("响应不是 JSON 对象。");
        }
        return QJsonObject();
    }
    return jsonDocument.object();
}

QString ks::online_scan::formatJsonObject(const QJsonObject& jsonObject)
{
    const QJsonDocument jsonDocument(jsonObject);
    return QString::fromUtf8(jsonDocument.toJson(QJsonDocument::Indented));
}

QString ks::online_scan::networkReplyErrorText(QNetworkReply* reply, const QByteArray& bodyBytes)
{
    if (reply == nullptr)
    {
        return QStringLiteral("网络响应对象为空。");
    }

    // statusCode 作用：记录 HTTP 层状态码，Qt 网络错误之外仍需展示。
    const QVariant statusCodeVariant = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    const int statusCode = statusCodeVariant.isValid() ? statusCodeVariant.toInt() : 0;
    const QString bodyPreviewText = compactBodyPreview(bodyBytes);

    QStringList messageLines;
    messageLines << QStringLiteral("HTTP 状态码：%1").arg(statusCode == 0 ? QStringLiteral("未知") : QString::number(statusCode));
    messageLines << QStringLiteral("Qt 网络错误：%1 (%2)")
        .arg(static_cast<int>(reply->error()))
        .arg(reply->errorString());
    if (!bodyPreviewText.isEmpty())
    {
        messageLines << QStringLiteral("响应摘要：%1").arg(bodyPreviewText);
    }
    return messageLines.join(QChar('\n'));
}

QString ks::online_scan::calculateSha256Hex(const QString& filePath, QString* errorTextOut)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadOnly))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("打开文件失败：%1").arg(inputFile.errorString());
        }
        return QString();
    }

    // sha256Hasher 作用：以流式方式累计文件内容，避免读取大文件时占用过多内存。
    QCryptographicHash sha256Hasher(QCryptographicHash::Sha256);
    while (!inputFile.atEnd())
    {
        const QByteArray chunkBytes = inputFile.read(1024 * 1024);
        if (chunkBytes.isEmpty() && inputFile.error() != QFile::NoError)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取文件失败：%1").arg(inputFile.errorString());
            }
            return QString();
        }
        sha256Hasher.addData(chunkBytes);
    }
    return QString::fromLatin1(sha256Hasher.result().toHex());
}

void ks::online_scan::showMissingApiKeyDialog(QWidget* parentWidget, const QString& serviceName)
{
    QMessageBox::information(
        parentWidget,
        QStringLiteral("在线扫描 API Key 未配置"),
        QStringLiteral("%1 API Key 为空。\n\n请在“设置 -> 在线扫描”中填写 API Key，保存后重新上传文件。").arg(serviceName));
}

void ks::online_scan::showErrorDialog(
    QWidget* parentWidget,
    const QString& titleText,
    const QString& detailText)
{
    QMessageBox::warning(parentWidget, titleText, detailText);
}

void ks::online_scan::showResultDialog(
    QWidget* parentWidget,
    const QString& titleText,
    const QString& summaryText,
    const QString& detailJsonText)
{
    QDialog resultDialog(parentWidget);
    resultDialog.setObjectName(QStringLiteral("onlineScanResultDialog"));
    resultDialog.setWindowTitle(titleText);
    resultDialog.resize(880, 640);
    resultDialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(resultDialog.objectName()));

    // dialogLayout 作用：上方放摘要，下方放 CodeEditorWidget，底部放复制与关闭按钮。
    QVBoxLayout* dialogLayout = new QVBoxLayout(&resultDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QLabel* summaryLabel = new QLabel(summaryText, &resultDialog);
    summaryLabel->setWordWrap(true);
    summaryLabel->setContentsMargins(10, 8, 10, 8);
    dialogLayout->addWidget(summaryLabel, 0);

    CodeEditorWidget* resultEditor = new CodeEditorWidget(&resultDialog);
    resultEditor->setReadOnly(true);
    resultEditor->setRawText(detailJsonText);
    dialogLayout->addWidget(resultEditor, 1);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &resultDialog);
    QPushButton* copyButton = buttonBox->addButton(QStringLiteral("复制结果"), QDialogButtonBox::ActionRole);
    QObject::connect(copyButton, &QPushButton::clicked, &resultDialog, [resultEditor]()
        {
            if (resultEditor != nullptr && QGuiApplication::clipboard() != nullptr)
            {
                QGuiApplication::clipboard()->setText(resultEditor->text());
            }
        });
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &resultDialog, &QDialog::reject);
    dialogLayout->addWidget(buttonBox, 0);

    ks::ui::ApplyDetailDialogChrome(&resultDialog);
    resultDialog.exec();
}
