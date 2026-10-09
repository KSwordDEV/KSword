#include "CodeEditorFileSession.h"

// ============================================================
// CodeEditorFileSession.cpp
// 作用：
// - 实现文本文件会话元数据识别；
// - 实现编码/BOM/换行风格保持；
// - 为 CodeEditorWidget 提供统一文件读写策略基础能力。
// ============================================================

#include <QBuffer>
#include <QTextStream>

namespace
{
    // readAllTextWithEncoding：
    // - 作用：按指定编码把字节块解析为文本；
    // - 调用：UTF-16 LE/BE 场景的统一读取入口；
    // - 入参 rawBytes：原始字节；encoding：目标编码；
    // - 返回：解码后的文本内容。
    QString readAllTextWithEncoding(const QByteArray& rawBytes, const QStringConverter::Encoding encoding)
    {
        QBuffer byteBuffer;
        byteBuffer.setData(rawBytes);
        if (!byteBuffer.open(QIODevice::ReadOnly))
        {
            return QString();
        }

        QTextStream textStream(&byteBuffer);
        textStream.setEncoding(encoding);
        return textStream.readAll();
    }
}

namespace code_editor_file_session
{
    QString decodeTextFileBytes(const QByteArray& fileBytes, FileSessionMetadata* metadataOut)
    {
        FileSessionMetadata sessionMetadata;
        QString decodedText;

        // BOM 检测：优先识别 UTF-8 / UTF-16 LE / UTF-16 BE。
        if (fileBytes.startsWith("\xEF\xBB\xBF"))
        {
            sessionMetadata.encoding = QStringConverter::Utf8;
            sessionMetadata.hasBom = true;
            decodedText = QString::fromUtf8(fileBytes.constData() + 3, fileBytes.size() - 3);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFF
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFE)
        {
            sessionMetadata.encoding = QStringConverter::Utf16LE;
            sessionMetadata.hasBom = true;
            decodedText = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16LE);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFE
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFF)
        {
            sessionMetadata.encoding = QStringConverter::Utf16BE;
            sessionMetadata.hasBom = true;
            decodedText = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16BE);
        }
        else
        {
            // 合法 UTF-8 可以包含 U+FFFD；只在字节解码失败时回退本地编码。
            QStringDecoder decoder(QStringConverter::Utf8);
            const QString utf8Text = decoder(fileBytes);
            if (decoder.hasError())
            {
                sessionMetadata.encoding = QStringConverter::System;
                sessionMetadata.hasBom = false;
                decodedText = QString::fromLocal8Bit(fileBytes);
            }
            else
            {
                sessionMetadata.encoding = QStringConverter::Utf8;
                sessionMetadata.hasBom = false;
                decodedText = utf8Text;
            }
        }

        sessionMetadata.lineEndingText = detectDominantLineEnding(decodedText);
        sessionMetadata.validFromFile = true;
        if (metadataOut != nullptr)
        {
            *metadataOut = sessionMetadata;
        }
        return decodedText;
    }

    QString detectDominantLineEnding(const QString& textValue)
    {
        // 统计三类换行出现次数，按出现次数最多者作为主导风格。
        int crlfCount = 0;
        int lfCount = 0;
        int crCount = 0;

        for (int index = 0; index < textValue.size(); ++index)
        {
            const QChar currentChar = textValue.at(index);
            if (currentChar == QChar('\r'))
            {
                if ((index + 1) < textValue.size() && textValue.at(index + 1) == QChar('\n'))
                {
                    ++crlfCount;
                    ++index;
                }
                else
                {
                    ++crCount;
                }
            }
            else if (currentChar == QChar('\n'))
            {
                ++lfCount;
            }
        }

        if (crlfCount >= lfCount && crlfCount >= crCount)
        {
            return QStringLiteral("\r\n");
        }
        if (lfCount >= crCount)
        {
            return QStringLiteral("\n");
        }
        return QStringLiteral("\r");
    }

    QString normalizeLineEndingForSaving(const QString& textValue, const QString& lineEndingText)
    {
        // 先统一成 LF，再按目标风格导出，避免混合换行持续扩散。
        QString normalizedText = textValue;
        normalizedText.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        normalizedText.replace(QChar('\r'), QChar('\n'));

        if (lineEndingText == QStringLiteral("\r"))
        {
            return normalizedText.replace(QChar('\n'), QChar('\r'));
        }
        if (lineEndingText == QStringLiteral("\r\n"))
        {
            return normalizedText.replace(QStringLiteral("\n"), QStringLiteral("\r\n"));
        }
        return normalizedText;
    }

    QString buildEncodingDisplayText(const FileSessionMetadata& metadata)
    {
        QString encodingName = QStringLiteral("UTF-8");
        switch (metadata.encoding)
        {
        case QStringConverter::Utf8:
            encodingName = QStringLiteral("UTF-8");
            break;
        case QStringConverter::Utf16LE:
            encodingName = QStringLiteral("UTF-16 LE");
            break;
        case QStringConverter::Utf16BE:
            encodingName = QStringLiteral("UTF-16 BE");
            break;
        case QStringConverter::System:
            encodingName = QStringLiteral("本地编码");
            break;
        default:
            encodingName = QStringLiteral("UTF-8");
            break;
        }
        if (metadata.hasBom)
        {
            encodingName += QStringLiteral(" BOM");
        }
        return encodingName;
    }

    QString buildLineEndingDisplayText(const QString& lineEndingText)
    {
        if (lineEndingText == QStringLiteral("\r\n"))
        {
            return QStringLiteral("CRLF");
        }
        if (lineEndingText == QStringLiteral("\r"))
        {
            return QStringLiteral("CR");
        }
        return QStringLiteral("LF");
    }
}
