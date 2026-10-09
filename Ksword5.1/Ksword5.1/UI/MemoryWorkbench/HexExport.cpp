// HexExport.cpp
#include "../FlatButtonTheme.h"
// 作用：HexExport.h 的实现——转储格式化、写文件、保存路径对话框与错误框。

#include "HexExport.h"

#include "../../theme.h"
#include "HexCanvasFormat.h"

#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QStringList>

#include <algorithm>

namespace ks::ui::hexexport
{
    // 格式化一行转储。
    QString FormatDumpRow(
        std::uint64_t rowAddress,
        const QByteArray& data,
        qsizetype offset,
        int bytesPerRow)
    {
        // columns：每行列数，非正数按默认值。
        const int columns = bytesPerRow > 0 ? bytesPerRow : kDumpBytesPerRow;

        // 十六进制列与 ASCII 列：越过数据末尾的列补位。
        QStringList hexColumns;
        hexColumns.reserve(columns);
        QString asciiColumns;
        asciiColumns.reserve(columns);
        for (int column = 0; column < columns; ++column)
        {
            const qsizetype index = offset + column;
            if (index >= 0 && index < data.size())
            {
                const std::uint8_t value = static_cast<std::uint8_t>(data.at(index));
                hexColumns.push_back(hexcanvas_format::FormatHexText(QByteArray(1, static_cast<char>(value))));
                asciiColumns.push_back(
                    hexcanvas_format::IsPrintableAscii(value) ? QChar(static_cast<char16_t>(value)) : QChar(u'.'));
            }
            else
            {
                hexColumns.push_back(QStringLiteral("--"));
                asciiColumns.push_back(QChar(u' '));
            }
        }

        // 行 = 地址 + 两空格 + 十六进制列 + 两空格 + |ASCII|。
        return QStringLiteral("%1  %2  |%3|")
            .arg(hexcanvas_format::FormatAddress(rowAddress, 16))
            .arg(hexColumns.join(QChar(u' ')))
            .arg(asciiColumns);
    }

    // 格式化整块转储。
    QString FormatDump(std::uint64_t base, const QByteArray& data, int bytesPerRow)
    {
        if (data.isEmpty())
        {
            return QString();
        }
        const int columns = bytesPerRow > 0 ? bytesPerRow : kDumpBytesPerRow;

        // 逐行格式化再用换行连接；行地址 = base + 行偏移（偏移是 qsizetype，转无符号后相加，64 位下不会回绕到小地址以外的意外值）。
        QStringList rows;
        rows.reserve(static_cast<qsizetype>((data.size() + columns - 1) / columns));
        for (qsizetype offset = 0; offset < data.size(); offset += columns)
        {
            rows.push_back(FormatDumpRow(base + static_cast<std::uint64_t>(offset), data, offset, columns));
        }
        return rows.join(QChar(u'\n'));
    }

    // 选中字节的十六进制文本：直接复用画布的大写空格分隔格式。
    QString FormatSelectedHex(const QByteArray& bytes)
    {
        return hexcanvas_format::FormatHexText(bytes);
    }

    namespace
    {
        // WriteFileImpl：两个写文件函数共用的实现。
        // 传入：路径、文件打开模式、要写入的原始字节、原因输出；传出：是否成功。
        bool WriteFileImpl(
            const QString& path,
            QIODevice::OpenMode mode,
            const QByteArray& payload,
            QString* errorOut)
        {
            // fail：统一失败出口，把原因写给调用方。
            const auto fail = [errorOut](const QString& reason) {
                if (errorOut != nullptr)
                {
                    *errorOut = reason;
                }
                return false;
            };

            if (path.trimmed().isEmpty())
            {
                return fail(QStringLiteral("没有指定导出路径"));
            }

            QFile file(path);
            if (!file.open(mode))
            {
                return fail(QStringLiteral("无法写入文件：%1（%2）").arg(path, file.errorString()));
            }

            // 写入必须完整：返回值不等于长度说明磁盘满或设备错误。
            const qint64 written = file.write(payload);
            if (written != payload.size())
            {
                const QString reason = file.errorString();
                file.close();
                return fail(QStringLiteral("写入不完整：%1（%2）").arg(path, reason));
            }
            if (!file.flush())
            {
                return fail(QStringLiteral("写入不完整：%1（%2）").arg(path, file.errorString()));
            }
            file.close();
            if (errorOut != nullptr)
            {
                errorOut->clear();
            }
            return true;
        }
    }

    // 写二进制文件。
    bool WriteBinaryFile(const QString& path, const QByteArray& bytes, QString* errorOut)
    {
        return WriteFileImpl(path, QIODevice::WriteOnly | QIODevice::Truncate, bytes, errorOut);
    }

    // 写文本文件：UTF-8，文本模式换行。
    bool WriteTextFile(const QString& path, const QString& text, QString* errorOut)
    {
        return WriteFileImpl(path, QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text, text.toUtf8(), errorOut);
    }

    // 建议文件名。
    QString SuggestedFileName(Kind kind)
    {
        switch (kind)
        {
        case Kind::Binary:
            return QStringLiteral("hex_export.bin");
        case Kind::HexDump:
            return QStringLiteral("hex_export.txt");
        case Kind::SelectedHex:
            return QStringLiteral("hex_selected.txt");
        }
        return QStringLiteral("hex_export.bin");
    }

    // 保存路径对话框。
    QString PickSavePath(QWidget* parent, Kind kind)
    {
        // title/filter：按导出种类给出标题与文件类型过滤器。
        QString title = QStringLiteral("导出二进制");
        QString filter = QStringLiteral("二进制文件 (*.bin);;所有文件 (*.*)");
        if (kind == Kind::HexDump)
        {
            title = QStringLiteral("导出十六进制文本");
            filter = QStringLiteral("文本文件 (*.txt);;所有文件 (*.*)");
        }
        else if (kind == Kind::SelectedHex)
        {
            title = QStringLiteral("导出选中字节的十六进制文本");
            filter = QStringLiteral("文本文件 (*.txt);;所有文件 (*.*)");
        }
        return QFileDialog::getSaveFileName(parent, title, SuggestedFileName(kind), filter);
    }

    // 模态错误框：每次新建、显式不透明样式。
    void ShowExportError(QWidget* parent, const QString& reason)
    {
        QMessageBox box(QMessageBox::Warning, QStringLiteral("导出失败"), reason, QMessageBox::Ok, parent);
        box.setAttribute(Qt::WA_TranslucentBackground, false);
        box.setAutoFillBackground(true);
        // 错误对话框保持不透明面板；确认按钮保留原 padding，改用实心中性样式。
        box.setStyleSheet(QStringLiteral(
            "QMessageBox{background-color:palette(base);}"
            "QMessageBox QLabel{color:palette(text);background-color:transparent;}"
            "QMessageBox QPushButton{padding:4px 14px;}")
            + ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral));
        box.exec();
    }
}
