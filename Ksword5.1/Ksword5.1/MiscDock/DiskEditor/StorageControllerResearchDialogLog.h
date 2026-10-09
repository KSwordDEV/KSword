#pragma once

// 控制器页面日志只管理文本，不读取设备、不翻译原始证据。
#include <QTextCursor>
#include <QTextDocument>

namespace ks::misc::detail
{
    // ControllerLogBuffer：复用 QTextDocument 的块语义，保留原先最多 500 块的日志界限。
    class ControllerLogBuffer final
    {
    public:
        ControllerLogBuffer()
        {
            m_document.setMaximumBlockCount(MaximumBlocks);
        }

        // append：追加完整日志条目，返回此次被丢弃的旧块数量；换行也按块计数。
        int append(const QString& entry)
        {
            // 已有内容前补一个段落分隔，不给第一条日志制造空白首行。
            const int previousBlocks = m_document.blockCount();
            QTextDocument incoming;
            incoming.setPlainText(entry);
            const int addedBlocks = incoming.blockCount() - (m_document.isEmpty() ? 1 : 0);
            QTextCursor cursor(&m_document);
            cursor.movePosition(QTextCursor::End);
            if (!m_document.isEmpty())
            {
                cursor.insertBlock();
            }
            cursor.insertText(entry);
            return previousBlocks + addedBlocks - m_document.blockCount();
        }

        // text：按原文返回已截断日志；该结果交给 CodeEditorWidget::setRawText。
        QString text() const
        {
            return m_document.toPlainText();
        }

        // blockCount：供离线夹具核验实际文本块界限。
        int blockCount() const
        {
            return m_document.blockCount();
        }

        static constexpr int MaximumBlocks = 500; // 页面历史日志块预算。

    private:
        QTextDocument m_document; // 拥有日志文本和自动截断策略，不参与 UI 展示。
    };
}
