#include "EmbeddedRowDelegate.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QEvent>
#include <QHelpEvent>
#include <QPainter>

namespace ks::ui
{
    EmbeddedRowDelegate::EmbeddedRowDelegate(
        QAbstractItemDelegate* sourceDelegate,
        OriginalHeightProvider originalHeightProvider,
        QObject* parent)
        : QAbstractItemDelegate(parent),
          m_sourceDelegate(sourceDelegate),
          m_originalHeightProvider(std::move(originalHeightProvider))
    {
        // 包装器复用原 delegate 的编辑器信号，保证双击编辑等页面行为不改变。
        if (m_sourceDelegate != nullptr)
        {
            connect(
                m_sourceDelegate.data(),
                &QAbstractItemDelegate::closeEditor,
                this,
                &QAbstractItemDelegate::closeEditor);
            connect(
                m_sourceDelegate.data(),
                &QAbstractItemDelegate::commitData,
                this,
                &QAbstractItemDelegate::commitData);
            connect(
                m_sourceDelegate.data(),
                &QAbstractItemDelegate::sizeHintChanged,
                this,
                &QAbstractItemDelegate::sizeHintChanged);
        }
    }

    void EmbeddedRowDelegate::paint(
        QPainter* painter,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        // sourceDelegate 无效时不绘制，避免访问已销毁的页面 delegate。
        if (painter == nullptr || m_sourceDelegate.isNull())
        {
            return;
        }

        // 非展开源行完全沿用原 delegate，保证普通页面视觉与交互保持不变。
        const int originalHeight = m_originalHeightProvider
            ? m_originalHeightProvider(index)
            : -1;
        if (originalHeight <= 0)
        {
            m_sourceDelegate->paint(painter, option, index);
            return;
        }

        // 展开行的 itemRect 仍包含详情区域，源内容必须限制在原始行高内。
        QStyleOptionViewItem clippedOption(option);
        clippedOption.rect.setHeight(qMin(originalHeight, option.rect.height()));
        if (clippedOption.rect.height() <= 0)
        {
            return;
        }

        // 只裁剪源 delegate 的绘制调用，详情编辑器仍由 DetailLayoutHost 覆盖下半区域。
        painter->save();
        painter->setClipRect(clippedOption.rect, Qt::IntersectClip);
        m_sourceDelegate->paint(painter, clippedOption, index);
        painter->restore();
    }

    QSize EmbeddedRowDelegate::sizeHint(
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        // 尺寸计算直接转发，展开行高由 QTableWidget/QTreeWidget 原有接口控制。
        return m_sourceDelegate.isNull()
            ? QSize()
            : m_sourceDelegate->sizeHint(option, index);
    }

    QWidget* EmbeddedRowDelegate::createEditor(
        QWidget* parent,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        return m_sourceDelegate.isNull()
            ? nullptr
            : m_sourceDelegate->createEditor(parent, option, index);
    }

    void EmbeddedRowDelegate::destroyEditor(QWidget* editor, const QModelIndex& index) const
    {
        if (!m_sourceDelegate.isNull())
        {
            m_sourceDelegate->destroyEditor(editor, index);
        }
    }

    void EmbeddedRowDelegate::setEditorData(QWidget* editor, const QModelIndex& index) const
    {
        if (!m_sourceDelegate.isNull())
        {
            m_sourceDelegate->setEditorData(editor, index);
        }
    }

    void EmbeddedRowDelegate::setModelData(
        QWidget* editor,
        QAbstractItemModel* model,
        const QModelIndex& index) const
    {
        if (!m_sourceDelegate.isNull())
        {
            m_sourceDelegate->setModelData(editor, model, index);
        }
    }

    void EmbeddedRowDelegate::updateEditorGeometry(
        QWidget* editor,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        if (!m_sourceDelegate.isNull())
        {
            m_sourceDelegate->updateEditorGeometry(editor, option, index);
        }
    }

    bool EmbeddedRowDelegate::editorEvent(
        QEvent* event,
        QAbstractItemModel* model,
        const QStyleOptionViewItem& option,
        const QModelIndex& index)
    {
        // 事件区域仍交给原 delegate，避免复用委托后改变复选框等交互。
        return !m_sourceDelegate.isNull()
            && m_sourceDelegate->editorEvent(event, model, option, index);
    }

    bool EmbeddedRowDelegate::helpEvent(
        QHelpEvent* event,
        QAbstractItemView* view,
        const QStyleOptionViewItem& option,
        const QModelIndex& index)
    {
        // 工具提示与原 delegate 保持一致，行内模式只影响绘制几何。
        return !m_sourceDelegate.isNull()
            && m_sourceDelegate->helpEvent(event, view, option, index);
    }
}
