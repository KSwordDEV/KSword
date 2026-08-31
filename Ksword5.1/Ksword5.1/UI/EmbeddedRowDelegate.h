#pragma once

// ============================================================
// EmbeddedRowDelegate.h
// 作用：
// - 在行内详情展开时，把源单元格的绘制区域限制在展开前的原始行高内；
// - 保留页面原有 item delegate 的绘制、编辑和提示行为；
// - 不修改业务模型，只修正视图层的源行绘制几何。
// ============================================================

#include <QAbstractItemDelegate>
#include <QModelIndex>
#include <QPointer>
#include <QStyleOptionViewItem>

#include <functional>

class QAbstractItemModel;
class QAbstractItemView;
class QHelpEvent;
class QPainter;
class QWidget;

namespace ks::ui
{
    // EmbeddedRowDelegate：包装页面原有 delegate，并裁剪已展开源行的绘制区域。
    // 调用方式：由 DetailLayoutHost 在首次展开行内详情时创建并安装到数据视图。
    // sourceDelegate：页面原有 delegate，包装器只借用不负责释放。
    // originalHeightProvider：按模型索引返回展开前原始行高，非详情行返回 <= 0。
    class EmbeddedRowDelegate final : public QAbstractItemDelegate
    {
    public:
        using OriginalHeightProvider = std::function<int(const QModelIndex&)>;

        // 构造函数：保存原 delegate 与行高查询函数，并转发原 delegate 的编辑信号。
        // parent：数据视图或详情布局宿主，负责包装器生命周期。
        EmbeddedRowDelegate(
            QAbstractItemDelegate* sourceDelegate,
            OriginalHeightProvider originalHeightProvider,
            QObject* parent = nullptr);

        // paint：详情行展开时仅在原始行高范围内绘制源单元格。
        // painter/option/index：Qt 视图传入的绘制上下文、选项和模型索引。
        void paint(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;

        // sizeHint：保持原 delegate 的尺寸建议，避免改变未展开页面布局。
        QSize sizeHint(
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;

        // 以下接口转发编辑、提示和事件处理，避免包装器改变页面既有交互行为。
        QWidget* createEditor(
            QWidget* parent,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;
        void destroyEditor(QWidget* editor, const QModelIndex& index) const override;
        void setEditorData(QWidget* editor, const QModelIndex& index) const override;
        void setModelData(
            QWidget* editor,
            QAbstractItemModel* model,
            const QModelIndex& index) const override;
        void updateEditorGeometry(
            QWidget* editor,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;
        bool editorEvent(
            QEvent* event,
            QAbstractItemModel* model,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) override;
        bool helpEvent(
            QHelpEvent* event,
            QAbstractItemView* view,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) override;

    private:
        // sourceDelegate：页面原有 delegate 的弱引用，实际所有权仍属于数据视图。
        QPointer<QAbstractItemDelegate> m_sourceDelegate;

        // originalHeightProvider：查询当前索引是否属于已展开行以及其原始行高。
        OriginalHeightProvider m_originalHeightProvider;
    };
}
