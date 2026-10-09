#pragma once

// ============================================================
// MonitorTextViewer.h
// 作用：
// 1) 提供监控模块统一的原生属性查看窗口；
// 2) 字段模型承载生成的事件属性，原始数据使用独立只读页；
// 3) 避免每个 Dock 各自重复实现“属性详情弹窗”。
// ============================================================

#include <QString>
#include "../UI/StructuredFieldView.h"

class QWidget;

namespace monitor_text_viewer
{
    // Native metadata and a genuine provider payload are separate parts of one snapshot.
    struct MonitorDocument {
        ks::ui::FieldDocument fields;
        QString rawPayload;
        QString toPlainText(bool localize = true) const;
        bool isEmpty() const { return fields.isEmpty() && rawPayload.isEmpty(); }
    };
    void showReadOnlyDocumentWindow(QWidget* parentWidget, const QString& titleText,
        const MonitorDocument& document, const QString& virtualPathText = QString());
    void showReadOnlyDocumentWindow(QWidget* parentWidget, const QString& titleText,
        const ks::ui::FieldDocument& document, const QString& virtualPathText = QString());

}
