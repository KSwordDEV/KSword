// ============================================================
// WorkbenchDiagnosticsHost.cpp
// 作用：实现 WorkbenchDiagnosticsHost.h，详见该文件头的说明。
// ============================================================

#include "WorkbenchDiagnosticsHost.h"

#include "../CodeEditorWidget.h"
#include "../StructuredFieldView.h"

#include <QStackedWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace ks::ui
{
    // 结构字段与原始日志共用抽屉几何，各自维护自己的数据源。
    WorkbenchDiagnosticsHost::WorkbenchDiagnosticsHost(QWidget* parent)
        : QWidget(parent)
    {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        panes_ = new QStackedWidget(this);
        editor_ = new CodeEditorWidget(panes_);
        editor_->setReadOnly(true);
        fields_ = new StructuredFieldView(panes_);
        panes_->addWidget(editor_);
        panes_->addWidget(fields_);
        layout->addWidget(panes_);
    }

    WorkbenchDiagnosticsHost::~WorkbenchDiagnosticsHost() = default;

    // HostWidget：本类自己就是宿主控件。
    QWidget* WorkbenchDiagnosticsHost::HostWidget()
    {
        return this;
    }

    // SetDiagnosticsText：原样覆盖（setRawText，不翻译，见文件头）。
    void WorkbenchDiagnosticsHost::SetDiagnosticsText(const QString& text)
    {
        if (editor_ != nullptr)
        {
            editor_->setRawText(text);
            panes_->setCurrentWidget(editor_);
        }
    }

    void WorkbenchDiagnosticsHost::SetDiagnosticsDocument(const FieldDocument& document)
    {
        fields_->setDocument(document);
        panes_->setCurrentWidget(fields_);
    }

    // DiagnosticsText：读回当前内容。
    QString WorkbenchDiagnosticsHost::DiagnosticsText() const
    {
        if (panes_->currentWidget() == fields_) return fields_->plainText();
        return (editor_ != nullptr) ? editor_->text() : QString();
    }

    // Display policy uses the shared editor API and never rewrites diagnostics.
    void WorkbenchDiagnosticsHost::SetWrapEnabled(bool wrap)
    {
        lastWrapRequest_ = wrap;
        if (editor_ != nullptr) editor_->setWordWrapEnabled(wrap);
        if (fields_ != nullptr)
        {
            fields_->tree()->setWordWrap(wrap);
            fields_->setPresentation(fields_->presentation());
        }
    }

    CodeEditorWidget* WorkbenchDiagnosticsHost::editorForTest() const noexcept
    {
        return editor_;
    }

    StructuredFieldView* WorkbenchDiagnosticsHost::fieldsForTest() const noexcept
    {
        return fields_;
    }

    bool WorkbenchDiagnosticsHost::lastWrapRequestForTest() const noexcept
    {
        return lastWrapRequest_;
    }
}
