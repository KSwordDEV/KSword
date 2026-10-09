// ============================================================
// WorkbenchDiagnosticsHost.cpp
// 作用：实现 WorkbenchDiagnosticsHost.h，详见该文件头的说明。
// ============================================================

#include "WorkbenchDiagnosticsHost.h"

#include "../CodeEditorWidget.h"

#include <QVBoxLayout>

namespace ks::ui
{
    // 构造：包一层 CodeEditorWidget，设为只读，塞满整个容器（边距归零——本类
    // 只是状态条抽屉里的一个内容区，不需要自己的外边距）。
    WorkbenchDiagnosticsHost::WorkbenchDiagnosticsHost(QWidget* parent)
        : QWidget(parent)
    {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        editor_ = new CodeEditorWidget(this);
        editor_->setReadOnly(true);
        layout->addWidget(editor_);
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
        }
    }

    // DiagnosticsText：读回当前内容。
    QString WorkbenchDiagnosticsHost::DiagnosticsText() const
    {
        return (editor_ != nullptr) ? editor_->text() : QString();
    }

    // Display policy uses the shared editor API and never rewrites diagnostics.
    void WorkbenchDiagnosticsHost::SetWrapEnabled(bool wrap)
    {
        lastWrapRequest_ = wrap;
        if (editor_ != nullptr) editor_->setWordWrapEnabled(wrap);
    }

    CodeEditorWidget* WorkbenchDiagnosticsHost::editorForTest() const noexcept
    {
        return editor_;
    }

    bool WorkbenchDiagnosticsHost::lastWrapRequestForTest() const noexcept
    {
        return lastWrapRequest_;
    }
}
