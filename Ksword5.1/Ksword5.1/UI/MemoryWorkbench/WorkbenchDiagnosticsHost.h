#pragma once

// ============================================================
// WorkbenchDiagnosticsHost.h
// 作用：
// - 接口缺口 G3 的生产实现：实现 WorkbenchStatusBar.h 声明的
//   IWorkbenchDiagnosticsHost（诊断抽屉的最小接口），内部包一层项目内置
//   CodeEditorWidget（只读），供 MemoryWorkbenchView::buildUi() 构造
//   WorkbenchStatusBar 时注入。
// - 换行设置统一调用 CodeEditorWidget::setWordWrapEnabled，只改变显示布局；
//   SetWrapEnabled / lastWrapRequestForTest 与真正编辑区保持一致。
// - 诊断文本混合中文提示与通道给出的英文原文，属于"日志/原始内容"一类，按
//   仓库规范（AGENTS.md）经 CodeEditorWidget::setRawText 写入，不经任何翻译
//   通道、不受 LanguageChange 影响。
// ============================================================

#include "WorkbenchStatusBar.h"

#include <QWidget>

class CodeEditorWidget;

namespace ks::ui
{
    // WorkbenchDiagnosticsHost：见文件头。既是一个可直接加入布局的 QWidget
    // （HostWidget() 返回 this），也实现 IWorkbenchDiagnosticsHost 四个方法。
    class WorkbenchDiagnosticsHost final : public QWidget, public IWorkbenchDiagnosticsHost
    {
        Q_OBJECT

    public:
        explicit WorkbenchDiagnosticsHost(QWidget* parent = nullptr);
        ~WorkbenchDiagnosticsHost() override;

        // ---- IWorkbenchDiagnosticsHost 四个方法 ----
        QWidget* HostWidget() override;
        void SetDiagnosticsText(const QString& text) override;
        QString DiagnosticsText() const override;
        void SetWrapEnabled(bool wrap) override;

        // ---- 供夹具白盒断言，不是业务接口 ----
        // editorForTest：取内部的 CodeEditorWidget 指针（例如断言只读/文本内容）。
        CodeEditorWidget* editorForTest() const noexcept;
        // lastWrapRequestForTest：SetWrapEnabled 最近一次被要求并应用的值。
        bool lastWrapRequestForTest() const noexcept;

    private:
        // editor_：唯一的子控件，拥有（parent 关系释放）。
        CodeEditorWidget* editor_ = nullptr;
        // lastWrapRequest_：见 SetWrapEnabled/lastWrapRequestForTest 的说明。
        bool lastWrapRequest_ = true;
    };
}
