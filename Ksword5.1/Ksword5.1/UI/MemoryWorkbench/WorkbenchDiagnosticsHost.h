#pragma once

// ============================================================
// WorkbenchDiagnosticsHost.h
// 作用：
// - 接口缺口 G3 的生产实现：实现 WorkbenchStatusBar.h 声明的
//   IWorkbenchDiagnosticsHost，结构报告直接使用 StructuredFieldView；
//   失败信息、通道原文与真实日志使用只读 CodeEditorWidget。
// - 两种数据各自保存，由正式 setter 切换当前展示；字段报告不生成文本镜像。
// - 换行仅改变显示；复制在触发时从当前模型或原文生成。
// ============================================================

#include "WorkbenchStatusBar.h"

#include <QWidget>

class CodeEditorWidget;
class QStackedWidget;

namespace ks::ui
{
    class StructuredFieldView;
    // WorkbenchDiagnosticsHost：见文件头。既是一个可直接加入布局的 QWidget
    // （HostWidget() 返回 this），也实现 IWorkbenchDiagnosticsHost 的正式方法。
    class WorkbenchDiagnosticsHost final : public QWidget, public IWorkbenchDiagnosticsHost
    {
        Q_OBJECT

    public:
        explicit WorkbenchDiagnosticsHost(QWidget* parent = nullptr);
        ~WorkbenchDiagnosticsHost() override;

        // ---- IWorkbenchDiagnosticsHost 的正式方法 ----
        QWidget* HostWidget() override;
        void SetDiagnosticsText(const QString& text) override;
        void SetDiagnosticsDocument(const FieldDocument& document) override;
        QString DiagnosticsText() const override;
        void SetWrapEnabled(bool wrap) override;

        // ---- 供夹具白盒断言，不是业务接口 ----
        // editorForTest：取内部的 CodeEditorWidget 指针（例如断言只读/文本内容）。
        CodeEditorWidget* editorForTest() const noexcept;
        StructuredFieldView* fieldsForTest() const noexcept;
        // lastWrapRequestForTest：SetWrapEnabled 最近一次被要求并应用的值。
        bool lastWrapRequestForTest() const noexcept;

    private:
        // 原始日志与字段报告各有子控件，由堆叠容器管理当前展示。
        CodeEditorWidget* editor_ = nullptr;
        StructuredFieldView* fields_ = nullptr;
        QStackedWidget* panes_ = nullptr;
        // lastWrapRequest_：见 SetWrapEnabled/lastWrapRequestForTest 的说明。
        bool lastWrapRequest_ = true;
    };
}
