#include "MonitorTextViewer.h"
#include "../theme.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/DetailDialogChrome.h"

// ============================================================
// MonitorTextViewer.cpp
// 作用：
// 1) 统一创建原生字段详情窗口；
// 2) 事件属性使用字段模型，原始 provider payload 独立只读展示；
// 3) 非模态显示，方便用户边看事件列表边对照原始详情。
// ============================================================

#include <QDialog>
#include <QDialogButtonBox>
#include <QVBoxLayout>
#include <QTabWidget>
#include "../Internationalization/LanguageManager.h"

namespace monitor_text_viewer
{
    QString MonitorDocument::toPlainText(const bool localize) const
    {
        const QString fieldsText = fields.toPlainText(localize);
        if (rawPayload.isEmpty()) return fieldsText;
        const QString label = localize ? ks::i18n::sourceText(QStringLiteral("返回详情")) : QStringLiteral("返回详情");
        return fieldsText + QLatin1Char('\n') + label + QStringLiteral(":\n") + rawPayload;
    }
    void showReadOnlyDocumentWindow(QWidget* parentWidget, const QString& titleText,
        const MonitorDocument& document, const QString& virtualPathText)
    {
        auto* dialog = new QDialog(parentWidget);
        dialog->setAttribute(Qt::WA_DeleteOnClose, true);
        dialog->setObjectName(QStringLiteral("monitor_native_document"));
        dialog->setWindowTitle(titleText.trimmed().isEmpty() ? ks::i18n::sourceText(QStringLiteral("详情查看")) : titleText);
        dialog->resize(980, 720);
        dialog->setModal(false);
        dialog->setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog->objectName()));
        auto* layout = new QVBoxLayout(dialog);
        auto* fields = new ks::ui::StructuredFieldView(dialog);
        fields->setDocument(document.fields);
        fields->setToolTip(virtualPathText);
        if (document.rawPayload.isEmpty()) layout->addWidget(fields, 1);
        else {
            auto* tabs = new QTabWidget(dialog);
            tabs->addTab(fields, ks::i18n::sourceText(QStringLiteral("属性")));
            auto* raw = new CodeEditorWidget(tabs);
            raw->setReadOnly(true);
            raw->setRawText(document.rawPayload);
            tabs->addTab(raw, ks::i18n::sourceText(QStringLiteral("原始数据")));
            ks::ui::SetDetailTabGroups(tabs, {{ks::ui::DetailNavigationKind::General, {0}},
                {ks::ui::DetailNavigationKind::Content, {1}}});
            layout->addWidget(ks::ui::CreateDetailTabShell(tabs, dialog), 1);
        }
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
        QObject::connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        QObject::connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        layout->addWidget(buttons);
        ks::ui::ApplyDetailDialogChrome(dialog);
        dialog->show();
        dialog->raise();
        dialog->activateWindow();
    }
    void showReadOnlyDocumentWindow(QWidget* parentWidget, const QString& titleText,
        const ks::ui::FieldDocument& document, const QString& virtualPathText)
    {
        showReadOnlyDocumentWindow(parentWidget, titleText, MonitorDocument{document, {}}, virtualPathText);
    }


}
